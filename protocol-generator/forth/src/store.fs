\ entity-core-protocol-forth — the foundation store: a content-addressed Content Store
\ (§1.1 immutable, content_hash -> entity) + an Entity Tree (§6.3 mutable, path ->
\ content_hash). Both live in a DURABLE bump heap the store owns (the codec arena is reset
\ per operation, so an entity the store keeps must be copied out of the arena — A-FT-009).
\
\ §4.8 store-safety is STRUCTURAL here: gforth is one thread, and the peer dispatches one
\ inbound frame to completion before the next select() wake, so there is never a concurrent
\ store access — no lock, no data race by construction (the single-thread-select idiom).
\
\ The two indexes are plain parallel arrays scanned linearly (the corpus is tiny; a hashed
\ dictionary is a later optimization, not a correctness need at S3).

\ ── the durable heap ──
\ Allocated off the OS heap (allocate/malloc), NOT the gforth dictionary (allot) — a multi-MiB
\ dictionary allot overflows gforth's default dictionary; a full conformance run accretes
\ hundreds of bound entities across categories, so the durable store must be generously sized
\ without bloating the dictionary.
8 1024 * 1024 * constant STORE-HEAP-SIZE
STORE-HEAP-SIZE allocate throw constant store-heap
variable store-hp
: store-heap-reset ( -- )  store-heap store-hp ! ;
store-heap-reset
: store-dup { addr u -- addr' u }   \ copy a span into the durable heap, return the copy
  u  store-heap STORE-HEAP-SIZE + store-hp @ -  > if E-ARENA-OVERFLOW throw then
  store-hp @ { dst }
  addr dst u move
  u store-hp +!
  dst u ;

\ ── Content Store: content_hash -> entity (durable copies) ──
2048 constant MAX-ENTITIES
create sc-hash-addr  MAX-ENTITIES cells allot     \ content_hash addr
create sc-hash-len   MAX-ENTITIES cells allot     \ content_hash len
create sc-ent-addr   MAX-ENTITIES cells allot     \ entity record addr (durable)
variable sc-count
: sc-reset ( -- )  0 sc-count ! ;
sc-reset

\ sc-find ( h-addr h-u -- idx | -1 )
: sc-find { haddr hu -- idx }
  sc-count @ 0 ?do
    sc-hash-addr i cells + @  sc-hash-len i cells + @
    haddr hu compare 0= if i unloop exit then
  loop  -1 ;

\ store-put ( ent-addr ent-u -- )  put an entity (deduped by content_hash). Copies the
\ entity into the durable heap. Idempotent (§1.1 immutability).
: store-put { eaddr eu -- }
  eaddr ent-hash sc-find 0>= if exit then            \ already present
  eaddr eu store-dup drop { daddr }                  \ durable entity copy addr
  sc-count @ { i }
  i MAX-ENTITIES >= if E-ARENA-OVERFLOW throw then
  daddr ent-hash store-dup                           \ durable hash copy
  sc-hash-len i cells + !  sc-hash-addr i cells + !
  daddr sc-ent-addr i cells + !
  i 1+ sc-count ! ;

\ store-get-by-hash ( h-addr h-u -- ent-addr | 0 )  the durable entity for a content_hash.
: store-get-by-hash { haddr hu -- eaddr }
  haddr hu sc-find dup 0< if drop 0 exit then
  cells sc-ent-addr + @ ;

\ ── Entity Tree: path -> content_hash (a durable string binding) ──
2048 constant MAX-PATHS
create st-path-addr  MAX-PATHS cells allot
create st-path-len   MAX-PATHS cells allot
create st-hash-addr  MAX-PATHS cells allot        \ 0 == unbound (deletion marker)
create st-hash-len   MAX-PATHS cells allot
variable st-count
: st-reset ( -- )  0 st-count ! ;
st-reset

: st-find { paddr pu -- idx }
  st-count @ 0 ?do
    st-path-addr i cells + @  st-path-len i cells + @
    paddr pu compare 0= if i unloop exit then
  loop  -1 ;

\ store-bind ( path-addr path-u ent-addr ent-u -- )  put the entity + bind path->its hash.
: store-bind { paddr pu eaddr eu -- }
  eaddr eu store-put
  eaddr ent-hash store-dup { hu } { haddr }
  paddr pu st-find { idx }
  idx 0< if
    st-count @ dup MAX-PATHS >= if E-ARENA-OVERFLOW throw then to idx
    paddr pu store-dup  st-path-len idx cells + !  st-path-addr idx cells + !
    idx 1+ st-count !
  then
  haddr st-hash-addr idx cells + !  hu st-hash-len idx cells + ! ;

\ store-get-at ( path-addr path-u -- ent-addr | 0 )  the entity bound at a path (or 0).
: store-get-at { paddr pu -- eaddr }
  paddr pu st-find dup 0< if drop 0 exit then { idx }
  st-hash-addr idx cells + @ dup 0= if drop 0 exit then    \ unbound
  st-hash-len idx cells + @  store-get-by-hash ;

\ store-unbind ( path-addr path-u -- )  clear a path binding (deletion marker).
: store-unbind { paddr pu -- }
  paddr pu st-find dup 0< if drop exit then
  0 swap  st-hash-addr swap cells + ! ;

: store-reset ( -- )  store-heap-reset sc-reset st-reset ;
