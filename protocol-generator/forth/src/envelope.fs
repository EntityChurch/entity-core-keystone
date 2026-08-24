\ entity-core-protocol-forth — the protocol envelope (§3.1): a `root` entity plus an
\ `included` map of protocol entities keyed by content_hash (the §5.8 authority carrier —
\ capabilities, peer identities, signatures travel here).
\
\ On the wire (§3.1) `included` is a content_hash -> entity MAP with BYTE-string keys (the
\ major-2 seam, NOT text keys — N5). Duplicate hashes collapse, so we dedup preserving
\ first-seen order before encoding (the canonical codec rejects a duplicate map key), and
\ on decode we verify each map key == its entity's content_hash (§3.1) — N5 both sides.
\
\ THE STACK-MACHINE MODEL (A-FT-009): an envelope-under-construction is an INCLUDED SET —
\ a small parallel array of (entity-addr, entity-len) with first-seen dedup — plus a root.
\ We keep ONE inbound and ONE outbound builder set (single-threaded; a reentry uses the
\ outbound set while the inbound set holds the request being served — see dispatch.fs).

\ The included set must hold a full capability chain (§4.10(b) depth default 64) PLUS the
\ per-link signers + peer entities + the request signature — so it is sized comfortably
\ above the chain-depth cap, not equal to it (a 64-deep chain needs > 64 included entities).
256 constant MAX-INCLUDED
\ An "inc-set" is a base into two parallel arrays (addr[], len[]) + a count cell. We give
\ each of the two sets its own storage rather than a shared allocator (single-thread, two
\ live sets max: the inbound request + one outbound reentry).
: make-inc-set ( -- )  ;   \ (documentation only; storage is declared per set below)

create incA-addr  MAX-INCLUDED cells allot
create incA-len   MAX-INCLUDED cells allot
variable incA-n
create incB-addr  MAX-INCLUDED cells allot
create incB-len   MAX-INCLUDED cells allot
variable incB-n

\ inc-add ( addr[] len[] n-var  e-addr e-len -- )  add an entity to a set, deduped by hash.
: inc-add { arr lens nvar eaddr eu -- }
  eaddr ent-hash { hu } { haddr }
  nvar @ 0 ?do
    arr i cells + @ ent-hash  haddr hu compare 0= if unloop exit then   \ already present
  loop
  nvar @ dup MAX-INCLUDED >= if E-ARENA-OVERFLOW throw then { i }
  eaddr arr i cells + !  eu lens i cells + !
  i 1+ nvar ! ;

\ inc-get ( arr lens n-var  h-addr h-u -- eaddr | 0 )  find an included entity by hash.
: inc-get { arr lens nvar haddr hu -- eaddr }
  nvar @ 0 ?do
    arr i cells + @ dup ent-hash  haddr hu compare 0= if unloop exit then drop
  loop  0 ;   \ not found: the loop body already dropped each candidate — just push 0

\ inc->map-tv ( arr lens n-var -- mtv-addr mtv-u )  build the wire `included` map TV: a map
\ of byte-key(content_hash) -> entity-wire-map, first-seen order (already deduped on add).
: inc->map-tv { arr lens nvar -- maddr mu }
  am-mark { mk }
  [char] m b,  nvar @ 4 >be
  nvar @ 0 ?do
    arr i cells + @ { e }
    e ent-hash tv-bytes 2drop           \ byte key = content_hash
    e ent->wire 2drop                  \ value = entity wire map
  loop
  mk am-span ;

\ ── envelope encode: {root, included} map TV, then CBOR-encode to a frame payload ──
\ env->wire ( root-eaddr  arr lens n-var -- wire-addr wire-u )  build+encode the envelope.
: env->wire { root arr lens nvar -- waddr wu }
  am-mark { mk }
  [char] m b,  2 4 >be
  s" included" tv-text 2drop  arr lens nvar inc->map-tv 2drop
  s" root"     tv-text 2drop  root ent->wire 2drop
  mk am-span                            \ envelope map TV
  cbor-encode ;                          \ -> canonical wire payload

\ ── envelope decode: parse a wire payload into (root-entity, an inc-set) ──
\ Fills the given set with the decoded included entities (verifying key==content_hash).
\ Returns the root entity addr. THROWs on a bad shape (caught at the dispatch boundary).
-25300 constant E-MISSING-ROOT
-25301 constant E-INCLUDED-KEY-NOT-BYTES
-25302 constant E-INCLUDED-KEY-MISMATCH
: env<-wire { payaddr payu arr lens nvar -- root-eaddr }
  0 nvar !
  payaddr payu cbor-decode drop { mtv }
  mtv c@ [char] m <> if E-MISSING-ROOT throw then
  mtv s" root" tv-map-get dup 0= if E-MISSING-ROOT throw then ent<-wire { root }
  mtv s" included" tv-map-get dup if
    { incm }
    incm c@ [char] m <> if E-INCLUDED-KEY-NOT-BYTES throw then
    incm tv-count { n }
    incm 5 + { p }
    n 0 ?do
      p c@ [char] b <> if E-INCLUDED-KEY-NOT-BYTES throw then
      p tv-payload { klen } { kaddr }               \ key = declared content_hash
      p tv-node-len p + { vp }                       \ value TV addr
      vp ent<-wire { e }
      e ent-hash  kaddr klen compare 0<> if E-INCLUDED-KEY-MISMATCH throw then
      arr lens nvar  e e ent-len  inc-add
      vp tv-node-len vp + to p                        \ next pair
    loop
  else drop then
  root ;
