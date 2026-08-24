\ entity-core-protocol-forth — byte buffers + the tagged-value (TV) heap.
\
\ THE STACK-MACHINE SUBSTRATE (A-FT-000 / A-FT-009). Forth has no records and no
\ typed values: a "value" is a byte span (c-addr u) somewhere in memory. Both the
\ decoded value model (the internal tagged-value rep) AND the encoded wire output are
\ built by APPENDING bytes into a bump-allocated arena and handing back the (addr,len)
\ span. This is the idiomatic Forth string builder — a HERE-style pointer over an
\ ALLOTed region — and it is what lets the recursive CBOR encoder/decoder compose on
\ the data stack with (addr,len) pairs, never deep dup/roll gymnastics.
\
\ We use a private arena rather than the dictionary HERE so a codec call never disturbs
\ compilation state and so we can rewind the whole arena between top-level operations.

\ 8 MiB working arena, allocated off the OS heap (allocate) — NOT the gforth dictionary (allot),
\ which a multi-MiB reservation overflows. Sized to hold a large single-op working set: a
\ 256-KiB tree.put (concurrency t1_3's slow entity) decodes to TVs + materializes the entity +
\ re-encodes the response, all in the arena between per-op resets — comfortably inside 8 MiB.
8 1024 * 1024 * constant ARENA-SIZE
ARENA-SIZE allocate throw constant arena
variable ap                              \ arena pointer (next free byte, absolute addr)

: arena-reset ( -- )  arena ap ! ;
: arena-here  ( -- addr )  ap @ ;
: arena-avail ( -- u )  arena ARENA-SIZE + ap @ - ;

\ leaf_kinds (profile [error_model]): private THROW-code range base -25000.
-25000 constant ERR-BASE
ERR-BASE  0 - constant E-NON-CANONICAL-ECF
ERR-BASE  1 - constant E-TRUNCATED-INPUT
ERR-BASE  2 - constant E-TAG-REJECTED
ERR-BASE  3 - constant E-BAD-SEED
ERR-BASE  4 - constant E-UNSUPPORTED-CONTENT-HASH-FORMAT
ERR-BASE  5 - constant E-UNSUPPORTED-KEY-TYPE
ERR-BASE  6 - constant E-BAD-VARINT
ERR-BASE  7 - constant E-BAD-BASE58
ERR-BASE  8 - constant E-CRYPTO
ERR-BASE  9 - constant E-ARENA-OVERFLOW

\ A SEPARATE scratch stack for transient bookkeeping (the map-encode sort arrays) that
\ must NOT contaminate the output-value arena. LIFO: sc-alloc bumps, sc-free rewinds.
\ Independent so nested recursive encodes each get their own scratch frame (reentrancy).
256 1024 * constant SCRATCH-SIZE
create scratch  SCRATCH-SIZE allot
variable sp                                      \ scratch pointer
: scratch-reset ( -- )  scratch sp ! ;
: sc-mark  ( -- addr )  sp @ ;
: sc-free  ( mark -- )  sp ! ;
: sc-alloc ( u -- addr )                          \ reserve u bytes, return base
  scratch SCRATCH-SIZE + sp @ - over < if E-ARENA-OVERFLOW throw then
  sp @  swap sp +! ;

\ b, ( c -- )  append one byte to the arena (guarding overflow — a hostile frame
\ must not run us off the end; §4.10 payload bound is enforced above the codec).
: b, ( c -- )
  arena-avail 1 < if E-ARENA-OVERFLOW throw then
  ap @ c!  1 ap +! ;

\ bytes, ( c-addr u -- )  append a byte span to the arena.
: bytes, ( c-addr u -- )
  dup arena-avail > if E-ARENA-OVERFLOW throw then
  ap @ swap dup >r  move  r> ap +! ;

\ >be ( u width -- )  append u as `width` big-endian bytes.
: >be ( u width -- )
  dup 0 ?do
    2dup 1- i - 8 * rshift 255 and b,
  loop 2drop ;

\ span helpers: a value is (c-addr u). Save/restore the arena pointer so a word can
\ compute a span, then rewind (used when a candidate encoding is discarded).
: am-mark  ( -- addr )  arena-here ;
: am-span ( mark -- c-addr u )  arena-here over - ;   \ (mark end -- addr len)
: rewind ( mark -- )  ap ! ;
