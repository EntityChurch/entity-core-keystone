\ entity-core-protocol-forth — canonical CBOR (ECF) codec, PURE FORTH.
\
\ THE STACK-MACHINE / TYPELESS PROBE (A-FT-000). A "value" is an untyped cell; a float
\ lives on the separate FP stack; there are no records. So the codec's value model is an
\ explicitly-TAGGED byte record (A-FT-003) built in the arena, and encode/decode recurse
\ on the data + return stacks carrying only (c-addr u) spans — never inferring a CBOR
\ major type from a bare cell.
\
\ INTERNAL TAGGED-VALUE (TV) REP — a self-delimiting byte record; LEN is 4 BE bytes:
\   'i' <sign:1> <n:8 BE>        int (mt0/1). sign 0 => value = n (mt0);
\                                sign 1 => value = -1-n (mt1). n is an UNSIGNED cell
\                                (A-FT-001): mt1 min -2^64 needs n = 2^64-1. So NO LEN.
\   'b' LEN <raw bytes>          byte string (mt2)
\   't' LEN <utf-8 bytes>        text string (mt3; gforth is byte-oriented, LEN=bytes)
\   'f' <bits:8 BE>              float (mt7); ALWAYS the f64 bit pattern internally
\   'a' LEN <child TVs...>       array (mt4; LEN = element count)
\   'm' LEN <(k,v) TVs...>       map   (mt5; LEN = pair count)
\   'R' 'F' 'N' 'U'              true / false / null / undef (mt7 simple, no payload)
\   's' <v:1>                    simple value (mt7 24..255 and <20 forms)
\
\ Canonical rules (ENTITY-CBOR-ENCODING v1.5): minimal int/length heads; length-then-lex
\ map-key ordering on ENCODED key bytes (§4.2.1); shortest-float ladder f16->f32->f64 with
\ canonical NaN 0x7e00 / ±Inf / ±0 (Rule 4/4a); recursive major-type-6 tag REJECTION on
\ decode (N2); full-consume + minimal-head re-validate.

\ ─────────────────────────── TV builders (into the arena) ───────────────────────────
\ Each returns the (c-addr u) span of the TV it just laid down.

: tv-int { sign n -- c-addr u }                 \ sign 0/1, n unsigned cell
  am-mark  [char] i b,  sign b,  n 8 >be  am-span ;
: tv-uint ( u -- c-addr u )  0 swap tv-int ;    \ non-negative
: tv-bytes { c-addr u -- c-addr u }
  am-mark  [char] b b,  u 4 >be  c-addr u bytes,  am-span ;
: tv-text { c-addr u -- c-addr u }
  am-mark  [char] t b,  u 4 >be  c-addr u bytes,  am-span ;
: tv-f64bits { bits -- c-addr u }
  am-mark  [char] f b,  bits 8 >be  am-span ;
: tv-true  ( -- c-addr u )  am-mark [char] R b, am-span ;
: tv-false ( -- c-addr u )  am-mark [char] F b, am-span ;
: tv-null  ( -- c-addr u )  am-mark [char] N b, am-span ;

\ ─────────────────────────── TV navigation ───────────────────────────
\ tv-tag ( c-addr u -- ch )
: tv-tag ( c-addr u -- ch )  drop c@ ;
\ a big-endian field of `w` bytes at addr+off
: @be { addr off w -- u }
  addr off +  { p }
  0                                              ( acc )
  w 0 ?do  8 lshift  p i + c@  or  loop ;

\ tv-node-len ( c-addr -- u )  the byte length of the TV node at c-addr.
\ DEFENSIVE RECURSION GUARD (§4.9 malformed-input never crashes): a well-formed TV nests only a
\ few levels deep, but a walk that lands on a GARBAGE address (e.g. after a state-corruption bug
\ or a hostile frame) reads an absurd child count and recurses without bound, overflowing the
\ data stack — an uncatchable crash. A depth cap turns that into a THROW the dispatch boundary
\ catches (→ a coded error, peer stays alive). 256 is far above any legitimate ECF nesting.
64 constant TV-DEPTH-CAP                           \ far above any legit ECF nesting
16 1024 * 1024 * constant TV-COUNT-CAP             \ a container's child count can't exceed the
                                                  \ 16-MiB frame cap in bytes — a larger count is
                                                  \ a corrupt/garbage TV; refuse it (§4.9).
-25010 constant E-TV-DEPTH
variable tv-depth
: tv-node-len { addr -- u }
  tv-depth @ TV-DEPTH-CAP > if E-TV-DEPTH throw then
  1 tv-depth +!
  addr c@ case
    [char] i of 10 endof                          \ tag + sign + 8
    [char] f of 9  endof                          \ tag + 8
    [char] R of 1  endof
    [char] F of 1  endof
    [char] N of 1  endof
    [char] U of 1  endof
    [char] s of 2  endof                          \ tag + 1
    [char] b of  addr 1 4 @be 5 +  endof
    [char] t of  addr 1 4 @be 5 +  endof
    [char] a of                                   \ tag + 4 + sum(children)
      addr 1 4 @be dup TV-COUNT-CAP > if E-TV-DEPTH throw then  { nch }  5  ( total )
      nch 0 ?do  dup addr + recurse +  loop
    endof
    [char] m of
      addr 1 4 @be 2* dup TV-COUNT-CAP > if E-TV-DEPTH throw then  { nnodes }  5
      nnodes 0 ?do  dup addr + recurse +  loop
    endof
    ( default ) 1
  endcase
  -1 tv-depth +! ;

\ ─────────────────────────── ENCODE ───────────────────────────
defer enc-node                                   \ forward ref for recursion via array/map

\ emit-head ( major arg -- )  CBOR head byte(s): (major<<5)|minimal-arg.
: emit-head ( major arg -- )
  swap 32 * swap                                 ( ib arg )
  dup 24 u< if       + b,  exit then             \ tiny
  \ +1 byte (arg 24..255): SWAP (not OVER) so `ib` is consumed, not left dangling.
  \ OVER kept `ib` on the stack after both b,; that stray cell (=major*32) only surfaces
  \ once the head grows past the tiny boundary (arg>=24) and, when this map/text is an
  \ element re-encoded inside an array loop, it clobbered the loop's source pointer (-9).
  dup 256 u< if      swap 24 + b, b, exit then   \ +1 byte
  dup 65536 u< if    swap 25 + b, 2 >be exit then
  dup 4294967296 u< if swap 26 + b, 4 >be exit then
  swap 27 + b, 8 >be ;

\ enc-int ( addr -- )  addr points at 'i'; emit mt0/mt1 head.
: enc-int ( addr -- )
  dup 1+ c@                                       ( addr sign )
  swap 2 8 @be                                    ( sign n )
  swap if 1 else 0 then swap emit-head ;

\ ── float encode: the shortest-float ladder over native f64 bits ──
\ We assemble the wire from REAL IEEE bits (A-FT-002). The half-float leg + the ladder
\ are hand-rolled bit arithmetic on those bits (A-FT-006). Helpers return a candidate or
\ -1 ("not exactly representable in this width").

\ split an f64 bit pattern
: f64-sign ( bits -- s )  63 rshift ;
: f64-exp  ( bits -- e )  52 rshift 2047 and ;
: f64-mant ( bits -- m )  1 52 lshift 1- and ;   \ low 52 bits

\ f64bits->f16  ( bits -- half | -1 )
: f64->f16 ( bits -- half )
  dup f64-sign 15 lshift { s16 }
  dup f64-exp { e }
  f64-mant { m }
  e 0= if
    m 0= if s16 exit then                          \ ±0
    -1 exit                                         \ subnormal f64 not f16
  then
  e 2047 = if -1 exit then                          \ inf/nan handled by caller
  e 1023 - { ue }                                   \ unbiased
  ue 15 > if -1 exit then
  ue -14 >= if
    m 42 rshift 42 lshift m <> if -1 exit then      \ low 42 mant bits must be 0
    m 42 rshift  ue 15 + 10 lshift or  s16 or  exit
  then
  ue -24 >= if
    1 52 lshift m or { full }                        \ implicit leading 1
    42 -14 ue - +  { sh }
    full sh rshift sh lshift full <> if -1 exit then \ low `sh` bits must be 0
    full sh rshift  s16 or  exit
  then
  -1 ;

\ f64bits->f32 ( bits -- f32 | -1 )
: f64->f32 ( bits -- f32 )
  dup f64-sign 31 lshift { s32 }
  dup f64-exp { e }
  f64-mant { m }
  e 0= if  m 0= if s32 exit then  -1 exit  then
  e 2047 = if -1 exit then
  e 1023 - { ue }
  ue 127 > if -1 exit then
  ue -126 >= if
    m 29 rshift 29 lshift m <> if -1 exit then
    m 29 rshift  ue 127 + 23 lshift or  s32 or  exit
  then
  ue -149 >= if
    1 52 lshift m or { full }
    29 -126 ue - +  { sh }
    full sh rshift sh lshift full <> if -1 exit then
    full sh rshift  s32 or  exit
  then
  -1 ;

: enc-float ( addr -- )  \ addr points at 'f'
  1+ 0 8 @be { bits }
  bits f64-exp 2047 = if                                        \ inf / nan
    $f9 b,
    bits f64-mant 0= if
      bits f64-sign if $fc b, $00 b, else $7c b, $00 b, then    \ ±Inf
    else
      $7e b, $00 b,                                             \ canonical NaN
    then
    exit
  then
  bits f64->f16 dup -1 <> if
    $f9 b,  2 >be  exit
  then drop
  bits f64->f32 dup -1 <> if
    $fa b,  4 >be  exit
  then drop
  $fb b,  bits 8 >be ;

\ keycmp ( a-addr a-u b-addr b-u -- -1|0|1 )  length-then-lex unsigned byte compare of
\ two ENCODED key byte spans (§4.2.1). Forth has no space-pad trap; compare bytes.
: keycmp { aa au ba bu -- n }
  au bu <> if  au bu u< if -1 else 1 then exit  then
  au 0 ?do
    aa i + c@  ba i + c@
    2dup <> if  u< if -1 else 1 then unloop exit  then  2drop
  loop  0 ;

\ Encoded-key sort: for a map with n pairs we record each pair's (key-TV-addr, val-TV-addr,
\ key-wire-addr, key-wire-len), sort by the encoded key bytes (length-then-lex, §4.2.1),
\ REWIND the intermediate key encoding, then re-encode key+value in sorted order into the
\ arena. The four parallel arrays live on the reentrant SCRATCH stack (nested maps each get
\ their own frame), NOT the output arena — so the map's output span stays clean. Re-encoding
\ sidesteps any source/destination overlap a byte-copy would risk.

\ enc-map ( addr -- )  addr at 'm'; canonical: sort entries by encoded key bytes.
: enc-map { addr -- }
  addr 1 4 @be { n }
  sc-mark { scm }                                 \ reentrant scratch frame
  n cells sc-alloc { map-kt }                     \ key TV addr array
  n cells sc-alloc { map-vt }                     \ value TV addr array
  n cells sc-alloc { map-ka }                     \ key wire addr (compare)
  n cells sc-alloc { map-ku }                     \ key wire len
  addr 5 +  { p }                                 \ first child TV addr
  am-mark { istart }                              \ intermediate key encoding starts here
  n 0 ?do
    p  map-kt i cells + !                          \ key TV addr
    p tv-node-len p +  { vp }                      \ value TV addr
    vp map-vt i cells + !
    p enc-node                                     ( key-wire-addr key-wire-len )
    map-ku i cells + !  map-ka i cells + !
    vp tv-node-len vp +  to p                       \ next key TV
  loop
  \ insertion-sort the parallel arrays by the encoded key bytes (length-then-lex, §4.2.1).
  \ Guard n>=2 — `1 0 ?do` (empty map) would wrap the counted loop.
  n 2 >= if
    n 1 ?do
      i { j }
      begin
        j 0> if
          map-ka j 1- cells + @  map-ku j 1- cells + @
          map-ka j    cells + @  map-ku j    cells + @  keycmp 0>
        else false then
      while
        map-kt j cells + @  map-kt j 1- cells + @  map-kt j cells + !  map-kt j 1- cells + !
        map-vt j cells + @  map-vt j 1- cells + @  map-vt j cells + !  map-vt j 1- cells + !
        map-ka j cells + @  map-ka j 1- cells + @  map-ka j cells + !  map-ka j 1- cells + !
        map-ku j cells + @  map-ku j 1- cells + @  map-ku j cells + !  map-ku j 1- cells + !
        j 1- to j
      repeat
    loop
  then
  istart rewind                                   \ discard the intermediate key encodings
  5 n emit-head
  n 0 ?do
    map-kt i cells + @ enc-node 2drop              \ re-encode key in sorted order
    map-vt i cells + @ enc-node 2drop              \ then value
  loop
  scm sc-free ;                                   \ pop the scratch frame

\ enc-node-impl ( addr -- wire-addr wire-len )  encode ONE TV node at addr; return the
\ (addr,len) span of the wire bytes appended to the arena.
: enc-node-impl { addr -- c-addr u }
  am-mark { mk }
  addr c@ case
    [char] i of  addr enc-int  endof
    [char] b of  2 addr 1 4 @be emit-head  addr 5 +  addr 1 4 @be  bytes,  endof
    [char] t of  3 addr 1 4 @be emit-head  addr 5 +  addr 1 4 @be  bytes,  endof
    [char] a of  addr 1 4 @be { na } 4 na emit-head
                 addr 5 +  na 0 ?do  dup enc-node 2drop  dup tv-node-len +  loop  drop
    endof
    [char] m of  addr enc-map  endof
    [char] f of  addr enc-float  endof
    [char] R of  $f5 b,  endof
    [char] F of  $f4 b,  endof
    [char] N of  $f6 b,  endof
    [char] U of  $f7 b,  endof
    [char] s of  addr 1+ c@ dup 24 u< if 224 + b, else $f8 b, b, then  endof
    ( default ) E-NON-CANONICAL-ECF throw
  endcase
  mk am-span ;
' enc-node-impl is enc-node

\ cbor-encode ( tv-addr tv-u -- wire-addr wire-u )  the public encoder. Encodes the TV
\ into fresh arena space AFTER the input TV and returns the wire span.
: cbor-encode ( c-addr u -- c-addr u )  drop enc-node ;

\ ─────────────────────────── DECODE ───────────────────────────
\ Decode reads from a wire span held in two globals (the input never moves); a cursor
\ walks it. Every node appended to the arena as a TV; a reject THROWs a leaf-kind code.
variable din-addr    variable din-len    variable dpos    \ input base, length, cursor(0-based)

: d-remain ( -- u )  din-len @ dpos @ - ;
: d-byte ( -- c )  d-remain 1 < if E-TRUNCATED-INPUT throw then
  din-addr @ dpos @ + c@  1 dpos +! ;
: d-take ( n -- addr )  \ return addr of n bytes at cursor, advance; reject if short
  dup d-remain > if E-TRUNCATED-INPUT throw then
  din-addr @ dpos @ +  swap dpos +! ;
: d-peek ( -- c )  d-remain 1 < if E-TRUNCATED-INPUT throw then
  din-addr @ dpos @ + c@ ;

\ d-head ( -- major arg )  read a CBOR head with minimal-argument enforcement.
: d-head ( -- major arg )
  d-byte  dup 5 rshift  swap 31 and { ai } { major }
  ai 24 u< if  major ai exit  then
  ai 24 = if
    d-byte dup 24 u< if E-NON-CANONICAL-ECF throw then  major swap exit
  then
  ai 25 = if
    2 d-take 0 2 @be dup 256 u< if E-NON-CANONICAL-ECF throw then  major swap exit
  then
  ai 26 = if
    4 d-take 0 4 @be dup 65536 u< if E-NON-CANONICAL-ECF throw then  major swap exit
  then
  ai 27 = if
    8 d-take 0 8 @be dup 4294967296 u< if E-NON-CANONICAL-ECF throw then  major swap exit
  then
  E-NON-CANONICAL-ECF throw ;

defer dec-node

\ f16/f32 bit patterns -> f64 bit pattern (widen on decode; store f64 internally).
: f16->f64 ( h -- bits )
  dup 15 rshift 63 lshift { s }
  dup 10 rshift 31 and { e }
  1023 and { m }                                    \ 10-bit mantissa
  e 0= if
    m 0= if s exit then                              \ ±0
    \ subnormal: normalize
    -14 { ue }
    begin m 1024 < while  m 2* to m  ue 1- to ue  repeat
    m 1023 and to m
    ue 1023 + 52 lshift  m 42 lshift or  s or exit
  then
  e 31 = if  s 2047 52 lshift or  m 42 lshift or  exit  then
  e 15 - 1023 + 52 lshift  m 42 lshift or  s or ;
: f32->f64 ( f -- bits )
  dup 31 rshift 63 lshift { s }
  dup 23 rshift 255 and { e }
  8388607 and { m }                                 \ 23-bit mantissa
  e 0= if
    m 0= if s exit then
    -126 { ue }
    begin m 8388608 < while  m 2* to m  ue 1- to ue  repeat
    m 8388607 and to m
    ue 1023 + 52 lshift  m 29 lshift or  s or exit
  then
  e 255 = if  s 2047 52 lshift or  m 29 lshift or  exit  then
  e 127 - 1023 + 52 lshift  m 29 lshift or  s or ;

\ shortest-float re-validation on decode: a wider encoding that would fit a narrower
\ width is non-canonical. Reuse the encode-side predicates.
: would-be-f16 ( bits -- f )  dup f64-exp 2047 = if drop true exit then  f64->f16 -1 <> ;
: would-be-f32 ( bits -- f )  dup f64-exp 2047 = if drop true exit then  f64->f32 -1 <> ;

: dec-simple ( -- c-addr u )   \ major 7 already peeked; consume the head byte here
  d-byte 31 and { ai }
  ai 20 = if tv-false exit then
  ai 21 = if tv-true  exit then
  ai 22 = if tv-null  exit then
  ai 23 = if  am-mark [char] U b, am-span exit then
  ai 24 = if
    d-byte dup 32 u< if E-NON-CANONICAL-ECF throw then
    am-mark [char] s b, b, am-span exit
  then
  ai 25 = if  2 d-take 0 2 @be f16->f64  tv-f64bits exit  then
  ai 26 = if
    4 d-take 0 4 @be f32->f64  dup would-be-f16 if E-NON-CANONICAL-ECF throw then
    tv-f64bits exit
  then
  ai 27 = if
    8 d-take 0 8 @be  dup would-be-f16 over would-be-f32 or if E-NON-CANONICAL-ECF throw then
    tv-f64bits exit
  then
  ai 20 u< if  am-mark [char] s b, ai b, am-span exit  then
  E-NON-CANONICAL-ECF throw ;

\ dec-node-impl ( -- c-addr u )  decode ONE item at the cursor, append its TV, return span.
: dec-node-impl ( -- c-addr u )
  d-peek 5 rshift { m0 }
  m0 6 = if E-TAG-REJECTED throw then               \ N2: major-type-6 tag rejected
  m0 7 = if dec-simple exit then
  d-head { major arg }
  major 0 = if  0 arg tv-int exit  then
  major 1 = if  1 arg tv-int exit  then             \ value = -1-arg; TV stores n=arg,sign=1
  major 2 = if  arg d-take arg tv-bytes exit  then
  major 3 = if  arg d-take arg tv-text exit  then
  major 4 = if
    am-mark { mk }  [char] a b,  arg 4 >be
    arg 0 ?do  dec-node 2drop  loop  mk am-span exit
  then
  major 5 = if
    am-mark { mk }  [char] m b,  arg 4 >be
    0 { prevka } 0 { prevku }                        \ previous key wire span
    arg 0 ?do
      din-addr @ dpos @ +  { kaddr }                 \ key wire start addr
      dec-node 2drop                                  \ decode key -> TV; discard TV span
      din-addr @ dpos @ +  kaddr -  { klen }          \ key wire len = cursor - kaddr
      i 0> if
        prevka prevku kaddr klen keycmp 0>= if E-NON-CANONICAL-ECF throw then
      then
      kaddr to prevka  klen to prevku
      dec-node 2drop                                   \ value TV
    loop
    mk am-span exit
  then
  E-NON-CANONICAL-ECF throw ;
' dec-node-impl is dec-node

\ cbor-decode ( wire-addr wire-u -- tv-addr tv-u )  the public decoder. Full-consume:
\ trailing bytes are rejected. THROWs a leaf-kind on any canonical violation.
: cbor-decode ( c-addr u -- c-addr u )
  din-len !  din-addr !  0 dpos !
  dec-node
  d-remain 0<> if E-TRUNCATED-INPUT throw then ;
