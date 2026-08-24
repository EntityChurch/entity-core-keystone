\ entity-core-protocol-forth — tagged-value (TV) navigation helpers.
\
\ The TV rep is the self-delimiting byte record produced by the codec (see cbor.fs).
\ These walk it: array element, map lookup by text key, scalar unwrap. The value-model
\ layer the harness (and the S3 peer) build on. A TV is (c-addr u); helpers take the
\ addr and use tv-node-len to skip.

\ tv-count ( addr -- n )  element/pair count of an array/map TV (the 4-byte LEN field).
: tv-count ( addr -- n )  1 4 @be ;

\ tv-array-elem ( addr idx -- elem-addr )  addr of the idx-th element TV of an array.
: tv-array-elem { addr idx -- eaddr }
  addr 5 +  idx 0 ?do  dup tv-node-len +  loop ;

\ tv-payload ( addr -- p-addr p-len )  bytes payload of a leaf TV ('b'/'t': the LEN-framed
\ payload). For 'i' returns the 8-byte magnitude span; caller knows the tag.
: tv-payload ( addr -- p-addr p-len )
  dup c@ [char] i = if  1+ 1+ 8  exit  then      \ int magnitude: skip tag+sign
  dup 1 4 @be  swap 5 +  swap ;                  \ ( addr+5 len )

\ tv-text-eq ( addr c-addr u -- flag )  is the text/bytes TV at addr equal to the span?
: tv-text-eq { addr saddr su -- flag }
  addr tv-payload  saddr su compare 0= ;          \ compare handles length + bytes

\ tv-map-get ( map-addr key-addr key-u -- val-addr | 0 )  value TV bound to TEXT key, or 0.
: tv-map-get { maddr kaddr ku -- vaddr }
  maddr c@ [char] m <> if 0 exit then
  maddr tv-count { n }
  maddr 5 +  { p }
  n 0 ?do
    p tv-node-len p +  { vp }                    \ value addr = p + key-node-len
    p c@ [char] t = if
      p tv-payload  kaddr ku compare 0= if
        vp unloop exit                           \ found: return the value TV addr
      then
    then
    vp tv-node-len vp +  to p                    \ next pair addr
  loop
  0 ;

\ tv-has ( map-addr key-addr key-u -- flag )
: tv-has ( maddr kaddr ku -- flag )  tv-map-get 0<> ;

\ tv-int-value ( addr -- value )  the (possibly negative) integer value of an 'i' TV, as a
\ signed cell. For mt0 = n; for mt1 = -1-n. (Callers using this must ensure the value fits
\ a signed cell — true for all format/key/hash codes and small ints in the corpus.)
: tv-int-value ( addr -- n )
  dup 1+ c@  swap 2 8 @be                          ( sign n )
  swap if  -1 swap -  else  then ;                 \ -1 - n  |  n
