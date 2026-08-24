\ entity-core-protocol-forth — unsigned LEB128 varint (§7.3 multicodec, N1).
\
\ N1: all format-code / key-type / hash-type framing routes through a REAL varint
\ primitive, never a hard-coded single byte. The currently-allocated codes are < 0x80
\ (one byte), so this is byte-identical to a fixed field today — but peer_id.3 and
\ content_hash.4 carry synthetic codes >= 0x80 that widen to 2 bytes, proving the
\ primitive. Pure Forth over RSHIFT / AND + b, into the arena.
\
\ Values are unsigned 64-bit cells. gforth's RSHIFT is a LOGICAL (unsigned) shift, so
\ a code with bit 63 set still shifts in zeros — correct for the full u64 range.

\ varint-encode ( u -- )  append the unsigned LEB128 encoding of u to the arena.
: varint-encode ( u -- )
  begin
    dup 7 rshift             ( n high )        \ n >> 7 (logical, unsigned)
    dup 0<> if
      swap 127 and 128 or b, ( high )          \ low7 | 0x80 continuation
    else
      drop 127 and b,        ( )               \ final low7
      exit
    then
  again ;

\ varint-to ( u buf-addr -- nbytes )  write the unsigned LEB128 encoding of u to a plain
\ byte buffer (NOT the arena); return the byte count. For assembling small fixed frames
\ (peer_id prefix) without contaminating the output arena.
: varint-to { u buf -- n }
  0 { c }
  begin
    u 7 rshift  { hi }                             \ u >> 7
    hi 0<> if  u 127 and 128 or  else  u 127 and  then
    buf c + c!  c 1+ to c
    hi to u
    hi 0=
  until
  c ;

\ varint-decode ( c-addr u -- value nconsumed )  decode an unsigned LEB128 varint at
\ the start of the (addr,len) span; reject a truncated or non-minimal (trailing 0x00
\ continuation byte) form. Multi-accumulator loop -> locals (A-FT-009 escape hatch).
: varint-decode { c-addr u -- value nconsumed }
  0 0 0 { result shift nb }
  begin
    nb u >= if E-BAD-VARINT throw then
    c-addr nb + c@                              ( byte )
    dup 127 and  shift lshift  result +  to result
    shift 7 + to shift
    nb 1+ to nb
    128 and 0=                                  \ continuation bit clear?
  until
  \ minimality: a >1-byte varint whose last byte is 0x00 is non-minimal.
  nb 1 > c-addr nb 1- + c@ 0= and if E-BAD-VARINT throw then
  result nb ;
