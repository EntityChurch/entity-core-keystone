\ entity-core-protocol-forth — fixed-width-cell integer boundary self-test (A-FT-001).
\
\ The profile mandates a [2^63, 2^64-1] self-test for the fixed-width-int class: a 64-bit
\ cell holds uint64 as ONE UNSIGNED cell, and the signed/unsigned seam at the top of the
\ range (values >= 2^63) must encode as mt0 with an 8-byte head — the corpus tops out at
\ 2^63-1 (int.10), so this test covers the range the corpus can't. It also covers the mt1
\ minimum (-2^64), whose magnitude n = 2^64-1 needs a full unsigned cell (value = -1-n).
\
\ Usage: gforth test/int-boundary.fs   (no crypto / FFI needed — pure codec)

warnings off
require ../src/buf.fs
require ../src/varint.fs
require ../src/base58.fs
require ../src/cbor.fs
require ../src/tv.fs

variable fails  0 fails !
: .h base @ >r hex 0 ?do dup i + c@ 0 <# # # #> type space loop drop r> base ! ;
: span-eq ( aa au ba bu -- flag )  compare 0= ;

\ check ( sign n expect-addr expect-u -- )  encode the int TV, compare to expected wire.
: check { sign n ea eu -- }
  arena-reset scratch-reset
  sign n tv-int cbor-encode  ( wa wu )
  ea eu span-eq if ." PASS" else 1 fails +! ." FAIL want=" ea eu .h ." got=" then
  ."  " cr ;

\ expected wire bytes helper (count then bytes on stack, MSB first as pushed).
create eb 16 allot
: expect { n -- ea eu }  n 0 ?do eb i + c! loop eb n ;

: run
  \ 2^63 = 9223372036854775808 = 0x8000000000000000 -> mt0 1b 8000000000000000
  ." mt0 2^63:        " 0 1 63 lshift  ( n=2^63 )
     $00 $00 $00 $00 $00 $00 $00 $80 $1b 9 expect check
  \ 2^64-1 = 0xFFFFFFFFFFFFFFFF (all ones, unsigned) -> 1b ffffffffffffffff
  ." mt0 2^64-1:      " 0  -1  ( -1 as unsigned cell = 2^64-1 )
     $ff $ff $ff $ff $ff $ff $ff $ff $1b 9 expect check
  \ mt1 -1-2^63 : sign=1, n=2^63 -> value = -(2^63+1) ; head 3b 8000000000000000
  ." mt1 -(2^63+1):   " 1 1 63 lshift
     $00 $00 $00 $00 $00 $00 $00 $80 $3b 9 expect check
  \ mt1 minimum -2^64 : sign=1, n=2^64-1 -> 3b ffffffffffffffff
  ." mt1 -2^64:        " 1 -1
     $ff $ff $ff $ff $ff $ff $ff $ff $3b 9 expect check
  \ round-trip: decode 1b ffffffffffffffff then re-encode -> identical
  arena-reset scratch-reset
  eb $ff $ff $ff $ff $ff $ff $ff $ff $1b 9 expect drop
  eb 9 cbor-decode cbor-encode  eb 9 span-eq
  ." decode/re-encode 2^64-1: " if ." PASS" else 1 fails +! ." FAIL" then cr
  cr fails @ 0= if ." === int-boundary: OK ===" else ." === int-boundary: FAILED ===" then cr
  fails @ 0> if 1 else 0 then (bye) ;
run
