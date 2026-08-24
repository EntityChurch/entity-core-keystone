\ entity-core-protocol-forth — S2 FULL codec conformance (v0.8.0 corpus, 69 vectors).
\
\ Walks the pinned corpus (decoded with OUR OWN decoder) and asserts, per vector:
\ encode(reconstructed input) == canonical bytes; and decode(canonical) REJECTS (throws a
\ leaf-kind) where kind = decode_reject. Class B (content_hash / signature) is reconstructed
\ through the FFI crypto binding (src/ffi/crypto.fs). A codec reject is a THROW caught here.
\
\ Usage (from the forth dir, with libentitycore_codec on LIBRARY_PATH+LD_LIBRARY_PATH):
\   gforth test/conformance.fs <corpus.cbor>
\ The Makefile / run-s2.sh supply the path.

require ../src/buf.fs
require ../src/varint.fs
require ../src/base58.fs
require ../src/cbor.fs
require ../src/tv.fs
require ../src/peer-id.fs
require ../src/ffi/crypto.fs
require ../src/hash.fs

variable npass  variable nfail  variable nskip
0 npass !  0 nfail !  0 nskip !

: .hex ( addr u -- )  base @ >r hex 0 ?do dup i + c@ 0 <# # # #> type space loop drop r> base ! ;
: span-eq ( aa au ba bu -- flag )  compare 0= ;

\ starts-with ( str-addr str-u pfx-addr pfx-u -- flag )  does str begin with pfx?
: starts-with { sa su pa pu -- flag }
  su pu < if false exit then  sa pu pa pu compare 0= ;

: ok  ( -- )  1 npass +! ;
: fail. { ida idu -- }  1 nfail +!  cr ." FAIL " ida idu type ."  " ;

\ pass/fail a category by comparing a produced wire span to the canonical span.
: judge { wa wu cana canu ida idu -- }
  wa wu cana canu span-eq if ok else
    ida idu fail. ." want=" cana canu .hex ." got=" wa wu .hex
  then ;

\ vec is a map TV: keys id, kind, input, canonical, description.
: process-vec { vec -- }
  vec s" id"        tv-map-get tv-payload  { idu } { ida }
  vec s" kind"      tv-map-get { kindtv }
  vec s" canonical" tv-map-get tv-payload  { canu } { cana }
  vec s" input"     tv-map-get { intv }               \ 0 for decode_reject

  \ decode_reject: decode canonical, expect a THROW.
  kindtv s" decode_reject" tv-text-eq if
    cana canu ['] cbor-decode catch if              \ threw?
      2drop ok                                       \ ( cana canu ) left -> drop; good
    else
      2drop ida idu fail. ." decoded OK, expected reject"
    then
    exit
  then

  \ encode_equal per category.
  ida idu s" peer_id." starts-with if
    intv s" key_type"  tv-map-get tv-int-value        ( kt )
    intv s" hash_type" tv-map-get tv-int-value        ( kt ht )
    intv s" digest"    tv-map-get tv-payload          ( kt ht daddr du )
    peerid-format tv-text cbor-encode                  ( wa wu )
    cana canu ida idu judge  exit
  then
  ida idu s" content_hash." starts-with if
    intv s" type" tv-map-get tv-payload               ( taddr tu )
    intv s" data" tv-map-get dup tv-node-len          ( taddr tu daddr du )
    intv s" format_code" tv-map-get                    ( ... fmt-tv|0 )
    dup 0= if drop 0 else tv-int-value then            ( taddr tu daddr du fmt )
    hash-content                                       ( wa wu )
    cana canu ida idu judge  exit
  then
  ida idu s" signature." starts-with if
    intv s" seed"   tv-map-get tv-payload drop         ( seed-addr )
    intv s" entity" tv-map-get dup tv-node-len         ( seed-addr ent-addr ent-u )
    cbor-encode                                        ( seed-addr wa wu )
    crypto-ed25519-sign                                 ( sig-addr 64 )
    cana canu ida idu judge  exit
  then
  \ default class A: encode the input TV directly.
  intv dup tv-node-len cbor-encode                     ( wa wu )
  cana canu ida idu judge ;

: run-corpus { path-addr path-u -- }
  arena-reset  scratch-reset
  path-addr path-u slurp-file  { wu } { wa }
  wa wu cbor-decode  { topu } { top }                  \ top TV = array of vectors
  top c@ [char] a <> if ." FATAL: corpus top not array" cr 2 (bye) then
  top tv-count { n }
  n 0 ?do  top i tv-array-elem process-vec  loop
  cr cr ." === conformance: " n . ." vectors — "
  npass @ . ." pass / " nfail @ . ." fail / " nskip @ . ." skip ===" cr
  nfail @ 0> if 1 else 0 then (bye) ;

: main
  next-arg dup 0= if
    2drop s" ../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"
  then
  run-corpus ;
main
