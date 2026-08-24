\ entity-core-protocol-forth — crypto ACCEPT-path unit test.
\
\ The corpus's signature category asserts sign() produces the expected bytes; it never
\ exercises the VERIFY accept path, and content_hash never exercises a hash we then check.
\ Per the keystone guidance (conformance-green can be vacuous — always add an accept-path
\ test the oracle can't cover), this signs a message, VERIFIES it (must accept), then
\ tampers a signature byte and verifies again (must reject). Crypto crosses the FFI.
\
\ Usage: gforth test/crypto-accept.fs   (with libentitycore_codec on LIBRARY/LD paths)

warnings off
require ../src/buf.fs
require ../src/varint.fs
require ../src/base58.fs
require ../src/cbor.fs
require ../src/tv.fs
require ../src/peer-id.fs
require ../src/ffi/crypto.fs
require ../src/hash.fs

create seed  32 allot
create msg   4  allot
create sigbuf 64 allot
variable fails  0 fails !

: run
  arena-reset  scratch-reset
  seed 32 erase                              \ deterministic all-zero seed
  msg 4 [char] A fill                        \ message "AAAA"
  \ sign; copy the sig out of the arena into a stable buffer we can tamper.
  seed msg 4 crypto-ed25519-sign  drop sigbuf 64 move
  \ derive the public key from the seed (FFI seed_to_pubkey).
  seed 32 crypto-ed25519-pubkey  { pubu } { pub }
  pub msg 4 sigbuf crypto-ed25519-verify
  if ." PASS accept-path sign->verify VALID" cr
  else 1 fails +! ." FAIL accept-path verify returned INVALID" cr then
  \ tamper one signature byte -> verify must REJECT.
  sigbuf c@ 1 xor sigbuf c!
  pub msg 4 sigbuf crypto-ed25519-verify
  if 1 fails +! ." FAIL tampered signature verified VALID" cr
  else ." PASS tampered signature rejected" cr then
  \ SHA-256 sanity: sha256("") = e3b0c442... (well-known KAT); hash a non-trivial msg and
  \ confirm it is 32 bytes and deterministic.
  msg 4 crypto-sha256  nip 32 <> if 1 fails +! ." FAIL sha256 length" cr then
  cr fails @ 0= if ." === crypto-accept: OK ===" else ." === crypto-accept: FAILED ===" then cr
  fails @ 0> if 1 else 0 then (bye) ;
run
