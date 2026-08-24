\ entity-core-protocol-forth — crypto (§9.1 floor) over the codec C-ABI.
\
\ A-FT-005 (the KEY differentiator vs Rexx): gforth's libcc `c-function` is a GENUINE
\ IN-PROCESS libffi binding — libcc.fs uses libtool+gcc to compile a wrapper .so and
\ dlopen it; `s" entitycore_codec" add-lib` links -lentitycore_codec. No subprocess, no
\ FIFO, no co-process daemon (Rexx's whole S3 transport pain does not arise). We bind the
\ SHA-256/384 + Ed25519 floor symbols from ffi-generator/c-abi/spec/entitycore_codec.h.
\
\ GOTCHA (A-FT-005, banked): gforth caches the compiled wrapper .so in
\ ~/.gforth/libcc-named keyed by the c-library NAME — clear it on a symbol-set change or a
\ stale .so binds old symbols. The umbrella loader / run-s2.sh clear it before loading.
\
\ Buffers are (ptr,len); outputs are caller-allocated. All fallible calls return int32
\ (EC_OK = 0). We surface a non-zero status as E-CRYPTO.

require libcc.fs

c-library entitycore_codec
  s" entitycore_codec" add-lib
  \c #include <stdint.h>
  \c #include <stddef.h>
  \c #include "entitycore_codec.h"
  \ int32_t ec_sha256(const uint8_t*, size_t, uint8_t* /*32*/);
  c-function ec-sha256 ec_sha256 a n a -- n
  \ int32_t ec_sha384(const uint8_t*, size_t, uint8_t* /*48*/);
  c-function ec-sha384 ec_sha384 a n a -- n
  \ int32_t ec_ed25519_seed_to_pubkey(const uint8_t* /*32*/, uint8_t* /*32*/);
  c-function ec-ed25519-seed-to-pubkey ec_ed25519_seed_to_pubkey a a -- n
  \ int32_t ec_ed25519_sign(const uint8_t* /*32 priv*/, const uint8_t*, size_t, uint8_t* /*64*/);
  c-function ec-ed25519-sign ec_ed25519_sign a a n a -- n
  \ int32_t ec_ed25519_verify(const uint8_t* /*32 pub*/, const uint8_t*, size_t, const uint8_t* /*64*/);
  c-function ec-ed25519-verify ec_ed25519_verify a a n a -- n
  \ const char* ec_impl_info(void);
  c-function ec-impl-info ec_impl_info -- a
end-c-library

\ Output scratch buffers (single-threaded peer; one op at a time).
create sha-out    48 allot
create pub-out    32 allot
create sig-out    64 allot

: ck ( status -- )  0<> if E-CRYPTO throw then ;

\ crypto-sha256 ( data-addr data-u -- digest-addr 32 )  append the 32-byte digest to the
\ arena (so the result outlives the shared sha-out scratch) and return its span.
: crypto-sha256 ( c-addr u -- c-addr u )
  sha-out ec-sha256 ck
  am-mark  sha-out 32 bytes,  am-span ;

: crypto-sha384 ( c-addr u -- c-addr u )
  sha-out ec-sha384 ck
  am-mark  sha-out 48 bytes,  am-span ;

\ crypto-ed25519-pubkey ( seed-addr seed-u(=32) -- pub-addr 32 )
: crypto-ed25519-pubkey ( c-addr u -- c-addr u )
  drop pub-out ec-ed25519-seed-to-pubkey ck
  am-mark  pub-out 32 bytes,  am-span ;

\ crypto-ed25519-sign ( seed-addr msg-addr msg-u -- sig-addr 64 )  Ed25519 sign msg with
\ the 32-byte SEED (the ABI's priv is the seed for RFC 8032).
: crypto-ed25519-sign { saddr maddr mu -- c-addr u }
  saddr maddr mu sig-out ec-ed25519-sign ck
  am-mark  sig-out 64 bytes,  am-span ;

\ crypto-ed25519-verify ( pub-addr msg-addr msg-u sig-addr -- flag )  1 valid / 0 invalid.
: crypto-ed25519-verify { paddr maddr mu sigaddr -- flag }
  paddr maddr mu sigaddr ec-ed25519-verify 0= ;

\ crypto-impl-info ( -- c-addr u )  provenance string (ec_impl_info), for the report.
: crypto-impl-info ( -- c-addr u )
  ec-impl-info  dup  begin dup c@ while 1+ repeat over - ;
