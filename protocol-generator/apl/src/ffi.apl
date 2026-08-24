⍝ entity-core-protocol-apl — src/ffi.apl
⍝
⍝ The FFI half of the FFI-hybrid codec: crypto floor (§9.1), SHA-256/384, and
⍝ base58 peer-id ride libentitycore_codec through the GNU APL NATIVE FUNCTION
⍝ shim (src/ext/ec_native.cc -> ec_native.so). No native audited APL crypto
⍝ exists, and APL has no exact integer past 2^63 so base58 long-division would be
⍝ lossy (A-APL-010) — hence the C-ABI. The CBOR VALUE codec stays PURE APL
⍝ (cbor.apl); only crypto/base58 cross here.
⍝
⍝ 'src/ext/ec_native.so' ⎕FX 'EcNative' loads the shim (apl -export-dynamic
⍝ resolves apl's own symbols at load; the shim resolves libentitycore_codec via
⍝ its -rpath). A single DYADIC native fn  Z ← opcode EcNative B  is fanned out
⍝ into idiomatic wrappers below. Byte vectors cross as APL integer cells 0..255
⍝ (the array byte model). Loading FAILS CLOSED if the .so is missing.

ecNativeSoPath←'src/ext/ec_native.so'
ecFxName←ecNativeSoPath ⎕FX 'EcNative'

⍝ ── idiomatic wrappers (bytes in / bytes out) ──
EcSha256←{1 EcNative ⍵}                       ⍝ data       -> 32 bytes
EcSha384←{2 EcNative ⍵}                       ⍝ data       -> 48 bytes
EcSeedPub←{3 EcNative ⍵}                      ⍝ seed(32)   -> pubkey(32)
EcSign←{4 EcNative ⍵}                         ⍝ (priv)(msg)         -> sig(64)
EcVerify←{1⊃5 EcNative ⍵}                     ⍝ (pub)(msg)(sig)     -> rc scalar
EcPeeridFmt←{6 EcNative ⍵}                    ⍝ (keyType)(hashType)(digest) -> base58 ASCII
EcPeeridParse←{7 EcNative ⍵}                  ⍝ base58 ASCII -> (keyType hashType), digest
