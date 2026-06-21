/-
  Crypto FFI bindings — the spec's own trust boundary (S1 1a §4).

  These `@[extern]` opaque defs bridge to `libentitycore_codec` via the C shim
  (`ffi/ec_ffi_shim.c`). Being `@[extern]` they do NOT reduce in the kernel, so
  any property of the hash/signature is AXIOMATIC in Lean — which is exactly the
  trust line V7 itself draws (it cites Ed25519/SHA-256 normatively but does not
  define them). Prove the protocol, trust the primitive. NEVER `@[extern]` the
  pure proven core; the boundary lives only here.
-/
namespace EntityCore.Crypto

/-- SHA-256 of `data` (32-byte digest). C-ABI `ec_sha256`. -/
@[extern "ec_lean_sha256"]
opaque sha256 (data : @& ByteArray) : ByteArray

/-- Deterministic Ed25519 signature (64 bytes) of `msg` under the 32-byte
`seed` (the RFC-8032 secret key). C-ABI `ec_ed25519_sign`. -/
@[extern "ec_lean_ed25519_sign"]
opaque ed25519Sign (seed msg : @& ByteArray) : ByteArray

/-- A fresh RFC-8032 Ed25519 keypair as a 64-byte buffer `priv32 ‖ pub32`
(C-ABI `ec_ed25519_keygen`). The S3 peer mints its identity from this at boot.
`IO` because it draws fresh randomness. Takes a scalar arg (ignored) rather than
`Unit`: Lean erases a `Unit` extern arg, which breaks the C arg count and faults
on an obj-returning IO extern — mirroring `Net.randomBytes`'s proven shape. -/
@[extern "ec_lean_ed25519_keygen"]
opaque ed25519Keygen (salt : UInt32) : IO ByteArray

/-- Deterministically derive the 32-byte Ed25519 public key from a 32-byte
`seed` (the RFC-8032 secret key). C-ABI `ec_ed25519_seed_to_pubkey`. Pure (no
randomness): a fixed seed always yields the same pubkey — this is what lets a
peer carry a *persistent* identity loaded from an on-disk keypair (`--name`). -/
@[extern "ec_lean_ed25519_seed_to_pubkey"]
opaque ed25519SeedToPubkey (seed : @& ByteArray) : ByteArray

/-- Verify a 64-byte Ed25519 `sig` over `msg` under the 32-byte `pub`
(C-ABI `ec_ed25519_verify`). The §5.5 chain-walk crypto boundary: opaque, so the
*fact* of signature validity is an axiomatic input the pure verdict core consumes
(it is never reasoned about — exactly the spec's own trust line). -/
@[extern "ec_lean_ed25519_verify"]
opaque ed25519Verify (pub msg sig : @& ByteArray) : Bool

/-- Provenance of the linked codec library (`ec_impl_info`). -/
@[extern "ec_lean_impl_info"]
opaque implInfo (u : Unit) : String

end EntityCore.Crypto
