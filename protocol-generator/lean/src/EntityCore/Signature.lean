/-
  Ed25519 signing (V7 §7.3) over the FFI boundary.

  Ed25519 is RFC-8032 deterministic: a fixed 32-byte seed + fixed message gives a
  fixed 64-byte signature — exactly what the corpus `signature.*` vectors pin.

  What is signed: the PROTOCOL signing path signs over the content_hash bytes; the
  codec CORPUS `signature.*` vectors sign over the ECF preimage `ECF{type,data}`
  (the locked-corpus convention, cf. Swift A-SW-007 / Haskell). Both are just
  "sign these bytes"; this module signs whatever message it is given.
-/
import EntityCore.Codec.Value
import EntityCore.ContentHash
import EntityCore.Crypto

namespace EntityCore.Signature

open EntityCore (Value)

/-- Deterministically sign `msg` with a 32-byte Ed25519 seed → 64-byte signature. -/
def signBytes (seed msg : ByteArray) : ByteArray :=
  EntityCore.Crypto.ed25519Sign seed msg

/-- Sign an entity the corpus way: over its ECF preimage `ECF{type,data}`. -/
def signEntity (seed : ByteArray) (typ : String) (dataV : Value) : ByteArray :=
  signBytes seed (EntityCore.ContentHash.ecfOfEntity typ dataV)

end EntityCore.Signature
