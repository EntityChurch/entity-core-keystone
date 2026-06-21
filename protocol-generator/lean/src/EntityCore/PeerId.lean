/-
  peer_id construction (V7 §1.2 / §7.3):

    peer_id = Base58( varint(key_type) ‖ varint(hash_type) ‖ digest )

  `formatPeerId` takes the abstract `(key_type, hash_type, digest)` components
  (the corpus `peer_id.*` form). The §1.5 canonical-hash-type derivation (Ed25519
  → identity-multihash, others → SHA-256-form) belongs to the protocol path (S3),
  not the encode-only conformance surface.
-/
import EntityCore.Codec.Varint
import EntityCore.Base58

namespace EntityCore.PeerId

/-- Format peer-id components to a Base58 string. -/
def formatPeerId (keyType hashType : Nat) (digest : ByteArray) : String :=
  let payload :=
    EntityCore.Codec.Varint.varintEncode keyType
      ++ EntityCore.Codec.Varint.varintEncode hashType
      ++ digest
  EntityCore.Base58.base58Encode payload

end EntityCore.PeerId
