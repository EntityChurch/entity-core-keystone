/-
  Identity (L1) — peer_id derivation and signature verification (§1.5, §3.5,
  §7.3, §7.4). A peer's identity is an Ed25519 keypair; the public artifacts
  derive from the public key.

  §1.5 v7.65 canonical Ed25519 peer_id is identity-multihash form:
    key_type = 0x01, hash_type = 0x00 (identity), digest = the RAW public_key.
  NOTE: §7.4's "NORMATIVE" pseudocode still shows the pre-v7.65 SHA-256 form
  (hash_type=0x01, SHA256(public_key)), which contradicts the §1.5 canonical-form
  table. We follow §1.5 (the later, specific contract); the divergence is the
  cohort's A-OC-007 / A-SW-008 finding — re-confirmed by this peer (§7. log).

  `verifySignature` is the §5.5 chain-walk crypto boundary: it calls the opaque
  FFI `ed25519Verify`, so it is part of the unproven shell, not the pure core.
-/
import EntityCore.Model
import EntityCore.PeerId
import EntityCore.Crypto

namespace EntityCore.Identity

open EntityCore (Value)
open EntityCore.Model

/-- §1.5 Ed25519 → identity-multihash peer_id: `Base58(varint(1) ‖ varint(0) ‖ pub)`. -/
def peerIdOfPubkey (publicKey : ByteArray) : String :=
  EntityCore.PeerId.formatPeerId 0x01 0x00 publicKey

/-- The `key_type` of a Base58 peer_id (its leading LEB128 varint), for the §4.6
unsupported-key-type gate (AGILITY-UNKNOWN-1: a peer_id carrying key_type 0xFD is
rejected at authenticate even though the field still says "ed25519"). `none` if
the peer_id does not decode. -/
def peerIdKeyType (pid : String) : Option Nat := do
  let bytes ← EntityCore.Base58.base58Decode pid
  let rec go (i shift acc fuel : Nat) : Option Nat :=
    match fuel with
    | 0 => none
    | fuel + 1 =>
      if h : i < bytes.size then
        let byte := bytes[i]!.toNat
        let acc := acc + (byte % 128) * (2 ^ shift)
        if byte < 128 then some acc else go (i + 1) (shift + 7) acc fuel
      else none
  go 0 0 0 10

/-- The `system/peer` entity (§3.5, v7.65: NO peer_id in the hashable basis). -/
def peerEntityOfPubkey (publicKey : ByteArray) : Entity :=
  Model.make "system/peer"
    (.map [(.text "public_key", .bytes publicKey), (.text "key_type", .text "ed25519")])

/-- Verify a `system/signature` entity against the signer's `system/peer` entity:
read the signer's `public_key`, verify the 64-byte `signature` over the 33-byte
`target` content_hash. The §5.2 signer-hash check is the caller's responsibility.
Calls the opaque FFI verifier → this is the trust boundary, never the pure core. -/
def verifySignature (signature signerPeer : Entity) : Bool :=
  match bytesField signature "target", bytesField signature "signature",
        bytesField signerPeer "public_key" with
  | some target, some sigBytes, some pub => EntityCore.Crypto.ed25519Verify pub target sigBytes
  | _, _, _ => false

/-- The local peer's own identity (a fresh Ed25519 keypair minted at boot). The
32-byte `priv` is the RFC-8032 seed/secret key (`ed25519Keygen` output), kept for
signing; everything else derives from the public key. -/
structure Self where
  priv : ByteArray
  publicKey : ByteArray
  peerId : String
  peerEntity : Entity
  identityHash : ByteArray
  deriving Inhabited

/-- Mint a fresh identity (validate-peer dials whatever peer listens, so a fresh
per-boot keypair is sufficient; no fixed seed→pubkey derivation needed). -/
def generate : IO Self := do
  let kp ← EntityCore.Crypto.ed25519Keygen 0
  let priv := kp.extract 0 32
  let pub := kp.extract 32 64
  let pe := peerEntityOfPubkey pub
  pure { priv := priv, publicKey := pub, peerId := peerIdOfPubkey pub,
         peerEntity := pe, identityHash := pe.hash }

/-- A *persistent* identity from a fixed 32-byte Ed25519 `seed` (the RFC-8032
secret key, loaded from an on-disk keypair via `--name`). Mirrors `generate` but
derives the public key deterministically from the seed (no randomness), so the
same seed always yields the same peer_id — and matches the Go validator's
`FromSeed(seed).PeerID()`. The validator's multisig accept-path probe co-signs AS
the peer, so it needs the peer's keypair on disk to share this identity. -/
def ofSeed (seed : ByteArray) : Self :=
  let pub := EntityCore.Crypto.ed25519SeedToPubkey seed
  let pe := peerEntityOfPubkey pub
  { priv := seed, publicKey := pub, peerId := peerIdOfPubkey pub,
    peerEntity := pe, identityHash := pe.hash }

/-- Sign an entity the PROTOCOL way: over its 33-byte content_hash (§7.3), and
build the `system/signature` entity (§3.5). Deterministic Ed25519, so pure. -/
def signEntity (self : Self) (target : Entity) : Entity :=
  let sigBytes := EntityCore.Crypto.ed25519Sign self.priv target.hash
  Model.make "system/signature"
    (.map [(.text "target", .bytes target.hash),
           (.text "signer", .bytes self.identityHash),
           (.text "algorithm", .text "ed25519"),
           (.text "signature", .bytes sigBytes)])

end EntityCore.Identity
