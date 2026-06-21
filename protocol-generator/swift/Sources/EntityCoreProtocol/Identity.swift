// Identity.swift — L1 identity bundle: keypair, system/peer, peer_id, signing.
//
// SPEC-FIRST peer_id construction (§1.5, the canonical-form table). For Ed25519
// (key_type 0x01) the canonical hash_type is 0x00 identity-multihash and the
// digest IS the raw 32-byte public key (v7.64/v7.65). The peer_id string is
//   Base58(varint(0x01) || varint(0x00) || public_key).
//
//   ⚑ A-SW-008 (§7.4-vs-§1.5 peer-id contradiction — see SPEC-AMBIGUITY-LOG).
//   §7.4 line 4001 lists "Peer ID derivation (§7.4)" in the §9.1 floor and §7.4's
//   prose historically read as SHA-256(pubkey); §1.5's canonical-form table (v7.65)
//   mandates identity-multihash (digest = raw pubkey) for Ed25519. The v7.74 §7.4
//   text now DEFERS to the §1.5 table ("See §1.5 canonical-form per key_type"), so
//   the contradiction is *narrowed* but the floor bullet still cites §7.4 by number.
//   We construct per §1.5 (identity-multihash) — the canonical, cap-pattern-bearing
//   form. Corroborates OCaml A-OC-007 / Zig A-ZIG-001 (prior peers hit the same).
//
// system/peer entity (§3.5, v7.65): data is {public_key (bytes), key_type (string)}
// — peer_id is NOT in the hashable basis (P×I primitive discipline). The content
// hash of the peer entity is the identity hash used in caps/signatures.

/// A peer's identity: the Ed25519 keypair, the derived peer_id, and the
/// materialized `system/peer` entity (whose content_hash is the identity hash).
public struct Identity: Sendable {
    /// 32-byte Ed25519 seed (private key material).
    public let seed: [UInt8]
    /// 32-byte Ed25519 public key.
    public let publicKey: [UInt8]
    /// Base58 peer_id (§1.5 identity-multihash form for Ed25519).
    public let peerID: String
    /// The materialized `system/peer` entity.
    public let peerEntity: BuiltEntity
    /// content_hash of the peer entity — the identity hash referenced by caps,
    /// signatures, grants (§3.5 / §5.2: grantee/signer/author are all this).
    public var identityHash: [UInt8] { peerEntity.hash }

    public init(seed: [UInt8]) throws(CodecError) {
        guard seed.count == 32 else { throw .badSeed }
        self.seed = seed
        self.publicKey = try Signing.publicKey(fromSeed: seed)
        // §1.5 canonical-form: Ed25519 → identity-multihash, digest = raw pubkey.
        self.peerID = try PeerID.fromEd25519(publicKey: publicKey).format()
        // system/peer hashable basis = {public_key, key_type} (v7.65; no peer_id).
        // key_type is the canonical lowercase-ASCII string (§1.5 line 496): "ed25519".
        self.peerEntity = try Model.make(type: "system/peer", fields: [
            ("public_key", .bytes(publicKey)),
            ("key_type", .text("ed25519")),
        ])
    }

    /// Sign an entity's content_hash (§7.3: message = full content_hash bytes).
    public func sign(contentHash: [UInt8]) throws(CodecError) -> [UInt8] {
        try Signing.sign(seed: seed, message: contentHash)
    }

    /// Build a `system/signature` entity (§3.5) over `target` by this identity.
    /// `signer` = this identity's hash (the peer-entity content_hash).
    public func signatureEntity(target: [UInt8]) throws(CodecError) -> BuiltEntity {
        let sig = try sign(contentHash: target)
        return try Model.make(type: "system/signature", fields: [
            ("target", .bytes(target)),
            ("signer", .bytes(identityHash)),
            ("algorithm", .text("ed25519")),
            ("signature", .bytes(sig)),
        ])
    }
}
