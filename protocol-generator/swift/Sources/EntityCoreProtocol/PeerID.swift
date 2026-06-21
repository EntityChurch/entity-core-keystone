// PeerID.swift — peer-id construction + parse (V7 §1.5 / §7.4, NORMATIVE).
//
//   PeerID := Base58(varint(key_type) || varint(hash_type) || digest)
//
// For Ed25519 (key_type=0x01, hash_type=0x00 identity-multihash), the digest IS
// the raw 32-byte public key (v7.64). For SHA-256-form key types (hash_type=0x01),
// the digest = SHA-256(canonical_pubkey_encoding). This module operates at the
// component level: it formats/parses the abstract (key_type, hash_type, digest)
// triple — the digest is supplied by the caller (derivePeerID, at the identity
// layer, computes it from the pubkey per the §1.5 canonical-form table).
//
// The peer-id string round-trips: parse(format(components)) == components.

public struct PeerID: Sendable, Equatable {
    public let keyType: UInt64
    public let hashType: UInt64
    public let digest: [UInt8]

    public init(keyType: UInt64, hashType: UInt64, digest: [UInt8]) {
        self.keyType = keyType
        self.hashType = hashType
        self.digest = digest
    }

    /// Format the components to the Base58 peer-id string (N1: varints via the
    /// LEB128 primitive — the synthetic key_type=128 vector proves the multi-byte
    /// prefix path).
    public func format() -> String {
        var data: [UInt8] = []
        data.append(contentsOf: Varint.encode(keyType))
        data.append(contentsOf: Varint.encode(hashType))
        data.append(contentsOf: digest)
        return Base58.encode(data)
    }

    /// Parse a Base58 peer-id string back to (key_type, hash_type, digest).
    /// The digest is everything after the two leading varints. Throws on invalid
    /// Base58 or a truncated prefix.
    public static func parse(_ string: String) throws(CodecError) -> PeerID {
        let bytes = try Base58.decode(string)
        let (keyType, afterKey) = try Varint.decode(bytes, at: 0)
        let (hashType, afterHash) = try Varint.decode(bytes, at: afterKey)
        let digest = Array(bytes[afterHash...])
        return PeerID(keyType: keyType, hashType: hashType, digest: digest)
    }

    /// Derive a peer-id directly from an Ed25519 public key (key_type 0x01).
    /// Canonical form is identity-multihash (hash_type 0x00): digest = raw pubkey
    /// (§1.5 table). Pubkey MUST be 32 bytes.
    public static func fromEd25519(publicKey: [UInt8]) throws(CodecError) -> PeerID {
        guard publicKey.count == 32 else { throw .unsupportedKeyType(0x01) }
        return PeerID(keyType: 0x01, hashType: 0x00, digest: publicKey)
    }
}
