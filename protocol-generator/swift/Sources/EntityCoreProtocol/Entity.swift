// Entity.swift — the core Entity value type + byte-fidelity decode (N4).
//
// An Entity is {type, data, content_hash?}. The content hash is computed over
// {type, data} (§7.1). N4 (Entity Fidelity, §1.8): after validating a received
// entity's hash, an impl MUST forward the ORIGINAL bytes, never a re-encode of
// the decoded form (a lossy decode→re-encode changes bytes → breaks the hash and
// any signature over it). So `decode` retains the exact wire bytes alongside the
// decoded structure.
//
// Value type per [memory].default_aggregate = "struct"; Sendable-clean.

public struct Entity: Sendable, Equatable {
    public let type: String
    public let data: CBORValue
    /// 33-byte wire content_hash (format code + 32-byte digest), when present.
    public let contentHash: [UInt8]?

    public init(type: String, data: CBORValue, contentHash: [UInt8]? = nil) {
        self.type = type
        self.data = data
        self.contentHash = contentHash
    }

    /// Compute and return this entity's content_hash bytes (format code 0x00).
    public func computeContentHash() throws(CodecError) -> [UInt8] {
        try ContentHash.contentHash(formatCode: 0x00, type: type, data: data)
    }

    /// Validate a received entity's claimed content_hash by recomputation (§7.2).
    /// Never trust a claimed hash without verification.
    public func validateContentHash() throws(CodecError) -> Bool {
        guard let claimed = contentHash else { return false }
        let expected = try computeContentHash()
        return expected == claimed
    }

    /// Canonically ECF-encode this entity as {type, data, content_hash?}. NOTE:
    /// this re-encodes the decoded form and is for LOCAL construction only — for
    /// forwarding a received entity, use the original wire bytes (N4), see
    /// `DecodedEntity.originalBytes`.
    public func encode() throws(CodecError) -> [UInt8] {
        var pairs: [(key: CBORValue, value: CBORValue)] = [
            (.text("type"), .text(type)),
            (.text("data"), data),
        ]
        if let ch = contentHash {
            pairs.append((.text("content_hash"), .bytes(ch)))
        }
        return try CBOR.encode(.map(pairs))
    }
}

/// A decoded entity paired with the exact wire bytes it was decoded from (N4).
/// Forwarding MUST use `originalBytes`, not a re-encode of `entity`.
public struct DecodedEntity: Sendable {
    public let entity: Entity
    public let originalBytes: [UInt8]

    /// Decode an entity from wire bytes, retaining the originals for fidelity-safe
    /// forwarding. The decode runs the full ECF decoder, so tags (N2) and
    /// duplicate keys are rejected here.
    public static func decode(_ bytes: [UInt8]) throws(CodecError) -> DecodedEntity {
        let value = try CBOR.decode(bytes)
        guard case .map = value else { throw .malformed("entity is not a map") }
        guard let typeVal = value.mapValue("type"), case let .text(type) = typeVal else {
            throw .malformed("entity missing text 'type'")
        }
        let data = value.mapValue("data") ?? .null
        let ch: [UInt8]?
        if let chVal = value.mapValue("content_hash"), case let .bytes(b) = chVal {
            ch = b
        } else {
            ch = nil
        }
        return DecodedEntity(entity: Entity(type: type, data: data, contentHash: ch), originalBytes: bytes)
    }
}
