// Model.swift — materialized-entity construction helpers (foundation surface).
//
// The S2 codec gives us `Entity {type, data, contentHash?}` (value type) and the
// ECF encoder/decoder. The peer layer needs to *build* entities with their
// content_hash computed (§7.1) and to read structured fields off `CBORValue`
// maps idiomatically. This module is the thin bridge: pure value-type helpers,
// no shared state, `Sendable`-clean.
//
// Everything here works on the canonical map shape `{type, data}` and the
// §7.1 content_hash = varint(format) || SHA-256(ECF{type,data}). The codec is
// the single source of truth for the bytes.

/// A stored/built entity: the value `Entity` plus its computed wire bytes and
/// content_hash. Construction is the local path (§4.4/§4.5a author under the
/// active format — SHA-256 / format-code 0x00 on the core floor). For received
/// entities we keep the original wire bytes (N4 fidelity) via `DecodedEntity`.
public struct BuiltEntity: Sendable, Equatable {
    public let entity: Entity
    /// 33-byte content_hash (format 0x00 + 32-byte SHA-256 digest).
    public let hash: [UInt8]
    /// Canonical ECF bytes of `{type, data, content_hash}` — the wire form.
    public let bytes: [UInt8]

    public var type: String { entity.type }
    public var data: CBORValue { entity.data }
}

public enum Model {
    /// Build a materialized entity from `{type, data}`: computes the content_hash
    /// over `{type, data}` (§7.1), then encodes the full `{type, data, content_hash}`
    /// to canonical ECF (the wire form). Format code 0x00 (ECFv1-SHA-256) — the
    /// core floor; §4.5a single-active-format per connection.
    public static func make(type: String, data: CBORValue) throws(CodecError) -> BuiltEntity {
        let hash = try ContentHash.contentHash(formatCode: 0x00, type: type, data: data)
        let entity = Entity(type: type, data: data, contentHash: hash)
        let bytes = try entity.encode()
        return BuiltEntity(entity: entity, hash: hash, bytes: bytes)
    }

    /// Convenience: build a map-data entity from ordered pairs.
    public static func make(type: String, fields: [(String, CBORValue)]) throws(CodecError) -> BuiltEntity {
        let pairs = fields.map { (key: CBORValue.text($0.0), value: $0.1) }
        return try make(type: type, data: .map(pairs))
    }

    /// The canonical empty-params entity (§3.2): `primitive/any` whose data is the
    /// empty CBOR map (`0xA0`). Stable content_hash across impls (N3).
    public static func emptyParams() throws(CodecError) -> BuiltEntity {
        let empty: [(key: CBORValue, value: CBORValue)] = []
        return try make(type: "primitive/any", data: .map(empty))
    }

    /// Wrap a value as a `primitive/any` entity (the §6.5 step-5 bare-primitive rule).
    public static func primitiveAny(_ value: CBORValue) throws(CodecError) -> BuiltEntity {
        try make(type: "primitive/any", data: value)
    }
}

// MARK: - CBORValue field-access ergonomics for the peer layer

public extension CBORValue {
    /// Build a map value from ordered `(String, CBORValue)` pairs (text keys). A
    /// distinct name from the `.map` enum case so an empty `.map([])` is never
    /// ambiguous (the codec corpus tests rely on the enum-case `.map([])` form).
    static func textMap(_ fields: [(String, CBORValue)]) -> CBORValue {
        let pairs: [(key: CBORValue, value: CBORValue)] = fields.map { (CBORValue.text($0.0), $0.1) }
        return .map(pairs)
    }

    /// All `(key,value)` pairs if this is a map, else nil.
    var mapPairs: [(key: CBORValue, value: CBORValue)]? {
        if case let .map(p) = self { return p } else { return nil }
    }

    /// Bytes at a text key in a map, if present.
    func bytesAt(_ key: String) -> [UInt8]? { mapValue(key)?.bytesValue }
    /// Text at a text key in a map, if present.
    func textAt(_ key: String) -> String? { mapValue(key)?.textValue }
    /// Uint at a text key in a map, if present.
    func uintAt(_ key: String) -> UInt64? { mapValue(key)?.uintValue }
    /// Array at a text key in a map, if present.
    func arrayAt(_ key: String) -> [CBORValue]? { mapValue(key)?.arrayValue }
}
