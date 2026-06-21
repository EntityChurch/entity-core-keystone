// Wire.swift — L2 interaction: framing, the two message types, envelope, errors.
//
// V7 §3.3: ONLY two wire message types — EXECUTE (system/protocol/execute) and
// EXECUTE_RESPONSE (system/protocol/execute/response). Any other root type is
// invalid → close the connection. `hello`/`authenticate` are OPERATIONS on the
// system/protocol/connect handler (§4.1), NOT message types (3 EXECUTE + 3
// EXECUTE_RESPONSE handshake).
//
// §1.6 wire frame: 4-byte BIG-ENDIAN length prefix + the CBOR envelope bytes.
// `[idiom].explicit_endianness` — we convert via explicit bigEndian, never host
// order. The envelope (§3.1) is {root, included?} where `included` is a CBOR
// map keyed by content-hash BYTE STRINGS (bstr keys), carrying capabilities,
// identities, signatures, and any entity referenced by root data fields.

// MARK: - Envelope (§3.1)

/// A decoded wire envelope. `root` is the primary entity (EXECUTE or
/// EXECUTE_RESPONSE). `included` maps content_hash bytes → entity (N5: this map
/// MUST survive every dispatch surface, request- and result-side). We retain
/// each included entity's ORIGINAL wire bytes for N4 fidelity-safe forwarding.
public struct Envelope: Sendable {
    public let root: Entity
    /// content_hash bytes → included entity. Keyed by HashKey for byte identity.
    public let included: [HashKey: Entity]

    public init(root: Entity, included: [HashKey: Entity] = [:]) {
        self.root = root
        self.included = included
    }

    /// Look up an included entity by content_hash bytes.
    public func included(_ hash: [UInt8]) -> Entity? { included[HashKey(hash)] }
}

public enum Wire {
    public static let executeType = "system/protocol/execute"
    public static let responseType = "system/protocol/execute/response"

    // MARK: framing (§1.6)

    /// Frame an envelope's CBOR bytes: 4-byte big-endian length || bytes.
    public static func frame(_ envelopeBytes: [UInt8]) -> [UInt8] {
        let n = UInt32(envelopeBytes.count).bigEndian
        var out: [UInt8] = withUnsafeBytes(of: n) { Array($0) }
        out.append(contentsOf: envelopeBytes)
        return out
    }

    /// Parse a 4-byte big-endian length prefix into a payload length.
    public static func frameLength(_ prefix: [UInt8]) throws(CodecError) -> Int {
        guard prefix.count == 4 else { throw .truncated }
        let n = (UInt32(prefix[0]) << 24) | (UInt32(prefix[1]) << 16)
            | (UInt32(prefix[2]) << 8) | UInt32(prefix[3])
        return Int(n)
    }

    // MARK: envelope encode/decode

    /// Encode an envelope to canonical ECF. `root` and each `included` entity are
    /// materialized (carry content_hash). The `included` map keys are the entities'
    /// content_hash byte strings (§3.1 — bstr keys, MUST match the value's hash).
    public static func encodeEnvelope(root: BuiltEntity, included: [BuiltEntity] = []) throws(CodecError) -> [UInt8] {
        var pairs: [(key: CBORValue, value: CBORValue)] = [
            (.text("root"), try decodedValue(root.bytes)),
        ]
        if !included.isEmpty {
            // The codec re-sorts map keys canonically on encode, so any order in
            // works; the encoder produces the canonical byte order. (for-loop, not
            // .map, so the typed `throws(CodecError)` propagates correctly.)
            var inc: [(key: CBORValue, value: CBORValue)] = []
            for e in included {
                inc.append((.bytes(e.hash), try decodedValue(e.bytes)))
            }
            pairs.append((.text("included"), .map(inc)))
        }
        return try CBOR.encode(.map(pairs))
    }

    /// Decode envelope bytes into `Envelope`. The root entity and each included
    /// entity are decoded; tags (N2) and duplicate keys are rejected by the codec.
    public static func decodeEnvelope(_ bytes: [UInt8]) throws(CodecError) -> Envelope {
        let value = try CBOR.decode(bytes)
        guard case .map = value, let rootVal = value.mapValue("root") else {
            throw .malformed("envelope missing root")
        }
        let root = try entityFromValue(rootVal)
        var included: [HashKey: Entity] = [:]
        if let inc = value.mapValue("included"), case let .map(pairs) = inc {
            for pair in pairs {
                guard case let .bytes(key) = pair.key else { throw .malformed("included key not bytes") }
                let e = try entityFromValue(pair.value)
                // §3.1: the included content_hash MUST match the map key.
                if let ch = e.contentHash, !ch.elementsEqual(key) {
                    throw .malformed("included content_hash != map key")
                }
                included[HashKey(key)] = e
            }
        }
        return Envelope(root: root, included: included)
    }

    // MARK: EXECUTE / EXECUTE_RESPONSE builders

    /// Build an EXECUTE entity (§3.2). `params` is a materialized entity. `author`
    /// and `capability` are content hashes (omitted for connect-path requests).
    /// `resource` carries `{targets, exclude?}` (§3.2 path-as-resource).
    public static func buildExecute(
        requestID: String, uri: String, operation: String,
        params: BuiltEntity, author: [UInt8]? = nil, capability: [UInt8]? = nil,
        resourceTargets: [String]? = nil
    ) throws(CodecError) -> BuiltEntity {
        var fields: [(String, CBORValue)] = [
            ("request_id", .text(requestID)),
            ("uri", .text(uri)),
            ("operation", .text(operation)),
            ("params", try decodedValue(params.bytes)),
        ]
        if let t = resourceTargets {
            fields.append(("resource", .textMap([("targets", .array(t.map { .text($0) }))])))
        }
        if let a = author { fields.append(("author", .bytes(a))) }
        if let c = capability { fields.append(("capability", .bytes(c))) }
        return try Model.make(type: executeType, data: orderedExecuteData(fields))
    }

    /// Build an EXECUTE_RESPONSE entity (§3.3): {request_id, status, result}.
    public static func buildResponse(requestID: String, status: UInt64, result: BuiltEntity) throws(CodecError) -> BuiltEntity {
        try Model.make(type: responseType, data: .textMap([
            ("request_id", .text(requestID)),
            ("status", .uint(status)),
            ("result", try decodedValue(result.bytes)),
        ]))
    }

    /// Build a `system/protocol/error` result entity (§3.3): {code, message?}.
    public static func errorEntity(code: String, message: String? = nil) throws(CodecError) -> BuiltEntity {
        var fields: [(String, CBORValue)] = [("code", .text(code))]
        if let m = message { fields.append(("message", .text(m))) }
        return try Model.make(type: "system/protocol/error", fields: fields)
    }

    // MARK: signature lookup (§3.5 / §5.2)

    /// Scan `included` for a `system/signature` whose `data.target` equals
    /// `targetHash` (§5.2 find_signature).
    public static func findSignature(target: [UInt8], in included: [HashKey: Entity]) -> Entity? {
        for (_, e) in included where e.type == "system/signature" {
            if let t = e.data.bytesAt("target"), t.elementsEqual(target) { return e }
        }
        return nil
    }

    /// Multi-sig variant (§5.2 find_signature_by_signer): match BOTH target and signer.
    public static func findSignature(target: [UInt8], signer: [UInt8], in included: [HashKey: Entity]) -> Entity? {
        for (_, e) in included where e.type == "system/signature" {
            if let t = e.data.bytesAt("target"), t.elementsEqual(target),
               let s = e.data.bytesAt("signer"), s.elementsEqual(signer) { return e }
        }
        return nil
    }

    // MARK: internals

    /// Decode bytes back to a CBORValue (used when nesting one entity's bytes
    /// inside another structure for encode — re-encoding the decoded form is
    /// canonical because the bytes were canonical).
    static func decodedValue(_ bytes: [UInt8]) throws(CodecError) -> CBORValue {
        try CBOR.decode(bytes)
    }

    /// Decode a CBORValue into an `Entity` (carrying its claimed content_hash).
    static func entityFromValue(_ value: CBORValue) throws(CodecError) -> Entity {
        guard case .map = value, let typeVal = value.mapValue("type"), case let .text(type) = typeVal else {
            throw .malformed("entity is not a {type,data} map")
        }
        let data = value.mapValue("data") ?? .null
        let ch = value.bytesAt("content_hash")
        return Entity(type: type, data: data, contentHash: ch)
    }

    /// EXECUTE data is built from an ordered field list; the codec canonically
    /// re-sorts map keys, so order in is irrelevant to the bytes.
    static func orderedExecuteData(_ fields: [(String, CBORValue)]) -> CBORValue {
        .map(fields.map { (key: CBORValue.text($0.0), value: $0.1) })
    }
}
