// CBORValue.swift — the value model the ECF codec operates over.
//
// A `CBORValue` is the decoded form of any ECF data item. It is a value type
// (enum) per [memory].default_aggregate = "struct": copy semantics, no shared
// mutable state, Sendable-clean for Swift 6 strict concurrency.
//
// String-model discipline (A-SW-002): `.text` carries a Swift `String`, but the
// codec treats it strictly as a UTF-8 carrier — every wire length/ordering
// operation goes through `String.utf8` ([UInt8]), never `String.count`
// (grapheme clusters) or `String` ordering (Unicode-canonical / locale-aware).
// See CBOR.swift for the encode/decode side of that discipline.

/// A decoded ECF/CBOR data item. The full set of major types the Entity Core
/// core surface uses: unsigned int, negative int, byte string, text string,
/// array, map, bool, null, float. Major type 6 (tags) is intentionally absent —
/// tags are not part of ECF and the decoder rejects them (N2 / §6.3).
public indirect enum CBORValue: Sendable, Equatable {
    /// Major type 0 — unsigned integer, full range 0 ... 2^64-1 (UInt64).
    case uint(UInt64)
    /// Major type 1 — negative integer. Stores `n` where the value is `-1 - n`,
    /// so the full range -1 ... -2^64 is representable without signed overflow
    /// (the integer-width trap that bit prior peers — see PHASE-S2.md).
    case nint(UInt64)
    /// Major type 2 — byte string.
    case bytes([UInt8])
    /// Major type 3 — text string (UTF-8; carried as `String`, accessed via `.utf8`).
    case text(String)
    /// Major type 4 — array (ordered).
    case array([CBORValue])
    /// Major type 5 — map. Insertion-ordered pairs; ECF re-sorts on encode by
    /// (encoded-key-length, then lexicographic over encoded key bytes).
    case map([(key: CBORValue, value: CBORValue)])
    /// Major type 7 — IEEE 754 float (encoded shortest-form per Rule 4 / 4a).
    case float(Double)
    /// Major type 7 — simple value `true` (0xF5).
    case bool(Bool)
    /// Major type 7 — simple value `null` (0xF6).
    case null

    // Equatable must be hand-written because the `.map` payload is a tuple array
    // (tuples aren't Equatable-synthesized). Equality is structural and
    // order-sensitive for arrays; for maps it compares the pair sequences as
    // decoded (canonical ordering is an encode concern, not an identity concern).
    public static func == (lhs: CBORValue, rhs: CBORValue) -> Bool {
        switch (lhs, rhs) {
        case let (.uint(a), .uint(b)): return a == b
        case let (.nint(a), .nint(b)): return a == b
        case let (.bytes(a), .bytes(b)): return a == b
        case let (.text(a), .text(b)): return a == b
        case let (.array(a), .array(b)): return a == b
        case let (.map(a), .map(b)):
            guard a.count == b.count else { return false }
            for i in a.indices where a[i].key != b[i].key || a[i].value != b[i].value {
                return false
            }
            return true
        case let (.float(a), .float(b)):
            // Bit-pattern equality so NaN == NaN and -0.0 != 0.0 (wire-meaningful).
            return a.bitPattern == b.bitPattern
        case let (.bool(a), .bool(b)): return a == b
        case (.null, .null): return true
        default: return false
        }
    }
}

public extension CBORValue {
    /// Look up a value by text key in a `.map`. Returns nil if not a map or key absent.
    /// Comparison is over the raw `String` value (the decoded key), which is correct
    /// for the fixture/peer field lookups we do (ASCII field names).
    func mapValue(_ key: String) -> CBORValue? {
        guard case let .map(pairs) = self else { return nil }
        for pair in pairs {
            if case let .text(k) = pair.key, k == key { return pair.value }
        }
        return nil
    }

    /// Convenience accessors used by the conformance harness + peer layer.
    var textValue: String? { if case let .text(t) = self { return t } else { return nil } }
    var bytesValue: [UInt8]? { if case let .bytes(b) = self { return b } else { return nil } }
    var uintValue: UInt64? { if case let .uint(n) = self { return n } else { return nil } }
    var arrayValue: [CBORValue]? { if case let .array(a) = self { return a } else { return nil } }
}
