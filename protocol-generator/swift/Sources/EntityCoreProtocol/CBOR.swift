// CBOR.swift — canonical Entity Canonical Form (ECF) encode/decode.
//
// Hand-rolled per [codec].cbor_library = "hand-rolled" (A-005: no Swift CBOR lib
// gives ECF's guarantees — type-distinct float/int, length-then-lex key ordering,
// recursive tag-reject, full uint64/nint range). Derived directly from
// ENTITY-CBOR-ENCODING.md §3–§4, §9 and RFC 8949 §4.2.
//
// String-model discipline (A-SW-002, the headline Swift finding): text-string
// length is `String.utf8.count` (UTF-8 BYTES) — NEVER `String.count` (grapheme
// clusters); map-key lexicographic ordering is over ENCODED UTF-8 key bytes
// ([UInt8] comparison) — NEVER Swift `String` ordering (Unicode-canonical /
// locale-aware). Both are marked at their site below.

public enum CBOR {

    // MARK: - Encode (canonical ECF)

    /// Canonically encode a value to ECF bytes. Deterministic per §9.1:
    /// minimal integers, length-then-lex map keys, definite lengths, shortest
    /// floats, no duplicate keys (caller-supplied maps must be duplicate-free;
    /// duplicates are rejected on encode too).
    public static func encode(_ value: CBORValue) throws(CodecError) -> [UInt8] {
        var out: [UInt8] = []
        try encode(value, into: &out)
        return out
    }

    static func encode(_ value: CBORValue, into out: inout [UInt8]) throws(CodecError) {
        switch value {
        case let .uint(n):
            encodeHead(major: 0, arg: n, into: &out)
        case let .nint(n):
            encodeHead(major: 1, arg: n, into: &out)
        case let .bytes(b):
            encodeHead(major: 2, arg: UInt64(b.count), into: &out)
            out.append(contentsOf: b)
        case let .text(s):
            // A-SW-002: length is the UTF-8 BYTE count, never `s.count`.
            let utf8 = Array(s.utf8)
            encodeHead(major: 3, arg: UInt64(utf8.count), into: &out)
            out.append(contentsOf: utf8)
        case let .array(items):
            encodeHead(major: 4, arg: UInt64(items.count), into: &out)
            for item in items { try encode(item, into: &out) }
        case let .map(pairs):
            try encodeMap(pairs, into: &out)
        case let .float(d):
            encodeFloat(d, into: &out)
        case let .bool(b):
            out.append(b ? 0xf5 : 0xf4)
        case .null:
            out.append(0xf6)
        }
    }

    /// Encode a map with canonical key ordering: sort by ENCODED key length,
    /// then lexicographically over the ENCODED key bytes (Rule 2 / RFC 8949
    /// §4.2.1). Rejects duplicate (byte-identical) keys (Rule 5).
    static func encodeMap(_ pairs: [(key: CBORValue, value: CBORValue)], into out: inout [UInt8]) throws(CodecError) {
        var encoded: [(keyBytes: [UInt8], valueBytes: [UInt8])] = []
        encoded.reserveCapacity(pairs.count)
        for pair in pairs {
            let kb = try encode(pair.key)
            let vb = try encode(pair.value)
            encoded.append((kb, vb))
        }
        // Canonical sort: A-SW-002 — over encoded [UInt8] bytes, never String.
        encoded.sort { a, b in
            if a.keyBytes.count != b.keyBytes.count { return a.keyBytes.count < b.keyBytes.count }
            return lexicographicallyLess(a.keyBytes, b.keyBytes)
        }
        // Duplicate-key rejection (Rule 5): adjacent byte-identical keys after sort.
        for i in 1..<max(encoded.count, 1) where i < encoded.count {
            if encoded[i].keyBytes == encoded[i - 1].keyBytes { throw .duplicateKey }
        }
        encodeHead(major: 5, arg: UInt64(pairs.count), into: &out)
        for e in encoded {
            out.append(contentsOf: e.keyBytes)
            out.append(contentsOf: e.valueBytes)
        }
    }

    /// Encode the initial byte + minimal-length argument for `major`.
    static func encodeHead(major: UInt8, arg: UInt64, into out: inout [UInt8]) {
        let mt = major << 5
        switch arg {
        case 0...23:
            out.append(mt | UInt8(arg))
        case 24...0xff:
            out.append(mt | 24)
            out.append(UInt8(arg))
        case 0x100...0xffff:
            out.append(mt | 25)
            out.append(UInt8((arg >> 8) & 0xff))
            out.append(UInt8(arg & 0xff))
        case 0x1_0000...0xffff_ffff:
            out.append(mt | 26)
            var s = 24
            while s >= 0 { out.append(UInt8((arg >> UInt64(s)) & 0xff)); s -= 8 }
        default:
            out.append(mt | 27)
            var s = 56
            while s >= 0 { out.append(UInt8((arg >> UInt64(s)) & 0xff)); s -= 8 }
        }
    }

    /// Lexicographic (byte-wise) comparison of two byte arrays.
    static func lexicographicallyLess(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        let n = min(a.count, b.count)
        var i = 0
        while i < n {
            if a[i] != b[i] { return a[i] < b[i] }
            i += 1
        }
        return a.count < b.count
    }

    // MARK: - Float (Rule 4 / 4a shortest-form ladder)

    /// Encode `d` as the shortest IEEE 754 form preserving value: f16 if exactly
    /// representable, else f32 if exact, else f64. Special values (NaN, ±Inf, ±0)
    /// take their canonical f16 forms per Rule 4a.
    static func encodeFloat(_ d: Double, into out: inout [UInt8]) {
        if let half = doubleToHalfExact(d) {
            out.append(0xf9)
            out.append(UInt8(half >> 8))
            out.append(UInt8(half & 0xff))
            return
        }
        let f = Float(d)
        if Double(f) == d {
            out.append(0xfa)
            let bits = f.bitPattern
            var s = 24
            while s >= 0 { out.append(UInt8((bits >> UInt32(s)) & 0xff)); s -= 8 }
            return
        }
        out.append(0xfb)
        let bits = d.bitPattern
        var s = 56
        while s >= 0 { out.append(UInt8((bits >> UInt64(s)) & 0xff)); s -= 8 }
    }

    /// Return the 16-bit half-precision pattern iff `d` is exactly representable
    /// as IEEE 754 binary16 (and handle the Rule 4a specials). nil otherwise.
    static func doubleToHalfExact(_ d: Double) -> UInt16? {
        if d.isNaN { return 0x7e00 }                              // canonical quiet NaN
        if d.isInfinite { return d < 0 ? 0xfc00 : 0x7c00 }
        if d == 0 { return d.sign == .minus ? 0x8000 : 0x0000 }   // ±0.0
        // Must round-trip through f32 exactly to be a candidate for f16.
        let f = Float(d)
        if Double(f) != d { return nil }
        let bits = f.bitPattern
        let sign = UInt16((bits >> 16) & 0x8000)
        let exp = Int((bits >> 23) & 0xff) - 127
        let mant = bits & 0x7f_ffff
        if exp < -24 { return nil }                               // underflows half
        if exp < -14 {
            // Subnormal half: shift mantissa (with implicit leading 1) right.
            let shift = UInt32(-exp - 14)
            let full = mant | 0x80_0000
            let m = full >> (shift + 13)
            if (m << (shift + 13)) != full { return nil }         // lossy → not exact
            return sign | UInt16(m)
        }
        if exp > 15 { return nil }                                // overflows half normal range
        if (mant & 0x1fff) != 0 { return nil }                    // low 13 mantissa bits must be 0
        let hexp = UInt16(exp + 15) << 10
        let hmant = UInt16(mant >> 13)
        return sign | hexp | hmant
    }

    // MARK: - Decode

    /// Decode a single complete top-level ECF data item. Throws if there are
    /// trailing bytes, on any tag (N2), on duplicate keys, on non-canonical /
    /// indefinite-length / malformed input, or on invalid UTF-8.
    public static func decode(_ bytes: [UInt8]) throws(CodecError) -> CBORValue {
        var decoder = Decoder(bytes: bytes)
        let value = try decoder.decodeItem(depth: 0)
        if decoder.offset != bytes.count { throw .trailingBytes }
        return value
    }

    struct Decoder {
        let bytes: [UInt8]
        var offset: Int = 0
        static let maxDepth = 64   // §10.2 DoS bound

        mutating func readByte() throws(CodecError) -> UInt8 {
            guard offset < bytes.count else { throw CodecError.truncated }
            let b = bytes[offset]
            offset += 1
            return b
        }

        mutating func readBytes(_ n: Int) throws(CodecError) -> [UInt8] {
            guard offset + n <= bytes.count else { throw CodecError.truncated }
            let slice = Array(bytes[offset..<offset + n])
            offset += n
            return slice
        }

        /// Read the argument for an initial byte's additional-information field,
        /// rejecting non-minimal (non-canonical) length/value encodings.
        mutating func readArgument(_ ai: UInt8) throws(CodecError) -> UInt64 {
            switch ai {
            case 0...23:
                return UInt64(ai)
            case 24:
                let b = try readByte()
                if b < 24 { throw CodecError.nonCanonicalECF("non-minimal 1-byte arg") }
                return UInt64(b)
            case 25:
                let bs = try readBytes(2)
                let v = (UInt64(bs[0]) << 8) | UInt64(bs[1])
                if v <= 0xff { throw CodecError.nonCanonicalECF("non-minimal 2-byte arg") }
                return v
            case 26:
                let bs = try readBytes(4)
                var v: UInt64 = 0
                for b in bs { v = (v << 8) | UInt64(b) }
                if v <= 0xffff { throw CodecError.nonCanonicalECF("non-minimal 4-byte arg") }
                return v
            case 27:
                let bs = try readBytes(8)
                var v: UInt64 = 0
                for b in bs { v = (v << 8) | UInt64(b) }
                if v <= 0xffff_ffff { throw CodecError.nonCanonicalECF("non-minimal 8-byte arg") }
                return v
            case 28, 29, 30:
                throw CodecError.malformed("reserved additional info \(ai)")
            default: // 31 — indefinite length
                throw CodecError.nonCanonicalECF("indefinite length not allowed")
            }
        }

        mutating func decodeItem(depth: Int) throws(CodecError) -> CBORValue {
            if depth > Decoder.maxDepth { throw CodecError.limitExceeded("nesting depth") }
            let ib = try readByte()
            let major = ib >> 5
            let ai = ib & 0x1f

            switch major {
            case 0: // unsigned int
                return .uint(try readArgument(ai))
            case 1: // negative int — value is -1 - n; store n
                return .nint(try readArgument(ai))
            case 2: // byte string
                let len = try readArgument(ai)
                return .bytes(try readBytes(Int(len)))
            case 3: // text string — validate UTF-8 (§9.2.5)
                let len = try readArgument(ai)
                let raw = try readBytes(Int(len))
                guard let s = String(bytes: raw, encoding: .utf8) else { throw CodecError.invalidUTF8 }
                return .text(s)
            case 4: // array
                let count = try readArgument(ai)
                var items: [CBORValue] = []
                items.reserveCapacity(Int(min(count, 1024)))
                for _ in 0..<count { items.append(try decodeItem(depth: depth + 1)) }
                return .array(items)
            case 5: // map
                let count = try readArgument(ai)
                var pairs: [(key: CBORValue, value: CBORValue)] = []
                pairs.reserveCapacity(Int(min(count, 1024)))
                var seenKeyBytes: [[UInt8]] = []
                for _ in 0..<count {
                    let key = try decodeItem(depth: depth + 1)
                    let value = try decodeItem(depth: depth + 1)
                    // Duplicate-key rejection (§9.2.4) over canonical-encoded key bytes.
                    let kb = try CBOR.encode(key)
                    if seenKeyBytes.contains(kb) { throw CodecError.duplicateKey }
                    seenKeyBytes.append(kb)
                    pairs.append((key, value))
                }
                return .map(pairs)
            case 6: // tag — N2 / §6.3: MUST reject, at any depth.
                throw CodecError.tagRejected
            case 7:
                return try decodeSimpleOrFloat(ai)
            default:
                throw CodecError.malformed("impossible major type")
            }
        }

        mutating func decodeSimpleOrFloat(_ ai: UInt8) throws(CodecError) -> CBORValue {
            switch ai {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            case 23: throw CodecError.malformed("undefined (0xf7) not used in ECF")
            case 25: // f16
                let bs = try readBytes(2)
                let half = (UInt16(bs[0]) << 8) | UInt16(bs[1])
                return .float(halfToDouble(half))
            case 26: // f32
                let bs = try readBytes(4)
                var bits: UInt32 = 0
                for b in bs { bits = (bits << 8) | UInt32(b) }
                return .float(Double(Float(bitPattern: bits)))
            case 27: // f64
                let bs = try readBytes(8)
                var bits: UInt64 = 0
                for b in bs { bits = (bits << 8) | UInt64(b) }
                return .float(Double(bitPattern: bits))
            case 24: // simple value in following byte
                throw CodecError.malformed("unassigned simple value")
            default:
                throw CodecError.malformed("unsupported simple value \(ai)")
            }
        }
    }

    /// Convert an IEEE 754 binary16 bit pattern to Double.
    static func halfToDouble(_ half: UInt16) -> Double {
        let sign = UInt64(half & 0x8000) << 48
        let exp = Int((half >> 10) & 0x1f)
        let mant = UInt64(half & 0x3ff)
        if exp == 0 {
            if mant == 0 { return Double(bitPattern: sign) } // ±0
            // subnormal
            let d = Double(mant) * pow2(-24)
            return Double(bitPattern: sign) == 0 ? d : -d
        }
        if exp == 0x1f {
            if mant == 0 { return Double(bitPattern: sign | 0x7ff0_0000_0000_0000) } // ±inf
            return Double(bitPattern: sign | 0x7ff8_0000_0000_0000) // NaN
        }
        // normal: bias 15 → 1023
        let dexp = UInt64(exp - 15 + 1023) << 52
        let dmant = mant << 42
        return Double(bitPattern: sign | dexp | dmant)
    }

    static func pow2(_ e: Int) -> Double {
        var r = 1.0
        let base = e < 0 ? 0.5 : 2.0
        for _ in 0..<abs(e) { r *= base }
        return r
    }
}
