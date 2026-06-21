// Varint.swift — multicodec-style LEB128 varints (V7 §7.3, normative).
//
// N1: ALL format-code / key_type / hash_type framing routes through these
// primitives, NOT a hard-coded "read 1 byte". Codes 0–127 encode as a single
// byte (no continuation bit); codes ≥128 extend to 2+ bytes. Today's allocated
// codes are all < 0x80, so they are byte-identical to a fixed-width field — the
// trap is hard-coding that. The synthetic `format_code 128` / `key_type 128`
// conformance vectors prove the multi-byte path.

public enum Varint {
    /// Encode a value as a multicodec-style LEB128 varint (little-endian groups
    /// of 7 bits; continuation bit 0x80 set on every byte except the last).
    public static func encode(_ value: UInt64) -> [UInt8] {
        var v = value
        var out: [UInt8] = []
        repeat {
            var byte = UInt8(v & 0x7f)
            v >>= 7
            if v != 0 { byte |= 0x80 }
            out.append(byte)
        } while v != 0
        return out
    }

    /// Decode a varint from `bytes` starting at `offset`. Returns the value and
    /// the new offset past the varint. Throws on truncation or overlong (>10-byte)
    /// encodings. Rejects non-minimal encodings (a trailing 0x00 continuation
    /// group that adds no value) per canonical-varint discipline.
    public static func decode(_ bytes: [UInt8], at offset: Int) throws(CodecError) -> (value: UInt64, next: Int) {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        var idx = offset
        while true {
            guard idx < bytes.count else { throw .truncated }
            let byte = bytes[idx]
            idx += 1
            if shift >= 64 { throw .malformed("varint overflow") }
            result |= UInt64(byte & 0x7f) << shift
            if (byte & 0x80) == 0 {
                // Minimal-encoding check: a multi-byte varint whose final group is
                // 0 would have been encodable in fewer bytes.
                if byte == 0 && idx - offset > 1 {
                    throw .nonCanonicalECF("non-minimal varint")
                }
                return (result, idx)
            }
            shift += 7
        }
    }
}
