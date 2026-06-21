// Base58.swift — Bitcoin-alphabet Base58, encode + decode.
//
// Used for peer-id construction/parse (V7 §7.4). Leading-zero preserving via
// byte long-division — no bignum dependency. Profile: base58_library = "hand-rolled".

public enum Base58 {
    static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

    // Reverse map: ASCII byte → digit value (or 0xff for invalid).
    static let decodeMap: [UInt8] = {
        var m = [UInt8](repeating: 0xff, count: 256)
        for (i, c) in alphabet.enumerated() { m[Int(c)] = UInt8(i) }
        return m
    }()

    /// Is `byte` a valid Base58-alphabet ASCII byte? Used by §5.4 `is_peer_id`.
    public static func alphabetContains(_ byte: UInt8) -> Bool { decodeMap[Int(byte)] != 0xff }

    /// Encode bytes to a Base58 string. Each leading 0x00 byte maps to a leading '1'.
    public static func encode(_ input: [UInt8]) -> String {
        var zeros = 0
        while zeros < input.count && input[zeros] == 0 { zeros += 1 }

        // Long-division of the big-endian integer by 58, base-256 → base-58.
        var digits: [UInt8] = []
        for byte in input {
            var carry = Int(byte)
            for i in 0..<digits.count {
                carry += Int(digits[i]) << 8
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }

        var out: [UInt8] = []
        out.reserveCapacity(zeros + digits.count)
        for _ in 0..<zeros { out.append(alphabet[0]) }   // leading '1' per leading zero byte
        for d in digits.reversed() { out.append(alphabet[Int(d)]) }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decode a Base58 string to bytes. Throws `.invalidBase58` on any character
    /// outside the alphabet. Leading '1's restore as leading 0x00 bytes.
    public static func decode(_ input: String) throws(CodecError) -> [UInt8] {
        let chars = Array(input.utf8)
        var zeros = 0
        while zeros < chars.count && chars[zeros] == alphabet[0] { zeros += 1 }

        var bytes: [UInt8] = []
        for c in chars {
            let val = decodeMap[Int(c)]
            if val == 0xff { throw .invalidBase58 }
            var carry = Int(val)
            for i in 0..<bytes.count {
                carry += Int(bytes[i]) * 58
                bytes[i] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xff))
                carry >>= 8
            }
        }

        var out: [UInt8] = []
        out.reserveCapacity(zeros + bytes.count)
        for _ in 0..<zeros { out.append(0) }
        for b in bytes.reversed() { out.append(b) }
        return out
    }
}
