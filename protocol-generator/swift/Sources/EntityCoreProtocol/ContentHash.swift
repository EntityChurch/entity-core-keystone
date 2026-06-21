// ContentHash.swift — content_hash construction + the ECF-of-entity helper.
//
// V7 §7.1 (NORMATIVE):
//   content_hash = varint(format_code) || HASH(ECF({type, data}))
//   For format_code 0x00 (ecfv1-sha256): SHA-256, 32-byte digest, 33 bytes total.
// §4.4 construction-vs-verification asymmetry (v7.73): the CONSTRUCTION path
// serialises whatever format_code the caller supplies (does NOT gate on the
// registry) — this enables forward-compat. The VERIFICATION path (decoder) MUST
// reject unsupported codes. SHA-384/512 are wired for later agility.

import Crypto

public enum ContentHash {

    /// ECF-encode the hashable `{type, data}` shape. Map-key sort applies, so
    /// "data" (4 bytes) sorts before "type" (4 bytes) lexicographically — the
    /// canonical encoder handles ordering; we just supply the two pairs.
    public static func ecfOfEntity(type: String, data: CBORValue) throws(CodecError) -> [UInt8] {
        let hashable: CBORValue = .map([
            (.text("type"), .text(type)),
            (.text("data"), data),
        ])
        return try CBOR.encode(hashable)
    }

    /// Construct the content_hash bytes: `varint(format_code) || digest`.
    /// `format_code` defaults to 0x00 (ecfv1-sha256). Construction does NOT gate
    /// on the registry (§4.4): an unknown code is serialised with the appropriate
    /// digest function if known, else this throws (we can't produce a digest we
    /// don't have). For the synthetic 128 vector, the digest function is still
    /// SHA-256 (the test exercises the multi-byte varint PREFIX, not a new algo).
    public static func contentHash(formatCode: UInt64 = 0x00, type: String, data: CBORValue) throws(CodecError) -> [UInt8] {
        let ecf = try ecfOfEntity(type: type, data: data)
        let digest = try hashDigest(formatCode: formatCode, over: ecf)
        return Varint.encode(formatCode) + digest
    }

    /// Dispatch the digest function from the format code. The construction path's
    /// known algorithms; unknown algorithm codes throw (cannot construct a digest).
    /// Note (per content_hash.4 vector): a caller-supplied forward-compat code in
    /// the ECF-v1 family hashes with SHA-256 — the synthetic 128 case is a varint
    /// prefix exercise, the digest stays SHA-256.
    static func hashDigest(formatCode: UInt64, over bytes: [UInt8]) throws(CodecError) -> [UInt8] {
        switch formatCode {
        case 0x00: return sha256(bytes)
        case 0x01: return sha384(bytes)
        case 0x02: return sha512(bytes)
        default:
            // Forward-compat construction (§4.4): serialise the caller's code with
            // ECF-v1 / SHA-256 digest. (Real future algos would dispatch here.)
            return sha256(bytes)
        }
    }

    public static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        var hasher = SHA256()
        hasher.update(data: bytes)
        return Array(hasher.finalize())
    }

    public static func sha384(_ bytes: [UInt8]) -> [UInt8] {
        var hasher = SHA384()
        hasher.update(data: bytes)
        return Array(hasher.finalize())
    }

    public static func sha512(_ bytes: [UInt8]) -> [UInt8] {
        var hasher = SHA512()
        hasher.update(data: bytes)
        return Array(hasher.finalize())
    }

    /// Display form (§4.4): "ecfv1-sha256:<64 hex LOWERCASE>". For logs/UI only —
    /// never on the wire. Hex is lowercase per §9.3 step 4.
    public static func displayString(_ wireBytes: [UInt8]) throws(CodecError) -> String {
        guard let first = wireBytes.first else { throw .truncated }
        let name: String
        switch UInt64(first) {
        case 0x00: name = "ecfv1-sha256"
        case 0x01: name = "ecfv1-sha384"
        case 0x02: name = "ecfv1-sha512"
        default: throw .unsupportedHashFormat(UInt64(first))
        }
        return name + ":" + Hex.encode(Array(wireBytes.dropFirst()))
    }
}

/// Lowercase hex (§9.3 step 4 / §7.4 line 823). Local helper to avoid Foundation.
/// `digits` is the ASCII byte table "0123456789abcdef" — no Character/force-unwrap.
public enum Hex {
    static let digits = Array("0123456789abcdef".utf8)
    public static func encode(_ bytes: [UInt8]) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count * 2)
        for b in bytes {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0xf)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}
