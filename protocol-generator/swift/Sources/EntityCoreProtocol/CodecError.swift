// CodecError.swift — the typed error model for the codec surface.
//
// Per profile [error_model]: Swift-native `throws` + an `Error`-conforming enum,
// one case per rejection condition. This is Swift's primary error model (checked,
// typed, value-shaped control flow the compiler tracks) — NOT exceptions/panics.
// `Result<T,E>` is reserved for stored/async outcomes (S3), not the codec path.
//
// Each case maps to a protocol-status code at the module boundary (peer layer):
//   .nonCanonicalECF / .tagRejected / .duplicateKey / .truncated / ...  → 400 non_canonical_ecf
//   .unsupportedHashFormat                                              → 400 unsupported_content_hash_format
//   .unsupportedKeyType                                                 → 400 unsupported_key_type
// (status mapping lives in the peer layer at S3; the codec only names the condition.)

/// Errors thrown by the ECF codec, content-hash, peer-id, and signing surfaces.
/// Used with typed `throws(CodecError)` where ergonomic (profile: typed_throws =
/// "preferred-if-clean").
public enum CodecError: Error, Equatable, Sendable {
    /// A non-canonical encoding was encountered on decode (e.g. non-minimal int,
    /// indefinite-length container, non-shortest float) where canonical is required.
    case nonCanonicalECF(String)
    /// Input ended before a complete data item could be read.
    case truncated
    /// A CBOR major-type-6 tag appeared in a data position (any nesting depth).
    /// §6.3 / N2 — MUST reject with 400 non_canonical_ecf.
    case tagRejected
    /// A map contained duplicate keys. Rule 5 / §9.2.4 — MUST reject.
    case duplicateKey
    /// Trailing bytes remained after a complete top-level item was decoded.
    case trailingBytes
    /// A reserved/unassigned CBOR additional-information value or simple value.
    case malformed(String)
    /// Text string bytes were not valid UTF-8 (§9.2.5).
    case invalidUTF8
    /// An Ed25519 seed/private key was not 32 bytes.
    case badSeed
    /// A content_hash carried a format code the verifier cannot interpret (§4.4 decode side).
    case unsupportedHashFormat(UInt64)
    /// A peer-id carried a key_type the impl does not support.
    case unsupportedKeyType(UInt64)
    /// A base58 string contained a character outside the Bitcoin alphabet.
    case invalidBase58
    /// A nesting/size limit (§10.2) was exceeded.
    case limitExceeded(String)
}
