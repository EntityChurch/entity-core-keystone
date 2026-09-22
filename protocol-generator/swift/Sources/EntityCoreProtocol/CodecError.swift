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

    /// A §1.8 / §3.1 RESOLUTION-INTEGRITY failure: an entity whose carried
    /// `content_hash` is not `content_hash({type, data})`, or an `included` entry whose
    /// MAP KEY does not bind to the entity filed under it.
    ///
    /// A DIFFERENT CAUSE FROM `.malformed`, TAKING A DIFFERENT CODE. §5.2a pins this arm:
    /// *"A peer that refuses at the decode boundary MUST answer `400 hash_mismatch`
    /// `[MUST]`"* (mood corrected 0.8.2.24), and in the same breath *"`400
    /// non_canonical_ecf` is NOT conformant here `[MUST]`."*  That code is
    /// `ENTITY-CBOR-ENCODING` §5.4's, for a CBOR TAG-POLICY violation, and a mis-keyed
    /// included entry carries no tag at all — its encoding is canonical. What is false is
    /// the claim the KEY makes, so the remedy `non_canonical_ecf` selects (*re-encode*)
    /// sends an honest caller to the wrong layer. This peer answered `non_canonical_ecf`
    /// for every decode-boundary refusal until 0.8.2.24 (measured on the wire: arc-probe
    /// B1/B2).
    case hashMismatch(String)

    /// A frame whose declared length exceeds the configured maximum, detected at the
    /// LENGTH PREFIX before the body is buffered (§4.10(a)). Since 0.8.2.25 (N14) the
    /// `413` MUST be EMITTED: §4.10(a)'s SHOULD became a MUST, because the condition is
    /// detected with the connection intact and nothing spent.
    case frameTooLarge

    /// A frame that never completed: a partial length prefix, or a prefix declaring N
    /// bytes followed by fewer. §4.11's framing arm names this input explicitly and
    /// answers `400 invalid_request`.
    ///
    /// SEPARATE FROM AN ORDINARY CLOSE BECAUSE THE TWO ARE DIFFERENT EVENTS. A clean EOF
    /// at a frame BOUNDARY is an ordinary hangup and is owed nothing; a stream that ends
    /// mid-frame is a REFUSAL and is owed a coded frame. The distinction can only be made
    /// where the frame boundary is known, which is why `Socket.readFrame` reports it
    /// rather than collapsing everything into `nil`.
    case truncatedFrame
}
