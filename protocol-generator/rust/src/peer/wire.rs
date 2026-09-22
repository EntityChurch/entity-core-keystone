//! Wire framing (§1.6) and the two L2 message builders (§3.2 EXECUTE, §3.3
//! EXECUTE_RESPONSE). Frame := `[4-byte BE length][CBOR-encoded envelope payload]`.
//!
//! §4.10(a) resource bound: a finite max inbound payload (16 MiB, the §1.6 SHOULD
//! / §4.10 recommended default) is enforced from the length prefix BEFORE the body
//! is buffered — an over-limit frame is rejected as `413 payload_too_large`
//! without reading the body. Since 0.8.2.25 (N14) that rejection MUST be EMITTED:
//! §4.10(a)'s "SHOULD … and otherwise MAY close after a best-effort coded frame"
//! became a MUST, because the over-size condition is detected at the length prefix
//! with the connection intact and nothing spent. §4.11 is the emission shape for the
//! whole pre-admission class; the transport still closes afterwards (the body was
//! never drained, so the framing is lost), but the close is now IN ADDITION TO the
//! frame rather than instead of it. The reader/writer threading lives in
//! [`super::transport`]; this module is framing + the message-entity builders.

use std::io::{Read, Write};

use crate::value::{Key, Value};

use super::model::{self, Entity, Envelope, ModelError};

/// §1.6 SHOULD bound / §4.10(a) recommended default — 16 MiB max inbound payload.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Frame read / write errors.
#[derive(Debug)]
pub enum WireError {
    /// EOF / connection closed at a FRAME BOUNDARY — an ordinary hangup, owed nothing.
    Closed,
    /// A frame that never completed: a partial length prefix, or a prefix declaring `n`
    /// bytes followed by fewer. §4.11's framing arm names this input outright —
    /// "un-parseable, truncated or non-canonical CBOR, or a length prefix that never
    /// completes" → `400 invalid_request`.
    ///
    /// A SEPARATE VARIANT FROM [`WireError::Closed`] BECAUSE THE TWO ARE DIFFERENT EVENTS
    /// AND A NAIVE READ-EXACT COLLAPSES THEM. A clean EOF at a frame boundary is an
    /// ordinary close; a stream that ends MID-FRAME is a REFUSAL and is owed a coded
    /// frame. Both surface as `read` answering `Ok(0)`, so the distinction can only be
    /// made here, where the frame boundary is known — and getting it wrong in the other
    /// direction would answer a 400 to every peer that simply hangs up.
    Truncated,
    /// Length prefix exceeded the connection's bound → maps to `413 payload_too_large`.
    PayloadTooLarge,
    /// Underlying I/O failure.
    Io(std::io::Error),
}

impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e)
    }
}

// ── frame read / write ───────────────────────────────────────────────────────

/// Read exactly `buf.len()` bytes.
///
/// `at_frame_boundary` says that a close having read ZERO bytes is an ordinary hangup
/// ([`WireError::Closed`]) rather than a truncated frame; a close having read SOME is a
/// truncation either way. Only the length-prefix read sits at a boundary.
fn read_exact(
    stream: &mut impl Read,
    buf: &mut [u8],
    at_frame_boundary: bool,
) -> Result<(), WireError> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => {
                return Err(if at_frame_boundary && off == 0 {
                    WireError::Closed
                } else {
                    WireError::Truncated
                })
            }
            Ok(n) => off += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(WireError::Io(e)),
        }
    }
    Ok(())
}

/// Read one length-prefixed frame under the default [`MAX_FRAME`] bound.
pub fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, WireError> {
    read_frame_limit(stream, MAX_FRAME)
}

/// Read one length-prefixed frame; returns the owned payload. The §4.10(a) bound
/// (`max_frame_bytes`, the peer's configured budget — H6) is checked on the length
/// prefix BEFORE the body is read.
pub fn read_frame_limit(stream: &mut impl Read, max_frame_bytes: usize) -> Result<Vec<u8>, WireError> {
    let mut hdr = [0u8; 4];
    read_exact(stream, &mut hdr, true)?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len > max_frame_bytes {
        return Err(WireError::PayloadTooLarge);
    }
    // A ZERO-LENGTH frame is COMPLETE, not truncated: the body read touches no bytes and
    // the empty payload reaches the decoder, which refuses it as bytes that never become
    // an Envelope.
    let mut payload = vec![0u8; len];
    read_exact(stream, &mut payload, false)?;
    Ok(payload)
}

// ── §4.11 pre-admission refusal classification (0.8.2.25) ────────────────────

/// Whether a [`read_frame_limit`] failure is a REFUSAL owed a coded frame (§4.11) rather
/// than an ordinary end of connection. A closed or reset socket is not a refusal of
/// anything and there is nobody left to answer.
pub fn framing_refusal(e: &WireError) -> bool {
    matches!(e, WireError::PayloadTooLarge | WireError::Truncated)
}

/// The `(status, code, message)` §4.11 assigns a pre-admission failure's CAUSE.
///
/// *"The frame obligation belongs to the class; the CODE belongs to the cause `[MUST]`"* —
/// a single code for the class would answer an honest caller under the wrong reason and
/// send them to the wrong layer.
///
/// | cause | answer | stated at |
/// |---|---|---|
/// | connect-auth proof-of-possession | `401 authentication_failed` | §4.6/§4.7 — the connect handler's, not this function's |
/// | envelope over the configured max | `413 payload_too_large` | §4.10(a), N14 |
/// | resolution integrity (mis-keyed `included`) | `400 hash_mismatch` | §5.2a, §1.8 |
/// | framing / never becomes an Envelope | `400 invalid_request` | §4.7, §4.11 |
/// | root is neither EXECUTE nor EXECUTE_RESPONSE | `400 invalid_request` | §3.3, §4.11 — in dispatch, not here |
///
/// THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
/// non-conformant *"on the framing arm"* and gives its reason in the same sentence:
/// `ENTITY-CBOR-ENCODING` *"defines that code for CBOR tag-policy violations
/// specifically"*, which that document still MUSTs at decode time (§6.3). The two rows are
/// disjoint by CAUSE rather than in conflict, and §6.3 says so itself: a tag in a
/// DATA-FIELD position is the policy violation with its own code, while *"the envelope and
/// entity-wrapper CBOR shapes are fixed maps and contain no positions where a tag could
/// legally be placed; any tag encountered in those structures is a structurally invalid
/// frame rejected by ordinary decoder validation"* — i.e. the framing arm. Everything else
/// this decoder calls non-canonical (a non-minimal head, an indefinite length, mis-ordered
/// keys) is genuinely "non-canonical CBOR that never becomes an Envelope" and takes
/// `invalid_request`.
///
/// The messages are a FIXED TABLE, never a rendered internal error: a wire-visible string
/// must stay ASCII (two peers in this cohort have been killed at runtime by a non-ASCII
/// byte in an encoded string), and nothing here echoes attacker-supplied bytes back.
pub fn pre_admission_refusal(e: &WireError) -> (u64, &'static str, &'static str) {
    match e {
        WireError::PayloadTooLarge => (
            413,
            "payload_too_large",
            "inbound frame exceeds the configured maximum size",
        ),
        _ => (400, "invalid_request", "frame did not decode into an envelope"),
    }
}

/// The same classification for a failure AT THE DECODER rather than at the framing layer:
/// a complete frame that never became an Envelope. See [`pre_admission_refusal`] for the
/// table and for why the tag arm keeps its own code.
pub fn decode_refusal(e: &ModelError) -> (u64, &'static str, &'static str) {
    match e {
        // §5.2a (0.8.2.24 N4/N5): "A peer that refuses at the decode boundary MUST answer
        // `400 hash_mismatch` [MUST]" and, in the same breath, "`400 non_canonical_ecf` is
        // NOT conformant here [MUST]". A mis-keyed `included` entry carries no tag and its
        // encoding IS canonical; what is false is the claim the KEY makes, so the remedy
        // `non_canonical_ecf` selects (*re-encode*) sends an honest caller to the wrong
        // layer. This peer answered `non_canonical_ecf` for every decode-boundary refusal
        // until 0.8.2.24 (measured on the wire: arc-probe B1/B2).
        ModelError::ContentHashMismatch | ModelError::IncludedKeyMismatch => (
            400,
            "hash_mismatch",
            "an entity was addressed by a hash that does not bind to it",
        ),
        ModelError::Codec(crate::CodecError::TagRejected) => (
            400,
            "non_canonical_ecf",
            "CBOR tags are forbidden anywhere in an entity data field",
        ),
        _ => (400, "invalid_request", "frame did not decode into an envelope"),
    }
}

/// Write a length-prefixed frame. The caller serializes concurrent writes (the
/// transport holds a mutex over the shared stream).
pub fn write_frame(stream: &mut impl Write, payload: &[u8]) -> Result<(), WireError> {
    let hdr = (payload.len() as u32).to_be_bytes();
    stream.write_all(&hdr)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

// ── EXECUTE_RESPONSE builder (§3.3) ──────────────────────────────────────────

/// Build an EXECUTE_RESPONSE entity (§3.3).
pub fn make_response(request_id: &str, status: u64, result: &Entity) -> Entity {
    Entity::make(
        "system/protocol/execute/response",
        Value::Map(vec![
            (Key::Text("request_id".into()), model::text(request_id)),
            (Key::Text("status".into()), Value::UInt(status)),
            (Key::Text("result".into()), result.to_cbor()),
        ]),
    )
}

// ── EXECUTE builder (§3.2) ───────────────────────────────────────────────────

/// Fields for an EXECUTE message.
pub struct ExecuteFields<'a> {
    pub request_id: &'a str,
    pub uri: &'a str,
    pub operation: &'a str,
    pub params: Entity,
    pub resource: Option<Value>,
    pub author: Option<&'a [u8]>,
    pub capability: Option<&'a [u8]>,
}

/// Build an EXECUTE entity (§3.2).
pub fn make_execute(f: ExecuteFields) -> Entity {
    let mut pairs: Vec<(Key, Value)> = vec![
        (Key::Text("request_id".into()), model::text(f.request_id)),
        (Key::Text("uri".into()), model::text(f.uri)),
        (Key::Text("operation".into()), model::text(f.operation)),
        (Key::Text("params".into()), f.params.to_cbor()),
    ];
    if let Some(a) = f.author {
        pairs.push((Key::Text("author".into()), model::bytes(a)));
    }
    if let Some(c) = f.capability {
        pairs.push((Key::Text("capability".into()), model::bytes(c)));
    }
    if let Some(r) = f.resource {
        pairs.push((Key::Text("resource".into()), r));
    }
    Entity::make("system/protocol/execute", Value::Map(pairs))
}

// ── small result entities ────────────────────────────────────────────────────

/// `system/protocol/error` result entity (§3.3).
pub fn error_result(code: &str, message: Option<&str>) -> Entity {
    let mut pairs = vec![("code", model::text(code))];
    if let Some(m) = message {
        pairs.push(("message", model::text(m)));
    }
    Entity::make("system/protocol/error", model::map(pairs))
}

/// Empty-params entity (§3.2): a `primitive/any` whose data is the empty map.
pub fn empty_params() -> Entity {
    Entity::make("primitive/any", Value::Map(vec![]))
}

/// Convenience: wrap a response build into an envelope (no `included`).
pub fn response_envelope(request_id: &str, status: u64, result: &Entity) -> Envelope {
    Envelope::new(make_response(request_id, status, result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::model::{entity_of_cbor, envelope_of_cbor};
    use crate::value::Key;

    // ── §4.11 pre-admission refusals (0.8.2.25) — the CLASSIFICATION half ──────
    //
    // §4.11's rule has two parts and they fail differently. "The frame obligation
    // belongs to the class" is wire-visible and is driven over a socket (see
    // `peer::transport::tests`); "the CODE belongs to the cause [MUST]" is a MAPPING, and
    // a mapping is exactly the thing that regresses silently when a new failure joins an
    // existing branch. These cases pin the mapping at the unit level so `run-s2.sh`
    // carries it. The pinned check set (778) has NO vector on this surface, which is why
    // the coverage is authored here rather than inherited.

    fn read_all(input: &[u8]) -> Result<Vec<u8>, WireError> {
        read_frame_limit(&mut std::io::Cursor::new(input.to_vec()), MAX_FRAME)
    }

    /// A clean EOF at a frame boundary is an ordinary close and is owed nothing; a stream
    /// that ends MID-FRAME is a §4.11 framing refusal and is owed a coded frame. A naive
    /// read-exact collapses the two (both are `Ok(0)`), so the distinction has to be made
    /// where the frame boundary is known.
    #[test]
    fn read_frame_distinguishes_close_from_truncation() {
        assert!(matches!(read_all(&[]), Err(WireError::Closed)),
            "clean close at a frame boundary");
        assert!(matches!(read_all(&[0x00, 0x00]), Err(WireError::Truncated)),
            "partial length prefix");
        assert!(matches!(read_all(&[0x00, 0x00, 0x10, 0x00, 0xa1]), Err(WireError::Truncated)),
            "prefix declares more than is sent");
        assert!(matches!(read_all(&[0x02, 0x00, 0x00, 0x00]), Err(WireError::PayloadTooLarge)),
            "length prefix above the bound");
        // A zero-length frame is COMPLETE, not truncated: it reaches the decoder and is
        // refused there as bytes that never become an Envelope.
        assert_eq!(read_all(&[0, 0, 0, 0]).expect("empty frame is complete").len(), 0);
    }

    /// §4.11's table, one row at a time. *"A single code for the class would answer an
    /// honest caller under the wrong reason and send them to the wrong layer."*
    #[test]
    fn pre_admission_code_is_the_causes() {
        // §4.10(a), mood raised to MUST at 0.8.2.25 (N14).
        assert_eq!(pre_admission_refusal(&WireError::PayloadTooLarge).0, 413);
        assert_eq!(pre_admission_refusal(&WireError::PayloadTooLarge).1, "payload_too_large");
        // §4.7 / §4.11 framing arm: bytes that never become an Envelope.
        assert_eq!(pre_admission_refusal(&WireError::Truncated).1, "invalid_request");

        // §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
        // non_canonical_ecf NON-CONFORMANT here.
        assert_eq!(decode_refusal(&ModelError::IncludedKeyMismatch), (400, "hash_mismatch",
            "an entity was addressed by a hash that does not bind to it"));
        assert_eq!(decode_refusal(&ModelError::ContentHashMismatch).1, "hash_mismatch");
        // ENTITY-CBOR-ENCODING §5.4 — the tag-policy arm keeps its own code.
        assert_eq!(decode_refusal(&ModelError::Codec(crate::CodecError::TagRejected)).1,
            "non_canonical_ecf");
        // Everything else that never becomes an Envelope.
        assert_eq!(decode_refusal(&ModelError::BadEntity).1, "invalid_request");
        assert_eq!(decode_refusal(&ModelError::Codec(crate::CodecError::Truncated)).1,
            "invalid_request");

        // framing_refusal separates "owed a frame" from "the connection simply ended".
        assert!(framing_refusal(&WireError::PayloadTooLarge));
        assert!(framing_refusal(&WireError::Truncated));
        assert!(!framing_refusal(&WireError::Closed));
        assert!(!framing_refusal(&WireError::Io(std::io::Error::other("x"))));
    }

    /// The two decode-boundary CAUSES must reach the classifier as DIFFERENT errors.
    /// Before 0.8.2.24 this peer answered `400 non_canonical_ecf` for every one of them,
    /// which is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed `included`
    /// entry carries no tag, its encoding is canonical, and *re-encode* is not the
    /// caller's remedy.
    #[test]
    fn decode_boundary_cause_split() {
        let good = Entity::make("primitive/any", model::map(vec![("x", Value::UInt(1))]));
        let root = Entity::make(
            "system/protocol/execute",
            model::map(vec![
                ("request_id", model::text("t1")),
                ("uri", model::text("system/tree")),
                ("operation", model::text("get")),
                ("params", empty_params().to_cbor()),
            ]),
        );
        let envelope_with = |key: Vec<u8>| {
            Value::Map(vec![
                (Key::Text("root".into()), root.to_cbor()),
                (
                    Key::Text("included".into()),
                    Value::Map(vec![(Key::Bytes(key), good.to_cbor())]),
                ),
            ])
        };
        assert_eq!(
            envelope_of_cbor(&envelope_with(vec![0x11; 33])).unwrap_err(),
            ModelError::IncludedKeyMismatch,
            "a mis-keyed included entry is a RESOLUTION-INTEGRITY fault"
        );

        // A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same
        // class (§1.8 item 1) and takes the same code.
        let tampered = Value::Map(vec![
            (Key::Text("type".into()), model::text(&good.typ)),
            (Key::Text("data".into()), good.data.clone()),
            (Key::Text("content_hash".into()), model::bytes(&[0x22; 33])),
        ]);
        assert_eq!(entity_of_cbor(&tampered).unwrap_err(), ModelError::ContentHashMismatch);

        // STRUCTURAL faults stay BadEntity -> invalid_request. THIS IS THE DISCRIMINATOR:
        // if both causes collapsed into one error value the split above would pass
        // vacuously.
        let no_type = model::map(vec![("data", Value::UInt(1))]);
        assert_eq!(entity_of_cbor(&no_type).unwrap_err(), ModelError::BadEntity);
        let not_an_envelope = model::map(vec![("nope", Value::UInt(1))]);
        assert_eq!(envelope_of_cbor(&not_an_envelope).unwrap_err(), ModelError::BadEntity);

        // And the WELL-FORMED envelope must still decode, or every case above is
        // satisfied by a decoder that refuses everything.
        let env = envelope_of_cbor(&envelope_with(good.hash.clone()))
            .expect("well-formed envelope must decode");
        assert!(env.included_get(&good.hash).is_some(),
            "the included entity did not survive decode");
    }

    #[test]
    fn response_builder_well_formed() {
        let result = empty_params();
        let resp = make_response("r1", 404, &result);
        assert_eq!(resp.typ, "system/protocol/execute/response");
        assert_eq!(resp.uint_field("status"), Some(404));
        assert_eq!(resp.text_field("request_id"), Some("r1"));
    }

    #[test]
    fn frame_roundtrip_in_memory() {
        let env = Envelope::new(Entity::make("system/root", Value::Map(vec![])));
        let payload = env.encode();
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &payload).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let back = read_frame(&mut cursor).unwrap();
        assert_eq!(back, payload);
    }
}
