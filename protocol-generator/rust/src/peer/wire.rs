//! Wire framing (§1.6) and the two L2 message builders (§3.2 EXECUTE, §3.3
//! EXECUTE_RESPONSE). Frame := `[4-byte BE length][CBOR-encoded envelope payload]`.
//!
//! §4.10(a) resource bound: a finite max inbound payload (16 MiB, the §1.6 SHOULD
//! / §4.10 recommended default) is enforced from the length prefix BEFORE the body
//! is buffered — an over-limit frame is rejected as `413 payload_too_large`
//! without reading the body. The reader/writer threading lives in
//! [`super::transport`]; this module is framing + the message-entity builders.

use std::io::{Read, Write};

use crate::value::{Key, Value};

use super::model::{self, Entity, Envelope};

/// §1.6 SHOULD bound / §4.10(a) recommended default — 16 MiB max inbound payload.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Frame read / write errors.
#[derive(Debug)]
pub enum WireError {
    /// EOF / connection closed.
    Closed,
    /// Length prefix exceeded [`MAX_FRAME`] → maps to `413 payload_too_large`.
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

fn read_exact(stream: &mut impl Read, buf: &mut [u8]) -> Result<(), WireError> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => return Err(WireError::Closed),
            Ok(n) => off += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(WireError::Io(e)),
        }
    }
    Ok(())
}

/// Read one length-prefixed frame; returns the owned payload. The §4.10(a) bound
/// is checked on the length prefix BEFORE the body is read.
pub fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, WireError> {
    let mut hdr = [0u8; 4];
    read_exact(stream, &mut hdr)?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len > MAX_FRAME {
        return Err(WireError::PayloadTooLarge);
    }
    let mut payload = vec![0u8; len];
    read_exact(stream, &mut payload)?;
    Ok(payload)
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
