//! cbor_host.rs — the host's CBOR *structure* layer (NOT the canonical codec).
//!
//! The profile (`[codec] canonical_mode = "delegated"`) draws the seam so the host
//! NEVER hand-rolls the canonical guarantee (shortest-float ladder / length-then-lex
//! key sort / major-type-6 tag scan on encode) — that all lives behind the C-ABI
//! (`codec_ffi::encode_bare_value` / `content_hash`). This module is only the
//! marshalling the host genuinely needs to move protocol structure around:
//!
//!   * [`encode`] emits *valid but NON-canonical* CBOR (insertion-order maps,
//!     minimal-length integer heads, `f64` floats as the 8-byte form). Every
//!     entity/frame that reaches the wire is then canonicalized by one
//!     `codec_ffi::encode_bare_value` pass — so the host contributes ZERO canonical
//!     decisions. The protocol envelope carries no floats, so the delegated
//!     float-ladder is never exercised by the host regardless.
//!   * [`decode`] parses an inbound frame into a [`Value`] tree so the host can read
//!     fields (request_id, status, operation, …) and marshal facts into the Ascent
//!     program. It rejects CBOR **major-type-6 tags** (N2 / §6.3) and indefinite
//!     lengths; it does not re-derive canonical-ness (the sender's bytes are already
//!     FFI-canonical, and per-entity content_hash is re-checked via the C-ABI).
//!
//! Opaque values (signatures, digests, keys) live here only as [`Value::Bytes`] —
//! Datalog never sees them; the authority interior sees readable IDs + fields.

/// A CBOR map key. The protocol keys on text (fields) or byte strings (the
/// `included` map, keyed by content_hash). Integer/bool keys round-trip for
/// completeness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    Text(String),
    Bytes(Vec<u8>),
    UInt(u64),
    NInt(u64),
    Bool(bool),
}

/// A CBOR value tree (ECF core types).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    UInt(u64),
    /// Negative integer, raw `n` where value = `-1 - n` (full u64 range of n).
    NInt(u64),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    /// Insertion-order map; the FFI canonicalizer sorts keys at the wire boundary.
    Map(Vec<(Key, Value)>),
}

// ── encode (naive; canonicalization delegated to the C-ABI) ────────────────────

/// Emit valid (non-canonical) CBOR. Callers that need canonical wire bytes route
/// the result through [`crate::codec_ffi::encode_bare_value`].
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::UInt(n) => head(0, *n, out),
        Value::NInt(n) => head(1, *n, out),
        Value::Float(f) => {
            // 8-byte form always; the FFI canonicalizer applies the shortest-float
            // ladder. The host never decides float width (delegated).
            out.push(0xfb);
            out.extend_from_slice(&f.to_bits().to_be_bytes());
        }
        Value::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for it in items {
                encode_into(it, out);
            }
        }
        Value::Map(entries) => {
            head(5, entries.len() as u64, out);
            for (k, val) in entries {
                encode_key(k, out);
                encode_into(val, out);
            }
        }
    }
}

fn encode_key(k: &Key, out: &mut Vec<u8>) {
    match k {
        Key::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Key::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Key::UInt(n) => head(0, *n, out),
        Key::NInt(n) => head(1, *n, out),
        Key::Bool(false) => out.push(0xf4),
        Key::Bool(true) => out.push(0xf5),
    }
}

/// Minimal-length CBOR head (canonical integer minimization is trivial + width-only,
/// not the delegated float/key-order guarantee).
fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | (arg as u8));
    } else if arg < 0x100 {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg < 0x1_0000 {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg < 0x1_0000_0000 {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

// ── decode (structure only; tag + indefinite rejection per N2/§6.3) ────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    /// A CBOR major-type-6 tag at any depth (N2 / §6.3 — MUST reject).
    TagRejected,
    IndefiniteLength,
    Malformed,
    TrailingData,
}

pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut d = Dec { buf: bytes, pos: 0, salvage: false };
    let v = d.value()?;
    if d.pos != d.buf.len() {
        return Err(DecodeError::TrailingData);
    }
    Ok(v)
}

/// A LENIENT decode of a frame the STRICT decoder has ALREADY rejected, for one purpose
/// only: recovering the `request_id` so the refusal can be correlated (§6.3, whose second
/// half is that rejection returns a STATUS, not silence).
///
/// It differs from [`decode`] in exactly one respect — a major-type-6 tag head is SKIPPED
/// and its content returned, instead of erroring. Everything else stays strict: minimal
/// heads, key ordering, the float ladder, full-consume.
///
/// THIS MAY NEVER REACH AN INGESTION PATH. Its only caller builds a 400 and discards
/// everything else it read, so the tag is never interpreted and nothing is stored — §6.3's
/// MUST NOT strip / preserve / interpret rules all still hold.
pub fn decode_salvage(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut d = Dec { buf: bytes, pos: 0, salvage: true };
    let v = d.value()?;
    if d.pos != d.buf.len() {
        return Err(DecodeError::TrailingData);
    }
    Ok(v)
}

struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Set only by [`decode_salvage`]; unwraps tags instead of rejecting them.
    salvage: bool,
}

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn arg(&mut self, ai: u8) -> Result<u64, DecodeError> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => Ok(self.byte()? as u64),
            25 => {
                let b = self.take(2)?;
                Ok(u16::from_be_bytes([b[0], b[1]]) as u64)
            }
            26 => {
                let b = self.take(4)?;
                Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64)
            }
            27 => {
                let b = self.take(8)?;
                Ok(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            31 => Err(DecodeError::IndefiniteLength),
            _ => Err(DecodeError::Malformed),
        }
    }
    fn value(&mut self) -> Result<Value, DecodeError> {
        let head = self.byte()?;
        let major = head >> 5;
        let ai = head & 0x1f;
        match major {
            0 => Ok(Value::UInt(self.arg(ai)?)),
            1 => Ok(Value::NInt(self.arg(ai)?)),
            2 => {
                let n = self.arg(ai)? as usize;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.arg(ai)? as usize;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| DecodeError::Malformed)?;
                Ok(Value::Text(s.to_string()))
            }
            4 => {
                let n = self.arg(ai)? as usize;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.value()?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.arg(ai)? as usize;
                let mut entries = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    let k = self.key()?;
                    let v = self.value()?;
                    entries.push((k, v));
                }
                Ok(Value::Map(entries))
            }
            6 => {
                // N2 / §6.3: tags are forbidden at any nesting depth. Salvage only
                // (see `decode_salvage`): consume the tag's argument and answer its
                // CONTENT, so an already-rejected frame can still yield its request_id.
                if self.salvage {
                    self.arg(ai)?;
                    return self.value();
                }
                Err(DecodeError::TagRejected)
            }
            7 => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                25 => {
                    let b = self.take(2)?;
                    Ok(Value::Float(f16_to_f64(u16::from_be_bytes([b[0], b[1]]))))
                }
                26 => {
                    let b = self.take(4)?;
                    Ok(Value::Float(
                        f32::from_bits(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) as f64,
                    ))
                }
                27 => {
                    let b = self.take(8)?;
                    Ok(Value::Float(f64::from_bits(u64::from_be_bytes([
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    ]))))
                }
                _ => Err(DecodeError::Malformed),
            },
            _ => Err(DecodeError::Malformed),
        }
    }
    fn key(&mut self) -> Result<Key, DecodeError> {
        match self.value()? {
            Value::Text(s) => Ok(Key::Text(s)),
            Value::Bytes(b) => Ok(Key::Bytes(b)),
            Value::UInt(n) => Ok(Key::UInt(n)),
            Value::NInt(n) => Ok(Key::NInt(n)),
            Value::Bool(b) => Ok(Key::Bool(b)),
            _ => Err(DecodeError::Malformed),
        }
    }
}

fn f16_to_f64(h: u16) -> f64 {
    let sign = if (h >> 15) & 1 == 1 { -1.0 } else { 1.0 };
    let exp = ((h >> 10) & 0x1f) as i32;
    let mant = (h & 0x3ff) as f64;
    if exp == 0 {
        sign * 2f64.powi(-14) * (mant / 1024.0)
    } else if exp == 0x1f {
        if mant == 0.0 {
            sign * f64::INFINITY
        } else {
            f64::NAN
        }
    } else {
        sign * 2f64.powi(exp - 15) * (1.0 + mant / 1024.0)
    }
}

// ── small builders (host-side entity construction) ─────────────────────────────

pub fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (Key::Text(k.to_string()), v))
            .collect(),
    )
}
pub fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}
pub fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}
pub fn text_array(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::Text(s.to_string())).collect())
}

/// Look up a text-keyed entry in a `Value::Map`.
pub fn map_get<'a>(c: &'a Value, key: &str) -> Option<&'a Value> {
    match c {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            Key::Text(t) if t == key => Some(v),
            _ => None,
        }),
        _ => None,
    }
}

/// Lowercase hex (tree-path hash segments).
pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_map() {
        let v = map(vec![("x", Value::UInt(1)), ("s", text("hi"))]);
        let enc = encode(&v);
        let back = decode(&enc).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn tag_rejected_on_decode() {
        // 0xc0 = tag(0) — MUST reject (N2 / §6.3).
        assert_eq!(decode(&[0xc0, 0x00]), Err(DecodeError::TagRejected));
    }
}
