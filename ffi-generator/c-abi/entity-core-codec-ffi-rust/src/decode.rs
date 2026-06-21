//! Minimal CBOR reader: reconstruct a `Value` and enforce N2 tag-rejection.
//!
//! First-pass hand-roll (see Cargo.toml note). It deliberately does NOT accept
//! CBOR tags (major type 6) anywhere: per ECF §6.3 tags are forbidden on the
//! wire, so any tag => DecodeError (this is N2). Indefinite-length items are
//! also rejected (ECF is definite-length only).

use crate::value::Value;

#[derive(Debug)]
pub struct DecodeError(pub &'static str);

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.buf.get(self.pos).ok_or(DecodeError("unexpected end of input"))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError("length overflow"))?;
        let s = self.buf.get(self.pos..end).ok_or(DecodeError("truncated item"))?;
        self.pos = end;
        Ok(s)
    }

    /// Read the argument for a head byte's low 5 bits (additional info).
    fn argument(&mut self, ai: u8) -> Result<u64, DecodeError> {
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
                Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
            }
            28..=30 => Err(DecodeError("reserved additional-info value")),
            31 => Err(DecodeError("indefinite-length not allowed in ECF")),
            _ => unreachable!(),
        }
    }

    fn value(&mut self) -> Result<Value, DecodeError> {
        let head = self.byte()?;
        let major = head >> 5;
        let ai = head & 0x1f;
        match major {
            0 => Ok(Value::Int(self.argument(ai)? as i128)),
            1 => {
                let arg = self.argument(ai)? as i128;
                Ok(Value::Int(-1 - arg))
            }
            2 => {
                let n = self.argument(ai)? as usize;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.argument(ai)? as usize;
                let s = core::str::from_utf8(self.take(n)?).map_err(|_| DecodeError("invalid utf-8 in text string"))?;
                Ok(Value::Text(s.to_string()))
            }
            4 => {
                let n = self.argument(ai)? as usize;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value()?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let n = self.argument(ai)? as usize;
                let mut pairs = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.value()?;
                    let v = self.value()?;
                    pairs.push((k, v));
                }
                Ok(Value::Map(pairs))
            }
            6 => Err(DecodeError("CBOR tag (major type 6) forbidden in ECF (N2)")),
            7 => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                25 => {
                    let b = self.take(2)?;
                    Ok(Value::Float(half::f16::from_bits(u16::from_be_bytes([b[0], b[1]])).to_f64()))
                }
                26 => {
                    let b = self.take(4)?;
                    Ok(Value::Float(f32::from_bits(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) as f64))
                }
                27 => {
                    let b = self.take(8)?;
                    Ok(Value::Float(f64::from_bits(u64::from_be_bytes([
                        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    ]))))
                }
                23 => Err(DecodeError("undefined (0xf7) not used in ECF")),
                _ => Err(DecodeError("unsupported simple value")),
            },
            _ => unreachable!(),
        }
    }
}

/// Decode a single self-delimiting ECF value. Errors on trailing bytes, tags
/// (N2), and indefinite-length items.
pub fn decode_value(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut r = Reader::new(bytes);
    let v = r.value()?;
    if r.pos != bytes.len() {
        return Err(DecodeError("trailing bytes after top-level item"));
    }
    Ok(v)
}

/// N2 gate: returns Ok(()) iff the bytes are a single well-formed ECF item with
/// NO tag anywhere (decode_value already rejects tags during the structural
/// walk). This is what `ec_decode_entity` uses to satisfy decode_reject.
pub fn validate_no_tags(bytes: &[u8]) -> Result<(), DecodeError> {
    decode_value(bytes).map(|_| ())
}

/// Byte span (offset, length) of a sub-item within the decoded buffer. Used to
/// hand the caller borrowed slices of the ORIGINAL wire bytes (N4, spec §4.1
/// option a) — never a re-encode of the decoded structure.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Span {
    pub off: usize,
    pub len: usize,
}

impl<'a> Reader<'a> {
    /// Walk one value, discarding the reconstructed `Value`, returning the byte
    /// span it occupied. Tag/indefinite rejection (N2) still applies.
    fn span_of_value(&mut self) -> Result<Span, DecodeError> {
        let start = self.pos;
        self.value()?;
        Ok(Span { off: start, len: self.pos - start })
    }
}

/// N4 decode: structurally validate a single entity map `{type, data, ...}` and
/// return the byte spans of its `type` and `data` values within `bytes`. The
/// whole-entity span is the full input (caller already holds it). Rejects tags
/// (N2) anywhere via the structural walk.
pub fn entity_spans(bytes: &[u8]) -> Result<(Span, Span), DecodeError> {
    let mut r = Reader::new(bytes);
    let head = r.byte()?;
    if head >> 5 != 5 {
        return Err(DecodeError("entity is not a CBOR map"));
    }
    let n = r.argument(head & 0x1f)? as usize;
    let mut type_span = None;
    let mut data_span = None;
    for _ in 0..n {
        let key = r.value()?;
        let vspan = r.span_of_value()?;
        if let Value::Text(s) = &key {
            match s.as_str() {
                "type" => type_span = Some(vspan),
                "data" => data_span = Some(vspan),
                _ => {}
            }
        }
    }
    if r.pos != bytes.len() {
        return Err(DecodeError("trailing bytes after entity"));
    }
    match (type_span, data_span) {
        (Some(t), Some(d)) => Ok((t, d)),
        _ => Err(DecodeError("entity missing type or data")),
    }
}

/// A structural view of an `{root, included}` envelope, as byte spans into the
/// original wire. `included` is the list of (key-hash span, entity span) pairs.
pub struct EnvelopeView {
    pub root: Span,
    pub included: Vec<(Span, Span)>,
}

/// Walk an envelope map, returning spans for `root` and each `included` entry.
/// Rejects tags (N2) during the walk. Missing `included` is treated as empty.
pub fn envelope_view(bytes: &[u8]) -> Result<EnvelopeView, DecodeError> {
    let mut r = Reader::new(bytes);
    let head = r.byte()?;
    if head >> 5 != 5 {
        return Err(DecodeError("envelope is not a CBOR map"));
    }
    let n = r.argument(head & 0x1f)? as usize;
    let mut root = None;
    let mut included = Vec::new();
    for _ in 0..n {
        let key = r.value()?;
        match &key {
            Value::Text(s) if s == "root" => {
                root = Some(r.span_of_value()?);
            }
            Value::Text(s) if s == "included" => {
                // included is itself a map: hash-bytes => entity.
                let ihead = r.byte()?;
                if ihead >> 5 != 5 {
                    return Err(DecodeError("included is not a CBOR map"));
                }
                let m = r.argument(ihead & 0x1f)? as usize;
                for _ in 0..m {
                    let kspan = r.span_of_value()?;
                    let espan = r.span_of_value()?;
                    included.push((kspan, espan));
                }
            }
            _ => {
                // Unknown envelope key: skip its value.
                let _ = r.span_of_value()?;
            }
        }
    }
    if r.pos != bytes.len() {
        return Err(DecodeError("trailing bytes after envelope"));
    }
    match root {
        Some(root) => Ok(EnvelopeView { root, included }),
        None => Err(DecodeError("envelope missing root")),
    }
}
