//! Hand-rolled canonical ECF CBOR codec.
//!
//! Owns the canonical layer in full (S1 `cbor_library = hand-rolled`), because
//! ECF's guarantees are stricter than any general CBOR library's "deterministic"
//! mode (profile [codec] A-RUST-001). Implements, byte-for-byte against the v1
//! conformance corpus:
//!
//! - Rule 1: shortest integer argument length (head minimization).
//! - Rule 2: map keys sorted by canonical encoded-key bytes (RFC 8949 §4.2.1;
//!   bytewise on encoded form = length-then-lex for this key space — matches
//!   the go oracle's `encodeMapCanonical`).
//! - Rule 3: definite lengths only; indefinite-length headers rejected on decode.
//! - Rule 4/4a: shortest-float ladder f64 -> f32 -> f16 with exact special bytes
//!   (NaN F97E00 / -0.0 F98000 / +Inf F97C00 / -Inf F9FC00), enforced on decode
//!   (a non-minimal float is non-canonical).
//! - Rule 5: duplicate map keys rejected on decode.
//! - §6.3: recursive major-type-6 (tag) rejection at ANY nesting depth.
//! - full uint64 / nint range (the int.10 .. [2^63, 2^64-1] band, via u64 carriers).
//! - raw-byte fidelity for byte strings.

use crate::error::{CodecError, Result};
use crate::value::{key_order, Key, Value};

// ───────────────────────── encode ─────────────────────────

/// Encode a value tree to canonical ECF bytes.
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
        Value::UInt(n) => encode_head(0, *n, out),
        Value::NInt(n) => encode_head(1, *n, out),
        Value::Float(f) => encode_float(*f, out),
        Value::Text(s) => {
            encode_head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(b) => {
            encode_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Array(items) => {
            encode_head(4, items.len() as u64, out);
            for it in items {
                encode_into(it, out);
            }
        }
        Value::Map(entries) => {
            // Canonical Rule 2 sort by encoded key bytes (stable on the
            // already-encoded key form).
            let mut pairs: Vec<(Vec<u8>, &Value)> =
                entries.iter().map(|(k, val)| (k.encoded(), val)).collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            encode_head(5, entries.len() as u64, out);
            for (kb, val) in pairs {
                out.extend_from_slice(&kb);
                encode_into(val, out);
            }
        }
    }
}

/// Emit a CBOR head: major type in the top 3 bits, shortest argument length
/// (RFC 8949 §4.2.1 Rule 1).
fn encode_head(major: u8, arg: u64, out: &mut Vec<u8>) {
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

/// Shortest-float encoding (Rule 4/4a). Try f16, then f32, then f64; the first
/// width that reproduces the exact f64 bit pattern (incl. -0.0 and NaN payload)
/// wins. Specials: +0.0/-0.0/Inf/NaN all collapse into f16.
fn encode_float(f: f64, out: &mut Vec<u8>) {
    if let Some(h) = f64_to_f16_exact(f) {
        out.push(0xf9);
        out.extend_from_slice(&h.to_be_bytes());
        return;
    }
    let s = f as f32;
    if (s as f64).to_bits() == f.to_bits() {
        out.push(0xfa);
        out.extend_from_slice(&s.to_bits().to_be_bytes());
        return;
    }
    out.push(0xfb);
    out.extend_from_slice(&f.to_bits().to_be_bytes());
}

/// Convert an f64 to a canonical f16 bit pattern IFF the half value reproduces
/// the f64 exactly. Returns `None` when f16 is lossy (so the ladder falls
/// through to f32/f64). Handles -0.0 (sign-preserving), the infinities, and the
/// canonical NaN payload 0x7e00.
fn f64_to_f16_exact(f: f64) -> Option<u16> {
    let bits = f.to_bits();
    let sign = ((bits >> 63) & 1) as u16;

    if f.is_nan() {
        // Canonical quiet NaN (Rule 4a). The corpus pins f97e00 for NaN.
        return Some(0x7e00);
    }
    if f.is_infinite() {
        return Some((sign << 15) | 0x7c00);
    }
    if f == 0.0 {
        // Covers +0.0 and -0.0; sign carries -0.0 -> 0x8000.
        return Some(sign << 15);
    }

    // Round-trip via the f32 first (half lives inside single's range/precision),
    // then half. The value survives only if half->f64 == original f64 exactly.
    let single = f as f32;
    if (single as f64).to_bits() != bits {
        return None; // not even f32-exact -> certainly not f16-exact
    }
    let half = f32_to_f16(single)?;
    if (f16_to_f64(half)).to_bits() == bits {
        Some(half)
    } else {
        None
    }
}

/// Encode an f32 into an f16 bit pattern when it is representable exactly as a
/// normal/subnormal half (no rounding). Returns `None` otherwise.
fn f32_to_f16(value: f32) -> Option<u16> {
    let x = value.to_bits();
    let sign = ((x >> 16) & 0x8000) as u16;
    let exp = ((x >> 23) & 0xff) as i32; // f32 biased exponent
    let mant = x & 0x007f_ffff; // 23-bit mantissa

    // Zero already handled by the caller; here value != 0.
    let unbiased = exp - 127;

    // Normal half range: unbiased exponent in [-14, 15].
    if (-14..=15).contains(&unbiased) {
        // f16 mantissa is 10 bits; the low 13 bits of the f32 mantissa must be
        // zero for an exact (non-rounding) conversion.
        if mant & 0x1fff != 0 {
            return None;
        }
        let half_exp = ((unbiased + 15) as u16) << 10;
        let half_mant = (mant >> 13) as u16;
        return Some(sign | half_exp | half_mant);
    }

    // Subnormal half range: 2^-24 .. 2^-15 (exact powers/sums representable).
    if (-24..-14).contains(&unbiased) {
        // Reconstruct the full significand (implicit leading 1 for normals).
        let full_mant = mant | 0x0080_0000; // 1.mant, 24 bits
        let shift = -14 - unbiased; // 1..10
                                    // Bits that would be lost on the shift into a 10-bit subnormal field.
        let total_shift = 13 + shift;
        let lost_mask = (1u32 << total_shift) - 1;
        if full_mant & lost_mask != 0 {
            return None;
        }
        let half_mant = (full_mant >> total_shift) as u16;
        return Some(sign | half_mant);
    }

    None
}

/// Decode an f16 bit pattern to f64 (exact; half is a subset of double).
fn f16_to_f64(h: u16) -> f64 {
    let sign = if (h >> 15) & 1 == 1 { -1.0 } else { 1.0 };
    let exp = ((h >> 10) & 0x1f) as i32;
    let mant = (h & 0x3ff) as f64;
    if exp == 0 {
        // Subnormal: 2^-14 * (mant / 1024).
        sign * 2f64.powi(-14) * (mant / 1024.0)
    } else if exp == 0x1f {
        if mant == 0.0 {
            sign * f64::INFINITY
        } else {
            f64::NAN
        }
    } else {
        // Normal: 2^(exp-15) * (1 + mant/1024).
        sign * 2f64.powi(exp - 15) * (1.0 + mant / 1024.0)
    }
}

// ───────────────────────── decode ─────────────────────────

/// Decode canonical ECF bytes to a value tree, rejecting any non-canonical
/// input (tags at any depth, indefinite lengths, non-minimal int/float,
/// duplicate or unsorted map keys, trailing data).
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    let v = d.value()?;
    if d.pos != d.buf.len() {
        return Err(CodecError::TrailingData);
    }
    Ok(v)
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(CodecError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a head argument for the given additional-info, enforcing minimal
    /// length (Rule 1). Returns the argument value.
    fn read_arg(&mut self, ai: u8) -> Result<u64> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => {
                let b = self.byte()?;
                if b < 24 {
                    return Err(CodecError::NonMinimalInt);
                }
                Ok(b as u64)
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v < 0x100 {
                    return Err(CodecError::NonMinimalInt);
                }
                Ok(v)
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v < 0x1_0000 {
                    return Err(CodecError::NonMinimalInt);
                }
                Ok(v)
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v < 0x1_0000_0000 {
                    return Err(CodecError::NonMinimalInt);
                }
                Ok(v)
            }
            28..=30 => Err(CodecError::Malformed),
            31 => Err(CodecError::IndefiniteLength),
            _ => Err(CodecError::Malformed),
        }
    }

    fn value(&mut self) -> Result<Value> {
        let head = self.byte()?;
        let major = head >> 5;
        let ai = head & 0x1f;
        match major {
            0 => Ok(Value::UInt(self.read_arg(ai)?)),
            1 => Ok(Value::NInt(self.read_arg(ai)?)),
            2 => {
                if ai == 31 {
                    return Err(CodecError::IndefiniteLength);
                }
                let n = self.read_arg(ai)? as usize;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                if ai == 31 {
                    return Err(CodecError::IndefiniteLength);
                }
                let n = self.read_arg(ai)? as usize;
                let s = self.take(n)?;
                let txt = std::str::from_utf8(s)
                    .map_err(|_| CodecError::Malformed)?
                    .to_string();
                Ok(Value::Text(txt))
            }
            4 => {
                if ai == 31 {
                    return Err(CodecError::IndefiniteLength);
                }
                let n = self.read_arg(ai)? as usize;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value()?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                if ai == 31 {
                    return Err(CodecError::IndefiniteLength);
                }
                let n = self.read_arg(ai)? as usize;
                self.decode_map(n)
            }
            6 => {
                // §6.3: tags are forbidden at any nesting depth. Reject the
                // whole datum the moment a tag head is seen.
                Err(CodecError::TagRejected)
            }
            7 => self.decode_simple_or_float(ai),
            _ => Err(CodecError::Malformed),
        }
    }

    fn decode_map(&mut self, n: usize) -> Result<Value> {
        let mut entries: Vec<(Key, Value)> = Vec::with_capacity(n);
        let mut prev_key_enc: Option<Vec<u8>> = None;
        for _ in 0..n {
            let key_start = self.pos;
            let key = self.key()?;
            let key_enc = self.buf[key_start..self.pos].to_vec();
            // Rule 2 / Rule 5: keys must be strictly ascending by canonical
            // encoded bytes (also catches duplicates).
            if let Some(prev) = &prev_key_enc {
                match key_enc.as_slice().cmp(prev.as_slice()) {
                    std::cmp::Ordering::Less => return Err(CodecError::UnsortedKeys),
                    std::cmp::Ordering::Equal => return Err(CodecError::DuplicateKey),
                    std::cmp::Ordering::Greater => {}
                }
            }
            prev_key_enc = Some(key_enc);
            let val = self.value()?;
            entries.push((key, val));
        }
        Ok(Value::Map(entries))
    }

    /// Decode a value in key position into a [`Key`]. Tags/floats/containers are
    /// not valid keys in the corpus surface; reject anything unexpected.
    fn key(&mut self) -> Result<Key> {
        let head = self
            .buf
            .get(self.pos)
            .copied()
            .ok_or(CodecError::Truncated)?;
        let major = head >> 5;
        match major {
            0 => match self.value()? {
                Value::UInt(n) => Ok(Key::UInt(n)),
                _ => unreachable!(),
            },
            1 => match self.value()? {
                Value::NInt(n) => Ok(Key::NInt(n)),
                _ => unreachable!(),
            },
            2 => match self.value()? {
                Value::Bytes(b) => Ok(Key::Bytes(b)),
                _ => unreachable!(),
            },
            3 => match self.value()? {
                Value::Text(s) => Ok(Key::Text(s)),
                _ => unreachable!(),
            },
            6 => Err(CodecError::TagRejected),
            7 => {
                // Allow bool keys; reject float/null/simple keys.
                let ai = head & 0x1f;
                if ai == 20 || ai == 21 {
                    match self.value()? {
                        Value::Bool(b) => Ok(Key::Bool(b)),
                        _ => unreachable!(),
                    }
                } else {
                    Err(CodecError::Malformed)
                }
            }
            _ => Err(CodecError::Malformed),
        }
    }

    /// Major type 7: simple values + floats. ECF uses 0xf4/0xf5/0xf6; floats
    /// must be in shortest form (Rule 4 decode check).
    fn decode_simple_or_float(&mut self, ai: u8) -> Result<Value> {
        match ai {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => Err(CodecError::Malformed), // undefined (0xf7) not used in ECF
            25 => {
                // f16 — always shortest by construction; decode and accept.
                let b = self.take(2)?;
                let h = u16::from_be_bytes([b[0], b[1]]);
                Ok(Value::Float(f16_to_f64(h)))
            }
            26 => {
                let b = self.take(4)?;
                let bits = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let f = f32::from_bits(bits);
                // Reject if it would have fit in f16 (non-minimal float).
                if f64_to_f16_exact(f as f64).is_some() {
                    return Err(CodecError::NonMinimalFloat);
                }
                Ok(Value::Float(f as f64))
            }
            27 => {
                let b = self.take(8)?;
                let bits = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                let f = f64::from_bits(bits);
                // Reject if a narrower form would reproduce it (non-minimal).
                if f64_to_f16_exact(f).is_some() {
                    return Err(CodecError::NonMinimalFloat);
                }
                let s = f as f32;
                if (s as f64).to_bits() == f.to_bits() {
                    return Err(CodecError::NonMinimalFloat);
                }
                Ok(Value::Float(f))
            }
            // ai 24 (1-byte simple), 28..=31 (reserved/indefinite), and simple
            // values 0..19 are all unused in ECF -> malformed.
            _ => Err(CodecError::Malformed),
        }
    }
}

/// Sort the entries of a map value into canonical order in place — a helper for
/// callers that build maps programmatically (the encoder sorts at emit time, so
/// this is only needed if one wants a pre-sorted in-memory form).
pub fn sort_map(entries: &mut [(Key, Value)]) {
    entries.sort_by(|a, b| key_order(&a.0, &b.0));
}
