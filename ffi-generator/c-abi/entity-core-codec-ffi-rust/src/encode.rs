//! Hand-written canonical ECF encoder.
//!
//! No CBOR library is trusted to produce canonical output (spec §3, R1). This
//! module owns every canonical guarantee:
//!   - shortest-form integer arguments (RFC 8949 §4.2.1 Rule 1)
//!   - shortest-float minimization + the four special floats (§3.5 / Rule 4a)
//!   - map keys sorted bytewise-lexicographically on their *encoded* form
//!     (RFC 8949 §4.2.1 Core Deterministic — what the Go reference fxamacker
//!     CoreDet produced, which is the fixture's source of truth; see F4 note).

use crate::value::Value;

const MT_UINT: u8 = 0 << 5;
const MT_NINT: u8 = 1 << 5;
const MT_BYTES: u8 = 2 << 5;
const MT_TEXT: u8 = 3 << 5;
const MT_ARRAY: u8 = 4 << 5;
const MT_MAP: u8 = 5 << 5;

/// Encode a value to canonical ECF bytes.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(n) => encode_int(*n, out),
        Value::Float(f) => encode_float(*f, out),
        Value::Bytes(b) => {
            encode_head(MT_BYTES, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            let b = s.as_bytes();
            encode_head(MT_TEXT, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Array(items) => {
            encode_head(MT_ARRAY, items.len() as u64, out);
            for it in items {
                encode_into(it, out);
            }
        }
        Value::Map(pairs) => encode_map(pairs, out),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::PreEncoded(bytes) => out.extend_from_slice(bytes),
    }
}

/// Major-type head with the shortest argument encoding.
fn encode_head(major: u8, n: u64, out: &mut Vec<u8>) {
    if n < 24 {
        out.push(major | n as u8);
    } else if n <= 0xff {
        out.push(major | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(major | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(major | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_int(n: i128, out: &mut Vec<u8>) {
    if n >= 0 {
        encode_head(MT_UINT, n as u64, out);
    } else {
        // CBOR negative: major 1 with argument (-1 - n).
        let m = (-1 - n) as u64;
        encode_head(MT_NINT, m, out);
    }
}

/// Shortest-float per §3.5: try f16, then f32, then f64; specials are exact f16.
fn encode_float(f: f64, out: &mut Vec<u8>) {
    if f.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]); // canonical quiet NaN
        return;
    }
    if f.is_infinite() {
        out.extend_from_slice(if f > 0.0 { &[0xf9, 0x7c, 0x00] } else { &[0xf9, 0xfc, 0x00] });
        return;
    }
    if f == 0.0 {
        // distinguishes +0.0 / -0.0 by sign bit
        out.extend_from_slice(if f.is_sign_negative() { &[0xf9, 0x80, 0x00] } else { &[0xf9, 0x00, 0x00] });
        return;
    }

    // f16 if it round-trips exactly.
    let h = half::f16::from_f64(f);
    if h.to_f64() == f {
        out.push(0xf9);
        out.extend_from_slice(&h.to_bits().to_be_bytes());
        return;
    }
    // f32 if it round-trips exactly.
    let s = f as f32;
    if s as f64 == f {
        out.push(0xfa);
        out.extend_from_slice(&s.to_bits().to_be_bytes());
        return;
    }
    // otherwise full f64.
    out.push(0xfb);
    out.extend_from_slice(&f.to_bits().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &Value) -> String {
        encode(v).iter().map(|b| format!("{:02x}", b)).collect()
    }

    // The fixture's `int` category tops out at i64::MAX (9223372036854775807).
    // CBOR major-type-0 uints in [2^63, 2^64-1] are valid but UNTESTED by the
    // corpus — and that is exactly where a signed-i64 decode overflows. These
    // lock our encoder across that gap (mirror in entity-core-codec-ffi-c).
    #[test]
    fn uint_above_i64_max() {
        assert_eq!(hex(&Value::Int(9223372036854775808_i128)), "1b8000000000000000"); // 2^63
        assert_eq!(hex(&Value::Int(18446744073709551615_i128)), "1bffffffffffffffff"); // u64::MAX
    }

    // Negatives beyond the corpus's -256: larger args + the i64::MIN boundary.
    #[test]
    fn negatives_beyond_corpus() {
        assert_eq!(hex(&Value::Int(-257)), "390100"); // -1-(-257)=256 → major1, 2-byte arg
        assert_eq!(hex(&Value::Int(-65537)), "3a00010000"); // 65536 → 4-byte arg
        assert_eq!(hex(&Value::Int(-9223372036854775808_i128)), "3b7fffffffffffffff"); // i64::MIN
    }

    // Float specials + shortest-form selection (spec §3.5), re-pinned locally.
    #[test]
    fn float_specials_and_shortest() {
        assert_eq!(hex(&Value::Float(f64::NAN)), "f97e00");
        assert_eq!(hex(&Value::Float(f64::INFINITY)), "f97c00");
        assert_eq!(hex(&Value::Float(f64::NEG_INFINITY)), "f9fc00");
        assert_eq!(hex(&Value::Float(-0.0)), "f98000");
        assert_eq!(hex(&Value::Float(1.5)), "f93e00"); // f16
        assert_eq!(hex(&Value::Float(100000.0)), "fa47c35000"); // f32
        assert_eq!(hex(&Value::Float(1.1)), "fb3ff199999999999a"); // f64
    }
}

fn encode_map(pairs: &[(Value, Value)], out: &mut Vec<u8>) {
    // Encode each (key, value) pair independently, then sort by the encoded KEY
    // bytes, bytewise-lexicographic (RFC 8949 §4.2.1). Length-first ordering
    // falls out for same-major-type keys because the length lives in the head.
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = pairs
        .iter()
        .map(|(k, v)| (encode(k), encode(v)))
        .collect();
    encoded.sort_by(|a, b| a.0.cmp(&b.0));

    encode_head(MT_MAP, pairs.len() as u64, out);
    for (k, v) in encoded {
        out.extend_from_slice(&k);
        out.extend_from_slice(&v);
    }
}
