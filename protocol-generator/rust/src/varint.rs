//! Multicodec-style LEB128 unsigned varint (V7 §1.5 / §7.3).
//!
//! Codes 0..127 are a single byte with the high bit clear; codes >= 128 emit
//! continuation bytes (high bit set on every byte except the last), low 7 bits
//! first. Used for the content_hash `format_code` prefix and the peer-id
//! key_type/hash_type prefix. Hand-rolled per the S1 `varint_handling = native`
//! decision (route ALL framing through this primitive — invariant N1).

use crate::error::{CodecError, Result};

/// Encode `v` as a LEB128 varint.
pub fn encode(v: u64) -> Vec<u8> {
    if v < 0x80 {
        return vec![v as u8];
    }
    let mut out = Vec::new();
    let mut x = v;
    while x >= 0x80 {
        out.push(((x & 0x7f) as u8) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
    out
}

/// Decode a LEB128 varint from the front of `buf`, returning `(value,
/// bytes_consumed)`. Rejects non-minimal encodings (a trailing 0x00
/// continuation) and overlong (> 10-byte) sequences.
pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if i == 10 {
            return Err(CodecError::Malformed);
        }
        let payload = (b & 0x7f) as u64;
        if shift >= 64 || (shift == 63 && payload > 1) {
            return Err(CodecError::Malformed);
        }
        result |= payload << shift;
        if b & 0x80 == 0 {
            // Minimality: a non-final-position zero payload on the last byte
            // (except the lone single-byte 0) is non-minimal.
            if i > 0 && payload == 0 {
                return Err(CodecError::NonMinimalInt);
            }
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(CodecError::Truncated)
}
