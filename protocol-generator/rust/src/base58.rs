//! Base58 (Bitcoin alphabet) encode/decode.
//!
//! Hand-rolled per the S1 `base58_library = hand-rolled` decision (dodges a
//! `bs58` registry pin; same call C#/Go made). Used by the peer-id grammar
//! (V7 §1.2): peer-id = Base58(varint(key_type) || varint(hash_type) || digest).

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes to a Base58 string (Bitcoin alphabet). Leading zero bytes map
/// to leading '1's.
pub fn encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();

    // Big-endian base-256 -> base-58 via repeated division.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    if out.is_empty() {
        // All-empty input encodes to empty string.
    }
    out
}

/// Decode a Base58 string back to bytes. Returns `None` on an invalid
/// character. Leading '1's map back to leading zero bytes.
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let mut value: Vec<u8> = Vec::new(); // big-endian base-256 accumulator
    let ones = input.bytes().take_while(|&b| b == b'1').count();

    for c in input.bytes().skip(ones) {
        let idx = ALPHABET.iter().position(|&a| a == c)?;
        let mut carry = idx as u32;
        for v in value.iter_mut() {
            carry += (*v as u32) * 58;
            *v = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            value.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = vec![0u8; ones];
    out.reserve(value.len());
    out.extend(value.iter().rev());
    Some(out)
}
