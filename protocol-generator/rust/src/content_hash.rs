//! Content hash construction (V7 §1.5 / ENTITY-NATIVE-TYPE-SYSTEM §4.2).
//!
//! content_hash = varint(format_code) || SHA-256(ECF({type, data})).
//!
//! The hash input is the two-key map `{type, data}`; canonical Rule 2 sorts the
//! keys to `{data, type}` (same encoded length, "data" < "type"). format_code 0
//! is the SHA-256 floor; codes >= 0x80 exercise the multi-byte varint prefix
//! (the agility forward-compat seam). All framing routes through the real
//! LEB128 varint primitive (invariant N1).

use sha2::{Digest, Sha256};

use crate::cbor;
use crate::value::{Key, Value};
use crate::varint;

/// Compute the content_hash bytes for an entity `{type, data}` at the given
/// format code. `data` is the already-built value tree of the data field.
pub fn content_hash(entity_type: &str, data: Value, format_code: u64) -> Vec<u8> {
    let hash_input = Value::Map(vec![
        (
            Key::Text("type".to_string()),
            Value::Text(entity_type.to_string()),
        ),
        (Key::Text("data".to_string()), data),
    ]);
    let encoded = cbor::encode(&hash_input);
    let digest = Sha256::digest(&encoded);

    let mut out = varint::encode(format_code);
    out.extend_from_slice(&digest);
    out
}
