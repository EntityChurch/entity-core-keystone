//! Entity model (L-foundation) — the materialized `{type, data, content_hash}`
//! form (V7 §1.1, §3.4) and the protocol envelope (§3.1), lifted onto the S2
//! `cbor::Value` tree.
//!
//! An [`Entity`] owns its type string, its data tree, and its 33-byte
//! content_hash (`0x00` format byte ‖ 32-byte SHA-256, the ecfv1-sha256 floor —
//! [`content_hash`] at format_code 0 yields exactly that). Rust's ownership model
//! makes this allocation discipline implicit (no manual `deinit`, unlike the
//! no-GC Zig peer this is modeled on).
//!
//! N4 validate-before-trust: a decoded inbound entity is re-materialized through
//! our own codec (recomputing the hash from `{type, data}`); we trust the
//! recomputed hash, not the wire bytes (§5.2), so a forwarded entity is canonical
//! by construction. A carried `content_hash` that disagrees is a hard reject (§1.8).

use std::collections::BTreeMap;

use crate::content_hash::content_hash;
use crate::value::{Key, Value};

/// A materialized entity: its type name, data tree, and content_hash (33 bytes).
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    /// The entity type, e.g. `system/peer`.
    pub typ: String,
    /// The entity data tree (a CBOR map for structured entities).
    pub data: Value,
    /// content_hash = `0x00` ‖ SHA-256(ECF({type, data})), 33 bytes.
    pub hash: Vec<u8>,
}

impl Entity {
    /// Construct a materialized entity, computing the content_hash under the
    /// ecfv1-sha256 floor (format_code 0).
    pub fn make(typ: &str, data: Value) -> Entity {
        let hash = content_hash(typ, data.clone(), 0);
        Entity {
            typ: typ.to_string(),
            data,
            hash,
        }
    }

    /// Field accessor: the raw value at `key` (data must be a map).
    pub fn field(&self, key: &str) -> Option<&Value> {
        map_get(&self.data, key)
    }

    pub fn text_field(&self, key: &str) -> Option<&str> {
        match self.field(key)? {
            Value::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn bytes_field(&self, key: &str) -> Option<&[u8]> {
        match self.field(key)? {
            Value::Bytes(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn uint_field(&self, key: &str) -> Option<u64> {
        match self.field(key)? {
            Value::UInt(n) => Some(*n),
            _ => None,
        }
    }

    /// Parse a sub-entity carried as a CBOR map field (e.g. `params`, the inner
    /// entity in a put). Returns the recomputed canonical entity (or `None` if the
    /// field is absent / not an entity-shaped map).
    pub fn entity_field(&self, key: &str) -> Option<Entity> {
        entity_of_cbor(self.field(key)?).ok()
    }

    /// Wire form: the entity carries its content_hash so it is self-describing
    /// across serialization (§3.1).
    pub fn to_cbor(&self) -> Value {
        Value::Map(vec![
            (Key::Text("type".into()), Value::Text(self.typ.clone())),
            (Key::Text("data".into()), self.data.clone()),
            (
                Key::Text("content_hash".into()),
                Value::Bytes(self.hash.clone()),
            ),
        ])
    }
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

/// Parse a wire entity, recomputing the hash from `{type, data}` and validating
/// it against any carried `content_hash` (§1.8 fidelity). We trust the recomputed
/// hash (§5.2 validate-before-trust).
pub fn entity_of_cbor(c: &Value) -> Result<Entity, ModelError> {
    let typ = match map_get(c, "type") {
        Some(Value::Text(s)) => s.clone(),
        _ => return Err(ModelError::BadEntity),
    };
    let data = map_get(c, "data").cloned().ok_or(ModelError::BadEntity)?;
    let e = Entity::make(&typ, data);
    if let Some(Value::Bytes(carried)) = map_get(c, "content_hash") {
        if carried != &e.hash {
            return Err(ModelError::ContentHashMismatch);
        }
    }
    Ok(e)
}

/// A protocol envelope (§3.1): a root entity plus a content-addressed bundle of
/// included entities keyed by content_hash.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub root: Entity,
    /// content_hash bytes → entity. A `BTreeMap` keyed on the hash bytes gives a
    /// deterministic `included` ordering and O(log n) lookup.
    pub included: BTreeMap<Vec<u8>, Entity>,
}

impl Envelope {
    pub fn new(root: Entity) -> Envelope {
        Envelope {
            root,
            included: BTreeMap::new(),
        }
    }

    pub fn with_included(root: Entity, included: Vec<Entity>) -> Envelope {
        let mut map = BTreeMap::new();
        for e in included {
            map.insert(e.hash.clone(), e);
        }
        Envelope {
            root,
            included: map,
        }
    }

    pub fn included_get(&self, h: &[u8]) -> Option<&Entity> {
        self.included.get(h)
    }

    pub fn to_cbor(&self) -> Value {
        let inc_pairs: Vec<(Key, Value)> = self
            .included
            .iter()
            .map(|(k, e)| (Key::Bytes(k.clone()), e.to_cbor()))
            .collect();
        Value::Map(vec![
            (Key::Text("root".into()), self.root.to_cbor()),
            (Key::Text("included".into()), Value::Map(inc_pairs)),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        crate::cbor::encode(&self.to_cbor())
    }
}

/// Build an envelope from a decoded `cbor::Value`. Validates each `included` key
/// matches its entity hash (§3.1).
pub fn envelope_of_cbor(c: &Value) -> Result<Envelope, ModelError> {
    let root_src = map_get(c, "root").ok_or(ModelError::BadEntity)?;
    let root = entity_of_cbor(root_src)?;
    let mut included = BTreeMap::new();
    if let Some(Value::Map(kvs)) = map_get(c, "included") {
        for (k, v) in kvs {
            let key_bytes = match k {
                Key::Bytes(b) => b.clone(),
                _ => return Err(ModelError::BadEntity),
            };
            let e = entity_of_cbor(v)?;
            if key_bytes != e.hash {
                return Err(ModelError::IncludedKeyMismatch);
            }
            included.insert(key_bytes, e);
        }
    }
    Ok(Envelope { root, included })
}

/// Decode a length-prefixed frame payload into an envelope.
pub fn envelope_of_frame(payload: &[u8]) -> Result<Envelope, ModelError> {
    let v = crate::cbor::decode(payload).map_err(ModelError::Codec)?;
    envelope_of_cbor(&v)
}

/// Model-layer parse errors (distinct from the codec's [`crate::CodecError`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelError {
    /// A map lacked the `type`/`data` an entity requires.
    BadEntity,
    /// A carried content_hash disagreed with the recomputed one (§1.8).
    ContentHashMismatch,
    /// An `included` key did not equal its entity's content_hash (§3.1).
    IncludedKeyMismatch,
    /// The underlying codec rejected the bytes.
    Codec(crate::CodecError),
}

// ── small Value helpers ──────────────────────────────────────────────────────

/// Lowercase hex of a byte slice (tree-path hash segments).
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// A text-keyed map from `(key, value)` pairs (the common entity-data builder).
pub fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (Key::Text(k.to_string()), v))
            .collect(),
    )
}

/// A text value.
pub fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

/// A byte-string value.
pub fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

/// An array of text values.
pub fn text_array(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::Text(s.to_string())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_make_hash_is_33_bytes() {
        let e = Entity::make("system/test", map(vec![("k", Value::UInt(1))]));
        assert_eq!(e.hash.len(), 33);
        assert_eq!(e.hash[0], 0x00); // format byte
        assert_eq!(e.uint_field("k"), Some(1));
    }

    #[test]
    fn entity_wire_roundtrip_validates_content_hash() {
        let e = Entity::make("system/test", map(vec![("x", Value::UInt(7))]));
        let wire = e.to_cbor();
        let back = entity_of_cbor(&wire).unwrap();
        assert_eq!(e.hash, back.hash);
    }

    #[test]
    fn envelope_frame_roundtrip() {
        let root = Entity::make("system/root", Value::Map(vec![]));
        let env = Envelope::new(root.clone());
        let frame = env.encode();
        let back = envelope_of_frame(&frame).unwrap();
        assert_eq!(root.hash, back.root.hash);
    }

    #[test]
    fn content_hash_mismatch_rejected() {
        let mut wire = Entity::make("system/test", Value::Map(vec![])).to_cbor();
        // tamper the carried content_hash
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Key::Text(t) = k {
                    if t == "content_hash" {
                        *v = Value::Bytes(vec![0xff; 33]);
                    }
                }
            }
        }
        assert_eq!(entity_of_cbor(&wire), Err(ModelError::ContentHashMismatch));
    }
}
