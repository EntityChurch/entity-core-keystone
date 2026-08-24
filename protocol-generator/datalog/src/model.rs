//! model.rs — the materialized entity `{type, data, content_hash}` (§1.1, §3.4) and
//! the protocol envelope (§3.1), built on the [`crate::cbor_host`] value tree.
//!
//! The canonical guarantee is DELEGATED: every content_hash is computed by the
//! C-ABI (`codec_ffi::content_hash` over `encode_bare_value(data)`), and every wire
//! frame is canonicalized by one `encode_bare_value` pass. The host never sorts a
//! map key or minimizes a float — it marshals structure and lets the seam own the
//! bytes. This keeps the S1 `codec_strategy = ffi` decision intact at the peer layer.
//!
//! N4 fidelity: a decoded inbound entity is re-materialized through the SAME seam
//! (recomputing the hash from `{type, data}`); a carried content_hash that disagrees
//! is a hard reject (§1.8).

use std::collections::BTreeMap;

use crate::cbor_host::{self, Key, Value};
use crate::codec_ffi;

/// Canonicalize a bare data value via the C-ABI, then hash it (§4.1). The data
/// bytes are embedded OPAQUE + pre-encoded by the codec, so they MUST be canonical
/// (the C `cc_content_hash` uses `ev_preencoded`).
fn content_hash(typ: &str, data: &Value) -> Vec<u8> {
    let canonical = codec_ffi::encode_bare_value(&cbor_host::encode(data))
        .expect("encode_bare_value on host-built data");
    codec_ffi::content_hash(typ.as_bytes(), &canonical).expect("content_hash via C-ABI")
}

/// A materialized entity: type name, data tree, and the 33-byte content_hash
/// (`0x00` ‖ SHA-256(ECF)).
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    pub typ: String,
    pub data: Value,
    pub hash: Vec<u8>,
}

impl Entity {
    pub fn make(typ: &str, data: Value) -> Entity {
        let hash = content_hash(typ, &data);
        Entity {
            typ: typ.to_string(),
            data,
            hash,
        }
    }

    pub fn field(&self, key: &str) -> Option<&Value> {
        cbor_host::map_get(&self.data, key)
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
    /// Parse a sub-entity carried as a CBOR map field (`params`, an inner entity).
    pub fn entity_field(&self, key: &str) -> Option<Entity> {
        entity_of_cbor(self.field(key)?).ok()
    }

    /// Wire form: `{type, data, content_hash}` (§3.1).
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

/// Parse a wire entity, recomputing + validating the hash (§1.8 / §5.2).
pub fn entity_of_cbor(c: &Value) -> Result<Entity, ModelError> {
    let typ = match cbor_host::map_get(c, "type") {
        Some(Value::Text(s)) => s.clone(),
        _ => return Err(ModelError::BadEntity),
    };
    let data = cbor_host::map_get(c, "data")
        .cloned()
        .ok_or(ModelError::BadEntity)?;
    let e = Entity::make(&typ, data);
    if let Some(Value::Bytes(carried)) = cbor_host::map_get(c, "content_hash") {
        if carried != &e.hash {
            return Err(ModelError::ContentHashMismatch);
        }
    }
    Ok(e)
}

/// A protocol envelope (§3.1): a root entity + a content-addressed bundle keyed by
/// content_hash.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub root: Entity,
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
        let inc: Vec<(Key, Value)> = self
            .included
            .iter()
            .map(|(k, e)| (Key::Bytes(k.clone()), e.to_cbor()))
            .collect();
        Value::Map(vec![
            (Key::Text("root".into()), self.root.to_cbor()),
            (Key::Text("included".into()), Value::Map(inc)),
        ])
    }
    /// Canonical wire frame payload (delegated canonicalization).
    pub fn encode(&self) -> Vec<u8> {
        codec_ffi::encode_bare_value(&cbor_host::encode(&self.to_cbor()))
            .expect("encode_bare_value on envelope")
    }
}

pub fn envelope_of_cbor(c: &Value) -> Result<Envelope, ModelError> {
    let root_src = cbor_host::map_get(c, "root").ok_or(ModelError::BadEntity)?;
    let root = entity_of_cbor(root_src)?;
    let mut included = BTreeMap::new();
    if let Some(Value::Map(kvs)) = cbor_host::map_get(c, "included") {
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

pub fn envelope_of_frame(payload: &[u8]) -> Result<Envelope, ModelError> {
    let v = cbor_host::decode(payload).map_err(ModelError::Codec)?;
    envelope_of_cbor(&v)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelError {
    BadEntity,
    ContentHashMismatch,
    IncludedKeyMismatch,
    Codec(cbor_host::DecodeError),
}

// re-export the builders at model scope for handler ergonomics.
pub use cbor_host::{bytes, hex, map, map_get, text, text_array};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_hash_is_33_bytes_and_roundtrips() {
        let e = Entity::make("system/test", map(vec![("k", Value::UInt(1))]));
        assert_eq!(e.hash.len(), 33);
        assert_eq!(e.hash[0], 0x00);
        let back = entity_of_cbor(&e.to_cbor()).unwrap();
        assert_eq!(back.hash, e.hash);
    }

    #[test]
    fn envelope_frame_roundtrip() {
        let root = Entity::make("system/root", Value::Map(vec![]));
        let env = Envelope::new(root.clone());
        let frame = env.encode();
        let back = envelope_of_frame(&frame).unwrap();
        assert_eq!(back.root.hash, root.hash);
    }

    #[test]
    fn tampered_content_hash_rejected() {
        let mut wire = Entity::make("system/test", Value::Map(vec![])).to_cbor();
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if matches!(k, Key::Text(t) if t == "content_hash") {
                    *v = Value::Bytes(vec![0xff; 33]);
                }
            }
        }
        assert_eq!(entity_of_cbor(&wire), Err(ModelError::ContentHashMismatch));
    }
}
