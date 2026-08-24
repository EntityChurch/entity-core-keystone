//! identity.rs — a peer's keypair + the entities it derives (§1.5, §3.5, §7.3).
//! All crypto crosses the C-ABI seam (`codec_ffi`); the host never hand-rolls it.
//!
//! ```text
//!   public_key    = ed25519_seed_to_pubkey(seed)                 (32 bytes)
//!   peer_id       = Base58(varint(1) ‖ varint(0) ‖ public_key)   (§1.5 v7.65
//!                   identity-multihash — key_type 0x01 = ed25519, hash_type 0x00)
//!   peer entity   = system/peer { public_key, key_type }         (§3.5)
//!   identity_hash = content_hash(peer entity)                    (33 bytes)
//! ```
//!
//! Signing target = the entity's 33-byte content_hash (NOT an ECF re-encoding) —
//! the reference-peer `system/signature` shape.

use crate::cbor_host::{self, Value};
use crate::codec_ffi;
use crate::model::{self, Entity};

#[derive(Clone, Debug)]
pub struct Identity {
    pub seed: [u8; 32],
    pub public_key: [u8; 32],
    pub peer_id: String,
    pub peer_entity: Entity,
    pub identity_hash: Vec<u8>,
}

impl Identity {
    pub fn of_seed(seed: [u8; 32]) -> Identity {
        let public_key = codec_ffi::ed25519_seed_to_pubkey(&seed).expect("seed_to_pubkey");
        let peer_entity = peer_entity_of_pubkey(&public_key);
        let identity_hash = peer_entity.hash.clone();
        let peer_id = peer_id_of_pubkey(&public_key);
        Identity {
            seed,
            public_key,
            peer_id,
            peer_entity,
            identity_hash,
        }
    }

    /// Sign an entity's 33-byte content_hash → a `system/signature` entity (§3.5).
    pub fn sign_entity(&self, target: &Entity) -> Entity {
        let sig = codec_ffi::ed25519_sign(&self.seed, &target.hash).expect("ed25519_sign");
        Entity::make(
            "system/signature",
            cbor_host::map(vec![
                ("target", cbor_host::bytes(&target.hash)),
                ("signer", cbor_host::bytes(&self.identity_hash)),
                ("algorithm", cbor_host::text("ed25519")),
                ("signature", cbor_host::bytes(&sig)),
            ]),
        )
    }
}

/// Build the `system/peer` entity for a public key (§3.5; v7.65 — no peer_id field
/// in the hashable basis).
pub fn peer_entity_of_pubkey(public_key: &[u8]) -> Entity {
    Entity::make(
        "system/peer",
        cbor_host::map(vec![
            ("public_key", cbor_host::bytes(public_key)),
            ("key_type", cbor_host::text("ed25519")),
        ]),
    )
}

/// Canonical Ed25519 peer_id (§1.5 v7.65 identity-multihash) via the codec seam.
pub fn peer_id_of_pubkey(public_key: &[u8]) -> String {
    codec_ffi::peerid_format(0x01, 0x00, public_key).expect("peerid_format")
}

/// Verify a `system/signature` entity against the signer's `system/peer` entity.
/// The host does the crypto (C-ABI) and asserts `verified_signer(_)` into Ascent;
/// Datalog never touches a key or a byte.
pub fn verify_signature(sig_entity: &Entity, signer_peer: &Entity) -> bool {
    let target = match sig_entity.bytes_field("target") {
        Some(t) => t,
        None => return false,
    };
    let sig = match sig_entity.bytes_field("signature") {
        Some(s) if s.len() == 64 => s,
        _ => return false,
    };
    let pubkey = match signer_peer.bytes_field("public_key") {
        Some(p) if p.len() == 32 => p,
        _ => return false,
    };
    codec_ffi::ed25519_verify(pubkey, target, sig)
}

/// A `system/hash` result entity (§3.4).
pub fn hash_entity(h: &[u8]) -> Entity {
    Entity::make("system/hash", Value::Bytes(h.to_vec()))
}

#[allow(unused_imports)]
use model as _model; // keep model in scope for doc-links

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_and_sign_verify() {
        let id = Identity::of_seed([7u8; 32]);
        let sig = id.sign_entity(&id.peer_entity);
        assert!(verify_signature(&sig, &id.peer_entity));
        // peer_id parses back to key_type=1, hash_type=0, digest=pubkey.
        let (kt, ht, digest) = codec_ffi::peerid_parse(&id.peer_id).unwrap();
        assert_eq!((kt, ht), (1, 0));
        assert_eq!(digest, id.public_key.to_vec());
    }
}
