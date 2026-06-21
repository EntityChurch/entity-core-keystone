//! Identity (L1) — a peer's keypair and the entities derived from it (§1.5, §3.5,
//! §7.3). The peer identity is a 32-byte Ed25519 seed; everything else derives:
//!
//! ```text
//!   public_key    = Ed25519 pub of seed                          (32 bytes)
//!   peer_id       = Base58(varint(1) ‖ varint(0) ‖ public_key)   (§1.5 v7.65
//!                   identity-multihash — key_type 0x01 = ed25519, hash_type 0x00,
//!                   digest = raw public_key; NOT the stale §7.4 SHA-256 form)
//!   peer entity   = system/peer { key_type, public_key }         (§3.5; v7.65 —
//!                   NO peer_id in the hashable basis)
//!   identity_hash = content_hash(peer entity)                    (33 bytes)
//! ```
//!
//! Cohort-confirmed (A-ZIG-001 / A-OC-007): the canonical identity-multihash
//! peer_id is what an oracle expects at handshake; the §7.4 "NORMATIVE" SHA-256
//! form is decode-only. Signing is over the full 33-byte content_hash of the
//! target entity (the dispatcher's `system/signature` shape) — distinct from the
//! S2 codec's `signature::sign_entity` (which signs the entity's ECF bytes); the
//! peer layer signs the *hash*, matching the reference peer.

use crate::peer_id;
use crate::signature;

use super::model::{self, Entity};

/// A peer's identity material + derived entities.
#[derive(Clone, Debug)]
pub struct Identity {
    pub seed: [u8; 32],
    pub public_key: [u8; 32],
    /// Base58 canonical identity-multihash peer-id.
    pub peer_id: String,
    /// The `system/peer` entity.
    pub peer_entity: Entity,
    /// content_hash of `peer_entity` (33 bytes).
    pub identity_hash: Vec<u8>,
}

impl Identity {
    pub fn of_seed(seed: [u8; 32]) -> Identity {
        let public_key = signature::public_from_seed(&seed);
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

    /// Sign an entity's 33-byte content_hash, producing a `system/signature`
    /// entity (§3.5). The signature target IS the entity's content_hash.
    pub fn sign_entity(&self, target: &Entity) -> Entity {
        let sig = sign_hash(&self.seed, &target.hash);
        Entity::make(
            "system/signature",
            model::map(vec![
                ("target", model::bytes(&target.hash)),
                ("signer", model::bytes(&self.identity_hash)),
                ("algorithm", model::text("ed25519")),
                ("signature", model::bytes(&sig)),
            ]),
        )
    }
}

/// Build the `system/peer` entity for a public key (§3.5; v7.65 — no peer_id
/// field in the hashable basis).
pub fn peer_entity_of_pubkey(public_key: &[u8]) -> Entity {
    Entity::make(
        "system/peer",
        model::map(vec![
            ("public_key", model::bytes(public_key)),
            ("key_type", model::text("ed25519")),
        ]),
    )
}

/// Canonical Ed25519 peer_id (§1.5 v7.65 identity-multihash).
pub fn peer_id_of_pubkey(public_key: &[u8]) -> String {
    peer_id::format(0x01, 0x00, public_key)
}

/// Sign a 33-byte content_hash with the seed; returns the 64-byte signature. The
/// message signed is the raw hash bytes (NOT an ECF re-encoding).
fn sign_hash(seed: &[u8; 32], hash: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(seed);
    key.sign(hash).to_bytes()
}

/// Verify a `system/signature` entity against the signer's `system/peer` entity.
/// The §5.2 signer-hash binding is the caller's responsibility.
pub fn verify_signature(sig_entity: &Entity, signer_peer: &Entity) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let target = match sig_entity.bytes_field("target") {
        Some(t) => t,
        None => return false,
    };
    let sig_bytes = match sig_entity.bytes_field("signature") {
        Some(s) if s.len() == 64 => s,
        _ => return false,
    };
    let pub_bytes = match signer_peer.bytes_field("public_key") {
        Some(p) if p.len() == 32 => p,
        _ => return false,
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pub_bytes);
    let mut sg = [0u8; 64];
    sg.copy_from_slice(sig_bytes);
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(k) => k,
        Err(_) => return false,
    };
    vk.verify(target, &Signature::from_bytes(&sg)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_derivation_and_sign_verify() {
        let id = Identity::of_seed([7u8; 32]);
        // peer_id decodes to key_type=1, hash_type=0, digest = pubkey.
        let parsed = peer_id::parse(&id.peer_id).unwrap();
        assert_eq!(parsed.key_type, 1);
        assert_eq!(parsed.hash_type, 0);
        assert_eq!(parsed.digest, id.public_key.to_vec());

        let sig = id.sign_entity(&id.peer_entity);
        assert!(verify_signature(&sig, &id.peer_entity));
    }

    #[test]
    fn signature_target_is_content_hash() {
        let id = Identity::of_seed([3u8; 32]);
        let target = Entity::make("system/test", crate::value::Value::Map(vec![]));
        let sig = id.sign_entity(&target);
        assert_eq!(sig.bytes_field("target"), Some(target.hash.as_slice()));
    }
}
