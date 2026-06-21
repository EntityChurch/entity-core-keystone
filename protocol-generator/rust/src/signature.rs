//! Ed25519 sign/verify (RFC 8032; V7 §1.4 / system/signature).
//!
//! Deterministic signing by construction (no RNG to sign) via `ed25519-dalek`.
//! A signature over an entity is the Ed25519 signature over the canonical-ECF
//! encoding of that entity (the same bytes content_hash consumes). A fixed seed
//! over a fixed message therefore produces a fixed 64-byte signature — what the
//! `signature.*` corpus vectors pin.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::cbor;
use crate::error::{CodecError, Result};
use crate::value::Value;

/// Sign the canonical-ECF encoding of `entity` with the 32-byte Ed25519 `seed`.
/// Returns the 64-byte signature.
pub fn sign_entity(seed: &[u8; 32], entity: &Value) -> [u8; 64] {
    let key = SigningKey::from_bytes(seed);
    let msg = cbor::encode(entity);
    key.sign(&msg).to_bytes()
}

/// Verify a 64-byte signature over the canonical-ECF encoding of `entity`
/// against a 32-byte Ed25519 public key.
pub fn verify_entity(public: &[u8; 32], entity: &Value, sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public).map_err(|_| CodecError::Malformed)?;
    let signature = Signature::from_bytes(sig);
    let msg = cbor::encode(entity);
    vk.verify(&msg, &signature)
        .map_err(|_| CodecError::NonCanonicalEcf)
}

/// Derive the 32-byte Ed25519 public key from a 32-byte seed.
pub fn public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}
