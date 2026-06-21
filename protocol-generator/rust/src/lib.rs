//! `entity-core-protocol-rust` — the GENERATED clean-room Rust core-protocol peer.
//!
//! S2 scope: the canonical ECF CBOR codec + native type system (encode, decode,
//! content_hash, peer-id format/parse, Ed25519 sign/verify) for the V7 core
//! types. Proven byte-identical against the go `wire-conformance` oracle (v7.75
//! surface, corpus v1). Distinct from the hand-written siblings `entity-core-rust`
//! and `entity-core-codec-ffi-rust` — an independent reimplementation from spec.
//!
//! The canonical layer is owned in full (no CBOR library): ECF's guarantees are
//! stricter than any general "deterministic CBOR" mode. See [`cbor`] for the
//! Rule 1–5 + §6.3 enforcement.
//!
//! S3 scope (this phase): the live peer machinery in [`peer`] — V7 Layers 1–4 plus
//! foundation (identity, store, capability/§5 verification, TCP transport, dispatch,
//! §6.9a seed-policy, §7a conformance handlers) on top of the S2 codec. Built for
//! `validate-peer --profile core`.

#![forbid(unsafe_code)]

pub mod base58;
pub mod cbor;
pub mod content_hash;
pub mod error;
pub mod peer;
pub mod peer_id;
pub mod signature;
pub mod value;
pub mod varint;

pub use error::{CodecError, Result};
pub use value::{Key, Value};

#[cfg(test)]
mod tests;
