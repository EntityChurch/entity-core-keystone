//! The live peer machinery (S3) — V7 Layers 1–4 plus foundation, built on the S2
//! canonical ECF codec (`crate::{cbor, content_hash, peer_id, signature}`).
//!
//! Module map:
//! - [`model`]      — the materialized entity + envelope (§3.1) over `cbor::Value`.
//! - [`identity`]   — keypair → peer-id / peer-entity / content-hash signing (§1.5, §3.5).
//! - [`store`]      — the §1.7 content/tree store, `RwLock`-guarded (§4.8).
//! - [`wire`]       — §1.6 framing + EXECUTE / EXECUTE_RESPONSE builders + §4.10(a) bound.
//! - [`capability`] — §5 verification core: chain-walk, attenuation, verdict
//!   trichotomy, §4.10(b) chain-depth pre-check, §3.6 K-of-N multisig.
//! - [`type_defs`]  — the 53 core `system/type` entities (render-from-model floor).
//! - [`core`]       — the `Peer`: bootstrap, the four MUST handlers, the §6.6 dispatch
//!   chain, §6.9a seed-policy, §7a conformance handlers.
//! - [`transport`]  — TCP listener/dialer, the §6.11 reader-demux, two-peer loopback.
//! - [`handler`]    — the extension-host surface: native handler install (H1/H3), the
//!   frame budget (H6), the entity-native evaluator seam (H7), local dispatch.
//! - [`host`]       — the peer's own host as a library function (`run_host`), and the
//!   readiness record.
//! - [`seed_policy`] — the §6.9a seed policy as a value, and its keystone file format.
//!
//! Idiom: `std::thread` + `std::sync` (no async runtime — A-RUST-003), `Result`/
//! `Option` over the fallible surface, exhaustive `match` on the verdict ADTs. The
//! store is the only shared mutable state and is structurally race-safe (a shared
//! unsynchronized store is a compile error — the §4.8 floor, free in Rust).

pub mod capability;
pub mod core;
pub mod handler;
pub mod host;
pub mod identity;
mod json;
pub mod model;
pub mod seed_policy;
pub mod store;
pub mod transport;
pub mod type_defs;
pub mod wire;

pub use core::{Conn, CreateOptions, Peer, PeerConfig};
pub use handler::{
    ExpressionEvaluator, ExpressionRequest, FnHandler, Handler, HandlerContext, HandlerHandle,
    HandlerResult, HandlerSpec, LocalExecute, OperationSpec, RegisterError,
};
pub use host::{run_host, run_host_announcing, run_host_with};
pub use store::{ConsumerId, ContentStoreEvent, TreeChangeEvent};
pub use model::{Entity, Envelope};
pub use seed_policy::{SeedPolicy, SeedPolicyEntry};
