//! entity-core-protocol-datalog — the QUERY-NATIVE (bottom-up Datalog) core peer.
//!
//! Two halves, per profile.toml:
//!   * the SEAM (`codec_ffi`, `cbor_host`) — the thin safe surface over the C-ABI
//!     `libentitycore_codec` plus the host's CBOR structure marshalling. Canonical
//!     CBOR / content_hash / Ed25519 / SHA all cross the C-ABI; the host holds no
//!     canonical decision. Datalog holds no bytes and does no crypto.
//!   * the AUTHORED interior (`authority`) — the `ascent! { … }` §5.2/§5.5/§5.5a/
//!     §3.6/§6.6 rules (the wrapper-guard artifact) — plus `identity`, `model`,
//!     `store`, `dispatch`, `host` (the stateful-sequential half the profile expects
//!     to leak host-side: sockets, §1.6 framing, dispatch sequencing, handshake).
//!
//! The host establishes FACTS (it did the crypto/glob/clock); the engine DERIVES
//! `allow` (§5.2) and `resolved` (§6.6). The seam split IS the probe's finding.

pub mod authority;
pub mod cbor_host;
pub mod codec_ffi;
pub mod dispatch;
pub mod host;
pub mod identity;
pub mod model;
pub mod store;
pub mod types;
