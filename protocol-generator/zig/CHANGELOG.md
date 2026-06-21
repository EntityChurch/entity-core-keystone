# Changelog — entity-core-protocol-zig

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.72 + v7.74 (§10.1 core-register + §9.5a
CORE-TREE) closeout. Codec corpus v0.8.0 (byte-identical v7.71→v7.72, no wire change).**

First release line. Peer #4 (Zig), derived **spec-first** in a distant idiom (no GC, explicit
allocators, error unions, `comptime`). Not yet published — parked at `-pre` pending
architecture v0.1 sign-off + first external consumer (S5 promotion gate). Distribution is a
git tag pinned by URL + content hash in consumers' `build.zig.zon` (no central registry).

### Toolchain pins (S11)
- **Zig 0.15.1** (released 2025-08; ~10 months old at pin — clears the ≥30-day supply-chain
  floor). Settled point release over the newer 0.16.0 beta. `std.crypto` Ed25519 + SHA-2 stable.
- **Zero third-party packages** — the whole peer is `std`-only. The single pin is the Zig
  version; mirrored in `containers/zig-toolchain/Containerfile` (official ziglang.org tarball,
  SHA-256-pinned + minisign signature-verified, no distro `zig` rpm).

### Conformance
- `validate-peer --profile core`: **PASS** — 568 / 284P / 195W / **0F** / 89skip
  (machine-verified `summary.failed == 0`). Same fixed point as C# (#1) / TS (#2) / OCaml (#3),
  reached spec-first in the Zig idiom.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, first run, 0 codec fixes.
- `zig build test`: leak-clean under `std.testing.allocator` (S2 69/69 vectors + A-ZIG-008
  53-type byte-diff + deletion-marker + §7a echo).
- `zig build smoke`: two-peer loopback SMOKE PASS (7/7), leak-clean.

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16 ⊂ f32 ⊂ f64 shortest-float minimization,
  length-then-lex map-key sort on encoded key bytes, recursive major-type-6 tag rejection,
  LEB128 + Base58 (no extra deps). `comptime` encode dispatch (zero runtime reflection).
- CBOR head-form integer carrier over native `u64` — full 0..2⁶⁴−1; ReleaseSafe overflow-traps.
- Ed25519 identity, deterministic signatures (`std.crypto.sign.Ed25519`); SHA-256/384
  (`std.crypto.hash.sha2`). Canonical identity-multihash peer_id (`hash_type=0x00`, A-ZIG-001).
- §4.1 handshake, §6.5 dispatch, capability authorization with chain attenuation, the §9.5
  53-type registry (render-from-model, 53/53 byte-identical), in-memory store with CAS.
- §9.5a CORE-TREE get/put/CAS/delete (deletion-marker listing-omit) + §1.4 peer-root and
  foreign-root listing. §10.1 entity-native register-then-dispatch round-trip floor (§6.13(a)).
- Concurrency: `std.Thread` (one reader per connection); `request_id` demux; write-serialized
  via `std.Thread.Mutex`; transport-agnostic dispatch brain (A-ZIG-003).
- Memory: no-GC ownership contract — per-request `ArenaAllocator` for dispatch, deep-clone of
  the response into the long-lived allocator, store owns persisted entities; `defer`/`errdefer`
  on every path; leak-checked under test (A-ZIG-004 / A-ZIG-007).

### Known limitations
- **Ed448 / crypto-agility higher bar unsupported** — `std.crypto` has no Ed448 and no audited
  pure-Zig Ed448 exists; Zig has no BouncyCastle-equivalent (A-ZIG-002, mirrors OCaml A-OC-002).
  Planned: hybrid native-Ed25519 + FFI-Ed448 (consume `libentitycore_codec` for the Ed448
  family only) when agility enters scope. Does NOT affect the ECF/Ed25519 conformance floor.
- `tree_operations.cleanup` carries one non-critical WARN (shared with the C#/TS/OCaml cohort).
- Public API surface is documented (README §Use, `src/root.zig` re-exports), not yet frozen
  with an explicit semver lock — deferred to publish-prep / first external consumer.

### Spec items surfaced (routed to architecture)
- **A-ZIG-001 ⚑** §7.4 NORMATIVE `derive_peer_id` (SHA-256-form) contradicts the §1.5 v7.65
  canonical-form table (identity-multihash, `hash_type=0x00`). A literal §7.4 reader fails
  every handshake. **Independently corroborates OCaml A-OC-007 from a second spec-first peer.**
- **A-ZIG-006 ⚑** §5.2 flat "DENY → 403" under-specifies the §4.6 authn(401)/authz(403)
  request-time boundary. **Fourth** spec-first peer to hit this (OCaml A-OC-008; arch F20).
- **A-ZIG-005** the peer_id conformance corpus uses opaque digests + `hash_type=0x01` only, so
  it does not discriminate the A-ZIG-001 contradiction — a coverage gap (vector request to arch).
