# Changelog — entity-core-protocol-swift

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.74** (register / handler outbound-closure /
emit / peer-owner-cap / §7a conformance handlers / §7b concurrency gate). Codec corpus v0.8.0
(byte-identical across the v7.71→v7.74 line — no wire change).

First release line. Peer **#7** (Swift), derived **spec-first** — and the **first genuinely
spec-first peer on the freshly-stamped v7.74 surface** (the prior cohort either ported earlier
peers or derived against v7.72; Swift independently arrived at the v7.74 protocol surface from
spec-data, consulting siblings only for the cross-blessed structural type-floor enumeration and
the §7a/§7b contract shape, never for protocol semantics). Not yet published — parked at `-pre`
pending architecture v0.1 sign-off + first external consumer (S5 promotion gate). Distribution is
a reviewed semver git tag consumers pin by URL + version in their own `Package.swift` (SwiftPM
has no central binary registry).

### Toolchain + dependency pins (S11 — every dep ≥30 days old at pin time)
- **Swift 6.2-RELEASE** (~9 months old). `containers/swift-toolchain`
  (official swift.org `fedora39` tarball, GPG + SHA-256 verified, runs on fedora:43).
- **swift-crypto 3.14.0** (~10 months old) — `Curve25519.Signing` (Ed25519)
  + SHA-256/384/512. Audited, BoringSSL-backed (BoringSSL vendored + compiled from source — no
  system OpenSSL dep).
- **swift-asn1 1.7.0** (~59 days old) — transitive dep of swift-crypto,
  pinned **explicitly** because SwiftPM auto-resolves to 1.7.1 (~6 days old), which
  violates the S11 30-day cool-down (A-SW-005). Both locked by exact revision in the committed
  `Package.resolved`.
- No CBOR / Base58 / varint packages — hand-rolled in-repo.

### Conformance
- `validate-peer --profile core`: **PASS** — 573 / 288P / 196W / **0F** / 89skip
  (machine-verified `summary.failed == 0`). Same fixed point as the C#/TS/OCaml/Zig/Elixir/
  Common-Lisp cohort, reached spec-first in the Swift idiom.
- §10.1 core-register gate: **10/10 PASS** (incl. `validate_echo_dispatch` + the §3.4 grant-sig
  at the invariant pointer `system/signature/{grant_hash}`, enforced both ways; unregister
  symmetry).
- §10.2 origination-core: **3/3 PASS** incl. `dispatch_outbound_reentry` over real two-peer TCP
  (validator-as-B over the same inbound connection, §6.11 reentry, no third-peer dial).
- §7b concurrency gate: **5/5 PASS** (3.0s).
- Codec (S2): **69/69 byte-identical** to `conformance-vectors-v1`, first run, **0 codec fixes**.
  `swift test` 27/27 (corpus 69/69 + 25 selftests + the A-SW-009 53-type byte-diff); `swift run
  smoke` 11/11.

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16 ⊂ f32 ⊂ f64 shortest-float minimization,
  length-then-lex map-key sort **over encoded UTF-8 key bytes**, recursive major-type-6 tag
  rejection on decode, full `uint64`/`nint` 0..2⁶⁴−1 range over native `UInt64`, raw-byte
  fidelity. LEB128 + Base58 hand-rolled (no extra deps).
- Ed25519 identity, deterministic signatures (`Curve25519.Signing`, swift-crypto); SHA-256/384/512.
  Canonical identity-multihash peer_id (`hash_type=0x00`, the §1.5 v7.65 construction; A-SW-008).
- §4.1 handshake, §6.5 dispatch, capability authorization with chain attenuation, the §9.5 53-type
  registry (render-from-model, 53/53 byte-identical), §9.5a CORE-TREE get/put/CAS/delete
  (deletion-marker listing-omit), in-memory store with CAS.
- v7.74 Phase B foundations: F1 handler register (§6.13a/§6.2, five writes incl. grant-sig at
  `system/signature/{grant_hash}`), F2 handler outbound closure (§6.13b/§6.11 reentry via the
  Connection-actor reader-demux + `makeOutbound`/`originate` seam), F3 emit (§6.10/§6.8a), F4
  peer-owner cap + §6.9a seed-policy read (`SeedPolicy` + `--seed-policy` / `--owner-identity`).
  §7a conformance handlers (`system/validate/{echo,dispatch-outbound}`), opt-in via
  `conformanceHandlers:` / host `--validate`, **OFF by default**.
- Concurrency: an **`actor` store** (the §7b store-race is a compile error) + a `Connection`
  actor per socket (`request_id` demux for §4.8 / §6.11), with blocking I/O offloaded to dedicated
  OS threads (the Swift §7b finding — the bounded cooperative pool must not carry blocking
  syscalls). `TCP_NODELAY` on every socket.
- Memory: value-type (`struct`/`enum`, `Sendable`) codec data model — cycle-free by construction
  under ARC; `class`/`actor` only where shared-mutable identity is intrinsic (Peer / Connection /
  Store).

### Known limitations
- **Ed448 / crypto-agility higher bar unsupported** (A-SW-001) — swift-crypto / BoringSSL omits
  Ed448 and no audited pure-Swift Ed448 exists; the planned path is hybrid native-Ed25519 +
  FFI-Ed448 (consume `libentitycore_codec` for the Ed448 family only, mirroring OCaml A-OC-002).
  Does NOT affect the Ed25519 / SHA-256 §9.1 conformance floor.
- The `compute/literal` evaluator ships (the minimal §6.13a dispatch seam) but is no longer
  gate-exercised post-§7a (cohort-wide deferred cleanup; harmless).
- Public API surface is documented (README §Install/use, the `public` `Peer`/`Server`/`Model`/…
  surface) but not yet frozen with an explicit semver lock or hidden behind a strict module
  boundary — deferred to publish-prep / first external consumer.

### Spec items surfaced (routed to architecture)
- No NEW spec ambiguity — Swift **corroborates** the inherited findings from a seventh,
  spec-first peer on the v7.74 surface:
  - **A-SW-008 ⚑** §7.4 NORMATIVE peer-id derivation contradicts the §1.5 v7.65 canonical-form
    table (identity-multihash, `hash_type=0x00`). Validated live (connectivity 22/22 +
    peer_canon 7/7); the stale §7.4 SHA-256 form would fail handshake. **Fourth** peer to
    corroborate (OCaml A-OC-007 / Zig A-ZIG-001).
  - **A-SW-010** §4.2/§5.1 flat "403" under-specifies the §5.2a author-absent(401)/
    capability-absent(403) request-time boundary. Built to §5.2a; security/authz green against
    the oracle. Corroborates F20 / OCaml A-OC-008.
  - **A-SW-007** §7.3 NORMATIVE `message = entity.content_hash` contradicts the normative
    Appendix E `signature` vectors (sign the ECF preimage of `{type,data}`). Seventh peer to
    arrive at the corpus convention; first to surface the §7.3-vs-Appendix-E *text* tension.
- **A-SW-009** (53-type registry render) — **RESOLVED** at S4 (byte-diff clean, 53/53).
- A-SW-002 (String/UTF-8-byte discipline), A-SW-003 (CryptoKit→swift-crypto), A-SW-004
  (XCTest), A-SW-005 (swift-asn1 explicit pin), A-SW-006 (§7a/§7b GUIDE-carried) — all
  resolved-in-peer / operator-local (see `status/SPEC-AMBIGUITY-LOG.md`).
