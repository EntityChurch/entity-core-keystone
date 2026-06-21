# Changelog — entity-core-protocol-rust

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.75. Codec corpus v0.8.0 (byte-identical
across the v7.56→v7.71 window — the ECF corpus did not change).**

First release line. **Clean-room Rust peer**, derived from the V7 spec + the keystone
`shared/lifecycle` contracts + the cohort's language-neutral sibling profiles — and,
critically, **NOT** from the hand-written Rust siblings `entity-core-rust` /
`entity-core-codec-ffi-rust`. Because a Rust core already exists in those siblings, this
peer's value is an **independent same-language cross-check** (a from-scratch dep-minimized
Rust peer byte-agrees with the Go oracle) + a generator-independence proof. Not yet
published — parked at `-pre` pending architecture v0.1 sign-off + first external consumer
(S5 promotion gate). Distribution is `cargo publish` to crates.io, **deferred per S10**.

### Toolchain & dependency pins (S11)
- **rust / cargo `1.96.0-1.fc43`** — from `containers/rust-toolchain/Containerfile`
  (fedora:43 distro NVR, a reviewed channel — so the ≥30-day age floor relaxes to "pin
  exactly for repro"). Asserted MSRV `rust-version = "1.96"` (the verified-build floor).
- **Two direct registry deps**, exact pins, each ≥30 days old at S2:
  - `ed25519-dalek = "=2.2.0"` — audited pure-Rust RFC-8032 deterministic
    signing; `default-features = false`.
  - `sha2 = "=0.10.9"` — SHA-256 content_hash floor + native SHA-384 agility
    hashing; the settled 0.10.x line (NOT the fresh 0.11.0 major; A-RUST-004).
- **Full transitive closure committed in `Cargo.lock`** (24 packages) with
  `curve25519-dalek` held at `4.1.3` (`4.2.0` was yanked). The ECF canonical-CBOR layer,
  Base58, and the LEB128 varint are **hand-rolled** (no `ciborium` / `bs58` / `leb128`;
  A-RUST-001). `#![forbid(unsafe_code)]` on the crate.

### Conformance
- `validate-peer --profile core` (oracle `entity-core-go` `e8524ed`): **PASS** —
  **665·0F @ e8524ed** (292 pass · 268 warn · 0 FAIL · 93 skip; machine-verified
  `summary.failed == 0`; 0 FAIL-severity records). All 16 core-profile categories 0-FAIL.
  **0 peer-code changes** — green on the first oracle run (the S3 §9.5 registry + full
  surface carried it).
- **multisig 11/11, 0 skip** — incl. `valid_2of3_peer_signed_accepted` PASS (the oracle
  co-signs a genuine 2-of-3 quorum AS the peer via the provisioned `--name conformance`
  keypair); the §3.6 root ALLOWs.
- **origination-core 3/3** — `reference_connect` + `reference_ready` +
  `dispatch_outbound_reentry` over real two-peer TCP (Rust :7777 + Go `entity-peer` :7778),
  exercising the §6.11 reentry seam from the no-async `std::thread` idiom.
- Codec (S2): **69/69 byte-identical** to `conformance-vectors-v1` (64 encode + 5
  decode-reject), first run, 0 codec fixes.
- §9.5 53-type registry: 53/53 byte-identical (render-from-model through the peer's own
  codec). S3 loopback smoke + 33 lib units green. `cargo fmt --check` + `cargo clippy
  --all-targets -D warnings` clean.

### Added
- Hand-rolled canonical-CBOR (ECF) codec (`src/cbor.rs`): Rule 1–5 + §6.3 — shortest int
  head, length-then-lex map-key sort on the *encoded* key bytes (A-RUST-005), definite
  lengths, shortest-float ladder f64→f32→f16 with decode-side minimality enforcement,
  no-duplicate-keys, recursive major-type-6 tag rejection on decode → `400 non_canonical_ecf`.
  LEB128 varints (`src/varint.rs`) + Base58 (`src/base58.rs`), both hand-rolled.
- CBOR head-form integer carrier over native `u64`/`i64` — full §3.2 0..2⁶⁴−1 / −1..−2⁶⁴
  range, no BigInt and no 63-bit trap.
- Ed25519 identity + deterministic signatures (`ed25519-dalek`); SHA-256 content_hash
  (`sha2::Sha256`), SHA-384 agility hashing (`sha2::Sha384`, native). Canonical
  identity-multihash `peer_id` (§1.5; Base58 over `varint(kt)‖varint(ht)‖digest`).
- The live peer: handshake, dispatch (§6.6 routing), capability authorization with §5
  chain attenuation incl. §4.10(a)/(b) bounds, §3.6 K-of-N multisig, §6.13 register-live,
  §6.11 reentry, the §9.5 53-type registry, the §10.1 register-then-dispatch round-trip,
  and the §7a `system/validate/*` opt-in conformance handlers.
- Error model: hand-written `CodecError` enum + `Display` (no `thiserror` / `anyhow`);
  typed error → status code (400/401/403/413) at the dispatcher boundary.
- Concurrency: `std::thread` + `std::sync` (no `tokio`; A-RUST-003); one reader thread per
  connection; `request_id` demux; `RwLock<HashMap>` store (store-race structurally
  unrepresentable — an unsynchronized shared-mutable store is a compile error).
- Handshake nonce from `/dev/urandom` directly + hand-rolled host `--name` PEM base64 decode
  (no `rand` / `getrandom` / `base64` crate; A-RUST-007).

### Known limitations
- **Ed448 / crypto-agility higher bar unsupported** — native-full-agility incl. Ed448 is
  not cleanly reachable in Rust (RustCrypto `ed448-goldilocks` has signing only in a
  `0.14.0-pre` unaudited prerelease; stable `0.9.0` has no signing API; the third-party
  `ed448-goldilocks-plus` is a single-maintainer unaudited fork). Planned: **hybrid** native
  Ed25519 (shipped) + FFI Ed448 via `libentitycore_codec`'s `ec_ed448_*` over the C-ABI when
  agility enters scope — Rust is in the cohort's gap→hybrid-FFI band with Go / Zig / OCaml /
  Swift. Does NOT affect the ECF/Ed25519 conformance floor. A-RUST-002 (the headline crypto
  finding). When agility lands, the manifest gains an `ec_abi_version` pin (lifecycle
  §Version-pin, codec_strategy=ffi clause).
- Public API surface is documented (README §Use, rustdoc), not yet frozen with an explicit
  semver lock — deferred to publish-prep / first external consumer.
- `cargo publish` to crates.io is **deferred per S10**; the crate is `publish = false` to
  guard against an accidental upload (`cargo package` / `cargo publish --dry-run` work).

### Spec items surfaced (ambiguity log, owner-routed)
All S1–S4 entries A-RUST-001…008 are **operator/research-level** profile/library/build
decisions — **no new spec-semantic defect** was discovered (the discovery well is dry for a
same-as-sibling peer, as expected; the v7.75 surface is tight and well-trodden by 9 prior
peers). The headline is **A-RUST-002** (Ed448 deferred→hybrid-FFI). A-RUST-001 (CBOR
hand-roll), 003 (`std::thread` over tokio), 004 (`sha2` 0.10.x pin), 005 (map-key
ordering note), 006 (peer-layer signature target = content_hash), 007 (nonce + PEM decode
without a crate), 008 (S4 offline vendor mirror) — all local/informational, owner-routed.
Full text in [`status/SPEC-AMBIGUITY-LOG.md`](status/SPEC-AMBIGUITY-LOG.md).
