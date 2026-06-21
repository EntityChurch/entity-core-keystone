# entity-core-protocol-rust — Phase S2 (Codec) Summary

**Peer:** `entity-core-protocol-rust` — the GENERATED clean-room Rust core-protocol peer.
**Branch:** `lang/rust` (git worktree at `keystone-worktrees/rust`).
**Phase:** S2 (native canonical CBOR/ECF codec + native type system).
**Spec read:** `spec-data/v7.75` (ENTITY-CBOR-ENCODING 1.5 +
ENTITY-NATIVE-TYPE-SYSTEM 4.2.1, authoritative for the codec).

## Result — the gate

**69 / 69 PASS, 0 FAIL**, byte-identical against the go `wire-conformance` oracle
(entity-core-go `e8524ed`, v7.75 surface). 64 encode vectors byte-for-byte + 5
decode-reject vectors (all `non_canonical_ecf`). Full detail in `CONFORMANCE-REPORT.md`.
The S7 lower bar (69/69, 0 fail) is met. No oracle test was doctored — the corpus is the
LOCKED 3-way-equality golden corpus; this peer reproduces it.

## Clean-room discipline (held)

Authored from the spec + the go oracle's *public conformance mechanism* only. The Rust
siblings `entity-core-rust` and `entity-core-codec-ffi-rust` were **not opened, read,
grepped, or referenced**. The go oracle's `cmd/internal/wire-conformance` source WAS
studied (permitted: it is the oracle and a cohort output, not a Rust sibling) to learn
the exact emission protocol — this is byte-validation-mechanism discovery, not Rust-impl
copying. No native codec from other peers was needed.

## What was built (all under `protocol-generator/rust/`)

| Module | Responsibility |
|---|---|
| `src/cbor.rs` | Hand-rolled canonical ECF encoder + strict decoder. Rule 1 (shortest int head), Rule 2 (map-key order by encoded-key bytes), Rule 3 (definite-length only), Rule 4/4a (shortest-float ladder f64→f32→f16 + exact specials, decode-side minimality check), Rule 5 (dup-key reject), §6.3 (recursive tag reject at any depth). |
| `src/value.rs` | The ECF value tree + key type. Full uint64/nint range via `u64` carriers (the `[2^63,2^64-1]` and `[-2^64,-1]` bands, no BigInt). |
| `src/varint.rs` | LEB128 multicodec varint (§1.5/§7.3), encode + minimality-checking decode. All framing routes through this (invariant N1). |
| `src/base58.rs` | Bitcoin-alphabet base58 encode/decode (peer-id grammar). |
| `src/content_hash.rs` | `varint(format_code) \|\| SHA-256(ECF({type,data}))` (`sha2 0.10.9`). |
| `src/peer_id.rs` | `Base58(varint(kt)\|\|varint(ht)\|\|digest)` format/parse. |
| `src/signature.rs` | Deterministic Ed25519 sign/verify over canonical-ECF entity bytes (`ed25519-dalek 2.2.0`). |
| `src/error.rs` | Hand-written `CodecError` enum + `Display` (no thiserror/anyhow). Sentinels → `non_canonical_ecf`. |
| `src/bin/wire_conformance.rs` | The conformance harness (go `emit-canonical` analogue): emits the §3.1 emission file + self-checks against corpus golden bytes. |
| `src/tests.rs` | 13 unit tests; N1/N2/N3 each have a covering case + float ladder, int boundaries, map order, content_hash, peer_id, round-trip. |

`Cargo.toml` + `Cargo.lock` (full transitive closure committed). `#![forbid(unsafe_code)]`
on the crate. Lint floor green: `cargo fmt --check` + `cargo clippy --all-targets -D warnings`.

## Codec spike outcome (the S1-mandated cheap insurance)

The S2-open spike (`map_keys.*` + `float.*` + `tag_reject.*` through the hand-rolled
codec before the full build) is subsumed by the unit-test battery (`float_*`,
`map_key_*`, `n2_tag_rejected_recursively`) — all green on first full run. **Native
strategy confirmed viable; no ffi fallback needed** (the profile's bet held; Rust was
indeed the cleanest native-codec candidate — std u64/i64 + audited ed25519-dalek/sha2,
no library canonical-layer gaps to fight because the layer is owned).

## Dep closure (S11 — full Cargo.lock committed, each pin ≥30 days old)

| Crate | Version | Age |
|---|---|---|
| ed25519-dalek | 2.2.0 (direct, `=`) | ~11 mo ✓ |
| sha2 | 0.10.9 (direct, `=`) | ~13 mo ✓ |
| curve25519-dalek | 4.1.3 (transitive) | ~24 mo ✓ (4.2.0 YANKED — held at 4.1.3) |
| signature | 2.2.0 | (transitive) | ≥30 d ✓ |
| ed25519 | 2.2.3 | (transitive) | ≥30 d ✓ |
| sha2/digest | 0.10.7 | (transitive) | ≥30 d ✓ |

`cargo build` resolved curve25519-dalek to **4.1.3** (not the yanked 4.2.0), confirming
the pin held. Offline rebuild (`--network=none --offline`) verified after the one-time
fetch (the container's `offline-after-fetch` policy).

## Container pin (S11 ≥30-day discipline)

The S1-authored rust/cargo NVR **1.95.0-5.fc43 drifted** — it has aged out of fedora:43's
repos entirely (`dnf list --showduplicates rust cargo` now serves only 1.90.0-1.fc43 in
the base `fedora` repo and **1.96.0-1.fc43** in `updates`). Per the S11 distro-channel
"pin exactly for repro" rule, the Containerfile was **re-pinned to 1.96.0-1.fc43** (the
current freshest reviewed distro build) — `containers/rust-toolchain/Containerfile`
records the drift + re-pin. `clippy` and `rustfmt` (separate fedora rpms, same NVR) were
added so the profile's lint floor runs in-image. The distro channel is reviewed, so its
age floor is "pin-for-repro," not the ≥30-day cool-down (which still governs the crate
pins, all of which clear it independently).

## New ambiguity-log entries

- **A-RUST-005** — map-key canonical ordering: recorded that bytewise-on-*encoded*-key
  (what the oracle does, what this impl does) is provably equivalent to Rule-2
  length-then-lex for the ECF key space, and *why* (the head byte carries the
  length class). An implementation note, not a spec ambiguity — kept so a future
  maintainer doesn't refactor it into a decoded-value comparator and break `map_keys.2`.

No spec-semantic blocker surfaced; the v7.75 codec surface matched the oracle exactly.

## What S3 (peer machinery) inherits / what could block it

**Nothing blocking S3.** Hand-off notes:
- The codec API (`cbor::{encode,decode}`, `content_hash`, `peer_id::{format,parse}`,
  `signature::{sign_entity,verify_entity,public_from_seed}`, the `Value`/`Key`/
  `CodecError` types) is the stable surface S3 builds the dispatcher + transport on.
- S3 surface conventions are already recorded in `profile.toml [surface]` (`--name`
  persistent identity, genuine §3.6 K-of-N multisig, §6.9a seed-policy, opt-in §7a
  conformance handlers) — S3 implements against `validate-peer --profile core`, the live
  oracle (the codec floor is now proven, so peer-level conformance is the next gate).
- Concurrency (`std::thread` + `Mutex<HashMap>` store, `set_nodelay(true)`) per
  `[concurrency]` — codec is pure-sync, so S3 owns the threading.
- Ed448 (A-RUST-002, hybrid-FFI) remains out of scope until the agility phase; the
  Ed25519+SHA-256 floor proven here is complete for `--profile core`.
- The throwaway oracle-build go image (golang 1.25.11) is **not** committed — it exists
  only to rebuild the oracle for byte-validation; re-create it from the corpus + the
  vendored oracle source if a future phase re-validates.
