# entity-core-protocol-rust — Phase S1 (Profile) Summary

**Peer:** `entity-core-protocol-rust` — the GENERATED clean-room Rust core-protocol peer.
**Branch:** `lang/rust` (git worktree at `keystone-worktrees/rust`).
**Phase:** S1 (profile research + authoring). **Author-only — NO podman, NO build, NO
toolchain execution** (per the S1 task contract for this peer).
**Spec read:** `spec-data/v7.75` (V7 `057dc8eb…`, CBOR 1.5,
type-system 4.2.1).

## Clean-room discipline (the defining property)

Rust has **two hand-written reference siblings**: `entity-core-rust` (full peer) and
`entity-core-codec-ffi-rust` (the FFI codec building `libentitycore_codec`). This
generated peer is **distinct from both**; its value is an **independent reimplementation
from spec**. **No source under either sibling was opened, read, grepped, or referenced.**
Read only: `spec-data/v7.75`, `shared/lifecycle` contracts, the cohort's language-neutral
profiles (go/csharp/typescript), `shared/seed-policy/`, the existing
`containers/cargo/Containerfile` (to confirm it's the FFI codec's, not the peer's), the
swift/ghc toolchain container shape, and seeded memory. **go is the closest analog** (it
too has a hand-written reference sibling = the oracle), so the framing is **adoption +
independence cross-check, NOT spec discovery** (discovery well is dry per the 8-peer
synthesis). Honest limited-signal caveat recorded in PROFILE-RATIONALE.

## Decisions made (all populated in profile.toml — no field is TBD)

| Surface | Decision |
|---|---|
| **Codec strategy** | `native`. ECF canonical layer must be owned regardless of any lib (A-005 pattern, all 9 prior native peers). Rust has the cleanest native crypto+integer story → native is also the lighter path. ffi = documented fallback. |
| **CBOR** | hand-rolled (~600-line `cbor` module, no `serde`). `ciborium`/`minicbor`/`cbor4ii` rejected (canonical-layer gaps); `serde_cbor` excluded (deprecated). A-RUST-001. |
| **Ed25519** | `ed25519-dalek` **2.2.0** (~11mo). Deterministic signing, audited pure-Rust. Pulls `curve25519-dalek` **4.1.3** (4.2.0 YANKED, 5.0 pre-release-only). |
| **SHA-256/384** | `sha2` **0.10.9** (~13mo). SHA-256 = floor; SHA-384 native via `sha2::Sha384` → **agility hashing is native**. 0.10.x stable over the new 0.11.0 major (A-RUST-004). |
| **Ed448 / agility** | **DEFERRED → hybrid-FFI** (A-RUST-002). **Native-full-agility NOT cleanly reachable** (UNLIKE Haskell): RustCrypto `ed448-goldilocks` signing is pre-release+unaudited only; `ed448-goldilocks-plus` is a single-maintainer unaudited fork. Rust sits in the cohort's gap→hybrid-FFI band (Go/Zig/OCaml/Swift). Floor (Ed25519+SHA-256) unaffected. |
| **base58 / varint** | hand-rolled (dep-minimization; `bs58`/`leb128` rejected). |
| **Error model** | `Result<T, E>` + `?`, hand-written error **enums** + exhaustive match (no `thiserror`/`anyhow`). `panic!` = programmer-error only, caught at conn-task boundary (§4.9). Status mapping grounded in §6.3/§4.10/§5.2a. |
| **Concurrency** | `std::thread` + `std::sync` (blocking `std::net`, thread-per-conn) — **NOT tokio** (dep-minimization, A-RUST-003). **Store-safety enforced by the type system** (compile error without a lock) → Zig/CL store-race structurally unrepresentable (cohort-strongest). `Mutex<HashMap>` store, `set_nodelay(true)`. |
| **Integers** | native `u64`/`i64` → §3.2 full uint/nint range maps directly; no BigInt (vs TS F7), no 63-bit trap (vs OCaml A-OC-001). nint `-1-n` decode watch-item (shared with Go). |
| **Naming** | rustfmt/clippy: PascalCase types, snake_case fns/vars/modules, SCREAMING_SNAKE consts, **initialisms-as-words** (`PeerId`/`Ecf`, NOT `PeerID`/`ECF` — clippy::upper_case_acronyms). |
| **Build / test** | cargo; `cargo test` (std `#[test]`, zero test-framework dep); `cargo clippy -D warnings` + `cargo fmt --check` lint floor. `Cargo.lock` committed (binary-bearing peer). |
| **Packaging** | crates.io (`cargo publish`, deferred per S10), parked **`0.1.0-pre`**, edition 2021. |
| **License** | **Apache-2.0** (S9 default; Rust norm is dual MIT/Apache-2.0 → Apache-2.0 is half of it, no override needed). |
| **Container** | **AUTHORED** `containers/rust-toolchain/Containerfile` (NOT built — S1 author-only). fedora:43 + distro `rust`/`cargo` 1.95.0-5.fc43 + gcc + git. DISTINCT from `containers/cargo/` (that's the FFI codec's). |

## S3 surface baked in (cohort conventions, for later phases to inherit)

`[surface]` block records, all derived from V7 + the keystone seed-policy convention (not
sibling source): **`--name NAME`** persistent identity (Ed25519 from
`~/.entity/peers/NAME/keypair`, PEM = base64 of a 32-byte seed); **genuine §3.6 K-of-N
multisig** (root-only M3 + M4 distinct-signer threshold + M6 local∈signers, single-sig a
byte-identical subset, accept-path unit test); **§6.9a seed-policy** bootstrap
(detached-sig self-owner cap + dual-form authenticate lookup); **§7a conformance
handlers** (`system/validate/*`, opt-in `--validate` OFF by default, §6.11 reentry).

## Container pin choices + release dates (S11 ≥30-day confirmation)

- **rust / cargo `1.95.0-5.fc43`** — fedora:43 **distro channel** (reviewed) → S11 age
  floor relaxes to "pin exactly for repro"; the NVR is the pin (same build
  `containers/cargo/`). Re-verify NVR at the S2 build.
- **ed25519-dalek `2.2.0`** — ~11 months old. **Clears** the
  ≥30-day registry cool-down. ✓
- **sha2 `0.10.9`** — ~13 months old. **Clears.** ✓
- **curve25519-dalek `4.1.3`** (transitive, pinned in Cargo.lock at S2) —
  ~24 months old. **Clears.** (4.2.0 YANKED; 5.0 pre-release only.) ✓
- All registry crates clear the floor; the full transitive closure is pinned exactly in
  the committed `Cargo.lock` at S2, each re-verified ≥30 days old.

## Ambiguity-log entries raised

4 entries, all **profile/library decisions** (operator escalation), **none
blocking-severity** — no spec-semantic ambiguity surfaced at S1 (tight v7.75 surface,
same-language cross-check peer):
- **A-RUST-001** — hand-roll CBOR vs `ciborium`/etc.
- **A-RUST-002** — Ed448 deferred (native-full-agility NOT reachable; hybrid-FFI planned). *(headline crypto finding)*
- **A-RUST-003** — `std::thread` not tokio for the core peer.
- **A-RUST-004** — `sha2` 0.10.x stable line over the new 0.11.0 major.

## Phase exit criteria

- [x] `profile.toml` — every field populated, none `"TBD"`.
- [x] `arch/PROFILE-RATIONALE.md` — written (one section per major choice + clean-room caveat).
- [x] `containers/rust-toolchain/Containerfile` — authored (not built; S1 author-only).
- [x] `status/SPEC-AMBIGUITY-LOG.md` — initialized, 4 entries, 0 blocking.
- [x] `status/PHASE-S1.md` — this file.

## What would block S2 (codec)

**Nothing blocking.** S2 readiness notes:
- **S2 opens with the codec spike** (per PHASE-S1-PROFILE): push `map_keys.*` + `float.*`
  + `tag_reject.*` vectors through the hand-rolled encoder/decoder before the full build.
  `ffi` is the documented fallback if the spike fails (not expected — Rust is the cleanest
  native-codec candidate in the cohort).
- **S2 authors the committed `Cargo.lock`** pinning the full transitive closure
  (curve25519-dalek 4.1.3, signature, ed25519, digest 0.10.x) — each re-verified ≥30 days
  old, with `curve25519-dalek` held at 4.1.3 (NOT 4.2.0 — yanked).
- **S2 builds + verifies the container** (`containers/rust-toolchain/`) — re-confirm the
  `rust`/`cargo` NVR against current fedora:43 and re-pin exactly if it has moved.
- Ed448 is out of scope for S2 (codec) and the §9.1 floor — no blocker (A-RUST-002 is an
  agility-phase concern).
