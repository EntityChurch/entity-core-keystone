# entity-core-protocol-rust — Phase S3 (Peer Machinery) Summary

**Peer:** `entity-core-protocol-rust` — the GENERATED clean-room Rust core-protocol peer.
**Branch:** `lang/rust` (git worktree at `keystone-worktrees/rust`).
**Phase:** S3 (live peer machinery on top of the S2 codec — V7 Layers 1–4 + foundation).
**Spec read:** `spec-data/v7.75` (ENTITY-CORE-PROTOCOL-V7).

## Result — the S3 gate

**GREEN, both legs.**

| Gate leg | Result |
|---|---|
| **Two-peer loopback over real TCP** | **6 / 6 checks PASS, 0 fail** (`tests/loopback.rs`) |
| **Type-registry conformance** | **53 / 53 byte-identical** to the v7.71 Go vector set |
| §3.6 multisig accept-path test | **PASS** (2-of-3 ALLOW + M3/M4/M6 deny flips + single-sig superset) |
| Peer lib unit tests | 33 / 33 pass |
| S2 codec (no regression) | still 69 / 69, 0 fail |
| Lint floor | `cargo clippy --all-targets -- -D warnings` clean + `cargo fmt --check` clean |

Loopback breakdown: handshake (remote peer_id matches) → 404 on unregistered path →
granted `system/tree` get returns a `system/type` entity (200) → `system/capability`
request (200) → 8/8 `request_id` demux of concurrent requests → clean teardown.

## Clean-room discipline (held)

Authored from V7 (`spec-data/v7.75`) + the keystone `shared/lifecycle` contracts + the
keystone `shared/seed-policy/` convention + the **cohort peers' machinery for shape**
(`protocol-generator/{go,ocaml,zig}/src/` — explicitly permitted as cohort outputs; the
Zig peer was the primary structural blueprint because its `std.Thread` + lock-guarded-store
model maps directly onto the Rust `std::thread` + `RwLock<HashMap>` profile). The Rust
siblings `entity-core-rust` / `entity-core-codec-ffi-rust` were **NOT opened, read, grepped,
or referenced**. Every protocol-shaped decision grounds in a V7 §-pointer.

## What was built (all under `protocol-generator/rust/src/peer/`)

| Module | Responsibility |
|---|---|
| `model.rs` | Materialized `Entity {type, data, hash}` (33-byte hash) + `Envelope` (§3.1) over `cbor::Value`; N4 validate-before-trust on decode (recompute hash, reject carried mismatch). |
| `identity.rs` | Keypair → peer_id (§1.5 identity-multihash: kt=0x01, ht=0x00, digest=pubkey) + `system/peer` entity + **content-hash signing** (`system/signature` over the 33-byte hash). |
| `store.rs` | §1.7 content/tree store, `RwLock<HashMap>`-guarded (§4.8 — a shared unsynchronized store is a compile error); §6.10 emit-consumer seam (live, zero core consumers). |
| `wire.rs` | §1.6 length-prefixed framing + EXECUTE/EXECUTE_RESPONSE builders; **§4.10(a) 16-MiB bound checked on the length prefix before buffering** → `413 payload_too_large`. |
| `capability.rs` | §5 verification core: §5.4 pattern match, §5.5 chain-walk + §5.6 attenuation + §5.7 caveats + §5.1 revocation, §5.2 verdict trichotomy (401/403), **§4.10(b) chain-depth pre-check → `400 chain_depth_exceeded`** (structural, before the authz walk), **genuine §3.6 K-of-N multisig root** (M3 structure → M6 local-in-quorum → M4 distinct-signer threshold). |
| `capability/tests.rs` | The multisig **accept-path** test (the oracle's rejection-heavy category can't cover it) + pattern/canonicalize tests. |
| `type_defs.rs` | The **53 core `system/type`** entities, render-from-model; the type-registry conformance gate (byte-diff vs the v7.71 vector set). |
| `core.rs` | The `Peer`: §6.9 bootstrap, the four MUST handlers (tree/handler/capability/connect) + §6.6 backward-walk routing, §4.1/§4.6 handshake, §6.9a seed-policy (self-owner cap + dual-form authenticate lookup ∪ §4.4 floor), §6.13 register-live + handler outbound, §6.10 emit, §7a `system/validate/{echo,dispatch-outbound}` (opt-in). |
| `transport.rs` | TCP listener/dialer, the §6.11 reader-demux (request_id → condvar slot), inbound-EXECUTE-on-its-own-thread (§4.8, N6), the §6.13(b) outbound reentry seam, the initiator `Session`, `set_nodelay(true)` (§7b). |
| `src/bin/host.rs` | The S4 host: `--name NAME` (load `~/.entity/peers/NAME/keypair`, PEM = base64 of a 32-byte seed) · `--port N` · `--validate` · `--debug-open-grants` · `--help`. |
| `tests/loopback.rs` | The S3 loopback gate (two peers over real TCP). |

## Peer surfaces wired (for the S4 `validate-peer --profile core` gate)

- **TCP transport** — length-prefixed framing, `set_nodelay(true)`, reader-demux with
  `request_id` correlation, two-peer loopback proven green.
- **Type registry + §6.6 dispatch** — 53-type floor, backward tree-walk handler resolution.
- **Capability** — §5.5 chain-walk with per-link granter frame (§PR-8), §5.6 attenuation,
  §5.2 verdict trichotomy, §4.10(b) `400 chain_depth_exceeded` (structural pre-check; an
  *unreachable* parent stays 403), §4.10(a) `413 payload_too_large`.
- **§3.6 K-of-N multisig** — root-only M3 (n≥2, 2≤threshold≤n, distinct signers) → M6
  (local ∈ signers) → M4 (distinct-signer valid-sig count ≥ threshold); single-sig path a
  strict superset; accept-path unit test green.
- **§6.13 register-live** (cap-checked, grant-sig at `system/signature/{grant_hash}`),
  **handler outbound closure** (§6.11 reentry over the inbound connection), **emit** (§6.10),
  **peer-owner cap** (detached-sig self-owner at L0) + **seed-policy read** (dual-form ∪ §4.4 floor).
- **§7a conformance handlers** `system/validate/{echo,dispatch-outbound}` — opt-in via the
  `conformance` builder flag, surfaced as host `--validate`, **OFF by default**;
  dispatch-outbound originates back to the caller over the inbound connection (§6.11), not
  a third-peer dial.
- **Host `--name`** — persistent Ed25519 identity from the standard on-disk keypair.

## Idiom notes (the code reads as Rust)

`std::thread` + `std::sync` (no async runtime — A-RUST-003); `Result`/`Option` over the
fallible surface; exhaustive `match` on the `Verdict`/`ReqVerdict` ADTs (the Rust analogue
of the OCaml/Lean verdict ADT); the store is the only shared mutable state and is
structurally race-safe; `#![forbid(unsafe_code)]` holds (no FFI in the core peer). No new
registry crate was pulled — the closure is unchanged from S2 (ed25519-dalek + sha2 + their
transitive deps); the handshake nonce reads `/dev/urandom` directly and the host's
base64 keypair decode is hand-rolled, both to avoid a `rand`/`getrandom`/`base64` pin.

## New ambiguity-log entries

- **A-RUST-006** — peer-layer signature is over the entity's **33-byte content_hash**
  (not the ECF-encoded entity bytes the S2 `signature::sign_entity` signs). Grounded in
  §3.5 + the cohort `system/signature {target = content_hash}` shape; recorded so the two
  signing paths are not conflated.
- **A-RUST-007** — handshake nonce via `/dev/urandom` (and host keypair base64 decode
  hand-rolled) to hold the dep-minimization line — no `rand`/`getrandom`/`base64` crate.

No spec-semantic blocker surfaced; the v7.75 peer surface matched the cohort conventions
(consistent with the dry-discovery-well finding for a same-language-as-a-reference peer).

## What S4 (`validate-peer --profile core`) inherits / could block it

**Nothing structurally blocking.** Hand-off notes:
- The host binary `entity-peer-host` is the live target (`--port`/`--name`/`--validate`).
  It boots and emits the `LISTENING 127.0.0.1:{port} peer_id=… open_grants=… validate=…`
  readiness line a run-script can wait on.
- S4 runs the go `validate-peer --profile core` against a booted host; the clean-room rule
  permits byte/behaviour validation against the oracle (not reading its source). Re-pin the
  oracle commit to S4-current if newer than the recorded `e8524ed`.
- The §7a handlers are OFF by default; the S4 driver passes `--validate` for the categories
  that need the echo / dispatch-outbound hooks.
- Ed448/agility remains out of scope (A-RUST-002, hybrid-FFI) — the Ed25519+SHA-256 floor
  is complete for `--profile core`.
- Known watch-item for S4 tuning (not a block): the exact wire-status mapping for edge
  categories is grounded in V7 + the cohort blueprint, but only the live oracle confirms
  byte-for-byte; any S4 status-code drift is a code fix, never an oracle workaround (S5).
