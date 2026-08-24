# Changelog — entity-core-protocol-unison

All notable changes to the Unison core protocol peer (peer #43, operator-directed).
Versioning is held at `0.1.0-pre` until the promotion gate is met (S4 green — done —
**and** an external consumer confirms the peer).

## 0.1.0-pre (unreleased) — tracks Entity Core **v0.8.0 (V8)**

Spec basis: spec-data **v0.8.0** (the single pinned V8 snapshot; the core wire contract is
byte-unchanged across the V7→V8 cutover). ECF codec corpus `conformance-vectors-v1`
(SHA-256 `9695b1f1…`). Oracle: Go `validate-peer` @ pinned ref **`cc1970f`**.

### Conformance

- `validate-peer --profile core` → **`Result: PASS`** · 682 total · 292 pass · 294 warn ·
  **0 fail** · 96 skip (`682·0F @ cc1970f`). All 17 core-gate categories 0 FAIL. Every
  skip is oracle-emitted under the V7 v7.72 §9.0 carve-out; no `-allow-skip` was passed.
- `wire-conformance` ECF corpus → **71/71, 0 FAIL**, byte-identical encode + correct
  decode-reject.
- origination-core (reference-peer-gated) → **3/3**: `reference_connect`,
  `reference_ready`, `dispatch_outbound_reentry`.
- §3.6 K-of-N multisig: the oracle's `valid_2of3_peer_signed_accepted` **passes**, and was
  a hard FAIL before the multi-granter implementation landed — the accept path is genuine,
  not vacuous green.

### Added

- Canonical ECF codec (`src/Codec.u`, `src/Protocol.u`) — hand-rolled over UCM runtime
  builtins: shortest-float ladder incl. f16, length-then-lexicographic map-key ordering
  over encoded key bytes, definite-length only, recursive major-type-6 tag rejection on
  decode, LEB128 varint framing, `content_hash`, peer-id parse/format (hand-rolled base58).
- Pure-Unison Ed25519 **key derivation** (`src/Ed25519.u`) — GF(2²⁵⁵−19) field arithmetic
  in base-2¹⁶ `Nat` limbs, twisted-Edwards scalar multiplication, point compression. UCM
  exposes `crypto.Ed25519.sign.impl`/`verify.impl` but **no** keygen, and Unison has no C
  FFI, so this had to be built from scratch (A-UN-009).
- Core peer machinery, Layers 1–4 + foundation (`src/{Model,Wire,Identity,Store,Capability,
  SeedPolicy,TypeDefs,Peer,Transport,Host}.u`) — EXECUTE/EXECUTE_RESPONSE only,
  `request_id` demux, capability chain-walk + §5.10 verdict, TCP listener/dialer.
- Host CLI: `--name NAME` (persistent identity from `~/.entity/peers/NAME/keypair`),
  `--validate` (§7a conformance handlers, off by default), `--debug-open-grants`.
- Headless build/test harnesses as UCM transcripts (`transcripts/`), with committed golden
  outputs as the drift signal.

### Substrate floor (§9.1)

- **§4.8 store safety — structural.** All store state is a single `MVar StoreState`; every
  mutation is `take → pure fn → put`, serializing access through one cell (an actor-like
  guarantee via the ability system).
- **§4.9 resilience.** Every inbound EXECUTE dispatches under `tryEval` + an `Exception`
  ability handler, so any host ROOT-class failure becomes a **500** rather than a hang
  (deliver-or-signal).
- **§4.10 resource bounds.** `413 payload_too_large` rejected on the length prefix before
  buffering; `400 chain_depth_exceeded` via a structural depth pre-check that runs
  **before** the per-link authz walk (an unreachable parent still yields 403). Depth 64.

### Known gaps (tracked, not hidden)

- **Ed448 / SHA-384 agility DEFERRED.** Neither is a UCM builtin and Unison has no general
  C FFI, so the `libentitycore_codec` hybrid-FFI path other peers used is structurally
  unavailable. Core crypto floor (Ed25519 + SHA-256) is native.
- **§4.10(c) connection admission not implemented** (a SHOULD). `r3_connection_flood`
  WARNs — the same WARN the Go reference peer produces.
- **Peer-side multisig accept unit UNVERIFIED.** `transcripts/multisig-test.md` is authored
  but has never run green (a Unison parse error in the *test* source). The accept path is
  substantiated by the oracle leg alone, which suffices for the gate.

### Spec findings routed to architecture

- **A-UN-015** — §3013 enumerates policy `peer_pattern` forms as `{caller_peer_hex}` or
  `default` and states no others are defined, but `PEER-PATTERN-2` requires accepting a
  Base58 peer_id in the pending-canonicalization state; implementing §3013 literally fails
  the vector.
- **A-UN-016** — the ordering of the unsupported-key_type check relative to the
  peer_id↔public_key binding is unstated; the natural implementation returns `401
  identity_mismatch` where `AGILITY-UNKNOWN-1` expects `400 unsupported_key_type`.

### Packaging

- Not published to Unison Share. `pack_command` is a compiled `.uc` + codebase export;
  registry publish is deferred, consistent with the rest of the cohort.
