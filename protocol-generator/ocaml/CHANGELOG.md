# Changelog — entity-core-protocol-ocaml

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 v7.72 head + v7.73 (§PR-8 + Amendment-1) closeout.**

First release line. Peer #3, derived spec-first. Not yet published to opam — parked at
`-pre` pending architecture v0.1 sign-off + first external consumer (S5 promotion gate).

### Conformance
- `validate-peer --profile core`: **PASS** — 558 / 274P / 195W / **0F** / 89skip
  (machine-verified `summary.failed == 0`).
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, first run, 0 fixes.

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16⊂f32⊂f64 float minimization, length-then-lex
  map-key sort, recursive major-type-6 tag rejection, LEB128 + Base58 (no extra deps).
- Ed25519 identity, deterministic signatures (`mirage-crypto-ec`); SHA-256/384 (`digestif`).
- CBOR head-form integer carrier (unsigned-Int64) — full 0..2⁶⁴−1 despite 63-bit native int.
- §4.1 handshake, §6.5 dispatch, capability authorization, type registry (render-from-model,
  53/53 byte-identical), in-memory store with CAS.
- v7.73 §PR-8 dispatch-boundary granter frame (V2(a)) + Amendment-1 chain-walk per-link
  granter frame (V1′ triple) with preferred hard-fail on unresolvable granter.
- Concurrency: stdlib threads (one per connection); transport-agnostic dispatch brain.
- **Crypto-agility higher bar (A-OC-002 resolved):** Ed448 (`key_type 0x02`)
  via the **opt-in `entitycore_agility` sub-library** (`src/agility/`) — hybrid FFI: Ed25519
  + SHA-256/384 stay native, Ed448 is sourced from `libentitycore_codec` over the C-ABI v1.1.
  The shipped Ed25519+SHA-256 core peer stays self-contained and FFI-free (`opam install`
  still pulls no system packages). Byte-verified 25/25 vs the agility corpus (`run-agility.sh`)
  against both the C and Rust FFI impls (byte-interchangeable). key_type / content_hash_format
  registries with reject-unknown; §1.5 size-cutoff peer_id across both key families.

### Known limitations
- The crypto-agility higher bar is an **opt-in** surface (links `libentitycore_codec`); the
  default `entity-core-protocol-ocaml` package is Ed25519+SHA-256-only and FFI-free. A
  separate agility opam package is deferred to first external consumer (see `PHASE-S5.md` §4).
- `tree_operations.cleanup` carries one non-critical WARN (shared with the C#/TS cohort).
- Public API not yet locked with per-module `.mli` (deferred to publish prep; surface tiers
  documented in `status/PHASE-S5.md`).

### Spec items surfaced (routed to architecture)
- **A-OC-007 ⚑** §7.4 NORMATIVE peer-id pseudocode contradicts §1.5 v7.65 identity-multihash.
- **A-OC-004 ⚑** format_code emit/receive asymmetry unstated in §4.7.
- **A-OC-008** §5.2/§4.6 401/403 request-time boundary under-specified (corroborates F20).
