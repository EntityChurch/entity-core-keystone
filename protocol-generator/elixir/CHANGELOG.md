# Changelog — entity-core-protocol-elixir

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 v7.74 head** (Phase B extensibility boundary:
register / handler outbound-closure / emit / peer-owner-cap / §7a conformance handlers).

First release line. Peer #4, derived spec-first on the BEAM actor model. Not yet published
to Hex — parked at `-pre` pending architecture v0.1 sign-off + first external consumer
(S5 promotion gate).

### Conformance
- `validate-peer --profile core`: **PASS** — 568 / 284P / 195W / **0F** / 89skip,
  first run, 0 fixes (machine-verified `summary.failed == 0`). Identical fixed-point to
  the OCaml peer (#3).
- §10.1 core-register gate: **10/10 PASS**. §10.2 origination-core: **3/3 PASS** incl.
  `dispatch_outbound_reentry` over real two-peer TCP.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, first run, 0 fixes.
- Crypto-agility (S2/S3): 35/35 byte-pins, **native** (no FFI).

### Added
- Hand-rolled canonical-CBOR (ECF) codec via binary pattern-matching: f16⊂f32⊂f64 float
  minimization, length-then-lex map-key sort, recursive major-type-6 tag rejection, LEB128 +
  Base58 (no Hex deps).
- Ed25519 **and Ed448** identity + deterministic signatures, SHA-256/384 — **all native via
  OTP `:crypto`**. The crypto-agility higher bar (Ed448, SHA-384) is reached from the default
  build with no FFI (contrast OCaml's hybrid-FFI Ed448, A-OC-002).
- CBOR head-form integer carrier — full 0..2⁶⁴−1 with no native-int special-casing (BEAM
  arbitrary-precision integers).
- §4.1 handshake, §6.5 dispatch, capability authorization with chain attenuation, type
  registry (render-from-model, 53/53 byte-identical), GenServer in-memory store with CAS.
- v7.74 Phase B foundations: F1 handler register (§6.13a/§6.2 five writes incl. grant-sig at
  `system/signature/{grant_hash}`), F2 handler outbound closure (§6.13b/§6.11 reentry over a
  per-connection process), F3 emit (§6.10/§6.8a), F4 peer-owner cap + seed-policy read (§6.9a);
  §7a conformance handlers (`system/validate/{echo,dispatch-outbound}`), opt-in via
  `--validate` / `conformance: true`, OFF by default.
- Concurrency: BEAM actor model — GenServer store (serialized, atomic CAS), process per
  connection, selective `receive` for §6.11 demux.

### Known limitations
- The `compute/literal` evaluator ships but is no longer gate-exercised post-§7a (cohort-wide
  deferred cleanup; harmless).
- Emit consumers currently run sync-inline in the Store GenServer (inert at core — zero
  consumers); a re-entrant/slow consumer would deadlock/stall once the emit-consumer surface
  is built → resolve to async `send`-to-process delivery (A-ELX-007, §9.4-permitted).
- Public API not yet locked with `@moduledoc false` on internal modules / HexDocs generation
  (deferred to publish-prep; surface tiers documented in `status/PHASE-S5.md`).

### Spec items surfaced (routed to architecture)
- No NEW spec ambiguity — Elixir **corroborates** the inherited findings from a fourth,
  distant-idiom peer: **A-OC-007 ⚑** (§7.4/§1.5 peer-id contradiction), **A-OC-008**
  (§5.2/§4.6 401/403), A-011/A-013 (§7a conformance-handler coupling, resolved).
- **A-ELX-005** (positive): first independent keystone byte-verification of the §3.6 `root_cap`
  pins (every prior peer deferred them).
- **A-ELX-006** (idiom note): actor-model concurrency placement.
- **A-ELX-007** (forward seam): emit-delivery async fork (see Known limitations).
