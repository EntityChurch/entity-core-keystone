# Changelog — entity-core-protocol-common-lisp

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note (A-CL-010):** ASDF's `:version` field is dotted-integer only and rejects a
> SemVer `-pre` suffix, so the ASDF systems carry `0.1.0` while the release LINE below is
> `0.1.0-pre`. The `-pre` marker is carried here + in README.md, not in the `.asd`.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.72 + the v7.73/v7.74 peer-surface closeout**
(register / outbound-dispatch / emit live-hooks + §6.9a owner-cap bootstrap + §7a conformance
handlers); codec corpus v0.8.0.

First release line. Peer #5, derived spec-first in the cohort's most distant idiom (CLOS
multiple dispatch, the condition system, native bignums, `sb-thread`). Not yet published — parked
at `-pre` pending architecture v0.1 sign-off + first external Common Lisp consumer (S5 promotion
gate).

### Conformance
- `validate-peer --profile core`: **PASS** — 568 / 284P / 195W / **0F** / 89skip
  (machine-verified `summary.failed == 0`). Same fixed point as OCaml (#3), reached spec-first.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, first full run, 0 codec fixes.
- origination-core: 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam cross-impl wire-proven).

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16⊂f32⊂f64 float minimization, length-then-lex
  map-key sort, recursive major-type-6 tag rejection, LEB128 + Base58 (no extra deps).
- **Ed25519 AND Ed448 both native, pure-Lisp** via `ironclad` — no FFI, no opt-in agility
  sub-library. Reaches the §9.1 floor (Ed25519 + SHA-256) and the agility higher bar
  (Ed448 + SHA-384) from the default build. Ed448 byte-equality RFC-8032-KAT-gated (A-CL-005).
  Deterministic RFC-8032 signing → cross-impl signature byte-equality. SHA-256/384 via
  `ironclad:digest-sequence`.
- **Native arbitrary-precision integers** — full §3.2 0..2⁶⁴−1 carrier range with no workaround.
- §1.5 size-cutoff peer_id construction (Ed25519 → `hash_type 0x00` raw-pubkey identity-multihash;
  Ed448 → `hash_type 0x01` SHA-256-of-pubkey), following the §1.5 canonical-form table, NOT the
  stale §7.4 pseudocode (A-CL-002).
- §4.1 handshake, §6.5/§6.6 dispatch as **CLOS multiple dispatch** on `(handler-class × operation)`
  (A-CL-008), capability authorization with chain attenuation + §5.7 delegation caveats, type
  registry (render-from-model, 53/53 byte-identical), in-memory address-space store with CAS.
- v7.73/v7.74 peer surface: §6.13 register's five normative writes, §PR-8 dispatch-boundary
  granter frame (V2(a)), §6.9a owner-cap bootstrap, §7a conformance handlers (`--validate`).
- Error model: the CL **condition system** — `entity-core-error` + typed subconditions; restarts
  available; protocol status carried as a value record, never across a condition.
- Concurrency: SBCL native threads (`sb-thread`, no third-party dep) — one reader thread per
  connection + `request_id`→waitqueue demux under a mutex (8-way demux verified at S3).

### Known limitations
- Crypto-agility **full MATRIX** (the M2/M3/M6 cross-product corpus) is a known cohort-wide
  deferral; the primitives (Ed448 + SHA-384) are S2-proven byte-equal and the connect-path slice
  is exercised, but the full agility matrix harness is not wired (see `status/PHASE-S5.md` §4).
- `tree_operations.cleanup` carries one non-critical WARN (shared with the OCaml cohort fixed
  point — the 284P/195W vs C#/TS 285P/194W delta).
- Public API not compiler-enforced (CL has no module-private keyword); surface tiers documented
  in `src/peer-package.lisp` + `status/PHASE-S5.md` §3 (the OCaml `.mli`-deferral analogue).
- ASDF version field cannot carry the `-pre` pre-release suffix (A-CL-010) — see the version note.
- The v7.73/v7.74 peer-surface behavior is cohort+oracle-sourced, not sourced from a SHA-pinned
  v7.73/v7.74 spec-data snapshot (which remains absent locally) — a byte-provenance gap, A-CL-001.

### Spec items surfaced (routed to architecture)
- **A-CL-002 ⚑** §7.4 NORMATIVE peer-id pseudocode contradicts §1.5 v7.65 identity-multihash —
  the **third** spec-first peer to corroborate (after OCaml A-OC-007, Zig A-ZIG-001).
- **A-CL-007 ⚑** ECF `format_code = 128` construct-vs-receive asymmetry unstated in §4.3/§4.7 —
  independent corroboration of OCaml A-OC-004 (second spec-first peer to reach the same fork).
- **A-CL-009 ⚑** address-space tree-path hex-case unspecified in §3.4/§3.5 (lowercase is the de
  facto convention) — NEW; a latent interop trap for any peer whose stdlib hex defaults uppercase.
- **A-CL-008** §6.5/§6.6 dispatch maps cleanly onto CLOS multiple dispatch — idiom-neutrality
  signal (five idioms converge on the same dispatch behavior); no spec change requested.
- **A-CL-001** v7.73/v7.74 spec-data snapshot missing — byte-provenance gap (the oracle check-set
  IS at HEAD; the peer's v7.73+ behavior is cohort+oracle-sourced).
- **A-CL-010** ASDF `:version` has no SemVer pre-release channel — packaging note (operator).
