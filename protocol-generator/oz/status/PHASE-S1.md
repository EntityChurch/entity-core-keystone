# PHASE-S1 — profile research + authoring — entity-core-protocol-oz

**Date:** 2026-07-15. **Verdict: COMPLETE — S2 unblocked.**

S1 feasibility was pre-gated GO on 2026-07-15 (live in-container probes,
`protocol-generator/shared/evaluations/oz-io-viability.md` §S1; build plan
`docs/status/HANDOFF-2026-07-15-oz-io-s1-go.md`). This phase encoded that
evidence into the pinned recipe + profile.

## Produced

| Artifact | State |
|---|---|
| `containers/mozart-toolchain/Containerfile` | authored; image **built green** (`entity-core-keystone/mozart-toolchain:latest`). Mozart 2.0.1 release RPM, SHA-256-pinned (`d7b0fee5…ae04`), fetched fresh + fail-closed; tcl/tk resolve from fedora:43 (ozwish-only) |
| `containers/mozart-toolchain/gogate-selftest.sh` | baked into the image build (puredata-toolchain pattern): headless ozc/ozengine + dataflow-thread resume + bignum `[2^63, 2^64−1]` boundary + byte-clean `Open.socket` TCP echo (0x00/0xFF) + byte-clean `Open.pipe` co-process — FATAL on any miss |
| `profile.toml` | complete, no TBD fields |
| `arch/PROFILE-RATIONALE.md` | written |
| `status/SPEC-AMBIGUITY-LOG.md` | initialized; A-OZ-001…004 filed |

## Key decisions (detail in PROFILE-RATIONALE)

1. **Release RPM, no source build** — the S1 evidence, now pinned + self-tested
   at every image build.
2. **Codec = hand-rolled canonical CBOR in pure Oz** (bignum ints verified — the
   A-OZ-001 probe answered the handoff's "verify Oz integer semantics at S2"
   early: bignum class, head-form tax waived) **+ floats as IEEE bit patterns**
   (A-OZ-002: no VM float arithmetic on the wire path).
3. **Crypto/clock/entropy = `entity-codec-daemon` co-process** over `Open.pipe`
   (ecnet vocabulary, binary framing — A-OZ-004); Oz owns its sockets natively.
4. **Concurrency = dataflow-thread-per-connection + port agents** for all shared
   state; §6.11 demux as a bare dataflow variable (the paradigm claim S4 tests);
   no locks by design.
5. **TCP_NODELAY substrate-unreachable** (A-OZ-003) — logged, not silent.

## Watch-items carried to S2/S4

- `Open.pipe` blocking semantics under concurrent handler outbound + t2_2-class
  connection churn (S1 watch-item) — churn test scheduled EARLY in S4.
- A-PD-016 ms-precision mints (daemon NOW), A-PD-017 seed dual-form
  `["*", "/*/*"]`, §1.6 frame-cap discipline, multisig accept-path unit test —
  all pre-resolved into the profile's `[spec]` trap list.

## Exit criteria

Profile complete (no TBD) ✅ · rationale written ✅ · container exists + builds
green ✅ · no blocking-severity ambiguity ✅.
