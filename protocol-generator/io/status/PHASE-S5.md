# entity-core-protocol-io — Phase S5 summary (COMPLETE)

**Phase:** S5 (publish / close-out)
**Date:** 2026-07-15
**Status:** ✅ artifacts complete. Registry publish deferred like the cohort
(exploratory paradigm probe, `0.1.0-pre`).

## Artifacts produced

| Artifact | Path |
|---|---|
| README | `README.md` (what the peer is, the §6.6-as-delegation probe, build/run) |
| CHANGELOG | `CHANGELOG.md` (`v0.1.0-pre`, tracks v0.8.0 / V8) |
| LICENSE | `LICENSE` (Apache-2.0, S9 default) |
| Profile | `profile.toml` + `arch/PROFILE-RATIONALE.md` |
| Toolchain | `containers/io-toolchain/` (frozen Io tag + Socket addon + GO-gate) |
| Conformance report | `status/CONFORMANCE-REPORT.{md,json}` (oracle-pinned P/W/F/S) |
| Phase status | `status/PHASE-S1…S5.md` |
| Ambiguity log | `status/SPEC-AMBIGUITY-LOG.md` (A-IO-001…026; 023 retracted) |
| Harnesses | `run-s2.sh`, `run-s4.sh`, `run-origination-core.sh`, `Makefile` |
| Tests | `test/{smoke,s2-corpus,typecheck,smoke-peer,multisig-accept}.io` |

## Release-readiness

- **Codec:** 71/71 byte-identical; **type floor:** 53/53, 0 drift.
- **Live gate:** **`--profile core` → `Result: PASS` — 0 FAIL across every gated
  category, `concurrency` included** (t2_1 sustained-load 0/10000 dropped, t2_2
  churn PASS); origination-core **3/3**; genuine multisig accept-path unit test
  PASS.
- **Concurrency reconciliation (A-IO-023 retracted):** an earlier draft recorded
  t2_1/t2_2 as an unfixable single-threaded "throughput ceiling." Measurement
  disproved it (the slower-crypto Oz/Mozart sibling passes the same checks); the
  real causes were two fixable poll-loop bugs — **A-IO-025** (Io `try` clones a
  Coroutine per call → per-request retain-stack leak) and **A-IO-026** (a blocking
  send stalled the single-threaded loop). Both fixed → clean 0-FAIL.
- **Version:** `0.1.0-pre` (tracks ENTITY-CORE-PROTOCOL v0.8.0 / V8). Promotion to
  `0.1.0` is not proposed — the probe's value is the §6.6-as-delegation rendering
  and the substrate lessons, not a deployment.

## Steady state

Tier: **probe** (exploratory ‡ row). Re-run the cohort harness on future spec
amendments. The single-threaded poll loop now clears the §4.9 sustained-load/churn
bar; the sole informational WARN (t1_1 no physical parallel speedup) is inherent
to a single event loop and marked a non-violation by the oracle.

## Operator handoff

- The oracle binaries in `output/s4-oracles/` are pin-verified (`cc1970f`) and
  were NOT rebuilt.
- No `git add`/`commit` performed — the operator commits after review.
- `CONFORMANCE-MATRIX.md` (repo root) row: NOT added by this agent (out of the
  permitted write scope — `protocol-generator/io/` + `containers/io-toolchain/`
  only). The operator adds the matrix row after review, with the status:
  probe, `--profile core` **clean 0-FAIL** (`Result: PASS (with warnings)`),
  origination 3/3, multisig accept.
