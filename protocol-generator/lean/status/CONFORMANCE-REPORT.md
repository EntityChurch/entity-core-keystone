<!-- current-pin-banner:c1b0708 -->
> **CURRENT (2026-08-22) — oracle `entity-core-go @ c1b0708`, spec snapshot `v0.8.2`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **755 total · 312 pass · 337 warn · 0 FAIL · 106 skip** (elapsed 2976 ms).
>
> Re-measured directly against the pinned oracle via
> `tools/run-cohort-census.sh --to-status lean` — **a measurement, not a copy of the census.**
> The machine-readable `CONFORMANCE-REPORT.json` beside this file is the authoritative
> artifact; `tools/check-set-gate.py --tracked` gates it against the pinned check set.

# entity-core-protocol-lean — Conformance Report

**This file is new as of 2026-08-22.** `lean` carried a `CONFORMANCE-REPORT.json` but never a
markdown companion, so unlike its twelve siblings there is no prior build-history section below
the banner — nothing was superseded or removed to create it.

## Gate

`validate-peer --profile core` against the pinned oracle, driven by
`protocol-generator/lean/run-s4.sh`. Note `lean` runs with `INCONTAINER=0` (its own
`-v "$PWD":/repo` mount convention) — see `tools/run-cohort-census.sh`.

## History worth carrying

`lean` scored **83F** at the `c1b0708` re-pin (2026-08-21) — **2 real FAILs + 81 cascade**. The
cascade came from a single §6.3 defect: the peer refused the six malformed-temporal capability
variants (CAP-6a) by **closing the connection** instead of returning the `400 non_canonical_ecf`
that §6.3 mandates. The oracle reuses that connection, so every check after `capability` failed on
a broken pipe.

The peer was completely healthy throughout — clean stderr, exit code 0, never crashed — which is
what made it a distinct defect shape worth naming: every reflex the crash-cascade lesson trains
(find the uncaught exception, grep the peer log) finds nothing here. **A refusal implemented at the
wrong layer cascades exactly like a crash and reads like one.** Both the defect class and its
diagnosis (first FAIL in run order vs. last check before the first transport error) are ratcheted in
`AGENTS.md`; the cohort-level account is `CONFORMANCE-MATRIX.md` §1b/§1c.

`lean`'s distinguishing property is unchanged: a **pure-Lean proven codec core** with FFI crypto,
with selected invariants proved in `proofs/` rather than only tested. See `status/PHASE-S*.md`.
