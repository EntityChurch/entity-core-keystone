# PHASE-S4 — conformance — entity-core-protocol-oz

**Date:** 2026-07-15. **Verdict: PASS — 0 FAIL.**

## Gate

```
validate-peer --profile core @ cc1970f
682 · 285P / 301W / 0F / 96S   Result: PASS
```

(96 skips = §9.0 extension carve-outs, auto-allowlisted; 0 fail-counting skips.)
Full per-category table + JSON in `CONFORMANCE-REPORT.{md,json}`. Origination-core
3/3 via `run-origination-core.sh`; multisig accept-path unit test PASS via
`make multisig-accept`.

## Iteration (bugs → fixes)

1. **`Conn.SetOutbound` type error** — `C.field := V` on a record of cells was
   parsed as array-slot assignment. Fixed by binding the cell to a var first.
2. **All authenticated dispatch → 404** — §6.6 resolution dropped the leading `/`
   because `"" == nil` in Oz and the fold used `== nil` as a first-element sentinel
   (A-OZ-005 bug 1). type_system/handlers/tree/capability all went 0-FAIL after.
3. **Root-listing hang (20s) cascading to every later category** — `{List.last ""}`
   raised, escaped the narrow catch, killed the worker thread → no response
   (A-OZ-005 bug 2). Fixed: guard empty/`"/"` targets as root listing + broaden the
   dispatcher catch to `[] _ then 500`.
4. **`agility_unknown_1` → 401 instead of 400** — decode the claimed peer_id's
   varint key_type; ≠ 0x01 ⇒ 400 unsupported_key_type (A-OZ-007).
5. **Full-run cascade after `concurrency`** — the default oracle wall-clock timeout
   fired during `t2_1_sustained_load` (~50s on this crypto-crosses-a-pipe peer),
   marking later categories as skips-that-count-as-fail. Fixed operationally: the
   run-s4 default `-timeout 10m` (the cohort's slow-peer budget, as dart/prolog/rexx
   do). NOT a peer bug — categories are all 0-FAIL in isolation and under the budget.

## Watch-item outcomes (from S1)

| Watch-item | Outcome |
|---|---|
| `Open.pipe` blocking under concurrent handler outbound + t2_2 churn | **PASS** — reader-never-blocks-on-dispatch + dataflow-var demux; t2_2 4.6s, t1_2 reentry, origination reentry all green (A-OZ-006) |
| A-PD-016 ms-precision mint `created_at` | daemon `NOW` (clock_gettime ms) — no revoke-aliasing cascade; capability/security/authz all green |
| A-PD-017 open/debug seed `["*", "/*/*"]` | `OpenGrantsScope` carries both forms — universal_address_space 8/0 |
| §1.6 frame-cap | 16 MiB cap in transport; §4.10(a) 413 keeps-serving PASS |

## Exit

All core-gate categories PASS; origination-core 3/3; multisig accept + sub-threshold
DENY unit test PASS; report finalized; no blocking ambiguities (A-OZ-001…007 all 🟢).
