# entity-core-protocol-io — Phase S4 summary (COMPLETE — clean 0-FAIL)

**Phase:** S4 (conformance)
**Date:** 2026-07-15
**Oracle:** `validate-peer` @ **`cc1970f`** (matches `tools/oracle-pin.env`
fingerprint `8261a03…`). Measured natively, sealed-offline (`--network=none`).
**Reproduce:** `./run-s4.sh`, `./run-origination-core.sh`. Report:
`status/CONFORMANCE-REPORT.{md,json}`.

## Result

**`--profile core` → `Result: PASS` — 0 FAIL across every gated category,
`concurrency` included** (`682 total: 291 P / 295 W / 0 F / 96 S`; the 96 skips
are §9.0 profile-carve-out extension categories, exempt from the gate; the warns
are informational).

| Surface | Outcome |
|---|---|
| S2 wire corpus | **71/71** byte-identical, 0 fail |
| §9.5 type floor | **53/53** byte-identical to oracle (0 drift) |
| 15 functional core categories | **0 FAIL each** (connectivity, encoding, type_system 108/292/0, handlers, capability, tree_operations, security 28/0, multisig 11/0, authz, resource_bounds, universal_address_space, peer_canonicalization, format_agility, crypto_agility, negotiation) |
| `concurrency` | t1_2 PASS, t1_3 PASS, **t2_1 PASS (0/10000 dropped), t2_2 PASS**, t1_1 WARN (informational) |
| origination-core | **3/3 PASS** |
| multisig accept-path unit test | **PASS** (genuine 2-of-3 + M3/M4/M6 negatives) |

All categories pass **cumulatively** (against one long-lived peer — no
degradation) as well as in isolation. **The earlier concurrency FAIL was NOT a
throughput ceiling** — that A-IO-023 claim is retracted (see the ambiguity log).
It was two fixable bugs in the poll loop: **A-IO-025** (Io `try` clones a
Coroutine per call → a ~55 KB/request retain-stack leak) and **A-IO-026** (a
blocking send with `System sleep` stalled the single-threaded loop, cross-conn
head-of-line). With both fixed, `t2_1` clears 10 000 requests with 0 drops and
`t2_2` churn passes.

## Iteration highlights (the S4 debugging arc)

1. **Transport rewrite (A-IO-020):** the coroutine-per-connection Socket-addon
   model deep-recurses `EventManager yield → handleEvent` and wedges under the
   oracle's concurrent connections → replaced with a single-coroutine
   non-blocking poll loop. Connectivity 22/22.
2. **`try(...)` trap (A-IO-013):** Io's `try` returns nil/exception, not the
   value — this silently discarded the dispatch result (every EXECUTE → 500) and
   the peerid-parse (key_type=0xFD → wrong 401). Converted all try-for-value.
3. **Reentry via method not stored block (A-IO-015):** a stored `block` invoked
   from a foreign handler call site did not run; a Transport method fixed §6.11 →
   origination-core 3/3, concurrent reentry t1_2 PASS.
4. **Throughput fixes:** O(n²) `removeSlice`-per-frame → cursor-drain (A-IO-021);
   the poll loop body a METHOD so its retain pool drains per pass; skip binding
   the transient per-request EXECUTE signature (A-IO-022) — together these
   removed the ~6-req/s wall and the later-category timeout degradation.
5. **Reap-trap (A-IO-024):** a pass-count connection reaper (3000 passes ≈ 0.3 s)
   reaped active-but-idle connections mid-check → 5 spurious `security` §5.5a
   FAILs + an apparent wedge. Switched to a 60 s wall-clock idle reap. Root cause
   proven by reverting the suspect (the S1 watch-item discipline).
6. **Real logic fixes surfaced by the oracle:** empty-string tree target → root
   listing (§6.3); `unresolvable_grantee` as a returned verdict → 401 (§5.2/PR-3,
   was surfacing 500 via a fragile addon-boundary exception message).
7. **The concurrency reconciliation (A-IO-023 retraction):** the sibling Oz/Mozart
   peer passed t2_1/t2_2 with *slower* crypto, disproving a "throughput ceiling."
   Measurement showed accumulation (163→31 req/s, not flat-but-slow), bisected to
   **A-IO-025** (per-request `try` clones a Coroutine → ~55 KB/req leak → made the
   whole dispatch path total/non-raising and removed every hot-path `try`) and
   **A-IO-026** (blocking `_sendFrame` stalled the loop → non-blocking buffered
   sends flushed at the poll boundary). t2_1 0/10000 drops, t2_2 PASS.

## Findings filed (SPEC-AMBIGUITY-LOG)

A-IO-013/015/020/021/022/024/025/026 — all substrate/implementation class, none a
spec defect. A-IO-023 **retracted** (the "ceiling" was A-IO-025 + A-IO-026).
**Arch-worthy candidate:** A-IO-022 (a memory-primary peer should scope §6.5
dispatcher signature ingestion to handler-discoverable signatures, not the
transient request signature) — doc-class. The paradigm probe's durable findings:
A-IO-020 (Io's default coroutine concurrency is disqualified at the scheduler
level for a many-connection server; the manual poll loop is the seam), and the
A-IO-025/026 pair (on a single-threaded interpreter BOTH the error-model `try` and
the egress write must be leak-free/non-blocking) — all SUBSTRATE findings.

## Exit criteria

Functional conformance: MET (every core category 0 FAIL, origination 3/3, genuine
multisig accept). Binary `--profile core` 0-FAIL gate: **MET** — `Result: PASS
(with warnings)`, concurrency included. No oracle doctored; no golden file edited;
derived from the v0.8.0 spec-data.
