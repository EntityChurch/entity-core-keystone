# HANDOFF TO ARCH — `validate-peer` reports "never ran" and "deliberately not run" identically in JSON

**From:** entity-core-keystone (conformance anchor)
**Date:** 2026-08-17
**Oracle:** `entity-core-go @ de8f807` (`tools/oracle-pin.env`)
**Severity:** **High for anyone consuming the JSON report.** It let three peers carry 3 core
FAILs each while their reports read as 1 for four consecutive cohort censuses.
**Wire impact:** none. This is a reporting/observability defect in the oracle, not a spec or
protocol issue.

---

## 1. The claim being violated

`validate-peer -h`, verbatim:

```
-timeout duration
      overall timeout — must exceed the whole run; categories past it are recorded as
      untested, never silently dropped (default 10m0s)
```

**"recorded as untested, never silently dropped" is true of the human output and false of the
JSON.** For every machine consumer, they *are* silently dropped.

## 2. What the two output channels actually do

When the global budget expires mid-suite, the human output is unmistakable:

```
- !! WHOLE CATEGORIES NEVER RAN — the -timeout window expired mid-suite [resource_bounds]
     → raise -timeout (default 10m); this is coverage loss, not a slow peer
```

The JSON, for the same run, emits one synthetic entry per starved category:

```json
{ "category": "resource_bounds", "name": "skipped", "severity": "SKIP",
  "message": "category skipped: budget_exhausted: prior categories consumed the -timeout
              window (context deadline exceeded); re-run with a longer -timeout ..." }
```

Compare a legitimate `--profile core` carve-out from the same report:

```json
{ "category": "connectivity", "name": "keepalive_ping_pong", "severity": "SKIP",
  "message": "outside --profile core (NETWORK-extension keepalive, V7 §9.0)" }
```

**Same severity token.** The only thing separating "we chose not to run this" from "we never got
to this" is a substring of a free-text `message`. And `summary` — the block every aggregator
reads — carries neither:

```json
"summary": { "total": 699, "passed": 545, "warned": 42,
             "failed": 1, "skipped": 111, "elapsed_ms": 599947 }
```

Three consequences, all of which bit us:

1. **`failed` under-reports.** The starved categories contained real FAILs. The report said 1.
2. **`skipped` conflates two incomparable things**, so the usual "a skip counts as a failure
   unless it's a declared carve-out" rule cannot be applied programmatically.
3. **`total` shrinks**, so scores stop being comparable between peers — silently. A reader
   diffing `passed` across the cohort is comparing different denominators.

## 3. How it presented here

Measured across our 45-peer `--profile core` census at `de8f807`:

- **42 of 45 peers executed a byte-identical 740-check set.** The oracle is deterministic and
  consistent; we want to state that plainly, because it is the good news here.
- **3 peers (`asm-x86_64`, `asm-arm64`, `riscv64`) executed 699.** 48 checks across 7 categories
  never ran, one of them the **core `resource_bounds`** category.
- Their reports said `"failed": 1`. Driving the starved categories individually with
  `-category` produced **2 further real core FAILs** (`r1_payload_over_limit`,
  `r3_connection_flood`).
- This survived **four consecutive census runs** and was recorded in our published matrix as a
  "1 FAIL peer-latency flake". It was neither 1 FAIL nor latency.

The trigger on our side is a peer defect — one check (`t2_2_connection_churn`) hangs and consumes
599 s of the 600 s budget. **We are not asking the oracle to be robust against a hung peer.** We
are asking that when it degrades, the machine-readable artifact says so as loudly as the console
does.

## 4. Ask

Any one of these closes it; listed cheapest-first, and we have no preference beyond it being
machine-readable:

1. **A `summary` field** — e.g. `"budget_exhausted_categories": ["authz", "resource_bounds", …]`
   (empty array on a clean run). Smallest change, fully sufficient for our gate, and it makes
   every historical consumer's `summary` self-describing.
2. **A distinct severity** — `UNTESTED` (or `NOT_RUN`) instead of reusing `SKIP`. Cleanest
   semantically and matches the flag's own wording; a breaking change for anything parsing the
   severity enum.
3. **A top-level `"complete": false`** plus the category list.

**Related, smaller:** consider whether `Result:` should be `INCOMPLETE` rather than `PASS`/`FAIL`
when categories were starved. A peer that starves a category it would have failed currently gets
a better-looking `Result:` than one that ran everything, which inverts the incentive.

## 5. What we did on our side in the meantime

We did **not** patch or work around the oracle (`AGENTS.md` Boundaries — oracle bugs escalate,
they don't get patched here). We added a gate over its *output*:

- **`tools/check-set-gate.py`** — requires every peer in a census to have executed the identical
  check set, pinned as `core_executed_check_set_digest` in `tools/oracle-pin.env`
  (`8537d875…`, 740 checks @ `de8f807`), and hard-fails on any `budget_exhausted` category.
- Wired into `tools/run-cohort-census.sh`, which now exits non-zero on a non-comparable census.
- Playbook entry: `research/diagnostics/validate-peer-usage.md` → "Budget starvation — the
  failure mode that looks like a clean run", plus
  `protocol-generator/shared/diagnostics/starved-categories-probe.sh` to measure starved categories directly
  (seconds, versus re-running the whole suite behind the hang).

This protects us going forward. It does not help any other consumer of the JSON, which is why
we're filing it.

## 6. Reproduce

```
# a starved report from our census (or produce one against any peer that hangs a check)
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); \
  print(sorted({c["category"] for c in d["checks"] if "budget_exhausted" in c.get("message","")})); \
  print(d["summary"])' output/scratch/census/asm-x86_64.json

# -> ['authz','crypto_agility','format_agility','negotiation','peer_canonicalization',
#     'resource_bounds','universal_address_space']
# -> {'total': 699, ..., 'failed': 1, 'skipped': 111}      <- nothing here says 7 categories never ran

# the same peer, starved categories driven directly
protocol-generator/shared/diagnostics/starved-categories-probe.sh asm-x86_64
# -> resource_bounds  P=1 W=0 F=2 S=0
```

Full keystone-side trace: `research/stewardship/SESSION-2026-08-17-asm-budget-starvation.md`.
Adopter-facing consequences: `CONFORMANCE-MATRIX.md` §1a.
