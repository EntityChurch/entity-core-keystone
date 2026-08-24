# validate-peer — usage + diagnostics

**Source:** `entity-core-go/cmd/validate-peer/main.go`
**Purpose:** Live-peer conformance testing. Runs categorized test suites against a remote peer over TCP.

## Building the binary

From `entity-core-go/`:

```bash
cd <sibling>/entity-core-go
go build -o bin/validate-peer ./cmd/validate-peer
```

Or pull pre-built into the keystone container via `containers/<toolchain>/Containerfile`:

```dockerfile
COPY --from=docker.io/library/entity-core-go:latest /usr/local/bin/validate-peer /usr/local/bin/
```

(adjust source per how `entity-core-go` is distributed)

## Single-peer invocation

```bash
validate-peer -addr localhost:7777 \
              -identity framework-admin \
              -timeout 60s \
              -verbose \
              -json-out report.json
```

Flags:

| Flag | Meaning |
|---|---|
| `-addr host:port` | Peer to test |
| `-identity name` | Named identity from `~/.entity/identities/`; signs auth-required calls |
| `-category name` | Run only this category; otherwise runs all |
| `-exclude cats` | Comma-separated categories to exclude (useful: `-exclude tree_operations,local_files` for extension-free peers) |
| `-reference-peer host:port` | Known-good reference for origination (A-role) tests; single-peer mode can't catch outbound-dispatch bugs without it |
| `-timeout duration` | **GLOBAL** budget for the whole run, not per-category. **Default is `10m` as of the 740-check pin (`8537d875…`) and unchanged at the current 755-check pin** (it was `60s` at earlier pins — always confirm with `validate-peer -h`, don't trust a written-down default). When it expires mid-suite, the remaining categories are recorded as `budget_exhausted` and **never run** — see "Budget starvation" below. |
| `-verbose` | Wire request/response traces on stderr |
| `-failures-only` | Suppress passing checks; show only FAIL/SKIP/WARN |
| `-json` | JSON to stdout |
| `-json-out path` | JSON to file + text summary to stdout |

## Multi-peer convergence mode

```bash
validate-peer -peers host1:7777,host2:7778,host3:7779 \
              -identity framework-admin \
              -json-out convergence-report.json
```

Tests cross-peer consistency. The cross-impl parity matrix in `entity-core-architecture/docs/architecture/v7.0-core-revision/CROSS-IMPL-PARITY-MATRIX.md` uses this mode.

## Categories

Names per Go source (subject to drift; verify with `validate-peer -h` or `cmd/internal/validate/`):

| Category | Extension-free? | What it tests |
|---|---|---|
| `connectivity` | ✅ | TCP listen, `system/protocol/connect` handshake (`hello` → `authenticate`, EXECUTE/EXECUTE_RESPONSE) |
| `encoding` | ✅ | ECF / canonical CBOR round-trips |
| `type_system` | ✅ | `system/*` entity-type discipline; type-dispatch |
| `origination` | ✅ | A-role outbound dispatch (needs `-reference-peer`) |
| `handlers` | depends | Handler-interface conformance (base interface only is extension-free) |
| `tree_operations` | ❌ | Requires TREE extension |
| `local_files` | ❌ | Requires `local/files` domain handler |
| `…` | check `--list-categories` | additional categories per V7 amendments |

**Extension-free required set for `entity-core-protocol-<lang>` v0.1:** `connectivity`, `encoding`, `type_system`, `origination`, handler-interface basics.

## Reading the JSON output

```json
{
  "categories": [
    {
      "name": "connectivity",
      "checks": [
        {
          "name": "hello_round_trip",
          "status": "pass" | "fail" | "skip" | "warn",
          "detail": "...",
          "duration_ms": 12
        },
        ...
      ],
      "summary": { "pass": 10, "fail": 0, "skip": 2, "warn": 1 }
    },
    ...
  ],
  "budget_warning": "..." | null,
  "overall": { "pass": 45, "fail": 0, "skip": 2, "warn": 1 }
}
```

`status` values:
- `pass` — check executed and succeeded
- `fail` — check executed and failed; output should report root cause
- `skip` — preconditions not met (e.g. category-required extension not installed); usually not blocking
- `warn` — check passed with caveats (e.g. slower than expected); investigate but not blocking

## Common failure modes

### `connection_broken` errors

Transport layer dropped before the response. Causes:
- Generated peer panics on a message it doesn't recognize → fix message dispatch
- Generated peer holds the response (deadlock) → check that inbound reading doesn't block on outbound dispatch (V7 §4.8)
- Generated peer's framing is wrong → check length-prefix encoding

### `protocol_error` errors

Response received but malformed. Causes:
- Response missing required `code` field (V7 §6.12)
- Response not parseable as canonical CBOR
- Response entity has wrong `type`

### `recv_timeout` errors

Per-request deadline fired (V7 §6.11(c)). Causes:
- Handler dispatch is synchronous and slow
- Handler holds a lock the response writer needs
- Connection reader is blocked on outbound dispatch (V7 §4.8 violation)

### "Encoding" category failures

Bytes don't match canonical. See PHASE-S2-CODEC.md "byte-identity rule" for common causes. Cross-check against a conforming codec C-ABI impl (`libentitycore_codec`) byte-for-byte.

### "Origination" category failures

The generated peer can't initiate outbound EXECUTE correctly. Common cause: signing the wrong target (e.g. signing `request.content_hash` instead of `params.content_hash`). Reference: V7 §5.2 cap-chain provenance + §3.5 signature discovery.

### Budget starvation — the failure mode that looks like a clean run

**Check for this before trusting any summary.** `-timeout` is a **global** budget. If one check
hangs or one category is slow enough to consume it, every remaining category is recorded as
`budget_exhausted` and **never runs** — and the two output channels disagree about how serious
that is:

- **Human output** says so unmistakably:
  `!! WHOLE CATEGORIES NEVER RAN — the -timeout window expired mid-suite [resource_bounds] → this is coverage loss, not a slow peer`
- **JSON output** files those categories under **`skipped`**. So `summary.failed` stays small and
  a summary-only reader sees a nearly-clean run.

A starved run is an **incomplete measurement**: its P/W/F/S is a floor, not a result, and the
categories that didn't run are exactly where undiscovered FAILs live.

**Detect** (works on any report JSON):

```
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); \
  print(sorted({c["category"] for c in d["checks"] if "budget_exhausted" in c.get("message","")}))' \
  output/scratch/census/<peer>.json
```

**Then measure the hidden categories directly** — do *not* just raise `-timeout` and re-run the
whole suite behind the hang:

```
protocol-generator/shared/diagnostics/starved-categories-probe.sh <peer> [category...]
```

`-category <name>` runs each starved category on its own in seconds, and keeps the published gate
verdict at the default budget where it belongs. Raising `-timeout` to make a red run green is
forbidden (`AGENTS.md`); raising it as a one-off diagnostic to surface hidden coverage is fine,
just slower than `-category`.

**Locating the hog:** sum `elapsed_ms` per category — starvation is usually one check, not general
slowness.

```
python3 -c 'import json,sys,collections; d=json.load(open(sys.argv[1])); \
  t=collections.Counter(); [t.update({c["category"]: c.get("elapsed_ms",0)}) for c in d["checks"]]; \
  print(t.most_common(5))' output/scratch/census/<peer>.json
```

**Worked example** (asm-x86_64, 2026-08-17): `concurrency` consumed 599 947 ms of a 600 s budget
— all of it `t2_2_connection_churn` — while every other category finished in ~0 ms. Seven
categories starved, `resource_bounds` among them, hiding two real core FAILs. Full trace:
`research/stewardship/SESSION-2026-08-17-asm-budget-starvation.md`; consequences for the published
numbers: `CONFORMANCE-MATRIX.md` §1a.

### A `run-s4.sh` exit code is not a verdict

All 46 harnesses end the oracle invocation with `|| true`
(`grep -l '|| true' protocol-generator/*/run-s4.sh | wc -l` → 46/46). A peer with
`Result: FAIL` still exits `0`. The **JSON summary is the authoritative verdict source**; an
`rc` anomaly is a signal about the harness or its container, never about conformance.

## Debugging workflow

1. **Reproduce.** Run with `-verbose -failures-only`. Watch the wire traces for the failing check.
2. **Identify the surface.** Map the failing check to a V7 §-pointer. The check name usually hints.
3. **Locate generated code.** Find the matching function/method in `protocol-generator/<lang>/src/`.
4. **Inspect entities.** Use the inspect taps from `GUIDE-INSPECTABILITY` if you can. The peer's `dump` primitive should print the entity at the failure point.
5. **Cross-check against reference.** Same operation against `entity-core-go`'s peer — does it succeed? What differs?
6. **Fix; rerun.**

## When to escalate

- Spec-data ambiguity → architecture (logged in `research/stewardship/` and routed upstream per the hand-off boundary in `AGENTS.md`)
- Failure not reproducible against reference peers → research stewards (could be `validate-peer` test gap)
- Failure points at a profile decision the agent couldn't have made cleanly → operator + research (profile may need new field)

## Related tools

- `research/diagnostics/conformance-invariants.md` — **prevention-side companion to this doc.** This file is for diagnosing symptoms *after* a failure; that file pins the bug classes (N1–N8) to catch at design time. The "Common failure modes" above map onto N5–N8 (`connection_broken`/`recv_timeout` → N6/N7; convergence-mode disagreement → N8).
- `entity-core-go/cmd/internal/wire-conformance` — pure codec round-trip; subprocess, no live peer
- `entity-core-go/cmd/dump-types` — print entity-type registry
- `entity-core-go/cmd/dump-messages` — print message-type registry
- `entity-workbench-go/perfreview/` — perf + inspect harness; reference for the inspectability surface
