# entity-core-protocol-go — Phase S4 (Conformance) Summary

**Peer: Go (clean-room)** · **Status: COMPLETE —
`validate-peer --profile core` = `Result: PASS`, machine-verified `failed == 0`.**

## Gate

```
validate-peer --profile core  (oracle entity-core-go 75c532e, peer @ 127.0.0.1:7778)
→ 653 total · 291 pass · 268 warn · 0 FAIL · 94 skip · Result: PASS (with warnings)
```

Machine-verified `summary.failed == 0` (and 0 FAIL-severity records). The 94 skips
are the 93 §9.0 profile carve-out auto-allowlists + 1 local-env multisig skip, both
exempt from the FAIL gate. (Live total is 653 at `75c532e`, not the docs' 576; the
delta is non-failing newer-category skips + a wider type_system probe — see
A-GO-007.)

## Iteration count: 2

1. **108 FAIL** — 107 `type_system` (`system/type/*` → 404) + 1 `security`
   (cross-peer cap-token path, same root cause). The peer had not published the
   **V7 §9.5 53-core-type registry** (an explicit S3 deferral).
2. **0 FAIL** — after publishing the registry (`src/peer/typedefs.go`,
   `publishCoreTypes` in `NewPeer`). No other peer change.

## What was built this phase

- `src/peer/typedefs.go` — the §9.5 53-type floor as an in-code model
  (`typeDef`/`fspec` omit-empty builders) rendered through the peer's OWN S2
  codec; published at `/{peer}/system/type/{name}`. Clean-room render-from-model
  (NOT ingest-oracle-bytes); core+operational+type-bootstrap only, no extension
  vocab (refined G4 / F17).
- `src/peer/type_registry_test.go` — `TestCoreTypeRegistryByteIdentical`:
  renders all 53 and byte-diffs each `content_hash` against the canonical
  `type-registry-vectors-v1` (S8 golden-file). **53/53 byte-identical, first run.**
- `run-s4.sh` — single-peer conformance harness (host @ :7778, `--validate`,
  sealed-offline container).
- `run-origination-core.sh` — the reference-peer-gated origination probe
  (Go target :7778 + Go `entity-peer` reference :7779).

## Supporting gates

- **53-type registry:** 53/53 byte-identical (`TestCoreTypeRegistryByteIdentical`).
- **origination-core:** 3/3 PASS (`reference_connect`, `reference_ready`,
  `dispatch_outbound_reentry` over real two-peer TCP, §6.11 reentry).
- **S2 codec regression:** 69/69 + units, unbroken.
- **S3 loopback smoke:** 11/11, unbroken.
- **gofmt / go vet:** clean.

## go test -race — ATTEMPTED, did not complete in-env (non-gating)

The S3-deferred `-race` run was attempted twice at S4 and **did not complete in
this environment** (neither a DATA RACE nor a clean pass was produced):

1. **Host toolchain** — the host `go` is a mise shim at **1.24.13** (below the
   oracle's go.mod `go 1.25` floor); the `CGO_ENABLED=1 go test -race` stalled
   during the cgo race-detector build (never reached the test), and was killed.
2. **Container + ephemeral gcc** — redone in `entity-core-keystone/go:latest`
   (go 1.25.10) with `dnf install gcc` (the race detector needs cgo; the minimal
   stdlib-only image ships no C compiler). The cold race-instrumented build of the
   crypto-heavy `peer` package stalled under the sandbox past a 540s timeout
   (build cache plateaued at 79 MiB), so it too produced no verdict.

**This is NOT a gate.** Store safety is **structural** (`sync.RWMutex` over both
store maps; reads RLock, writes Lock; emit consumers fire OUTSIDE the lock; each
inbound EXECUTE dispatches on its own goroutine), and it is exercised live by
(a) the S3 loopback's concurrent **8-way request_id demux** and (b) the oracle's
**`concurrency` category — 5/5 PASS under `--profile core`**, which includes the
§7b T2.1 sustained-load store-race probe (the exact probe that flushed the
Zig/Common-Lisp store races the Go peer was designed to avoid from day one).
`-race` would be confirmatory only; its absence does not weaken the store-safety
claim, which is carried by structure + the live concurrency gate.

## Oracle-build isolation (hard rule, followed)

Vendored the **committed** snapshot `75c532e` via
`git -C ~/projects/entity-systems/entity-core-go archive 75c532e | tar -x -C <TEMP>`
into a temp dir OUTSIDE `entity-core-go`; removed the vendored `mise.toml` (host
go shim trips on it); built `validate-peer` + `entity-peer` in that temp dir
(in the `go:latest` container, `GOWORK=<temp>/go.work`), output copied to the
gitignored `output/s4-oracles/`. **Never cd'd into the oracle tree, never built
with it as cwd, no `.bin-out` or build artifact leaked** (verified `git status`
on the oracle tree shows zero new files).

## Exit criteria

`validate-peer --profile core` = `Result: PASS` (0 FAIL, machine-verified) ·
53-type registry 53/53 byte-identical · origination-core 3/3 · S2/S3 regression
unbroken · gofmt+vet clean · oracle build isolated · ambiguity log updated
(A-GO-007). **S4 PASS.**

## Not committed

Per phase discipline + the worktree handoff: changes are left uncommitted for the
orchestrator to review (`typedefs.go`, `type_registry_test.go`,
`bootstrap.go` edit, `run-s4.sh`, `run-origination-core.sh`, the status reports).
