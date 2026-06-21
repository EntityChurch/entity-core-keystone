# Phase S4 — Conformance

> Loaded by `/entity-rosetta <lang> --phase verify` or as fourth phase of full `/entity-rosetta <lang>`.

## Objective

Stand up the S3 peer; point `validate-peer --profile core` at it; iterate until it reports a clean `Result: PASS` (0 fail) under the V7 v7.72 §9.0 core-profile.

## The gate: `validate-peer --profile core` (V7 v7.72 §9.0)

> **Updated (F23).** The hand-listed category set this section used to
> carry is superseded by the V7 v7.72 §9.0 **core-profile** the oracle now ships
> (`validate-peer --profile core`, finding F18). The profile *is* the gate: it scopes
> to the core-profile categories, applies the 53-type §9.5 floor, and **auto-allowlists
> the §9.0 extension carve-out skips** (exempt from the FAIL gate). A spec-compliant
> core peer reports a clean **`Result: PASS`** under it. Do not hand-maintain a category
> list — and note repeated `-category` flags do NOT accumulate in Go's flag parser
> (last wins); `--profile core` is the correct single-flag gate.

**The gate (binary):** `validate-peer --profile core` → **`Result: PASS`** with
**0 fail**. Warns (non-§9.5-floor type vocabulary, matched-if-present) and
auto-allowlisted §9.0 skips do not block.

What the profile contains (informative — the oracle owns the authoritative list):

| Category | Core-profile? | Notes |
|---|---|---|
| `connectivity` `encoding` `type_system` | ✅ core | type_system = 53-type §9.5 floor; non-floor types WARN (matched-if-present) |
| `capability` `authz` `security` `multisig` | ✅ core | authz/security route some checks through ROLE/SUBSCRIPTION ext → those skip (F18/F19) |
| `negotiation` `crypto_agility` `format_agility` `peer_canonicalization` `universal_address_space` | ✅ core | the v7.65/§4.5/§4.7/§1.4 surfaces |
| `handlers` `tree_operations` | ✅ core (subset) | core get/put/list/connect/capability checks; EXTENSION-TREE §9 ops + extension handlers auto-skip |
| **`concurrency` `resource_bounds`** | ✅ core (v7.75 §9.0) | the non-functional substrate floor (§4.8/§4.9/§4.10) — folded into `coreProfileCategories` in v7.75. `concurrency` = §7b store-safety + resilience (T2.1/T2.2); `resource_bounds` = r1 payload→`413` (MUST) / r2 chain-depth→`400 chain_depth_exceeded` (MUST) / r3 conn-flood→WARN (SHOULD). Build them in at S3 (see PHASE-S3 "v7.75 non-functional substrate floor"). |
| **`origination`** | ❌ **extension-only** (v7.72 §9.0) | **was wrongly listed "required for v0.1" here.** The oracle auto-allowlists it under `--profile core`. Its outbound-dispatch core legs (`reference_connect`/`reference_ready`) pass with a `-reference-peer`; the deeper checks are ASYNC/NETWORK extension. Not a v0.1 gate. |
| `tree_operations`(ext ops), `subscriptions`, `continuations`, `role`, `local_files`, … | ❌ extension | whole extension categories — auto-skipped under core |

## How to invoke

The Go `validate-peer` is a fedora:43 ELF binary — it runs **inside the language
toolchain container** alongside the peer, so oracle + peer share one loopback and the
run stays sealed-offline (no `--network host`, no second container). Pattern (see the
TS reference harness `protocol-generator/typescript/run-s4.sh`):

**Resource caps are mandatory (RESOURCE-CAPS standard).** The conformance host is a
long-running TCP server; a frame-handling bug can spin or balloon memory and take the
host machine down. Every `podman run` in a run-script MUST source `tools/podman-caps.sh`
and pass `$PODMAN_RUN_CAPS` (memory + zero-swap + pids + cpus). Never launch a peer
container uncapped.

```bash
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z [-v <cache>:...] \
    entity-core-keystone/<lang-toolchain>:latest sh -c '
      # 1. build the peer (offline), then launch the host with --debug-open-grants
      #    (grant-gated categories need it); wait for its LISTENING readiness line.
      <build> && <peer-host> --port 7777 --debug-open-grants & 
      # 2. point the oracle at it — the profile IS the gate.
      /work/output/s4-oracles/validate-peer -addr 127.0.0.1:7777 -profile core \
          -json-out /work/protocol-generator/<lang>/status/CONFORMANCE-REPORT.json'
```

(Exact build/host commands are profile-driven — see the per-language `run-s4.sh`.)
`origination`'s outbound legs, if you want to exercise them, run under the *full*
profile with a Go `entity-peer` as `-reference-peer` — but they are not part of the
core gate.

## Iteration loop

1. Run validate-peer; capture JSON output
2. For each `FAIL`: read the failure detail; locate the surface in your peer; fix; recompile
3. If a failure points to spec-data ambiguity (not your code bug), log it and consult research stewards
4. Repeat until all required categories report `PASS`
5. If your peer hits an `validate-peer` test the agent didn't anticipate, surface to research stewards (could be a test-suite gap)

## What you do NOT do

- Patch validate-peer to accept your wrong output
- Mark a category "skipped" without justification in the report
- Exit the phase with any required category red

## Phase output

- `protocol-generator/<lang>/status/CONFORMANCE-REPORT.md` — green summary; per-category status; any deferred categories explained
- `protocol-generator/<lang>/status/CONFORMANCE-REPORT.json` — raw validate-peer output (for tooling)
- `protocol-generator/<lang>/status/PHASE-S4.md` — phase summary, iteration count
- `protocol-generator/<lang>/status/SPEC-AMBIGUITY-LOG.md` — updated

## Phase exit criteria

All required categories `PASS`; conformance report finalized; ambiguity log items either resolved or escalated with named owner.
