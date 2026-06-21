# entity-core-protocol-ada — Conformance Report (S4)

**Peer #10** (Ada 2012/2022, GNAT — safety-critical /
strong-typing; tasks + protected objects + rendezvous, design-by-contract) ·
**Phase:** S4 (conformance) · **Status: 🟢 GREEN — `validate-peer --profile core`
PASS, 0 FAIL (machine-verified `summary.failed == 0`).**

---

## S4 — `validate-peer --profile core` → **PASS** (576 · 0 FAIL · 89 skip) — cohort baseline `b30a589`

```
576 total · 292 passed · 195 warned · 0 FAILED · 89 skipped → Result: PASS (with warnings)
```

**This is the HEADLINE certification — the true cohort-comparable number.** Machine-verified:
`CONFORMANCE-REPORT.json` → `summary.failed == 0`. Peer ID
`2KD6sD8JpEHJ3EaQu2mKCfiQZnkvcDmS8xtvstw9c4dHZm`. `resource_bounds` is now an **ACTIVE
core category** (2 PASS · 1 WARN, not SKIP) and `concurrency` is 5/5 — see below.

**Command:** `NOBUILD=1 ./protocol-generator/ada/run-s4.sh` →
`validate-peer -addr 127.0.0.1:7778 -profile core -json-out status/CONFORMANCE-REPORT.json`,
run sealed-offline (`--network=none`) in `entity-core-keystone/ada-toolchain:latest`;
the Go `validate-peer` ELF and the GNAT host share one loopback. Port **7778** (Ada's
assigned parallel-hazard port; the C sibling uses 7777). Host launched
`--debug-open-grants --validate`. `NOBUILD=1` — the **already-green Ada peer binary
was NOT rebuilt or modified**; this is an oracle-swap + re-run only.

### Oracle provenance — the v7.75 cohort baseline `b30a589`

`output/s4-oracles/{validate-peer,entity-peer}`, built `CGO_ENABLED=0 / GOWORK=off`
in `containers/go` from a **READ-ONLY `git archive`** of `entity-core-go` at the
v7.75 cohort baseline **`b30a589`**
("v7.75: pair §9.0 drift gate post-arch-fold; resource_bounds enumerated"). The go tree
was never touched (git archive is read-only). The prior `62044c5` oracle binaries are
retained alongside as `{validate-peer,entity-peer}-62044c5` for the 574 evidence run below.

`b30a589` is the **resolved cohort oracle**: it is the commit that folds `resource_bounds`
into `coreProfileCategories` (`cmd/internal/validate/profile.go` adds `catResourceBounds:
true`, joining `catConcurrency: true`), so `resource_bounds` runs ACTIVE under
`--profile core` → the real **576 · 0F · 89S**. The cohort scorecard's "62044c5" label is
off-by-one-commit; `b30a589` (its immediate child, clean, ancestor of the later clean
commits) is the true v7.75 oracle. See A-ADA-013 in SPEC-AMBIGUITY-LOG.md.

### Additional evidence — clean `62044c5` build (574 · 0F · 90S) + standalone resource_bounds GREEN

A clean `62044c5` build gives **574 · 0F · 90S** — the entire difference from 576 is the
`resource_bounds` category: at `62044c5`, `coreProfileCategories` contains `concurrency`
but **NOT** `resource_bounds`, so a CLEAN `62044c5` build auto-skips `resource_bounds`
under `--profile core` (the 90th skip). That run is 0-FAIL, and `resource_bounds` was
separately certified GREEN there as its own `-category` run (r1 413 / r2 400 / r3 WARN,
below). The next commit `b30a589` simply enumerates `resource_bounds` into core, folding
that standalone GREEN into the headline run → 576. The binary gate (`Result: PASS`,
0 FAIL) holds across every commit; the oracle was never modified (S5 — no doctoring).

### Core-profile scoreboard

| Category | P | W | F | S | Note |
|---|--:|--:|--:|--:|---|
| connectivity / encoding | 22 / 6 | 0 | 0 | 0 | §4.1 handshake (incl. F12 cross-connection replay reject) + ECF wire |
| type_system | 108 | 194 | **0** | 0 | **53/53 §9.5 floor byte-identical**; 194 WARN = non-floor (matched-if-present) |
| handlers | 35 | 0 | **0** | 32 | core get/put/connect/cap + §10.1 register gate **10/10**; ext handlers auto-skip |
| capability / multisig | 12 / 10 | 0 | 0 | 0 | §6.2 request/configure/revoke + scope-widening reject + §PR-8 V2(a) |
| tree_operations | 25 | 0 | **0** | 31 | core get/put + CAS (409) + path-flex + deletion-marker listing-filter; EXTENSION-TREE §9 auto-skip |
| security | 28 | 0 | **0** | 1 | §5 capability/signature chain |
| authz | 6 | 0 | 0 | 2 | §A4-AUTHZ codes; ROLE-ext skips carved out |
| **concurrency** | **5** | 0 | **0** | 0 | **§7b — all 5 PASS** (genuinely concurrent, not serialized — see below) |
| **resource_bounds** | **2** | **1** | **0** | 0 | **§9.1 — ACTIVE in core at `b30a589`** (r1/r2 PASS, r3 conn-flood WARN — see below) |
| universal_address_space / peer_canonicalization | 8 / 7 | 0 | 0 | 0 | §1.4 absolute/relative equivalence; §1.5 + v7.65 §3.6 lazy-canon mint |
| negotiation / crypto_agility / format_agility | 4 / 4 / 10 | 0 | 0 | 0 | §4.5 disjoint-set reject (400) + §4.7 unknown-key-type reject (400) |
| (extension categories) | 0 | 0 | 0 | ~50 | auto-allowlisted §9.0 carve-outs |
| **Total** | **292** | **195** | **0** | **89** | **Result: PASS** |

### concurrency — genuinely 5/5 (not serialized)

All five §7b checks PASS: `t1_1_concurrent_demux`, `t1_2_concurrent_reentry`,
`t1_3_no_head_of_line`, `t2_1_sustained_load` (10000 reqs, 0 dropped, ~8.5s),
`t2_2_connection_churn`. `t1_3` (no-head-of-line) and `t2_1` (sustained parallel
load) PASS together, which proves the dispatch is **genuinely concurrent across
connections, not accidentally serialized**: the §4.8 **protected-object store** +
**one reader task per connection** make the store-race structurally unrepresentable
(the C sibling's heap-race A-C-009 cannot occur here by construction), and a child
task is spawned ONLY for the §6.11 reentry op (dispatch-outbound) so the per-request
task storm that exhausted earlier designs under the load gates is avoided.

### resource_bounds — ACTIVE in core at `b30a589` (2 PASS · 1 WARN · 0 FAIL)

At `b30a589` `resource_bounds` is an enumerated core category, so these three checks
run **inside the headline 576 `--profile core` gate** (no longer a standalone
`-category` run). Live result from the b30a589 core run:

```
r1_payload_over_limit        PASS  (declared_max_payload=16777216 → wrote 16778240-byte length prefix → connection terminated; payload_too_large)
r2_chain_depth_over_limit    PASS  (declared_max_chain_depth=64 → 65-deep chain → 400 chain_depth_exceeded; tree.get on same conn still served; 400 ≠ 403)
r3_connection_flood          WARN  (256 conns opened without refusal, peer kept serving — admission delegated externally; SHOULD/external)
```

(The same 2P+1W result was first obtained as a standalone `-category resource_bounds`
run against the `62044c5` oracle — that GREEN is what `b30a589` folds into core.)

### origination-core 3/3 (`run-origination-core.sh`)

```
[origination]  PASS reference_connect · PASS reference_ready · PASS dispatch_outbound_reentry
Result: PASS (3 total, 3 passed, 0 failed)
```

The §6.11 reentry seam wire-proven over real two-peer TCP against a Go
`entity-peer --open-access` reference (vendored from `b30a589`): the Ada target
originates an outbound EXECUTE back to the validator-as-B over the SAME inbound
connection. dispatch-outbound is a **generic relay** — it forwards the `{value: X}`
params bytes verbatim and returns the downstream result entity verbatim
(per the §7b concurrency-gate matrix ruling #2).

### §9.5 53-type floor — byte-identical 53/53

The peer publishes the 53 core type definitions at `system/type/<name>` from a
generated table (`src/entity_core-protocol-type_registry.adb`, generated by
`tools/gen_type_registry.py` from the oracle's `types.RegisterCoreTypes`
registry). The oracle's `type_system *_match` (content_hash equality) is 53/53, 0
FAIL — the Ada S2-green codec recomputes each content_hash byte-identically.

## What S4 built (real bodies, not stubs — the C-sibling-class work)

| Deliverable | File |
|---|---|
| §9.5 53-type registry (publish-from-canonical) | `src/entity_core-protocol-type_registry.{ads,adb}` (+ `tools/gen_type_registry.py`) |
| §6.11 dispatch-outbound reentry body + transport seam | `Handle_Dispatch_Outbound` (handlers) + `Connection_Outbound` / reentry-only `Dispatch_Task` (transport) |
| §6.2 capability ops: real configure / revoke + scope-widening reject | `Handle_Cap_Configure`, `Handle_Cap_Revoke`, `Grants_Are_Subset` |
| §10.1 dynamic-register gate (register/unregister + 5 writes) | `Handle_Handler_Register`, `Handle_Handler_Unregister` |
| §3.9 tree CAS (expected_hash → 409) + §6.3 delete + §1.4 path-flex + deletion-marker listing filter | `Handle_Tree_Put`, `Valid_Tree_Path`, `Build_Listing` |
| §4.5 negotiation disjoint-set reject + §4.7 unknown-key-type reject | `Handle_Hello` |
| F12 per-connection nonce uniqueness (replay reject) | `Nonce_Counter` / `Next_Nonce_Seq` |
| handler-interface operations sets (§6.2 N3) | `Ops_Map` + `*_Ops` lists |
| the `--profile core` harness + the §6.11 reentry probe harness | `run-s4.sh` + `run-origination-core.sh` |
| oracle built from `b30a589` (cohort baseline; `62044c5` retained as `*-62044c5`) | `output/s4-oracles/{validate-peer,entity-peer}` (gitignored via root `**/output/`) |

## Regression

- **S2 codec corpus: 69/69** + 37/37 self-tests (Ed25519/SHAKE256 KATs) — codec untouched.
- **S3 two-direction loopback smoke: GREEN** (Scenario A 5/5, Scenario B 2/2) against the
  Go reference — the transport reentry/CAS/dispatch changes did not break wire-compat.
- Build clean under `-gnatwa` (all warnings) + `-gnata` (contracts live).

## Standards honored
- **S1** — all in-container, sealed offline (`--network=none`); the READ-ONLY go oracle
  was extracted via `git archive` (never modified) and built in `containers/go`.
  `--debug-open-grants` is the cohort's non-conformant debug seed; `--validate` makes the
  §7a handlers live (off by default).
- **S5/S7** — raw oracle verdict; the 195 warns are oracle-marked non-§9.5-floor type
  vocabulary (matched-if-present) + the r3 connection-flood SHOULD; the 89 skips are §9.0
  extension carve-outs. No FAIL disguised as a SKIP; no oracle/vector/harness doctoring;
  no category marked skipped by us. The oracle was re-vendored from `b30a589` via READ-ONLY
  `git archive` (never modified) and the Ada peer was NOT rebuilt (`NOBUILD=1`).
- **S8** — convergence: the most idiom-distant axes in the batch (Ada tasking/rendezvous +
  protected objects + design-by-contract) reach the same 0-FAIL fixed point as the cohort.

## Exit criteria
`validate-peer --profile core` PASS (**576 · 0 FAIL · 89 skip** at cohort baseline
`b30a589`, `summary.failed == 0`) · §10.1 register gate 10/10 · concurrency 5/5 (genuinely
concurrent) · resource_bounds ACTIVE in core (r1 PASS / r2 PASS / r3 WARN) ·
origination-core 3/3 · 53-type §9.5 floor byte-identical (53/53) · oracle built from clean
`b30a589` (with the `62044c5`/574 + standalone-resource_bounds-GREEN runs as additional
0-FAIL evidence) · S3 smoke + S2 corpus regression unbroken · container reproducible ·
Ada peer NOT rebuilt (oracle-swap only). **S4 PASS.**
