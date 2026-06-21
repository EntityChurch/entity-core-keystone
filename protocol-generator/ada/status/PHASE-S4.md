# entity-core-protocol-ada — Phase S4 (Conformance) Summary

**Peer #10** (Ada 2012/2022, GNAT) · **10th byte-compat impl** ·
**Outcome: 🟢 `validate-peer --profile core` PASS — 0 FAIL, machine-verified
(`summary.failed == 0`).**

## The gate — cohort baseline `b30a589`

```
576 total · 292 passed · 195 warned · 0 FAILED · 89 skipped → Result: PASS (with warnings)
```

**This is the HEADLINE — the true cohort-comparable 576·0F·89S.** Machine-verified
`summary.failed == 0`. Command: `NOBUILD=1 ./protocol-generator/ada/run-s4.sh` — the
already-green **Ada peer was NOT rebuilt**; this is an oracle-swap + re-run only.
Oracle = `output/s4-oracles/validate-peer`, built `CGO_ENABLED=0 / GOWORK=off` in
`containers/go` from a **READ-ONLY `git archive`** of the v7.75 cohort baseline
`entity-core-go @ b30a589` ("v7.75: pair §9.0 drift gate post-arch-fold; resource_bounds
enumerated"). The prior `62044c5` binaries are retained as `*-62044c5`.

**Why `b30a589` is the resolved cohort oracle:** `b30a589` adds `catResourceBounds: true`
to `coreProfileCategories` (`cmd/internal/validate/profile.go`, joining `catConcurrency`),
so `resource_bounds` runs ACTIVE under `--profile core` → the real **576·0F·89S**. The
cohort scorecard's "62044c5" label is off-by-one; `b30a589` (its clean immediate child) is
the true v7.75 oracle (see A-ADA-013). A clean `62044c5` build = **574·0F·90S** (kept as
additional 0-FAIL evidence) — the 2-check delta is exactly `resource_bounds`, which at
`62044c5` is NOT enumerated into core (auto-skipped), and was separately certified GREEN
there as its own `-category` run. `b30a589` folds that standalone GREEN into the headline.

`resource_bounds` in the b30a589 core run: **2 PASS · 1 WARN** (r1 PASS / r2 PASS /
r3 conn-flood WARN) — now ACTIVE, not SKIP. Plus **§10.1 register gate 10/10**,
**concurrency 5/5** (genuinely concurrent), **origination-core 3/3**
(`dispatch_outbound_reentry` PASS over real two-peer TCP vs the `b30a589` Go
`entity-peer`), **§9.5 53-type floor byte-identical 53/53**.

## What S4 built (S3 left these as stubs/deferred — built as real bodies now)

The Ada S3 shipped the four-MUST-handler skeleton + transport. S4 built the real bodies
the conformance gate exercises — the C-sibling-class work the prompt flagged:

1. **§9.5 53-type registry** (`src/entity_core-protocol-type_registry.{ads,adb}` via
   `tools/gen_type_registry.py`) — publishes the 53 floor type definitions at
   `system/type/<name>`, byte-identical to the `62044c5` oracle's `RegisterCoreTypes`.
   Closed the 107-FAIL type_system cluster (404 → 53/53 match).
2. **§6.11 dispatch-outbound reentry** — handler body `Handle_Dispatch_Outbound` +
   transport seam `Connection_Outbound` (write outbound on the same socket + demux the
   reply by request_id) + a reentry-ONLY child task (`Needs_Async`/`Dispatch_Task`) so
   the reader stays free to demux the reentry response without a per-request task storm.
   Generic relay (verbatim value + result). Closed concurrency `t1_2` + origination-core.
3. **§6.2 capability ops** — real `configure` (bind policy-entry; "default"/66-hex/peer-id
   pattern validation, partial-prefix → 400), real `revoke` (revocation marker +
   handler-set `revoked_at`; zero-token → 400), and a `request` scope-widening reject
   (`Cap.Grants_Are_Subset`). Plus the cap-request grants navigation fix.
4. **§10.1 dynamic-register gate** — `register` (manifest → interface@`system/handler/<p>`,
   handler@`<p>`, grant@`system/capability/grants/<p>`, grant-sig@`system/signature/<hash>`)
   and `unregister` (symmetric teardown incl. the grant signature).
5. **§3.9 tree CAS** (`expected_hash` → 409; zero-hash CAS-create vs non-zero CAS-update),
   **§6.3 delete** (no-entity put = unbind), **§1.4 path-flex** (`Valid_Tree_Path`: reject
   null byte / empty segment / dot / dotdot / non-peer-id leading slash; accept Unicode +
   absolute `/peer-id/...`), **deletion-marker listing filter** (`Build_Listing` omits
   tombstoned leaves).
6. **§4.5 negotiation** disjoint hash_formats/key_types → 400, **§4.7** unknown key_type
   (peer-id prefix ≠ ed25519) → 400 at hello, **F12** per-connection nonce uniqueness
   (`Nonce_Counter`) so a captured authenticate cannot replay cross-connection.
7. **§6.2 N3** handler-interface `operations` sets (connect/tree/cap/handler).

## The grind: 159 → 0 FAIL (iteration count: ~7 oracle runs)

| Run | Count | Fix |
|---|---|---|
| baseline | 159 FAIL | S3 peer as-is |
| put fix | 142 | `params.data.entity` navigation (put was reading one level too shallow; same root bug as the Java A-JAVA-010 / cap-grants) |
| type registry | 34 | published the 53-type §9.5 floor (107 type_system FAILs → 0) |
| handler bodies | 23 | dispatch-outbound + cap configure/revoke + scope-widening + ops sets |
| reentry-async + op-name | concurrency 5/5 | dispatch-outbound operation is `dispatch` (not `dispatch-outbound`); reentry-only child task to fix t1_2 without t2_1/t2_2 task exhaustion |
| register + CAS + path | 9 | §10.1 register reads `params.data.manifest`; CAS `expected_hash`→409; path-flex; deletion-marker listing filter |
| negotiation/agility/nonce | 0 | §4.5/§4.7 reject; per-connection nonce uniqueness (F12) |

No doctoring: every fix was derived spec-first from V7 + the oracle's own check
sources, never by patching validate-peer, hand-editing vectors, or disguising a FAIL as a
SKIP. The re-certification at `b30a589` is a pure oracle-swap — no peer change.

## The Ada idiom payoff (the centerpiece)

The §4.8 **protected-object store** + **one reader task per connection** make the
store-race **structurally unrepresentable** — the C sibling's live-concurrency heap race
(A-C-009) cannot occur here by construction. concurrency is genuinely 5/5 (not
serialized): `t1_3_no_head_of_line` AND `t2_1_sustained_load` (10000 reqs, 0 dropped)
pass together. The §6.11 reentry is the one place a child task is needed — and it is
spawned ONLY for the dispatch-outbound op, so the load gates stay cheap.

## New ambiguities
None blocking. **A-ADA-013 RESOLVED:** the cohort oracle is `b30a589`, not `62044c5`.
`62044c5` does not enumerate `resource_bounds` into `coreProfileCategories` (only
`concurrency` was folded there) → a clean `62044c5` `--profile core` is 574·0F·90S; its
immediate child `b30a589` adds `catResourceBounds: true` → the real cohort 576·0F·89S. The
cohort scorecard's "62044c5" label was off-by-one-commit. Re-certified at `b30a589`
(oracle-swap only). Non-blocking, now resolved.

## Exit criteria
`validate-peer --profile core` PASS (**576 · 0 FAIL · 89 skip** at cohort baseline
`b30a589`) · §10.1 10/10 · concurrency 5/5 · resource_bounds ACTIVE in core (r1/r2 PASS,
r3 WARN) · origination-core 3/3 · 53/53 type floor · oracle `b30a589` (`62044c5`/574 +
standalone resource_bounds GREEN as additional 0-FAIL evidence) · Ada peer NOT rebuilt
(oracle-swap only) · S2/S3 regression unbroken · container reproducible. **S4 PASS.**
