# entity-core-protocol-c — Phase S4 (Conformance) Summary

**Peer #10** (C / C11 / POSIX — procedural / manual-memory /
return-code idiom) · **Outcome: 🟢 `validate-peer --profile core` PASS — 0 FAIL,
machine-verified (`summary.failed == 0`) @ the TRUE v7.75 cohort baseline `b30a589`
(576·0F·89S, `resource_bounds` 2P+1W active) — also 0 FAIL @ the `62044c5` subset (574) and
the `7e5ab04` superset (631).**

## Re-certification against the TRUE cohort baseline `b30a589`

This phase is **certified against `b30a589`** — the actual v7.75 cohort oracle. The 9-peer
cohort scorecard is recorded as "oracle `62044c5`, 576·0F·89S with `resource_bounds` PASS",
but that label is **off-by-one-commit**: `62044c5`'s
`cmd/internal/validate/profile.go` `coreProfileCategories` has `catConcurrency: true` but
**NOT** `catResourceBounds`, so `resource_bounds` SKIPs under `--profile core` there (→ 574,
which is exactly what this peer scored). The **next commit `b30a589`** ("v7.75: pair §9.0
drift gate post-arch-fold; resource_bounds enumerated") adds `catResourceBounds: true` →
`resource_bounds` becomes ACTIVE in core → **576·0F·89S**, the real cohort number. So
`b30a589` is the commit that yields the recorded cohort figure; the scorecard's "62044c5" is
a provenance mislabel. See **A-C-008** and SPEC-AMBIGUITY-LOG for the full correction.

This was an **oracle swap only** — the C peer was NOT rebuilt or modified: the
`7e5ab04`-built peer host `entity-peer-c` (binary timestamp unchanged) and its Peer ID
`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` are identical; only the Go oracle ELF was
swapped (62044c5 → `b30a589`) and the gate re-run with `NOBUILD=1`.

## The gate (HEADLINE — @ `b30a589`)

```
576 total · 291 passed · 196 warned · 0 FAILED · 89 skipped → Result: PASS
```

Command: `./protocol-generator/c/run-s4.sh` (= `validate-peer -addr 127.0.0.1:7777
-profile core -json-out status/CONFORMANCE-REPORT.json`), run with `NOBUILD=1` (peer not
rebuilt). Machine-verified: `status/CONFORMANCE-REPORT.json` → `summary.failed == 0`. Run
sealed-offline (`--network=none`) in the `c-toolchain` container; the Go `validate-peer` ELF
+ the C host share one loopback on port 7777.

**Live count confirmed (NOT assumed): 576 total · 0 FAIL · 89 skip** — matching the recorded
cohort figure exactly. The decisive difference vs `62044c5`: `resource_bounds` is now an
**ACTIVE** category (0 skip in-category), scoring **r1 `413 payload_too_large` PASS · r2
`400 chain_depth_exceeded` PASS · r3 connection-flood WARN** (the §4.10(c) external-admission
SHOULD carve-out). `concurrency` **5/5** PASS; §10.1 register gate **8/8** PASS; §9.5
53-type floor 53/53.

## Conformance-safety — 0 FAIL at the subset, the cohort baseline, AND the superset

The same unchanged peer is **0 FAIL at ALL THREE** check inventories: the **574** subset
(`62044c5`, resource_bounds-not-yet-in-core), the **576** TRUE cohort baseline (`b30a589`,
resource_bounds active), and the **631** superset (`7e5ab04`). `b30a589` sits check-wise
between the 574 subset and the 631 superset (it adds exactly the resource_bounds 2P+1W rows
on top of 574-style inventory), so a peer that is 0-FAIL at both bounds is necessarily
0-FAIL at `b30a589` — which the live run confirms. Per the Java-peer precedent, 0-FAIL across
subset and superset means no conformance category is dodged → **conformance-safe**.

### Additional evidence — `62044c5` subset run (resource_bounds not yet in core)

```
574 total · 289 passed · 195 warned · 0 FAILED · 90 skipped → Result: PASS
```

Same unchanged peer, `62044c5` oracle (retained as `output/s4-oracles/*.62044c5`).
`resource_bounds` carried as a single SKIP placeholder here (the category is not in
`coreProfileCategories` at `62044c5`) — the 2-total/1-skip delta vs 576/89 is purely the
oracle's resource_bounds row count, not any C-peer behavior.

### Additional evidence — `7e5ab04` superset run

```
631 total · 291 passed · 248 warned · 0 FAILED · 92 skipped → Result: PASS
```

Peer ID identical (`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`, byte-identical to the
Java/CL cohort from seed `0x11` — §1.5 canonical form). New v7.75 categories GREEN at the
superset: `resource_bounds` (r1 `413 payload_too_large` / r2 `400 chain_depth_exceeded` / r3
connection-flood WARN) and `concurrency` 5/5.

## Oracle provenance — certification oracle vendored from the TRUE cohort baseline `b30a589`

`output/s4-oracles/{validate-peer,entity-peer}` (the **certification oracle**), built
`CGO_ENABLED=0 / GOWORK=off` from a **read-only `git archive` extract** of the READ-ONLY
`entity-core-go` source at commit **`b30a589`** ("v7.75: pair §9.0 drift gate
post-arch-fold; resource_bounds enumerated") — the commit that folds `catResourceBounds: true`
into `coreProfileCategories` and yields the recorded cohort 576·0F·89S. The oracle tree was
**never** checked-out / stashed / cleaned (the confinement rule honored — `git archive |
tar -x` is read-only; `entity-core-go` HEAD untouched). Verified at the binary's live behavior
that `resource_bounds` is now an ACTIVE category under `--profile core` (2 PASS + 1 WARN, 0
SKIP) rather than a SKIP — the decisive `catResourceBounds: true` behavior. The earlier oracle
binaries are retained alongside as `output/s4-oracles/{validate-peer,entity-peer}.62044c5`
(574 subset) and `*.7e5ab04` (631 superset). See A-C-008 — the provenance correction
(cohort "62044c5" label is off-by-one; `b30a589` is the real oracle).

## Plus origination-core 3/3 (`run-origination-core.sh`)

```
[origination]  PASS reference_connect · PASS reference_ready · PASS dispatch_outbound_reentry
Result: PASS (3 total, 3 passed, 0 failed)
```

Re-run at the cohort baseline against the **`b30a589`** Go `entity-peer -open-access`
reference (identical 3/3 to the earlier `62044c5`/`7e5ab04`-reference runs). The §6.11 reentry seam
wire-proven over real two-peer TCP: the C target originates an outbound EXECUTE back to the
validator-as-B over the SAME inbound connection. dispatch-outbound is a **generic relay** —
forwards the `{value: X}` echo params verbatim and returns the downstream result entity
verbatim (per the concurrency-gate 7b matrix ruling #2).

## Plus the §9.5 53-type floor byte-identical: 53/53

Rendered from the in-code override table `src/core_typedefs.c` (GENERATED by
`tools/gen-typedefs.py` from the shared cross-impl `type-registry-shapes.json` — mirrors the
Java/OCaml/CL generators exactly); each content_hash computed by THIS peer's own S2-green
codec. Diffed **53/53 byte-identical** against `type-registry-vectors-v1` by the
`typereg-bin` harness (peer-side dual of the S2 corpus) AND independently confirmed by the
live oracle's `type_system` checks (108 PASS / 0 FAIL).

## What S4 built (the S3 deferrals + the live-gate fixes)

| Deliverable | File |
|---|---|
| §9.5 53-type registry render-from-model | `src/core_typedefs.{c,h}` (generated by `tools/gen-typedefs.py`) + `publish_core_types` in `dispatch.c` (bound at `/{peer}/system/type/{name}`) |
| real `system/type:validate` body (replaces the S3 absence) | `dispatch.c` `h_type` — required-field + unevaluated-field structural validation → `system/type/validate-result` |
| dispatch-outbound §7a reentry body (replaces the S3 `503` stub) | `dispatch.c` `h_validate_dispatch_outbound` + `outbound_dispatch` + `ec_io_outbound` (new public transport primitive over `conn->io`) |
| type-registry byte-diff harness | `test/typereg.c` (`make typereg`) — **53/53 byte-identical** |
| the `--profile core` conformance harness | `run-s4.sh` (container-bound, `--network=none`, `--validate` on) |
| the §6.11 reentry probe harness | `run-origination-core.sh` (target + Go reference, shared loopback) |
| oracle build from the TRUE go cohort baseline `b30a589` (certification oracle, resource_bounds active) | `output/s4-oracles/{validate-peer,entity-peer}` (gitignored; built from a read-only git-archive extract); `62044c5` retained as `*.62044c5` (574 subset) and `7e5ab04` as `*.7e5ab04` (631 superset) |

## The grind: 31 → 0 FAIL (iteration count: 3 oracle runs)

**Run 1 (S3 peer + new type-registry/dispatch-outbound):** 631 · 261P / 247W / **31 FAIL** /
92S — but **22 of the 31 were one crash cascade**, not independent bugs:

- **The crash (A-C-009):** under the `concurrency` category's sustained C×K load the peer
  **segfaulted** — ASan pinpointed `heap-use-after-free in ec_entity_ref`. Root cause: the
  `ec_entity` refcount was a plain `int`, raced across the per-EXECUTE dispatch threads (one
  thread per inbound EXECUTE, §4.8) on the SHARED store/identity entities → lost decrement →
  premature free. Once the host died, every later category that re-dialed got "connection
  refused / broken pipe" — the 22-FAIL cascade (universal_address_space, peer_canonicalization,
  format_agility, negotiation, authz, resource_bounds, …). **Fix:** `refcount → atomic_int`
  (relaxed add / acq-rel sub). This is the C peer's net-new §4.8 datapoint: a no-GC
  manual-memory peer is the one that surfaces the shared-refcount race (the GC'd cohort never
  hits it). The S3 two-peer smoke (one connection's 8-way demux) never exercised C×K
  independent connections, so it passed green with the latent race.

**Run 2 (atomic refcount):** 631 · 282P / 248W / **9 FAIL** / 92S — the cascade gone; 9
genuine independent peer bugs remain, each fixed spec-first (no oracle/vector/harness
doctoring):

1. **connectivity/handshake_replay_cross_connection (A-C-010, F12):** the challenge nonce was
   clock-derived (`ec_now_ms()`), so two connections in the same millisecond got the same
   nonce → a captured authenticate replayed. Fix: CSPRNG nonce (`ec_random_bytes` →
   libsodium `randombytes_buf`).
2. **handlers/*_operations_match ×3 (A-C-011):** the interface entities carried an EMPTY
   `operations` map. Fix: populate per handler (tree→get/put, connect→hello/authenticate,
   capability→request/revoke/configure/delegate, type→validate).
3. **tree_operations/path_reject_empty_segment + core_tree_path_flex_1 (A-C-011):** `strtok_r`
   collapses `//` (empty segment never caught) + the embedded-NUL check was a C-string no-op.
   Fix: detect literal `//` pre-tokenize + pass the value-node byte length to catch
   embedded-NUL targets → 400 invalid_path.
4. **capability/delegate_remote_caller_returns_501 (A-C-011):** delegate validated `parent`
   before the same-peer check → remote caller got 400 not 501. Fix: §2.6-F1 same-peer check
   moves FIRST.
5. **negotiation/format_disjoint_reject + keytype_disjoint_reject (A-C-011):** the hello never
   inspected the advertised accept-set. Fix: reject a disjoint non-empty advertisement → 400
   incompatible_hash_format / unsupported_key_type.

**Run 3 (all fixes):** 631 · **291P / 248W / 0 FAIL / 92S → PASS.**

## Regression — unbroken (sanitized: ASan/LSan/UBSan)

- **S3 two-peer loopback smoke: 11/11 GREEN** (`make smoke`, re-run after the
  atomic-refcount + type-registry + dispatch-outbound + handshake/path changes) — ASan-clean.
- **S2 codec corpus: 69/69** + the Ed25519/SHAKE256/Base58 selftests (`make test` → 82/82) —
  the codec layer is untouched and clean.
- **New type-registry harness: 53/53 byte-identical** (`make typereg`) — ASan-clean.
- `make` compiles every source `-std=c11 -pedantic -Wall -Wextra -Werror` with **zero
  warnings** (the hardened host + the sanitized test bins).

## Standards honored

- **S1 (sealed-offline):** all in-container, `--network=none`; the READ-ONLY go oracle source
  was extracted via `git archive | tar` (never checked-out/stashed/cleaned — the dirty-tree
  rule honored). `--debug-open-grants` is the cohort's explicit non-conformant debug seed
  (grant-gated categories); `--validate` makes the §7a handlers + dispatch-outbound live (off
  by default).
- **S5/S7 (no doctoring):** raw oracle verdict; the 248 warns are oracle-marked non-§9.5-floor
  type vocabulary (matched-if-present, not hidden); the 92 skips are §9.0 extension carve-outs
  the oracle auto-allowlists. **No FAIL disguised as SKIP; no oracle / vector / harness edit.**
  Every one of the 31→0 fixes was derived spec-first from V7 + the cohort.
- **S8 (convergence):** the procedural / manual-memory / return-code C idiom reaches the same
  0-FAIL fixed-point as the GC'd cohort — and contributes a genuinely new §4.8 datapoint
  (A-C-009: the shared-refcount race only a no-GC peer surfaces).

## Carried findings → arch (via stewardship)

- **A-C-009 (NEW ⚑ ARCH-BOUND)** — shared-entity refcounts MUST be atomic (or lock-guarded)
  on a multi-threaded peer; a plain-int refcount passes the single-connection smoke then
  use-after-frees under the live `concurrency` C×K load. The no-GC manual-memory peer is the
  one that surfaces it. Sibling to A-JAVA-010 ("passes smoke green, breaks under the live
  gate" latent peer bugs).
- **A-C-010 (NEW)** — clock-derived handshake nonce → cross-connection replay (F12); use a
  CSPRNG. Peer bug, spec clear; recorded as the F12 surface.
- **A-C-011 (NEW)** — the five live-gate fixes (negotiation disjoint-reject, handler
  operations-match, §1.4 path validation, delegate-501 ordering). Peer bugs; spec/closeout
  clear.
- **A-C-008 (CLOSED — provenance correction ⚑ worth surfacing to mainline/arch)** — the
  9-peer cohort scorecard records its v7.75 oracle as **`62044c5`** (576·0F·89S,
  resource_bounds PASS), but that is **off-by-one-commit**: `62044c5`'s
  `cmd/internal/validate/profile.go` `coreProfileCategories` has `catConcurrency: true` but
  **NOT** `catResourceBounds`, so `resource_bounds` SKIPs under `--profile core` there (→ 574).
  The next commit **`b30a589`** ("v7.75: ... resource_bounds enumerated") adds
  `catResourceBounds: true`, making resource_bounds ACTIVE → **576·0F·89S** — the actual
  recorded cohort number. So `b30a589` is the true v7.75 oracle; the scorecard's "62044c5"
  label should be corrected. This C peer is now certified at `b30a589` (576·0F·89S,
  resource_bounds 2P+1W active); oracle vendored from a read-only `git archive` extract,
  resource_bounds-active behavior verified live.
- **A-C-001 (OPEN, re-stated)** — Ed448/SHA-384 agility native gap (libsodium has no Ed448);
  the Ed25519 + SHA-256 §9.1 floor is complete + native. The oracle's `crypto_agility`
  category PASSES (4/4) at the floor; the deeper Ed448 sign/verify is extension.

## Not in scope (unchanged)

The extension surface (auto-skipped under §9.0) · the deeper EXTENSION-TYPE v1.1 constraint
analysis beyond the structural type-validate floor (`byte_size`, `union_of` membership,
nested recursion) · `.so`/pkg-config packaging polish + the cross-peer architecture review
(S5).

## Exit criteria

`validate-peer --profile core` PASS (576 · 0 FAIL, `summary.failed == 0`) @ the TRUE cohort
baseline `b30a589` (resource_bounds 2P+1W active), also 0 FAIL @ `62044c5`/574 and
`7e5ab04`/631 · §10.1 register gate 8/8 · resource_bounds r1/r2 PASS + r3 WARN ·
origination-core 3/3 incl. `dispatch_outbound_reentry` · §9.5 53-type floor
byte-identical (53/53) · oracle built from the cohort baseline `b30a589` with the §7a wire-gate ·
S3 smoke + S2 corpus + typereg regression unbroken (ASan/LSan/UBSan-clean) · `-Werror` clean ·
conformance report + JSON finalized · ambiguity log updated (A-C-009/010/011 new, A-C-008
closed) · container reproducible. **S4 PASS.**
