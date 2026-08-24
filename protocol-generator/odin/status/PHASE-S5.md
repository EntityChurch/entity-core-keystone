# Odin — Phase S5 (Publish / packaging) summary

**Date:** 2026-07-12
**Spec-data:** v0.8.0 (V8), the pinned snapshot
**Package version:** `0.1.0-pre`
**Outcome:** packaging artifacts authored (README, CHANGELOG, LICENSE, Makefile with a
`make dist` source-tarball target, peer-local `.gitignore`). **No code touched, no
conformance re-run** — this is packaging polish over the S4-GREEN peer. Registry-publish
deferred (the cohort convention); operator finalizes the shared-file updates + the commit.

## Version pin (confirmed)

| Field | Value |
|---|---|
| Package version | **0.1.0-pre** |
| Spec-data | **v0.8.0 (V8)** — core wire byte-unchanged across V7→V8 |
| Codec corpus | v0.8.0 (`conformance-vectors-v1`, 71 vectors) |
| Oracle pin | `entity-core-go @cc1970f` (core-gate fingerprint `8261a033…`) |

Odin has no package manager and no version-grammar field — the `0.1.0-pre` marker lives in
README.md + CHANGELOG.md only (there is nothing analogous to a `Cargo.toml` version to carry
it); `make dist` stamps the tarball name from `VERSION` (default `0.1.0-pre`).

## Files produced (this phase, peer-local only)

| File | Purpose |
|---|---|
| `README.md` | What the peer is; the idiom points; build/test/run; conformance badge; honest ADR-0012 framing; Ed448-deferred + container notes |
| `CHANGELOG.md` | `0.1.0-pre` entry — tracks v0.8.0 (V8); codec 71/71, validate-peer 292·0F @ cc1970f; native crypto; Ed448 deferred; pre-release |
| `LICENSE` | Apache-2.0 full text (copied verbatim from the Forth peer) |
| `Makefile` | `make build`/`test`/`check`/`clean` container wrappers (profile dev_loop) + `make dist` source-tarball target (no compiled binaries) |
| `.gitignore` | Ignores the compiled build outputs: `bin/entity-core-peer`, `bin/smoke`, `*.o`, `dist/` |
| `status/PHASE-S5.md` | this file |

No `src/`, `host/`, `smoke/`, `test/`, or shared/repo-root file was modified.

## Release-readiness checklist

| Item | State |
|---|---|
| **S1 (profile)** — profile authored, container built + verified, ambiguity log clean | ✅ GREEN (`PHASE-S1.md`) |
| **S2 (codec)** — hand-rolled canonical CBOR + native crypto, **71·0F** wire-conformance, u64 head-form + Ed25519 KATs, leak-clean | ✅ GREEN (`PHASE-S2.md`, `CONFORMANCE-REPORT-S2.md`) |
| **S3 (peer machinery)** — full L1–L4 peer on raw-thread + manual-mutex; two-peer loopback smoke **7·0F**, leak-clean | ✅ GREEN (`PHASE-S3.md`) |
| **S4 (conformance)** — `validate-peer --profile core` **292·0F @ cc1970f**, verified; multisig accept-path unit | ✅ GREEN (`PHASE-S4.md`, `CONFORMANCE-REPORT.md`) |
| **§9.5 type floor** — 53/53 byte-identical to the Go vector set (render-from-model) | ✅ unit-proven |
| **Ambiguity log** — A-ODIN-001..011, none blocking, all owner-tagged | ✅ operator/research-owned; no arch escalation outstanding |
| **Packaging** — README / CHANGELOG / LICENSE / Makefile `dist` / `.gitignore` | ✅ this phase |
| **Compiled binaries gitignored** — `bin/entity-core-peer`, `bin/smoke` not staged | ✅ ignored (peer-local `.gitignore` + repo-root `**/bin/`) |
| **Registry publish** | ⏸ DEFERRED — `0.1.0-pre`, pending arch v0.1 sign-off + a first external Odin consumer (cohort convention) |
| **Git tag / release** | ⏸ operator step — `/entity-rosetta` never tags/publishes |

## Ambiguity-log ownership (A-ODIN-001..011)

All eleven items are **resolved at their stage or research-owned** — none are open spec
findings, none require arch escalation. Owner tags: A-ODIN-001/002/003/004/005/006/008/009/010
= **operator** (local / language-runtime decisions); A-ODIN-007/011 = **spec-derived** (§4.7,
§7a — logged for the phase boundary, no ambiguity). Consistent with the corroboration framing:
on the saturated wire surface an Odin peer surfaces no fresh spec-precision issue.

## Honest framing (ADR-0012)

**292·0F is cohort-consistent, not independent convergence.** The `validate-peer` oracle and
the type-registry vectors are the Go author's artifacts; one peer passing one author's vectors
is generator robustness on a fresh no-exceptions / no-GC / no-package-manager shape plus a
native pure-Odin crypto re-derivation — not a second independent witness to the protocol bytes.
The value is the generator's packaging path exercised on a decentralized-by-absence ecosystem
(no registry → git-vendored → tarball) and the native-crypto corroboration, not a spec finding.

## Operator handoff (shared-file finalization — NOT done here)

This phase deliberately touched **only** peer-local files. The operator finalizes the
shared/repo-root surface and commits:

1. **`CONFORMANCE-MATRIX.md`** (repo root) — add/confirm the Odin row: `0.1.0-pre`,
   `validate-peer --profile core = 292·0F @ cc1970f`, tier T3 corroboration, native pure-Odin
   crypto, Ed448 deferred, the ADR-0012 cohort-consistent caveat + the unaudited-crypto note.
2. **`research/LANDSCAPE.md`** — reconcile the peer index / tier roster (A-ODIN-005: the
   `peer-NN` index reconciles at merge with the Julia/Nim branch — descriptive tier only until
   then).
3. **`STATUS.md` / `research/stewardship/`** — the dated session note for this build.
4. **Commit** (DCO-signed, `git commit -s`, accountable human) — the peer tree is untracked;
   stage the sources + status + packaging, confirm the compiled binaries stay ignored.
5. **Tag / registry** — deferred: `/entity-rosetta` never tags or publishes; promotion off
   `0.1.0-pre` is a later review-gated operator step.
