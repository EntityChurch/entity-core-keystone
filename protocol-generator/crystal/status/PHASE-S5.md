# Crystal — Phase S5 (Publish) summary

**Date:** 2026-07-12
**Version pin:** `0.1.0-pre` · spec-data **v0.8.0 (V8)** · codec corpus v0.8.0
**Outcome:** packaging complete; release-ready pending operator publish + the shared-file
finalization (matrix/landscape/STATUS) + the DCO commit.

## Release-readiness checklist

| Item | State |
|---|---|
| S1 profile | ✅ complete (no TBD); container built + verified |
| S2 codec | ✅ **71·0F** wire-conformance (71/71 byte-identical) + head-form + Ed25519 units |
| S3 peer | ✅ smoke green (handshake → 404 → request_id demux → teardown) |
| S4 conformance | ✅ **292·0F @ cc1970f** (`--profile core`); §9.5 53/53 floor; genuine multisig accept |
| S4 robustness | ✅ **20/20 crash-free** repeated `--profile core` runs (graceful-shutdown fix) |
| README / CHANGELOG / LICENSE | ✅ authored (Apache-2.0) |
| Package metadata | ✅ `shard.yml` + `shard.lock` (zero runtime shard deps) |
| `.gitignore` | ✅ compiled `bin/*` + `lib/` + caches ignored (not committed) |
| Ambiguity log | ✅ A-CRY-001..011, all owner-tagged; none blocking; no arch escalation |
| CI config | deferred (cohort convention — run-s2.sh / run-s4.sh are the reproducible gates) |
| Registry publish / git tag | **deferred to operator** (`0.1.0-pre`) |

## The S4 hardening (durable lesson)

The one genuine defect found across S3/S4 beyond the shared NUL-byte path check (A-CRY-009):
an intermittent `Thread#execution_context cannot be nil` crash under the harness's kill-based
reap, on Crystal 1.20's preview Execution-Contexts scheduler. Fixed with a graceful
`SIGTERM`/`SIGINT` handler (close listener → clean exit) + a graceful `run-s4.sh` reap;
verified 0/20. Recorded as A-CRY-011 and surfaced to the durable-lessons digest: a
fiber-scheduler peer on a preview scheduler needs a graceful signal handler or it flakes under
a kill-based harness.

## Honest framing (ADR-0012)

Corroboration / generator-robustness peer (the Ruby-overfit check). Green is
**cohort-consistent, not independent convergence**. No spec finding surfaced (well is dry);
the net-new code was the NUL-byte path check (a shared cohort validation refinement) and the
graceful-shutdown hardening (a runtime lesson).

## Operator handoff (shared-file finalization — NOT done by this phase)

The following repo-root/shared files are the operator's to finalize in one pass alongside the
Odin peer (kept out of the peer dir to avoid concurrent edits + merge churn with the Julia/Nim
branch):
- `CONFORMANCE-MATRIX.md` — Crystal row (added) + footnote for the graceful-shutdown note.
- `research/LANDSCAPE.md` — Crystal tier: not-started → built (S1→S5).
- `docs/status/STATUS.md` — cohort +Crystal +Odin.
- DCO-signed commit on `dev` (operator; check before push/merge).
