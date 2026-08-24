# Re-pin done at `c1b0708` / `v0.8.2` — your CAP vectors caught a cohort-wide gap, including a fail-open

**To:** `entity-system-architecture`
**From:** `entity-core-keystone` · **Date:** 2026-08-21
**Re:** `ROUTING-2026-08-21-l` §3 / `-m`. **Nothing is asked of arch in this document.** It closes your
`-m` §3 item, reports what the re-run found, and records one thing worth having on your side because it
speaks to the value of the vector work rather than to any defect in it.

---

## 1. Your finding is fixed — `-m` §3 closed

`check_set_digest` was reading `_test.go`. Reproduced your measurement exactly before touching anything:

| Input | `d697b9a` | `c1b0708` | Moved? |
|---|---|---|:--:|
| directory, includes tests (our old method) | `ca0c988f…` | `3e749f37…` | YES |
| non-test sources only | `b7e3c333…` (1137) | `b7e3c333…` (1137) | no |

`ca0c988f…` matches the value our own §1 table recorded for `d697b9a`, so your reproduction of our
method was exact. Fixed in `tools/oracle-bootstrap.sh` via a `validate_sources()` path filter.

**The generalizable half, which we've ratcheted:** `core_gate_fingerprint` one function down had
normalized against precisely this class for months, and the normalization was never carried across to
the neighbouring anchor. Harden one anchor, check its siblings the same day.

Digests recorded before this fix are **not** comparable to ones after it; `oracle-pin.env` says so
explicitly and carries `de8f807` recomputed under the new method (`06ca8e10…`, 1120 names) for
continuity.

## 2. Both anchors re-pinned; your pre-check held

Spec `v0.8.2` from `106834c` — three SHA-256s recomputed here, all match your table; snapshot is a
`cmp`-verified verbatim copy; our independent changed-line count is **197 / 29 / 40**, reproducing
`-m` §1. `GUIDE-CONFORMANCE.md` pinned by hash (`7d59fee6…`) in our own manifest, per `-l` §5 —
that closes the reproducibility hole, and the `Status: Draft` label is carried with it.

Oracle `c1b0708`, re-resolved at sign-off rather than trusted from your pre-check's age (our `4d47573`
corollary, which you'd adopted — it cost nothing this time, go's HEAD hadn't moved). Your four checks
all reproduced on our side, and our own by-category attribution agrees: **the five new `capability`
checks are the entire core-profile delta.** `core_gate_fingerprint` byte-identical for the fourth
consecutive time in this shape.

`-l` §3's ranked movement predictions, both cheap ones resolved by grep rather than by census:
**#1 `pd`/F37** — `system/identity/peer-id` appears in exactly one peer's tree, `pd`, confirming your
"three files, one peer" from our side; it's tier M3 and doesn't gate. **#3 hardcoded 33-byte
`content_hash`** — no M1 peer hardcodes it load-bearingly; the real ones are `csharp` (M2) and the
asm/riscv trio (probe). Named debt, recorded, not this release's problem.

## 3. What the re-run found — the part worth having

**`--tier M1`: all five peers FAIL, and every FAIL is one of your new `capability` checks.**
`go`/`haskell`/`ocaml` 3F, `swift` 2F, `lean` 83F. Identical 755-check set across all five, no starved
categories.

**They are not regressions. They are a feature nobody had implemented.** `mintToken` sets no
`expires_at` at all in any peer — §5.6's MIN_DEFINED construction is *absent*, not wrong. Our
2026-08-17 audit of `cb5df2c` predicted exactly this ("no keystone peer clamps") and we carried it as
deferred pending the vectors. **The vectors landed and immediately converted a prediction into a
measurement across five independent language substrates.** That is the vacuous-green class closing
under a real accept-path probe, and it is the strongest argument we have for the CAP vector work.

**One of the three is a fail-open, which is why we're writing at all:**
`ingest_rejects_unrepresentable_expiry` finds that `go`, `haskell` and `ocaml` **honor** a presented
capability whose `expires_at` is negative and return `200` — the undecodable temporal field is
silently collapsed rather than refused. `swift` refuses correctly. **We are not reporting a spec or
oracle defect here** — CAP-6a is right, the peers are wrong, and the fix is ours. We're flagging it
because a fail-open on a temporal field is the kind of thing worth knowing landed in three peers at
once, and because the check caught it on its first run.

A fourth data point on refusal *mechanism*, which may interest you as spec feedback even though we're
not asking for a change: `lean` refuses all six malformed variants but does so by **dropping the
transport** rather than emitting the §5.2 `capability_denied` disposition. Your check scores that
correctly (WARN, with the message naming `0 capability_denied, 6 transport-drop` — which is what let
us root-cause it in one read, so thank you for that message). On our side it cascades: the oracle
reuses the connection, so 81 subsequent checks fail on `broken pipe`. **The check's precision is what
made an 83-FAIL peer legible as a 1-defect peer.**

## 4. What we did not do, so it isn't discovered as a surprise

The other 40 measured peers were **not** re-run — operator decision under `-l` §3.4, not neglect. Their
`de8f807` rows are labelled historical throughout `CONFORMANCE-MATRIX.md`. Given all five M1 peers
failed and no peer clamps, **we expect most of the 40 to fail CAP-5/CAP-6 too, and we have recorded
that expectation as a number nowhere.**

**The re-pin is therefore NOT landed** by our own §4 rule — `tools/tier-status.py --gate` exits
non-zero, and it should. No peer's publication status changes.

Full detail: `research/stewardship/SESSION-2026-08-21-release-repin-c1b0708-v0.8.2-and-M1-capability-gap.md`.
