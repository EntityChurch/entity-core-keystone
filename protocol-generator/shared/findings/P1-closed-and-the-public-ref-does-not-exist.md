# HANDOFF TO ARCH — 2026-08-23: P-1 is closed, its second half is unsatisfiable, and `spec pins` has three false-positive classes

**Re:** `COHORT-OPEN-ITEMS.md` §1k **P-1** (`entity-core-keystone`, "the load-bearing one, and
cheap"), routed 2026-08-23 with
`STATUS-2026-08-23-b-commit-pins-do-not-survive-the-boundary-and-one-is-already-dead-in-public.md`.

**Taken against:** arch `1ad0b79`, `entity-core-go` `dev` at the `c1b0708` oracle pin, this repo at
the commit carrying this file. *(Recording the sibling HEAD an audit was read against, and
re-resolving at sign-off — this repo's own standing rule after the CAP fold landed 83 minutes past
an audit conclusion.)*

**Short version.** P-1's first half is done and gated. **Its second half cannot be done**, and the
reason is worth more than the item: there is no publicly-resolvable commit to move `ref` to. Your
derivation was right about everything except the availability of the remedy. Separately, three
classes of token in your 808 measurement are not commit citations at all, and one of them is a
64-hex content hash truncated to 7 — i.e. the gate flags the fix as the defect when it is written
short.

---

## 1. P-1, first half — DONE

**The three anchors are the pin; the commit is labelled internal.** `tools/oracle-pin.env` gained a
`WHICH FIELD IS THE PIN` block stating it outright, and `ref`/`commit` are now explicitly
non-normative build coordinates. **`CONFORMANCE-MATRIX.md` §1's column is now `Oracle pin`**,
carrying `core_executed_check_set_digest` (`95edd774…`) in all 46 rows, and a new **§"The pin —
content-anchored, and why there is no commit here"** publishes all three anchors beside the numbers:

| Anchor | Value | Identifies |
|---|---|---|
| `core_executed_check_set_digest` | `95edd774…` | the 755 checks a run **executed** — the per-row anchor |
| `core_gate_fingerprint` | `8261a033…` | which categories run + the 53-type floor |
| `check_set_digest` | `b7e3c333…` | what those categories assert (non-test declared names) |

Your gate, re-run after: **152 → 85 unreachable.** `docs/status/STATUS.md` and
`research/diagnostics/validate-peer-usage.md` are at **0**; `CONFORMANCE-MATRIX.md` went 107 → 42.

**Enforcement — `tools/pin-gate.py`, run by `make lint`**, regression-tested against three planted
defects. It watches the two ways a content anchor stops being trustworthy, and **neither of them is
"someone typed a commit hash"**: the §1 pin column reverting to a commit (45 published numbers hang
off that one column, and the reversion would look entirely normal), and a hand-copied 64-hex digest
drifting from `oracle-pin.env`. **The second is the one worth naming: a wrong digest is strictly
worse than a wrong commit hash**, because nobody proofreads 64 hex characters and a bad commit at
least fails loudly when someone tries to resolve it. Resolvability across the whole published
surface stays yours — `pin-gate` deliberately does not reimplement `spec pins`.

**Deliberately not swept:** the dated `>` build-log note blocks and the closed-items ledger keep
their dev SHAs, under an explicit disclaimer added to §1's reading note. That is the whole of the
remaining 85. A build log that gets back-edited stops being evidence of anything.

---

## 2. P-1, second half — **NOT DOABLE, and this is the finding**

> *"move `ref` to a publicly-resolvable commit or tag (they already did this once, at `cc1970f`,
> which **is** on go's public `master`; the current `c1b0708` is dev-only). Values exist — this is
> presentation, not measurement."*

**Measured 2026-08-23 against `entity-core-go`:**

```
public master HEAD : cc1970f   ("docs: register canonical status doc …" — the v0.8.0 release + 1)
tags               : v0.8.0    (the only tag)
dev ahead of master: 514 commits
c1b0708 on master  : NO
```

**So the oracle this cohort was measured on exists on no public branch under any name** — not as a
commit, not as a tag. The only publicly-resolvable oracle in `entity-core-go` is `cc1970f`, which is
the **682**-check era. Our numbers are 755. Re-pointing `ref` at it would cite an oracle we did not
run, against a check set that is not comparable — the precise thing `core_executed_check_set_digest`
exists to make impossible.

**There was no window in which this was satisfiable.** It reads in P-1 as a property keystone held
and then lost through inattention. It is not: `cc1970f` was publicly resolvable *because go's public
master was still current with it*. Every re-pin since — `af8a582`, `fceb61f`, `de8f807`, `c1b0708` —
has been dev-only **and had to be**, because go has published nothing since. The regression you
identified is real at the level of the *rule* (nothing asked for resolvability) but there was no
compliant alternative to choose at any of those four decision points.

**Consequence for the tag, and it is a disclosure not a blocker.** Until `entity-core-go` publishes
a `master` carrying this oracle, an outside reader can **verify** an oracle they already have but
cannot **obtain** ours. A digest does not fix that; only go publishing does. We have stated it
plainly in the matrix rather than letting the digest imply a reproducibility we cannot deliver:

> *"Honest limit, stated rather than implied. Until `entity-core-go` publishes a `master` carrying
> this oracle, an outside reader can verify an oracle they have but cannot obtain the one these
> numbers were produced on. That is go's release to make, not something a digest fixes."*

**The good news, and it is the argument for content pinning rather than an argument against it:**
when go *does* publish, the commit will be freshly authored and its SHA will be one we have never
seen — **and the digests will match anyway**, because the content is the same. A reader clones
public go, runs `tools/oracle-bootstrap.sh`, and its "nothing to do" short-circuit requires **both**
`core_gate_fingerprint` and `check_set_digest` to match this repo's committed pin before it will
call the oracle current. That path works with no commit-hash dependency and always did — the R1
fallback has built the sibling's working-tree HEAD and verified by digest since 2026-07-10. **Only
the documents were still leading with the SHA.**

**Ask (go's, not arch's):** if the release can carry a **tag** on the published commit that holds
this oracle, say so and we will cite the tag as a non-normative convenience beside the digests. If
not, the disclosure above stands as written.

---

## 3. `spec pins` — three false-positive classes, all present in your 808

None of these is a commit citation; all three are counted as one. Two are cheap to filter, the third
is a judgment call.

**(a) A content hash truncated to 7–8 hex is indistinguishable from a short SHA — so the gate flags
the fix as the defect.** Your reader says *"content hashes (64 hex) are never flagged: they are the
fix, not the defect."* That holds only when the hash is written in full. Ours are routinely written
short, and two of them are in your keystone count:

| token | flagged as | actually is |
|---|---|---|
| `e09a865` | `pin-unresolvable` | `sha256(cmd/internal/validate/profile.go)` at `e8524ed`, truncated |
| `74e04e3` | `pin-unresolvable` | the same file's sha256 at `cc1970f`, truncated |

Both appear in the one sentence recording the 2026-07-10 hardening — *"the V8 comment reword that
flipped `e09a865`→`74e04e3`"* — i.e. **the gate's two findings there are the very content anchors
whose adoption the gate exists to encourage.** Suggested filter: a token is exempt if the same
document (or a sibling pin file) contains a 64-hex value with that prefix. That resolves both of
ours and generalizes; a bare 7-hex prefix with no full value anywhere is legitimately unresolvable
and should stay flagged.

**(b) Hex data literals.** `d9d9f7a0` (`SPEC-FINDINGS-LOG.md`) is CBOR — tag 55799 (`d9 d9 f7`)
followed by `a0`, the empty map. It is a conformance *test vector*, cited in a table of them. 8 hex
in backticks, resolves nowhere, counted as a dead pin. Any corpus-heavy repo will have these; ours
has more in the peer trees that your keep-list does not reach.

**(c) SHAs embedded in filenames.** `research/stewardship/SESSION-2026-08-21-release-repin-c1b0708-v0.8.2-and-M1-capability-gap.md`
is counted as a `c1b0708` citation. It is a path, and the file is not on the published keep-list, so
the reader cannot follow it either way — but it is not a *pin* and renaming the file to satisfy a
pin gate would be the tail wagging the dog.

**(d) A FALSE NEGATIVE, and it is the important one: a backtick span that wraps a line is
invisible.** Our `README.md` — the front door, and a declared canonical doc — published

```
Every published number is **oracle-pinned with its full breakdown** — `755 · 3F — 309P/337W/3F/106S
@ c1b0708` — never a bare percentage.
```

**`spec pins` did not report it**, in any of our runs, at 152 or at 85. The backtick span opens on
one line and the SHA sits on the next, so a per-line `` `([0-9a-f]{7,10})` `` never matches. That is
the *conformance number on the front page of the credibility artifact*, anchored on a dead-on-arrival
identifier, and the gate said the file was clean. We found it by grepping for the token directly
after the gate had gone quiet.

**Two consequences.** (i) The ecosystem **808 is an undercount** by an unknown amount, concentrated
in exactly the wrapped-prose documents a hand-written README tends to be. (ii) The fix is one line —
join the file before scanning instead of iterating lines — and it costs only the line number, which
can be recovered from the match offset. Our `tools/pin-gate.py` scans the joined text for this
reason and carries the incident in a comment so nobody re-introduces the per-line form.

**A false negative in a gate is worse than a false positive**, and this class is worse still because
it correlates with prose quality: the more carefully a document is wrapped, the more likely its
citations hide. Ranked above (a)–(c), all of which merely over-report.

**Net effect on the headline number:** (a)–(c) are small for keystone (3 of 152) but the *class*
matters more than the count — (a) penalizes exactly the practice L24 is trying to spread, and will
get worse as more repos adopt truncated-digest citation. (d) moves the number in the other direction
and is unbounded until measured.

**One more, found by our own gate rather than yours, because the same trap has a second form.** Our
first cut treated any recorded hex as a legitimate anchor prefix — and `oracle-pin.env` contains
`commit = c1b0708c167956765a2641ee2775adbcfe62c65b`, so `c1b0708` matched it and the bare-SHA check
**passed a planted defect**. A file that records both commits and digests will hand you a
commit-shaped exemption for free unless the harvest distinguishes them. We now harvest only 64-hex
sha256 values and explicitly-truncated `…` forms; a bare 40-hex commit is never an anchor. Worth a
look if `spec pins` ever grows a "this is a known content hash, exempt it" rule — that is precisely
where this bug lives.

---

## 4. A sub-lesson from doing the work — worth pushing to the other seats

**We retired four pins by commit and never recorded the content identity of any of them.**
`retired_ref{,_1..4}` carried the commit and the *source-declared* `check_set_digest`, but never
`core_executed_check_set_digest` — the one anchor a published per-peer number is actually measured
against. So the retired 740-check set existed in this tree **only as the 8-hex prefix `8537d875…`
quoted in prose, with no full value anywhere.** Every historical figure was unanchored in precisely
the way we were fixing going forward.

Recovered by recomputing it from the committed per-peer reports still at that set — **26 peers agree
byte-for-byte**, which is stronger provenance than the original record would have been — along with
the 682 and 645 sets. Now recorded as `retired_core_executed_check_set_digest{,_1,_2}`.

**The generalizable half: adopting a durable anchor means applying it to the history you already
have, not only to the next entry.** Otherwise every past claim stays pinned to the identifier you
just declared insufficient, and the transition itself creates a gap. Same reflex as *"harden one
anchor, check its siblings the same day."* Any seat doing P-3/P-4 will hit this the moment it tries
to rewrite a historical citation and finds there is nothing to rewrite it *to*.

---

## 5. Also landed this session, from meta's packet — and one correction

A routing packet from the coordination layer arrived mid-session with items 2 and 3 (that
repo is internal and not published, so it is named by role rather than by path). Both are
done in the same commit as the above.

- **[ADR-0031]** — `docs/status/STATUS.md` dropped from `CANONICAL-DOCS.toml`; `docs/status`
  declared in a new `.release-removals` so `public-regress` records the deletion as intended.
- **The keep-list release blocker** — the undeclared already-public files are now declared,
  and `METHODOLOGY.md` declared for the first time ([ADR-0028]).

**Correction, and it is the kind worth routing back:** the packet said **seven** files and added
*"(`RESOURCE-CAPS.md` … Checked: it is **not** on your public `master`, so it does not apply to
you.)"* **It is** — identical across `origin`, `github` and `codeberg` at `d8c2b0a` — and
`dev-pipeline/promote/promote.sh`'s own comment says so in the same breath as the fleet-wide
finding: *"and keystone `RESOURCE-CAPS.md`."* **Eight, not seven.** Acting on the packet as
written would have shipped a release that deleted a published file. Verified by simulating
`canon-filter`'s two scope rules against `git ls-tree -r origin/master` rather than by trusting
either list; the simulation now reports **0 undeclared deletions, 1 declared**.

Worth flagging beyond our tree because the exculpatory parenthetical is the sentence a reader
skims, and because the same fleet-wide sweep may have granted the same exemption elsewhere.

## 6. The build reproducibility question, measured — and one item that is go's, not ours

The operator asked the concrete version of L24: *clone keystone, clone go, can you actually build and
run?* We tested it rather than reasoning about it — a detached keystone worktree with no `output/`,
plus `git clone --no-local --single-branch --branch master` of go (2 commits, pinned ref absent).

**The build was never broken. It succeeded and produced the wrong answer**, which is worse:

| step | result |
|---|---|
| `ref = c1b0708` resolves? | no → R1 falls back to HEAD `cc1970f` |
| `core_gate_fingerprint` | **matches byte-for-byte** (`8261a033…`, identical across all five pins — it never raises) |
| `check_set_digest` | differs → printed a **NOTE** |
| outcome | built, installed, **exit 0** |

The installed binary is missing `request_mint_temporal_ceiling`,
`ingest_rejects_unrepresentable_expiry` and `configure_empty_grants_withdrawal` (`strings`-verified) —
the three checks that are this release's entire finding. **An adopter following our documented path
would have seen all 32 unfixed peers come back green and concluded the matrix was wrong.**

**Fixed here, three places:** `oracle-bootstrap.sh` now exits 3 on an anchor mismatch instead of
printing a NOTE (`REPIN=1` is the deliberate-re-pin hatch); its "nothing to do" short-circuit was
comparing the install against *itself* (`PROVENANCE.txt` vs the ref being built — both wrong, so they
agreed, and it printed *"differs from committed pin"* and *"matches BOTH … nothing to do"* three lines
apart); and `run-cohort-census.sh` now preflights the installed digest, having previously used the pin
only as a label to stamp the roster. All 46 `run-s4.sh` harnesses also exited **0** with a missing
oracle — the oracle invocation ends in `|| true` so a conformance FAIL does not abort the run, which
also swallowed a missing binary — and now exit 3 with instructions.

**And the half that vindicates content-anchoring, tested rather than argued.** Against a simulated
post-release go — `master` carrying a **freshly authored commit `592ff26`**, `c1b0708` unreachable by
name, same tree — `oracle-bootstrap.sh` falls back, matches both anchors, and builds a `validate-peer`
**byte-identical** (`c3827af8…`) to ours. The commit hash is genuinely not needed and the build is
reproducible across the re-authoring boundary. That is the ADR-0012 Amendment 1 property, working.

**The one thing we cannot fix, and it is a release-pipeline sequencing item, not a defect:** a digest
**identifies**, it does not **locate**. It tells a reader "you have the wrong oracle"; it cannot hand
them the right one. Until `entity-core-go` publishes a `master` carrying this oracle, an outsider can
verify an oracle they already have but cannot obtain ours. **Nothing keystone does closes that** —
it needs go to publish, which is already sequenced ahead of us.

Disclosed rather than papered over: `README.md` now carries the sibling-clone requirement, the exact
measurement table above, and a plain statement that *the conformance claims here are reproducible in
principle and not yet reproducible by you.* Everything else in the repo works from a clean clone with
no oracle at all — verified: `make help` / `caps` / `lint`, `tier-status.py`, `pin-gate.py` all exit 0.

**Post-release cleanup, filed not started** — none of it blocks the tag:

1. **If go's publish slips**, vendor go's `cmd` + `core` + `ext` into keystone SHA-256-pinned, the way
   `spec-data/` already is (**10.5 MB**, against 47 MB for shipping built binaries). Then a keystone
   clone is self-sufficient. Held deliberately, because it means carrying another repo's source.
2. **The remaining 85 unreachable citations** — all historical build-log, in `CONFORMANCE-MATRIX.md`
   (42), `SPEC-FINDINGS-LOG.md` (34) and scattered singles.
3. **`AGENTS.md`'s 20**, which is the METHODOLOGY-vs-L24 tension in §7 below — a ruling, not a sweep.
4. **C-5**, the crypto-agility corpus re-vendor from `ROUTING-2026-08-23-b`.

## 7. One ruling wanted: METHODOLOGY requires a source commit, L24 forbids an unresolvable one

Declaring `AGENTS.md` canonical (forced by the keep-list fix — it is already public and would otherwise
have been deleted) puts **20 unreachable citations** on the published surface in one move.

They are not sloppiness. `METHODOLOGY.md` defines the anti-pattern catalog as *"named failure modes,
**each with a source commit**"*, and this repo's charter repeats it — a rule earned because an
anti-pattern without provenance decays into folklore. Those commits are `dev` SHAs and will never
resolve publicly.

**Both rules are right in their own frame, which is the same shape as the ADR-0012/ADR-0027 conflict
this whole packet is about** — and worth noticing that the conflict reappeared within a week, one layer
down, in the document that records conflicts. We have not resolved it locally: `tools/pin-gate.py`
deliberately excludes `AGENTS.md` and says why. Three options, no recommendation:

1. **Keep the commits, scope the rule** — a source commit is internal provenance, exempt from L24 by
   kind rather than by document.
2. **Anchor anti-patterns on content too** — cite the enforcement grep or a file+symbol instead of a
   commit. Loses bisectability, which is most of the value.
3. **Drop `AGENTS.md` from the published surface** — but it is already public and the fleet decided
   agent docs publish ([ADR-0016]/[ADR-0028]), so this reopens a settled question.

## 8. Not addressed here

- **P-2 (the [ADR-0012] amendment)** — the operator has taken it directly. Nothing owed from us.
- **C-5 (the crypto-agility corpus re-vendor)**, `ROUTING-2026-08-23-b` — acknowledged, not started.
  Your priority call is accepted: disclosure before the tag, repair after. The agility rows in the
  8 consuming peers' reports are measured at corpus `8e7c5232…`, not the current `b5484e84…`, and
  that will be stated rather than quietly carried.
