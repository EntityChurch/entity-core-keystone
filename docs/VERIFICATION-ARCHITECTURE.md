# VERIFICATION-ARCHITECTURE — what this repo may author, what it may conclude, and what it owes upstream

**The question this answers.** `CONTRACT-LAYERS.md` says which *layer* a rule belongs to. This says
which *kind of verification artifact* a thing is, what it is allowed to conclude, and what has to
happen when it disagrees with the oracle. Those are different questions and only the first one was
written down.

**Why it exists.** Five self-authored verification surfaces grew in this repo independently, and
exactly one of them was designed:

| Surface | What it is | Was it designed? |
|---|---|---|
| `protocol-generator/shared/scope-matching/` | one pinned reading of §5.2 typed scope matching, runnable reference + portable vectors | **yes** — states its authority order, its supersession, and what a peer's port must agree with |
| `tools/put-probe/`, `tools/p47-probe/` | standalone wire probes that censused the cohort | no — no README, no declared home, in no axis |
| `protocol-generator/*/run-s3.sh` | two-direction loopback interop, hand-written assertions | no — and it is the one axis measured to have gone stale |
| `protocol-generator/shared/diagnostics/*` | one-off investigation scripts | no — filed by accident of what needed keeping |
| `protocol-generator/*/test/`, `run-s2.sh` units | impl-internal unit tests | per-peer, unmanaged |

`put-probe` drove implementation across **46 peers** while being none of these officially. That is
the accretion this document exists to stop. The rule is not "write more docs" — it is **a
verification artifact declares its kind before it is written, and its kind decides what it may
conclude.**

---

## The three kinds

### Kind A — Probe

**What it is.** A one-off wire instrument that answers a *census* question: *what does the cohort
actually do at this surface?* It measures. It does not judge.

**What it may conclude.** A finding, with per-peer evidence. Nothing else.

**What it may NOT do.** Gate a peer. Appear in a published conformance number. Stand as the reason a
peer is called conformant or non-conformant.

**Obligations, all of them load-bearing and all of them earned on a defect:**

- **A positive control asserted in the same run, recorded per peer.** A peer whose control fails is
  `trusted: false` and its result is *suppressed*, not reported. A probe fails in the direction of
  the answer it is looking for; three separate probe faults in one afternoon each would have
  published a confident wrong finding.
- **A differential control** wherever the input under test is a *state* rather than a *value* —
  the same input supplied where the answer should differ. A positive control catches a malformed
  frame; only a differential catches a well-formed frame asking the wrong question.
- **Any material it forwards that it did not author is verified against the invariant its sender was
  obliged to satisfy** — and the check's scope is stated, because *an invariant check licenses
  exactly the invariant it checks*. `put-probe` verified that each forwarded entity agreed with its
  map key and said nothing about the keys being **unique**; the fault was a duplicate key, and five
  peers were published as strict when the probe was wrong.
- **Its first two runs are about the probe.** Budget them.

**Lifetime: it expires.** A probe is retired the moment the oracle ships a vector on its surface —
which is exactly what has now happened to `put-probe`. Retirement means the probe stops being cited
as evidence, not that the source is deleted; the finding keeps its measurement and gains a line
naming the vector that superseded it.

**Home:** `tools/<name>-probe/` with a README naming the surface, the normative text and snapshot
digest it was written against, its controls, and its superseding vector once one exists.

### Kind B — Transcription

**What it is.** One pinned *reading* of a normative rule, with a runnable reference and a portable
vector file, so that fixing N peers produces one reading instead of N.

**What it may conclude.** That a peer's port agrees with the pinned reading, case for case. Not that
the reading is right — the spec decides that, and the oracle measures it.

**Authority order, stated in the artifact itself:** the spec is normative; when the oracle ships the
vector it is **the measurement**; the transcription is neither. A transcription is a scaffold with an
expiry date.

**Home:** `protocol-generator/shared/<rule>/`. `scope-matching/` is the reference implementation of
this kind and new ones copy its shape.

### Kind C — Independent check

**What it is.** A keystone-authored conformance check aimed at the **same normative target** as the
oracle, built from the spec rather than from the oracle's source. Agreement is corroboration.
Disagreement is a finding.

**Why we want it, stated plainly.** A single test set can be wrong. Forty-six peers passing one
author's vectors is cohort-consistent, not independent convergence — this repo already says that
about its *peers*, and the same sentence is true of the *vectors*. Two independently authored check
sets aimed at one spec is the same design as the two C-ABI codec implementations and the same design
as generating peers against a reference implementation. It is the only structure that can catch a
bug the oracle and the peers share.

**What it may conclude.** For the repo: that our peers satisfy our reading. For the ecosystem:
**nothing, until routed.** An independent check is a *second measurement*, never a second authority.

**The hard constraints, and they are what separate this from writing our own spec:**

1. **It is derived from the spec, not from the oracle's source.** Reading the oracle to match its
   code inverts the keystone's purpose; spec-vs-oracle divergence is the finding we exist to
   produce, and it is unreachable if we author from the oracle.
2. **Where the oracle has a vector, the oracle is the measurement.** Our check never overrides it and
   never appears in a published conformance number. A peer is conformant because `validate-peer` says
   so.
3. **Divergence is routed, always, and promptly.** If our check and the oracle disagree, one of them
   is wrong and it is a finding for arch — never a private disagreement we carry. A silently
   divergent test set is worse than no second test set, because it manufactures a second de-facto
   standard, which is the thing this repo must not do.
4. **A gap we find is routed and implemented, not just recorded.** If arch rules, go updates the
   check; if something is missing, it gets implemented. "We noticed and moved on" is not an outcome.
5. **It ships with an executed control.** A check whose failure mode has never been demonstrated by
   planting a defect is not a check. This repo has shipped a gate that examined zero things at least
   six times; the count is printed and asserted, or the check is vacuous.
6. **It declares what it covers and what it does not.** A number published as evidence of
   equivalence must publish the surface it ranges over — `abi_differential` said "71/71" while
   driving 19 of 27 declared symbols.

**Open posture question, routed not assumed.** `GUIDE-CONFORMANCE.md` §7.0 currently reads that
*"`entity-core-keystone` authors none of these"* and that asking keystone for a vector *"asks the
scorer to write the exam."* That sentence is about **canonical vectors**, and an independent
verification lineage is a different claim — it does not become canonical, it gates nobody, and its
disagreements are routed. But the distinction is ours, not arch's, and adopting it unilaterally
would be the exact overclaim this repo is the anchor against. **The posture change is routed to arch
before Kind C ships anything.** Until it is answered, Kind C work is authored and held, not
published.

---

## The rules that apply to all three

- **Declare the kind before writing it.** An artifact that cannot name its kind is a preference or an
  unrouted finding.
- **Name the authority.** Every axis and every artifact states where its checks derive from — oracle,
  vendored corpus, or ours. An artifact that cannot name one is not conformance and is never reported
  as though it were.
- **Cite the normative source by section and snapshot digest**, not by memory and not by the oracle's
  behaviour. A finding that asserts a spec gap records *which sections it read, by number* — the F51
  rule, because a negative claim cites nothing and is never re-checked.
- **Nothing is measured until it is swept.** Every axis appears in `tools/run-axis-sweep.sh --list`.
  An artifact absent from the inventory is an exclusion nobody declared — the fix for "it does not fit
  the table's shape" is a row saying where its runner lives, never omission.
- **The one with no external authority rots first.** Measured: S3 was the only axis of four whose
  checks went stale, and it is the only one we author alone. Kind C inherits that hazard in full and
  is the first thing this repo would build with *no* upstream referent at all, so it carries the
  heaviest gate obligation, not the lightest.

---

## Where the current artifacts land

| Artifact | Kind | Status |
|---|---|---|
| `tools/put-probe/` | A | **retired** — the oracle's `tree_put_error_codes.go` ships six `put_*` vectors on this surface at the check set succeeding `d30c3dd0…`; the finding stands, the probe stops being cited |
| `tools/p47-probe/` | A | active — §4.7 pre-hello divergence; check for a superseding vector at each re-pin |
| `protocol-generator/shared/scope-matching/` | B | active — the reference shape for this kind |
| `protocol-generator/shared/seed-policy/` | B-adjacent | Layer 2a convention, not a check; see `CONTRACT-LAYERS.md` |
| `protocol-generator/*/run-s3.sh` | C (retroactively) | **the debt** — 17 of 18 are hand-written with no oracle behind them, authored before this document existed, and are what proved the rot hazard |
| `protocol-generator/shared/diagnostics/*` | not a kind | investigation scripts; keep, but they conclude nothing and gate nothing |

---

## Increments, so this is a program and not a gesture

A full independently-authored suite at the oracle's current surface is **778 checks**. Saying we will
build that is not a plan. The increments, in order, each of which is useful alone:

1. **Declare and document what exists** — this file, plus a README per probe, plus the probes in the
   axis inventory. *(No new checks; closes the accretion gap.)*
2. **Route the posture question to arch** — may keystone author an independent verification lineage,
   on the constraints above. Nothing of Kind C publishes until answered.
3. **Retrofit the S3 axis into Kind C properly** — it already is one, badly. Give it the
   `scope-matching` treatment: named authority, spec citation, executed controls, printed counts.
   This is the highest-value increment because the surface is already ours and already measured to
   rot.
4. **Author Kind C against one surface we have just implemented from the spec**, where our reading is
   fresh and independent by construction — §4.7's connect-error table is the live candidate. If our
   check and the oracle agree, that is corroboration worth having; if they disagree, that is the
   finding the whole structure exists to produce.
5. **Only then** consider breadth.

**Do not skip to 5.** The value is in independence, and independence is destroyed by authoring
against the oracle to catch up on coverage.
