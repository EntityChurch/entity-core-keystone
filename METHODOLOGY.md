# METHODOLOGY — Disciplines, Doctrines, and the Ratchet

**The canonical statement of the entity-OS working methodology.** Pulled together from the
four repos that independently built it out, reconciled into one framework with a universal
core and a per-repo native layer.

> **Status:** Canonical, undated, living — edit in place.
> **Authority:** synthesizes the four worked instances (§11 Provenance). Where this doc and a
> repo's own charter disagree on a *universal* rule, this doc wins; where they disagree on a
> *substrate-native* rule, the repo wins. That split is the whole design (§5).
> **Binding force:** `AGENTS-STANDARD.md` §Methodology names this doc and sets which tier each
> repo runs. This doc is the content; the standard is the pointer.

---

## 0. Why this exists

We are building operating-system-level software. Conformance to the protocol is the contract
at the core, and near the core it is nearly sufficient — the spec is refined, the wire is
locked, and a conformance suite can tell you that you are right.

**It stops being sufficient the moment we leave the core.** A browser engine, a game engine, a
GUI toolkit, a .NET dispatcher, an FFI boundary, a GC heap we do not own — these are complex,
non-deterministic substrates carrying decades of other people's design decisions, most of which
we did not choose and cannot change. Out there, *green tests are not evidence of a working
system*: Godot shipped 28 phantom hosts at 104/104 green; browser-rust froze the app on a frame
panic with 331 native + 17 peer-integration + Worker-e2e all passing; workbench-go blew Skia's
paint recursion with a headless suite that never loaded Skia.

In every one of those cases the internal signals lied and only external evidence didn't. The
methodology is what we built so that the lying stops being free.

**The one-line statement of the whole thing:**

> **A feature must make us stronger, not weaker.**

If shipping a feature leaves the system with one more bug and no more knowledge, we are running
a treadmill. The methodology's entire purpose is to convert each incident into a permanent,
written, enforced constraint — so the same class cannot recur. That conversion is **the ratchet**
(§2), and everything else here is scaffolding around it.

---

## 1. The five artifact kinds

The methodology is five kinds of document with five different jobs. Conflating them is the
most common way it degrades, so the split is normative — and **the split that matters most is
the one between what the ecosystem hands down and what a repo earns for itself.**

| Kind | Form | Answers | When read | Location |
|---|---|---|---|---|
| **Disciplines** | Invariants — the ***what*** | "What must always be true?" | Continuously; every diff, every review | **D1–D12 here (§4) — ecosystem-owned.** D13+ in the repo's charter + `AGENTS.md` inline |
| **Doctrines** | Procedures — the ***how*** | "What do I do next?" | At task-start, when work lands | **§7 of this document, and nowhere else. Three of them. Ecosystem-owned, closed set** |
| **Workflows** | Local procedures — the ***how, here*** | "What do I do next *on this substrate*?" | At task-start, under a doctrine | The repo's own `docs/**/WORKFLOW-*.md`. **Unlimited, repo-owned** |
| **Substrate model** | Ground truth — the ***what actually happens*** | "What does this platform really do?" | Before any lifetime / leak / render / persistence work | `MODEL-<SUBSTRATE>.md` |
| **Anti-patterns** | Named failure modes — the ***what bit us*** | "Have we paid for this before?" | At review; cited by disciplines | Catalog in the charter or `AGENTS.md` |

> **WHAT IS ECOSYSTEM-OWNED AND WHAT IS YOURS — read this before writing any of the above.**
>
> | | who decides | how many |
> |---|---|---|
> | **Doctrines** | **the ecosystem. Handed down.** | **exactly three** (§7), and a repo does not mint a fourth |
> | **Disciplines D1–D12** | **the ecosystem** (§4) | twelve, reserved |
> | **Disciplines D13+** | the repo, on its own bugs | as many as it earns |
> | **Workflows** | the repo | as many as it likes |
> | Substrate model · anti-patterns · guides | the repo | its own |
>
> **A repo's hard-won procedure is a WORKFLOW, not a doctrine.** This is not a naming
> preference. A doctrine is the *shape of the work itself* — what you do when a feature is
> asked for, when something is broken, when you open a new surface — and it must be the same
> shape everywhere or the ecosystem cannot compare two repos' output, review across them, or
> move a person between them. A workflow is how that shape lands on **your** substrate: the
> order that actually converges for an Avalonia crash, the sequence for a cohort state sweep,
> the browser-substrate procedure. Those are real, valuable, and yours. **They are not
> doctrines, and naming them so quietly re-opens a closed set.**
>
> **This document caused the drift it is correcting.** §1 sent repos to their own
> `docs/DOCTRINES*.md`, §12 told a cold-start session to read *"the repo's doctrines"*, and
> §11 lists a repo's `DOCTRINE-*.md` approvingly in the provenance table — while §7 said
> there are three. Three repos did exactly what they were told and produced
> `DOCTRINE-CRASH-FORENSICS.md`, `DOCTRINE-COHORT-STATE-TRACKING.md` and
> `DOCTRINES-BROWSER-SUBSTRATE.md`. **The ambiguity was ours; the renames are theirs, routed,
> and no repo is at fault for following canon.** `conform-audit` **R34** holds the line now.

Two supporting kinds, not part of the methodology proper but load-bearing beside it:

- **Guides** — recipes. "How do I build a panel / a 3D view / an extension." Says how to
  *achieve* an invariant, never what the invariant is.
- **References** — canonical specs for a surface, produced by a Foundation Audit (§7.3).

**Disciplines = invariants. Doctrines = procedures, and there are three. Workflows = your
procedures, and there are as many as you earn. Model = ground truth. Guides = recipes.
References = canonical specs. All are load-bearing; none substitutes for another.**

The two rules that keep the split honest:

1. **Don't duplicate disciplines into doctrines.** Doctrines *reference* disciplines by number
   as checkpoints. A doctrine that restates a discipline has created a second source of truth
   that will drift.
2. **A discipline with no enforcement point is theater.** Every discipline names at least one
   concrete enforcement surface — a file, a grep, a lint rule, a test gate, or a named review
   question. "We should be careful about X" is not a discipline.

---

## 2. The ratchet — the core law

The ratchet is the mechanism that makes the whole thing a system rather than a pile of good
intentions. It has one rule and two ends.

**The rule:** every feature and every audit ends by feeding what it taught back into the
disciplines — in the *same session*. An unsynced lesson rots in a document nobody re-reads.

**The two ends:**

- **Feature end (F7).** After the commit, write 3–5 lines: what did building this teach about
  the system? Any pattern with 2+ recurrences that should become a helper or a discipline? Any
  refactoring surfaced but not taken? Did any discipline get honored in letter but not spirit?
- **Audit end (A10/A11).** After the fix lands, the *audit of the audit*: what the disciplines
  as written DID catch, what they did NOT catch, what is still missing, and what the process
  did right and should keep.

**Both ends are non-skippable.** Without the process-review step, an audit document is a fix
record. With it, it is a learning record — and the learning is the point.

**The failure this prevents, stated precisely** (browser-rust §0.5, verbatim in spirit): a
change ships green; it breaks in a configuration the suite never exercises; the symptom is
diffuse and mislabeled because the failure surface is silent; we theorize about the substrate
instead of tracing a value; the user finds the edge case in the real world and reports it; we
react; go to 1. The user's own words for it: *"waiting for me to find every edge case and come
back and tell you to fix it — that's not working."* And the cost compounds — **adding
a feature has been making us weaker.**

The ratchet is the only thing that reverses that sign.

---

## 3. The promotion ladder — how a rule earns its place

Disciplines are **promoted on evidence, not speculation.** This is what keeps the rule set
small enough to actually run and credible enough to actually follow.

| Stage | Trigger | Where it lives |
|---|---|---|
| **Observation** | Something felt wrong once | A handoff or audit note |
| **Anti-pattern (AP)** | A pattern bit us **once**, diagnosed, with a source commit | The anti-pattern catalog |
| **Candidate discipline** | Named, defined, applied to the current audit; shape unproven | §5 of the audit doc + a `(candidate)` row in the charter |
| **Ratified discipline** | The pattern bit us a **second time, in a different shape** | The charter + `AGENTS.md` inline, same session |

**The second-incident rule is the load-bearing part.** One incident tells you a bug happened;
two incidents of different shapes tell you a *class* exists. Promoting on one incident produces
a rule set nobody can hold in their head; refusing to promote on two produces the treadmill.

Two corollaries, both learned the hard way:

- **A discipline added on speculation must be earned within one release cycle or removed.**
  (workbench-go §5.)
- **Assistants honor candidates pre-ratification.** A candidate is not "not yet a rule" — it is
  a rule whose *generality* is unproven. Apply it; just don't yet claim it generalizes.

There is one sanctioned exception to second-incident: a candidate may promote early when a
**second distinct shape** of the same class is identified even without a second outage — e.g.
godot's D14 ratified when the capture-claim release seam turned out to be a second
contract-test shape.

---

## 4. The universal disciplines (D1–D12)

**These twelve transfer verbatim, and they keep their numbers everywhere.** They govern how
any implementation uses the entity substrate; they are stack-agnostic. Godot codified D1–D8,
the foundation audit added D9–D11, D12 was generalized from the borrowed-framing anti-pattern,
egui/browser-rust cosigned, workbench-go inherited them verbatim, and arch published them
outward in `GUIDE-IMPL-DISCIPLINE.md`.

> **D1–D12 ARE RESERVED. A repo's own disciplines start at D13.** This paragraph exists
> because this document said three different things at once and a repo did exactly what it
> was told: §4 called the universal set D1–D11, the sentence under the table called D12
> *"universal in substance though numbered locally"*, the rule below said *"inherit D1–D12
> verbatim"*, and the native table then handed **D12** to two repos for something else
> entirely. So two different D12s exist in the fleet, and the repo that minted one was
> following canon, not drifting from it. **The ambiguity was ours.** Numbering is now fixed:
> universal is D1–D12 and native is D13 upward, which is what `entity-system-architecture`
> already did without being asked. `conform-audit` **R33** enforces both halves.

| # | Discipline | The invariant |
|---|---|---|
| **D1** | **Use the kernel; don't reinvent what extensions provide** | Reactivity → `subscription`. Audit → `history`. Versioning → `revision`. Indexed lookup → `query` (never client-side filtering of a full list). Long-running ops → `continuation`. If we built our own dispatcher, watch loop, or cache layer, we did it wrong. |
| **D2** | **L1 dispatch is the default; L0 is the back door** | Anything observable by another peer goes through L1 (`execute` / `*_async` / `subscribe`). L0 direct-store is reserved for render-loop reads, boot bootstrap, and session scratch no peer will ever observe. **Every L0 call is a visible opt-out from the security boundary.** L0 MUST NOT be exposed to delegated actors or attenuated handler bodies. |
| **D3** | **Capability-typed dispatch — surface now, even permissive** | Every privileged operation requires a named capability; contexts carry an explicit held-cap set; dispatch **fails closed**. The surface goes in while retrofit is cheap, even when every check passes today. |
| **D4** | **Bounded interfaces; one channel does one thing** | No channel carries two concerns. Actions carry actions. Selection goes through the selection sink. Modal transitions are their own state machine. Tree changes go per-prefix, never through a global "something changed" broadcast. |
| **D5** | **Declarative composition; boot dependencies are declared, not folk knowledge** | Every component declares what it requires; boot order is computed and verified; a missing dependency fails **loudly at boot**, not silently at first use. |
| **D6** | **Per-host namespaces, formalized** | Namespace is per-host, first-class, lookups local; cross-namespace access is an explicit handle, validated by the receiver, failing closed on dangling. The fully-qualified path *is* the data model — never strip the peer id. |
| **D7** | **The kernel keeps working when applications misbehave — and vice versa** | A panel/window crash never takes the host. A modal that fails to clean up is popped by host teardown. A misbehaving action never poisons the dispatcher. **And the symmetric prime:** the application never assumes the kernel will rescue it. **Symmetric state** — every push has a paired pop, every subscribe a paired unsubscribe, every grab a paired release, every recursive set a recursive restore. |
| **D8** | **Trust the spec; surface drift, don't normalize it** | Read code *against* the spec, never *as* the spec. Never bake observed-but-unspecified behavior into code or docs as if it were contract — annotate the call site with the question reference and the repair path. File to a durable tracking surface (spec-issues / QUESTIONS-FOR-ARCHITECTURE) with observation / spec-reading / working-hypothesis / what-we-did-meanwhile / ask. **And don't stall** — filing is not blocking; record the working position and keep moving. |
| **D9** | **Accounting — nothing accumulates that we didn't choose** | *"Every block of memory, every bit that goes through the system… Nothing accumulates, we know it, and when it does we know why and it's because we chose it too."* Two halves (three in some repos): **D9-runtime** — every allocation, handle, listener, timer, cache entry, subscription, and task has a teardown path *identified at the point of construction*. **D9-persistence** — every entity written to the tree has a documented **writer (single owner) / reader-at-boot / GC story**, or an explicit exemption with rationale. The tree does not auto-GC what we write: **our cleanup is the only cleanup.** |
| **D10** | **Real-session coverage — green tests ≠ a working system** | Load-bearing changes are exercised across the loops the user actually runs: **cross-boot / cross-reload** (boot → act → quit → boot, asserting each store's documented contract), the **real runtime** (headed, the actual WebView, real Skia — a tier that skip-passes is not coverage), and the **real store** (inspect the actual on-disk state; code-only analysis misses scale). |
| **D11** | **Inventory-boundary declaration (meta-discipline)** | Inventory-driven audits find what's in the inventory. At audit open, name what is in scope **and what is not**. At close, carry the un-inventoried domains forward. A finding from outside the boundary extends the boundary next time. |

**D12 — universal, and it is D12 everywhere:** *read canonical sources before
designing against them.* Cite the canonical source verbatim with `(symbol, path, commit)` and a
citation **type** (source-read / peer-reported / measured). Never paraphrase canonical material
from a handoff, summary, prior session note, or another implementer's design doc — those are
derivative artifacts carrying their author's framing. This is the antidote to the
**LLM-summary-confidence** failure mode: each summary-of-a-summary preserves confidence while
eroding source-grounding. Its failure mode is the named anti-pattern **borrowed framing**.

---

## 5. Substrate-native disciplines — the part that does *not* transfer

Above D11/D12, each repo earns its own. **These are the disciplines the substrate forces**, and
copying them between repos is a category error — godot's Godot-runtime rules are meaningless in
a browser, and browser-rust's arm matrix is meaningless in .NET.

The rule: **inherit D1–D12 verbatim, then earn your own on your own bugs — numbered from D13.**

**Two rows below are RENUMBERS OWED, not descriptions of a correct state.** `entity-browser-rust`
and `entity-workbench-go` were each assigned a native **D12** by an earlier version of this
table, which is the collision described in §4. Their native sets shift up by one when they next
touch their charters; canon records the corrected numbering now so nothing new is minted against
the old one. Neither repo did anything wrong.

| Repo | Substrate | Native disciplines | The failure class the substrate forces |
|---|---|---|---|
| **godot-entity-core-rust** | Godot 4 + GDScript + GDExtension | D13 observable long-running ops · D14 binding-contract negative tests · D15 input-fact single-writer · D16 perf-claim measurement · D17 visual-contract honesty | No GC; deterministic refcount + explicit free; cycles are silent leaks; headless tests assert wiring, never pixels |
| **entity-browser-rust** | WASM + JS + Worker + service worker + WebView | **D13** two-heap accounting · **D14** frame-loop integrity · **D15** worker-wire discipline · **D16** arm decision from the bound peer · **D17** persistence + cold-return *(renumber owed: was D12–D16)* | Two heaps with different collection semantics; one frame loop a panic can kill forever; the same code runs on Direct and Worker arms with different stores |
| **entity-workbench-go** | Avalonia + .NET + cgo + Go | **D13** cross-language lifetime accounting · **D14** UI-thread/dispatcher integrity · **D15** JSON-envelope IPC contract · **D16** bounded payloads · **D17** test-depth honesty · **D18** persistence honesty · **D19** renderer-agnostic substrate *(renumber owed: was D12–D18)* | Two GCs that don't know about each other; one UI thread; unbounded visual trees blow Skia's paint recursion |
| **entity-system-architecture** | Prose specs, no runtime | *(see §9 — arch's native layer is the spec-lifecycle discipline, and it is the gap this document's adoption plan closes)* | No compiler, no test runner; the only gates are a linter and a cohort |

**What makes a native discipline legitimate**, in all three worked cases: a **source bug with a
commit**, a **named enforcement point**, and a **second incident** before ratification.

---

## 6. The review questions — the continuous surface

Disciplines are checked continuously through a short question list run on **every diff**. The
list must be short enough to actually run — six to ten questions, no more.

**The universal core (six):**

1. **Which layer is this?** If the layer isn't obvious, the code is confused about its place.
2. **What kernel service does this touch / consume / reimplement?** If it reimplements one,
   name it and justify — or stop. (D1)
3. **What is the capability surface?** Gated? Typed? Held-cap set explicit? Fails closed? (D3)
4. **What is the failure mode if the kernel misbehaves, AND if this code misbehaves?**
   Symmetric. **If "the user can't tell anything is wrong" is a possible answer, you need an
   observability surface.** (D7)
5. **What is the accounting?** Every add → paired remove identified *at the same change*, or an
   explicit exemption. Every persisted entity → writer / reader-at-boot / GC story. (D9)
6. **Does the test cross the real loops?** Cross-boot, real runtime, real store — for whichever
   is load-bearing for this change. Named explicitly by tier. (D10)

**Each repo appends its substrate questions.** browser-rust adds *which arm?*, *can this panic
in a frame?*, *what persists with what cold-return story?*, and *what did this make redundant,
and did I delete it?* workbench-go adds *what's the bound?*, *can this block the UI thread?*,
and *is this feature or presentation?*

**Question 4's escape clause is the most valuable line in the list.** "The user can't tell
anything is wrong" is the answer that predicts every diffuse, mislabeled, expensive bug report
we have ever received.

---

## 7. The doctrines — procedures

Disciplines tell you what must be true. Doctrines tell you **what to do next**. The point is
that when a bug lands or a feature is asked for, the answer is never *"think hard and hope"* —
it is *"open this doctrine, you are at step N, the next step is M."*

**Three doctrines, distinguished by their input — and three is the whole set.** They are
ecosystem canon, maintained here, and **a repo does not author one.** What a repo earns from
its own substrate is a **workflow** (§1): open the doctrine, and where a step lands differently
on your platform, that landing is a `WORKFLOW-*.md` the doctrine's step points at.

**Why the set is closed, stated so it does not read as bureaucracy.** The doctrines are the
shape of the work — feature, breakage, new surface. If each repo defines its own, two repos'
audits stop being comparable, a reviewer cannot tell whether a step was skipped or never
existed, and the ratchet has nothing common to ratchet against. The substrate-specific part is
exactly the part that *should* vary, and that is what workflows are for. **Nothing is lost by
the rename; a closed set is gained.**

### 7.1 Feature Development Doctrine (F0–F8)

**Input:** "build X." **Output:** X shipped, tested at the tier that matters, every degraded
mode surfaced not silent, and the system understood incrementally better than before.

| Step | What |
|---|---|
| **F0 — Intake** | Restate the ask in one sentence. If you can't, ask **one** clarifying question. Note who asked and what success means. |
| **F1 — State machine on paper** | Every state, every transition, and **what the user sees in each state**. A state with no surface is an observability violation *by construction* — fix the design before the code. A state machine you can't write down because "it's just one function" is the warning. |
| **F1.5 — Map the handoff chain** | *(substrate-native)* Name every boundary the change crosses and **what is observable on the other side**. An invisible hop is where the next bug hides. |
| **F2 — Review questions on the design** | Run the full list **before writing code**. Output is a one-paragraph design note naming the layer, the kernel surface, the observability channel, the accounting story, the test tier. **The note is the forcing function — if you can't write it, you don't have a design yet.** |
| **F2-arm — Declare the configuration matrix** | *(substrate-native)* Which configurations can reach this in production, and how is each tested? A cell "tested by reading the code" is a **named hole**, not coverage. |
| **F3 — Decide the observability surface BEFORE writing the loop** | Any operation running longer than one frame/tick needs (a) a start signal, (b) periodic progress, (c) a failure **reason** — never a bare failed flag. Decide the channel before the loop, not after. A loop without one is **shipped blind by construction**. |
| **F4 — Build, with the binding rules** | The repo's red-flag list — each entry a non-negotiable that has already cost a bug. Violating one is a self-review stop. |
| **F5 — Test at the tier and configuration that matter** | The test that would have caught the bug ships in the **same commit** as the surface. **Phase-change rule:** if the helper has a barrier at K, test at ≥ 4K — N=10 doesn't catch N=16 race shapes. The bug surfaces at a *configuration*, not a count. |
| **F5.5 — Close-check against the standard** | *(where a UI/design standard exists)* Run it. **A standard without a gate is a suggestion** — this step exists because the standard was skipped twice while it sat on disk. |
| **F6 — Verify through the real delivery path** | Not "it compiles," not "the suite is green." The real runtime, the real cache layer, the live artifact hash. If you cannot reach the surface, **say so explicitly** — that is a named hole, not done. |
| **F7 — Close-out review** | **The ratchet.** (§2) |
| **F8 — Memory + handoff** | Non-obvious behavior → a durable note. Session ends mid-track → a handoff. |

### 7.2 Audit Doctrine (A0–A12)

**Input:** "Y is broken" / "something feels wrong" / a hunch. **Output:** root cause **known,
not guessed**; fix landed; **regression gate permanent, in the configuration that broke**;
disciplines updated; the audit doc as durable record.

| Step | What |
|---|---|
| **A0 — Open the audit doc FIRST** | Status OPEN, severity, and **name the framing** ("hardcore foundation audit" vs "quick correctness check" — both legitimate). Reserve all twelve sections at open; an empty section is a placeholder, not a skip. **The doc is the forcing function.** |
| **A1 — Trace before you theorize** | The most-violated rule, so it is first. One log line at the suspect value and a **re-run** *before* forming any substrate hypothesis. If the symptom doesn't match your mental model, **the model is wrong** — the cheapest fix for a wrong model is to print the state and look at it, not to edit a code path. *(Many rounds of race theory once cost us what a single trace showing `found=true` 877× resolved: the bug was our own logic.)* |
| **A2 — Honest state of knowledge** | Two lists: what we CAN say from reading the code (with `file:line`), and what we CANNOT say without instrumentation. **The second list is the more important one** — every item on it is a hypothesis you have no evidence for. |
| **A3 — Telemetry-gap map** | Table every surface a user might check during the failure and what each *actually shows*. If it's mostly "empty / silent / nothing," **you have an observability violation regardless of what the bug turns out to be** — and fixing the silence is part of the fix. |
| **A4 — Hypotheses ranked, each with its cheapest falsifier** | ≥2 hypotheses. **Instrument the falsifier for EVERY hypothesis in the SAME pass** — instrumenting only the leading one buys a second round. |
| **A5 — Discipline audit on what shipped** | Run the review questions against the code *at the failing commit*. Name which disciplines were violated **in letter vs in spirit**. *(Letter: the kernel didn't crash. Spirit: the user-visible surface was empty.)* **This split is where new disciplines come from.** |
| **A6 — Three passes, three commits** | **A: telemetry** (log at every falsifier site, zero happy-path change). **B: persisted observability** (the surfaces A3 found missing — permanent). **C: regression gate in the configuration that broke** — not a clean stand-in. Separate commits so instrumentation can be bisected. |
| **A7 — Run; fill data and findings** | Which hypothesis confirmed, by what evidence with `file:line`; which dismissed and why. |
| **A8 — Fix proposal with sequencing** | Each component: what it changes, where, cost, and **what it is NOT doing**. **User signoff before shipping** for anything deeper than a quick correctness check. |
| **A9 — Discipline + anti-pattern adoption** | Candidate vs ratified, per §3. |
| **A10 — Process review: the audit of the audit** | **Non-skippable.** (§2) |
| **A11 — Sync to the charter + `AGENTS.md`** | **Same session.** Otherwise it rots. Standing close criterion. |
| **A12 — Close checklist** | Data · cause confirmed · fix proposed + signed off · fix landed · **regression gate in the suite** · verified through the real delivery path · disciplines updated · anti-patterns catalogued · process review written · final state captured. Only then does it close. |

### 7.3 Foundation Audit Doctrine (FA0–FA7)

**Input:** "review this surface end-to-end before we design against it." No symptom, no feature
spec — the pre-feature, pre-design, architectural-foundation phase. **Output:** a canonical
reference doc that becomes the spec for the surface, a drift map against today's code, work
items, and usually a discipline candidate or two.

It is its own doctrine because the Audit Doctrine assumes a symptom and the Feature Doctrine
assumes a spec; foundation work has neither, and conflating it leaves half the audit steps as
no-ops. The shape is closer to research.

| Step | What |
|---|---|
| **FA0 — Open the doc inventory** | The dated audit/drift doc (inventory boundary first, per D11) **and** a citation-rich current-state doc where **every claim cites `file:line` with a 3–8 line quote** — no paraphrase across files, no speculation, no recommendations. Ends with **gaps observed**. |
| **FA1 — Landscape pass** | We don't start from scratch. Tier 1: the closest 2–3 analogues. Tier 2: 2–3 broader references solving the same problem elsewhere. Tier 3: outliers whose disagreement is informative. Same question list for each; **cite every claim** — "I think project X does Y" is not acceptable. |
| **FA2 — Convergence analysis** | Convergent (4+ agree) is the default unless requirements push elsewhere. Divergent: table the variants and say what kind of system tends to which. Then **our shape vs the field**, and whether each divergence is justified. Split decisions are made explicit as a requirements call. |
| **FA3 — Synthesis into the reference doc** | `REFERENCE-<SURFACE>.md`, **undated** — canonical. Model · state machine · routing/dispatch · failure modes · code map · open recommendations. |
| **FA4 — Drift → work items** | Each divergence becomes a work item with a fix shape and the gate test that would prove it. |
| **FA5 — Discipline + anti-pattern surface** | Candidates land, awaiting second incident. |
| **FA6 — Sync to `AGENTS.md`** | Pointer to the new reference; candidate rows added. |
| **FA7 — Close checklist** | Reference exists and is undated · audit CLOSED · landscape CLOSED · roadmap absorbed the drift · `AGENTS.md` updated · next session knows where to pick up. |

### 7.4 The shared spine

Five anchors both/all doctrines share:

1. **`AGENTS.md` inline + the charter are the canonical spec.** Both end in a sync step.
   **If it didn't land there, it didn't land.**
2. **The same review questions**, asked with different intent — Feature: *is this design right?*
   Audit: *what was missed?*
3. **Observability is checked at both ends.** Feature decides the surface up front (F3); audit
   checks whether it existed (A3). Every feature ships a channel; every audit verifies it was
   usable.
4. **The configuration matrix is the test contract.** Feature declares and tests in it; audit
   reproduces the bug in the cell where it broke.
5. **The ratchet.** Both end in learning extraction. **The disciplines grow via this ratchet
   only — no drift between what we know and what is written down.**

**Switching mid-stream — feature → audit.** You are in F4 or F6 and something doesn't add up.
**Stop. Open the audit doc.** The feature pauses; the audit completes; the feature resumes with
the lessons applied. Switch on **any** of: a test fails for a reason you don't understand within
30 seconds of reading · the symptom doesn't match the mental model · a "looks like" guess feels
comfortable · the user reports behavior you can reproduce · you are about to write a speculative
fix without knowing the root cause.

**Audit → feature.** The audit revealed a missing surface, helper, or system. Open a feature
subtask (F0–F8 in miniature); the audit pauses at the fix proposal, the feature builds the
surface, the audit resumes and verifies on top of it.

---

## 8. The anti-pattern catalog

Each entry: a **name** we actually use in conversation, the **failure mode**, the **fix shape**,
the **source commit**, and the **discipline it grounds**. Numbering is per-repo and stable —
entries are never renumbered and never deleted; a retired one is marked deleted with the commit
that removed it, so `git log -S` still recovers the history.

The catalog is what makes review conversations cheap: *"that's 5.7"* carries a full diagnosis.

Cross-repo anti-patterns worth knowing by name everywhere:

- **Add without paired remove** — the base accounting failure (D9).
- **Defined-but-uncalled cleanup primitive** — the primitive is correct in isolation and no
  production path calls it from the lifecycle-end seam. Two shapes: *premature primitive* (built
  ahead of a consumer that never lands) and *forgotten wire-up* (built alongside the writer, wire
  step deferred). Detection: PR-time grep for cleanup primitives with no caller. **Test pattern:
  assert the primitive is wired from the production teardown path, not that it works in isolation.**
- **Borrowed framing** — paraphrasing canonical material from a handoff or summary instead of
  citing the source. The LLM-summary-confidence failure mode (D12).
- **Latent infrastructure rots** — infrastructure added to support a use case, where the use case
  never shipped a test exercising it. It looks correct in isolation; nothing catches that it's unused.
- **Fix forward, leave the artifacts** — a defective writer is fixed without a one-shot prune for
  pre-fix artifacts in the same commit.
- **Defensive code that lies** / **failure flag without context** — a status of failed with no
  reason field; a fallback that silently degrades.
- **Test against suppressed behavior** — asserting a cause→effect across a guard that explicitly
  suppresses it; passes intermittently for unrelated reasons.
- **Claim asserted via wiring test, not outcome test** — the test confirms the wiring between
  APIs and code, never the outcome the user sees. Generalizes well beyond pixels: any claim whose
  observable is outside what the harness can reach needs either a real gate or an **explicit
  disclosure in the commit body**.

---

## 9. Adoption — which repo runs what

The methodology is **selective by design**, but the selection has been read too narrowly. The
correct axis is *how far the work sits from a surface conformance can hold*, and there are three
tiers, not two.

| Tier | Runs | Repos | Rationale |
|---|---|---|---|
| **Full** | Disciplines (D1–D12 universal + native from D13) · Feature + Audit + Foundation doctrines · substrate model · anti-pattern catalog · review questions | `entity-browser-rust`, `entity-workbench-go`, `godot-entity-core-rust` *(archived; the origin instance)* | Complex non-deterministic substrates. Conformance cannot reach them. |
| **Core** | Disciplines (D1–D12 universal + native from D13) · **Audit Doctrine** · anti-pattern catalog · review questions. Feature Doctrine optional; Foundation Doctrine when opening a new surface | `entity-core-go`, `entity-core-rust`, `entity-core-py`, `entity-core-keystone`, `entity-system-arch-tools` | Conformance is a strong gate but does **not** cover process drift, build-state claims, or accounting. |
| **Authoring** | A **lifecycle discipline set** in place of runtime disciplines · **Audit Doctrine** · **Foundation Audit Doctrine** · the ratchet | `entity-system-architecture`, `entity-core-protocol`, `entity-core-formalization` | No runtime to hold; the substrate is the corpus itself, and the failure modes are lifecycle failures. |

**The Core tier is a real gap, and it has already been measured.** `entity-core-go`'s own
discipline audit (2026-08-12) found its rules spread across a sibling repo's guide, an ADR in a
third repo, and its own `AGENTS.md`, and named the consequence directly:

> *"This repo has no `DOCTRINE-*` or `DISCIPLINE-*` document at all… An audit should not have to
> assemble its own standard first. **That is plausibly the root cause of drift being invisible.**"*

The same audit found the mechanism by which a discipline dies, and it is worth quoting because
it is not carelessness:

> *"A legitimate pressure ate a discipline, and nothing in the process noticed."*

A real constraint ("reduce cross-repo round trips") cannibalised a real rule ("spec arbitrates
ambiguity; do not vote") because both pointed at the same act. **That is the shape to watch
for.** It is invisible precisely because both sides are legitimate.

**The Authoring tier is the other real gap.** A spec repo has no compiler and no test runner;
its only mechanical gate is a linter. Its disciplines are therefore lifecycle disciplines, and
they already exist in scattered form — the proposal→ratify→fold lifecycle, the
read-the-live-worktree rule for build-state claims, the ratcheted narrative baseline. What is
missing is that they are not assembled as a discipline set with a promotion ladder, an
anti-pattern catalog, and an audit doctrine — so drift there is invisible the same way it was
invisible in go.

**Arch assembled and ratified this set on 2026-08-15** — the **Discipline Charter** in the
`entity-system-architecture` repo is the canonical home. The table below is the ecosystem-visible summary; **the
charter wins on its own content.** Three corrections came back from that ratification and are folded
in here, because meta drafted these as `A1–A6` and got three things wrong:

- **They are numbered `L`, not `A`.** `A0–A12` is already the Audit Doctrine (§7.2), whose own `A1`
  is *trace before you theorize*. Two different `A1`s one document apart is how a set stops being
  citable. The axis is now: **`D` runtime · `A` audit step · `F` feature step · `L` lifecycle.**
- **Two of six do not meet the ladder's bar** and are carried as **candidates**, not ratified — L3
  has one incident, and L6's single incident is in a *peer's* tree, so ratifying it would import
  another repo's evidence as arch's own. Ratifying all six because six were routed would have been
  the set's first violation of its own promotion rule.
- **The L1 gate's trigger as meta sketched it was wrong**, and arch measured it rather than arguing
  it — see below.

| # | Discipline | State | Source incident |
|---|---|---|---|
| **L1** | **No normative spec edit without a proposal** — the proposal is where rationale lives; a fold with no proposal has nowhere to put the *why*, so the why goes into the spec text | **Ratified** · gated | `EXTENSION-REVISION` v3.11 folded with no proposal in existence — two new MUSTs plus a rev bump; the rationale contamination was the *second-order* effect of skipping the lifecycle |
| **L2** | **Read the filing seat's own document, never a peer's summary of it** | **Ratified** | The same fold ruled 2 of 7 items from a formal peer spec-issue that was on disk and unread, then bumped the version — which reads downstream as *this area is handled* |
| **L3** | **A partial fold does not get a version bump** | **Candidate** — one incident | Same incident; the version bump is the signal that carried the falsehood |
| **L4** | **A claim about a document or a tree is checked by opening it** — outward *and* **inward** (our own corpus is a tree too) | **Ratified** | Failed **four times** (07-28 → 08-08); every instance caught by a peer, never by us. The stale claim is always *plausible* — which is why review doesn't catch it and only opening the tree does |
| **L5** | **Spec text is not our log** | **Ratified** · gated | Ratcheted in `.spec-baseline.json`: **489 findings across 30 normative specs**; new violations gate |
| **L6** | **Resolve divergence from the table, before the fix is written** | **Candidate** — one incident, and it is in a peer's tree | go's F-1: a three-way divergence resolved by majority when the doctrine says *all three differ = spec ambiguity, tighten the spec*. **A fix whose justification includes a count of implementations is the smell.** |

**The L1 gate — `spec provenance`, in arch-tools, warn-level.** Meta's routed sketch keyed
on the `**Version**` header changing. Arch measured it against the two normative folds landed the
same day — one adding 2 MUSTs, one adding 4 — and **both changed zero version
headers**, correctly, under arch's standing *cohort findings fix the spec in place, no rev bump*
carve-out. **A version-triggered gate is silent on precisely the class arch uses most.** The shipped
trigger is two-part: the version header changed, **or the file's count of normative tokens changed
— added *or* removed**, since retiring a requirement is as normative as adding one.

Two further calibrations, both measured rather than assumed, and both worth carrying wherever a
change-gate is built next:

- **Count the file, not the diff's `+` lines.** A `+`-line count reports every reworded sentence
  that merely *contains* a MUST as a new requirement, so an editorial touch-up fires the gate.
  Residue stated honestly in the module: a rewrite swapping one MUST for a different MUST nets to
  zero and is invisible.
- **Exemptions are declared trailers, never inferred** — `Spec-Change: hygiene` and
  `Spec-Change: cohort-finding`. Without the second, trigger 2 fires on every in-place fix, *"which
  is the shape that gets a gate switched off in a week."*

**The self-test caught itself**, and this is the transferable part: two "satisfaction" cases passed
**vacuously** on first run — they never moved the token count, so no trigger fired and they proved
nothing. Fixed, plus a **negative control** asserting the guard fires unaided. That is *a check that
cannot be made to fail has not been shown to measure anything*, applied to one's own test — and it
belongs in every repo that ships a gate.

---

## 10. Enforcement surfaces — the honest table

**A discipline with no enforcement point is theater.** Every repo owes this table: for each
discipline, how enforcement happens *today*, and what is still owed. Naming the gap is the
discipline working; leaving it unnamed is how "we have a standard" becomes "we had a standard."

Enforcement escalates through four rungs, cheapest first:

1. **Review question** — a human/agent runs the list. Free, and forgettable.
2. **Named catalog entry** — the failure has a name, so review conversations are cheap.
3. **Mechanical grep / lint** — a `make lint` rule with a **ratcheted baseline** that can only
   go down. This is the highest-leverage rung: existing debt is held and doesn't block, new
   drift fails the build, and re-baselining your way to green is not available.
4. **Gate test** — a regression test in the suite, in the configuration that broke.

The ratcheted-baseline pattern (arch's `.spec-baseline.json`, browser-rust's
`ui-lint-baseline.txt`) is the single most transferable enforcement mechanism we have, and it is
currently used in two repos. It should be the default answer for any discipline that can be
approximated by a grep.

---

## 11. Provenance

Four independent instances, built over roughly eight months, reconciled here.

| Instance | Artifacts | Contribution to the whole |
|---|---|---|
| **godot-entity-core-rust** | `REFRAME-EOS-DISCIPLINE.md` · `DOCTRINES.md` · `MODEL-GODOT-RUNTIME.md` · inline core in `CLAUDE.md` | **The origin.** D1–D8 from the substrate-sandwich reframe; D9–D11 from the foundation audit that found 28 phantom hosts at 104/104 green; the Feature/Audit/Foundation doctrine skeleton; the second-incident promotion ladder; the anti-pattern catalog convention |
| **entity-browser-rust** | `DISCIPLINE-REFRAME-BROWSER-SUBSTRATE.md` · `DOCTRINES-BROWSER-SUBSTRATE.md` *(a workflow — rename owed, §1)* · `MODEL-BROWSER-WASM-RUNTIME.md` | **The generalization proof** — took the skeleton verbatim and re-earned the substrate layer on its own bugs. Contributed the §0.5 *name the recurring cycle* practice, the configuration-matrix step, *trace before you theorize*, delivery-path verification, and the enforcement-point requirement |
| **entity-workbench-go** | `DISCIPLINE-CHARTER.md` · `MODEL-AVALONIA-RUNTIME.md` · `DOCTRINE-CRASH-FORENSICS.md` *(a workflow — rename owed, §1)* · `GUIDE-AVALONIA-PANEL-PATTERNS.md` · `TESTING-STRATEGY.md` | **The second generalization** — inherited D1–D11 verbatim across a completely different stack. Contributed the explicit promotion criteria (§5 of its charter), the enforcement-surfaces table, test-depth honesty (*naming the tier is the discipline*), and the AP-grounded-by-commit convention |
| **entity-system-architecture** | `guides/GUIDE-IMPL-DISCIPLINE.md` · `DOCTRINE-COHORT-STATE-TRACKING.md` *(a workflow — rename owed, §1)* | **The outward publication** — carried D7–D12 into a contributor-facing guide, and added the architecture-side mirror disciplines (A-D1…A-D6) addressing the *"we aligned but never followed up"* pattern |
| **entity-core-go** | its 2026-08-12 discipline self-audit | **The diagnosis** — the self-audit that measured drift in a Core-tier repo and named the root cause: rules with no home in the repo that must follow them |

---

## 12. Progressive discovery — what loads when, and why not all of it

**The constraint is real and it is not going away: this material cannot all sit in every
context window.** A session that loads the whole methodology, every charter, every doctrine and
every model has spent its budget before it reads a line of code — and a session that loads none
of it re-derives decisions the ecosystem already paid for. The resolution is not a compromise
between the two. It is that **each artifact has a trigger, and the trigger is what gets
memorized, not the content.**

| tier | what | when |
|---|---|---|
| **0 — always** | `AGENTS.md` + `AGENTS-STANDARD.md` | **`AGENTS.md` ≤ 30 KiB · `AGENTS-STANDARD.md` ≤ 24 KiB · tier 0 total ≤ 54 KiB, in bytes** |
| **1 — cold start, once** | this document §1–§4 (kinds · ratchet · ladder · D1–D12) · the repo charter's discipline list · the latest handoff | a session asking *"how do we work here?"* |
| **2 — by trigger** | **the one doctrine matching the task** (§7) · the substrate model · the workflow the doctrine's step names | at task start, never speculatively |
| **3 — looked up** | anti-pattern entries · guides · references · dated status docs · this document's §5–§11 | when something points at them |

**The triggers, explicitly** — this is the part worth knowing by heart:

- building something asked for → **Feature Doctrine** (§7.1)
- *"Y is broken"* or *"something feels wrong"* → **Audit Doctrine** (§7.2). **A1 is the prime:
  trace a value before you theorize.**
- opening a surface you have not designed against → **Foundation Audit Doctrine** (§7.3)
- touching lifetime, leaks, rendering or persistence → **the substrate model**, first
- a crash, a cohort sweep, a platform-specific procedure → **the repo's `WORKFLOW-*`**

**The rule that keeps tier 0 small: `AGENTS.md` names the trigger; it does not carry the
content.** Any section of it that could be replaced by *"when X, open Y"* should be. An
`AGENTS.md` that grows into a library stops being read at all — measured, at 4,663 lines, on
the repo where it had become the front door.

### ⚠ This tiering is a mechanism, not a preference — say which half is enforced

**`METHODOLOGY.md` is tier 1, not tier 0** ([ADR-0028] Am. 1). It is carried byte-identical in
every repo (`R2b`) so it can be opened on demand, and it is **not** part of the default load.
That is why it is allowed to be this long: it escapes the byte budget by escaping tier 0, and
capping it instead would have compressed the material rather than deferring it.

**And a warning about this very table, because it was wrong for a month.** This row used to
read *"auto-loaded"* for both tier-0 files. **Only `AGENTS.md` is auto-loaded** — through
`CLAUDE.md`'s `@AGENTS.md` import, the one real import in the system. `AGENTS-STANDARD.md`
reaches context because **`AGENTS.md` instructs the full read and additionally imports it**;
the instruction is the load-bearing half and works for any agent, while the import is an
optimization only some agents honor. Agents differ: Claude Code follows `@` imports
recursively, Codex has no import syntax and concatenates only files *named* `AGENTS.md`.

**A tier that is declared but not wired is a control that does not exist.** If you add a tier-0
file, wire it and say how it loads — do not write it into this table and assume a mechanism.

**And then go and read the actual area.** The doctrines tell you the shape of the work; they
do not tell you the domain. Once the matching doctrine is open, the next move is research on
the surface in front of you — the spec section, the substrate's real behavior, the sibling
implementation's source — **read canonically, per D12, never from a summary of a summary.**
