# Findings and escalation — keystone memory

Authoring a finding that survives review: the false-negative family, negative claims, counts and the surface they range over, and verifying a routed claim in both directions.

**Arrive here when:** you are about to publish a count, a negative claim, or a correction to a counterpart.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- A RAW CONTROL BYTE IN A SOURCE FILE MAKES IT INVISIBLE TO EVERY GREP-BASED AUDIT — and the audit reports "absent", not "could not look"
- "THE SPEC DOES NOT SAY" IS A CLAIM ABOUT YOUR SEARCH, AND WE PUBLISHED ONE AS A CLAIM ABOUT THE SPEC — SEARCH THE SECTION THE BEHAVIOUR BELONGS TO, NOT THE WORDS THE QUESTION IS PHRASED IN
- RATIFIED, FIFTH OCCURRENCE OF THE FALSE-NEGATIVE CLASS AND THE FIRST THAT UNDERSTATES A CAPABILITY: A SURVEY KEYED ON A LIST YOU AUTHORED CANNOT SEE WHAT YOU DID NOT THINK OF, AND IT REPORTS "ABSENT" RATHER THAN "COULD NOT LOOK."
- RATIFIED — A NEGATIVE CLAIM ABOUT A SIBLING'S CORPUS IS THE SAME UNFALSIFIABLE SHAPE AS "THE SPEC DOES NOT SAY", AND WE SHIPPED TWO OF THEM IN ONE PACKET
- A GAP IN THE SPEC DOES NOT PRODUCE A GAP IN THE CODE — IT PRODUCES WHATEVER THE EXISTING BRANCH ALREADY DID, AND THAT BRANCH WAS WRITTEN FOR A DIFFERENT FRAME
- AN OPEN QUESTION IS AN UNFALSIFIABLE NEGATIVE WEARING A POLITE FACE — AND WE PUBLISHED ONE THAT THE SECTION OWNING THE *TYPE* HAD ANSWERED SINCE 0.8.1
- A BOUND ON A DEFECT'S REACH CAN BE ENFORCED BY A FUNCTION'S CALLER, NOT BY THE FUNCTION — so a sweep over the matcher cannot find it, and a refutation built from that sweep is refuting the wrong input space
- RATIFIED — A COUNT INHERITS THE SHAPE OF THE SEARCH THAT PRODUCED IT, AND THE SHAPE IS INVISIBLE IN THE NUMBER. THREE INSTANCES IN ONE AUDIT, THREE DIFFERENT MECHANISMS, TWO SEATS — AND ONE WAS OURS, RELAYED VERBATIM INTO A NORMATIVE PROPOSAL
- A SWEEP MUST RUN OVER BOTH MOODS — A CALL IS WRITTEN AS PSEUDOCODE WHERE IT IS IMPLEMENTED AND AS PROSE WHERE IT IS OBLIGED, AND A FOLD THAT CORRECTS ONE LEAVES THE OTHER MANDATING WHAT IT NOW FORBIDS
- A RULING THAT PINS ONE DISPOSITION ACROSS TWO CONFORMANT MECHANISMS RE-CREATES THE MECHANISM-SHAPED MUST IT JUST CORRECTED — THE STATUS CODE IS PART OF THE MECHANISM, NOT PART OF THE PROPERTY
- THE COHORT READ AN INDICATIVE SENTENCE AS A CONSTRAINT AND THREE GROUND-UP IMPLEMENTATIONS READ IT AS A DESCRIPTION — AND WHICH ONE YOU ARE BUILDING DECIDES IT, NOT THE MOOD
- WHEN A FIND-RATE STAYS FLAT ACROSS MANY FOLDS, STOP LOOKING FOR THE NEXT DEFECT AND ENUMERATE THE DECISION SPACE — THE RECURRING FINDING IS THE ABSENCE OF THE ENUMERATION, NOT N DEFECTS
- A SOURCE TRACE ACROSS SEVEN PEERS PRODUCED A CONFIDENT WRONG CONCLUSION, AND THE SPEC SECTION THAT OWNS THE BEHAVIOUR REVERSED IT IN ONE READ
- RATIFIED — A REVISION'S OWN NEW `[MUST]` IS SATISFIED ON THE ROWS IT WAS INVESTIGATING AND NOT ON THE SCOPE IT DECLARES, AND THAT IS THE `L23` CLASS POINTED AT ITS OWN AUTHOR
- WHEN A FINDING SAYS *NOBODY VALIDATES X*, THE FIX IS A RULE ABOUT WHO SUPPLIES X — AND DEMANDING A REFUSAL WHEN X IS WRONG PUTS BACK THE MECHANISM THE SAME REVISION JUST REMOVED
- A RULE STATED AS ARITHMETIC GETS IMPLEMENTED AS ARITHMETIC — and a count that is a correct CONSEQUENCE can be a hole as a PRIMITIVE, including one that removes a protection already in place
- A RECONSTRUCTED "BEFORE" THAT *BORROWS* FUNCTIONS FROM THE CURRENT TREE IS ONLY FAITHFUL IF THE BORROWED ONES DID NOT MOVE — AND THEY ARE NOT THE ONES A REVIEWER CHECKS
- A PATH SWEEP'S FALSE NEGATIVE IS THE DIRECTORY AS A SEPARATE STRING — VERIFY THAT PATHS RESOLVE, NEVER THAT THE OLD STRING IS GONE
- A RULE WITH TWO INDEPENDENT VARIABLES NEEDS A VECTOR AT THE CORNER — TWO CHECKS THAT EACH COVER ONE AXIS READ AS COVERAGE OF THE SURFACE, AND NEITHER CAN SEE THE INTERSECTION
- AN AUDIT'S SUMMARY CAN CONTRADICT ITS OWN TABLE, AND THE SUMMARY IS THE PART THAT GETS RELAYED

---

- **A RAW CONTROL BYTE IN A SOURCE FILE MAKES IT INVISIBLE TO EVERY GREP-BASED AUDIT — and the
  audit reports "absent", not "could not look".** RATIFIED 2026-09-01, two peers, same session.
  `dart/lib/src/peer/peer.dart` and `ruby/lib/entity_core/peer.rb` each wrote `"\x00"` as a
  **literal NUL byte** rather than the escape, in the same helper (`path_flex_ok?` /
  `_pathFlexOk` — a check for an embedded NUL in a path, correct at runtime). `file` calls both
  `data`; `grep` treats them as binary and, in a pipeline, prints nothing at all.
  **What it cost: the cohort-wide survey for the §1.4 gate put BOTH peers in the "no gate" bucket
  when both had one.** Acting on that would have added a second, redundant gate to each and
  published a wrong count of how many peers were missing the feature. Only the oracle caught it.
  This is the `vendor-unmatched` shape one level down — **a could-not-look that presents as a
  clean answer** — and it is the same reason `spec corpus --vendor` reports rather than passes.
  **Enforcement, and `grep -P '\x00'` is NOT it (it does not reliably match a NUL):** scan tracked
  files in Python — `b'\x00' in open(f,'rb').read()` — and treat any hit outside a declared data
  file as a defect. The full tree is clean apart from `cobol/src/core-types.dat`, which is data.
  **Generalize past NUL: before concluding a source-wide grep found nothing, confirm the grep could
  see the file.**

- **"THE SPEC DOES NOT SAY" IS A CLAIM ABOUT YOUR SEARCH, AND WE PUBLISHED ONE AS A CLAIM ABOUT THE
  SPEC — SEARCH THE SECTION THE BEHAVIOUR BELONGS TO, NOT THE WORDS THE QUESTION IS PHRASED IN.**
  RATIFIED 2026-09-01: **second occurrence of the false-negative class in two days**, and the pair
  is what earns it — the `dart`/`ruby` NUL byte above is a grep that **could not see** the file, this
  is a grep that **looked in the wrong vocabulary**, and both publish as a confident negative that
  reads identically to a real one.
  **F51** (`protocol-generator/shared/findings/peers-dimension-reachability.md`) was routed to arch
  on 2026-08-30 asking for a normative sentence on whether a core peer must resolve its own handler
  for a URI naming a FOREIGN peer's namespace. It states *"The spec answers this nowhere we can
  find"* — **four lines under a header citing `v0.8.2`, in which §1.4 line 300 reads *"the path MUST
  target the local peer's namespace. If the peer ID does not match the local peer, the peer MUST
  reject with status 400 (`invalid_request`)."*** Byte-identical in `v0.8.2.3`
  (`sha256(line) = 376953b9…`), i.e. it was in the snapshot we were building the whole cohort
  against.
  **The mechanism is dull and entirely reusable.** The search used the vocabulary of the QUESTION —
  `peers`, `target_peer`, `check_permission`, `extract_peer` — and the rule is written in the
  vocabulary of ADDRESSING. It contains none of those four terms. The finding even names where it
  expected the answer to be added (*"in §5.2 beside `extract_peer`, or in §6.6 beside handler
  resolution"*) and **never read §1.4, the section it is named after.**
  **Two things make it worse than an ordinary miss, and both are about direction.** (a) The finding's
  leading argument — the `peers` default is dead weight under the majority reading, *"the strongest
  argument we have that the minority of 6 is right"* — argued **against** settled normative text; it
  survived only because it was explicitly framed as an argument from construction rather than from
  the spec. (b) It is a **negative** claim, so nothing could contradict it: a wrong positive claim
  about the spec gets caught by the next person to read the cited line, while *"the spec is silent"*
  cites nothing and is never re-checked. It sat published for two days in the register, the matrix
  and `docs/STATUS.md`.
  **Say precisely what upstream did, because the flattering reading is available and is a second
  error.** 0.8.2.2/0.8.2.3 added the code NAME and the explicit prohibition on both wrong
  dispositions (§3.3's 400 table, §6.2's `handler_not_found` carve-out, §6.5 step 3's *"MUST NOT be
  reached by resolving a local handler … and letting §5.2 decide"*). **The MUST itself predates the
  finding.** So this is a WITHDRAWAL, not "arch resolved our ambiguity" — the sharpening is real and
  it is not what we asked for.
  **Enforcement, and it is a documentation rule rather than a grep, because a grep is what failed:**
  a finding that asserts a spec gap MUST record **which sections it read**, by number. That turns an
  unfalsifiable negative into a reviewable one — the next reader sees the hole instead of inheriting
  the conclusion — and it costs one line. Corollary for the cheap direction: **before claiming
  silence, read the section that OWNS the behaviour** (addressing rules live with addressing, not
  with authorization), and grep the spec for the *disposition* you would expect (`invalid_request`)
  as well as the *concept* — one `grep -c invalid_request` on `v0.8.2` returns 1 and it is the
  answer.
  *(Sub-lesson, measured the same session and worth its own line: **a WARN never meant a peer was
  safe.** `wasm-wat` WARNed on the retired check and still carried the defect — it refused, but by
  resolving locally and then failing authz. And **all six peers that PASSed the retired check needed
  the new gate**, which is not a coincidence: passing required exactly the behaviour §6.5 step 3
  forbids. A check whose PASS branch rewards a defect is worse than no check, and the oracle deleted
  it rather than re-pointing it.)*

- **RATIFIED, FIFTH OCCURRENCE OF THE FALSE-NEGATIVE CLASS AND THE FIRST THAT UNDERSTATES A
  CAPABILITY: A SURVEY KEYED ON A LIST YOU AUTHORED CANNOT SEE WHAT YOU DID NOT THINK OF, AND IT
  REPORTS "ABSENT" RATHER THAN "COULD NOT LOOK."** 2026-09-04, re-deriving the host contract's H4
  packaging survey. The four earlier members all *hid* something (`dart`/`ruby`'s NUL byte — a grep
  that could not SEE the file; F51 — the wrong VOCABULARY; the de-versioning sweep — a pattern that
  could not SPAN the construction; the `host.err` sweep — the right token in the WRONG BRANCH).
  **This one manufactures a false "nothing owed here"**, which is the direction nobody re-checks.
  The survey in circulation split the cohort **26 with a packaging unit / 20 that structurally
  decline**. Measured from each peer's own `[publishing]` block: **25 registry-published · 13
  source-vendored · 8 undeclared**, and **11 of 46 rows disagree**. Five peers that publish to a
  real registry were filed as declining — `fortran` (fpm), **`lean` (Reservoir via Lake, and it is
  an M1 peer)**, `prolog` (SWI-Prolog pack), `smalltalk` (Metacello), `unison` (unison-share).
  **The mechanism reproduced three times in one sitting, on me, while writing the correction**: a
  scan for `package.json Cargo.toml pyproject.toml …` missed `ada`'s `alire.toml`, then `lean`'s
  `lakefile.lean`, then `prolog`'s `pack.pl` — and `prolog`'s sources live in `prolog/prolog/`, so a
  source grep scoped to `src/` returns nothing for it either. Every miss printed a confident row.
  **Enforcement: derive a cohort survey from the tree's OWN declarations — `profile.toml`, the
  roster, a manifest the peer authored — never from an inventory of names you wrote down.** A peer
  with no declaration is then a *reviewable gap*; under a filename list, "declines" and "the
  surveyor had not heard of this package manager" are the same output. Corollary, and it is the
  cheap tell: **a survey whose misses all fall on the unfamiliar members is not noisy, it is
  measuring your familiarity.**
  **Sub-lesson, and it is a design rule rather than a grep: A REQUIREMENT CAN CONFLATE TWO
  INDEPENDENT AXES, AND THE COHORT IS WHERE YOU FIND OUT.** H4 reads *"usable as a library and not
  only as a standalone binary"* — which is really *(a) is there an in-process construction surface*
  and *(b) is there a distribution unit*, and peers answer them **opposite** ways: `c` has no
  registry and is the most library-shaped artifact in the tree (`.a` + `.so` + `make install` + a
  `.pc`, pkg-config being C's actual distribution convention), while `node-red`/`turbowarp` ship a
  `package.json` and are **applications**. A single `host | declined` field gets both wrong, in
  opposite directions. Detail: `protocol-generator/shared/evaluations/extension-host-packaging-boundaries.md`.

- **RATIFIED — A NEGATIVE CLAIM ABOUT A SIBLING'S CORPUS IS THE SAME UNFALSIFIABLE SHAPE AS "THE SPEC
  DOES NOT SAY", AND WE SHIPPED TWO OF THEM IN ONE PACKET.** 2026-09-04. The F51 rule already covers
  *"the spec is silent"*; this is its second surface — *"we do not find this anywhere in your ledger or
  your proposal"* — and it is worse in one respect: a spec is one corpus you can enumerate, while a
  sibling's ledger, proposals, guides and routing packets are four, and nobody re-reads a claim that
  something is ABSENT. `HANDOFF-TO-ARCH-2026-09-04` §2 opened with exactly that sentence about the
  `EXTENSION-COMPUTE` builtins/D1 interaction. **It is in the proposal** — `PROPOSAL-EXTENSION-HOST-
  INSTALL-SEAM.md` §7's homes table rules it explicitly (*"no edit needed, it is scoped to
  bootstrap-registered builtins and stays true under D1"*). §3b asked whether the frozen compute
  corpus is owed publication; **`GUIDE-CONFORMANCE` §7c answers it in the section we were quoting**,
  and more sharply than we asked (*"built, cross-blessed, and homeless"*). Both withdrawn at sign-off,
  struck in place rather than deleted.
  **The mechanism is F51's exactly and it is worth naming twice: we searched the vocabulary of the
  QUESTION, not of the DOCUMENT that owns the answer** — and in §3b we did not read to the end of the
  section we were citing. **Enforcement, and it is the F51 rule with its scope widened: a finding that
  asserts an absence in ANY corpus — the spec, a sibling's ledger, a sibling's proposals — must record
  which documents it searched, by name.** One `grep -rn builtins docs/proposals/active/` would have
  stopped this leaving the tree. Corollary for outbound packets specifically: **the exculpatory and
  the accusatory halves fail differently — an "already handled, nothing owed" is checked by the
  recipient, a "you have never addressed this" lands as a correction to them and is checked by nobody.**
  *(The re-resolution that caught both is the standing rule paying out for the third time —* record the
  sibling HEAD an audit was taken against and re-resolve it at SIGN-OFF, not at audit time. *Drafted
  against arch `06904ab`, signed off against `7792f61`, twenty commits later, and the delta withdrew
  two of the packet's four asks. Budget the re-resolution; it is not optional and it is minutes.)*

- **A GAP IN THE SPEC DOES NOT PRODUCE A GAP IN THE CODE — IT PRODUCES WHATEVER THE EXISTING BRANCH
  ALREADY DID, AND THAT BRANCH WAS WRITTEN FOR A DIFFERENT FRAME.** RATIFIED 2026-09-10, and it is
  **A1 missed on a security clause by the seat that keeps quoting A1.** Our F66 sub-item said a
  K-of-N-rooted credential *"cannot be classified as presented authority and falls back to the
  ambient arm — under-acceptance, not a hole."* It was a **live over-acceptance in `entity-core-go`,
  `entity-core-rust` and `entity-core-py`**, found by `go` building it. §5.5's root-granter check has
  a multi-signature branch — correct for its original purpose, a peer verifying its **own** group
  root, where the frame is the **local** peer — and `0.8.2.18` repurposed that frame to the
  **target**. Neither rule is wrong alone; **they composed into a hole.**
  **We reasoned from what the text UNDERDETERMINES to what an implementation would therefore do, and
  never opened a `verifyRootGranter`.** That inference is always unsound: an undefined case does not
  reach a well-marked "undefined" branch, it reaches whatever branch already matches, and the
  question is only ever *which existing code claims this input*. **Enforcement: a finding that says
  a spec gap is benign must cite the implementation line that makes it benign** — file and symbol,
  in at least one artifact. A claim about behaviour with no `file:line` under it is a claim about
  the text, and those two are different findings with different severities.
  **The generalizable half is arch's and it is worth carrying verbatim: changing what a shared
  parameter MEANS re-scopes every check that reads it, and those readers are listed nowhere.**
  Before repurposing a frame, a peer id, a "local" argument — enumerate its readers. Every prior
  instance in this arc was one rule with a home nobody found; this is **two correct rules whose
  composition nobody enumerated**, which is a new shape and the harder one to grep for.
  *(Two sub-lessons from answering it. **A mechanism sentence in a "transferable lesson" paragraph is
  what other implementers self-check against, so its precision is load-bearing** — arch's said the
  branch accepts a root when the frame peer is *"merely among the signers"*; `go` also requires a
  verified signature, so the real tell is a **co-signed** root, and someone testing
  listed-but-unsigned finds it correctly refused and wrongly concludes they are clean. And
  **a correction can land in the rule and miss its own restatement**: `05b7f74` fixed §1.4 in three
  lines and left §9.1's conformance floor — the section a new implementation builds from — still
  publishing the withdrawn conditional. Check the floor, the summary and the index whenever a rule
  moves; that is this file's own harden-one-anchor rule, and it caught arch the day after it caught us.)*

- **AN OPEN QUESTION IS AN UNFALSIFIABLE NEGATIVE WEARING A POLITE FACE — AND WE PUBLISHED ONE
  THAT THE SECTION OWNING THE *TYPE* HAD ANSWERED SINCE 0.8.1.** RATIFIED 2026-09-10, and it is the
  F51 class in its third shape. F51 was *"the spec does not say"*; the `HANDOFF-TO-ARCH-2026-09-04`
  pair was *"we do not find this in your corpus"*; this one is **"does rule X reach surface Y?"** —
  which reads as diligence, routes as an ask, and is the same claim about our own search.
  **F50** asked whether F40's id-scope pin reached `scope_subset`, reasoning *"F40 names
  `matches_scope` only; `scope_subset` is pattern-vs-pattern, not value-vs-pattern."* §3.6's
  id-scope grammar paragraph — **in our own pinned snapshot, four lines above the table we were
  quoting** — ends *"An implementation on the canonicalizing reading is **non-conformant** and MUST
  adopt the literal matcher."* It binds the **scope type**, not a function. There was never a
  question.
  **The mechanism is F51's exactly, one level up: we searched the vocabulary of the FUNCTION a
  prior finding named, instead of the section that owns the TYPE.** F40 said `matches_scope`, so we
  looked at call sites of `matches_scope`; the obligation is written about *id-scope patterns*, and
  a grep for the function cannot see it. **Enforcement, and it is the F51 rule with its scope
  widened again: a finding that asks whether a rule REACHES a surface must record which sections it
  read, by number — and must read the section that owns the TYPE of the thing being matched, not
  only the one that owns the function doing the matching.**
  **Two consequences worth holding separately.** (a) **The cost was mis-stated in the flattering
  direction**: we recorded the eventual fold as *creating* cohort work, when the truth is our 46
  peers were **non-conformant against the spec we are pinned to**, at `778 · 0F`, for as long as
  the grammar has existed. *"Behind a ruling"* and *"non-conformant at your own pin"* have different
  owners and different urgency, and the first is what an open question turns the second into.
  (b) **`entity-core-formalization` found it independently, graded it correctly, and got there by
  checking our PIN first** — their own finding was weaker until they confirmed the rule was in text
  we had already adopted. Recorded as corroboration with the same weight as a catch; **checking the
  receiving seat's pin before grading a divergence is a rule worth taking from them.**

- **A BOUND ON A DEFECT'S REACH CAN BE ENFORCED BY A FUNCTION'S CALLER, NOT BY THE FUNCTION — so a
  sweep over the matcher cannot find it, and a refutation built from that sweep is refuting the
  wrong input space.** Candidate (first occurrence, 2026-09-10, enforcement exact). Refuting a
  routed refutation: a sibling withdrew a published bound (*"both divergences need a leading `/`"*)
  on the witness `operations: ["*/apply"]` admitting `["compute/apply"]` — ordinary namespaced
  operation names, no leading slash, and it looks decisive. **§5.4 `canonicalize` rejects `*/`
  outright** — *"Reject bare peer wildcard — ambiguous without leading /"* — so the pattern never
  reaches a matcher under EITHER reading, and §5.4's `matches_pattern` has no interior segment
  wildcard to match it with anyway. The witness fails twice before the defect is reachable.
  **The withdrawn bound was not only correct, it was STRUCTURAL and neither side had said so:**
  `canonicalize` refuses `*/`-leading patterns by construction, so `/*/rest` is the only
  peer-wildcard form that can ever reach a matcher, and it carries the leading `/`. That is a
  theorem about the canonicalizer, not a generalization from the two rows that happened to diverge
  — which is what both the original claim and its retraction were.
  **Enforcement: when probing the reach of a defect in function `F`, enumerate what `F`'s CALLERS
  reject before `F` runs. The input space of `F` is not the input space of the system**, and a
  `#eval`-style sweep over `F` alone will manufacture witnesses that cannot occur. **And measure a
  refutation the same way you would measure a claim** — this one took lifting the peer's own
  `canonicalize`/`matches_pattern`/`scope_subset` and running five cases, three of them controls;
  the controls are what proved the instrument rather than the conclusion.

- **RATIFIED — A COUNT INHERITS THE SHAPE OF THE SEARCH THAT PRODUCED IT, AND THE SHAPE IS INVISIBLE
  IN THE NUMBER. THREE INSTANCES IN ONE AUDIT, THREE DIFFERENT MECHANISMS, TWO SEATS — AND ONE WAS
  OURS, RELAYED VERBATIM INTO A NORMATIVE PROPOSAL.** 2026-09-11, reviewing arch's `0.8.2.20` draft.
  The false-negative family already in this file is about a search that *could not see* its target
  (a NUL byte, the wrong vocabulary, a pattern that could not span the construction). **This is its
  arithmetic half: the search saw everything it looked at, and what it looked at was the wrong
  population.** All three published as a bare integer, which is the form that carries no provenance.
  - **MEMBER OMISSION — a claim of the form *"A and B do X; C and D do Y"* over a FIVE-member cohort
    names four and leaves the fifth to be inferred.** Ours. `f68-caller-exclude-wire-census.md`
    published *"`ocaml` and `python` have no arity check … `csharp`, `typescript` count"*, and
    **the generated `go` has the identical defect** (`handlers.go:231-243` tests `len(targets)==0`
    then returns `targets[0]`). Three, not two — and the missed member is in the reproducing set,
    because the head selection is *why* it reproduces. Nobody re-read it: the sentence is
    well-formed, the four it names are correct, and the fifth is absent rather than wrong. It was
    relayed into `entity-core-protocol` `564055f` §6 and two architecture packets before being
    re-derived. **Enforcement: enumerate every member of a cohort BY NAME, including the ones the
    claim is not about.** A cohort sentence that does not sum to the roster is a defect regardless
    of whether its named members are right.
  - **LINE COUNT vs SITE COUNT, and a CROSS-REFERENCE IS NOT A RAISE.** Arch's. The proposal states
    *"`EXTENSION-ROLE` raises `malformed_resource` at five sites"*; the document contains **three**
    occurrences, of which **one** is a `return error(...)`, one is prose stating the rule, and one is
    a comparison *about a different code*. The five is a `grep -rn` returning five LINES across
    **three documents**, one of them arch's own `DESIGN-REGISTER`. **Enforcement: `grep -c` counts
    lines and `grep -o | wc -l` counts occurrences, and NEITHER counts sites** — classify each hit as
    raise / statement / citation before it becomes a number in a normative document.
  - **A SENTENCE-SHAPED SWEEP CANNOT FIND A BLOCK-SHAPED RESTATEMENT.** Arch's, and it is their own
    `L23` pointed back at them. `G4` withdraws a characterization at **three** sentences; it occurs
    at **seven** places, and the four unswept ones are §9.1 MUST Implement, **two pseudocode comments
    inside the very block that implements the rule**, the layer table, and a second occurrence on
    `G4`'s own cited line. The proposal's whole argument is that *the block is what gets implemented
    and the prose beside it is not* — and the sweep took the prose.
  **The common enforcement, and it is one line rather than three: publish the SURFACE a count ranges
  over, never the count alone** — *"N sites, in documents X/Y/Z, classified as raises"*. That is the
  `abi_differential` *"71/71 over 19 of 27 symbols"* rule generalized off harnesses and onto prose,
  and each of the three above is caught by it. **Corollary, measured twice here in one day:
  recomputing a supplied inventory is minutes and the diff is always the question worth asking** —
  arch's `22 targets[0] sites across 5 documents` recomputes to **28 across 7**, the extra two being
  `guides/`, i.e. the sweep was scoped to `specs/` while the mechanism it serves (*a function
  nameable in the pseudocode both sides copy*) lives or dies on the guides. **A scope boundary is
  the most common reason a diligent count is wrong, and it never appears in the count.**
  *(Sub-lesson, and it is the standing "check the floor, the summary and the index whenever a rule
  moves" rule recurring at the SHORTEST possible distance: §9.1's conformance floor was missed again,
  in the same arc, four commits after the seat recorded the lesson about missing §9.1. **A lesson
  written down in a status doc is not an enforcement point.** The floor is where a new implementation
  builds from, so it is the site whose staleness costs the most and the one a sweep reaches last —
  put it FIRST in the sweep order, not last.)*

- **A SWEEP MUST RUN OVER BOTH MOODS — A CALL IS WRITTEN AS PSEUDOCODE WHERE IT IS IMPLEMENTED AND AS
  PROSE WHERE IT IS OBLIGED, AND A FOLD THAT CORRECTS ONE LEAVES THE OTHER MANDATING WHAT IT NOW
  FORBIDS.** RATIFIED 2026-09-13 reviewing the `K1`–`K6` proposal — **third occurrence in one arc, and
  this one is `L23`'s mirror.** `L23` (ours, at `0.8.2.20`) was a *sentence*-shaped sweep that could
  not find a *block*-shaped restatement; here a **block-shaped sweep missed the sentence-shaped ones**.
  `K5` rules `handler_pattern` REQUIRED and names **3 of 8** three-argument call sites; of the five it
  misses, **three are normative MUSTs** (`EXTENSION-COMPUTE` `:2178` `:2196`, `EXTENSION-REVISION`
  `:3966`) that write the forbidden short form *inside the obligation*, plus a fourth pseudocode site
  in a document nobody was looking at (`EXTENSION-TRANSACTION` `:324`). **Enforcement: classify every
  hit as pseudocode / normative prose / definition / citation before it becomes a number**, and state
  the surface the count ranges over — the `abi_differential` rule, applied to a corpus.
  **AND THE ENFORCEMENT GREP THAT SHIPS WITH SUCH A SWEEP IS THE NEXT THING TO MEASURE, BECAUSE A CALL
  SITE WRAPS.** `K6`'s proposed gate — `grep -rn "check_path_permission(" | grep -v "system/tree"` —
  returns **13 hits today and ~9 post-fold against a claimed 2**: 4 of 9 sites carry the frame on the
  *continuation* line, so they fire forever **including after the fix**, and the two survivors it names
  live in a different repo than the one the command scans. **Fifth time in these two trees that a
  per-line scan has missed or manufactured a hit on a wrapped construct** (after `README.md`'s wrapped
  backtick span, `coherence-gate`'s wrapped pin clause, `link-gate`'s wrapped citation, and the
  de-versioning sweep). **Scan the JOINED text; recover the line number from the match offset** — and
  before proposing a gate, RUN it and compare the output to the postcondition you claimed, because a
  gate whose stated answer is 2 and whose real answer is 9 is switched off in a week.

- **A RULING THAT PINS ONE DISPOSITION ACROSS TWO CONFORMANT MECHANISMS RE-CREATES THE
  MECHANISM-SHAPED MUST IT JUST CORRECTED — THE STATUS CODE IS PART OF THE MECHANISM, NOT PART OF THE
  PROPERTY.** Candidate (first occurrence, 2026-09-13, `K1.7`; enforcement exact). The proposal gets
  the hard half right — *resolve authority only through a verified address*, stated as a **property**
  with two conformant mechanisms, explicitly because the mechanism-shaped wording would have specified
  the one structurally-immune seat into non-conformance — and then, **one paragraph later**, pins a
  single disposition (`AUTHZ_DENY`, with 401 declared non-conformant) for the violation. Under
  mechanism 2 (discard the key, address by validated `content_hash`) a forged **author** entry is not
  *detected* anywhere; the lookup simply **misses**, and §5.2a's landed normative table already answers
  that miss — *"Author not in envelope `included`" → **401** `authentication_failed`*, the value just
  declared non-conformant. **A uniform verdict is reachable only by mechanism 1, because mechanism 2
  has no single site to attach one to.** The general form: **when a rule admits N mechanisms, every
  observable consequence of violating it — status, code, which layer refuses — is a property of the
  mechanism unless the rule also fixes the detection point.** Enforcement: for each conformant
  mechanism named in a ruling, trace the violation through it and write down what the wire shows; if
  the answers differ, the disposition is per-site or the mechanism list is a fiction. *(Sub-lesson,
  and it is the standing "a check can pass for the wrong reason" rule from the other end: the seat
  being asked to change its status chose the auth class **deliberately**, and its own forgery test
  asserts that class specifically **in order to discriminate between two guards**. Before asking a
  seat to change a disposition, read what its test uses the disposition FOR.)*

- **THE COHORT READ AN INDICATIVE SENTENCE AS A CONSTRAINT AND THREE GROUND-UP IMPLEMENTATIONS READ IT
  AS A DESCRIPTION — AND WHICH ONE YOU ARE BUILDING DECIDES IT, NOT THE MOOD.** Recorded 2026-09-13,
  `K1` (the `included`-map-key forgery: every §5.2/§5.5 authority lookup resolves an entity **by
  wire-supplied key**, nothing bound the key to the value, so an attacker who knows a victim's identity
  hash files their own `system/peer` under it and is attributed the victim's authority). The invariant
  is stated **five times in the corpus, all indicative** (§3.1, `ENTITY-CBOR-ENCODING` §5,
  `ENTITY-NATIVE-TYPE-SYSTEM` §1057, `EXTENSION-QUERY` §473, `EXTENSION-REVISION` §938) and **never as
  an obligation** — and it was live at two of three ground-up seats. **At least 33 of our 46 peers
  already enforce it at the envelope decode boundary, most citing §3.1 in the source** (`go`
  `model.go:222` — and its `EntityOfCbor` *recomputes* the hash and trusts the recomputation over the
  carried bytes, which is the stronger property; `rust` a dedicated `IncludedKeyMismatch`; `c`/`cpp`
  *"§3.1 (N5): the included key MUST equal the entity's content_hash"*). **The reason is not that we
  are more careful: a peer generated from the schema builds a DECODER, and a decoder reads "keyed by
  content hash" as a constraint it must maintain, while a verifier built from §5.2 has no reason to
  look at §3.1 at all.** That is the sharpest argument this repo has produced for *where* an obligation
  belongs, and it is worth reaching for whenever a rule is being homed.
  **Say the limits, because this is the flattering direction and nobody re-checks those.** It is a
  **source read, not a drive** — the number is `unknown` until a probe drives it, and **the probe is
  owed** (mis-keyed `author`, `capability`, chain `granter` and `grantee` independently, positive
  control per peer). It is **one generation lineage** — 33 peers agreeing is cohort-consistent; the
  honest comparison is four lineages against three, not thirty-six against three. **And the survey
  under-reported itself three times in one sitting** — keyed first on filenames we chose (missed 14),
  then on one phrasing of the error string (missed 6), then on a second phrasing, because `c` and `cpp`
  write *"MUST equal"* where everyone else writes `!=`. **Every pass printed a confident
  classification**, which is the false-negative family's arithmetic half arriving three times in an
  hour: the 10 still-unclassified peers are *"could not look"*, not *"absent"*.

- **WHEN A FIND-RATE STAYS FLAT ACROSS MANY FOLDS, STOP LOOKING FOR THE NEXT DEFECT AND ENUMERATE
  THE DECISION SPACE — THE RECURRING FINDING IS THE ABSENCE OF THE ENUMERATION, NOT N DEFECTS.**
  Candidate (first occurrence, 2026-09-12, `tools/scope-cell-table.py` +
  `shared/findings/scope-algebra-cell-census.md`; enforcement exact). Twenty-one `0.8.2.x`
  revisions in twelve days moved almost nothing but ten functions of the §5 scope algebra, and
  every finding across four seats had one of three shapes: *this cell says A here and B there* ·
  *this cell is unreachable* · *the sweep covered 3 of 7 sites*. Enumerated from the pseudocode:
  **146 live cells, 37 with a named vector**, and **every finding of the arc landed in a
  zero-coverage region** — while **F40, the one cell family that got vectors, is the one that
  closed and stayed closed.** That correlation is the diagnosis, and unlike *"the find-rate is the
  instrument, not the disease"* (true when written for newly-instrumented OLD surfaces, carried
  four weeks past its evidence onto text the cycle itself authored) **it is falsifiable**: the
  census publishes the prediction that the next finding lands in one of its four zeros.
  **Three things generalize past this arc.**
  - **THE REDUCTION IS THE VALUABLE HALF, NOT THE COUNT.** A naive product said 640; the space is
    146, and the single biggest factor is that **scope type is FIXED by the dimension and is not a
    free axis** (−320). Enumerating forces you to find that out. And the residual −126 named the
    *generator* in one sentence — `resources` is the only dimension whose subject is a
    set-with-exclusions rather than a value — which is what makes the next revision able to
    predict where it will need to look instead of discovering it.
  - **A COVERAGE TABLE MAPPED BY NAME FAILS IN BOTH DIRECTIONS FROM ONE MIS-ASSIGNMENT.** Filing
    `chain_parent_exclude_drop_denied` under the L1 caller-exclude arm (it drives the L3 delegation
    link) simultaneously reported a **false ZERO** on exclude-inheritance and a **false COVER** on
    the F68 arm. So a coverage claim is `unknown` until a harness drives it — the standing rule —
    and the cells that survive being wrong about the mapping are the ones worth publishing: here
    the four zeros hold either way, because no check in the set names that layer or dimension *at
    all*.
  - **THE INSTRUMENT NEEDED THE EXAMINED-ZERO-THINGS RULE TWICE IN ONE SITTING, AND ONLY THE
    PRINTED COUNTS CAUGHT IT.** The first cut reported `structurally dead 0` from two classifier
    branches that could not fire (the space already excluded them by construction — better design,
    dishonest reporting). The reduction rows then summed to 172 against an enumeration of 146.
    **Fix both the same way: stage each reduction from the one above and ASSERT CLOSURE, plus a
    non-zero assertion per stage** — a reduction that stops removing anything is a rule the code no
    longer implements, sitting there reading as load-bearing.
  **And the finding it surfaced is the shape to expect from this method: `matches_scope` dispatches
  on a `scope.type` read off the RECEIVED ENTITY while all 46 peers supply it from the call site,
  and nothing validates that value against the dimension anywhere** (§6.3, M3,
  `verify_capability_chain` and §5.6's relative child-vs-parent check all read, not assumed) — **F72,
  cohort cost zero.** Four seats reviewing §5 for twelve days could not see it because **the two
  readings agree on every well-typed grant**; only a table that asks each cell *what decides this,
  and who supplies it* separates them. **A defect invisible to every reading is visible to an
  enumeration, and that is the whole argument for building one.**
  - **A section headed "Current state" was anchored to a pin retired three flips earlier**
    (`CONFORMANCE-MATRIX.md` §4, `2026-08-30 @ the 755-check pin`, while §1 published `778`).
    `coherence-gate` is scoped to §1's rows and the 46 per-peer banners, so §2–§4 prose can go
    stale with every gate green. The table's contents were still TRUE — they record when each tier
    FIRST closed — so the fix is to say which question the table answers, not to back-date it.
  - **A HANDOFF-FROM-ARCH doc HAS NEVER EXISTED — `git log --all` on it is empty — and it was
    cited from `protocol-generator/shared/lifecycle/PROMPT-CONSTANTS.md`, which PUBLISHES.** Both
    link-gate checks are structurally blind to it: check 1 resolves markdown links in the
    bracket-then-parenthesis form and this is a **backticked inline path**, check 2 fires on
    non-prose citations only. **[ADR-0021]'s own
    follow-up list names it** — *"keystone HANDOFF-FROM-ARCH-v1 → non-HANDOFF name"* — having
    assumed it existed and needed renaming off a scrubbed prefix. It did not need renaming; it
    needed deleting, and the sentence it anchored was redundant with line 31 of its own file.
  **Three things generalize, and the second is a correction of this entry's own first draft.**
  (a) **A dangler that never existed cannot be found by any diff, any rename sweep, or any tool
  that reasons from history — only by resolving the path.**
  (b) **THE OBVIOUS GATE DOES NOT SURVIVE THE TREE, AND MEASURING IT IS WHAT SAID SO.** This entry
  first prescribed "harvest every backticked `.md` and stat it" as a link-gate check 3. Measured:
  **863 candidates → 318 unresolved**, because root-relative shorthand (`status/PHASE-S2.md` means
  *this peer's*) is correct prose and unresolvable by construction; scoping to repo-rooted paths
  gives **418 → 38**, and even those carry an irreducible ambiguity because **`docs/` is a top-level
  directory here AND in every sibling**, so the generator's `docs/spec/…` is indistinguishable from
  ours by path alone. That is the standing *"a check that cannot separate its signal from its noise
  is broken, not weak — scope it or drop it, and say which"* rule applied to a gate **I had already
  written into this file**. It ships as a probe with its triage in its own docstring
  (`shared/diagnostics/backticked-path-resolution-probe.py`), not as an eleventh-and-a-half gate.
  (c) **THE DISCRIMINATOR IS NOT "DOES IT RESOLVE" — IT IS LIVE INSTRUCTION vs PROVENANCE.** Of the
  38, one was a live instruction (*"escalate per `X`"*) and was fixed; **~15 are `research/RELEASE-
  READINESS.md`, a peer-selection slate that also never existed here**, cited by four peers' dated
  phase records — and those were deliberately NOT rewritten, because a dated snapshot that gets
  back-edited stops being evidence of anything. Sweeping the two together would have destroyed
  fifteen records to fix one pointer. **Fix what points a reader somewhere on purpose; leave what
  records what was believed on a date.**
  (d) **An ADR follow-up item is a claim about the tree with no gate on it** — this one was wrong
  about the defect's nature for two months and nothing re-read it. When an ADR names a known defect
  in your repo, resolve it or record why it is still open; an unactioned follow-up reads as tracked
  and is not.

- **A SOURCE TRACE ACROSS SEVEN PEERS PRODUCED A CONFIDENT WRONG CONCLUSION, AND THE SPEC SECTION THAT
  OWNS THE BEHAVIOUR REVERSED IT IN ONE READ.** Same session, and it is the F51 rule paying out in the
  *positive* direction for once. Tracing all seven `NOT-RESOLVED` peers showed dispatch resolving
  through a static op ladder, a pattern ladder or a bootstrap-only table, and **none of the seven
  mentions `expression_path` anywhere in its source** — from which the obvious conclusion is *"a
  missing extension feature, not a defect; the previous session's ranking was wrong."* That was drafted.
  Then §6.6 was actually opened: the walk is the definition, the index is the optimisation, and
  equivalence is a MUST. **The peers are failing a core requirement, the previous session's ranking was
  RIGHT, and the draft was one section away from publishing the opposite.** The cost of reading it was
  one `awk`. **Rule, and it is the cheap direction of the F51 lesson: before concluding that a measured
  behaviour is permitted, read the section that OWNS it — not the section your hypothesis is phrased
  in.** A source trace tells you what the code does; only the spec says whether it may.

- **RATIFIED — A REVISION'S OWN NEW `[MUST]` IS SATISFIED ON THE ROWS IT WAS INVESTIGATING AND NOT ON
  THE SCOPE IT DECLARES, AND THAT IS THE `L23` CLASS POINTED AT ITS OWN AUTHOR.** 2026-09-16, auditing
  `0.8.2.31`. The revision adds *"a row here that restates a rule stated elsewhere NAMES that section as
  its normative home `[MUST]`"* plus *"a fold that changes a rule edits every row naming it, in the same
  commit"* — and it lands having done that for the **two rows it was investigating**. Measured over §9.1
  as vendored: **70 rows · 22 assert a rule AND cite a section · 8 name an authority relationship · 14
  name none**, with three of the 14 opened and confirmed as restatements whose home is the cited section
  (the `effective_targets` subject rule lives in §3.3's 400 row; the tree-listing filter in §6.3/§6.8;
  the unimplemented-operation row in §3.3's 501 row, which §6.2 names as the authority in those words).
  **The revision itself states the diagnosis:** the `0.8.2.22` fold *"enumerated its homes as §6.3's
  three sites and §6.8's table; there were four, and the fourth is this list."*
  **Two things generalize, and the second is about our own instrument.** (a) **When a rule is about a
  CLASS OF ROW, the fold's scope is the class, not the instances that prompted it** — and a `[MUST]`
  satisfied on 36% of its own scope on the day it lands is indistinguishable, to the next reader, from
  one nobody has applied. (b) ⚠ **THE DISCRIMINATOR MUST ACCEPT EVERY SPELLING OF THE CONVENTION
  BEFORE THE COUNT IS PUBLISHED.** My first scan keyed on the literal phrase `normative home` and
  counted **6**; broadening to eight spellings (`is the authority`, `§N wins`, `§N governs`, `RESTATES`,
  `where they differ`, …) counted **8**. The narrow scan would have overstated the defect by two rows —
  the false-negative family's arithmetic half, arriving in the instrument built to measure somebody
  else's. **Report the surface the count ranges over, including how many spellings the discriminator
  accepts.**

- **WHEN A FINDING SAYS *NOBODY VALIDATES X*, THE FIX IS A RULE ABOUT WHO SUPPLIES X — AND DEMANDING
  A REFUSAL WHEN X IS WRONG PUTS BACK THE MECHANISM THE SAME REVISION JUST REMOVED.** RATIFIED
  2026-09-14 (third instance in three days, and the third one is **ours**). F72 found that the §5
  scope type is specified as a value read off the received entity while all 46 peers supply it from
  the call site, and asked for two things. Clause 1 — *the type is a property of the DIMENSION,
  supplied by the call site* — is right and costs zero. **Clause 2, which our own tracker row asked
  for in these words (*"plus a malformed disposition for a scope whose declared type contradicts its
  dimension"*), obliges every implementation to PARSE a field clause 1 has just told it to ignore**:
  an implementation that ignores `scope.type` completely — the one clause 1 calls correct — cannot
  detect the contradiction at all. **Measured on the wire: `200` on 38 of 38, `403` on zero, and the
  no-`type`-at-all differential answered identically, so nothing in the cohort reads it in any
  direction; `entity-core-rust` has no scope object, `entity-core-py`'s has no `type` field, and
  `entity-core-go`'s grants are a struct of named dimensions.** So the population was not *2 of 3
  seats* but **~48 of 49 implementations**, and arch's fold notes and ours both said *"cohort cost
  zero"*.
  **The class, and it is why this is a rule rather than an incident:** `K1.5`/`K1.7` is the same
  shape (a property with two conformant mechanisms, then one pinned disposition that only mechanism 1
  can produce) and we caught it; this one arch caught and we caused. **Enforcement: for every ruling
  that names a mechanism-free PROPERTY, trace the violation through EACH conformant mechanism and
  write down what the wire shows. If the answers differ, the disposition is per-site or the mechanism
  list is a fiction** — and if a mechanism cannot even DETECT the violation, a disposition for it is
  a requirement to build the detector.

- **A RULE STATED AS ARITHMETIC GETS IMPLEMENTED AS ARITHMETIC — and a count that is a correct
  CONSEQUENCE can be a hole as a PRIMITIVE, including one that removes a protection already in place.**
  Candidate (first occurrence, 2026-09-10, enforcement exact). Arch's F68 ruling has two halves: a
  general rule (*a handler MUST NOT act on a target the authorization check SKIPPED*) and an arithmetic
  (*count the EFFECTIVE set; 0 -> `path_required`, >1 -> `ambiguous_resource`, 1 -> proceed*). Measured:
  `targets:[P,Q] exclude:[P]` with `Q` in-grant has effective set `{Q}`, size 1, so the arithmetic says
  **proceed** — and all three vulnerable peers **return `P`**, because the handler selects raw
  `targets[0]`. The count is fully satisfied and the bypass is untouched. Worse, the two peers that are
  currently SAFE on that arm are safe because of a **raw** arity check (`Count != 1 -> 400`), which the
  ruling replaces with an effective count of 1 — so implementing the arithmetic literally **opens** an
  arm that is refused today. **Rule: when a rule has a set-shaped half and a number-shaped half, state
  the SELECTION and let the count follow — implementers code the primitive, because it is three branches
  and a pseudocode block can express it.** The tell to look for: a ruling whose two halves would be
  implemented by different people in different files, where only one of them is load-bearing.

- **A RECONSTRUCTED "BEFORE" THAT *BORROWS* FUNCTIONS FROM THE CURRENT TREE IS ONLY FAITHFUL IF THE
  BORROWED ONES DID NOT MOVE — AND THEY ARE NOT THE ONES A REVIEWER CHECKS.** Candidate (first
  occurrence, 2026-09-16, verifying `entity-core-formalization`'s A-4 differential; enforcement
  exact). They transcribed two of our functions at a named commit, said so, and asked us to check
  the transcription — which is exactly right and is the ask we answered. **But `canonSegsPre` and
  `scopeSubsetPre` call `splitSegs` and `matchesSeg`, which the file does NOT transcribe: it takes
  them from the current tree it was built inside.** So the "before" is a HYBRID unless those two are
  byte-identical across the interval, and nothing in the file said whether they were. Measured:
  both unmoved (`3daa1bef718d`, `8c374edb1c12` at both commits) while the two transcribed functions
  did move — so the reconstruction is genuine and their result stands.
  **Enforcement: for any transcribed "before", list the symbols it CALLS but does not transcribe and
  hash each across the interval.** The two functions a reviewer opens are the transcribed ones; the
  two that can silently invalidate the whole differential are the others. Generalises past Lean to
  any differential harness built inside a copy of someone else's tree.

- **A PATH SWEEP'S FALSE NEGATIVE IS THE DIRECTORY AS A SEPARATE STRING — VERIFY THAT PATHS RESOLVE,
  NEVER THAT THE OLD STRING IS GONE.** Candidate, same session, and it is the third false-negative
  grep in this file after the `dart`/`ruby` NUL byte (a grep that could not SEE the file) and F51 (a
  grep in the wrong VOCABULARY). This one is a grep whose PATTERN cannot span the construction. After
  rewriting `test-vectors/v0.8.0/<artifact>` cohort-wide, `git grep 'test-vectors/v0\.8\.0'` returned
  one benign hit and read as done. **Eight harnesses were broken**, because they build the path from
  parts — `File.join(…, "test-vectors", "v0.8.0", "conformance-vectors.cbor")`,
  `Path.join(["..", "shared", "test-vectors", "v0.8.0", name])` — so the sweep rewrote the FILENAME
  (a single token) and left the directory element untouched, and no pattern containing a slash could
  ever match. `crystal` and `elixir` failed outright on the next run; `julia` would have.
  **The check that works is not a better regex.** Resolve every referenced path against disk and
  assert it exists — ~20 lines, runs in a second, and it is indifferent to how the string was
  assembled. Generalize: **after a mechanical rename, verify the POSTCONDITION (the new thing
  resolves), not the ABSENCE of the old token** — absence is a property of your pattern, existence is
  a property of the tree.
  **Two sub-lessons from the same sweep, both cheap and both mine:**
  (a) **A repo-wide sweep must EXCLUDE `spec-data/` by construction, not by remembering.** Mine
  rewrote two SHA-256-pinned boundary files; `make lint` caught it on the next run. This file already
  says *"after any repo-wide mechanical commit … re-verify the SHA-256 spec-data pins"* — that rule
  fired and worked, and this is its **second occurrence**, so the standard is now stricter: the
  exclusion goes in the sweep script's own exclusion list beside `docs/status/` and `docs/archive/`,
  and the pin check stays as the backstop rather than as the only control.
  (b) **`cmd | tail` in a verification loop reports `tail`'s exit code, not the command's.** My first
  agility sweep printed `rc=0` for five peers, two of which had failed outright (`ocaml`: target not
  found; `csharp`: NuGet restore failed). Same family as the gate that examined zero things — the
  loop was structurally incapable of reporting a failure. Use `${PIPESTATUS[0]}`, or do not pipe.
  **RATIFIED 2026-09-02 — second occurrence, and it was committed to this file between them.** The
  first probe of the peers with no S2 gate ran `podman run … "cmd | tail -30"` and reported `rc=0`
  for **all five**; every one had failed — `go` on a wrong working directory, `rust` unable to resolve
  a vendored crate, `python` with no pytest, `typescript` with two real failures, `swift` with a
  compile error. **A written-down rule did not prevent the identical mistake**, which is the argument
  for putting the check in the tool rather than in the prose: `tools/run-s2-sweep.sh` captures each
  gate's status with no pipe at all and says so at the line where it would be tempting. The tell is
  the shape of the result, not the code — **a batch in which every member passes is a claim to
  distrust before reading it**, especially when the members share no toolchain.

- **A RULE WITH TWO INDEPENDENT VARIABLES NEEDS A VECTOR AT THE CORNER — TWO CHECKS THAT EACH COVER
  ONE AXIS READ AS COVERAGE OF THE SURFACE, AND NEITHER CAN SEE THE INTERSECTION.** Candidate (first
  occurrence, 2026-09-07), and it is the first thing the first **Kind C** independent check found, on
  its first roster run. §4.7's 0.8.2.6 note is a table over two variables — connection *state*
  (pre-establishment / established) × *address* (own namespace / foreign) — and pins the corner:
  a pre-establishment EXECUTE naming a **foreign** namespace is `400 invalid_request`, **not** the
  `401 authentication_failed` the own-namespace row takes, because *"a 401 names a remedy that does
  not exist"* for an address no authentication state can fix. The oracle ships
  `execute_before_established_refused` (pre-establishment × own) and
  `dispatch_inbound_foreign_namespace_refused` (established × foreign). **A peer that evaluates
  authentication first passes both** — on the own-namespace input 401 IS correct, and on the foreign
  input it is already authenticated. Measured: **36 of 45 peers answer 401 (or, `sql`, 403) where the
  table pins 400**, every one of them at `756 · 0F`. The 9 that get it right are what make it a
  defect rather than a reading.
  **The diagnostic that generalizes is cheap: for any rule stated as a TABLE, enumerate the cells and
  ask which vector supplies each one.** Coverage is counted per check, and a check names one input;
  a two-variable rule has four cells and two checks can only reach two of them. Do this before
  concluding a surface is covered — "there are checks on this" is an answer about the axes.
  **A DIFFERENTIAL CONTROL MUST VARY EXACTLY ONE THING, AND MINE VARIED TWO — a control that cannot
  separate its own two explanations is not a control, it is a second copy of the case.** The finding
  is only reportable because a differential re-sends the same foreign URI on an ESTABLISHED
  connection: all 36 answer `400 invalid_request` there, so the address IS recognised and the
  ordering is the defect rather than our URI being malformed. **The first cut sent it UNSIGNED** —
  which answers `401 authentication_failed` on any address, because an EXECUTE with no verified
  signer is auth-class by §5.2a — so it returned the identical status to the case it existed to
  disambiguate and discriminated nothing. It read as "the peer does not recognise the URI", i.e. as
  *our* bug, which would have killed a true finding. **Before trusting a differential, name the two
  explanations it is separating and check that only one variable moved.**
  **AND "THE ORACLE HAS NO VECTOR FOR X" IS A CLAIM ABOUT *WHICH* ORACLE — ask the candidate, not the
  pin, whenever a re-pin is in flight.** Same session, and it withdrew half of this finding before it
  left the tree. The check also caught `501 operation_not_supported` (4 peers) and `401
  missing_author` (5 peers) — minted codes on a surface §4.7 declares a *"MUST-emit contract"* — and
  reasoning from the **pinned** oracle, where the covering checks do not exist, that read as a second
  coverage gap and was drafted as one. The **candidate** oracle catches both by name, asserting the
  code and not just the status (`unsupported_operation_on_registered_handler`,
  `execute_before_established_refused`), plus a third of the same class we never drove. So they are
  ordinary cohort debt the re-pin gates, and the honest report is **corroboration between two
  independently authored readings**, not an accusation. This is the standing *"verify the exculpatory
  half"* rule pointed at the accusatory half of my own draft, and it cost one `python3 -c` against a
  report the census had already written.
  *(Sub-lesson, cheap and it silently truncated a 46-peer run: **`nohup cmd &` inside a
  background-task runner exits IMMEDIATELY and the census is killed partway through.** The wrapper
  reports exit 0, the log ends mid-roster with no error, and 17 of 46 peers have JSONs — which reads
  exactly like a completed run of a smaller roster. Let the runner background it; do not background
  it twice. The leftover containers then produced `odin: script file read error: Permission denied`
  on the next run, which is the standing contention signature — a filesystem-permission failure is
  contention until proven otherwise, and it was.)*
  **CLOSED 2026-09-08 AT 46 OF 46, AND THE CLOSING IS A HARDER CLAIM THAN THE FINDING WAS:
  INDEPENDENT CONVERGENCE IS NOT EVIDENCE OF CORRECTNESS WHEN THE TEXT IS EXPLICIT.** The three
  ground-up implementations — `entity-core-{go,rust,py}` — and our own `go` peer, four separate
  lineages, all answered `401` on this row. This repo's standing warning is the opposite one:
  *"a cohort all passing one author's vectors is cohort-consistent, not independent convergence."*
  Here the convergence was genuinely independent **and on the wrong side of a table that names the
  status, the code, and its own reason in one paragraph**, with §1.4 supplying the MUST. Nine
  keystone peers already answered `400`, which is what made it reportable at all.
  **So the rule cuts both ways and the discriminator is the TEXT, not the tally**: agreement among
  implementations is evidence about a spec's SILENCE and evidence about nothing when the spec
  speaks. Where it speaks, AGENTS.md's boundary already decides it — *derive behavior from the
  spec, not from the oracle* — and the honest form of the report is the one used here: implement
  the text, say plainly that four independent implementations disagree, and route the vector ask
  rather than assume the answer. **State the reversal cost when you do it** (25 peers × a
  three-line hoist) so the decision stays cheap to unwind if arch rules the other way.
  **The propagation itself was one shape in 37 languages and that invariance is the evidence.**
  Every peer already HAD the gate, below the §5.2 verdict where it is unreachable for an
  unauthenticated caller — so this was an ORDERING change, not a feature, and the diff is
  hoist-plus-a-note in 33 of them. **Four needed a different shape and each reason is worth
  keeping**: `forth`/`smalltalk` had it one rung down (after authn rather than after authz, a
  smaller move); `pd` took a three-line canvas REWIRE that moves the single existing rung rather
  than adding a second; `prolog`'s lived in a clause reachable only on `allow`, and the old check
  is KEPT as a restatement so the two cannot drift; and `oz` was expressed as the FIRST BRANCH of
  the existing verdict chain rather than as a wrapping `if/else`, because wrapping meant +2 `end`s
  outside and −1 inside a run of eighteen contiguous `end` tokens. **On a substrate whose block
  structure the compiler checks by counting, prefer the edit that changes no counts** — binding a
  pure verdict one line earlier costs nothing observable and cannot be got wrong.
  **Verified the way the ratchet requires and the number is the point: 3 of 34 868 severities moved
  across all 46 tracked reports, all three the same documented `t1_1_concurrent_demux` timing flake,
  two against us and one for.** Reporting only the flattering one would have been the error this
  file records twice; none of the three was banked.

- **AN AUDIT'S SUMMARY CAN CONTRADICT ITS OWN TABLE, AND THE SUMMARY IS THE PART THAT GETS RELAYED.**
  Candidate (2026-09-13). A delegated audit of the generator's findings a–j reported *"7 hold as written,
  3 in part"* above a table with nine CONFIRMED rows and one PARTIAL; the 7/3 went into a user reply and
  a routing packet before a re-read of the rows caught it. This is "a count inherits the shape of the
  search that produced it" with the search being a summarizer. **Enforcement: recount a delegated
  verdict from its rows before it leaves the session** — it is one pass over ten lines.
