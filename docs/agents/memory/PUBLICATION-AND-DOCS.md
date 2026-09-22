# Publication and docs — keystone memory

The publication boundary: the keep-list, what a citation must resolve to, and how published prose rots while every gated number stays correct.

**Arrive here when:** a published document points at something a reader cannot open, or a number's anchor does not resolve.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- A REPRODUCE RECIPE THAT NAMES A BINARY THE REPO HAS NEVER CONTAINED IS A PUBLISHED NUMBER WITH NO EVIDENCE UNDER IT
- RATIFIED (fourth occurrence of the stale-input class, and the one that had ALREADY FIRED IN PUBLIC): an identifier is only a pin if it resolves for the audience the claim is published to. A commit hash never does. Publish the content digest
- `CANONICAL-DOCS.toml` IS A KEEP-LIST, NOT A SCRUB-LIST — undeclared means DELETED FROM THE PUBLIC TREE, and for months this repo's own header said the opposite
- THE ECOSYSTEM ADRs DO NOT PUBLISH — standing operator ruling, 2026-08-24. `docs/adr/ecosystem/` stays undeclared, all 33 strip, and that is the correct answer rather than a finding
- RATIFIED, FOURTH OCCURRENCE OF THE PUBLISHED-PROSE CLASS — A CITATION THAT NEVER RESOLVED IS INVISIBLE TO EVERY GATE, AND THE ONE WE HAD WAS NAMED IN AN ECOSYSTEM ADR TWO MONTHS AGO
- A MARKDOWN TABLE WHOSE HEADER DECLARES FEWER COLUMNS THAN ITS ROWS CARRY DROPS THE EXTRA COLUMNS AT RENDER — SILENTLY, IN THE CANONICAL REGISTER, FOR SIX FINDINGS AT ONCE
- NO GATE ASKS WHETHER THE PUBLISHED TREE IS INTERNALLY COHERENT — and every defect this release cycle was found by walking it by hand
- A PIN IS A CLAIM, AND THE SENTENCE THAT STATES IT ROTS WHILE EVERY GATED NUMBER STAYS CORRECT
- The findings PUBLISH; the escalation stays a draft
- `AGENTS.md` GROWS BECAUSE IT IS THE ONLY FILE WHOSE NAME INVITES IT — A CLEANUP IS NOT A FIX

---

- **A REPRODUCE RECIPE THAT NAMES A BINARY THE REPO HAS NEVER CONTAINED IS A PUBLISHED NUMBER
  WITH NO EVIDENCE UNDER IT.** Candidate, same session, and it is the `forth bin/peer.fs` shape
  with the *harness* untracked instead of the entrypoint. `entity-core-codec-ffi-rust/README.md`
  documented `./target/release/conformance_harness <corpus>` and **"69/69 byte-identical to the
  vendored cross-blessed fixture"**; `conformance/README.md` cited the same harness by path;
  `MANIFEST.md` carried its number. The crate declares no `[[bin]]`, `src/bin` **has never
  existed in git history** (`git log --all -- 'src/bin*'` is empty — not deleted, never added),
  and the documented command exits `No such file or directory`. **The consequence is bigger than
  the wrong number:** it means the Rust impl has **no independent corpus harness at all**, so
  its only verification is the cross-impl differential — a **mutual** check that a defect both
  impls shared would pass. Withdrawn rather than restated. **Enforcement: run the reproduce
  recipe.** It is one command and it is the only thing that distinguishes a stale number from a
  fabricated one — and note the four documents agreed with each other, so cross-reading them
  corroborates the claim instead of testing it.

- **RATIFIED (fourth occurrence of the stale-input class, and the one that had ALREADY FIRED IN
  PUBLIC): an identifier is only a pin if it resolves for the audience the claim is published to.
  A commit hash never does. Publish the content digest.** Raised by the operator, measured by arch
  (`ROUTING-2026-08-23` / `COHORT-OPEN-ITEMS` §1k **P-1**), landed here 2026-08-23, and now the
  ecosystem rule: **[ADR-0012] Amendment 1** — *"the digest is the normative anchor; `N·0F @
  <digest>` is the citable form."*
  **The mechanism, and it is not a rewrite story.** [ADR-0027] authors every published commit
  **fresh at the release boundary**, so public `master` is a *different history* from `dev` — `dev`
  is never rewritten and `master` is fast-forward-only; the two lines simply are not the same line.
  A `dev` SHA has therefore **never** resolved for a public reader and never will. It is not
  degraded at release; **it was invalid on arrival for the audience we ship it to.**
  **It had already fired here, twice, and one instance was live.** Published `CONFORMANCE-MATRIX.md`
  reads `665·0F @ e8524ed`; `e8524ed`, `33f35fd`, `b30a589`, `75c532e` resolve in **no repo in the
  checkout** — they died in go's 2026-07-10 mirror history rewrite. [ADR-0012] calls oracle-pinned
  conformance *"our single strongest credibility artifact,"* and on the public surface it was
  unverifiable by an outsider **and by us**.
  **The galling part is that this repo diagnosed it correctly six weeks ago and built the fix.**
  `core_gate_fingerprint` was created on 2026-07-10 *in response to that exact death*, and
  `oracle-pin.env` has carried the proof in one line ever since — `retired_ref_4 = e8524ed
  (unreproducible after mirror history rewrite; same fingerprint)`. **The commit died; the
  fingerprint carried the verdict across its death.** What never happened is that the practice
  reached the *documents*: the pin then quietly regressed from `cc1970f` (which **is** on go's
  public `master`) to a dev-only commit, with nothing objecting, because nothing asked.
  **A local fix that never reaches the rule is not landed — it is a habit in one seat, and it
  decays.** That is this repo's own ratchet law failing in the direction it was written to prevent.
  **And "just re-point `ref` at a public commit" is NOT available — check before promising it.**
  Measured 2026-08-23: go's public `master` HEAD is `cc1970f` (the v0.8.0 release) and its `dev` is
  **514 commits** past it, so **the oracle the whole cohort was measured on exists on no public
  branch under any name**. Any publicly-resolvable commit we could cite is a *different oracle*.
  The digest is not the convenient option, it is the only honest one.
  **What landed:** the three anchors are the pin and the commit is labelled internal
  (`tools/oracle-pin.env` gained a "WHICH FIELD IS THE PIN" block); §1's column is `Oracle pin`
  carrying `core_executed_check_set_digest` (`95edd774…`) in all 46 rows; a new
  **[The pin](../../../CONFORMANCE-MATRIX.md)** section publishes all three anchors plus the reproduction
  recipe **and the limit a digest does not fix** — until go publishes a `master` carrying this
  oracle, an outsider can *verify* an oracle they have but cannot *obtain* ours.
  **Enforcement: `tools/pin-gate.py`, run by `make lint`.** It watches the two ways a content
  anchor stops being trustworthy, and note that **neither is "someone typed a commit hash"**:
  (a) the §1 pin column reverting to a commit — 45 published numbers hang off that one column and
  the reversion would look completely normal; (b) a hand-copied 64-hex digest drifting from
  `oracle-pin.env`. **(b) is the one worth internalizing: a wrong digest is strictly worse than a
  wrong commit hash**, because nobody proofreads 64 hex characters and a bad commit at least fails
  loudly when someone tries to resolve it. Regression-tested against all three planted defects.
  Cross-repo resolvability across the whole published surface is arch's `spec pins`
  (`entity-system-arch-tools`), which resolves cross-repo and attributes by owning repo — do not
  build a second copy of it here.
  **Sub-lesson, and it is the same defect one level down: we retired four pins by COMMIT and never
  recorded the content identity of any of them.** `retired_ref*` carried the commit and the
  *source-declared* digest, but never `core_executed_check_set_digest` — the one anchor a published
  per-peer number is actually measured against. So the retired 740-check set existed in this tree
  only as the 8-hex prefix `8537d875…` quoted in prose, with **no full value anywhere**, and every
  historical figure was therefore unanchored in exactly the way we were fixing going forward.
  Recovered by recomputing from the committed reports still at that set — 26 peers agree
  byte-for-byte, which is better provenance than the original record would have been — and now
  recorded as `retired_core_executed_check_set_digest{,_1,_2}` (740 / 682 / 645).
  **Rule: retiring a pin means recording its content identity, not just its successor.** When you
  build a durable anchor, apply it to the history you already have, not only to the next entry —
  the same "harden one anchor, check its siblings the same day" reflex the `check_set_digest`
  test-fixture fix earned.
  **Deliberately NOT swept, and say so rather than let it read as an oversight:** the dated `>`
  build-log note blocks and the closed-items ledger keep their dev SHAs, under an explicit
  disclaimer in §1's reading note. A build log that gets back-edited stops being evidence of
  anything. 152 unreachable citations → **85**, all of them historical.
  **Two gate defects found while doing it, and both generalize past this repo.** (i) **A backtick
  span that WRAPS A LINE is invisible to a per-line scan.** `README.md` — the front door — published
  ``…309P/337W/3F/106S\n@ c1b0708` `` and arch's `spec pins` never reported it, at 152 or at 85,
  because the span opens on the previous line. That is the headline number on the credibility
  artifact anchored to a dead identifier, with the gate saying clean. **Scan the joined text, not
  lines** — recover the line number from the match offset. **A false negative in a gate is worse
  than a false positive, and this class correlates with prose quality**: the more carefully a
  document is wrapped, the better its citations hide. (ii) **A file that records both commits and
  digests hands out commit-shaped exemptions for free.** Our own first cut accepted any recorded hex
  as an anchor prefix, and `oracle-pin.env` holds `commit = c1b0708c1679…`, so `c1b0708` matched it
  and the bare-SHA check **passed a planted defect**. Harvest only 64-hex sha256 and explicitly
  truncated `…` forms; a bare 40-hex commit is never an anchor. **Both were caught by planting the
  defect, not by reading the code** — the regression suite is the enforcement point, and a gate
  without one is just a script that has never been wrong yet.

- **`CANONICAL-DOCS.toml` IS A KEEP-LIST, NOT A SCRUB-LIST — undeclared means DELETED FROM THE
  PUBLIC TREE, and for months this repo's own header said the opposite.** Found 2026-08-23
  (fleet-wide by the arch-tools first full pass, routed to us as a release blocker).
  `canon-filter` (`entity-core-devops` release-builder, `internal/canon`) removes every file it
  does **not** find declared, within its scope. Our header described a *scrub-list of name
  patterns* (`**/HANDOFF*`, `PROPOSAL-*`, `CLAUDE.md`, …), which is the wrong model **in the
  dangerous direction**: it reads as "undeclared files are dropped only if they match a
  pattern," and under it **eight files that were already on public `master` sat undeclared and
  one release away from silent deletion** — `AGENTS.md` `AGENTS-STANDARD.md` `CHANGELOG.md`
  `CLAUDE.md` `CODE_OF_CONDUCT.md` `CONTRIBUTING.md` `RESOURCE-CAPS.md` `SECURITY.md`. **No
  other gate sees this**: leak-audit asks whether it is safe to publish, conform-audit whether
  it conforms, the build whether it works — none asks *does this still contain what we already
  gave people*. Only `[6/6] public-regress` does, and it is new.
  **Know the scope exactly, because it decides what a mistake can destroy** (verified by reading
  `internal/canon/canon.go`, not by inference): **only PROSE is ever dropped** — `.md .markdown
  .rst .txt .adoc` plus `.patch`/`.diff` — **and only** when it is loose at the top level (no `/`
  in the path) or under a doc-root **prefix** (`docs/ doc/ reviews/ review/ research/
  explorations/ proposals/ validation/ stewardship/ status/ reports/ notes/ handoffs/ audits/
  planning/ design/ designs/` and their singular/plural twins). Everything else — source,
  configs, vectors, `.py`, `.sh` — is **always kept, wherever it sits**. **Prefix means at the
  START of the path** — `strings.HasPrefix`, so `protocol-generator/<lang>/status/*.md` is out
  of scope and never has been at risk.
  **CORRECTED 2026-08-24, and the correction is the lesson: this entry said "droppable REGARDLESS
  OF EXTENSION," which was true of the tool when written and is now false.** `canon-filter` was
  fixed to prose-only on 2026-08-23 after the old rule shipped an `entity-core-go` mirror that
  **failed its own test suite on a clean clone** — it had stripped four conformance `.cbor`
  vectors and a `.json` baseline that published code reads, because they were filed under
  `docs/validation/`. *Location is not function.* The operator's ruling on the fix shape is worth
  carrying: **"we fix our thing that doesn't strip out essential things from repos"** — not a
  keep-list entry per artifact, which would be a permanent public-surface commitment made to work
  around a filter defect. **The general rule: a documented fact about someone else's tool has a
  shelf life, and re-reading the source is cheap.** We caught this only because a routed strip
  list disagreed with our own recomputation by exactly three `.sh` files — **diff a supplied list
  against your own before accepting either.**
  **Enforcement:** simulate before every release — walk `git ls-tree -r origin/master`, subtract
  the declared set, apply those two scope rules, and require the remainder to be empty or
  declared in `.release-removals`. Currently: **0 undeclared deletions, 1 declared**
  (`docs/status` — [ADR-0031], and it is a MOVE of `STATUS.md` to `docs/`, not a withdrawal).
  **RATIFIED 2026-08-23, second occurrence and a different shape: "regardless of extension" is
  the half that bites is *prose under a doc root*, because that is where the durable writing
  lives.** The first occurrence was eight prose files. The second was **fourteen** — five
  cross-cutting paradigm surveys under `research/evaluations/`, `rt13-write-concurrency-classes.md`
  under `research/diagnostics/`, and eight dated cross-cutting syntheses at `research/` top level
  including the **954-line red-team review of our own claims** and one that calls itself *the
  front-door document*. Every one was named from the published surface: the surveys from
  `AGENTS.md`, `CONFORMANCE-MATRIX.md`, four peers' `PROFILE-RATIONALE.md`, `sql/profile.toml` and
  two `Containerfile`s; `rt13` from the go and rust peers' concurrency **test source**; three
  syntheses from a published finding.
  **The sharpest instance is still not a doc link at all — `tools/check-set-gate.py` PRINTS a
  diagnostic's path at RUNTIME as the reader's next step** — but note the correction directly
  above: that diagnostic is a `.sh` and, since the 2026-08-23 prose-only fix, was never actually
  at risk. **The instinct was right and the reason was wrong**, which is worth more than being
  right for the right reason would have been: it is why the scope statement got re-derived from
  source instead of carried forward.
  **THE FIX IS TO MOVE THE FILE, NOT TO DECLARE IT — operator ruling, 2026-08-23, and it
  reverses what this entry said when it was first written a few hours earlier.** The reflex on
  finding an undeclared file that ought to publish is to add a `[[doc]]` block, and it is wrong:
  **`CANONICAL-DOCS.toml` declares CANONICAL DOCS. It is not a catch-all for whatever needs to
  survive the filter.** A probe script, a paradigm survey and a forwarding map are none of them
  canonical documentation, and declaring them turns the keep-list into a junk drawer nobody can
  audit — it stops answering *what is this repo's documentation* and starts answering *what did
  somebody once need to keep*. All nine moved to `protocol-generator/shared/{diagnostics,
  evaluations}/` instead, beside the findings, which is the same move for the same reason.
  **The standing answer to the whole class: `protocol-generator/**` is outside every doc-root
  prefix and publishes with NO declaration at all. Anything that must ship and is not
  documentation goes there; declaration is reserved for documents.** The keep-list grew by
  exactly one entry across the whole release-readiness push — `docs/STATUS.md`, which is a
  canonical doc — while 33 documents moved into publication without touching it.
  **RATIFIED 2026-08-24, third occurrence, and it is now a GATE rather than a grep —
  `tools/link-gate.py` check 2, in `make lint`.** A published file must not NAME a path the
  release strips. Check 1 (link resolution) is structurally blind to this: the target exists in
  our tree, so the link resolves here and is dead for the reader. The three occurrences were the
  sixteen non-doc citations that defeated the first findings rename, the diagnostic
  `check-set-gate.py` printed at runtime, and — found by DevOps' independent pass, not by us —
  **three source comments citing dated snapshots, two of them in published peer source, a `.c`
  and an `.s`.**
  **We had already run this check and reported "one hit." It was three.** The scan was scoped to
  `*.sh *.py *.go *.rs *.toml Makefile` and never opened a `.c` or an `.s`; and it matched bare
  basenames, so 66 of 69 raw hits were `README.md` colliding with itself, which is precisely the
  noise that makes a reader dismiss the other three. **Two failure modes in one grep — wrong file
  set, and a signal-to-noise ratio that hid the answer inside its own output.** Match FULL PATHS,
  scan EVERY extension.
  **And the wrapped form is not an edge case here — it was two of the three.** The gate reads the
  JOINED text and tolerates a comment marker on the continuation line (`//`, `#`, `;`, `*`, `--`,
  `!`, `%`), because a path broken across a line with `# ` starting the next one is invisible to
  every per-line tool. Fourth time this shape has cost real time.
  **Severity is split on purpose, same principle as `check-set-gate`'s disclosed debt:** non-prose
  citations FAIL (shipped engineering provenance, small and actionable — currently 0), prose-to-
  prose citations are REPORTED and do not fail (26 dated snapshots cited from published docs,
  measured and parked by operator ruling). Hard-failing those would hold the gate permanently red,
  which teaches people to skip it — a failure mode written down twice in this file already.
  Regression-tested against all four cases: plain non-prose citation → exit 1, wrapped non-prose
  citation → exit 1, prose citation → exit 0 with a report, clean tree → exit 0.

- **THE ECOSYSTEM ADRs DO NOT PUBLISH — standing operator ruling, 2026-08-24. `docs/adr/ecosystem/`
  stays undeclared, all 33 strip, and that is the correct answer rather than a finding.** Cite
  `[ADR-NNNN]` by NUMBER in published prose freely — the number references a decision, not a
  promise of a file — but **never send a published reader to the PATH**, because that directory is
  not in the mirror. The transport question (with [ADR-0030] retracted there is no automated
  injection, so hand-synced copies rot) is **correctly identified and deliberately unanswered** —
  blocked behind a decision on what publishing an ADR means at all. Hand-sync, say so in the
  commit message, and **do not build a local mechanism for it.**
  **The near-miss is the part to remember, because it came in through good behaviour.** We
  re-synced `AGENTS-STANDARD.md` faithfully; the authored copy then said *"`docs/adr/ecosystem/`
  carries the full text of every ecosystem ADR… It is now local."* `AGENTS-STANDARD.md` is
  **declared**, so the cut would have published a canonical document telling a reader to open a
  directory the release deletes — **the index shipping while the evidence does not, inside the
  standard that warns about that exact shape.** The four already-public repos were clean only
  because their copies were *stale*; keystone was first precisely because it was in sync.
  **Being current is not the same as being correct, and a re-sync inherits the upstream's
  defects along with its fixes** — so after every overlay pull, grep the *published* surface for
  paths the release strips, not just for drift. That grep found three more in **our own**
  authored files (`AGENTS.md`, the keep-list header, `link-gate.py`'s comment) that the upstream
  repair could not have touched.

- **RATIFIED, FOURTH OCCURRENCE OF THE PUBLISHED-PROSE CLASS — A CITATION THAT NEVER RESOLVED IS
  INVISIBLE TO EVERY GATE, AND THE ONE WE HAD WAS NAMED IN AN ECOSYSTEM ADR TWO MONTHS AGO.**
  2026-09-09, found by hand-walking the published surface during a status audit with all eleven
  gates green. Three instances, one class — **published prose rots exactly where the gates are
  scoped somewhere else** — and the third is the durable one:
  - **The canonical register cited in-flight escalation packets by PATH.** `SPEC-FINDINGS-LOG.md`
    is declared canonical; F54 and F58 each ended `Routed in \`…/HANDOFF-TO-ARCH-<date>-<slug>.md\``,
    and those packets are undeclared under a doc-root prefix, so they strip. That is the standing
    *"the index shipped and the evidence did not"* shape **in the exact file AGENTS.md names as its
    enforcement point** — and `link-gate` is right not to fail it, because prose-to-prose citations
    are parked by ruling. **A parked class still needs a rule for the one member the ruling was not
    about: the register's evidence citations.** Fixed by naming the ROUTING DATE, never the path —
    the packet is a process artifact, the finding is the research output, and only the second one
    publishes. **Enforcement: `grep -n 'research/stewardship/HANDOFF' research/stewardship/SPEC-FINDINGS-LOG.md`
    must return nothing.**

- **A MARKDOWN TABLE WHOSE HEADER DECLARES FEWER COLUMNS THAN ITS ROWS CARRY DROPS THE EXTRA
  COLUMNS AT RENDER — SILENTLY, IN THE CANONICAL REGISTER, FOR SIX FINDINGS AT ONCE.** RATIFIED
  2026-09-10, found while appending F63–F67 rather than by any gate. `SPEC-FINDINGS-LOG.md` —
  the file `AGENTS.md` names as canonical for every finding, and which **publishes** — carried a
  **three-column** header (`| ID | Kind | Disposition |`) over rows carrying **six** cells. Under
  GFM everything past column three is discarded, so **F54, F58, F59, F60, F61 and F62 rendered
  with their Cites, Owner and Disposition columns invisible** — the `Open — surfaced`, the asks,
  and the routing state, i.e. the entire reason a reader opens the register. This is the standing
  *"the index shipped and the evidence did not"* class reached through a **column count** instead
  of a keep-list, and it is worse in one respect: the source file is complete and correct, so
  reading it in a diff, a grep or an editor shows nothing wrong. **Only the render is lossy.**
  `F59` was separately mangled by a `` `\|| true` `` in its prose — the first pipe escaped, the
  second not — which split its last cell into three.
  **Enforcement: count UNESCAPED pipes per row and require every row to equal its header.** One
  line, and it is the whole check: `re.split(r'(?<!\\)\|', line)`.
  **Sub-lesson, and it is the examined-zero-things rule catching the instrument again: my first
  counter used `line.count('|')`, which counts ESCAPED pipes too** — so it reported F59 at 8 cells
  *after* the escaping had correctly fixed it, and I nearly "fixed" a correct line twice. A
  counter over a syntax with an escape character must model the escape. **Validate it against two
  controls before believing either direction** — `| a | b | c |` must read 3 and `| a \| b |` must
  read 1; both were run, and the second is the one that would have failed.
  *(Third thing the same session taught, and it is the false-negative class in its **flattering**
  direction at cohort scale — seventh occurrence. Surveying `scope_subset` typing by asking "does
  this peer's capability file mention `id-scope`?" returned **40 typed / 6 untyped**. False:
  the file mentions id-scope for `matches_scope`, which landed with F40, while `scope_subset`
  beside it is untyped. Truth is **0 of 20**. **The discriminator is the function SIGNATURE, not
  the file's vocabulary** — a `scope_subset` with no scope-type parameter cannot dispatch on one
  whatever its neighbours say. The H4 packaging entry records the first member that *understated*
  a capability; this one **overstates conformance**, which is the direction nobody re-checks.)*

- **NO GATE ASKS WHETHER THE PUBLISHED TREE IS INTERNALLY COHERENT — and every defect this
  release cycle was found by walking it by hand.** Ratified 2026-08-23 (arrived as the one habit
  the release earned, and it is now ours because we are the repo it kept finding things in).
  The six release gates ask six different questions — is it safe (`leak-audit`), does it conform
  (`conform-audit`), does it build, is the identity right, did anything vanish
  (`public-regress`), is the promotion text clean — and **none of them asks whether a published
  document points at something a reader can open.** Neither do ours: `check-set-gate.py` checks
  that numbers are comparable, `pin-gate.py` that anchors resolve, `tier-status.py` that M1 is
  current. All three would pass a tree in which every internal link is broken.
  **The measured yield of one hand-walk, this session:** a README contradicting itself two lines
  apart (13 publishable, "binds 40"); four runtime-referenced diagnostics deleted at release; 23
  findings whose index published and whose evidence did not; two internal-token leaks; **and one
  nobody had routed** — `protocol-generator/fortran/status/` cited two findings at
  `research/stewardship/HANDOFF-TO-ARCH-*.md` paths that had not existed since those findings were
  archived weeks earlier, dangling from a *published* file the whole time.
  **Budget the pass; it is not optional and it is not automated.** Cheap partial enforcement that
  is worth having anyway: resolve every relative markdown link in the tree against disk
  (`\[[^\]]*\]\(([^)#\s]+)\)` → `(referrer.parent / target).exists()`) — it is ~20 lines, it runs
  in a second, and it would have caught the fortran dangler and every link the findings move
  broke. It does **not** catch inline-code paths in backticks, prose fragments, or a path printed
  by a tool at runtime, which is why the hand-walk stays.

- **A PIN IS A CLAIM, AND THE SENTENCE THAT STATES IT ROTS WHILE EVERY GATED NUMBER STAYS CORRECT.**
  RATIFIED 2026-09-09 (fifth occurrence of the stale-input class, and the first where the stale thing
  is the *anchor statement* rather than a report, an overlay or a build artifact). With **thirteen
  gates green**, five live sites in four published files named a RETIRED `core_executed_check_set_digest`
  in the present tense: **`README.md` twice — the front door, two flips stale**; `CONFORMANCE-MATRIX.md`
  footnote ², which defines what every cell in §1 MEANS, **three** flips behind; `docs/STATUS.md`;
  `docs/PROGRAM.md`; plus `AGENTS.md` itself and, worst, `PROGRAM.md`'s *"Disclosed gaps behind a
  0-FAIL row: **none** — the skip-provenance allowlist is empty"* published **one day after 46 F59
  entries went into that allowlist**. §1's 46 rows and the 46 per-peer banners were correct throughout,
  **which is precisely why nothing caught it** — `coherence-gate` is scoped to exactly those two
  surfaces.
  **The rule: for every number you gate, gate the sentence that says WHICH PIN it was measured at.**
  `coherence-gate` check 6 does it — in a live PARAGRAPH carrying a pin phrase, every digest and every
  `NNN-check` total must be the current one from `oracle-pin.env` — with four escape hatches so naming
  a retired pin stays cheap (a date within 80 characters, a `retired`/`superseded`/`then-current`/
  `first closed` marker, a `"quotation"` of former text, or a struck/✅ line).
  **Two method notes, both of which cost time here.** (a) **PER-LINE IS THE WRONG UNIT, for the fourth
  time in this file.** The clause that retires a pin *wraps*, so a per-line scan reads the marker and
  the value it governs as unrelated and fires on a correct sentence. Scan paragraphs and recover the
  line number from the offset — but **break the paragraph at list items, table rows and headings**, or
  one bullet naming the current pin puts the whole list in scope and a bullet nine items down
  recounting a 2026-08-28 measurement fires. Moving from lines to paragraphs took the check from 95 to
  **114** statements examined and the 19 it gained held two real defects. (b) **Assert the count, then
  distrust it in both directions**: an over-broad phrase list (`pinned\b`) took it to 776 statements
  and produced false positives on dated history, and the narrow list that fixed that had to be widened
  again — `pinned snapshot`, `NNN-check pin` — because the two real defects used forms the first list
  did not contain. A phrase list is a survey keyed on words you wrote down, so measure what it sees.

- **The findings PUBLISH; the escalation stays a draft.** A handoff has two lives and they want
  opposite things. As a **process artifact** it is dated, addressed, in flight, and internal —
  `research/stewardship/HANDOFF-TO-ARCH-<date>-<slug>.md`, the vocabulary unchanged. As **research
  output** it is the durable answer to *"we implemented this protocol 46 times, here is what we
  found wrong with the spec"* — and that belongs to an adopter, not to a filing cabinet. So once a
  handoff is written up it **moves to `protocol-generator/shared/findings/`** under an undated
  name, keeping its date in its own `**Date:**` header as provenance rather than as an identifier.
  **The register does NOT move with it** — `research/stewardship/SPEC-FINDINGS-LOG.md` is declared
  canonical, and the release keep-list is fail-closed on a declared path that is absent
  ([ADR-0021]), so moving it aborts every unit whose historical manifest names the old path.
  **Two mechanical reasons the destination is what it is, both of which read as arbitrary until
  you hit them:** (a) `canon-filter`'s doc-root prefixes match at the START of a path, so anything
  under `research/` needs a keep-list entry per file forever, while `protocol-generator/**` is
  protected and publishes with **no declaration at all**; (b) `conform-audit` **R10** files any
  *dated-named* doc as an ephemeral snapshot — measured 2026-08-23, it flagged **41** of ours as
  ERROR and had never fired only because the gate audits the canon-filtered tree, where they were
  absent. Declaring them in place would have started the fire; renaming is what puts it out.
  **The failure this fixes is the shape to remember: the index shipped and the evidence did not.**
  `SPEC-FINDINGS-LOG.md` was public, calls one finding a *front door*, and every document it names
  was deleted from the public tree by a keep-list nobody had read as a keep-list. **Enforcement:**
  `git ls-files research/stewardship/HANDOFF-TO-ARCH-*` should only ever return handoffs that are
  still in flight — anything there that `SPEC-FINDINGS-LOG.md` cites as evidence is unpublished
  evidence. References in `docs/status/` and `docs/archive/` were deliberately left pointing at
  the old names — a dated snapshot that gets back-edited stops being evidence of anything — and
  the old→new map sits beside the register as an internal breadcrumb, undeclared on purpose.

- **`AGENTS.md` GROWS BECAUSE IT IS THE ONLY FILE WHOSE NAME INVITES IT, AND A CLEANUP IS NOT A
  FIX — THE FIX IS A DESTINATION.** RATIFIED 2026-09-17 (ours measured at **508,792 B**, against a
  30,720 B budget; one fleet sibling cut its own from 4,663 lines to 289 and was back to 5,037
  **twenty-one days later**). Every session ends holding something worth keeping and, until there
  is a memory directory, exactly one obvious place to put it. **That sibling's cleanup was good
  work and it was not a fix**: nothing changed about where a session puts what it just learned.
  **Three homes, and one question decides it:** *would a competent newcomer need this **before**
  their first change, or only when they hit the thing it describes?* → `AGENTS.md` (living,
  bounded, edited in place) · `docs/agents/memory/<TOPIC>.md` (living, indexed) · `docs/status/`
  (dated, written once, ages out). **Never a file named for a category of feeling** — `MISC`,
  `NOTES`, `TIPS`, `GOTCHAS` — because such a file accepts anything and becomes the new
  `AGENTS.md`.
  **Four things about doing the split, and the first two are the ones that go wrong:**
  - **MOVE, DO NOT REWRITE.** Split on the existing entries, write the index, declare every file,
    leave a pointer section. **Then** ask the promotion question of the entries — *not during the
    split.* Mixing a move with a rewrite turns a two-hour job into a week and arrives unreviewable.
    Verify the move as a **postcondition**: every entry body must be present verbatim in the new
    tree *before* the old one is cut (ours: 171 of 171, checked by substring, plus 12 blocks
    relocated out of neighbouring sections).
  - **BYTES, NOT LINES.** `wc -c`, never `wc -l` — bytes are what a context window pays, and one
    fleet repo is fourth-*smallest* by lines and fifth-*largest* by bytes. The 30 KiB number is not
    arbitrary: **Codex defaults `project_doc_max_bytes` to 32,768 and silently truncates above it**,
    so a file that exists to be read by every agent is read by one of them.
  - **THE LESSONS SECTION IS NOT THE WHOLE PROBLEM.** Moving ours took 508 KiB → 64 KiB and the
    budget is 30. Three *other* sections were carrying memory inline — container pins, five
    oracle-pin entries, the census entries, the whole routing history — and moving those with an
    operational rule left in place took it to 26 KiB. **Measure per section before declaring
    victory**: `sed -n` the byte weight of each heading's span.
  - **⭐ IT PUBLISHES, AND DECLARE IT OR A CUT DELETES IT.** Memory is prose under a doc-root
    prefix, so undeclared it is stripped. It is also the durable answer to *"we implemented one
    protocol in 46 substrates, what did that teach"* — an adopter building the forty-seventh wants
    it, and it is the same content that was already published inside `AGENTS.md`.
  **Enforcement: `tools/doc-standard-gate.py`, in `make lint`.** The index and the directory must
  agree **in both directions** (a file missing from the index is unfindable; an index row with no
  file is a 404), every file must be declared, every file must carry an *Arrive here when* line
  because a reader arrives with a symptom rather than a filename, and no file may be named for a
  feeling. 13 plants, 13 caught, and **the self-test refuses to run against a red baseline** —
  a `CAUGHT` from an already-failing tree proves nothing.
  ⚠ **And the rule that bounds the directory is the one that keeps it from becoming what it
  replaced: an entry that could become a check SHOULD become one, and is then DELETED from
  memory.** Memory is where a finding waits *while it is still only prose*; it is not where
  findings retire. So the maintenance pass is never "trim the file" — it is, per entry, *could a
  test, a lint rule, a build assertion or a gate make this impossible instead of merely
  documented?*
