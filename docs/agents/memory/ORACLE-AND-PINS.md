# Oracle and pins — keystone memory

The oracle pin and its anchors, check-set digests, comparability, budget starvation, maintenance tiers, and every input a peer's verdict derives from.

**Arrive here when:** two numbers are not comparable, a run stopped early, or a pinned input moved under you.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- RATIFIED, FIFTH OCCURRENCE — PLAN AROUND IT: `core_gate_fingerprint` DOES NOT MOVE WHEN THE CORE GATE GAINS CHECKS, AND "the spec delta is minor" IS A JUDGEMENT ABOUT TEXT WHEN THE QUESTION IS ABOUT THE WIRE
- A score is only a score if every peer was measured on the same checks — and that is now ENFORCED, not assumed
- RATIFIED (third occurrence of the stale-input class, and the first where the stale artifact was the COMMITTED one): a gate that only reads gitignored scratch says nothing about what a CLONE shows
- A FRESH CLONE BUILT THE WRONG ORACLE, EXITED 0, AND WOULD HAVE REPORTED THE COHORT GREEN. The build was never broken — that is what made it dangerous
- RATIFIED, SIXTH OCCURRENCE OF THE STALE-INPUT CLASS AND THE FIRST WHERE THE INPUT IS AN ARCH-OWNED FILE WE DELIBERATELY DO NOT VENDOR: A PIN WITH NO READER IS A COMMENT, AND THE ONE INPUT NOBODY GATED IS THE ONE THAT SILENTLY MOVED UNDER 46 PEERS
- A SCAFFOLD PARAMS RENAME IS A WIRE-COMPATIBILITY BREAK AGAINST EVERY ORACLE PIN OLDER THAN IT — SO IT IS COUPLED TO THE RE-PIN AND CANNOT BE SCOPED AS "A RENAME"
- ONE FILE, FIVE PARSERS, AND THE ONE THAT CANNOT READ THE FORMAT BLAMES A DIFFERENT ARTIFACT — AUDIT EVERY READER BEFORE EDITING A MACHINE-CONSUMED VALUE, INCLUDING A COMMENT ON IT
- "IS UPSTREAM STABILIZING?" IS A MEASURABLE QUESTION, AND THE REVISION COUNT IS THE WRONG INSTRUMENT — ANSWER THE COST QUESTION WITH THE ORACLE, NEVER WITH THE SPEC'S VERSION NUMBER
- RATIFIED (second occurrence, different shape): a budget-starved run reads as a clean run, and the starved categories are where the real FAILs are
- RATIFIED, and it is the STALE-INPUT class reaching VENDORED DATA: a second copy of a corpus is a second authority, and the retired one answers
- A CANDIDATE ORACLE CAN MAKE THE DOCUMENTED ENTRY POINT REPORT `FAIL` — AND EXIT NON-ZERO — ON A PEER THAT IS 0-FAIL, INCLUDING THE REFERENCE PEER
- A REFERENCE BUILT FROM A SIBLING CHECKOUT'S HEAD IS AN UNPINNED INPUT DECIDING A VERDICT — and it can be a DIFFERENT REPO than the one you think
- MAINTENANCE TIERS ARE ACTIVE — do not run a 45-peer census for a re-pin
- The core-gate FINGERPRINT does not certify the gate — the CHECK-SET DIGEST does
- Never raise `-timeout` to make a red run green — and read the human output, not just the JSON, to find out whether the budget held
- An anchor is only as good as its INPUT — `check_set_digest` was reading go's test fixtures
- RATIFIED (third occurrence — and a FOURTH landed 2026-08-21 at `de8f807 → c1b0708`): an upstream that is "all extension work" can still move the core gate through ONE file — attribute new checks BY CATEGORY, never by commit message
- `-category <name>` OVERRIDES the `--profile core` carve-out — a category driven directly is NOT the same measurement as that category inside a core run

---

- **RATIFIED, FIFTH OCCURRENCE — PLAN AROUND IT: `core_gate_fingerprint` DOES NOT MOVE WHEN THE CORE
  GATE GAINS CHECKS, AND "the spec delta is minor" IS A JUDGEMENT ABOUT TEXT WHEN THE QUESTION IS
  ABOUT THE WIRE.** Measured 2026-09-04 for `0.8.2.3 → 0.8.2.7`. **One of three** normative files
  moved, `+80/−12` — which reads as trivial and is not. The go oracle grew **+15 declared checks, 0
  removed**, and **13 are `catConnectivity`, a CORE category**; `profile.go` did not move, so the
  fingerprint stayed byte-identical at `8261a033…` for the fifth time in this exact shape. The
  executed core set goes **758 → 772**.
  **Two method notes, both of which cost time here.** (a) **A `.Declare("…")` grep is the wrong
  vocabulary** — `connectivity_conn_errors.go` is 774 new lines registering checks as `const name =
  "…"`, so a Declare-only scan reported **+4** where the truth was **+15**. Our own
  `oracle-bootstrap.sh check_set_digest` already handles both forms; **use the repo's canonical
  extractor rather than authoring a third one**, and if you must grep, prove the pattern sees a check
  you know exists. (b) **A three-lineage probe is a strong prior and is not a cohort claim.** Building
  the HEAD oracle to scratch and running `go`, `rust` and `python` returned an **identical**
  `772 · 324P/336W/5F/107S` — same five failures, nothing else moving — which is good enough to
  scope the work as *one authored fix propagated 46 times* and NOT good enough to publish. Say which
  you have. **Build the candidate oracle to a scratch path and leave the pinned one alone**: a probe
  that clobbers `output/s4-oracles/` has destroyed the measurement state it was trying to inform.

- **A score is only a score if every peer was measured on the same checks — and that is now
  ENFORCED, not assumed.** `tools/check-set-gate.py` requires every report in a census to have
  executed the identical check set, pinned as `core_executed_check_set_digest` in
  `tools/oracle-pin.env` (**`7aa6f3de…` = 778 checks @ `78db4a9`**; the retired values are recorded
  as `retired_core_executed_check_set_digest*` in that same file — **no two are comparable, so never
  diff a row across a re-pin**. This sentence itself named the 755-check set as current for three
  flips; `coherence-gate` check 6 now gates the class and found it here), and hard-fails on any
  `budget_exhausted` category; `tools/run-cohort-census.sh` runs it automatically and **exits
  non-zero when a census is not comparable**. Note the distinction from the neighbouring pin:
  `check_set_digest` is what the oracle SOURCE declares, `core_executed_check_set_digest` is
  what a run EXECUTED — **the gap between them is exactly where a bad number hides**, and only
  the second one can catch a run that quietly stopped early. Re-measure the cohort and re-pin
  it whenever `ref` changes. **A peer that deviates is not a low-scoring peer, it is an
  INVALID MEASUREMENT** — quarantine it, never list it in the same column as the others.
  *(Measured 2026-08-17: 42 of 45 peers produced a byte-identical 740-check set, so the oracle
  itself is deterministic and consistent — the failure mode is a run that stops early, not an
  oracle that tests different things.)*
  **The gate itself had this bug, in the input it reads (found + fixed 2026-08-22).**
  `check-set-gate.py` overlays `output/scratch/reverify/` on top of the census dir so a
  post-rebuild re-verification supersedes a stale census row — correct in intent, but the overlay
  was **unconditional**, and that directory is scoped to neither a run nor an oracle pin. Three
  reports left there on 2026-08-17 at the retired `de8f807` pin (740 checks) therefore outranked
  the fresh 2026-08-21 `c1b0708` census (755 checks) indefinitely, and the gate condemned
  `node-red` / `rust-wasm` / `rust-wasm-wasmtime` as non-comparable — **7 bad peers reported where
  the truth was 4** — on four-day-old evidence measured against a different check set. It reads
  exactly like a real finding: the diff it prints (*"NEVER RAN capability(5), type_system(10)"*) is
  precisely the 5 new CAP checks, i.e. the most plausible-looking result it could have produced.
  **Fixed:** the overlay now applies only when it is *newer* than the census report it would
  replace, and says so on stderr when it skips one. **Rule, and it is the same one the stale-build-
  artifact entry at the end of this file states from the other side: an input that PREDATES what it
  supersedes is not an override, it is drift.** Enforcement: `stat -c %Y` both sides — any
  "supersedes" mechanism (overlay dirs, `-fixed.json` scratch files, vendored binaries) needs a
  recency check, or it silently pins the past over the present. Sanity-check for this specific
  trap: if the gate's report disagrees with `CONFORMANCE-MATRIX.md` §1a on *which* peers are
  INVALID, suspect the input before the peers.

- **RATIFIED (third occurrence of the stale-input class, and the first where the stale artifact was
  the COMMITTED one): a gate that only reads gitignored scratch says nothing about what a CLONE
  shows.** Found 2026-08-22 in the release sweep. Every tracked
  `protocol-generator/<lang>/status/CONFORMANCE-REPORT.{md,json}` had drifted a full oracle pin
  behind `CONFORMANCE-MATRIX.md` §1 — **38 peers at the retired `de8f807` 740-check set, 4 at 682,
  1 at 645, `io` unreadable, NONE at the current 755** — while §1 published fresh 755-check numbers.
  Several `.md` files still led with `cc1970f`/`b30a589`-era banners quoting `552`/`576` totals from
  oracle `cb54f5b`. **§1 was never wrong** (it is census-backed) — the defect is that the *only*
  numbers an adopter can read without re-running anything contradicted the published row, in the
  peer's own directory, and **every gate we had pointed at `output/scratch/`, which is gitignored.**
  **The cause was structural, and the structure was correct in isolation:** `run-cohort-census.sh`
  deliberately never writes tracked reports (a census must not silently rewrite 45 signed-off
  records) and `output/` is gitignored — two individually sound decisions that between them left
  *no* path to refresh a committed report, so it rotted for months with nothing watching.
  **The generalizable rule: for every artifact you PUBLISH a number from, name the gate that reads
  the COMMITTED copy.** Reproducible-from-the-pin (which is what [ADR-0012] requires and what we had)
  is not the same property as *consistent-in-the-tree*, and only the second one is what a reader
  actually experiences. **Enforcement: `tools/check-set-gate.py --tracked`, run by `make lint`** —
  it fails when a peer published as 0-FAIL carries a committed report from an older check set, and
  deliberately only *reports* peers with disclosed debt (a gate held permanently red by tracked
  backlog gets ignored, which is worse than no gate; fixed peers rejoin the gated set automatically,
  so it ratchets one way). Refresh with **`tools/run-cohort-census.sh --to-status <peer>`** — the
  missing destination, added to the *same* dispatch table rather than a second copy of it.
  **Refreshing a tracked report is a MEASUREMENT, never a file copy** — hand-copying
  `output/scratch/census/<peer>.json` onto a tracked report fabricates exactly the provenance the
  census/status separation exists to protect.
  **The PROSE sibling is what a human opens first, and nothing gated it — so it is GENERATED now,
  not hand-written.** `tools/status-banner.py` (added 2026-08-28) writes the `CONFORMANCE-REPORT.md`
  banner from that peer's own tracked JSON, and **refuses to write one from a report that is not at
  the pinned check set** — a banner is a publication of a number, and publishing one off a stale or
  starved measurement is the defect the tracked gate exists to prevent. It also declines to claim
  *"everything below predates this measurement"* when there is nothing below (three peers had no
  `.md` at all; the 2026-08-22 hand pass asserted exactly that falsehood for `lean`). **And it cites
  the executed check-set DIGEST rather than the oracle commit** — these files publish, and a `dev`
  SHA resolves for no outside reader ([ADR-0012] Am. 1). The 2026-08-22 hand pass wrote
  `oracle entity-core-go @ c1b0708` into all thirteen; generating the banner is what stopped that
  reaching the other twenty-six. **Rule: a per-peer number that publishes gets written by a tool that
  reads the measurement, not by a person reading the measurement.** (All 13 publishable peers were re-measured, not copied,
  and each reproduced its published number exactly — which is also the strongest evidence the
  release numbers are real.) **Two sub-lessons worth their own greps:** (a) the new gate had a bug in
  the shape it exists to catch — `collect()` keyed reports by *path stem*, and every tracked report is
  named `CONFORMANCE-REPORT.json`, so all 45 collapsed into one dict entry and the gate would have
  "passed" having examined a single file; **any dict keyed by `Path.stem` over a conventional
  filename is a collision waiting to happen** — key by the meaningful path component. (b) A one-off
  formatting pass over 13 prose reports must not assert history that does not exist: `lean` had never
  had a `.md` companion, so the generated *"everything below predates this measurement"* line was
  false for exactly one peer — check the generated text against each target, not just the template.

- **A FRESH CLONE BUILT THE WRONG ORACLE, EXITED 0, AND WOULD HAVE REPORTED THE COHORT GREEN.
  The build was never broken — that is what made it dangerous.** Measured 2026-08-23 against a
  genuine fresh clone (a detached keystone worktree with no `output/`, plus `git clone --no-local
  --single-branch --branch master` of go — 2 commits, pinned ref absent), because "does an adopter's
  build still work" is not answerable by reading the script.
  **What happened, in order:** `ref = c1b0708` did not resolve → R1 fell back to HEAD `cc1970f` →
  **`core_gate_fingerprint` MATCHED BYTE-FOR-BYTE** (`8261a033…`; it has been identical across all
  five pins, so it raises nothing, ever) → `check_set_digest` differed → printed a **NOTE** → built,
  installed, **exit 0**. The resulting binary is missing `request_mint_temporal_ceiling`,
  `ingest_rejects_unrepresentable_expiry` and `configure_empty_grants_withdrawal` (`strings`-
  verified) — **the three checks that are this release's entire finding.** An adopter following the
  documented path gets a clean build, a green run, and 32 peers passing that `CONFORMANCE-MATRIX.md`
  says fail, and concludes our matrix is wrong. **A falsely-GREEN result out of a SUCCESSFUL build is
  the worst thing this repo can emit**, and a warning on stderr inside a wall of `go: downloading`
  lines is not a control. **Rule: an anchor mismatch is a HARD STOP with a non-zero exit, never a
  NOTE.** `oracle-bootstrap.sh` now exits 3 with the cause and the remedy (`REPIN=1` is the explicit
  escape hatch for a deliberate re-pin).
  **Second bug, same session, worse shape: the "nothing to do" short-circuit compared the install
  against ITSELF.** `HAVE`/`HAVE_CS` came from `PROVENANCE.txt` (what is installed) and
  `CORE_FP`/`CHECK_SET` from the ref being built; on a second run both described the same wrong
  oracle, so they agreed trivially and the script printed *"NOTE check-set digest differs from
  committed pin"* and *"matches BOTH … nothing to do"* **three lines apart**. **A self-consistency
  check reads exactly like a correctness check and is not one** — always name the authority side of
  a comparison (here: the committed pin), and be suspicious of any equality test whose two operands
  are derived from the same source.
  **Third hole, closed at the same time:** `run-cohort-census.sh` read the pin's `ref` only as a
  *label* to stamp the roster and never checked the installed binary, so a whole census could run on
  a wrong oracle and stamp 45 rows `@ c1b0708`. `check-set-gate.py` does catch it afterwards, but as
  *"42 peers are not comparable"* — which reads as a peer problem and sends you looking in the wrong
  place **after** the multi-hour run. It now preflights the installed digest against the pin and
  refuses in seconds. **Ask the cheap question before spending the hours.**
  **The good half, and it is the whole justification for content pinning — PROVEN, not argued.**
  Simulated the post-release world: a go clone whose `master` carries a **freshly authored commit
  `592ff26`** (never seen by us, `c1b0708` unreachable by name) with the same tree. `oracle-bootstrap`
  falls back, matches both anchors, builds — and the resulting `validate-peer` is **byte-identical**
  to our pinned one (`c3827af8…`). **The commit hash is genuinely not needed; the digests are
  sufficient and the build is reproducible.** So the current gap is purely that go has not published
  this oracle yet — a sequencing dependency, not a design flaw. **Enforcement: re-run this three-
  scenario test (public-master clone → must exit 3 · our tree → must exit 0 · re-authored publish →
  must build byte-identically) before any release that claims an adopter can reproduce a number.**

- **RATIFIED, SIXTH OCCURRENCE OF THE STALE-INPUT CLASS AND THE FIRST WHERE THE INPUT IS AN ARCH-OWNED
  FILE WE DELIBERATELY DO NOT VENDOR: A PIN WITH NO READER IS A COMMENT, AND THE ONE INPUT NOBODY
  GATED IS THE ONE THAT SILENTLY MOVED UNDER 46 PEERS.** 2026-09-16. `tools/oracle-pin.env` has carried
  `guide_conformance = <sha256>` since `v0.8.2`, and **`grep -rn guide_conformance tools/ Makefile`
  returned exactly one line: the one that declares it.** Nothing read it, ever. Measured on landing a
  gate for it: pinned `7d59fee6…`, actual `204f4897…`, **17 commits elapsed** (`3deee05` 2026-08-24 →
  `a671a37` 2026-09-16, +485/−31 lines), carrying **three cohort obligations that reached us through no
  channel** — §7a.2a's plural `reentry_*` carriers, *"pin the scaffold grant narrow"*, and §7a.1b's
  per-call `deadline_ms` `[MUST]` (**`grep -rl deadline_ms protocol-generator/*/src/` → 0 of 46**).
  **The mechanism is structural and it is the argument for the gate rather than for more diligence.**
  Peers derive their **entire §7a conformance scaffolding** from `GUIDE-CONFORMANCE.md` — the
  `system/validate` handlers, their params contracts, the §7b concurrency gate. The spec-data snapshots
  are digest-verified on every `make lint`. The guide is deliberately **not** in `spec-data/`
  (non-normative, arch-owned) — which is correct, and is exactly why **the one input that moved was the
  one input with no gate**. And this file's own claim that the guide *"is pinned BY HASH in the
  snapshot's `MANIFEST.md`"* had decayed in two steps: it was a *pointer* to that line in `v0.8.2`,
  `.3` and `.11`, and `v0.8.2.25` and `.28` **dropped even the pointer**, so the documented control was
  half-gone and the surviving half was inert.
  **Enforcement: `tools/pin-gate.py` check 5, in `make lint`.** Three things about its shape are the
  transferable part. (a) **It FAILS only when the sibling is present and DIFFERS, and REPORTS
  "STALENESS NOT COMPARED" when the sibling is absent** — a clean clone has no sibling checkout and a
  gate that exits 1 there is a gate people switch off (the `author-extension-host --check` lesson, red
  on every clone for reading gitignored scratch). *"Could not look"* and *"looked and it matches"* must
  not print the same word. (b) ⭐ **The digest is a READ MARKER, NOT A CONFORMANCE CLAIM** — the same
  vendored-versus-consumed split `spec-data` already uses. Advancing it asserts *this revision has been
  read and its obligations enumerated*, never *implemented*; the debt lives in the tracker and the
  per-peer `spec_pin`. So it fires on an UNREAD revision, which is the state that costs, and does not
  hold itself permanently red against tracked backlog. (c) **`PIN_GATE_GUIDE` exists so the three arms
  can be driven without writing to the sibling** — the obvious way to test this check is to edit the
  guide in place, which crosses the standing never-write-to-arch boundary *for a test*. I did that once
  before adding the override; the override is so nobody has to again.
  **Generalize past this file: for every input a peer's behaviour derives from, name the gate that
  reads it — and count the inputs, because the uncounted one is arch-owned, non-normative, and
  therefore outside every mechanism built for the normative set.** *(Sub-lesson, and it fired in the
  very commit that added the gate: `link-gate` caught the new pin line naming
  `docs/status/TRACKER-…` **by path**. `oracle-pin.env` is non-prose and **publishes**, so that is a
  published file citing a path the release strips — the class `link-gate` exists for, found in the act
  of adding another gate. Describe the source; never name the path.)*

- **A SCAFFOLD PARAMS RENAME IS A WIRE-COMPATIBILITY BREAK AGAINST EVERY ORACLE PIN OLDER THAN IT —
  SO IT IS COUPLED TO THE RE-PIN AND CANNOT BE SCOPED AS "A RENAME".** Candidate (first occurrence,
  2026-09-16, enforcement exact). `GUIDE-CONFORMANCE` §7a.1 made the `reentry_*` carriers **plural** at
  `0.8.2.19` and 40 of 46 peers stayed singular, which reads as a mechanical 40-peer rename and is not.
  **The PINNED oracle sends the SINGULAR names.** A plural-only peer reads the triple as absent there,
  takes the **ambient arm**, and refuses — measured on the vanguard as **2 of 778 severities moving
  PASS → FAIL** (`dispatch_outbound_reentry`, `t1_2_concurrent_reentry`). Landing it across the cohort
  as a rename would take **every published row from `0F` to `2F`**. The guide's own note calls it *"a
  breaking params change"* without saying *against which pin*, and nothing on either side had joined the
  two facts. **Fix: accept BOTH spellings, the legacy one as an array of one, with the exit condition
  written AT THE SITE** — remove the fallback when `oracle-pin.env` names an oracle whose probe sends
  the new form, and not before. That keeps the cohort 0-FAIL at **both** check sets, which is strictly
  better evidence than either alone. **Enforcement: before sizing any change to a params contract, run
  the vanguard against the PINNED oracle as well as the candidate** — the candidate tells you the work
  and only the pinned one tells you the blast radius on what is already published.

- **ONE FILE, FIVE PARSERS, AND THE ONE THAT CANNOT READ THE FORMAT BLAMES A DIFFERENT ARTIFACT —
  AUDIT EVERY READER BEFORE EDITING A MACHINE-CONSUMED VALUE, INCLUDING A COMMENT ON IT.** Candidate
  (first occurrence, 2026-09-16, `tools/oracle-pin.env`; enforcement exact, and it was caught before
  the edit rather than by it). `oracle-pin.env` records a check count beside every **retired**
  executed digest (`# 740 checks`, `# 755 checks`, …) and **none beside the live one** — so the file
  that is authoritative for what the pin IS cannot answer how many checks it is, while it answers for
  all six pins it has retired. `check-set-gate.py` even PRINTS the canonical line for a new pin with
  exactly that trailing comment attached, i.e. the format is intended and the live entry is the
  outlier. Closing that asymmetry is a one-character-class edit to a value five tools parse.
  **Four of the five tolerate a trailing comment and one does not.** `check-set-gate` and `pin-gate`
  take `.split("=",1)[1].split()[0]`, `peer-contract/report.py` strips `#` first, `coherence-gate`
  matches a 64-hex regex — all safe. **`status-banner.py`'s `pin_values()` took the whole right-hand
  side**, so the digest-plus-comment compares unequal to the recomputed digest and the tool **refuses
  to write all 46 banners**, printing *"REFUSED — report is at check set … (re-measure, do not
  hand-edit)"* — **an accusation against the reports for a defect in the pin parser.** Measured both
  ways before relying on either: old parser on a commented line returns the digest with
  `'   # 778 checks (78db4a9)'` appended; new parser returns the digest, 21 keys either way.
  **Two rules.** (a) **Before editing a value another tool reads, enumerate the readers and check each
  one's EXTRACTION, not merely that it reads the file** — `grep -rn <filename>` finds the readers and
  says nothing about how they parse. (b) **When one tool emits a format a sibling cannot consume, that
  is a defect in the pair, not in whoever next writes the format** — the same two-copies-of-one-
  convention drift this file records for lockfiles and dependency pins, in a 10-line config. Verified
  no value in the file legitimately contains `#` before making comment-stripping general.

- **"IS UPSTREAM STABILIZING?" IS A MEASURABLE QUESTION, AND THE REVISION COUNT IS THE WRONG
  INSTRUMENT — ANSWER THE COST QUESTION WITH THE ORACLE, NEVER WITH THE SPEC'S VERSION NUMBER.**
  Candidate (first occurrence, 2026-09-16, answering *"do we wait for the spec to settle?"*). Three
  measurements, none of which is the revision count: **(a) the counterpart's own open-question
  register** — the direct evidence of how much is queued, and it is in their tree, not ours
  (`48 CQs filed, 12 closed, a new round filed the same day`); **(b) new `[MUST]`-markers per
  revision**, which is the obligation rate rather than the edit rate (flat across thirteen
  revisions, the latest tying the arc's high); **(c) whether the ORACLE's core category set moved**
  — `coreProfileCategories`, unchanged at 16 across **59 oracle commits and +39 declared checks**.
  So *"the spec moved five times today"* and *"the cohort owes one rename"* were **both true**, and
  only (c) has a number a work plan can use. **The spec is what peers are WRITTEN against; the
  oracle is what turns a row red.** Peg a sweep to the re-pin, not to the version header — which is
  the vendored-snapshot/oracle-pin separation this file already declares, finally exercised under
  pressure. **Enforcement: before sizing a sweep, diff the oracle's core category set and run the
  candidate against ONE vanguard peer; publish the per-category attribution, never the raw
  new-check count** (39 new checks, 10 reaching a core run, 4 failing, one cause).
  *(Sub-lesson, the examined-zero-things class in a new carrier: **`strings <binary> | grep -x
  <name>` ALWAYS reports missing.** A compiled binary packs string data contiguously, so there is
  no whole line for `-x` to anchor to, and six checks I knew were present all read `MISSING` in one
  confident column. Validate such an instrument against a name that must appear in BOTH sides
  before believing either direction — the control is what said the binary was fine and the grep was
  not.)*

- **RATIFIED (second occurrence, different shape): a budget-starved run reads as a clean run,
  and the starved categories are where the real FAILs are.** First shape — **Unison #43**: two
  *slow* categories consumed the global budget and seven core categories reported
  `budget_exhausted`, which gates as FAIL but reads like a carve-out *skip*; diagnosing that as
  **latency** rather than as seven independent failures was the high-leverage move. Second
  shape — **asm-x86_64 / asm-arm64 / riscv64, 2026-08-17**: not slowness at all but a single
  **hung** check (`t2_2_connection_churn` burning 599 s of 600 s while every other category
  finished in ~0 ms), starving seven categories including the core `resource_bounds` — which,
  when driven directly, turned out to hold **two further real core FAILs** (`r1_payload_over_limit`,
  `r3_connection_flood`). Same masking mechanism, opposite cause. **Enforcement:** grep any
  census JSON for `budget_exhausted` before trusting its `summary` (the human output flags it
  with `!!`, the JSON does not — it files starved categories under `skipped`), and drive the
  starved categories with `-category <name>` rather than re-running the whole suite behind the
  hang. **Fix the peer; never raise `-timeout` to turn the report green** — raising it as a
  one-off *diagnostic* to surface hidden coverage is the opposite move and is fine.

- **RATIFIED, and it is the STALE-INPUT class reaching VENDORED DATA: a second copy of a corpus is
  a second authority, and the retired one answers.** 2026-09-02, closing the vector-layout migration.
  `shared/test-vectors/` held both `v0.8.0/agility-vectors-v1.cbor` (`8e7c5232…`) and
  `crypto-agility/agility-vectors.cbor` (`b5484e84…`); the peers' harnesses pointed at the first.
  The job read as directory-naming hygiene — `GUIDE-CONFORMANCE.md` §5.1 forbids a version stamp in
  a corpus directory or artifact name — and was actually a **supersession**: upstream had INVERTED
  `hash-format-sha-384.2` (the re-hash it used to pin is now a construction that MUST be refused,
  §4.5a item 1a floor-pins `system/peer`) and moved M3/M6 `expected_peer_a_content_hash` to
  floor-form. **Nothing failed while both copies existed**, because every peer reading the old path
  got the old bytes and agreed with them.
  **Why this carrier is worse than the artifact ones already recorded here** (a `.wasm` older than
  its source, a reverify overlay older than its census, a tracked report a pin behind): a stale build
  artifact is *derived*, so a rebuild reconciles it. **A vendored corpus reconciles with nothing** —
  it is authoritative by construction, so the duplicate is not stale data, it is a rival ground
  truth. Enforcement: **one copy of a vendored corpus, ever**; retired digests go in
  `shared/test-vectors/README.md` (keystone-owned — the corpora's own `CHANGELOG.md` are
  byte-identical vendors and must not be edited), so a supersession shows up as a changed digest
  rather than as two directories.
  **A TRANSCRIBED PIN IS A COPY WITH NO GATE ON IT, AND IT MAKES THE HARNESS COMPARE THE PEER TO
  ITSELF.** This is the half to carry. Four peers were affected and they split by *how* they consume
  the corpus, not by language: `elixir` and `ruby` LOAD it and both FAILED the same two gates the
  moment the duplicate went (`got 0166f421…, want 00af37ab…` — the peers were computing the
  forbidden SHA-384 form). `ocaml` and `csharp` TRANSCRIBE the values into their own source and both
  **PASSED** — `ocaml` at a confident `RESULT: PASS (25/25)` — while carrying the identical defect,
  because the peer computed the SHA-384 form and the test expected the SHA-384 form. That is the
  `oracle-bootstrap` HAVE/WANT shape in a new place, and the rule written then holds verbatim:
  **name the authority side of a comparison, and distrust any equality test whose two operands
  derive from the same source.** Enforcement: **when a corpus moves, re-run the peers that LOAD it
  AND the peers that TRANSCRIBE it — the second group is the one that will not tell you**; and a
  transcription site must name the corpus artifact it came from so the next reader can diff it.
  *(Detail, including the one peer predicted-failing and unmeasurable and the negative half nobody
  implements: `protocol-generator/shared/findings/superseded-corpus-duplicate-and-transcribed-pins.md`.)*

- **A CANDIDATE ORACLE CAN MAKE THE DOCUMENTED ENTRY POINT REPORT `FAIL` — AND EXIT NON-ZERO — ON A
  PEER THAT IS 0-FAIL, INCLUDING THE REFERENCE PEER.** Candidate (2026-09-08, and it is a re-pin
  blocker rather than a peer defect). At go `78db4a9` (778 executed) `connectivity/
  connect_ping_before_hello` SKIPs on any peer that does not serve the NETWORK-extension `ping`,
  and that skip is **not** in the §9.0 profile carve-out: the run prints `106 skip(s)
  auto-allowlisted … 1 skip(s) count as FAIL` and ends `Result: FAIL (un-allowlisted skips)` with
  a JSON summary of `0 failed`. **`go` does this too**, which is what makes it upstream's and not
  ours — and checking `go` first is the whole diagnostic, one run against the reference peer
  instead of an investigation into the peer in hand. The blast radius is the harnesses that
  propagate the oracle's exit code rather than `|| true`-ing it: those
  will exit 1 on a green run the moment the pin flips. **Route it with the re-pin; do not raise it
  as a peer finding, and do not paper over it by adding a `|| true` — the harnesses that hold the
  exit code hold it deliberately.**
  **CORRECTED 2026-09-16 — THE SET IS SIX, NOT FIVE: `io pd python prolog ruby sql`. IT WAS COUNTED
  BY MEMORY OF THE PEERS THAT HAD BITTEN US, AND `prolog` SPELLS THE SAME THING DIFFERENTLY.** This
  entry, and the `run-s4.sh` argv entry above it, both said five and named the same five. Measured on
  the wire at the 778-check pin, the 46-peer refresh returned rc=1 on **six**: the missing one writes
  `"$ORACLE" … || RC=$?` and `exit "$RC"` where the others write `rc=0; … || rc=$?`, so a survey keyed
  on the first spelling cannot see it. **That is the standing false-negative family — a count
  inheriting the shape of the search that produced it — and the fix is the standing one: derive the
  set STRUCTURALLY, from what each harness does with the exit code, never from a list of names.**
  `grep -LE '\|\| true' protocol-generator/*/run-s4.sh` is the wrong test too (every harness contains
  that string in a comment); read each `"$ORACLE"` invocation's own continuation. The measured
  discriminator, and it needs no grep at all: **run the cohort and list the peers that exit non-zero
  on a 0-FAIL report** — six, every one for this same un-allowlisted skip.

- **A REFERENCE BUILT FROM A SIBLING CHECKOUT'S HEAD IS AN UNPINNED INPUT DECIDING A VERDICT — and
  it can be a DIFFERENT REPO than the one you think.** RATIFIED 2026-09-02 (`ada`), and it is the
  content-anchor rule ([ADR-0012] Am. 1) reaching the one axis nobody had swept. `ada`'s `run-s3.sh`
  did `go build ./entity-peer ./probe-peer` out of `$HOME/projects/entity-systems/entity-core-go`,
  printed the HEAD it used, warned if the tree was dirty, and carried on. Measured: that directory is
  **a different line of history altogether** — branch `main`, remote `digi`, subjects *"testing
  validate continuation refinements"* — in which the pinned commit `f313028` **does not exist**. The
  canonical sibling is `<keystone>/../entity-core-go` (what `oracle-bootstrap.sh` defaults to) and it
  has the pin. So the gate reported `[FAIL] session established (§4.1 handshake) — authenticate
  failed`, which reads as an `ada` defect and is not one: pointed at the pinned artifacts it is
  **GREEN, 3 check-groups, both directions**.
  **The fix is to consume `output/s4-oracles/`, never to build a reference** — those artifacts are
  content-anchored and `oracle-bootstrap.sh` hard-stops rather than falling back silently. `datalog`
  and `sql` already did this; `ada` was the only S3 harness that did not. **`probe-peer` joined the
  pinned set in the same commit**, because the reason `ada` was building its own was that the pinned
  set carried a reference *responder* and no reference *client* — **if the reference peer is pinned,
  so must be the reference client**, or the gap gets filled by whatever is on the disk.
  **Enforcement: `git grep -n "entity-core-go\|GO_ORACLE" -- "protocol-generator/*/run-*.sh"` must
  only ever match a COMMENT.** A harness that names the sibling repo at all is one that can build
  something the pin does not describe.

- **MAINTENANCE TIERS ARE ACTIVE — do not run a 45-peer census for a re-pin.** (Turned on
  2026-08-17; the policy existed as prose since ~15 peers and was never honoured, because §4
  named 17 peers of a 46-peer cohort so "re-run Tier-1" was undefined for the other 29.) The
  rule now: **an oracle re-pin is landed when `M1` is re-run and 0-FAIL** — `go` `haskell`
  `lean` `ocaml` `swift`, 5 peers. `M2` (8) catches up behind it, `M3` (13) on spare
  capacity / pre-release / adopter ask, `probe` (18) when its own axis is touched, and
  `exploratory` (2) never gates. **Run everything only before a release** — tiering governs
  the cadence *between* releases, never what a release claims, and it never affects whether a
  peer may be published ("no green report → no publish" is unchanged for every tier).
  - **Roster: `tools/peer-tiers.tsv`** — the single canonical home, all 46 peers, one tier
    each, plus the oracle pin each peer's current verdict was measured at. `CONFORMANCE-MATRIX.md`
    §1's `Maint.` column mirrors it; §4 explains it. Nothing else defines a tier.
  - **Commands:** `tools/tier-status.py` (where every peer stands; `--gate` exits non-zero
    unless M1 is current and 0-FAIL) · `tools/run-cohort-census.sh --tier M1` ·
    `--tier M1,M2` · `--stale` (only peers behind the current pin). A tier run gates **only
    the peers it ran**, or the exit code stops meaning anything.
  - **`M` is a deliberate prefix.** These are NOT `research/LANDSCAPE.md`'s tiers 1–5, which
    classify the *language landscape* ("what is worth building"). Both used to be bare
    `1`/`2`/`3` and were routinely conflated. They do not correlate — verified: `ocaml` is
    landscape Tier 5 and maintenance **M1** (lowest pull, highest discovery yield);
    `rust`/`python` are landscape Tier 1 and maintenance **M2**; `lean` is **M1** and does not
    appear in `LANDSCAPE.md` at all.
  - **A stale lower tier is a tracked state, not a failure.** Record it, don't panic-fix it:
    `tier-status.py` prints `STALE@<pin>` for any peer behind the current `ref`.

- **The core-gate FINGERPRINT does not certify the gate — the CHECK-SET DIGEST does.**
  `core_gate_fingerprint` hashes the category set + type floor, i.e. *which categories run*.
  It is blind to *what those categories assert*. Measured at the `cc1970f → af8a582`
  bucket-B cutover: four hard-FAIL vectors were added **inside existing core categories**
  (`connectivity/handshake_nonce_single_use`, `authz/f40_id_scope_{exclude_literal,
  include_no_overgrant}`, `concurrency/t1_4_frame_write_atomicity`), most of the cohort
  flipped PASS → FAIL, and the fingerprint stayed **byte-identical** (`8261a033…`). So
  "same fingerprint ⇒ the verdict carries forward" is unsound and is withdrawn.
  `tools/oracle-pin.env` now also carries `check_set_digest` (sorted set of declared check
  names); `oracle-bootstrap.sh` requires **both** to match before it says "nothing to do"
  — comparing the fingerprint alone would have declared a stale oracle current and run the
  old check set over all 43 peers.

- **Never raise `-timeout` to make a red run green — and read the human output, not just the
  JSON, to find out whether the budget held.** `-timeout` is a **GLOBAL** budget, not
  per-category. **Its default is `10m` as of the `de8f807` oracle** (verify with
  `output/s4-oracles/validate-peer -h | grep -A2 timeout` — it was 60 s at earlier pins, and
  this file recorded 60 s until 2026-08-17; the nine harnesses once flagged for defaulting to
  5–15 min are mostly at-or-under the current default, so re-check before citing that as drift).
  Record the budget a run used alongside its P/W/F/S, or the number is not comparable.
  **The starvation asymmetry is the trap** (2026-08-17, asm/ISA trio — `research/stewardship/
  SESSION-2026-08-17-asm-budget-starvation.md`): when the budget expires mid-suite the oracle's
  *human* output shouts `!! WHOLE CATEGORIES NEVER RAN … this is coverage loss, not a slow
  peer`, but the *JSON* files those categories under `skipped` — so `{"failed": 1}` is all a
  summary-only reader sees. One hung check (`t2_2_connection_churn`, 599 s of a 600 s budget)
  starved **seven** categories including the core `resource_bounds`, hiding **two more real
  core FAILs**. Grep any census JSON for `budget_exhausted` before trusting its summary; a
  starved run is an **incomplete measurement**, and its P/W/F/S is a floor, not a result.
  Raising `-timeout` to *surface* a starved category as a one-off diagnostic is legitimate and
  is not what this rule forbids — but prefer `-category <name>`, which drives the hidden
  categories directly in seconds instead of re-running the whole suite behind the hang.

- **An anchor is only as good as its INPUT — `check_set_digest` was reading go's test fixtures.**
  Found by arch 2026-08-21 (`ROUTING-2026-08-21-m` §3), measured here before fixing.
  `oracle-bootstrap.sh` computed the digest over `git archive <ref> cmd/internal/validate | tar -xO`,
  and **`git archive` of a DIRECTORY includes `_test.go`** — so the anchor this repo makes
  *authoritative for carry-forward* ("Both must match, or the cohort re-runs") was hashing test
  fixtures alongside real checks. **A test fixture could order a 45-peer census.** Measured
  `d697b9a → c1b0708`: directory-with-tests moved `ca0c988f… → 3e749f37…` while the non-test declared
  set was **identical at 1137 names both sides**; the entire move was three strings in
  `runner_test.go` (`before_gate`, `behavioral_body_ran`, `behavioral_root`), none of which exists in
  the built binary. **Fixed** — `validate_sources()` enumerates non-test `.go` paths explicitly.
  The generalizable half: `core_gate_fingerprint`, one function down, had normalized against exactly
  this class for months (hash the *semantic content*, not the raw bytes) and **the normalization was
  never carried across to the neighbouring anchor** — when you harden one anchor, check its siblings
  for the same defect the same day. **Rule: a file the built oracle cannot contain must not be able to
  move the pin.** Enforcement: the path filter in `validate_sources()`; regression-test it by adding a
  `.Declare("x")` inside any `_test.go` and confirming the digest does not move. **Comparison
  consequence:** every digest recorded before this fix (`43c23708…`, `3cfd272f…`, `f3a1516d…`,
  `8574f9d6…`) used the old method and is NOT comparable to a new one — `de8f807` recomputed under the
  new method is `06ca8e10…` (1120 names). Never diff across the method boundary.

- **RATIFIED (third occurrence — and a FOURTH landed 2026-08-21 at `de8f807 → c1b0708`): an upstream
  that is "all extension work" can still move the
  core gate through ONE file — attribute new checks BY CATEGORY, never by commit message.**
  Measured 2026-08-20 at `de8f807 → d697b9a`: 60+ go commits whose subjects are almost entirely
  REGISTRY/REVISION/subscription work (`registry v1.19`, daily three-way rounds with arch), which
  reads as "extension churn, the pin is fine." It is not. `check_set_digest` moved
  `43c23708… → ca0c988f…` (1139 → 1156 declared checks) and **5 of the 17 new checks are inside
  the core `capability` category** — the 0.8.1 CAP fold's (r)–(v) plus the later CAP-6a ingest
  check (`configure_empty_grants_withdrawal`, `configure_rejects_base58_partial_prefix`,
  `request_mint_temporal_ceiling`, `request_ttl_zero_and_overflow`,
  `ingest_rejects_unrepresentable_expiry`). `core_gate_fingerprint` stayed byte-identical
  (`8261a033…`) for the **third** time in this exact shape (`cc1970f→af8a582`,
  `fceb61f→de8f807`, now this) — the pattern is reliable enough to plan around: **new hard
  checks land inside EXISTING core categories, so the fingerprint never moves.**
  **Enforcement, cheap and exact:** diff declared check names *per file*, then map each file to
  its category constant and test that constant against `coreProfileCategories` in
  `cmd/internal/validate/profile.go` — a file whose `cat…` const is not in that map cannot gate,
  and one that is, does. Nine files changed here; only `capability.go` was in the core set.
  Do NOT reason from `git log --oneline`, and do not treat a quiet-looking subject line as
  evidence. (Corollary, same session: **a sibling-repo audit conclusion has a shelf life of
  hours when the sibling is actively moving.** Our `4d47573` audit read arch at `cb5df2c` and
  correctly concluded "we owe nothing yet"; the CAP fold landed at `bdb48f2` **83 minutes
  later**. Record the sibling HEAD an audit was taken against — `4d47573` did — and re-resolve
  it at sign-off, not at audit time.)

- **`-category <name>` OVERRIDES the `--profile core` carve-out — a category driven directly is NOT
  the same measurement as that category inside a core run.** Cost real time 2026-08-21 while
  diagnosing `lean`: `run-s4.sh -profile core -category tree_operations` ran the EXTENSION-TREE ops
  (snapshot/diff/extract/merge) that `--profile core` skips wholesale, producing 29 FAILs that look
  like a catastrophic regression and mean nothing — the peer is a core peer and correctly does not
  implement them. Naming a category forces its whole check set regardless of profile. This does not
  retract the standing advice to drive a starved category with `-category` instead of re-running the
  suite — it sharpens it: **read such a run for the specific check you are chasing, never for its
  Summary line**, and never compare its P/W/F/S to a `--profile core` row.
