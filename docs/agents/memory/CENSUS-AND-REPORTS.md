# Census and reports — keystone memory

Reading a run: rates and intermittents, stale and mixed-age reports, exclusions, cross-tabulation, and what the cohort can tell you that one peer cannot.

**Arrive here when:** a number moved, a peer looks unfairly good or unfairly terrible, or a result will not reproduce.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- "FLAKY" AND "LOAD" ARE NOT DIAGNOSES — THEY ARE THE NAMES WE GIVE A RACE WE HAVE NOT LOOKED FOR YET. RE-RUN N TIMES AND COUNT
- A sibling clearing the bar with a costlier seam disproves a "substrate can't" ceiling
- A CENSUS FIELD THAT NAMES THE WRONG RUNG PRODUCES A SCOPE ESTIMATE THAT IS WRONG IN THE EXPENSIVE DIRECTION — AND THE FIELD THAT MISLED US IS THE ONE BUILT TO PREVENT EXACTLY THIS
- THE COHORT IS THE INSTRUMENT THAT SEPARATES TWO CAUSES ONE PEER CANNOT DISTINGUISH — 404 AND 501 AT THE SAME STEP ARE DIFFERENT DEFECTS, AND ONLY THE SPLIT SAYS SO
- A SHARED EARLY ANSWER HIDES AN UNKNOWN NUMBER OF CAUSES, AND A `SKIP` COUNTS — not just a FAIL
- A FAILURE COUNT CANNOT SAY WHETHER ANY PEER HAS THE MECHANISM AT ALL — CROSS-TABULATE AGAINST THE NEIGHBOURING ROW, AND THE EMPTY CELL IS THE FINDING
- CLASSIFY A PROBE REPORT BY WHAT IT CONTAINS, NOT BY WHEN IT WAS WRITTEN — AND A ROSTER RUNNER THAT DIES PARTWAY MAY REPORT NOTHING
- RATIFIED — THE VOID IS THE FINDING, AND ITS CAUSE IS USUALLY NOT IN THE FAMILY'S OWN SUBJECT
- AN EXCLUSION IS A CLAIM WITH AN EXPIRY DATE — and the one that hides longest is enforced by the tool that would disprove it
- A REPRODUCTION IS A MEASUREMENT SETUP, NOT A COMMAND — and if the probe script is not kept, the rate cannot be re-measured, only re-argued
- NEW COVERAGE THAT TURNS A PEER RED IS THE COVERAGE WORKING — MEASURE THE BEFORE AND AFTER RATES BEFORE CALLING IT ANYTHING
- TWO MEASUREMENTS AT ONCE IS ONE MEASUREMENT AND SOME WRECKAGE — AND ITS FAILURES LOOK LIKE PEER DEFECTS
- `output/scratch/census/` is NOT scoped to the last run — stale per-peer JSONs from earlier censuses sit beside the fresh ones

---

- **"FLAKY" AND "LOAD" ARE NOT DIAGNOSES — THEY ARE THE NAMES WE GIVE A RACE WE HAVE NOT LOOKED
  FOR YET. RE-RUN N TIMES AND COUNT.** RATIFIED 2026-09-01 (`zig`), and it is the sharpest process
  failure this repo has recorded because the wrong explanation was *written into a commit message*
  before anyone objected. A census run came back `756 · 288P/27F` — `t2_2_connection_churn` failing
  at cycle 53, then 27 downstream checks reporting connection-refused. An isolated re-run passed,
  and that single passing re-run was published as *"external load, not the change"*. It was not.
  **Re-run five times on an idle host: 3 of 5 FAILED.** Load was never the variable.
  **The intermittency was TWO independent remotely-triggerable process aborts**, and the peer's own
  `--profile core` suite had been carrying them for months:
  - **A use-after-free**: `readLoop` spawns a DETACHED thread per inbound EXECUTE holding a `*Io`
    and `*Conn` that point INTO the connection's `ConnState`, then returns the moment the client
    closes — and the caller frees that state immediately. `Segmentation fault … io.gpa.destroy(ctx)`.
  - **A panic inside a call documented as best-effort**: `setNoDelay` carried *"a failure just
    leaves Nagle on, not fatal"* and a `catch {}`, and aborted the process anyway, because
    `std.posix.setsockopt` maps `BADF`/`NOTSOCK`/`INVAL`/`FAULT` to **`unreachable`** (the stdlib's
    own comment on those arms is *"always a race condition"*) and `unreachable` is a PANIC, which
    no `catch` can intercept.
  **THE MEASUREMENT IS THE METHOD, and the middle row is the lesson:**
  `before 3/5 FAIL · after fix 1 → 1/6 FAIL · after fix 2 → 0/22 FAIL`. **Fix 1 alone reads as
  "mostly fixed" and ships a peer that still aborts** — one bug masked the other, and only counting
  over repeated runs could tell them apart. A single green re-run is not evidence a race is gone; it
  is one sample from a distribution nobody has measured.
  **Why churn specifically, and why months of green runs missed it:** 100 open → request → close
  cycles is a loop that closes the connection *mid-dispatch by construction*. A sequential suite
  never opens that window. **When a check that stresses lifecycle is the one that fails, suspect a
  lifetime bug, not the harness.**
  **Enforcement, and it is a rule about the report rather than the code: an intermittent result may
  not be attributed to anything until it has been re-run and the failure rate recorded.** Cite the
  count (`3 of 5`), never an adjective. If the mechanism is not named, the finding is "not
  root-caused", which is an honest state; "flaky" and "load" are claims, and both were false here.
  *(Sub-lesson, cheap and general: **a detached worker must not outlive the state it borrows.**
  Register the in-flight count BEFORE the spawn — the thread can finish before `spawn()` returns —
  release it LAST in the worker's teardown, because the owner may free everything the instant it
  reaches zero, and await it before the owner frees. And: **a "best-effort" wrapper is only
  best-effort if its failure path returns; check whether the library panics on the errno you are
  ignoring.**)*
  **Residual, named rather than folded into the win:** `resource_bounds/r3_connection_flood` failed
  **2 of those 22** post-fix runs and is a DIFFERENT intermittent — churn is 0/22 — not root-caused,
  handed off. Reporting a partial fix as a whole one is the same defect as reporting a race as load.

- **A sibling clearing the bar with a costlier seam disproves a "substrate can't" ceiling.** Io's
  "single-threaded throughput ceiling" verdict was contradicted by Oz passing the same checks with
  *slower* co-process crypto → forced re-measurement → two fixable bugs, ceiling retracted. Cross-peer
  differentials are a first-class diagnostic; an unreconciled ceiling contradicted by the cohort is a
  pessimistic-direction overclaim, as much a misreport as a false green.

- **A CENSUS FIELD THAT NAMES THE WRONG RUNG PRODUCES A SCOPE ESTIMATE THAT IS WRONG IN THE
  EXPENSIVE DIRECTION — AND THE FIELD THAT MISLED US IS THE ONE BUILT TO PREVENT EXACTLY THIS.**
  RATIFIED 2026-09-09, closing F62's remaining six. The finding sized them as one repair —
  *"they need a container the wire register can write before they can have an index at all"* —
  and that was **true of three and false of three**: `cobol`, `fortran` and `forth` were
  ALREADY walking the entity tree at §6.6, correctly, and the `404` came from the rung
  **below** resolution, where a body-selection ladder spelled *"I resolved this and have no
  body"* as `handler_not_found`. One arm each. The estimate came from the finding's own
  evidence table, which was built from each peer's H5 `dispatch_read_site` — and on those three
  that field named the **ladder**, not the resolution site. `dispatch_read_site` exists
  *precisely* to tell a live host from a dead map (it is the field the four wrongly-nominated
  hosts taught us to add), and it mis-scoped a repair by naming the second rung of a
  two-rung mechanism.
  **This is the standing "TWO SITES FOR ONE REFUSAL" rule reaching the CENSUS rather than the
  fix.** There the repair went to the unreachable site and measured as a no-op; here the
  *measurement* recorded the wrong site and the no-op was in the plan. **Enforcement: for any
  mechanism that resolves and then selects, the census field names BOTH rungs and says which
  one answered the observed status.** The one-line form — `resolve X (§6.6 walk, file:line);
  the ladder below it is BODY SELECTION, file:line` — is what all six now carry, and it is what
  makes the next reader's estimate right.
  **AND A WALK CAN BE CORRECT AND QUERY A KEY SPACE NOTHING ELSE WRITES.** `forth`'s
  `resolve-handler` was a faithful §6.6 backward walk over the store and was structurally blind
  to every wire write: `register-handler` bound its bootstrap `system/handler` entity at the
  **bare pattern** while `publish-handler-dispatch`, the §6.2 register op and every validator
  `TreeGet` use `/<local>/<pattern>`. Two key spaces for one fact, so §6.6 equivalence had
  nothing to be equivalent TO — and **reading the walk clears the peer**, because the walk is
  right. **Enforcement: for any store-backed resolution, enumerate every WRITE site's key form
  and require exactly one.** `git grep` the bind calls, not the lookup.
  **THE PLANT IS WHERE THAT SHOWS UP, AND A PLANT THAT BREAKS THE PEER HAS NOT DEMONSTRATED THE
  DEFECT.** Reverting only `forth`'s walk — leaving the canonical bootstrap bind — made every
  built-in unresolvable: positive control `404`, verdict `UNTRUSTED`, no case executed. That is
  a red, and it proves nothing about the repair. **Rule: a mutation control must reproduce the
  ORIGINAL symptom with the positive control still green.** If the positive control fails, the
  plant is too broad; widen the revert to the whole change and re-run (both halves back to the
  bare key → `NOT-RESOLVED`, which is the pre-fix peer exactly). The failed plant is worth
  recording rather than discarding — it is the cheapest proof that two edits are one change.
  *(Sub-lesson, and it is the examined-zero-things rule catching the person who keeps citing it:
  the script written to prove "0 severities moved" first printed **`0 of 0`**, because it read a
  `categories/checks` shape these reports do not have. **The denominator is the only reason that
  was visible.** Print the count AND assert it non-zero, in a throwaway diff script as much as in
  a gate.)*

- **THE COHORT IS THE INSTRUMENT THAT SEPARATES TWO CAUSES ONE PEER CANNOT DISTINGUISH — 404 AND 501
  AT THE SAME STEP ARE DIFFERENT DEFECTS, AND ONLY THE SPLIT SAYS SO.** Same finding, and it is the
  standing *"where a single peer cannot distinguish 'this peer is broken' from 'our request was', the
  verdict must defer to the cohort"* rule earning a second, sharper form. From one peer, a dispatch
  that fails after a successful register is just a failure. Across 46: **26 answer 200** (resolution +
  evaluation), **12 answer 501** — which *proves resolution succeeded* and the body could not run —
  and **7 answer 404**, which proves resolution never found what register wrote. The 501 group is what
  makes the 404 group a **§6.6 core** finding rather than a **§6.13(a) extension** one, and no amount
  of staring at any single peer produces that distinction. **Rule: before classifying a failure, ask
  what the OTHER answer to the same step would have meant, and check whether any peer gives it.**

- **A SHARED EARLY ANSWER HIDES AN UNKNOWN NUMBER OF CAUSES, AND A `SKIP` COUNTS — not just a FAIL.**
  Ratified 2026-09-17 (`cobol`), extending the standing rule from the `go` vanguard. There, four
  checks FAILING behind one `400 invalid_params` were attributed to one cause and were two. Here the
  candidate oracle reported **`1F` on `dispatch_outbound_ambient_refused` with the F63 narrow-grant
  discriminator and the multisig row SKIPPED behind it** — and a SKIP is the easier one to
  misread, because it looks like a carve-out rather than a consequence. Both PASSed once the first
  answer was removed. **Read the skips under a failing check as part of that check's blast radius,
  and size the work only after the early answer is gone.**
  *(And the same run is why `cobol` could not be swept as a rename: `boot-handler` bound **no §6.8
  grant at all** — only the wire register op ever wrote one — so the gate could not be landed before
  the thing it reads. The `nim` shape. **When a gate has nothing to read, the missing artifact is the
  first half of the work and the gate is the second**; landing only the gate produces a peer that
  fails closed everywhere and reads as over-strict.)*

- **A FAILURE COUNT CANNOT SAY WHETHER ANY PEER HAS THE MECHANISM AT ALL — CROSS-TABULATE AGAINST
  THE NEIGHBOURING ROW, AND THE EMPTY CELL IS THE FINDING.** RATIFIED 2026-09-14, driving the cell
  census's last two structural zeros (`tools/arc-probe` families F and G, `F84`/`F85`). `G2`
  composes a caller `exclude` that VACATES the §5.2 dispatch check with a grant that does not cover
  the excluded target, so §6.3's `check_path_permission` — which the spec calls *"not a secondary
  check … the sole enforcement wherever the subject is derived after dispatch"* — is the only thing
  standing. **33 of 43 peers served the uncovered path.** That number is a list of peers to fix and
  it is the wrong reading. The 2×2 against `A3` (selection among two IN-GRANT targets) is the right
  one:

  | | `G2` conforms | `G2` discloses |
  |---|---:|---:|
  | **`A3` conforms** | **0** | **0** |
  | **`A3` does not** | 10 | 33 |

  `A3` is `no` on **45 of 45** — not one peer selects from the effective set — and **the top row is
  EMPTY**: there is no peer where the selection is wrong and the path check catches it. So the
  finding is not *33 peers have a bug*, it is *a layer the spec designates as sole enforcement has
  zero working instances in the cohort*, which is a different claim with a different owner and a
  different repair. **The 10 that look safe are safe for unrelated reasons** — a raw arity check
  (the arm `F71` warns refuses a legitimate single-entry effective set), a raw-target count, a
  blanket 403 — which is the standing *"a check can pass for the wrong reason"* rule, and only the
  cross-tabulation exposes it. **Enforcement: whenever a probe row measures a BACKSTOP, tabulate it
  against the row measuring the thing it backs up. A backstop is only demonstrated by a peer that
  fails the primary and passes the backstop; if that cell is empty, nobody has it** — and a bare
  failure count will read as though somebody does.

- **CLASSIFY A PROBE REPORT BY WHAT IT CONTAINS, NOT BY WHEN IT WAS WRITTEN — AND A ROSTER RUNNER
  THAT DIES PARTWAY MAY REPORT NOTHING.** RATIFIED 2026-09-14 (second occurrence of the stale-probe-
  directory class, and the control that fixed it is stronger than the mtime check the standing rule
  prescribes). A 46-peer roster run was launched as `nohup … &` inside a background runner — the
  double-backgrounding trap this file already records — and was killed at peer 19. `output/scratch/
  arc/` then held **45 well-formed JSONs**, 19 from the live binary and 26 from a run two hours
  older that **did not contain the families being counted at all**. Nothing warned. Reading the
  directory as a cohort picture would have published a table in which 26 rows were silently absent
  rather than measured.
  **The mtime check would have worked and the CONTENT check is better: ask whether each report
  carries the rows you are about to count.** A report from an older binary is definitionally
  missing them, and the check is indifferent to clock skew, to a peer re-run by hand mid-roster, and
  to the case where two runs are minutes apart. One loop, no judgement.
  **And the runner's own failure list did not name the peer that failed.** `unison` died on a
  `permission denied` writing a TRACKED transcript output and left its previous report in place; the
  content check is what surfaced it, and re-running it alone was clean — **a filesystem-permission
  failure is contention until proven otherwise**, which the standing rule says and which held again.
  **Enforcement: a cohort table is assembled by a loop that asserts the expected rows are present in
  every report, and prints the count of reports it rejected.**
  *(And a parser that cannot read a payload must say WHAT IT SAW. The listing reader reported
  *"no readable entry list"* for a listing that was right there — `entries` is a MAP on the
  reference peer, not an array — and separately for a peer whose `entries` map is **EMPTY**. Those
  are three different facts (wrong shape assumed · nothing enumerable here · genuinely unreadable)
  and **only one of them invalidates the control**; collapsing them sent the reader looking for a
  parser bug in the one case where the peer was the answer. A failed parse reports the field names,
  their types, and the first element's keys.)*

- **RATIFIED — THE VOID IS THE FINDING, AND ITS CAUSE IS USUALLY NOT IN THE FAMILY'S OWN SUBJECT.**
  2026-09-15, four peers in one tranche, four different causes, every one presenting as the same
  word. `arc-probe` grades a family whose control failed as VOID rather than owed — correctly, since
  unmeasured is its own state — and the temptation is to read VOID as "nothing to do here yet."
  Every one of the four was a live defect ONE LAYER UP from what the family measures:
  - `smalltalk` and `forth`, 7 VOID each — the handler-path predicate above. Families E, F and G all
    begin by MINTING, so a peer that cannot use its own minted token voids all three at once.
  - `cobol`, 3 VOID — §5.2's `peers` default read as an absence, so every mint carrying an explicit
    `peers` dimension was refused at MINT.
  - `wasm-wat`, 10 VOID — the peer refuses `system/capability:request` under the §6.9a discovery
    floor, which is a LAUNCH-CONFIGURATION question and not a defect: `run-mint-floor.sh` is the
    right instrument and the rows then read normally.
  **Enforcement: diagnose the CONTROL before reading a single row of its family, and expect the
  cause to be outside the family's subject.** The count of VOID rows is a measure of how much one
  upstream defect is hiding, not of how much is owed — `smalltalk` went from "4 owed + 7 VOID" to
  0 of 15 on one predicate.

- **AN EXCLUSION IS A CLAIM WITH AN EXPIRY DATE — and the one that hides longest is enforced by
  the tool that would disprove it.** RATIFIED 2026-08-30 (`apl`; second occurrence of the
  stale-input class in the shape where the *gate itself* is the stale input, after
  `check-set-gate`'s unconditional reverify overlay). `apl` was carried for months as
  `UNMEASURABLE — upstream-blocked; excluded from census by standing policy`, and the published
  headline read `45 of 45 measurable` on the strength of it. **All three clauses were false**, and
  the peer measured `755 · 0F` on the first attempt in 109 s:
  - the *upstream* claim was a bad inference (see the tarball bullet above — GNU reorganized, it did
    not delete);
  - the *toolchain* claim had been repaired three days earlier and nobody re-checked — the image was
    force-bumped to APL 2.0 on 2026-08-27 and **built successfully on 2026-08-28**, so the label
    outlived its own cause;
  - the *policy* clause was a hard-coded `apl) ... rc=125` in `run-cohort-census.sh` plus an
    `$1 == "apl" { next }` in `roster_peers()`, so **the one peer nobody could measure was the one
    peer the census would not attempt.** An exclusion that suppresses its own falsifier is
    permanent by construction, and it degrades silently: nothing errors, nothing warns, the tier
    report just says `NO-REPORT` next to a note explaining why that is fine.
  **What makes this worse than an ordinary stale fact is what it does to a NUMBER.** "45 of 45
  measurable" reads as a complete measurement and was one unrun command away from "46 of 46" — the
  word *measurable* is doing load-bearing work that no gate checks, because a peer that is not
  measured produces no report to be found non-comparable. `check-set-gate` and `tier-status` were
  both green throughout; they can only audit reports that exist.
  **Enforcement, and it is structural rather than a grep: no per-peer exclusion may live in the
  measurement tooling.** `run-cohort-census.sh` now carries none, and `roster_peers()` no longer
  filters — every peer in `tools/peer-tiers.tsv` is measured, so a peer can leave the census ONLY
  by leaving the roster, where `tier-status.py` reports its absence as backlog. **Generalize: when
  you must skip something, encode the skip where it is VISIBLE as a gap, never where it is
  invisible as a policy** — and wire every exclusion to a re-check of the condition that justifies
  it, or delete it. *(Sub-lesson worth its own line: the peer had sat out THREE cohort-wide
  propagation passes because of the label — 7 of its 8 FAILs were defect classes closed elsewhere,
  including the §6.2 register guard that reached 44 of 45 peers on 2026-08-17 with `apl` the sole
  omission. **An excluded peer does not hold still; it accumulates every debt the cohort pays
  down**, so the cost of an exclusion grows with exactly the thing that makes it feel safe to keep.)*
  **AND THE HAPPIEST FORM OF THE SAME CLASS: A PUBLISHED MEASUREMENT CAN BE SUPERSEDED BY THE VERY
  RULING IT ASKED FOR, AND IT GOES STALE SILENTLY BECAUSE NOTHING ABOUT IT LOOKS WRONG.** 2026-09-09,
  the §4.7 pre-hello `authenticate` census. We measured a **38/6/1** cohort split on 2026-08-30 and
  routed the normative question; arch folded it **the next day** (0.8.2.1, FM-1), we vendored it at
  0.8.2.3 and swept the cohort at `5a53b75c`, and the oracle grew `connect_prehello_authenticate`.
  Re-measured today: **46 of 46 uniform**, split gone. The register and the matrix had recorded the
  *ruling* as closed; **the published TABLE of what the peers do was ten days stale in four places**
  and nothing could see it, because a dated measurement with a date on it reads as history whether
  or not it still describes the tree.
  **Two enforcement points, and the second is the reusable one.** (a) **When a finding routes a
  question, the answer landing upstream is a trigger to RE-MEASURE, not only to update a status
  cell** — the whole point of the cohort number was the disagreement, and a resolved disagreement
  changes the number. (b) **A finding that states its own exit condition has handed you a gate;
  re-read it when the condition fires.** This one said *"if architecture rules, the ruling belongs
  in `validate-peer` as a vector — at which point this probe should be deleted, not kept as a second
  source of truth."* That sentence decided the whole disposition ten days later and cost nothing to
  honour. **Write the exit condition into the finding; it is the cheapest gate in this file.**
  *(Sub-lesson, and it is calibration in the flattering direction: the one row that looked like a
  disagreement with `entity-core-formalization`'s source census — `csharp`, which they read as `400`
  and which now measures `401` — was **the sweep, not a miss**. A one-line `git show` on the sweep
  commit showed their reading was correct for the source they read. **Before recording a sibling's
  claim as wrong, check whether YOUR tree moved under it**, and date what each side was looking at.)*

- **A REPRODUCTION IS A MEASUREMENT SETUP, NOT A COMMAND — and if the probe script is not kept, the
  rate cannot be re-measured, only re-argued.** RATIFIED 2026-09-02 (`zig`), and it is the standing
  *"re-run N times and count"* rule failing at its own next step. That rule produced an honest number
  in the morning — **5 aborts in 60 full `--profile core` runs (8%)** — and the probe that produced it
  was never saved. The same afternoon, on the **same source**, the abort would not reproduce at all:
  **0 of 130** sequential runs at `--cpus=4`, uncapped across all 32 cores, and with 12 CPU burners
  oversubscribing the container, plus **0 of 100** `-category concurrency` runs. Nothing in the tree
  had changed. The only surviving evidence of how the morning had measured it was a **port number in
  a log** (`LISTENING 127.0.0.1:7714` on run 14 — one port per run, i.e. the runs were concurrent),
  and reconstructing that regime from scratch cost more than keeping the script would have.
  **Three things generalise, and the second is the one that changes what you write down:**
  (a) **Commit the probe beside the finding.** A rate is a claim about a setup; without the setup it is
  an anecdote with a denominator. `output/scratch/zig-abort-probe.sh` now carries its own conditions in
  its header, including the ones that did NOT reproduce.
  (b) **A fix for an intermittent you can no longer reproduce is justified STRUCTURALLY or not at
  all — and 100 clean runs is not evidence when the baseline is also 0 of 100.** Post-fix greens are
  the number everyone wants to publish and they say nothing here; the honest claim is *"the mechanism
  is removed and the count cannot speak to it"*, and the enforcement point is a grep (`detach()`
  returns 0 outside comments), not a tally.
  (c) **When the headline intermittent will not reproduce, measure what WILL.** The same change also
  removed a 20.6-second `t2_2_connection_churn` stall — unfixed **7 of 100**, fixed **0 of 100** — and
  a third build carrying only HALF the fix scored **10 of 100**, which is what isolated the cause to
  the other half. A variant that changes one half at a time is how an attribution stops being a story;
  it cost one extra 100-run batch and replaced a plausible sentence with a measured one.

- **NEW COVERAGE THAT TURNS A PEER RED IS THE COVERAGE WORKING — MEASURE THE BEFORE AND AFTER RATES
  BEFORE CALLING IT ANYTHING.** RATIFIED 2026-09-03 (`io`), and it is the standing *"a fix that raises
  a peer's FAIL count is a finding, not a regression"* rule reached from the coverage side rather than
  the fix side. Folding `-reference-peer` in took 45 peers to `758 · 0F` and `io` to **28F**. The
  temptation is to call a 50%-reproducing failure flaky, or to revert to protect a 46-of-46 row. Both
  are forbidden and the counting is what settles it:
  `pre-fold (756, no reference peer) 0 of 6 FAIL · post-fold (758, with it) 3 of 6 FAIL`, always at
  idx 678 `concurrency/t1_2_concurrent_reentry`, always 28 FAILs with 27 cascading behind one.
  **The three new checks all PASS, at idx 674–676, immediately before the failure** — so the finding
  is not that io fails the new checks, it is that nothing had ever driven io's reentry path
  immediately before the *concurrent* one. Control (reference peer up, origination not executed via
  `-category concurrency`): clean 6 of 6 — which **narrows toward residue over CPU contention and does
  not prove it**, because an isolated category is a different timing regime (the `c` lesson). So it is
  recorded as **NOT root-caused**, which is an honest state; "load" and "flaky" are claims.
  **The rule: a coverage change that reddens a peer gets a before/after RATE on the same host in the
  same session, and the peer leaves the publishable set until it is fixed.** Do not revert, and do not
  publish the passing sample — for an intermittent, cite the rate.
  **CLOSED THE SAME DAY, and the defect was real: A RESPONSE FRAME FOR A DIFFERENT IN-FLIGHT REENTRY
  ON THE SAME CONNECTION WAS SILENTLY DISCARDED.** Two reentries can be live on ONE connection —
  dispatching a non-correlated inbound EXECUTE re-enters `peer dispatch`, and that handler may itself
  call `outboundDispatch` on the same conn. The inner loop saw the OUTER `request_id` on a response
  frame, which matched neither its own rid nor the `system/protocol/execute` arm, and **fell off the
  end of the `foreach`.** The outer could never see that frame again, so it waited out its full
  20-second deadline — and on a single-threaded event loop that starves every connection behind it.
  **This is a §4.9(c) silent drop of a CORRELATED RESPONSE, and it presents as a concurrency/latency
  problem rather than a correctness one** — the same "bills the caller, so it reads as slow" signature
  as the ISA op-ladder and `cobol`'s oversize frame, one layer up. Fix: park a non-matching response
  under its rid for the loop that is waiting on it; check the park on entry and each pass.
  **Measured: pre-fix 3 of 6, post-fix 0 of 12** (p≈0.02% against that baseline), with a per-check
  diff confirming **exactly 1 of 758** severities moved and that one being the known
  `t1_1_concurrent_demux` timing flake (WARN in 5 of the 6 post-fix runs, so the stable row is
  unchanged).
  **Two things generalize.** (a) **The 20-second wall in the failure message was the peer's OWN
  deadline, not the oracle's** — reading which side owns a timeout is what turned "the oracle timed
  out" into "our loop waited for a frame that had already arrived and been thrown away." (b) **Build
  the small reproduction before the fix, not after.** Driving `-category origination` then
  `-category concurrency` against ONE long-lived peer reproduced it in **9 checks instead of 758**,
  in about a minute instead of twenty-five — and it also showed the small form is much rarer (~1 in
  9 vs 1 in 2), which is itself the evidence that accumulated state from the full run is part of the
  trigger. A cheap reproduction that is *rarer* than the real one is still worth having; just do not
  measure the fix with it.

- **TWO MEASUREMENTS AT ONCE IS ONE MEASUREMENT AND SOME WRECKAGE — AND ITS FAILURES LOOK LIKE
  PEER DEFECTS.** Candidate (2026-09-07, self-inflicted). Running `pp.sh <peer>` (a probe census)
  while a `--tier M3` census was in flight produced, in the tier run, `crystal` dying with
  `Thread#execution_context cannot be nil`, `odin` with `permission denied` writing its own JSON,
  and `datalog` with `Permission denied` on its cargo dep-info — three peers reported RED for
  reasons entirely outside their source. Both runs write `output/scratch/`, both allocate ports,
  and both are capped against the same host budget. Re-run serially: all three clean, **0 of 721
  severities moved**. **Enforcement: one census at a time, and treat any run whose failures are
  filesystem-permission or runtime-internal rather than protocol-shaped as contended until proven
  otherwise.** The census's own STALE-JSON guard is what caught it — it refuses to report a JSON
  the run did not write, which is the same discipline as the probe driver's mtime check.
  *(Sub-lesson, cheap: **`pgrep -f <pattern>` in a watcher loop matches the WATCHER**, because the
  pattern is in its own command line. `while pgrep -f run-cohort-census; do sleep 30; done` never
  exits, and after two of them are running, `pgrep` stops answering the question you are asking.
  Discriminate on something the watcher cannot contain — the log's completion marker, or a
  podman-process count.)*
  **AND THE SECOND MEASUREMENT CAN BE THE SAME RUN: `CONCURRENCY` IS A KNOB ON THE CENSUS ITSELF,
  ITS DEFAULT IS 1 FOR THIS EXACT RACE, AND RAISING IT COST A REPORT IN THE RUN THAT CLOSED THE
  0.8.2.25 SWEEP.** 2026-09-16. Every entry above is about two DIFFERENT runners colliding, and the
  holder guard each now carries is blind by construction to a single runner racing itself — the
  guard asks *"does another container hold this repo"*, and the census's own workers are not
  another container, they are this one. Measured: the 46-peer closing census completed in **19
  minutes**, where the serial 45-peer refresh the next morning took **~50**; `rexx` died `rc=1` with
  `Error creating /work/output/scratch/census/rexx.json: permission denied` — the `:Z` relabel race,
  named in `run-cohort-census.sh`'s own header as the reason the default is 1 — and left its
  PREVIOUS run's JSON on disk, well-formed, six hours stale, carrying no run identity. Re-measured
  serially it is `778 · 334P/337W/0F/107S`, exactly its published row: **the peer was never the
  problem and a reader of that directory could not have known.**
  **What saved it is worth as much as the lesson: the census's freshness guards fired on the same
  run.** The stale-JSON check refused to report a file the run did not write, and the roster stamp —
  hardened in a previous session from `[ -f ]` to an mtime test against the run's start, for this
  very peer — declined to record `rexx` as measured. So the damage was one missing row rather than a
  fabricated one. **Rule: the concurrency default of a measurement runner is part of the
  measurement. Do not raise it to make a census fit an attention span** — and if you do, the run is
  not comparable until every peer that lost a write is re-measured serially.
  **RATIFIED 2026-09-15 — THE GUARD LANDED IN THE CENSUS AND NOWHERE ELSE, AND THE 41 HARNESSES IT
  WAS NOT PORTED TO ARE THE ONES THAT PRODUCED THE NEXT OUTAGE.** `b91046c4` added the
  refuse-to-start holder check to `run-cohort-census.sh` on 2026-09-15 at 10:06, for the `:Z`
  relabel race: two containers relabeling one host path collide, **every check still PASSES and only
  the report write loses**, so the oracle exits 0 and a stale JSON reads as a result. Measured the
  same day: `grep -l ':Z' protocol-generator/*/run-s2.sh` returns **41**, and
  `grep -l "REFUSING TO START" protocol-generator/*/run-*.sh tools/run-axis-sweep.sh` returns
  **nothing**. So the axis sweeps can still manufacture precisely the contention the census now
  refuses — **the harden-one-anchor-check-its-siblings rule failing at a four-hour distance, in the
  session that wrote the anchor.**
  **It fired the same night, on `crystal`, twice**: two concurrent `crystal spec` containers, both
  logging `Unable to get file info: '/work/protocol-generator/crystal': Permission denied`. That is
  the signature this entry already names — *filesystem-permission, therefore contended until proven
  otherwise* — and it is now a **measured mechanism rather than a heuristic**: the loser of a `:Z`
  relabel sees the repo mount vanish out from under it mid-compile.
  **AND THE SECOND HALF IS A RUNTIME PROPERTY WORTH ITS OWN GREP: ON CRYSTAL, AN EXCEPTION RAISED
  INSIDE A `spawn`ED FIBER UNDER A `WaitGroup` IS A HANG, NOT A FAILURE.** The compiler's own
  `compiler.cr:643` spawns into `wait_group.cr:68`; the unhandled `File::AccessDeniedError` kills the
  fiber, the wait group never reaches zero, and the process parks **forever** — measured at 9 h with
  **48 threads in `futex_do_wait`, zero sockets, 0.07% CPU**, holding the repo and blocking every
  subsequent census. Both containers needed `SIGKILL`. **A contention fault that should have exited
  non-zero in seconds instead became an indefinite lock on the tree**, and nothing timed it out
  because the only deadline in that harness is on the peer socket, not on the build.
  **Two enforcement points. The first is LANDED the same day, which is the whole point of the rule
  it was failing:** `tools/run-axis-sweep.sh` carries the holder guard, asked **once per sweep**
  rather than 41 times — 46 identical refusals would be noise, and the hazard is a property of the
  run, not of the peer. **Three arms exercised before it was committed, because a guard that was
  never executed is not a guard:** no holder → proceeds (**with 9 unrelated containers running, so
  the match is on the mount list and not on "is anything up"**); a holder → **exit 4** naming its id
  and image; `SWEEP_IGNORE_HOLDERS=1` → proceeds with the contention warning. **The second is still
  owed: a wall-clock ceiling on every per-peer harness invocation** — *a build step needs a deadline
  for the same reason a wire read does, and the §4.11 sweep only ever put one on the socket.*
  Diagnostic, cheap, and it is what separated the two cases here: **`ls -l /proc/<pid>/fd` — sockets
  mean a protocol hang, a lock file and no sockets mean contention.**

- **`output/scratch/census/` is NOT scoped to the last run — stale per-peer JSONs from earlier
  censuses sit beside the fresh ones.** A `--tier M1` run leaves the other 40 peers' files untouched,
  so `grep -l budget_exhausted output/scratch/census/*.json` returns the `asm`/`riscv64` trio from a
  *previous* census and reads exactly like "this run starved." Scope every census-wide grep to the
  peers the run actually measured (or check mtimes) before drawing a conclusion from it — the
  starvation check itself is mandatory and unchanged, but it must be asked of the right files.
  **RATIFIED 2026-09-08 — the same is true of every `--probe <NAME>` directory, and it bites
  harder there because a probe report has no check-set gate behind it.** Re-reading
  `output/scratch/kind-c-connect-errors/*.json` after re-running six peers showed forty files, of
  which six were current and thirty-four were from a roster run two days older — including four
  peers whose defects had been fixed that morning and which the stale files still reported as
  failing. Nothing warns: the JSON is well-formed and carries no run identity. **Before reading a
  probe directory as a cohort picture, either re-run the whole roster or compare mtimes** — and
  prefer the roster run, because a mixed-age table is the one artifact that reads as a measurement
  and is not one.
  **RATIFIED 2026-09-16 — THIRD OCCURRENCE, AND THE NEW HALF IS THAT THE MISSING PEER IS MISSING
  FROM THE *WORK*, NOT ONLY FROM THE DIRECTORY: A SWEEP RUN TRANCHE-BY-TRANCHE CANNOT SEE A PEER NO
  TRANCHE TOUCHED, AND EVERY TRANCHE REPORTS HONESTLY WHILE IT HAPPENS.** The `0.8.2.25` sweep ran as
  nine tranches over two days; each measured its own peers, each truthfully reported them at
  `0 of 15` on `arc-probe`, and the closing act re-measured all 46 tracked reports. **`fortran` and
  `unison` were never swept at all** — no tranche and no vanguard commit touches either — and
  `CONFORMANCE-MATRIX.md` published both at `0.8.2.25` while `docs/STATUS.md` headlined *"46 of
  46"*. Measured on a single-age roster run: **six `arc-probe` rows owed each** (`A1`–`A4` and
  `G2`/`G4`, i.e. they are the two peers keeping **`F84`** open) and **5 of 6 §4.11 arms**, the
  pre-sweep baseline exactly.
  **Three things generalize, and the first is the cheap one.**
  (a) **THE CONTROL IS A SET DIFFERENCE, NOT A MEASUREMENT.** Diff the roster against the peers the
  sweep's own commits modified — `git show --name-only` over the tranche commits, `comm -23` against
  `tools/peer-tiers.tsv`. It answered in one command (**44 swept, 46 on the roster**) and no amount
  of re-running probes would have asked it, because **a per-peer instrument ranges over the peers you
  hand it.** This is the H4 packaging rule — *derive a cohort survey from the tree's own
  declarations, never from an inventory you wrote down* — reaching a WORK LIST instead of a feature
  survey.
  (b) **A PER-TRANCHE GREEN IS NOT A COHORT GREEN, AND N TRUE STATEMENTS DO NOT SUM TO ONE.** Every
  tranche commit's `0 of 15` was correct about its own peers. The cohort claim was assembled by
  addition, and addition cannot see an absent term — the arithmetic half of the false-negative
  family, in a work plan rather than in a count.
  ⭐ **AND THE CLOSING CLAIM IS THEREFORE A ROSTER RUN, NEVER A SUM — RATIFIED 2026-09-16 WHEN IT
  CAUGHT ME ONE PARAGRAPH AFTER I WROTE THIS RULE.** Closing `fortran` and `unison` made it tempting
  to state the cohort as *yesterday's 44, plus these two* — which is this exact defect one level up.
  Both instruments were re-driven across all 46 instead (`arc-probe` span **0.038 h**, `pa-probe`
  span **0.046 h**, none missing, all `trusted`), **and the §4.11 line I had already written by
  arithmetic said 44 peers at `0 of 6` where the roster run says 43.** The slip is left named in
  `docs/STATUS.md`, because a section arguing that summed cohort claims go wrong must not carry one.
  **Two checks make a roster run worth more than the count it prints:** assert the report set equals
  the roster (a run that stops at peer 29 and names nothing is the standing hazard), and
  **content-check each report for the rows you are about to count** — `assert "G2_…" in ids` — so a
  report written by an older binary cannot be silently tallied. That second one is strictly stronger
  than the mtime test the stale-probe-directory rule prescribes: it is indifferent to clock skew and
  to a peer re-run by hand mid-roster, and it answers the question you actually have.
  (c) **THE PROBE DIRECTORY CONFIRMED THE ERROR RATHER THAN CATCHING IT.** `output/scratch/arc/`
  spanned **29.5 h** with **seven** peers' reports older than their own sweep commit, and the two
  unswept peers' reports were from the pre-sweep census — so reading it showed them failing and that
  read as staleness. **A mixed-age directory does not merely fail to answer; it supplies a
  plausible wrong answer in whichever direction its oldest files point.** The single-age re-run
  (span **0.04 h**) is what separated *stale report* from *unswept peer*, and they are indistinguishable
  without it.
  **And the disclosure rule this cost: a hand-maintained per-peer revision column drifted within
  ONE DAY of being corrected** — footnote ¹² was written that morning, ends *"a value that is
  correct today and ungated is a value that is correct today,"* and was false on two rows before the
  day was out. That is `entity-system-conformance`'s `K-ASK-1` / our `Y-2` earning itself: the
  `spec_pin` column in `tools/peer-tiers.tsv`, **written by the sweep and gated so a sweep that does
  not update it fails**, would have failed the sweep that skipped these two.
