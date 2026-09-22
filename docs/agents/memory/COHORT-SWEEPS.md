# Cohort sweeps — keystone memory

Landing one rule across 46 peers: vanguard first, what propagates by rebuild and what does not, and the controls on the closing claim.

**Arrive here when:** a rule must land on every peer, or a cohort-wide claim needs a closing measurement.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- CURRENT STATE 2026-08-21 — the `c1b0708` re-pin IS landed; M1 is 5/5 at 0-FAIL
- BRING ONE OR TWO PEERS ALL THE WAY TO THE TARGET BEFORE SWEEPING 45 — IT IS THE ONLY THING THAT ANSWERS "IS THE TEXT IMPLEMENTABLE AS WRITTEN", AND IT PAYS FOR ITSELF IN ONE CORRECTION
- RATIFIED, SECOND OCCURRENCE AND FIRST IN A GATE — A SELECTOR KEYED ON ONE SPELLING OF A CONVENTION ACCUSES THE COMMITS THAT DEVIATE FROM IT, AND THE DEVIANTS ARE THE ONES THAT HAD A REASON TO
- A READ-LOOP FIX IS NOT INHERITED BY A PEER THAT REIMPLEMENTS THE READ LOOP — and depending on the crate that holds the fix looks exactly like inheriting it

---

- **CURRENT STATE 2026-08-21 — the `c1b0708` re-pin IS landed; M1 is 5/5 at 0-FAIL.** Both anchors
  moved (oracle `de8f807 → c1b0708`, spec snapshot `v0.8.0 → v0.8.2`), `--tier M1` initially came
  back **0 of 5**, and all five were then fixed to **`755 · 0F — 312P/337W/0F/106S`**, identical
  across the five. `tools/tier-status.py --gate` exits 0. The failures were never regressions:
  §5.6's MIN_DEFINED mint ceiling (CAP-5/CAP-6) had **never been implemented in any peer** —
  `mintToken` set no `expires_at` at all — and no vector exercised it until this pin. Three defect
  classes came out of it, all now ratcheted above: the §6.3 rejection-status rule, the
  absent-vs-unrepresentable accessor collapse (CAP-6a, a fail-OPEN in three peers), and swift's
  §5.5a frame over-scoping. **The same fix is owed to the other 40 peers** — author it once from the
  spec and propagate; the five M1 diffs are the reference. One known intermittent, recorded not
  hidden: `go`'s `concurrency/t1_2_concurrent_reentry` (§6.11 reentry cross-talk) failed **once** in
  a census run and passed 3/3 isolated plus on the census re-run — unexplained, load-dependent, not
  yet root-caused. Full detail:
  `research/stewardship/SESSION-2026-08-21-release-repin-c1b0708-v0.8.2-and-M1-capability-gap.md`.
  **M1 AND M2 ARE NOW BOTH COMPLETE — 13 of 45 peers publishable (2026-08-22).** `typescript`
  (84F→0F), `csharp` (INVALID→0F), then `rust` `python` `java` `kotlin` `elixir` `common-lisp`
  (3F→0F each). **The fix shape did not change once across thirteen languages** — ~200 lines over
  5–6 files, the same five places (capability mint, codec salvage, wire 400, read loop, policy
  lookup) — and that invariance is itself the evidence the spec reading is right, not just that the
  tests pass. Two peers needed a lesson the first eleven did not: rust and common-lisp reached 0F
  while still scoring CAP-6a **WARN**, because the `>2^64` half arrives only as a major-type-6 tag
  and is therefore rejected at DECODE — it needs the §6.3 answer to be *scored* as a refusal at all.
  **So on any peer, §6.3 is not optional even when the FAIL count is already zero.**
  Remaining owed: 32 peers (M3, the probes, `node-red`/wasm).
  **Re-verified 2026-08-22 (release-readiness pass), and the cohort's remaining work is smaller than
  the 40 suggests.** Gate re-run from the committed artifacts: `make lint` OK (both spec snapshots),
  `tier-status.py --gate` exits 0, and the census is **41/45 comparable with exactly the 4 INVALIDs
  §1a names** — the extra three the gate had been reporting were the stale-overlay bug, now fixed.
  Failure composition measured across all 45 reports: **CAP-5 + CAP-6 (§5.6 ceiling) is the whole
  gap for all 40** unfixed peers; CAP-6a adds to 30 of them; CAP-2/3 to 8; **CAP-7 fails on nobody.**
  Only **two** peers carry a defect outside the CAP family — `cobol` (27, standing) and the asm/ISA
  trio's shared connection-pressure family (1 visible + 2 starved). Everything else in the cohort is
  one feature. `typescript` and `csharp` are the same §6.3 fix (§1c), not two.
  **CLOSED 2026-08-28 — the propagation is done. 39 of 45 measured peers are at `755 · 0F`, up from
  13.** 23 peers fixed in one pass (all of M3 but `cobol`, 11 probes, `sql`), plus three that were
  never broken (below). The fix shape did not vary across **thirty-six** languages. `make lint`'s
  tracked gate reports **39 publishable, 0 stale**; the census is 23/23 comparable at the pinned
  check set.
  **What remains is SIX SEPARATE PROBLEMS, not one — say it that way, because "6 peers still fail"
  invites the reader to assume it is the same debt.** `cobol` 30F (its standing liveness cascade),
  the asm/ISA trio (INVALID, connection-pressure), `wasm-wat` 2F and `turbowarp` 3F (hand-authored /
  exploratory, unstarted), `apl` unmeasurable. None of them is the mint ceiling.
  **THREE OF THE PEERS IN THAT COUNT WERE NEVER BROKEN, AND THE CENSUS SAID THEY WERE.**
  `rust-wasm`, `rust-wasm-wasmtime` and `node-red` are thin seams over `../rust` (a path dep) and the
  `typescript` engine; both parents were fixed 2026-08-22. `out/peer.wasm` was dated 2026-08-17 —
  **seven days older than the source it compiles** — and `run-cohort-census.sh` hardcodes `NOBUILD=1`
  for the wasm peers, while `node-red`'s harness rebuilds `dist/` only when `index.js` is MISSING,
  never when it is merely stale. A forced rebuild took all three to 0F on the first try. **This is
  the standing stale-build-artifact rule firing on a plain SIBLING-CRATE fix rather than on an
  isolated-worktree merge** — the trigger is broader than that entry says, and the check is the same
  one second: `stat -c %Y` the artifact against `git log -1 --format=%cI` the source it derives from.
  **Compounding it, `tools/tier-status.py` was applying `output/scratch/reverify/` UNCONDITIONALLY —
  the identical defect `check-set-gate.py` was fixed for on 2026-08-22, in the file sitting next to
  it, reading the same directory.** Three reports left there on 2026-08-17 at the retired 740-check
  pin therefore outranked the fresh census indefinitely, and those same three peers displayed as
  current-and-0-FAIL on eleven-day-old evidence measured against a different check set. Fixed the
  same way (overlay applies only when NEWER, and says so on stderr when it skips one).
  **This is the "harden one anchor, check its siblings the same day" rule failing on its own terms,
  six days after it was written down.** The sibling was not a subtle one — same directory, same
  overlay, same file naming. **Enforcement, and it is the cheap one this repo already prescribes:
  when `tier-status.py` and `check-set-gate.py --tracked` disagree about which peers are green,
  suspect the INPUT before the peers.** They disagreed here, and the tracked gate was right.

- **BRING ONE OR TWO PEERS ALL THE WAY TO THE TARGET BEFORE SWEEPING 45 — IT IS THE ONLY THING THAT
  ANSWERS "IS THE TEXT IMPLEMENTABLE AS WRITTEN", AND IT PAYS FOR ITSELF IN ONE CORRECTION.**
  RATIFIED 2026-09-14 (`go` and `python` taken to `0.8.2.23`: the §3.3 ladder,
  `check_path_permission`, the listing filter — ~90 lines each, the shape identical across a static
  and a dynamic substrate). Three things came out of it that no amount of reading produced:
  - **A frame error of ours.** The first `go` cut threaded the per-link GRANTER frame into
    `check_path_permission` by analogy with §5.5a. §6.3's own block settles it —
    `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)`, and **there is no
    granter parameter to pass**. §5.5a governs chain ATTENUATION, where the subject is a pattern
    compared against a parent's pattern; that call site compares a CONCRETE LOCAL PATH. **The
    sibling `python` peer had it right and said so at the definition** (*"do not add a granter frame
    to it"*) — the standing *"when a scope question has 45 answers in the tree, ask them"* rule,
    reached from the side where the tree was right and we were not. Record that with the same weight
    as a catch.
  - **A genuine spec ambiguity, and the vanguard is what made it concrete rather than theoretical.**
    §3.3 says an empty effective list IS the absent case; §6.3's grammar makes the listing route a
    trailing-slash TARGET; and every peer answers an absent `resource` with a root listing while
    nothing in the check set objects. **Both vanguards keep the shipped behaviour and say so at the
    branch rather than resolving it unilaterally** — it is one sentence to ask now and a cohort-wide
    change after 43 peers are swept. **A sweep is the most expensive possible place to discover an
    ambiguity; a vanguard is the cheapest.**
  - **The measurement that turns a coverage complaint into a fact: `0 of 778` severities moved on
    EACH.** Two peers went from violating three landed MUSTs to conformant and the pinned check set
    could not tell. That is the same shape as `F62` and the H1 census, and it is a sharper argument
    for vectors than any count of uncovered cells.
  **Enforcement: for any cohort-wide rule not yet gated by the oracle, land it on two peers in
  DIFFERENT substrates and re-census both check-by-check before authoring the sweep.** Two is the
  number: one proves it compiles, two proves the shape transfers.
  *(Sub-lesson, and it is the examined-zero-things class in a new shape: **a count that disagrees
  with the detail printed beside it is worse than no count.** `arc-probe`'s family-A tally tested
  `Conforms == "yes"` while one row answers `"yes — total canonicalization…"`, so a fully conformant
  peer scored **4 of 5** next to a row printing five yeses. Prefix, not equality — and the tell is
  that the summary and the detail disagree, which is visible only because the detail was printed.)*

- **RATIFIED, SECOND OCCURRENCE AND FIRST IN A GATE — A SELECTOR KEYED ON ONE SPELLING OF A
  CONVENTION ACCUSES THE COMMITS THAT DEVIATE FROM IT, AND THE DEVIANTS ARE THE ONES THAT HAD A
  REASON TO.** The first was `run-s4.sh`'s argv sweep, where a `^"$ORACLE"` pattern skipped the five
  (six) harnesses that hold the exit code. 2026-09-16 it reached `tools/spec-pin-gate.py`, whose
  `--since` reconciliation selects sweep commits by SUBJECT with `^(sweep tranche|vanguard)`.
  **The TAIL of a sweep is not a numbered tranche**: closing the last two peers produced
  `sweep fortran to 0.8.2.25, …`, which matched nothing, so the gate reported both peers as
  *pin-advanced-but-never-touched* — **it accused the two commits that closed the hole it exists to
  catch.** Broadened to `^(sweep |vanguard)`.
  **Enforcement is the standing detector rule and it is what makes the broadening safe: DIFF THE HIT
  LIST, never the count.** Over the range the gate is run on: 17 matches before, 18 after, and the
  single addition is the `fortran` sweep — no other subject in the range begins with `sweep`. A
  loosening that swept in a whole unrelated class would also have produced a plausible number.
  *(And the meta-lesson is about where to look for this: the defect lived in the ONE arm of the gate
  that had never been run end-to-end against a real sweep. `--self-test` was green throughout,
  because a self-test builds its own commits and therefore its own subjects.)*
  **THIRD OCCURRENCE 2026-09-17, IN THE SAME GATE, UNDER THIS ENTRY'S OWN COMMENT — AND THE PATTERN
  WAS ANCHORED WHERE THE WORD IS NOT.** `^(sweep |vanguard)` cannot see **"second vanguard: python
  takes the same shape…"**, so closing the `0.8.2.31` sweep reported `python` as
  pin-advanced-but-never-touched and the claim had to be waved through with `--ack-unchanged` — the
  silent default that flag exists to prevent. **`vanguard` is a WORD in the subject, not a prefix of
  it**, and the fix is `^sweep |\bvanguard\b`: anchor on the TOKEN, not on the position, because the
  position is a property of one author's word order on one day. Hit lists diffed over both ranges
  rather than the counts trusted (22 → 23 and 41 → 42, the single addition being that one commit in
  each). **The generalizable half: after broadening a selector once, the next deviation will be a
  different AXIS of the same convention** — the second occurrence was a missing *word* (`tranche`),
  the third a missing *position*. A pattern that must be loosened twice is measuring the convention's
  spelling rather than its meaning.

- **A READ-LOOP FIX IS NOT INHERITED BY A PEER THAT REIMPLEMENTS THE READ LOOP — and depending on
  the crate that holds the fix looks exactly like inheriting it.** RATIFIED 2026-09-14 (the §6.3
  silent-refusal sweep reaching `rust-wasm`, `rust-wasm-wasmtime` and `node-red`), and it is the
  standing *"an inheriting peer takes its parent's fix by rebuilding"* rule with its limit found.
  Rebuilding genuinely propagates a fix in the parent's **codec, model or capability** modules — that
  is how all three took the §5.4 sentinel, verified on the wire rather than assumed. It does **not**
  propagate a fix in the parent's `read_loop`, because a thin transport seam's whole reason to exist
  is that it *owns* the read loop. The August §6.3 sweep landed `reject_non_canonical` in
  `peer/transport.rs`; these three kept `Err(_) => continue` and answered a refused frame with
  silence for four months, and `ingest_rejects_unrepresentable_expiry` was WARN on all three saying
  so. **Enforcement: when a fix lands in a parent, classify it by MODULE — a change below the seam
  propagates by rebuild, a change AT the seam must be made in each seam — and the cheap tell is that
  the inheriting peer's own source contains a function with the same job as the one you just fixed.**
