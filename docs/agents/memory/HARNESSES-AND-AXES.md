# Harnesses and axes — keystone memory

The per-peer `run-sN` harnesses and the cohort axis sweeps: invariants of that interface, teardown, argv, streams, container boundaries, and which axis has an authority behind it.

**Arrive here when:** `run-s*.sh` behaves differently than documented, an axis has no cohort runner, or a gate rewrote something it should not have.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- THE PEER'S DYING WORDS MAY NOT BE ON STDERR — CHECK WHICH STREAM THE RUNTIME USES BEFORE TRUSTING A CAPTURE THAT PRINTS NOTHING
- A GATE MUST NOT REWRITE A COMMITTED ARTIFACT — and on 36 of 46 peers a bare `./run-s4.sh` DOES
- RATIFIED — AN ARM WITH HARNESSES AND NO COHORT RUNNER IS ONE NOBODY IS MEASURING, AND "IT ISN'T PEER-SCOPED" IS WHY IT ESCAPED, NOT A REASON IT SHOULD HAVE
- AN ENV OVERRIDE DROPPED AT A CONTAINER BOUNDARY PRODUCES A SUCCESSFUL RUN AND A WRONG-SHAPED ARTIFACT — the discriminator is the OUTPUT SHAPE, never the exit code
- A SHARED BUILD ARTIFACT IS NOT YOURS TO SWAP — AND `Text file busy` IS LUCK, NOT AN INTERLOCK
- RATIFIED, second occurrence on the same peer and the sharper one: THE PEER'S OWN STDERR GOES TO A FILE INSIDE THE CONTAINER AND DIES WITH IT — four investigations found "no crash" because nobody had kept the evidence
- AN AXIS'S PER-PEER GATES ROT EXACTLY WHERE NO COHORT RUNNER REACHES — the NO-GATE column is not a list of peers without tests, it is a list of tests nobody runs
- AN INSERTED CALL AND THE DEFINITION IT NEEDS MUST BE ANCHORED TO THE SAME SCOPE — AND THE OBVIOUS ANCHOR IS IN A DIFFERENT SHELL ON A THIRD OF THE COHORT
- A DOCUMENTED CHECK THAT NOTHING INVOKES IS THE 2d ROT PATTERN, AND ITS EXIT CODE IS USUALLY NOT THE CHECK EITHER
- A UNIT THAT NOBODY RUNS FAILS IN THE DIRECTION THAT LOOKS LIKE A PEER BUG — AND THE COMMENT EXPLAINING WHY IT IS SAFE IS WHERE THE DEFECT LIVES
- A `run-*.sh` whose guard tests a CONTAINER path must be INVOKED in the container — and its failure is indistinguishable from a missing dependency
- A TEARDOWN THAT SIGNALS IS NOT A TEARDOWN THAT WAITS — and when the symptom is a RACE BETWEEN TWO DURATIONS, only one of which you own, it is absent on exactly the peers you would test first
- A SECOND AXIS WITH NO COHORT GATE IS AN EXCLUSION NOBODY DECLARED — and it will be defended by the fact that the FIRST axis is green
- EVERY VERIFICATION AXIS MUST NAME ITS AUTHORITY, AND THE ONE THAT CANNOT IS THE ONE THAT GOES STALE
- A PER-PEER ENTRY POINT ONLY WORKS THE WAY ITS AUTHOR HAPPENED TO INVOKE IT, AND NOTHING FINDS THAT UNTIL SOMETHING INVOKES IT DIFFERENTLY — this one class was 15 of the 21 failures across two axes
- A UNIT THAT NOBODY RUNS GOES STALE UNDER A PEER THAT KEEPS GETTING FIXED, AND IT FAILS IN THE DIRECTION THAT LOOKS LIKE A PEER BUG

---

- **THE PEER'S DYING WORDS MAY NOT BE ON STDERR — CHECK WHICH STREAM THE RUNTIME USES BEFORE
  TRUSTING A CAPTURE THAT PRINTS NOTHING.** Candidate (`io`, 2026-09-07; the cohort-wide
  keep-the-peer-stderr fix meeting a runtime it does not cover). Io writes an uncaught exception
  AND its backtrace to **stdout**, so the harness's `cat build/s4-peer.err` guard — the one added
  precisely so a mid-run abort is not reported as "connection refused" — printed nothing while the
  peer died mid-put. The probe reported `no response header: EOF`, which is exactly the
  no-crash-empty-stderr reading that rule exists to prevent. Fixed by also dumping the stdout log,
  but **only when it contains an exception marker**: printing it every run would train people to
  skip it, which is the failure mode this file records three times. **Enforcement: for each peer,
  know which stream its runtime uses for an uncaught fault — and if the answer is stdout, the
  stderr guard is not a guard for that peer.**
  *(The bug it was hiding is worth its own line: in Io `==` binds TIGHTER than `&`, so
  `b & 0x80 == 0` parses as `b & (0x80 == 0)` and raises. **On any substrate, write bit tests with
  the explicit methods (`bitwiseAnd`, `shiftLeft`) rather than the operators, unless you have
  checked that language's precedence table** — a varint loop is the place this bites, and a
  single-threaded peer turns the raise into a dead process.)*

- **A GATE MUST NOT REWRITE A COMMITTED ARTIFACT — and on 36 of 46 peers a bare `./run-s4.sh`
  DOES.** Found 2026-09-04 while diagnosing an unrelated change: `run-s4.sh` with no arguments
  defaults `-json-out` to `status/CONFORMANCE-REPORT.json`, **the tracked, signed-off record**. A
  human diagnostic run therefore silently republishes that peer's number, and mine banked a
  `t1_1_concurrent_demux` flake over a committed PASS before I noticed the `elapsed_ms` in the
  tracked file matched my run exactly. The census is unaffected — `run-cohort-census.sh` always
  passes an explicit destination — so this fires **only** on the invocation where overwriting is
  most wrong. This is the `python`/`ruby`/`prolog` hardcoded-args entry in a second shape: there
  the harness *ignored* the caller's args, here it *defaults* to the published path. **Enforcement:
  `grep -l 'json-out.*status/CONFORMANCE-REPORT.json' protocol-generator/*/run-s4.sh` should return
  nothing** — the default belongs in scratch, and writing the tracked report should require saying
  so (`JSON_OUT=`, or `run-cohort-census.sh --to-status`). Owed; 36 peers, mechanical, gateable in
  `harness-gate.py` as a third invariant of the same interface.
  *(Sub-lesson, and it cost me the whole edit set once: **commit before planting.** A
  plant/measure/restore loop that ends in `git checkout -- <dir>` restores to HEAD, which discards
  the uncommitted work the plants are testing — so plants 2 and 3 ran against a tree with none of
  the feature in it and reported a wall of compile errors that read like the plants failing. Commit
  first and `git checkout` becomes exactly the restore you meant.)*

- **RATIFIED — AN ARM WITH HARNESSES AND NO COHORT RUNNER IS ONE NOBODY IS MEASURING, AND
  "IT ISN'T PEER-SCOPED" IS WHY IT ESCAPED, NOT A REASON IT SHOULD HAVE.** 2026-09-04, and it
  is the standing *"a second axis with no cohort gate is an exclusion nobody declared"* rule
  one level up: that rule was about an AXIS inside `protocol-generator/`, this is a whole
  **arm** outside it. `tools/run-axis-sweep.sh` sweeps `protocol-generator/*`; `ffi-generator/`
  is not peer-scoped, so it sat in **no sweep and no `make lint` gate** — while **34 peers link
  the artifact it builds**. The codec leak closed the same day had been on the per-request path
  of every one of them for months and was found **by accident**, while measuring an unrelated
  peer's capacity work. Every harness that would have caught it already existed
  (`regression_test`, `conformance_harness`, `abi_differential`); nothing ran them on a
  schedule. **Enforcement: `ffi-generator/c-abi/run-ffi-gate.sh`, and the arm is listed in
  `run-axis-sweep.sh --list` even though its runner is separate** — S4's precedent, for the
  same reason. **The inventory is the control, not the sweep engine**: a thing absent from the
  list is an exclusion nobody declared, and the fix for "it doesn't fit the table's shape" is a
  row saying where its runner lives.
  **THE FIX DID NOT REACH THREE OF ITS CONSUMERS, BY THE BUILD-ONLY-IF-MISSING SHAPE THIS FILE
  ALREADY RECORDS TWICE** (`node-red`'s `dist/`, `turbowarp`'s installs). Nine peers declared
  the codec `.so` as a **bare make file target** — a file target with no prerequisites runs its
  recipe only when the file is ABSENT — so once built it was `Nothing to be done` forever, no
  matter what happened to the codec's source. Measured: `asm-arm64` and `riscv64` were linking
  cross-builds dated **2026-07-15** and `io` a peer-local copy dated **2026-07-27**, confirmed
  **by symbol** (`nm`: no `ev_free`) rather than by mtime alone. **Three of the nine said `if
  absent` in the comment above the rule** — the defect was written down and never read as one,
  which is the deferral-comment class in a Makefile.
  **The fix is DERIVED prerequisites, never a hand-listed set** (`$(shell find $(CODEC_SRC)/src
  $(CODEC_SRC)/include ...)`): a literal file list is a second copy of the dependency graph and
  a second copy drifts — the dart/csharp lockfile rule, in make. cmake still does the
  incremental work; make only decides whether to call it. **Both directions must be exercised
  or the fix is unmeasured**: touch a source → all nine rebuild; leave it current → all nine
  say `Nothing to be done`. Without the second control you have not fixed staleness, you have
  replaced it with an unconditional rebuild, which passes the first check identically.
  **Enforcement: `git grep -n 'libentitycore_codec.so:$'` — a `.so` target whose line ends at
  the colon has no prerequisites and cannot see a source change.**
  **And re-measure the peers the artifact moved under**: all three reproduced their committed
  row at the pinned check set (`asm-arm64`/`riscv64` **0 of 758** severities different, `io`
  **1 of 758** — the documented `t1_1_concurrent_demux` flake, WARN→PASS, so the tracked report
  was **left alone** under the standing "a single sample is not a rate" rule).

- **AN ENV OVERRIDE DROPPED AT A CONTAINER BOUNDARY PRODUCES A SUCCESSFUL RUN AND A WRONG-SHAPED
  ARTIFACT — the discriminator is the OUTPUT SHAPE, never the exit code.** RATIFIED 2026-09-06,
  found by driving a probe across the whole roster for the first time (`tools/put-probe`, §6.3's
  put-admission census). **Eight of 46 peers silently ran the REAL validator** and wrote a perfectly
  good 758-check conformance report where a probe report was expected. Nothing failed: the run exits
  0, the file exists, `check-set-gate` would have been happy with it, and the only thing that says
  the measurement never happened is that the JSON has a `checks` key instead of a `cases` key.
  **The claim that said otherwise was ours, in the tree, and it was a source read wearing a
  measurement's clothes.** `run-cohort-census.sh` carried *"(Checked across all 46: only these
  two.)"* beside a `lean`/`unison` special case. That is the standing false-negative class — sixth
  occurrence, after the `dart`/`ruby` NUL byte, F51's wrong vocabulary, the de-versioning sweep's
  un-spannable pattern, the `host.err` right-token-wrong-branch, and the H4 packaging survey keyed on
  a self-authored filename list. **Enforcement, and it is one line rather than a grep: classify the
  ARTIFACT, not the source.** A conformance report sitting in the probe directory *is* a dropped
  `ORACLE`, and that check is indifferent to how many ways a harness can drop one.
  **TWO CAUSES, AND A SURVEY THAT FINDS ONE MISSES THE OTHER.** Five were self-relaunching harnesses
  (`forth fortran oz rexx smalltalk`) that `exec podman run` and forward nothing — so their own
  header's *"ORACLE/PORT/NOBUILD/VALIDATE env overrides"* line had been false for as long as it had
  existed. Three were hand-written branches **in the census itself** (`prolog rust-wasm
  rust-wasm-wasmtime`) predating `run_podman`'s `${ORACLE:+...}`. `apl` `lean` `unison` carry the
  same harness defect and were masked because the census happens to enter their containers directly.
  Fixed at the SOURCE — all eight harnesses forward their own documented overrides — which also
  **closes the carried `JSON_OUT`-not-forwarded-through-`lean` item**, where the documented escape
  hatch was dropped and a bare run therefore wrote the TRACKED report. Same defect, different
  variable, already on the list.
  **`${VAR:+-e VAR="$VAR"}`, never `-e VAR=${VAR:-default}`** — the second form SETS policy while
  appearing to forward it, which is the `cobol` `run-s4-host.sh` defect this file already records.
  **Verify a forwarding fix in BOTH directions or it is unmeasured:** the probe direction (6 of the 8
  now produce probe reports) says the variable arrives; only the conformance direction says the edit
  changed nothing — `lean` and `smalltalk` re-measured through the edited harnesses reproduced their
  committed reports at **exactly 0 of 758** severities different.
  *(Sub-lesson, and it is the examined-zero-things class inside the fix itself: **`[ -x <directory> ]`
  is TRUE.** The guard added to reject a missing probe binary was `[ -x "$dir/$PROBE" ]`, and with
  `$PROBE` empty — it was unexported and `census_one` runs under `xargs bash -c`, so only exported
  vars survive — it tested the DIRECTORY and passed. Every peer was then handed
  `ORACLE=/work/output/s4-oracles/` and died with `Is a directory`. The guard written to catch a
  missing name passed vacuously on the emptiest possible name; it is `-n` and `-f` and `-x` now.)*

- **A SHARED BUILD ARTIFACT IS NOT YOURS TO SWAP — AND `Text file busy` IS LUCK, NOT AN INTERLOCK.**
  Candidate (first occurrence, 2026-09-09, `tools/p47-run.sh`; enforcement exact). The p47 wrapper
  installs its probe **over** `output/s4-oracles/validate-peer` for the duration of a run, backs the
  real binary up, restores it on trap and verifies by hash — careful, documented, and built on one
  unstated assumption: that this repo is the only consumer of that path. It is not.
  **`entity-system-generator` invokes `<keystone>/output/s4-oracles/validate-peer` BY PATH from its
  own tree**, and one of its `--profile core` runs was live when the swap was attempted. What stopped
  it was `cp` answering **`Text file busy`** — the kernel refusing to write a *running* executable.
  **Had that seat been BETWEEN invocations, the copy would have succeeded**, their next run would have
  executed our probe, and it would have written a probe report where a conformance report was expected
  — the exact defect `p47-run.sh`'s own header describes, inflicted on a repo whose owners have no
  reason to look for it. The failure was also invisible from our side: the trap reported *"validator
  restored and hash-verified"*, which was TRUE (nothing was ever overwritten) while the restore's own
  `cp` had failed the same way and left the backup in place as a poison pill for the next run.
  **Enforcement: refuse to start while any process holds the artifact**, scanning `/proc/*/cmdline`
  and matching **`argv[0]` only** — a shell wrapper whose command line merely *contains* the path is
  not a holder, which is the standing `pgrep -f` trap (the pattern is in the watcher's own command
  line) reached from a second direction. Both directions exercised: the guard names the holding pid
  while a sibling's run is live, reports nothing for a path nobody holds, and does not match the
  watcher.
  **SUPERSEDED THE NEXT DAY BY THE BETTER FIX, AND THE ORDER IS THE LESSON: A GUARD ON A HAZARDOUS
  MECHANISM IS NOT THE SAME QUESTION AS WHETHER THE MECHANISM IS STILL NEEDED, AND NOBODY ASKS THE
  SECOND ONE AFTER SHIPPING THE FIRST.** `tools/p47-run.sh` is **deleted** (2026-09-09). The swap
  existed for one reason, stated in its own header: eight harnesses dropped an `ORACLE=` override at
  their container boundary. **Those eight were fixed at source on 2026-09-06** — recorded in this
  file, in the entry above — so the wrapper had been unnecessary for three days when the guard was
  written for it, and the guard is a careful control on a mechanism that no longer had a reason to
  exist. Measured before deleting, never assumed: the whole 46-peer roster driven through the plain
  `--probe` route produced **46 of 46 probe-shaped outputs**, with the two failure classes the swap
  was built for (`forth` self-relaunching, `prolog` a hand-written census branch) driven first, and a
  both-routes control on one peer confirming the route does not change the answer. **Ask whether the
  dangerous step is still load-bearing before you harden it** — the fix that removes a hazard beats
  the fix that guards it, and a header explaining *why* a mechanism exists is the thing to re-read
  when its justification has been repaired elsewhere.
  *(Two more defects fell out of retiring it, both the never-executed class: its documented per-peer
  form `p47-run.sh <peer>` had **never worked** — `--probe` takes an optional NAME, so the peer name
  was consumed as the probe name — and the holder guard is **start-only**, fine for the two-minute
  single-peer run it was tested on and not for the ~90-minute roster run. A guard that samples once
  at t=0 is not a lock, and the run length is what decides whether that matters.)* **Generalize: before a tool mutates a file under `output/`, ask which OTHER repos reference
  that path** — `git grep` in the siblings, not in your own tree — because the cross-repo consumer is
  invisible to every check you run locally.

- **RATIFIED, second occurrence on the same peer and the sharper one: THE PEER'S OWN STDERR GOES TO
  A FILE INSIDE THE CONTAINER AND DIES WITH IT — four investigations found "no crash" because
  nobody had kept the evidence.** 2026-09-02, closing the `zig` `r3_connection_flood` item. Every
  `run-s4.sh` in the cohort launches the peer as `./host … >/tmp/host.out 2>/tmp/host.err &`. Those
  are **container** paths on a `--rm` container: when the run ends the stderr is gone, so a peer that
  aborts leaves a harness log reading *"connection refused"* and nothing else. Adding
  `cat /tmp/host.err` after the oracle call — one line — turned *"not root-caused, no crash, empty
  stderr"* into a stack trace on the first reproduction. **Before concluding a peer did not crash,
  confirm you kept its stderr.** (Pairs with the standing *"a source grep is not a conformance
  census"*: here the missing evidence was not in the tree at all.)
  **What it found, and it is a lifetime bug BELOW peer code:** `thread NNNNN panic: reached
  unreachable code` at `std/Thread.zig:1377` — `entryFn`'s `completion.swap(.completed, .seq_cst)`
  landing on the `.completed => unreachable` arm. That state is only reachable if a detached thread's
  `Instance` mapping was **reused while its previous thread was still inside that `defer`**:
  `detach()` makes the thread `freeAndExit()` its own stack+TLS+Instance mapping, and a concurrent
  `spawn()` can be handed the same address. This is the standing zig entry's *"a detached worker must
  not outlive the state it borrows"* with the stdlib's own bookkeeping as the victim rather than
  ours — so **`detach()` is the hazard, not just what you hand it.**
  **Measured: 5 aborts in 60 full `--profile core` runs (8%).** It presents first as
  `t2_2_connection_churn` failing mid-cycle, and only then as `r3`.
  **TWO REPORTING LESSONS, both about numbers we had already published:**
  (a) **The previous record said `r3` 2/22 and churn **0/22**. Re-measuring gave 4/22 and 2/22 — so
  churn was never 0**, and a "0" that came from too few samples had been carried forward as a fact
  distinguishing two bugs. The standing rule (*re-run N times and count*) already covers the failing
  case; extend it to the **passing** one: a 0-of-N is a rate estimate too, and its confidence is
  bounded by N.
  (b) **The oracle's failure text can name a mechanism that is not the mechanism.** `r3` reports
  *"admitted 0/256 … admission slots leaked; the bound must release when connections close"* — a
  precise, plausible, and completely wrong description of a peer that is simply **dead**. It is
  inferring from `connection refused`. Read a check's prose as a description of what it OBSERVED,
  never of what happened; the instrumented accept loop (which never exited) is what separated the
  two.
  **CLOSED separately in the same session, and do not let it absorb the above: `zig` had no §4.10(c)
  admission bound at all**, so a 256-connection flood became 256 concurrent threads and `r3` FAILED
  **9 of 30** runs with *"admitted all 256 … fell over on the serve probe … i/o timeout"* — plain
  saturation, no crash, accept loop healthy. A 64-connection bound (**reserved BEFORE the spawn**,
  because a detached thread can finish before `spawn()` returns; **released LAST in the worker's
  teardown**, because a slot must never be free while its resources are held) eliminated that shape
  entirely — **0 of 60** — and took `r3` WARN→PASS (`314P/336W → 315P/335W`). **Two independent
  defects behind one intermittent check, and fixing the first one does not touch the second**: this
  is the 2026-09-01 `zig` pattern (`3/5 → 1/6 → 0/22`) recurring, where one bug masked another and
  only counting over repeated runs told them apart. Reporting the bound as "the fix" would have been
  a partial fix sold as a whole one.
  **LANDED COHORT-WIDE 2026-09-02, and the sweep is the entry above one level up: only THREE of 46
  harnesses kept the peer's stderr, and the survey that said otherwise was wrong twice.** The item was
  deliberately deferred as "its own job"; doing it produced the defect it exists to catch, on the
  first run. Two failed surveys first, both already-named shapes:
  (a) `grep -l 'cat .*host\.err'` reported **39 of 46 already capturing.** Every one of those 39 cats
  the file ONLY on the **startup-failure** path (`host exited before LISTENING`), which by
  construction cannot fire for a peer that starts fine and dies mid-run — the only case the item is
  about. **A grep can match the right token in the WRONG CONTROL-FLOW BRANCH, and that reads exactly
  like a pass.** This is the fourth member of the false-negative family after the `dart`/`ruby` NUL
  byte (could not SEE the file), F51 (wrong VOCABULARY) and the de-versioning sweep (pattern could not
  SPAN the construction) — and it is the first that is a false POSITIVE, i.e. it manufactures
  confidence rather than absence.
  (b) Narrowing to `host.err` then reported 5 peers with **no stderr file at all**. They have one;
  `io`/`pd`/`sql`/`turbowarp` merge stderr into a combined log under their own names and `node-red`
  uses `/tmp/nr.err`. **The discriminator has to be STRUCTURAL — a `cat` of the peer's log AFTER the
  last oracle invocation — not textual.** By that measure the real state was 3 of 46.
  **Three shapes, decided by the harness and not by taste** (the same "the substrate decides" rule as
  the §6.3 salvage flag): append after the oracle call (38 peers + `node-red`); **split the streams
  first** where the launch merges them, since a combined log is never empty and a guard on it would
  dump the log every run — and fix the startup-failure path to print BOTH, or the split moves the
  evidence out from under the one guard that already worked; and **hold the exit code** on the five
  whose oracle call has no `|| true` under `set -e` (`io pd sql python ruby`), where a naive append
  runs only when the oracle SUCCEEDS and is therefore silently absent from every failing run.
  **Verified by RUNNING** — all 46 `bash -n`, 10 peers driven through the census covering every shape,
  then the full 46-peer census at `756`, 46/46 comparable. The guard was also observed FIRING
  (`go python pd sql` print a startup banner on stderr), which is the half normally left unverified.

- **AN AXIS'S PER-PEER GATES ROT EXACTLY WHERE NO COHORT RUNNER REACHES — the NO-GATE column is not a
  list of peers without tests, it is a list of tests nobody runs.** RATIFIED 2026-09-02, and it is the
  entry below (*a second axis with no cohort gate*) proven a second time by its own leftovers. That
  entry closed the S2 sweep at **37 GREEN / 0 RED / 9 NO-GATE** and recorded, in the same breath, that
  *"they probably have no separate codec suite"* was **a hypothesis of the same shape as the four
  claims this ratchet disproved.** It was. **Five of the nine had a real authored S2 surface, and four
  of those five were RED:** `asm-x86_64` (`make diff` — an L2 native-codec differential against the
  3-way-locked corpus, 71 vectors + 4 synthetic — plus parse-test and peers-scope-test), `asm-arm64`
  and `riscv64` (FFI seam KAT + the only `peers`-dimension guard in the tree), `wasm-wat` (three
  authored WAT test modules) and `unison` (a UCM corpus transcript + 15 pinned-invariant self-tests).
  Sweep now **46 GREEN, 0 RED, 0 NO-GATE**.
  **Four failure shapes, none of them visible to S4, and each is its own small lesson:**
  - **A test's stub list can be too COARSE, and then the test's own guard reads as a crash.** The asm
    trio's unit aborts if `grant_scope_ok` reaches a host/FFI extern — correct — but §5.5 put an
    `mcpy` (the peer's own leaf byte-copy) on that path, so it aborted **before printing anything**,
    because `abort()` does not flush stdio. Give the benign leaf a real implementation; keep the
    genuinely off-limits externs (crypto, peerid, `write_all`) aborting.
  - **BISECT THE UNIT, DO NOT ATTRIBUTE IT TO THE LAST INTERESTING COMMIT.** With the crash gone, two
    ACCEPT assertions failed and the obvious culprit was the §1.4 address gate that had just landed on
    exactly these peers. **It was not:** `0d2c45e` never touched `grant_scope_ok`. Measured 11/0 at
    `ab00ccf` and `041443c`, 9/2 from `f3acd7f`, **one line of diff** — `resource_matches` →
    the §5.5a-aware `resources_cover_target`. The fixture granted a bare `*`, which §5.5a makes
    GRANTER-LOCAL, and the synthetic token has no granter: **a test about the PEERS dimension was
    failing on RESOURCES.** The peer was never wrong, and both REJECT directions passed throughout,
    which is why nothing else noticed.
  - **A CROSS-COMPILE FLAG THAT ONE BUILD PATH ALREADY DOCUMENTS.** `riscv64` could not COMPILE its
    unit: the Debian sysroot is multiarch and the Fedora cross-gcc is not, and the peer Makefile calls
    `$(CC)` a *"LINK DRIVER only — no C compiled"*, true of everything except that one target. The
    codec's `riscv64-cross-toolchain.cmake` has carried the exact `-I` with the exact explanation
    since the sysroot was built. **When a build fails on a flag, grep the tree for that flag before
    deriving it.**
  - **A NON-ASSERT FAILURE IN AN ASSERT-CODED HARNESS READS AS A BROKEN BUILD.** `wasm-wat`'s
    dispatch-test died with an out-of-bounds write (`offset 0x00a00000, boundary 0x007fffff`) and no
    code-table entry: `dispatch.wat` keeps its store index at `0xA00000` while the unit grew memory to
    8 MiB. The live peer never hit it because `host.wat` grows to 5632 pages for per-connection
    buffers. **A unit that imports a module authored against a larger memory map inherits that map.**
  - **A TRANSCRIPT THAT NO LONGER TYPE-CHECKS, with the proof sitting in the tree.** `unison`'s corpus
    gate called `ed25519Sign` with two arguments after it became `(seed, pub, msg)`. The committed
    `conformance.output.md` still shows the **old 2-arg signature** while `peer-compile.output.md`
    shows the 3-arg — i.e. the repo contained, in two adjacent files, the evidence that the corpus
    gate had not run since. It now runs **71/71** with its sha check.
  **INHERITANCE MUST BE CHECKED, NOT ASSERTED — and that is what keeps it out of the exclusion trap.**
  The other four (`rust-wasm`, `rust-wasm-wasmtime`, `node-red`, `turbowarp`) genuinely have no codec
  of their own. Their `run-s2.sh` **verifies the dependency edge still exists** (`path = "../rust"`;
  the harness building from `protocol-generator/typescript`) and then runs the PARENT's gate. Fork a
  codec into a seam and the edge check goes RED — which is exactly the moment that peer would have an
  unmeasured codec. Regression-tested by planting a broken edge. **This is how to encode "it inherits"
  without a per-peer exclusion in the measurement tooling** (the `apl` lesson): the claim executes.
  **And two harness rules the peers themselves taught:** a gate must not rewrite a **committed**
  artifact (`ucm transcript X.md` writes `X.output.md`, and those are tracked — a gate that dirties
  the tree is one people stop running, so drive from a scratch copy); and where the runner's exit
  code is 0 for a completed-but-failing suite, **read the output text and print the COUNT** — the
  `smalltalk` `make sunit` defect. My first matcher then found `FAIL` in every transcript, because a
  ucm transcript **echoes its own source** and the source DEFINES the checker as
  `(if ok then "PASS " else "FAIL ")`. Match the rendered RESULT shape, not the word.

- **AN INSERTED CALL AND THE DEFINITION IT NEEDS MUST BE ANCHORED TO THE SAME SCOPE — AND THE
  OBVIOUS ANCHOR IS IN A DIFFERENT SHELL ON A THIRD OF THE COHORT.** RATIFIED 2026-09-03, folding
  `-reference-peer` into all 46 `run-s4.sh`. Both defects were in MY sweep and both were found by
  running it, not by reading it:
  - **Scope.** The natural anchor for a `. <helper>` line is the harness's own `ORACLE=` default near
    the top. For the **19 peers that re-exec into their container that line runs on the HOST**, while
    the oracle invocation runs INSIDE — so the helper was sourced where `/work` does not exist and the
    function was undefined where it was called. Measured on `c`. **Fix: anchor the definition to the
    CALL SITE, not to the top of the file** — then the scope question cannot be asked wrongly. Same
    reasoning forced the teardown call to be `if command -v f >/dev/null; then f; fi`: the trap is
    installed *before* the helper is sourced, and an `&&` form returns non-zero, which under `set -e`
    aborts the teardown **before the target is reaped** — a helper detail turned into a leaked peer.
  - **A line-start anchor misses exactly the peers that had a REASON to deviate.** Five harnesses
    (`io pd python ruby sql`) write `rc=0; "$ORACLE" -addr … || rc=$?` because their oracle call has
    no `|| true` under `set -e` and the exit code has to be held — the deviation this file already
    documents. A `^"$ORACLE"` pattern skipped all five. **The peers that do not match your template
    are the ones that had a reason not to, so a template-shaped pattern misses them systematically,
    not randomly** — and five reads as "a few odd peers" rather than as a broken pattern.
    *(And the count in this very bullet is SIX — `prolog` holds the exit code as `|| RC=$?` / `exit
    "$RC"`, a second spelling of the same deviation, which the enumeration above missed for the same
    reason the regex did. Measured 2026-09-16; see the candidate-oracle entry below. A bullet warning
    that a template-shaped pattern misses the deviants, itself keyed on one spelling of the
    deviation.)*
  **Enforcement, and it is the postcondition rule again: gate the PROPERTY, not the edit.**
  `tools/fold-reference-peer.py --check` (ninth `make lint` gate) re-parses every harness for the
  four properties independently of how they got there, and **prints the count** — 46 of 46 — because
  a sweep that patched zero files prints the same word as one that patched 46.

- **A DOCUMENTED CHECK THAT NOTHING INVOKES IS THE 2d ROT PATTERN, AND ITS EXIT CODE IS USUALLY NOT
  THE CHECK EITHER.** RATIFIED 2026-09-03 (`lean`). `lake build EntityCoreProofs` was called *"the
  proof check"* in three of this repo's own documents and **no Makefile, script or harness built that
  target** — `run-s2.sh` built the peer, `run-s4.sh` builds `host`. `AGENTS.md` calls the Lean proof
  vector *"the highest-signal channel"*; it was ungated for its whole life.
  **The sharper half is that calling the tool would not have been enough.** Measured in the peer's
  own pinned toolchain: a `sorry` is a **warning** — `lake` prints `Build completed successfully` and
  **exits 0** — and a hand-written `axiom` substituted for a proof exits 0 with **no warning at
  all**; only a type-check failure is non-zero. **A gate trusting that exit code catches one failure
  mode in three, and misses the two a proof check exists for.** The check is the **axiom set**: no
  declaration may depend on `sorryAx` or on anything outside the Lean-standard three, plus a FLOOR on
  the number of graded declarations, because a module that stops emitting `#print axioms` passes
  every name check vacuously.
  **Generalize past Lean: for any gate that shells out to a build tool, ask what that tool does with
  the failure you actually care about before trusting its exit status** — this is the Gradle
  `UP-TO-DATE` and Maven no-tests lesson in a third package manager, and the answer differed from the
  documented one in two of three cases.

- **A UNIT THAT NOBODY RUNS FAILS IN THE DIRECTION THAT LOOKS LIKE A PEER BUG — AND THE COMMENT
  EXPLAINING WHY IT IS SAFE IS WHERE THE DEFECT LIVES.** Second occurrence 2026-09-03 (`sql`, after
  `apl`), and it closes the S3 axis at 18 GREEN / 0 RED. `sql`'s S3 selftest drove its **post-auth**
  EXECUTEs through a helper commented *"no author/capability — §4.2 pre-authorized"*. That sentence
  is true of the connect path and **false of every request after leg 2**, so the peer answered `401
  authentication_failed` — correctly — and the gate read as a peer regression for as long as nobody
  ran it. It had been red since the §5.5a/§6.2 authority work landed underneath it.
  **The fix is a real request, never a relaxed assertion**, and the shape generalizes to any
  self-driven client: the capability **cannot be rebuilt client-side** (its `created_at` is the
  peer's wall clock, so its hash is unpredictable), so leg 2 must be read **without discarding the
  frame** and its `included` entities copied out and re-presented verbatim. Assert the lifted
  material in leg 2's own line (`cap=33B included=3`) so a leg-2 shape change fails *there* rather
  than silently producing an unsigned leg 3.
  **Two controls, not one, and they must produce DIFFERENT dispositions** — corrupt the request
  signature → `401 authentication_failed`; withhold the grant material → `403 capability_denied`. One
  control would not distinguish "the signature is checked" from "something is checked."

- **A `run-*.sh` whose guard tests a CONTAINER path must be INVOKED in the container — and its
  failure is indistinguishable from a missing dependency.** Candidate, and it is the standing
  *"a guard that was never executed is not a guard"* entry met from the caller's side rather than
  the author's. Running the S2 sweep on the host, `prolog` died with `swipl: command not found` and
  `ocaml/run-agility.sh` with `missing /work/ffi-generator/…/libentitycore_codec.so — build the FFI
  codec first` **while that file existed on disk**: `$SODIR` is `/work/…`, the repo's mount point,
  which does not exist on the host. Both scripts are correct; both read as a broken toolchain or a
  missing artifact, which is a diagnosis pointing at the tree instead of at the invocation. Each
  script's header carries the `podman run` line it expects — **read it before believing the error**,
  and prefer `rc=127`/`file missing` as a signal to re-check HOW you invoked it.
  **RATIFIED 2026-09-02, and the fix is uniformity rather than documentation: `prolog`'s `run-s2.sh`
  now re-execs itself into its container like the 21 siblings that already did.** A cohort axis is
  swept by invoking one conventional entry point per peer; the odd one out does not fail *informatively*,
  it fails as `command not found`, which is the single most misleading exit a sweep can produce.

- **A TEARDOWN THAT SIGNALS IS NOT A TEARDOWN THAT WAITS — and when the symptom is a RACE BETWEEN TWO
  DURATIONS, only one of which you own, it is absent on exactly the peers you would test first.**
  RATIFIED 2026-09-02 (cohort-wide sweep, 45 of 46 harnesses). Every `run-s4.sh` tore its peer down
  with `trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT` — fire-and-forget. `kill(1)` DELIVERS a
  signal and returns, so the trap returns, the script exits, and **the peer is still holding the
  listening socket.**
  **The methodological half is the durable one, and it nearly killed the work.** The reported symptom
  was *"a back-to-back invocation in the same container cannot rebind the port."* Reproducing it on
  `go` (5 of 5 clean) and on `zig` (10 of 10 clean at a full `--profile core`) says the defect does not
  exist — and those are the two peers anyone reaches for. The symptom is a race between *how long the
  old peer takes to die* and *how long the next invocation takes to reach its bind*, so a slow build
  step hides it and a fast runtime hides it. **Only one of those two durations is a property of the
  harness. Measure that one.** A probe that connects to the port in a tight loop the instant the
  harness returns answers directly, in one run per peer: `rexx` **never** released it, `elixir` **>400 ms**
  (and the next invocation exited 1, alternating), `julia` **~88 ms**, `smalltalk` **~4 ms**, `crystal`
  `zig` `go` **0 ms**. After: every one of them 0–1 ms. Generalise past ports — **when a reported
  defect will not reproduce, ask whether the symptom is a race you only half own, and instrument the
  half you do.**
  **`crystal` had the correct teardown the whole time and nobody had looked** — the standing *"when a
  scope question has 45 existing answers in the tree, ask them before deriving one"* rule, in the one
  direction that is easy to miss: the cohort can already contain the fix. The sweep propagated
  `crystal`'s function rather than authoring one.
  **Enforcement: `tools/harness-gate.py`, in `make lint`** — exactly one non-comment `trap` per
  harness, it must name a FUNCTION (an inline `trap 'kill …'` is the defect by construction), that
  function must exist, and its body must `wait` on a pid. It deliberately does not gate the signal
  (`python` `ruby` `prolog` chose `-9` deliberately, and SIGKILL + `wait` is correct) or the poll
  bound. It asserts the harness count against the peer roster, so a peer with no `run-s4.sh` is an
  ERROR rather than a silent skip, and it is regression-tested against four planted defects plus that
  vacuity case. It found one on its first run: `crystal` writes `trap 'reap_host' EXIT`, and the
  first cut rejected the quotes.
  **A SWEEP OF 46 HARNESSES IS NOT VERIFIED BY `sh -n`, BECAUSE 11 OF THEM RE-EXEC INTO A CONTAINER
  AND THE EDITED TEXT IS A STRING THERE.** `sh -n run-s4.sh` parses that argument as a literal and
  returns 0 whatever is inside it — so the obvious check covers 35 files and reports 46.
  Reconstructing the block with a regex fails too, and fails *plausibly*: those blocks contain
  `PORT="'"$PORT"'"`, where the outer shell CLOSES the quote, splices a value and reopens it, so a
  scanner that stops at the first unescaped quote captures a fragment and `sh -n` then reports a
  syntax error in text that never existed. **Shim `podman` and let the real shell do the quoting**
  (`protocol-generator/shared/diagnostics/inner-container-script-check.sh`). Its own first cut read
  the argument after a literal `-c` and captured **nothing** for the four peers using `bash -lc`,
  reporting them as "no inner script" — a false clean, which is the same defect class the sweep was
  about. Corollary for any text inserted into those blocks: **not one apostrophe may appear in it**,
  comments included; the rewriter asserts that before it writes anything.
  **`rexx` is the peer that proves the rule, and its two defects were both invisible-by-construction.**
  (a) The listening socket is held by a reparented `ecnet` co-process, not by the harness child, so
  `wait` cannot see it — and the existing cleanup reached for **`pkill -f`, WHICH IS NOT INSTALLED IN
  THAT IMAGE** (nor are `pgrep` or `ps`). `2>/dev/null || true` swallowed the command-not-found and
  the cleanup reported success having reaped nothing, so the daemon survived *every* run and the
  second invocation in a container exited 1 forever. Bisected against HEAD before attributing it —
  identical there, pre-existing. **Generalise: `|| true` on a command that may not exist converts
  "missing tool" into "success", and a cleanup path is where nobody notices.** The fix scans `/proc`,
  which needs no tooling at all. (b) Every diagnostic this peer emits — including its `PEER FATAL
  SYNTAX` handler — was written as `call lineout stderr, …`, where **`stderr` is an unset REXX
  variable and therefore evaluates to the literal string `STDERR`, a FILENAME.** For as long as the
  peer has existed its dying words went to an untracked file in the working tree. **This is the
  cohort-wide keep-the-peer-stderr fix meeting its second half: the harness now preserves fd 2
  faithfully, and this peer was not writing to it.** `'<stderr>'` is the stream (pinned by
  `protocol-generator/rexx/test/stderr-stream-name.rex`, which shows both spellings side by side).
  Neither defect moved a check: `rexx` measured `756 · 313P/337W/0F/106S` before and after, equal to
  its committed report.
  **Verification standard used, and it is the one the sweep rule demands:** every *shape* executed,
  not one representative — `HOST_PID` at top level, `HOST_PID` inside a re-exec block, `PEER`, `PP`,
  `PDPID`, `NR_PID`, the five one-line `cleanup()` peers, and the three hand-edited ones. Six peers
  (`java` `sql` `python` `io` `pd` `rexx`) were run to a full `--profile core` and each reproduced its
  committed row **exactly**; seven more were driven through the port probe.
  **AND THE SIBLING CHECK FOUND THE SECOND INVARIANT: `run-s4.sh [validate-peer-args...]` IS THE
  DOCUMENTED INTERFACE, AND THREE PEERS DROPPED IT ON THE FLOOR.** Noticed because `python`
  rewrote its own tracked `CONFORMANCE-REPORT.json` during a teardown probe that had explicitly
  passed `-json-out /tmp/…`. `python` `ruby` `prolog` hardcoded their entire argument list, so
  `run-s4.sh -category connectivity` ran **756 checks where the caller asked for 25** *and*
  overwrote the signed-off record it was meant to be diagnosed against — the *"a gate must not
  rewrite a committed artifact"* rule, in a harness, with the artifact being the number this repo
  publishes.
  **The five-peer `'"$*"'` splice is the more interesting half, because the prediction was wrong
  and measuring is what corrected it.** `ada` `c` `common-lisp` `java` `kotlin` spliced `$*` into
  their container block, which reads like it flattens argv into ONE argument. It does not: the
  outer shell CONSUMES those quotes and the inner shell word-splits what is left, so ordinary
  flags survive — `java -category connectivity` measured **25 checks**, correctly. So it is a
  latent quoting hazard (any value containing a space, a glob or a `;` is mangled or re-executed),
  not a break. **Say which it is; a hazard reported as a break is as much a misreport as the
  reverse.** All eight now use the `bash -c SCRIPT bash "$@"` form the other four re-exec peers
  (`sql` `io` `pd` `datalog`) already had, where the interpreter word is argv[0] and the caller
  args arrive as `$1..` with quoting intact.
  **A THIRD SELF-AUTHORED EXCULPATION, AND THIS ONE WAS HALF TRUE, WHICH IS WHY IT SURVIVED.**
  `CONFORMANCE-MATRIX.md` §1 disclosed `cobol`'s two extra skips as *"payloads (256 KiB, 16 KiB)
  that its 65535-byte frame cap and 8192-byte per-entity ceiling cannot accept, and it now
  refuses them with `413` rather than crashing."* The 16 KiB one does: it exceeds the per-entity
  ceiling and `handlers.cob` answers a **correlated** 413. **The 256 KiB one exceeds the FRAME
  cap, never reaches any COBOL code, and was answered with NOTHING** — `netshim.c` drained the
  body and kept serving, which is the half of §4.10(a) about the connection, with a comment
  explaining why closing would break the caller's pooled connection, and no trace of the half
  that is a MUST (*"MUST reject … with `413 payload_too_large`"*). **A §4.9(c) drop bills the
  CALLER, so it reads as the peer being slow**: the check reported `i/o timeout` and was filed as
  a capacity skip. Fixed 2026-09-02 (`oversize-result` emits the section's *best-effort coded
  frame*; the `request_id` is unavailable **by construction**, because refusing before decoding
  is the point of the rule, so it goes out empty rather than guessed). `t1_3` now reports
  `tree put status 413`. **The counts did not move** — 756 · 312P/336W/0F/108S before and after —
  which is the whole reason it was safe to believe the row for three days. **A disclosure that is
  true of one of two cases reads exactly like a disclosure that is true.**
  **AND THE CEILING ITSELF IS SPEC-LEGAL, so say what is a defect and what is a bound.** §4.10(a)
  requires only that the maximum be FINITE; the protocol places *"no restriction on entity size"*
  and the 16 MiB frame figure is a SHOULD. The missing 413 was the defect; the capacity is a bound
  — and **a conformant peer can be recorded as FAILING for honouring it**, because the oracle
  scores the resulting refusal as a SKIP and prints *"skip(s) count as FAIL"*. Routed to arch as
  **F53** (`shared/findings/conformance-payload-capacity-floor.md`).
  **RAISING IT TAUGHT THREE THINGS, and the first is the one to carry.**
  - **A CEILING IS A FAMILY, NOT A NUMBER, AND THE FAMILY IS NOT THE LITERAL YOU GREPPED FOR.**
    In COBOL a LINKAGE item is a VIEW over the caller's storage, so a callee declaring
    `pic x(32768)` over a caller's `pic x(8192)` reads 32 KiB out of an 8 KiB field on any
    full-length `MOVE` — **a PARTIAL raise is more dangerous than no raise**, which is why this
    lands as one uniform edit or not at all. And the first pass, keyed on `pic x(8192)`, **missed
    `cbor.cob`'s map-pair value slot, which is `pic x(4096)`** — a second family. That pass would
    have shipped a peer whose handlers accept a 32 KiB entity and whose canonicaliser cannot carry
    one, i.e. a 413 traded for a canon error. **Enumerate the size literals and classify each,
    rather than substituting the one you noticed.**
  - **THE SIZE THAT LOOKS AFFORDABLE IS DECIDED BY WHERE THE BUFFER LIVES.** 512 KiB works
    *functionally* — both probes PASS — and is unusable: `cbor-canon` is **recursive** and its
    per-call `LOCAL-STORAGE` holds a 64-entry pair table, so a 512 KiB value slot costs **~34 MB
    per call per nesting level**. Measured: sustained load dropped **7454 of 10000** requests, the
    category went **15.5 s → 9 m 50 s**, and both robustness checks that had been passing FAILED.
    At 32 KiB the same table costs 2 MB and the suite runs in 55 s. **Before raising a buffer, ask
    whether it is `WORKING-STORAGE` (once) or `LOCAL-STORAGE` in a recursive program (per call, per
    level)** — the same declaration in the two places differs by orders of magnitude.
  - **THE TRADE HAD A LOSING SIDE AND IT HAD TO BE PUBLISHED.** `t1_4` went SKIP → PASS **and**
    `t1_1_concurrent_demux` went PASS → WARN, because the bigger buffers slowed the peer past the
    check's 0.70 concurrent/sequential ratio. Not flaky — **4 of 4 WARN after against 3 of 3 PASS
    before**, counted rather than assumed. The WARN is the *more accurate* label (the oracle's own
    text: *"not a §6.11 violation — informational … for runtimes that do not physically
    parallelize"*), but it still moves a published column, and reporting only the gain would be the
    overclaim. **Verified per-check: exactly 2 of 756 severities moved.**
  **CLOSED 2026-09-04, and the closing move RETRACTS the middle bullet's conclusion while confirming
  its measurement — which is the durable half: A CAPACITY THAT IS UNAFFORDABLE IN ONE DATA STRUCTURE
  IS NOT AN EXPENSIVE CAPACITY, IT IS THE WRONG DATA STRUCTURE, AND THE COST FIGURE CANNOT TELL YOU
  WHICH.** "512 KiB costs ~34 MB per call per level" was correct, reproducible, and led to the wrong
  conclusion, because the ~34 MB was a property of a table that **buffered every map value into a
  fixed per-pair slot** — so the measured price of capacity was really the price of that design at
  that capacity, and it read as a substrate limit. `cbor-canon` now records each pair's canonicalized
  KEY plus the INPUT OFFSET its value starts at, and canonicalizes values straight into the output in
  sorted-key order on a second pass; values are bounded by the output buffer alone. Per call, per
  level: **2.13 MB → 65.8 KB**, i.e. 33× *below* where it started, and the per-value ceiling is gone
  rather than raised. With that, the frame cap is 512 KiB, `t1_3` is PASS, and **the suite is faster
  than it ever was at 64 KiB: 47.9 s → 13–15.7 s over 7 of 7 runs.** The store took the same move for
  the same reason (1024 fixed slots → one arena addressed by offset), which decouples the ONE-entity
  ceiling from the ALL-entities footprint that was multiplying it. **Rule: when a measurement says a
  capacity is unaffordable, ask what is multiplying it before believing the substrate — a per-call ×
  per-level × per-pair fixed slot is three multipliers, and removing any one of them changes the
  answer by orders of magnitude.**
  **The third bullet's trade REVERSED, and that is worth as much as the trade was.** `t1_1_concurrent_
  demux` went WARN → **PASS**, undoing the loss recorded above: the peer got fast enough that the
  oracle's sequential baseline falls under its 50 ms floor and the speedup signal is suppressed.
  Verified the same way it was recorded — **exactly 2 of 758 severities moved, 7 of 7 runs identical,
  no `budget_exhausted`, executed digest equal to the pin.** A published trade is not permanent, and
  re-measuring the losing side after a redesign is part of the redesign.
  **A SECOND SIZE FAMILY EXISTS THAT IS NOT A DECLARATION AT ALL — the NAMED CONSTANT that tells a
  callee how big the buffer it was handed is.** The first bullet says to enumerate the size literals;
  it is not enough, because a mechanical sweep over `pic x(N)` leaves `01 entmax … value 32768`,
  `01 cap-entmax … value 32768`, `01 maxlen … value 20000` and `01 cap65 … value 65535` behind —
  four guards and capacity arguments that were CORRECT at the old sizes and become a silent
  truncation or a false 413 at the new one. `grep -n '<old size>' src/*.cob | grep -v 'pic x('` finds
  them in one line and finding them by test would have meant a `413` on a payload the transport had
  already accepted. **After raising a declaration family, grep for the same number as a VALUE.**
  **And the store geometry was the cheap half, exactly as recorded:** peak occupancy across a full
  run is **116–119 content entries against 1024 slots**, so the arena carries a 264 KB entity at a
  *smaller* total footprint than the 1024 × 32 KiB slot table it replaced (33.6 MB → 8 MiB + offsets).
  **The gate is `tools/harness-gate.py` — teardown AND args, one file, because both are
  invariants of the same interface.** It counts its ANCHORS, not just its failures: `46 wait ·
  46 forward · 11 hand argv across a container boundary`, and that 11 is asserted non-zero and
  independently corroborated by `inner-container-script-check.sh` finding the same 11. Six planted
  defects, and the two arg plants are on DIFFERENT victims (`go` plain, `java` re-exec) because
  the two shapes fail through different mechanisms.

- **A SECOND AXIS WITH NO COHORT GATE IS AN EXCLUSION NOBODY DECLARED — and it will be defended by
  the fact that the FIRST axis is green.** RATIFIED 2026-09-02, and it is the `apl` exclusion lesson
  moved up one level: there, the one peer nobody could measure was the one peer the census refused to
  attempt; here, an entire **axis** had no sweep, so the question was never asked of anyone.
  `CONFORMANCE-MATRIX.md` published **46 of 46 at `756 · 0F`** while, on the S2 (codec /
  crypto-agility) axis, **four peers were red or unrunnable and had been for a long time.** S4 has
  `run-cohort-census.sh` plus three gates on its numbers; S2 had nothing, and every defect below sat
  behind that one absence:
  - `haskell` — **unrunnable at all.** Its S2 report claimed *"Offline … verified GREEN"* against a
    warm store in a **gitignored in-tree `.cabal-home`** that one machine had warmed by hand, and only
    for the LIBRARY deps. Once runnable: 1 real FAIL.
  - `smalltalk` — `make sunit` died compiling its own driver, **and asserted nothing about the suite's
    counts regardless** (a red suite printed `failures=3` and the target passed).
  - `ocaml` — `test/selftest.exe` had been **FAILING** on a stale §7a expectation, unswept because the
    peer had no `run-s2.sh` and its one host-invocable script never builds it.
  - `typescript` — `npm test` ran `node --test dist/**` with **no build step**.
  - `python` — its tests `import pytest`, declared as a pyproject `dev` extra and installed **nowhere**;
    the suite had never run in its own image.
  **THREE OF THOSE ARE ABSENCE DEFECTS, NOT RED GATES — the peer had no entry point on the swept path,
  so it was neither measured nor reported as missing.** That is why `tools/run-s2-sweep.sh` reports
  **NO-GATE as a first-class outcome** and prints the count of each; a sweep that silently skips what
  it cannot find reproduces the exact hole it exists to close. Enforcement: `tools/run-s2-sweep.sh`
  (`--gate` fails on RED; `--gate-missing` additionally requires full coverage), driven off
  `peer-tiers.tsv` with **no per-peer exclusions in the measurement tooling** — a peer leaves the sweep
  only by leaving the roster, where its absence reads as backlog. Result at ratification: **37 GREEN,
  0 RED, 9 NO-GATE** of 46. The 9 are the hand-authored / thin-seam / exploratory groups (`unison`, the
  ISA trio, `wasm-wat`, both `rust-wasm`, `node-red`, `turbowarp`); *"they probably have no separate
  codec suite"* is a **hypothesis, and it is the same shape as the four claims this ratchet disproved.*
  **CLOSED the same day, and the hypothesis was wrong: 5 of the 9 had a real authored S2 surface and
  4 of those 5 were RED. Sweep is now 46 GREEN, 0 RED, 0 NO-GATE** — see the *"an axis's per-peer
  gates rot exactly where no cohort runner reaches"* entry above for the four failure shapes and for
  how the remaining 4 encode inheritance as an executable edge check rather than an exclusion.
  **Generalize past S2: for every axis a number is published on, name the sweep AND the gate. An axis
  with a per-peer harness and no cohort runner is one nobody is measuring.**
  **CLOSED 2026-09-02 by ENUMERATING THE AXES — and the enumeration is the artifact, not the sweeps.**
  The S2 entry above was written the same day and stopped at S2. There were **two more**: `run-s3.sh`
  (18 peers, two-direction loopback interop) and `run-origination-core.sh` (31 peers, §10.2/§6.11
  reentry). Neither had ever been run across the cohort. First sweep of each: **S3 12 GREEN / 6 RED,
  origination 16 GREEN / 15 RED** — *half the authored origination gates and a third of the authored
  S3 gates were failing*, while `CONFORMANCE-MATRIX.md` published 46 of 46 at `756 · 0F` and was not
  wrong. `tools/run-axis-sweep.sh` is now the single engine with the axis table as DATA (`--list`
  prints it), `run-s2-sweep.sh`-style copies are not made per axis, and **an axis absent from that
  table has no cohort runner, which is an exclusion nobody declared.** S4 is deliberately excluded and
  says why in the file: it has its own runner plus three gates on the comparability of what it emits.

- **EVERY VERIFICATION AXIS MUST NAME ITS AUTHORITY, AND THE ONE THAT CANNOT IS THE ONE THAT GOES
  STALE.** RATIFIED 2026-09-03, prompted by the operator asking the question nobody in this repo had
  asked in writing: *where did these gates come from, and did architecture specify them?* The answer
  was mostly reassuring and the exception was the whole finding.
  **`GUIDE-CONFORMANCE.md` §7.0 settles the taxonomy** (arch-owned, `guides/` in
  `entity-system-architecture`, pinned `f7d4191d…` in the `v0.8.2.3` manifest and verified
  byte-identical): there are exactly three kinds of artifact — a **`validate-peer` check** authored by
  `entity-core-go`, a **fixture corpus** authored by architecture, and an **impl-internal unit test**
  which is *"that repo, its own concern"* — and it states outright that **"`entity-core-keystone`
  authors none of these"** and that asking keystone for a vector *"asks the scorer to write the exam."*
  Mapped onto our four axes: **S4** is the oracle; **origination** is *the same oracle*
  (`-category origination -reference-peer`) — **not a separate suite at all, but the category a
  single-peer census structurally cannot reach**; **S2** is arch's two vendored corpora plus our
  `type-registry/` drift target, which is explicitly labelled derived and non-normative. **S3 is
  ours**: 17 of its 18 harnesses are hand-written assertions with no oracle behind them.
  **The correlation is the lesson and it is exact: the only axis with no external authority is the
  only axis whose checks went stale.** `apl`'s selftest handed `CapCheckPermission` an absolute path
  where the peer passes the stripped one; `sql`'s never signs its post-auth requests. Both peers are
  `756 · 0F` on the wire. An assertion with an oracle behind it MOVES when the oracle is re-pinned and
  `check_set_digest` makes that visible; **an assertion we wrote ourselves has nothing watching it**,
  so it drifts against the code it exists to check and fails in the direction that looks like a peer bug.
  **And the guide already offers the replacement, which we have never run.** §7's surface map lists a
  **Live peer matrix** — *"integration bugs (handler routing, identity resolution, cross-peer
  convergence) fixtures can't reach"* — verified by `validate-peer -peers <addrs>`. `grep -rn '\-peers '`
  across every harness and tool returns **nothing**. S3 is a hand-rolled approximation of a surface the
  oracle covers properly and we have never measured.
  **Enforcement, and it is a documentation rule because the defect is one of provenance rather than of
  code: an axis in `tools/run-axis-sweep.sh` must carry, in the file, the authority its checks derive
  from — oracle, vendored corpus, or "ours, impl-internal".** An axis that cannot name one is not
  conformance and must never be reported as though it were. Corollary for the reverse direction:
  **before authoring a check here, look for the oracle flag that already drives that surface** — three
  of our four axes are consumption, and the fourth exists partly because nobody checked.
  **AND THE COROLLARY IMMEDIATELY PAID OUT AND IMMEDIATELY BIT: `-reference-peer` IS THE ORIGINATION
  AXIS, AND `-peers` IS NOT THE S3 REPLACEMENT I HAD JUST RECOMMENDED.** Measured 2026-09-03 against
  the reference peer, one flag at a time — the only way to tell these apart, because each flag's
  effect is invisible from its help text:
  | invocation | executed | skips |
  |---|---:|---:|
  | `--profile core` (every census row) | **756** | 106 |
  | `+ -corpus <ecf.cbor>` | 756 | 106 — **no effect; `conformance` is not a core category** |
  | `+ -reference-peer <addr>` | **758** | **105** |
  | `+ -peers a,b` | **200** — a DIFFERENT suite | 38 |
  - **`-reference-peer` adds exactly three checks** (`origination/dispatch_outbound_reentry`,
    `reference_connect`, `reference_ready`) in place of one `origination: skipped` placeholder. **That
    is the whole origination axis.** The census has never passed the flag, which is the only reason
    31 peers carry a `run-origination-core.sh` and 15 do not. Folding it in retires an axis, deletes
    31 scripts, and covers the 15 for free — at the cost of a 756 → 758 re-pin and a 46-peer
    re-census. **A separate harness that exists because a flag was never passed is not an axis, it is
    a workaround with a directory.**
  - **`-corpus` changes nothing under core**, so S2 is genuinely independent rather than a
    hand-rolled duplicate of an oracle category — worth knowing before "simplifying" it away.
  - **`-peers` does not extend a core run; it switches to a 200-check multi-peer suite that is
    ENTIRELY standard-extension surface** — 38 skips across `convergence` (10), `route` (8),
    `relay_source_route` (6), `relay_offline_delivery` (5), `cross_peer_http_subscription` (5),
    `relay_multi_peer` (4), and one FAIL in `relay_offline_delivery_registry` **against go's own
    reference peer** (B not started with `--inbox-relay-registry`). RELAY / NETWORK / SUBSCRIPTION are
    out of scope here, so adopting it would mean measuring what we deliberately do not build.
  **THE PROCESS LESSON IS THE ONE TO KEEP, AND IT IS ABOUT MY OWN OUTPUT.** *"Retire S3 in favour of
  `validate-peer -peers`"* was recommended in writing, with a rationale, hours before anyone measured
  it — and it was wrong in the direction that would have cost the most: it proposed deleting a working
  (if unauthored) axis in favour of one measuring surfaces we do not implement. The standing rule is
  *"verify a routed claim before acting on it, especially the exculpatory half"*, already broadened
  once to *"the exculpation most likely to be wrong is the one WE wrote, because nothing routes it back
  for review."* **Broaden it again: a RECOMMENDATION is an exculpation about future work** — it says
  which effort is unnecessary — and it is read once, acted on, and never re-derived. **Measure the flag
  before proposing the migration.** One `podman run` with four invocations answered it in ninety
  seconds and reversed the conclusion.
  **RATIFIED 2026-09-12 — second occurrence, different shape, and this one was refuted by the
  OPERATOR rather than by us.** The cell census (§5) offered *"could canonicalization move to mint
  time"* as the shape of question worth asking once — hedged as unverified, and still a
  recommendation about a **wire-affecting migration across 46 peers and three ground-up
  implementations**. The objection was one sentence — *the granter is always known at grant
  creation, so both readings freeze the same value* — and checking it case by case took twenty
  minutes: **extensionally equivalent in every single-granter case, and the only divergence is the
  K-of-N root, where the proposed direction is STRICTLY WORSE** (no single granter exists to
  freeze). The bug class it targeted was **already gated** — only one of four layers takes a
  non-local frame, and §5.5a ships three vectors on it. **So the rule is not "hedge the
  recommendation", it is BUILD THE CASE TABLE BEFORE PROPOSING**: the first occurrence was
  reversed by four invocations, this one by seven rows, and in both the artifact that settles it is
  cheaper than the paragraph arguing for it. Strike a withdrawn recommendation **in place with its
  case table** — *"we asked and the answer was no, here is why"* is worth more to the next reader
  than silence, and it is what stops the same migration being re-proposed in a month.
  *(Sub-lesson, cheap and general: **a `PARTIAL … do not cite this total` banner can be a property of
  YOUR INVOCATION rather than of the peer.** An ad-hoc run against a peer started `-open-access` with
  no `--name`/keypair prints exactly that banner, reports `Result: FAIL (un-allowlisted skips)`, and
  inflates passes 314P/336W → 650P/0W via the type-registry matched-if-present effect. Our census logs
  emit `Result: PASS (with warnings)` and no banner — checked, not assumed. I had drafted this as a
  cohort-wide overclaim finding before reading `output/scratch/census-logs/go.log`. **Compare against
  the harness the number actually came from, never against a hand-rolled invocation of the same tool.**)*

- **A PER-PEER ENTRY POINT ONLY WORKS THE WAY ITS AUTHOR HAPPENED TO INVOKE IT, AND NOTHING FINDS
  THAT UNTIL SOMETHING INVOKES IT DIFFERENTLY — this one class was 15 of the 21 failures across two
  axes.** RATIFIED 2026-09-02, and it is the third and largest occurrence of the shape already
  recorded for `prolog`'s `run-s2.sh` (*"a `run-*.sh` whose guard tests a CONTAINER path must be
  INVOKED in the container"*). **Fourteen** `run-origination-core.sh` were inside-container-only and
  died from the host with `cd: /work/...: No such file or directory`; `prolog` added `swipl: command
  not found`. Every one of them named the correct `podman run` line **in its own header comment** —
  the invocation was documented and not executed. Fixed by making each script re-exec itself into the
  image its header already named; 15 RED → 0 in one pass, verified by running every one.
  **Two things generalize.** (a) **The defect is invisible to the author by construction**: it only
  appears under an invocation the author never used, so it cannot be found by reading, only by
  sweeping. (b) **`rc=127` and `cd: No such file` are the signature** — both read as a broken tree or
  a missing toolchain, i.e. they point the reader at the peer instead of at the call. Enforcement:
  every per-peer entry point is invoked by its axis sweep from the host, so a new one that is
  container-only fails the first time the axis runs. *(Sub-lesson: `go`'s was a different bug wearing
  the same clothes — it mounted `protocol-generator/go/output/s4-oracles`, a path that has never
  existed, and failed with `statfs`. Do not batch-classify by exit signature alone; read each log.)*

- **A UNIT THAT NOBODY RUNS GOES STALE UNDER A PEER THAT KEEPS GETTING FIXED, AND IT FAILS IN THE
  DIRECTION THAT LOOKS LIKE A PEER BUG.** RATIFIED 2026-09-02, two peers, both at `756 · 0F` on the
  wire while their own S3 selftests were red — which is the inverse of the standing *"a check that
  passes can be passing for a reason unrelated to what it tests"* and just as misleading.
  - `apl`: `[FAIL] permission check ALLOWs system/tree:get`. The assertion passed
    `CapCheckPermission` the **absolute** `/{peer}/system/tree` while `DispatchInner` passes
    `StripLocal pattern` and the fixture grants the handler **relatively** (`CapGrant('system/tree')`).
    An absolute path cannot match a relative grant, so the unit could only ever deny. This is the
    `cobol` id-scope lesson exactly — *an id is compared literally, and the value handed to the
    matcher decides everything* — sitting in a test that had not run since the peer took that fix.
  - `sql`: `[FAIL] 404 unregistered path → status=401`. The selftest sends its post-auth EXECUTEs
    through a helper commented *"no author/capability — §4.2 pre-authorized"*, which is true of the
    connect path and false of everything after it. The peer correctly answers
    `401 authentication_failed`; the unit never signs. It passed while the peer was more permissive
    and has been red since the §5.5a/§6.2 authority work landed under it.
  **Enforcement is the sweep — there is no static form of this.** A stale unit compiles, runs, and
  reports a confident failure about the wrong thing. What made both diagnosable in minutes was
  reading the peer's OWN call site for the function under test and comparing argument shapes, and, for
  `sql`, **printing the disposition CODE next to the status**: `401` is nine different sites in that
  file and `401 authentication_failed` is one. **A gate line that prints only a status is a gate line
  that will be misread** — the code costs one field and names the branch.
