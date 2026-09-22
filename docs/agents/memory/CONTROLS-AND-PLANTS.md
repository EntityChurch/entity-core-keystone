# Controls and plants — keystone memory

Why a green gate may have measured nothing: vacuous checks, inert controls, plant discipline, and probe design.

**Arrive here when:** a gate or test passes and you are not sure it asked anything.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- A WIRE PROBE FAILS IN THE DIRECTION OF THE ANSWER IT IS LOOKING FOR — so a probe without a CONTROL is not a measurement, it is a rumour with a number attached
- A §4.11 TEST WITH NO READ DEADLINE HANGS ON THE PLANT INSTEAD OF FAILING — because the non-conformant behaviour IS "no response"
- A GATE'S OWN TIGHTENING CAN GO BLIND, IN THE DIRECTION NOBODY RE-CHECKS — DIFF THE HIT LIST ACROSS EVERY CHANGE TO A DETECTOR
- RATIFIED — AN "ALREADY SATISFIED" IS A MEASUREMENT AND MUST SHIP ITS EVIDENCE
- EIGHT INERT CONTROLS IN ONE SWEEP, EVERY ONE FOUND BY PLANTING AND NONE BY READING — AND ONE WAS IN THREE PEERS AT ONCE
- A PROBE COUNT IS NOT A SYMBOL COUNT, AND A DIFFERENTIAL IS SILENT ABOUT EXACTLY THE SURFACE IT DOES NOT DRIVE
- A LEAK PROBE MUST CROSS THE PUBLIC BOUNDARY ONLY — the shipped test binaries' leak output is the HARNESS's and reads exactly like the library's
- Conformance-green can be vacuous
- A PROBE THAT FORWARDS MATERIAL IT DID NOT AUTHOR MUST VERIFY THAT MATERIAL AGAINST ITS OWN KEY, OR A SLICING BUG AND A PEER DEFECT ARE THE SAME OBSERVATION
- A PREDICATE TEST BUILT ONLY FROM DENY CASES IS INDISTINGUISHABLE FROM ONE ASSERTING `False == False` — AND THE FIXTURE IS WHERE IT BREAKS, NOT THE PREDICATE
- A GATE THAT PROVES EVERY WRITE AND NEVER READS BACK THROUGH THE SURFACE UNDER TEST HAS MEASURED HALF A FEATURE — and the missing half is the half the feature is FOR
- A GATE THAT EXAMINES ZERO THINGS PRINTS THE SAME WORD AS ONE THAT EXAMINES FORTY-SIX — always print the COUNT, and assert on it in the regression suite
- A MEASUREMENT'S PRECONDITION CAN BE A LAUNCH FLAG THE WHOLE COHORT HARDCODES — and under it the probe reports the guard holding, on every peer, for a reason that has nothing to do with the guard
- A PROBE'S FAMILY CONTROL MUST VOID ITS OWN FAMILY'S ROWS, OR THE PEER THAT REFUSES EVERYTHING READS AS THE ONLY PEER THAT IMPLEMENTS THE RULE
- A PROBE WHOSE SUBJECT IS AN *UNMATCHABLE* VALUE CANNOT TELL "THE VALUE WAS READ AND MATCHED NOTHING" FROM "THE FIELD WAS NEVER READ" — EVERY SENTINEL-SHAPED CHECK NEEDS A MATCHABLE-VALUE CONTROL BESIDE IT
- A CONTROL MUST ASSERT THE PRECONDITION THE MEASUREMENT RESTS ON, NOT MERELY THAT THE STEP COMPLETED — and the cohort, not the peer, is what separates "your instrument is wrong" from "this peer is."
- RATIFIED — A CONTROL THAT CANNOT BE EXERCISED IS NOT A CONTROL, AND IT REPORTS THE SAME WORD AS ONE THAT PASSED
- FIFTH AND SIXTH OCCURRENCE OF THE EXAMINED-ZERO-THINGS CLASS, AND THE FIFTH IS THE WORST FORM: AN INCREMENTAL BUILD TOOL DOES NOT RUN THE SUITE AT ALL
- RATIFIED — A CONTROL THAT CANNOT OBSERVE THE DEFECT IS FOUND BY DESIGNING ITS PLANT, AND NOT BY RUNNING IT
- A GUARD THAT WAS NEVER EXECUTED IS NOT A GUARD — and "it's just a preflight" is exactly how one ships unrun
- A GATE'S SCOPE STATEMENT IS ITSELF UNGATED, AND IT IS THE ONE SENTENCE THAT EXEMPTS YOU FROM A CHECK

---

- **A WIRE PROBE FAILS IN THE DIRECTION OF THE ANSWER IT IS LOOKING FOR — so a probe without a
  CONTROL is not a measurement, it is a rumour with a number attached.** RATIFIED 2026-08-30
  (three independent instances in one afternoon, building `tools/p47-probe` to measure the §4.7
  pre-hello `authenticate` divergence formalization routed to us). Every one of the three would
  have produced a confident, publishable, wrong finding, and **none was visible in the output**:
  - **A placeholder `content_hash`** (33 zero bytes) is rejected under §1.8 validate-before-trust —
    and `go` reports that rejection as **`400 non_canonical_ecf`**, a bare 400 that reads exactly
    like the row-10 answer being measured. The frame was structurally perfect.
  - **`key_type` sent as the numeric §1.5 registry code** when the wire field is **text**
    (`"ed25519"`) made four peers answer `400 unsupported_key_type` — a plausible *fifth behaviour
    class*, concentrated in the hand-authored group, which is exactly where a real one would be.
  - **A `hello` with no `nonce` field** is accepted by 38 peers and rejected by three with
    **`400 connection_sequence_error`** — the precise status *and code* under measurement.
  **Two controls, and the second is the one nobody thinks to build.** (a) A *positive* control on a
  fresh connection — here a plain `hello` that MUST answer 200; if it does not, the peer's result
  is UNTRUSTED and is a probe fault, not a finding. (b) A **differential** control that supplies the
  same input in a state where the answer should differ — here `hello` *then* the same
  `authenticate`. Control (a) catches a malformed frame; only control (b) catches a frame that is
  well-formed and asks the wrong question, which is how the `key_type` class was killed.
  **And (b) paid for itself twice, because it turned out to be the actual finding.** 38 peers answer
  `401 invalid_nonce` pre-hello and **the same thing post-hello** — they never model the pre-hello
  case, they just reach the nonce check and find nothing to match. So a 38–6 "majority" is 6 peers
  that decided something and 38 that got one reading for free. **Generalize past this probe: when a
  census counts implementations agreeing, check whether the agreeing ones DECIDED — an answer
  reached by fall-through is not a vote**, and cohort weight built from it is an overclaim.
  **Enforcement:** no wire probe lands without a positive control asserted in the same run and
  recorded per-peer in its output (`trusted: false` must suppress the peer's result), plus a
  differential control wherever the input under test is a *state* rather than a *value*.

- **A §4.11 TEST WITH NO READ DEADLINE HANGS ON THE PLANT INSTEAD OF FAILING — because the
  non-conformant behaviour IS "no response".** RATIFIED 2026-09-14/15 (`ruby`, then `common-lisp`
  identically an hour later). This is the one place where the standing plant discipline turns on
  itself: the mutation that proves a §4.11 fix is *restore the silent drop*, and a reader with no
  deadline then parks forever rather than reporting red. It cost a 50-minute plant batch, an
  orphaned container, and then repeated on a second peer before it was understood.
  **Two enforcement points, and both are needed:** every wire case carries an explicit deadline with
  the reason at the site (`Timeout.timeout(5)`, `sb-ext:with-timeout`), **and** the plant RUNNER
  carries a per-plant timeout so a hang costs one plant rather than the batch.
  ⚠ **A socket option is NOT the deadline on every substrate:** Ruby's `IO#read` on a `TCPSocket`
  does **not** honour `SO_RCVTIMEO` — it retries through `EAGAIN` — so the first, obvious fix did
  nothing. Use the language's own timeout construct and verify it fires.
  *(Sub-lesson, the comment-is-code class in a FOURTH syntax: a `; PLANTED DEFECT` marker appended
  in Lisp swallowed six closing parens, and an inline marker in Ruby commented out a closing `))`.
  A plant MARKER is a mechanical edit and obeys the same rule as any other — put it where the
  language's comment ends at the newline, or on its own line, and have the runner assert the plant
  is present rather than trusting the write.)*

- **A GATE'S OWN TIGHTENING CAN GO BLIND, IN THE DIRECTION NOBODY RE-CHECKS — DIFF THE HIT LIST
  ACROSS EVERY CHANGE TO A DETECTOR.** Candidate (2026-09-14, `tools/ascii-wire-gate.py`, and the
  defect was authored by the same session that wrote the gate). The first cut returned 34 hits of
  which three were noise, so the pattern was tightened to require `token(` — an obviously-right
  repair that **silently dropped every prefix-notation peer in the cohort**, because their paren
  comes BEFORE the token: `(err 503 "…")` in common-lisp, `[err 403 …]` in tcl, `errMsg 403 "…"` in
  unison. Three peers vanished from the report; the count fell 20 → 16, **and 16 is a perfectly
  plausible number.** Caught only by comparing the hit lists before and after.
  **Two rules. (a) The discriminator belongs on POSITION, not on vocabulary** — requiring the
  offending literal to be an ARGUMENT to the emitter killed all three false positives without
  touching any syntax family, where the vocabulary constraint killed three peers to fix three lines.
  **(b) A detector's self-test needs a positive control PER SYNTAX FAMILY**, not one per defect
  class: four call shapes exist in this cohort (infix, s-expression, bracket-command, juxtaposition)
  and a suite carrying only the first would have passed the blind gate.

- **RATIFIED — AN "ALREADY SATISFIED" IS A MEASUREMENT AND MUST SHIP ITS EVIDENCE.** Across the
  0.8.2.25 sweep, two of eight rules came back *already satisfied by construction* on most peers,
  and that is the correct outcome rather than a gap — but only because each report named WHY.
  The sentinel-guard rule (F) is satisfied wherever the guard is the first arm INSIDE the single
  matcher, so every call site reaches it; it needs work only where a WRAPPER exists that some
  callers bypass, which was `lean` alone. The accepted form of the claim is **the enumerated call
  sites** (`zig` 4, `c` 1, `cpp` 1, `csharp` 7, `java` 6, `kotlin` 6), not the sentence. The
  operation-before-resource rule (G) was likewise already correct on most peers and was **pinned
  with a differential anyway** — unknown op WITH and WITHOUT a resource — so that the ordering is
  measured rather than incidental. **A rule reported as satisfied without either an enumeration or a
  test is a rule nobody checked.**

- **EIGHT INERT CONTROLS IN ONE SWEEP, EVERY ONE FOUND BY PLANTING AND NONE BY READING — AND ONE
  WAS IN THREE PEERS AT ONCE.** 2026-09-14/15. The examined-zero-things class has now caught more
  TESTS than gates, and the recurring mechanism is that **a control exercises one half of a
  two-part mechanism while its witness is decided by the other half**:
  - The RULE E control (`scope_subset` typing) was inert on `csharp`, `java` AND `kotlin`: its
    `*/apply` witnesses are decided by the SENTINEL, so mutating only the MATCHER left every
    assertion green. The witness that discriminates is child `operations: ["/x/get"]` under parent
    `["/*/get"]` — §5.4's peer-wildcard walk says TRUE, §3.6's literal matcher says FALSE, so the
    canonicalizing reading makes **a child grant wider than its parent**, which is the delegation
    widening F50 names. After the fix, frame-only and matcher-only mutations redden it
    **independently**, which is what says the two halves are separately measured.
  - The same plant BEHAVED DIFFERENTLY ON TWO PEERS FOR A REASON WORTH KNOWING: it worked on `c` and
    was partial on `cpp`, because `c`'s `ec_canonicalize` FAILS where `cpp`'s answers the sentinel.
    **A plant's adequacy is a property of the peer's error model, not of the plant.**
  - A §4.11 driver had no partial-length-prefix arm at all — its "truncated frame" case sends a
    COMPLETE 4-byte prefix, so the truncation was detected in the body read and the prefix
    discrimination had nothing driving it. The plant came back INERT and said so.
  **Enforcement, unchanged and now earning itself every session: assert the plant is PRESENT before
  the mutated run, require it to redden a NAMED case, and treat a plant that runs green as a finding
  about the TEST.** Add: when a mechanism has two halves, mutate each half separately and require
  each to redden the control alone.

- **A PROBE COUNT IS NOT A SYMBOL COUNT, AND A DIFFERENTIAL IS SILENT ABOUT EXACTLY THE SURFACE
  IT DOES NOT DRIVE.** Candidate (first occurrence, enforcement exact). `abi_differential.c`
  published **"71/71"** — since grown to 101 — as evidence that the two C-ABI codec impls are
  "interchangeable". It `dlsym`s **19** symbols; the spec declares **27**. So a symbol the two
  impls disagree about is invisible to a green run unless it happens to be one of the 19 — and
  one was: `ec_entity_original_bytes` is exported by the C impl and **has never been implemented
  in Rust** (no commit ever added it). **Say the conformance verdict precisely, because the
  flattering framing and the alarming one are both wrong:** spec §4.1 declares that symbol
  **OPTIONAL** ("MAY be provided"), so Rust is **conformant** — and it is still a footgun,
  because both impls ship the same soname and artifact name and are advertised as drop-in
  interchangeable, so a consumer that links one and swaps the other gets an unresolved symbol.
  **Enforcement: the differential now enumerates every spec-declared symbol, `dlsym`s it on
  BOTH libraries, and prints the asymmetry plus how many symbols it actually drives (19/27).**
  It **reports** rather than fails — an optional symbol present on one side is not a defect and
  hard-failing would hold the gate permanently red, the "teaches people to skip it" mode this
  file records twice. What it must never do again is stay silent. **Generalize: any harness
  that publishes a count as evidence of equivalence must also publish the SURFACE that count
  ranges over** — otherwise the number grows while the coverage does not, and nobody can tell.

- **A LEAK PROBE MUST CROSS THE PUBLIC BOUNDARY ONLY — the shipped test binaries' leak output
  is the HARNESS's and reads exactly like the library's.** Candidate, same session. The first
  ASan run of `regression_test` + `conformance_harness` reported **12 and 67 leak records at
  HEAD**, after the leak was fixed and verified — every one of them a tree the *harness* built
  directly, or the corpus it holds for the life of the process. A peer never does that: it only
  ever crosses the exported `ec_*` surface. A probe restricted to that surface reports **0**,
  and the pre-fix tree reports **141** on the same probe. **The stacks look identical** —
  `xmalloc → ev_new → …` in both cases — so the distinction is not visible in the output and
  has to be built into the driver. **Enforcement: `conformance/abi_leak_probe.c` calls only
  exported symbols, and drives MALFORMED input as well as valid** (two of the three fixed leaks
  were on decoder error paths, reachable by anyone who can send bytes and by no valid request).
  **And validate the instrument against a control before believing its result**: both the ASan
  probe and the RSS probe were run against the pre-fix tree first (141 records · 5 552
  bytes/pass) and only then against HEAD (0 · 0.00). A detector that has never fired has
  measured nothing — and the RSS instrument needed its OWN control, because the ASan control
  validates ASan and says nothing about RSS sensitivity.

- **Conformance-green can be vacuous.** A rejection-only oracle category lets a fail-closed
  peer pass without implementing the primitive — and a non-core category never gates. The
  keystone payoff is the *finding* (an untested, inconsistently-implemented core primitive)
  as much as the fix; always add an accept-path unit test in the direction the oracle can't
  cover. **Pin-scoped correction (Unison #43, 2026-07-19): `multisig` is NO LONGER the
  example.** The standing text cited it as "100% malformed→403"; at `cc1970f` the category
  ships a genuine accept vector, `valid_2of3_peer_signed_accepted`, which was a hard FAIL
  against the Unison peer until real K-of-N landed and passes after. The *lesson* stands;
  that *factual claim* is stale — do not treat a green `multisig` as automatically vacuous,
  and re-check any category's accept/reject mix against the CURRENT oracle pin before
  calling it rejection-only.

- **A PROBE THAT FORWARDS MATERIAL IT DID NOT AUTHOR MUST VERIFY THAT MATERIAL AGAINST ITS OWN KEY,
  OR A SLICING BUG AND A PEER DEFECT ARE THE SAME OBSERVATION.** Candidate (first occurrence,
  enforcement exact). `put-probe` must replay the handshake's capability material verbatim on every
  authenticated EXECUTE — §5.2 step 3 resolves the cap out of that map — so it slices raw byte spans
  out of the response rather than re-encoding a decoded structure, because a one-byte difference
  changes a content hash and an unverifiable capability looks exactly like a peer that refuses.
  **The span arithmetic is then unfalsifiable from the outside**: five peers refused or dropped the
  probe's valid `put`, and "my slicing is wrong" and "these five peers are strict" predict the
  identical output. The self-check re-decodes every forwarded entry and re-hashes its `{type, data}`
  against the map key it is filed under (§3.1 requires them equal); it reports **0 of 4 bad on every
  peer**. **Generalize: whenever a harness replays bytes it received, assert the invariant the
  sender was obliged to satisfy — the assertion costs ten lines and converts an unfalsifiable
  suspicion into a measurement.**
  **RATIFIED AND CORRECTED 2026-09-07 — this entry used to end that sentence with *"and THAT is
  what licenses reporting the five as a peer-side observation instead of a probe bug."* It licensed
  no such thing, and the five were the probe.** `authedExecute` unions the probe's own peer entity
  into the forwarded `included` map, which already contains it (the probe IS the grantee), and the
  encoder sorted map keys **without deduplicating** — so every authenticated frame carried the same
  byte-string key twice, which is not canonical ECF at all. `csharp` refused the whole frame in
  strict CTAP2 mode on **every** case including the positive control; `typescript`/`node-red`
  dropped it silently.
  **AN INVARIANT CHECK LICENSES EXACTLY THE INVARIANT IT CHECKS.** The self-check verified that
  each forwarded entry AGREES WITH its key and said nothing about the keys being UNIQUE — and the
  fault was a duplicate key. Offering a narrow check as general assurance is how a probe fault gets
  published as a cohort finding about five peers, in a document whose own section title was *"and
  the probe is not the reason"*.
  **The peer that caught it is the peer we published as broken, and its refusal named the wrong
  cause** (`400 non_canonical_ecf — "CBOR tags are forbidden"`, one code and one message standing in
  for several canonicalization branches), which is what made a fault of ours look like a defect of
  theirs wearing their own error code. **When ONE peer of a cohort refuses what the others accept,
  the prior belongs on the instrument, not on the peer** — the strict one is the one telling you
  something. **Enforcement: the encoder deduplicates by construction (a map HAS unique keys) and
  reports the dropped count per peer, so the dedup can never be silent; and a probe's diagnosis of a
  refusing peer is not final until the peer's OWN error path has been read.** It took one
  three-line stderr print in `csharp`'s decode-refusal catch to turn "these five peers are strict"
  into `CborContentException: does not support duplicate keys`.
  **And the POSITIVE control caught two probe faults before either could become a cohort finding**,
  which is the p47 lesson paying out on its second instrument: a stray decode call left the
  forwarded material silently empty (`403 capability_denied`), and then a `system/peer` entity
  carrying `peer_id` in its hashable basis produced `401 unresolvable_grantee`. **§3.5 (v7.65) says
  `peer_id` MUST NOT be in that basis; §4.6's own pseudocode still shows the pre-v7.65 three-field
  form**, and the probe had been written against the pseudocode. Both would have published as
  cohort-wide defects. **A wire probe's first two runs are about the probe.**

- **A PREDICATE TEST BUILT ONLY FROM DENY CASES IS INDISTINGUISHABLE FROM ONE ASSERTING
  `False == False` — AND THE FIXTURE IS WHERE IT BREAKS, NOT THE PREDICATE.** Candidate
  (2026-09-07, `python` H9; the examined-zero-things class reaching a *test* rather than a gate,
  and the enforcement point is exact). `check_path_permission` shipped with one accept case and
  three deny cases, one per scope dimension. The grant fixture wrapped each grant in
  `Entity.make(...).to_cbor()` where `GrantRec` reads a **plain dict**, so every scope parsed
  **empty**, the function denied everything, and **all three deny controls passed.** Only the
  accept case saw it. **Rule: every authorization/predicate test needs at least one ACCEPT
  assertion, and it is the one that validates the FIXTURE** — the deny cases validate only that
  the function can say no, which a broken fixture guarantees for free. Corollary for the deny side:
  one deny case per DIMENSION, because a single deny cannot distinguish "the predicate checks the
  dimension I care about" from "the predicate denies".
  **THE SAME SESSION'S SIBLING, and it is about the SHAPE OF THE HARNESS rather than the fixture:
  a test of "whose identity is this" must be driven from a SECOND peer, or it passes against the
  fabricated value.** H8's defect is that a tree-change event with no execution context is
  indistinguishable from an AUTONOMOUS write, so a recorder fills in `EXTENSION-HISTORY` §2.1's
  autonomous reading — author = the LOCAL peer — and attributes a remote caller's write to itself.
  On a single-peer test the caller and the local peer **are the same identity**, so the fabricated
  value and the correct value are the same bytes and every assertion passes. The test therefore
  asserts `author == initiator.identityHash` **and** `author != responder.identityHash` over real
  loopback. Generalise: **whenever the defect is a value being DEFAULTED to something plausible,
  the control is an input for which the default and the truth differ** — and if your harness cannot
  produce such an input, the harness is the thing to fix, not the assertion.
  *(Both were then planted — revert the context at the write site, reassert — and each plant
  reddened exactly its own test while leaving the companion control green. Two plants on disjoint
  checks is what says the arms are independently measured rather than one carrying the other.)*

- **A GATE THAT PROVES EVERY WRITE AND NEVER READS BACK THROUGH THE SURFACE UNDER TEST HAS MEASURED
  HALF A FEATURE — and the missing half is the half the feature is FOR.** RATIFIED 2026-09-09 (F62),
  and it is FM-1g's *"a MUST with roughly no gate"* reached from the coverage side rather than the
  spec side. `core_register_*` is **nine** checks: op status, op result, manifest at path, handler at
  path (asserting the entity's TYPE), grant at path, grant-signature at the invariant path, and the
  unregister teardown. Every one is a write. **Not one then dispatches at the pattern it just proved
  exists** — so seven peers score `778 · 0F` while answering `404 handler_not_found` at a path where
  a `system/handler` entity is provably present, which §6.6 makes a **MUST** (*"the index MUST produce
  equivalent results to the tree walk"*). The two neighbouring checks that look like they cover it are
  pointed elsewhere, verified rather than assumed: `unsupported_operation_on_registered_handler`
  targets `system/tree`, a **bootstrap** handler, and `validate_echo_dispatch` drives a built-in.
  **Enforcement, and it is a question to ask of any gate family rather than a grep: list what the
  checks ASSERT and sort them into writes and reads. A family that is all writes is a family that has
  never used the thing it built.** The read-back is usually one line at the end of the gate that
  already holds the pattern, the grant and the connection.

- **A GATE THAT EXAMINES ZERO THINGS PRINTS THE SAME WORD AS ONE THAT EXAMINES FORTY-SIX —
  always print the COUNT, and assert on it in the regression suite.** RATIFIED 2026-08-30
  (second occurrence of the vacuous-control class after `check-set-gate`'s `Path.stem`
  collision, which keyed 45 reports into one dict entry and would have "passed" having read a
  single file). Building `tools/coherence-gate.py`, its per-peer banner check searched for the
  compact `NNNP/NNW/NF/NNNS` form; the banners spell the same figures longhand
  (`755 total · 312 pass · 337 warn · 0 FAIL · 106 skip`), so the pattern matched **nothing**,
  every peer was `continue`d, and the gate printed *"OK — 46 §1 rows and **0** peer banners
  agree"*. **The only reason it was caught is that the line printed the number.** Reading the
  code would not have found it; the code is correct, it is the pattern that was wrong.
  **Enforcement, and it is one line in the self-test:** assert the count equals the population
  (`n_banners == len(peers)`), not merely that the error list is empty. An empty error list is
  the expected output of both a passing check and an absent one.
  **THIRD AND FOURTH OCCURRENCE 2026-09-02, both in PEER GATES rather than repo tooling, and the
  fix is the same one line in each.** `swift/run-s2.sh` ran `swift test` and trusted its exit
  code, which is 0 for a suite that executed 35 cases and for one that executed none — a dropped
  test file or a mis-declared target leaves it green. `smalltalk`'s `st_suite` grepped
  `failures=0 errors=0`, and an **empty** SUnit suite reports exactly that (`runs=0 passes=0
  failures=0 errors=0`), so a `buildSuite` over a class whose methods failed to compile passes
  perfectly. Both now assert the count — an XCTest floor (`SWIFT_TEST_FLOOR`, currently 35) and
  `runs=[1-9]` — and both were regression-tested by planting: floor raised above reality → exit 1;
  a synthetic `runs=0` line → rejected by the new pattern and accepted by the old one.
  **Generalise to every peer gate, not just the repo's own tooling: if a gate's success message
  does not contain a number, it cannot distinguish "all green" from "nothing ran."**
  **FIFTH, SIXTH AND SEVENTH OCCURRENCE 2026-09-09 — IN THE SAME FILE AS THE FOURTH, AND THE FIX
  FOR THE FOURTH DESCRIBES THEM IN ITS OWN COMMENT.** `smalltalk`'s `sunit` was fixed on 2026-09-02
  and its comment says, in these words, that *"`pharo eval` exits 0 whatever the suite reports, so a
  red suite printed `failures=3` and the target passed."* **Three sibling targets in the same
  Makefile had the identical defect and kept it**: `conformance`, `int-boundary` and `crypto-accept`
  each END by printing their own verdict (`=== crypto-accept: FAILED (1) ===`) and **nothing read
  it** — so three of the four members of that peer's own `gate` target could not go red. Measured
  rather than reasoned about: a planted bad SHA-256 KAT made the driver print `FAILED (1)` while
  `make crypto-accept` exited **0**.
  **This is the standing "harden one anchor, check its siblings the SAME DAY" rule failing at the
  shortest possible distance — the siblings were adjacent recipes in the file being edited — and
  what makes it worth a numbered entry is that the fix WROTE DOWN the class and still did not
  sweep it.** A comment explaining why a gate was unsound is a description of a defect class, not a
  record that the class was eliminated; the next reader (me) treated it as the latter for a week.
  **Enforcement, and it is a question rather than a grep: when a gate is fixed, list every OTHER
  target in the same file that ends in the same runner and check each one's exit path.** Corollary
  learned in the doing: **assert the GREEN verdict positively, never the absence of `FAILED`** —
  absence is a property of your pattern, presence is a property of the run, and a driver that dies
  midway or is renamed out from under the recipe prints neither word. Two of the six targets
  (`multisig-accept`, `selftest`) were deliberately left unwrapped because they already `Error
  signal:` on failure — **checked, not assumed**, because wrapping them would be a second control
  on one property while leaving them unchecked would have been the same mistake again.
  *(Adjacent, and the same session: a DETECTOR needs the same scepticism as a gate. A probe
  grepping its run log for `panic` reported **30 aborts in 30 clean runs**, because the oracle's
  `agility_decode_1` line contains the word in its own DESCRIPTION — "accepts key_type=0xFE
  without panic/hardcode-reject". **Scope a detector to the region that can contain the signal**
  — here the peer-stderr section, not the whole log — and treat a detector that fires on every
  sample exactly like one that fires on none: neither has measured anything.)*
  **The gate this came from is worth its own note, because it closes a hole the other five
  structurally cannot see.** `check-set-gate` asks whether numbers are COMPARABLE, `pin-gate`
  whether anchors RESOLVE, `link-gate` whether links reach real FILES — **all three pass a tree
  in which §1 publishes `595P/54W` for a peer whose own committed report says `313P/336W`.**
  Every documentation defect found in the two weeks before it existed was found by hand-walking
  the tree with `make lint` green throughout. It gates the 46 §1 rows and the 46 per-peer prose
  banners against the committed reports, and **reports rather than gates** superseded figures
  quoted elsewhere — this repo keeps those on purpose (footnote ⁷ preserves a peer's whole
  FAIL-count progression because the sequence is the finding), and hard-failing them would hold
  the gate permanently red, which is the "teaches people to skip it" failure written down twice
  already.
  **AND THE FIRST THING IT FOUND WAS OUR OWN, EIGHT DAYS STALE: 13 published banners were still
  anchored on a dead dev SHA.** `status-banner.py` was built on 2026-08-28 specifically so a
  per-peer number would cite the **content digest** rather than the oracle's commit ([ADR-0012]
  Am. 1) — and this file already records that *"the 2026-08-22 hand pass wrote `oracle
  entity-core-go @ c1b0708` into all thirteen; generating the banner is what stopped that
  reaching the other twenty-six."* **What it does not say, because nobody checked, is that the
  original thirteen were never regenerated.** They still named `c1b0708` — a `dev` commit that
  resolves for no outside reader — in files that **publish** (`protocol-generator/**` sits
  outside every doc-root prefix and ships with no declaration). `pin-gate` did not see them: it
  is scoped to §1's pin column and `oracle-pin.env`, not to per-peer status files.
  **This is the standing "when you build a durable anchor, apply it to the history you already
  have, not only to the next entry" rule failing again, in the same shape as the unrecorded
  `retired_ref*` digests** — a tool that prevents the defect going forward is not a fix for the
  instances already on disk, and nothing was watching them. All 46 are now digest-form, and
  `coherence-gate` fails on any banner citing an oracle commit, with a planted-defect test.
  **Generalize: after landing a generator that fixes a class, grep the tree for the class and
  count. If the count is not zero, the fix has not landed — it has only been scheduled.**
  **And one check was CUT rather than shipped noisy, which is the part to imitate.** The
  handoff asked for "flag a `§N` reference with no matching heading in the same file", and it
  sounds mechanical. It is not: there is **no textual discriminator between `§5` meaning *this
  file's* §5 and `§5` meaning the *spec's* §5**, and resolving against the pinned spec does not
  help because the spec has a §5. The heuristic that works on `CONFORMANCE-MATRIX.md` (whose
  own numbering, §1–§4, happens not to collide with the spec refs it makes at §5–§7b) produced
  **124 false positives and 0 true positives** across the tree, because a peer's `PHASE-S5.md`
  has a `## 7.` section and cites the spec's §7a/§7b. It is now scoped to three files with the
  fragility stated in the source. **A check that cannot separate its signal from its noise is
  not a weak check, it is a broken one** — scope it or drop it, and say which.

- **A MEASUREMENT'S PRECONDITION CAN BE A LAUNCH FLAG THE WHOLE COHORT HARDCODES — and under it the
  probe reports the guard holding, on every peer, for a reason that has nothing to do with the guard.**
  RATIFIED 2026-09-10 (`tools/f68-probe`, answering arch's F68 ask). **Every `run-s4.sh` in the cohort
  launches its peer with `--debug-open-grants`** — the degenerate `default -> *` seed policy — under
  which nothing is outside the caller's grant, so an AUTHORIZATION-BYPASS probe has nothing to bypass
  and every peer answers "refused" correctly and vacuously. This is the examined-zero-things class
  reaching the SUBJECT rather than the instrument: the probe is fine, the gate is fine, the *world the
  peer was started in* cannot contain the phenomenon. **Enforcement, and it is the antecedent control
  generalized: for any probe that measures whether a guard holds, the same request WITHOUT the bypass
  must be REFUSED in the same run, asserted per peer.** If it is not refused, the run is `VOID` rather
  than green — a deny-only probe on an authorization surface measures nothing, which is the objection
  this seat filed against another repo's check the day before and would have repeated here. The fix is
  to drive the peer's OWN harness with exactly the one flag removed (`tools/f68-probe/run.sh`), never a
  hand-rolled launch — the standing "compare against the harness the number actually came from" rule.
  **AND TWO PEERS REFUSING DOES NOT MEAN THE DEFECT IS ABSENT — ASK WHICH RUNG REFUSED.** Measured: all
  five backends skip a caller-excluded target identically, and `csharp`/`typescript` are saved by a
  **second, independent authorization site** in the tree handler that re-authorizes the path it is about
  to act on. The *messages* are what separate them (`Dispatcher.cs:164` "does not grant the operation"
  vs `TreeHandler.cs:96` "does not cover path"); the statuses are identical. This is the standing TWO
  SITES FOR ONE REFUSAL rule moved from the FIX side to the CENSUS side — there a repair went to the
  unreachable site, here a census would have recorded two peers as not having a defect they all have.
  **A green row on a bypass probe is a claim about a rung, so name the rung.**
  **And the discriminator was a DEAD GUARD**: `python` has that same function, unit-tested, and calls it
  **from nowhere** — the H5 dead-map shape, and the single reason `python` reproduces and `typescript`
  does not. `git grep` the call sites of any function a peer's safety rests on; a definition plus a test
  is not a dispatch path.

- **A PROBE'S FAMILY CONTROL MUST VOID ITS OWN FAMILY'S ROWS, OR THE PEER THAT REFUSES EVERYTHING
  READS AS THE ONLY PEER THAT IMPLEMENTS THE RULE.** RATIFIED 2026-09-14 (`tools/arc-probe`), and it
  is the examined-zero-things class reaching a SIBLING ROW rather than a gate. Five peers
  (`asm-x86_64` `asm-arm64` `riscv64` `sql` `wasm-wat`) refuse **every** `system/capability:request`,
  so their `403` on a mistyped scope graded as conformance and they printed as *the only five peers
  in the cohort enforcing the clause*. They refuse the **well-typed control identically**. Ungraded,
  that publishes `5 of 43` where the truth is `0`, in the flattering direction nobody re-checks.
  **A row cannot see its siblings, so the voiding cannot live in the per-row grader** — it is a
  post-pass over the assembled report, keyed on the family's own control, and `VOID` is its own
  state, never folded into "owed" (a peer whose control failed is unmeasured, not defective).
  **Two more grading defects from the same instrument, both found by the cohort rather than by
  reading, and both would have published a wrong claim:**
  - **GRADING A PEER NON-CONFORMANT FOR DOING WHAT THE REVISION RECOMMENDS.** `0.8.2.20`'s own
    comment says the diagnostic it removed from `canonicalize` *"belongs at admission (§6.5), which
    has a caller to answer"* — so the five peers that refuse a malformed path with a `400` at
    admission are doing exactly what it points at, and the first cut scored them `no`. **What a rule
    forbids and what it RECOMMENDS are different branches; a check that collapses them reddens the
    peers that read the text most carefully.** Read the revision's rationale, not only its MUST.
  - **A REFUSAL ON AN ADDRESS WITH NOTHING BEHIND IT IS A MISS, NOT A MECHANISM.** The capability
    arm points at a key holding nothing, so a key-TRUSTING peer misses exactly as a key-DISCARDING
    one does. Only the arm where the entity IS present at the wrong address discriminates. Reading
    the first arm's `403` as evidence of mechanism (b) is a claim the measurement cannot make, and
    six peers would have carried it. **Before attributing a mechanism to a refusal, ask what the
    WRONG implementation would have answered to the same input.**
  *(And the runner had a guard that COULD NOT EXECUTE, which is the standing never-executed-guard
  rule in a new shape: the guard was unreachable because the condition it guards against killed the
  script one line earlier. The image-name pattern `[a-z0-9.-]` omits `_`, so `asm-x86_64-toolchain`
  never matched, `grep` exited 1, and under `set -o pipefail` the ASSIGNMENT failed — `set -e` then
  killed the run **before** the `[ -n "$img" ]` guard written to report exactly that. The roster
  stopped at peer 29 and took the 17 behind it with it, leaving a bare non-zero exit as the only
  trace. Two fixes and both are general: **capture with `|| true` so the explicit guard is the thing
  that reports**, and **a roster loop must record a failing member and CONTINUE** — a run that stops
  at 29 of 46 and names nothing is worse than one that names one skip. `f68-probe`'s runner had
  carried the identical defect latent since it was written; fixed the same day, which is the standing
  harden-one-anchor-check-its-siblings rule actually being honoured for once.)*

- **A PROBE WHOSE SUBJECT IS AN *UNMATCHABLE* VALUE CANNOT TELL "THE VALUE WAS READ AND MATCHED
  NOTHING" FROM "THE FIELD WAS NEVER READ" — EVERY SENTINEL-SHAPED CHECK NEEDS A MATCHABLE-VALUE
  CONTROL BESIDE IT.** RATIFIED 2026-09-14 (`tools/arc-probe` `E2`), and it is the standing
  *"a wire probe fails in the direction of the answer it is looking for"* rule reaching a case
  where the probe was **right about its own question and silent about a bigger one**. `E1` mints a
  capability whose `resources.exclude` is `../nope` — the §5.4 sentinel — and asks whether the peer
  honours the grant anyway. A peer that reads grant excludes and finds the sentinel carves out
  nothing answers `200`; **a peer that never reads the exclude field at all answers `200`.** Same
  status, same code, two defects an order of magnitude apart, and the report's own prose
  (*"the exclude carved out nothing"*) asserted the half it could not see.
  **The control is one case and it is obvious once stated: exclude the VERY TARGET being requested**,
  which any exclude-reading peer must refuse. Measured: **40 of 44 answer `403`; four answer `200` —
  `asm-arm64` `asm-x86_64` `riscv64` `wasm-wat` — and on those four a capability's `exclude` has no
  effect at dispatch on ANY dimension**, so an attenuated capability is honoured as if unattenuated.
  `grant_scope_ok` tests `include` for all four dimensions and the string `exclude` does not occur in
  it. **They are exactly the four HAND-AUTHORED peers**, which is this file's own rule that a cohort
  defect about EFFORT distributes by authoring cost rather than by substrate — the same four that
  deferred the §5.5 chain walk.
  **Enforcement: for any check whose input is a value chosen because it matches NOTHING, a sibling
  case must supply a value chosen because it matches EVERYTHING the subject covers, and the family
  verdict must say outright when the first is unreadable because of the second.** Generalize past
  excludes: the same hole exists for any probe built on an empty set, a no-op pattern, or an absent
  optional — *"the peer processed it and it did nothing"* and *"the peer never looked"* are the same
  observation without a positive twin.
  *(And the measurement was blocked first by a SETUP question worth recording: seven peers reported
  the whole family VOID because they refuse `system/capability:request` under the §6.9a discovery
  floor, so nothing could be minted to test with. The probe runner removes `--debug-open-grants` for
  a reason that is about the **caller's** grant — under `default → *` there is nothing to bypass —
  and **that reasoning does not transfer to a family whose subject is a token the probe MINTS during
  the run**: widening the caller's floor decides only whether the mint is permitted, and cannot make
  a narrowed cap's own exclude look enforced when it is not. `tools/arc-probe/run-mint-floor.sh`
  drives the peer's UNMODIFIED harness and says in its header that only that family may be read out
  of it. **Before concluding a family is unmeasurable, ask whether the precondition that blocks it is
  a property of the SUBJECT or of the setup** — five of the seven were the setup.)*

- **A CONTROL MUST ASSERT THE PRECONDITION THE MEASUREMENT RESTS ON, NOT MERELY THAT THE STEP
  COMPLETED — and the cohort, not the peer, is what separates "your instrument is wrong" from "this
  peer is."** RATIFIED 2026-09-09, building `tools/host-seam-probe` for the H1 dispatch census
  (`shared/findings/host-seam-dispatch-wire-census.md`). Its first run reported `go` —
  which demonstrably HAS an entity-native evaluator — as having none. The probe had encoded the
  register-request's `manifest` as a full **entity** (`{type, data, content_hash}`) where the oracle's
  own `RegisterRequestData` carries it as a **bare map**; `MapField(manifest, "expression_path")`
  therefore read the entity's top level, found nothing, and the peer **bound a handler with no body
  reference while still answering 200**. Left unfixed the roster run would have published **all 46
  peers as non-hosts** — a cohort-wide finding, entirely ours.
  **The LANDED control existed and passed.** It asserted *"was something bound"* (200 at the pattern)
  when the measurement depended on *"does what was bound carry `expression_path`"*. Widening that one
  control named the fault in a single run. **Rule: for each step a measurement depends on, the control
  asserts the FIELD, not the status.** This is the standing examined-zero-things class one level in: a
  control can execute, pass, and check the wrong proposition.
  **Second half, and it is a rule about VERDICT DESIGN: where a single peer cannot distinguish "this
  peer is broken" from "our request was", the verdict must say so and defer to the cohort.** Ten peers
  bound a handler with no `expression_path`; from any one of them that is indistinguishable from the
  bug above. It is resolved by 26 peers having persisted the *identical* request — so the verdict is
  `REGISTER-DROPPED-EXPRESSION-PATH` with its resolution rule in the text, never `CONTROL-FAILED`
  (which blames us for a peer property) and never a flat defect claim (which overclaims from one
  observation). **And order the arms by which control is more fundamental**: `wasm-wat` both drops the
  path AND fails the differential, and reporting only the first implies its row becomes readable once
  the drop is fixed. It does not.
  **Calibration, recorded with the same weight as a catch:** a source trace of all 46 dispatch sites,
  made BEFORE the probe existed, predicted the binary question — does this peer evaluate an installed
  body — **correctly for 46 of 46**, sets identical peer for peer. The read was not wrong and the
  measurement was still necessary: only the wire produced the **three-way split** among the 20
  (reference dropped at register · bound but unresolvable · bound with no evaluator), which are three
  different repairs and are invisible in a read of the dispatch site. **A source read is not worthless
  because it is not a claim — it is a hypothesis worth stating precisely so a probe can confirm or
  refute it.**

- **RATIFIED — A CONTROL THAT CANNOT BE EXERCISED IS NOT A CONTROL, AND IT REPORTS THE SAME WORD AS
  ONE THAT PASSED.** Two occurrences in one session (2026-09-03), different mechanisms, and both
  produced a confident green from a plant that had never been applied:
  - **The mutation never landed.** A `sed -i 's|…ec_ed25519_sign(...)…|…|'` meant to corrupt a
    request signature died with ``unknown option to `s'`` (the pattern contained `||`), left the
    source UNMUTATED, and the run printed PASS. Caught only because the plant COUNT was checked
    (`grep -c 'PLANTED DEFECT'`) before the result was believed.
  - **The mutation could not reach the code.** `PROOF_FLOOR=99` against a harness that re-execs into
    its container, which did not forward the variable. The floor check ran at its default and
    passed. The gate was fine; the control was inert.
  **Enforcement, and it is one line each: assert that the plant is PRESENT before running the
  mutated case, and prefer a mutation applied by a tool that fails loudly** (python with the anchor
  asserted, not `sed`). For any control that crosses a container boundary, forward the variable
  explicitly and prove it arrived. This is the examined-zero-things class pointed at the regression
  suite instead of at the gate — and a regression suite is exactly where nobody looks for it.
  **THIRD OCCURRENCE 2026-09-04, and it inverts the second: FORWARDING A VARIABLE EXPLICITLY IS NOT
  NEUTRAL — an explicit `-e VAR=<default>` OVERRIDES the callee's own default, so a wrapper that
  "just passes things through" silently decides them.** The rule above says to forward a variable
  explicitly and prove it arrived. `cobol`'s `run-s4-host.sh` — the capped, documented, human-facing
  launcher, and the only `run-s4-host.sh` in the cohort — did forward it, as
  `-e "VALIDATE=${VALIDATE:-0}"`, against `run-s4.sh`'s own `${VALIDATE:-1}`. It arrived. It was
  wrong. **Measured: the documented by-hand entry point reports `312P/337W/0F/109S` and
  `Result: FAIL (un-allowlisted skips)` while the census reports the committed `315P/337W/0F/106S`**
  — the three are `t1_2_concurrent_reentry`, `handlers/validate_echo_dispatch` and
  `origination/dispatch_outbound_reentry`, each SKIPping with *"target peer not run with
  --validate"*. Nothing was wrong with the peer and nothing was wrong with the census. **The two
  entry points disagreed, and the one that was wrong is the one no cohort runner exercises** — the
  standing "an axis's per-peer gates rot exactly where no cohort runner reaches" rule, reaching a
  *wrapper* rather than a gate. It cost the first hour of the session: the baseline looked like a
  three-check regression against the committed report, which is the most alarming thing a baseline
  can do. **Enforcement: a wrapper that forwards `VAR=${VAR:-X}` must use the same `X` the callee
  does, or it is setting policy rather than forwarding.** `grep -n '\-e "[A-Z_]*=\${' ` over any
  launcher and diff each default against the script it invokes; and if a peer has a second entry
  point, run BOTH before trusting either — a baseline that disagrees with the committed report is
  more often the invocation than the peer.

- **FIFTH AND SIXTH OCCURRENCE OF THE EXAMINED-ZERO-THINGS CLASS, AND THE FIFTH IS THE WORST FORM:
  AN INCREMENTAL BUILD TOOL DOES NOT RUN THE SUITE AT ALL.** RATIFIED 2026-09-02. `kotlin`'s S2
  gate was `gradle test --offline` and nothing else. Gradle's entire design is to skip work it
  believes current, so on **every invocation after the first**, sources unchanged, it prints
  `> Task :test UP-TO-DATE` / `BUILD SUCCESSFUL` and exits 0 having executed **zero** tests.
  Measured by running it twice. That is a step below `swift`/`smalltalk`, which at least invoked a
  runner that reported nothing. **Two changes and both are needed:** `--rerun` (task-scoped, so
  compilation still caches) forces execution, and a COUNT parsed from the JUnit XML is asserted
  against a floor — `--rerun` alone still passes a suite that silently lost its test classes, and
  the results directory is deleted first so a stale XML cannot satisfy the floor.
  **`java` is the sibling and needed the same floor for a different reason:** `mvn -o clean test`
  recompiles every time so there is no UP-TO-DATE hazard, but surefire PRINTS `Tests run: 16` and
  nothing asserts it, and **Maven exits 0 when it finds no tests at all**. So the scoping rule is
  not *"does the gate compare a number"* — it is ***which gates delegate to a tool that can
  succeed having run nothing***. Four found so far (Gradle, Maven, `swift test`, SUnit); all four
  are closed.
  **THE PLANTED FLOOR CAUGHT THE COUNTER ITSELF BEING VACUOUS, WHICH IS THE ARGUMENT FOR PLANTING
  IN ONE LINE.** `java`'s first cut ran `podman run … python3 - "$FLOOR"` with the script on a
  heredoc, and **`podman run` does not forward stdin without `-i`** — python read an empty script,
  printed nothing, exited 0. The counter written to prevent a vacuous gate WAS one, it looked
  correct on the page, and only a floor set above reality showed it. *(Sub-lesson for the survey
  side: my heuristic for "which of the other 44 gates assert a count" **mis-binned `smalltalk`**,
  whose assertion lives in the peer's `Makefile`, not in `run-s2.sh`. A survey that reads one
  conventional file cannot see a gate that delegates — do not publish a count from it.)*

- **RATIFIED — A CONTROL THAT CANNOT OBSERVE THE DEFECT IS FOUND BY DESIGNING ITS PLANT, AND NOT BY
  RUNNING IT.** 2026-09-13, building the peer contract suite; the fourth member of the inert-control
  class (after the `sed` plant that never applied, the variable that never crossed the container, and
  the H6 plant whose two budget sources were equal). `install.evaluator/literal-floor-first` asserts the
  built-in `compute/literal` floor answers before an installed evaluator — and the fixture evaluator
  answered **only its own expression type**, so a peer that consulted it first would still have been
  answered by the floor and passed. Nothing about any run could show that: the suite was 47/47 green on
  its first execution. Writing the plant (*move the evaluator before the floor*) made it obvious the
  plant could not redden the case; the fixture now claims `compute/literal` too, and the plant is
  caught. **Enforcement: every driver requirement lists a control case (`report.py --check` refuses one
  that does not), and every control has a plant in `contract/plants.json` naming it — a control with
  no plant is a control nobody has shown can fail.** Corollary worth its own line: **a first run that is
  all green is the moment to plant, not to publish** — this repo's "a batch in which every member passes
  is a claim to distrust" rule, applied to a suite on its own first day.

- **A GUARD THAT WAS NEVER EXECUTED IS NOT A GUARD — and "it's just a preflight" is exactly how
  one ships unrun.** Candidate (first occurrence here, but it is the `check-set-gate --tracked`
  shape again: a control that watches the wrong copy). The 2026-08-23 release sweep added an
  oracle-existence preflight to `run-s4.sh` to fix a real defect (a missing oracle exited 0,
  so the documented Quick-start appeared to succeed while validating nothing). The guard tests
  `[ -x "$ORACLE" ]` on the **host**, but `$ORACLE` is a **container** path (`/work/...`, the
  repo root's mount point) — so it can never pass. **Every one of the 33 peers carrying it in
  that form exited 3 on the documented entry point**, from the day it landed until 2026-08-27,
  *(Sub-lesson from the same session, cheap and general: **a mechanical rewriter that cannot
  tell code from commentary must be scoped to the files it was asked about and must skip
  comment lines outright.** A `dnf install` canonicaliser run fleet-wide reflowed the words
  "dnf install erlang" out of a PROSE SENTENCE in `containers/beam/`, destroying the comment —
  it matched text, not a command. Anchor such patterns to the start of a line, exclude `#`
  lines, and pass an explicit target list rather than globbing the tree.)*
  and the same sweep **missed 5 peers** (`datalog io pd prolog sql`) which kept the original
  silent-false-green. Only the 8 that re-exec into the container before the guard runs, plus
  `unison` (which derives a host path), were correct. **Rule: a guard added across N files must
  be executed on at least one of them before the commit lands** — the fix is one `case` mapping
  `/work/*` back to the repo root, and five minutes of running it would have caught all 33.

- **A GATE'S SCOPE STATEMENT IS ITSELF UNGATED, AND IT IS THE ONE SENTENCE THAT EXEMPTS YOU
  FROM A CHECK — so it rots in the direction of "this does not apply to me".** Candidate
  (2026-09-17, found by hand while adopting the doc standard, with all thirteen gates green).
  `AGENTS.md` carried *"`coherence-gate` check 6 gates pin PARAGRAPHS in published prose;
  `AGENTS.md` is not a published surface and is not in its scope."* **Both clauses were false.**
  `AGENTS.md` is declared in `CANONICAL-DOCS.toml`, ships on public `master` (verified by cloning
  it), and does not appear in `PIN_EXEMPT` — so check 6 had been gating that file from the day it
  landed, and the sentence asserting otherwise was written in the file it was wrong about.
  **This is the pin-paragraph class with the subject changed from a NUMBER to a SCOPE, and the
  new half is why nobody re-reads it.** A stale pin sentence is at least adjacent to a number
  somebody re-measures. A stale *scope* sentence is an **exculpation** — it says a check does not
  reach here — and the standing rule already ratified for those holds: *a row that explains why
  something need not be measured is read once and never again, which is exactly backwards from
  how often each is wrong.*
  **Enforcement, and it is a reading rule because the alternative is a gate on prose about
  gates: a claim about a check's scope cites the check's own exemption list, by symbol.** Ours
  now names `PIN_EXEMPT` and enumerates it, so the next reader diffs a list instead of trusting
  a sentence — and the enumeration is short enough to check in one `grep`. Generalise past
  `coherence-gate`: **never write "X is not in scope" without naming the variable that decides
  it**, and when you find such a sentence, resolve it from the source rather than from the
  sentence's plausibility. The tell is that this one had survived every gate, every release
  sweep and every ratchet pass, because no instrument in the repo reads prose about instruments.
