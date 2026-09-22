# Wire and codec — keystone memory

Canonical ECF, framing, refusal dispositions, the put-admission path, the type registry, and the codec C-ABI.

**Arrive here when:** a peer drops a frame, answers the wrong status or code, stores something it should have refused, or two codec implementations disagree.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- No platform CBOR lib suffices for canonical ECF
- Integer head-form is a fixed-width artifact, not a protocol property
- RATIFIED, cohort-wide, first landed 2026-08-21 in all five M1 peers: §6.3's rejection is a STATUS, not silence — "Rejection returns `400 non_canonical_ecf`" is the second half of the sentence and every peer was ignoring it
- AN OP LADDER THAT DISPATCHES ON LENGTH MUST FALL THROUGH TO THE UNKNOWN-OP ANSWER, NEVER TO `return` — and a §4.9(c) silent drop bills the CALLER, so it presents as the peer being slow or under-resourced rather than wrong
- A FIXED BUFFER FILLED FROM WIRE DATA WITHOUT A SIZE TEST IS A REMOTELY-TRIGGERABLE PROCESS KILL, AND HARDENED libc MAKES IT LOOK LIKE A CRASH WITH NO CAUSE
- A REFUSAL IMPLEMENTED AT THE WRONG LAYER cascades exactly like a crash — and reads like one
- Type registry: render natively, don't ingest bytes
- A RETURN TYPE THAT COLLAPSES N EVENTS THE SPEC ANSWERS N WAYS CANNOT BE MADE CONFORMANT DOWNSTREAM, HOWEVER THE LOOP IS WRITTEN — fix the signature, not the caller
- FFI shared-lib gotchas
- WHICH `ec_content_hash` DID YOU JUST TEST? LINK ORDER DECIDES WHICH SYMBOL WINS, AND A DIFFERENTIAL AGAINST "the same `.so`" IS WORTHLESS IF THE PEER DOES NOT CALL THAT `.so`
- A SHARED LIBRARY'S LIFETIME ASSUMPTION IS PART OF ITS ABI, AND "the process exits" IS AN ASSUMPTION ABOUT THE CALLER THAT NO CALLER IS TOLD ABOUT
- THE ECF CORPUS'S `map_keys` VECTORS ARE ALL `encode_equal` — THE S2 AXIS TESTS THE ENCODER'S KEY ORDERING AND SAYS NOTHING ABOUT DECODE-SIDE REJECTION, AND A PEER CAN BE 71/71 WHILE ACCEPTING NON-CANONICAL BYTES ON THE WIRE
- AN ACCEPT-SIDE RULE IS NEW IMPLEMENTATION ON EVERY PEER, AND THE PEERS WHOSE `put` "WORKED" WERE THE ONES AUTHORING THE SUBMITTER'S CONTENT
- WHEN A PEER ALREADY HAS A FAILURE FLAG, ITS FAILURE SET IS NOT THE SPEC'S — mapping the whole flag to a new sentinel imports every refusal the peer happens to bundle into it
- A REFUSAL REACHED BY `throw` INTO A GENERIC CATCH IS NOT THE REFUSAL THE SOURCE APPEARS TO STATE — and the clause that states it can be DEAD CODE that has never once run
- A REFUSAL THAT EXISTS BUT CANNOT BE REACHED IS A §4.9(c) SILENT DROP — check that the answer path is REACHABLE, not just present
- THE §2.4a NEGATIVE HALF NEEDS A CONSTRUCTOR, NOT AN ASSERTION — a refusal observed through the raw primitive is the bypass the rule exists to forbid
- TWO SITES FOR ONE REFUSAL, AND ONLY THE ONE THAT RUNS FIRST IS OBSERVABLE — so correcting the other is a measurable NO-OP that reads as "the fix did not work."

---

- **No platform CBOR lib suffices for canonical ECF** (incl. Rust `ciborium`, .NET
  `System.Formats.Cbor`): every peer hand-rolls the shortest-float ladder + recursive
  major-type-6 tag-reject + length-then-lex key sort on top. This is why a from-spec C codec
  is reasonable, and why the FFI layer exists.

- **Integer head-form is a fixed-width artifact, not a protocol property.** Branch the
  profile by language class: fixed-width ints (OCaml int63 / C# ulong / TS bigint / Zig u64)
  must carry the head form + self-test `[2⁶³, 2⁶⁴−1]`; bignum languages
  (Elixir/Python/Ruby/Lisp/Haskell) carry the full range free.

- **RATIFIED, cohort-wide, first landed 2026-08-21 in all five M1 peers: §6.3's rejection is a
  STATUS, not silence — "Rejection returns `400 non_canonical_ecf`" is the second half of the
  sentence and every peer was ignoring it.** `ENTITY-CBOR-ENCODING.md` §6.3 says implementations
  MUST reject a frame carrying a CBOR tag in a data field **and** that "Rejection returns
  `400 non_canonical_ecf`". Every M1 peer did the first half and dropped the frame on the floor for
  the second — `continue` (go, ocaml), a logged skip (haskell), `break`/close (swift), or a `none`
  that ended the read loop (lean). §4.9(c) deliver-or-signal says the same thing from the other
  direction. **Three distinct symptoms, one rule:** (a) the sender blocks until its own timeout, so
  a refusal is indistinguishable from a dead peer — 60 s of go's CAP-6a check was three of these;
  (b) the CAP-6a `ingest_rejects_unrepresentable_expiry` check scores it WARN, because a
  transport-level drop is a refusal but not the §5.2 disposition; (c) on a peer that *closes*
  instead of dropping it takes the whole connection with it — **that is where lean's 81 cascade
  FAILs came from.** *(The bignum shape can only reach a peer as a major-type-6 tag, so this is the
  only way CAP-6a's `>2^64` half is reachable at all.)*
  **Implementation shape, identical in all five:** keep the strict decoder byte-unchanged, add a
  salvage decode that yields/unwraps the tag instead of erroring, use it ONLY to recover
  `request_id`, answer 400, and keep serving. The frame is still rejected — no entity is built,
  nothing stored, the tag never interpreted — so §6.3's MUST NOT strip / preserve / interpret all
  still hold, and the `tag_reject` wire-conformance vectors keep their meaning because the
  ingestion path never sees the flag. **Enforcement:** grep each peer's read loop for a decode
  failure that neither responds nor is EOF — `envelopeOf*`/`decodeEnvelope` returning
  none/err with no `writeFramed` on that branch is the defect. Check the *reference* peer when
  unsure: `entity-peer` answers this check 6/6 in 1 ms.
  **THE §6.3 FIX CAN PRODUCE THE CASCADE IT EXISTS TO REMOVE, and it presents as a catastrophic
  regression.** `zig`'s first measurement after the fix came back **755 · 89F** — worse than the 3F
  it started at. `wire.makeResponse` CONSUMES its `result` entity and deinits it; the new
  `rejectFrame` also deferred a deinit on the same entity, so *answering* a rejected frame
  double-freed and killed the connection. The peer was refusing correctly (CAP-6a scored "refused
  all 6 variants") and then taking the connection down with it — `lean`'s shape exactly, reached
  from the opposite direction. **The standing diagnostic found it in one step with no hypothesis
  about zig at all**: first FAIL in RUN ORDER was idx 566 (`tree_operations/put_entity`, "broken
  pipe"), and the last check before the first transport error was idx 562 — the CAP-6a check. The
  gap between them is the defect; the 89 is noise. **Rule: on any peer whose response builder
  CONSUMES its result entity, the salvage path must not also free it.**
  **THE SALVAGE FLAG'S MECHANISM IS DECIDED BY THE PEER'S CONCURRENCY SHAPE, not by taste** — and
  choosing wrong is a race, not a compile error. Measured across 23 peers: a field on the
  cursor/decoder struct where one exists (`c c++ zig ada dart odin nim crystal php ruby io`); a
  threaded PARAMETER where readers are real threads or the runtime has no mutable module state
  (`oz` forks a thread per connection, `unison` a green thread per connection); a THREAD-LOCAL where
  readers are threads but threading the flag would touch eight clause heads (`prolog`); a
  namespace/global ONLY on a single-threaded event loop, where one frame is fully decoded before the
  next is read (`tcl rexx forth`). In every global case both entry points must set the flag, or a
  strict decode inherits a stale 1.
  **AND ON A DECODER WRITTEN AS FREE FUNCTIONS, THREADING THE FLAG THROUGH THE RECURSION IS NOT
  OPTIONAL — forgetting it fails silently in the only direction that matters.** `ruby`'s
  `Cbor.decode_value` recurses into arrays and maps; passing the flag only at the top level leaves
  every nested call strict, so the salvage decode still raises on the tag — **and the tag is always
  nested, inside `root.data`**. A cursor-struct peer gets this for free; a free-function peer needs
  it passed through the array arm, the map arm AND the map's key/value reads.
  **(a) and (c) are the SAME BUG but present as two different failure classes — and one of them
  does not look like a conformance failure at all.** Measured 2026-08-22 across `typescript` and
  `csharp`, whose census reports are identical where it counts: same 3 real FAILs at the same
  indices (558/559/560), same first-transport-error index (563). The *only* difference is what the
  peer does with the connection after refusing. `typescript` **closes** → every later check fails
  instantly → **84F on a valid, complete 755-check measurement**. `csharp` **drops and holds the
  connection open** → every later check waits out a timeout → CAP-6a alone burns **120 060 ms**
  (six variants × a 20 s block, against `go`'s 1 ms), `security` 600 s, `tree_operations` 380 s,
  the global budget expires, nine categories never run → **quarantined as an INVALID MEASUREMENT
  with a *smaller* FAIL count (52)**. So the hang-form is strictly harder to see: it scores lower,
  it is filed under "starved run / harness problem," and it reads as unrelated to the peers whose
  numbers went up. **Diagnostic, cheap, run it FIRST on any starved peer before theorizing about
  latency or resources: compare the first-FAIL index and the first-transport-error index against a
  known peer carrying this defect.** Matching indices means same bug, and the starvation is a
  symptom rather than a finding. That one comparison is what turned `csharp` from "new at this pin,
  not root-caused" into "it is `typescript`." **Corollary for the fix log: a §6.3 fix can move a
  peer out of INVALID entirely — do not budget it as two separate work items.** (Detail:
  `CONFORMANCE-MATRIX.md` §1c.)

- **AN OP LADDER THAT DISPATCHES ON LENGTH MUST FALL THROUGH TO THE UNKNOWN-OP ANSWER, NEVER TO
  `return` — and a §4.9(c) silent drop bills the CALLER, so it presents as the peer being slow or
  under-resourced rather than wrong.** RATIFIED 2026-08-30 (two distinct shapes in one session; the
  second is the entry above). The three ISA peers route an operation by comparing its LENGTH first
  and only then its bytes. A length collision with an op they do route — `ping` against `echo`, both
  4 — failed the byte compare and jumped to the function's return with no frame written: not 501,
  not 400, nothing. `hello` (5) and `authenticate` (12) had the same hole.
  **What it cost, and why it was not found for months: every churn cycle ends with a `ping`, so
  every connection burned the caller's full 20 s read deadline.** `t2_2_connection_churn` reached
  cycle 29 of 100 inside the 10-minute budget, consumed all of it, and starved nine categories
  including three core ones — so all three peers were quarantined as INVALID MEASUREMENTS with a
  documented "connection-pressure family". **`CONFORMANCE-MATRIX.md` §1a's accumulation theory was
  wrong, and the 2026-08-29 measurement that ruled it out (peer healthy at the moment of failure,
  fds flat, children reaped) was right and pointed nowhere.** After the fix: `concurrency` 6/6 in
  1.1 s against 599 s, and the whole 755-check set runs.
  **The diagnostic that found it generalizes and the one that did not is worth naming too.** Reading
  the ladder finds nothing — the branch is three lines and looks like every other one. What found it
  in one build: set a flag in the frame WRITER, clear it at the top of dispatch, and print which
  operation returned WITHOUT having written. That question — *which dispatch answered nothing* — is
  cheap on any peer and is the direct form of §4.9(c). Sampling `/proc` and counting live children
  answered "the peer is healthy", which was true and useless.
  **Enforcement: in any length-then-bytes dispatch ladder, every byte-compare failure must target
  the unknown-op label.** Grep the ladder for a compare-failure branch whose target is the function
  epilogue rather than the next candidate or the 501 answer. Note the collisions are invisible to a
  reader who checks only the ops the peer implements — the defect is entirely about the ops it does
  NOT.

- **A FIXED BUFFER FILLED FROM WIRE DATA WITHOUT A SIZE TEST IS A REMOTELY-TRIGGERABLE PROCESS KILL,
  AND HARDENED libc MAKES IT LOOK LIKE A CRASH WITH NO CAUSE.** RATIFIED 2026-08-30 (`cobol`; three
  independent instances in one peer, which is the second shape rather than one bug). `tree-handler`
  did `compute nentlen = endo - eoff` then `move lk-env(eoff:nentlen) to nent(1:nentlen)` where
  `nent` is a fixed 8192-byte field. A 16 KiB `tree.put` — the oracle's own t1_4 staging payload —
  overflowed it, glibc's `_FORTIFY_SOURCE` aborted with `*** buffer overflow detected ***` and no
  backtrace, and **every check after that point failed with connection-refused: 24 of the peer's 30
  FAILs were one unchecked MOVE.** `store-put`/`store-bind` had it into a 4096-byte slot (so any
  entity over 4 KiB corrupted the store tables) and `cap-resolve` into an 8192-byte one.
  **The trap that cost the most time: the OVERSIZE path was correct and the IN-RANGE path was not.**
  The peer drains a frame past its 65535-byte cap exactly as §4.10(a) asks, and `resource_bounds`
  passes — so "oversize frames are handled" reads as evidence and is not. The trace showed a 264 109-
  byte frame drained across four reads without incident and then a perfectly ordinary 18 354-byte
  frame killing the process. **A payload bound is only a bound where the copy happens.**
  **Enforcement, and it is the same rule the AGENTS.md `nent`/`store` fix applies: the size test goes
  BEFORE the copy and produces a STATUS, not after it and not as a bigger buffer.** Grep any peer
  with fixed-extent fields for a copy whose length is computed from wire offsets
  (`endo - eoff`, `have - 4`, `end - start`) and check for a guard between the two. Raising the
  buffer instead of guarding just moves the threshold, and on a substrate where the store hands
  `lk-len` bytes back to the CALLER's fixed buffer it also creates a matching overflow on the read
  path — which is why `cobol`'s per-entity ceiling was left at 8192 and disclosed rather than raised.

- **A REFUSAL IMPLEMENTED AT THE WRONG LAYER cascades exactly like a crash — and reads like one.**
  New shape of the standing cascade class, found on `lean` 2026-08-21 (candidate; the class is
  ratified, this *shape* is first-occurrence). Every prior instance was an *uncaught* fault — a bad
  string, a `doesNotUnderstand:`, a raise escaping a narrow catch. This one is a **deliberate,
  correct-in-intent refusal** delivered as a **transport drop**: `lean` refuses all six malformed-
  temporal capability variants (CAP-6a) by closing the connection instead of returning the §5.2
  `capability_denied` disposition the rule mandates. The oracle reuses that connection, so every
  check after `capability` gets `broken pipe` — **81 cascade FAILs from one refusal path**, scoring
  `83F` against its siblings' `2F`/`3F`. **What makes this shape distinct and worth its own entry:
  the peer is completely healthy.** Clean stderr, exit code 0, never crashes — so every reflex the
  crash-cascade lesson trains (look for the uncaught exception, grep the peer log, check for a
  non-ASCII literal) finds nothing, and the natural next inference — "the peer died" — is wrong.
  **Diagnosis that worked, and the order matters:** the oracle's own check message named the defect
  outright (*"0 capability_denied, 6 transport-drop"*) — read it before theorizing; then bisect by
  scope (`-category capability` alone → 2F no cascade; `-category tree_operations` alone against a
  fresh peer → 0F; full core run → first FAIL at idx 559 is a `capability` check and the last check
  before the first `broken pipe` at idx 563 is the CAP-6a one). **Cohort rule: "refuse" means emit
  the protocol-level disposition the spec names — a transport-layer close is not a refusal, it is a
  refusal *and* a denial of service to every subsequent request on that connection.** Enforcement:
  when a peer's FAIL count is an order of magnitude off its cohort siblings, find the first FAIL in
  *run order* and the last check before the first transport error — the gap between them is the
  defect, and the count is noise. (Pairs with the standing "diff the per-check severities before
  believing the headline number" rule, in the opposite direction: that one catches a peer looking
  unfairly *good*, this one catches a peer looking unfairly *terrible*.)

- **Type registry: render natively, don't ingest bytes.** A peer publishes `system/type/*`
  via its language's reflection over its *own* data model + an override table for entity-type
  pins — single source of truth in code, with the Go-rendered vectors as a byte-exact
  diff/drift target. "Output these bytes to hit the check mark" adds zero independent signal.
  Scope to **core + operational + the type-system bootstrap** only; a core peer never
  pre-publishes extension vocabularies (extensions bring their own types when installed).
  **This rule now has an enforcement point and a known violator** (2026-08-17):
  `grep -rl 'system/type/compute/apply' protocol-generator/*/src/` should return **nothing**;
  it currently returns `asm-x86_64`, `asm-arm64`, `riscv64`, whose `src/typestore.s` publishes
  ~200 type entries including whole COMPUTE / CONTENT / CLOCK / CONTINUATION extension
  vocabularies. The oracle scores those *matched-if-present*, so over-publishing **converts
  283 `type_system` WARNs into PASSes** and makes those three peers read as `545P/42W` beside
  the cohort's `307P/327W` — **a higher pass count that means a scope violation, not better
  conformance.** The lesson generalizes past the type registry: when one peer's P/W split is
  structurally unlike the cohort's, diff the per-check severities before believing the
  headline number — a peer can look *better* than its siblings by doing something it
  shouldn't. (Detail: `CONFORMANCE-MATRIX.md` §1a.)
  **CLOSED 2026-08-30 — the grep returns nothing, and the fix is the cohort's cleanest example of a
  correct change that LOWERS a published number.** The trio was filtered to the 53-name core floor:
  `595P/54W → 313P/336W` (`asm-x86_64`) and `594P/55W → 312P/337W` (`asm-arm64`, `riscv64`), all
  three still `755 · 0F`. Verified per-check before/after on each peer: **exactly 282 checks changed,
  every one `type_system`, every one PASS→WARN, nothing outside that category moved.** The remaining
  deltas against `go` are all pre-existing and named elsewhere (F51 `authz_peers_target_from_uri`
  PASSes on all three; `authz_scope_exceeds_1` WARNed before and after; `r3_connection_flood` PASSes
  on `asm-x86_64` alone). **A 0-FAIL row does not retire an over-publication finding** — that stands,
  and it is why this one survived two weeks past the peers going green with no FAIL count drawing
  the eye to it.
  **THREE THINGS GENERALIZE, and the fix itself is the least of them.**
  - **The SCOPE FILTER BELONGS AT THE POINT OF PUBLICATION, NOT IN THE HARVEST.** These peers have
    no data model to reflect a registry over, so `typestore.s` is harvested byte-exact from the
    *reference* peer — which is a **FULL** peer and therefore serves every standard-extension
    vocabulary. The over-publication was not a mistake in the harvest; it was the *absence of a
    scoping step between harvesting and publishing*. The harvest stays intact (it is evidence of
    what the reference peer serves, and re-harvesting to prune it destroys that); `gen-typestore.py`
    filters. Generalize: **whenever a peer's data is captured from a richer source than the peer
    itself, name the filter and put it in the generator** — capture and publish are different scopes
    and the gap between them is silent.
  - **A KEEP-LIST, NEVER A DROP-LIST — the same argument as `CANONICAL-DOCS.toml`, one layer down.**
    A drop-list of extension prefixes fails **open**: a vocabulary added to a future harvest
    publishes silently and nothing objects. A keep-list of the 53 floor names fails **closed**: an
    omitted core type is a hard `type_system` FAIL on the next run, i.e. loud. Prefer the failure
    mode that shouts, and assert it in the generator (`CORE_FLOOR - harvested` must be empty) so it
    fires at generation time rather than at S4.
  - **`riscv64`'s `reference/typestore/` HAD NEVER BEEN COMMITTED — 0 files tracked, not gitignored,
    simply absent.** Its `gen-typestore.py` could not run from a clean clone and its `src/typestore.s`
    was a committed artifact with **no in-tree input**, byte-identical to its siblings' and
    unreproducible. This is the `forth` `bin/peer.fs` shape one level up: there the *entrypoint* went
    untracked, here the *generator's input* did, and in both cases everything worked locally forever.
    **Enforcement, and it is cheap: for any `tools/gen-*.py` that reads a directory, check
    `git ls-files` on that directory returns non-empty** — a generator whose input is untracked is a
    generator nobody can run but you. All three now regenerate byte-identically from their own
    committed harvest.
  **The cohort corroboration is worth recording because it was exact, not approximate:** 8 peers
  (`rust python haskell ocaml swift java c typescript`) publish a set **byte-for-name identical** to
  `go`'s 53, none publishes a 54th name, and none publishes any extension vocabulary. The floor is a
  hardcoded, order-stable list replicated across each peer's `tools/gen-typedefs.py`. When a scope
  question has 45 existing answers in the tree, ask them before deriving one.

- **A RETURN TYPE THAT COLLAPSES N EVENTS THE SPEC ANSWERS N WAYS CANNOT BE MADE CONFORMANT
  DOWNSTREAM, HOWEVER THE LOOP IS WRITTEN — fix the signature, not the caller.** RATIFIED 2026-09-16
  (`unison` and `fortran`, same session, two substrates, and the shape is identical in a pure
  functional peer and a C net shim). `unison`'s framed read was `readFrame : Socket -> Optional
  Bytes`, and `None` was **three different events** that §4.11 assigns three different answers: a
  clean close at a frame boundary (owed **nothing**), a length prefix that never completes (owed
  **400**), and an oversize declaration (owed **413**). No amount of care in `readLoop` recovers a
  distinction the value it receives does not carry. The fix is a four-case `FrameRead`, plus a
  `recvUpTo` that hands back the ACCUMULATED PREFIX — **because its SIZE is the discriminator: the
  two ends-of-stream differ by exactly one buffered byte.** `fortran` needed the same event in C
  (`EC_EV_TRUNCATED`) for the same reason.
  **The tell that you have this rather than a missing branch: the correct behaviour is not
  expressible at the call site.** If you find yourself wanting to know *why* a `None`/`nil`/`-1`
  came back, the signature is the defect. **Enforcement: for any read that can end in more than one
  way the protocol cares about, the return type enumerates them** — and keep the control that proves
  you implemented the distinction instead of deleting it (pa-probe's `D3`: the cheapest way to pass
  the truncation arm is to answer every short read, which turns an ordinary hangup into a refusal of
  nothing).
  *(And do not close on the peer's FIN while a refusal is owed. A FIN closes THEIR write side; ours
  is still open, and closing on receipt makes the mandatory coded frame undeliverable — which is
  Node's `allowHalfOpen` and the BEAM's `exit_on_close` arriving for free. On raw sockets we simply
  do not do it: mark the read side closed, let the peer queue its refusal, flush, then drop.)*

- **FFI shared-lib gotchas** (every `entity-core-codec-ffi-<lang>` + any dual-impl
  differential): with a verbatim header + linker version-script, do **not** use
  `-fvisibility=hidden` (hidden symbols can't be promoted by `global:` → zero exports; let
  the version script alone control exports, verify with `nm -D`). A same-soname differential
  needs `dlmopen(LM_ID_NEWLM, …)`, not `dlopen` (glibc dedups by soname → silently compares a
  lib against itself).

- **WHICH `ec_content_hash` DID YOU JUST TEST? LINK ORDER DECIDES WHICH SYMBOL WINS, AND A
  DIFFERENTIAL AGAINST "the same `.so`" IS WORTHLESS IF THE PEER DOES NOT CALL THAT `.so`.**
  RATIFIED 2026-09-07 (`asm-x86_64`), and it is the standing *"an exported symbol is not a
  reachable seam"* rule reached from the opposite side: there a symbol that looked reachable was
  not; here a symbol that looked like **the** implementation was a *different one with the same
  name*. It cost a whole session and produced a published `Not root-caused.`
  The peer refused the oracle's 256 KiB `t1_3` staging entity with `hash_mismatch`. The diagnosis
  traced **every input** — type string, byte-string head, all 262 144 payload bytes against the
  sender's filler, length, frame containment — and confirmed that *"a standalone call to the same
  `libentitycore_codec.so` with exactly those bytes returns the SENDER's hash."* Every clause true.
  **The peer never calls that function.** Its `Makefile` links `codec.o` **before**
  `-lentitycore_codec`, so the native `ec_content_hash` in `src/codec.s` wins and the `.so` supplies
  only the crypto floor — **and the Makefile says so, in a comment three lines above the link rule.**
  A byte-perfect input trace against a function that is never invoked is an unfalsifiable green.
  **Enforcement, and it is one command before any FFI-vs-native differential: ask the BINARY which
  one it resolved** — `nm -C bin/host | grep ' T ec_content_hash'` (a `T` means the peer defines it
  and the `.so`'s copy is dead), or read the link line for a local object preceding the `-l`. In a
  `dlopen` differential, **assert that `dlsym` did not hand back the symbol you are linked against**
  (`(void*)so != (void*)native`, abort if equal) — that check is four lines, it fired as intended
  here, and without it the harness compares the codec to itself and prints `identical`.
  **Two more defects came out of it, and each would have kept the check red alone.**
  - **A FIXED BUFFER MUST NAME THE INPUT BOUND IT IS SIZED AGAINST, AND "it has an overflow guard"
    IS NOT THAT.** `ecf_scratch` was `.space 65536` while the peer accepts frames to `MAX_FRAME`
    = 16 MiB (`b_req` is already 16 MiB, the store arena 64 MiB) — **256× smaller than the input it
    can legally receive**, with a perfectly correct `.Loverflow` guard on top. This is the `cobol`
    fixed-field lesson's *sibling, not its twin*: cobol had a copy with **no** size test, this has a
    right one on a buffer sized against nothing, so the failure is not corruption but a **capacity
    gap presenting as a wrong answer**. Sizing it to `MAX_FRAME` is a **derived** bound, not the
    "raise the buffer instead of guarding" move that entry forbids — and check the *shape* before
    fearing the cost: this is one `.bss` arena **per process**, demand-paged, where cobol's was
    `LOCAL-STORAGE` per call per recursion level. Enforcement: for every fixed buffer that receives
    wire-derived data, state the bound in a comment AT the declaration and tie it to the constant it
    tracks; a buffer whose size is a bare literal is one nobody has compared to the frame cap.
  - **AN UNCHECKED RETURN CODE FROM A FALLIBLE RECOMPUTE LIES IN THE DIRECTION OF BLAMING THE
    SUBMITTER.** `admit_put` called `ec_content_hash` and went straight to the `memeq`. On failure
    that function unwinds leaving `out` **UNWRITTEN**, and `ch_admit` is `.bss` — zeros, or the
    previous admission's digest — so a peer capacity limit was emitted as `400 hash_mismatch`: **an
    accusation about the submitter's bytes.** Fixed to distinguish `-3` `EC_DECODE_ERROR` (genuinely
    the submitter's, → `invalid_request`) from `-2` `EC_OUT_OF_SPACE` (ours, → `413
    payload_too_large`), and the `-2` arm is **kept after** the capacity fix made it unreachable,
    because a silent `-2` becoming a false accusation is wrong at any buffer size. **Enforcement: on
    any verification path, grep for a call whose result is compared without its status being tested
    — and note the tell, which is that the failure mode is a CONFORMANT-LOOKING refusal**, not a
    crash. Being unreachable, it was then **executed by planting the old 64 KiB cap and re-running**
    (`tree put status 413`, against `hash_mismatch` unfixed) — the standing *a guard that was never
    executed is not a guard* rule, applied to an arm added the same day.
  **THE SIBLING CHECK IS WHAT MADE THE SECOND HALF REAL, AND IT INVERTED THE OBVIOUS READING:
  "INTERCHANGEABLE IMPLEMENTATIONS" AGREE ON SUCCESS AND WERE NEVER ASKED ABOUT FAILURE.**
  `asm-arm64` and `riscv64` have no `codec.s`, so the *capacity* half is x86_64's alone — but both
  carried the identical unchecked return code, and the C `.so` returns `EC_OK` for any non-NULL
  argument, so the arm reads as **dead code** and leaving it alone reads as the disciplined call.
  The C-ABI has **two** interchangeable impls, so the other one was measured instead of reasoned
  about: `conformance/abi_failset_probe.c` finds **5 of 8 `type` inputs diverge** — Rust's
  `ec_content_hash` runs `str::from_utf8` and answers `EC_INVALID_ARGUMENT`, C hashes the bytes —
  and every divergent case is a **non-UTF-8 `type`, which is attacker-controlled wire bytes on the
  §6.3 put path** (CBOR major 3 does not enforce UTF-8, and step 1b only checks non-empty). So the
  "dead" arm is live the moment a peer links the other impl. **`abi_differential`'s 101 probes are
  structurally blind to this because they drive VALID input** — the `ec_entity_original_bytes`
  export-asymmetry entry above, in a BEHAVIOURAL rather than a presence shape — and §4.1 declares
  **no failure set at all**, so neither impl is violating anything written down. **Rule: a
  cross-implementation differential must drive REFUSAL inputs, not only accepted ones; two impls
  agreeing on every valid vector is not interchangeability, it is a shared happy path.** And
  before dismissing an error arm as unreachable, ask *unreachable under which implementation* —
  the answer for a swappable dependency is not a property of your code. Recorded, unresolved on
  purpose, in `ffi-generator/c-abi/status/FFI-ARM-STATE.md` §3: picking a winner is a behaviour
  change for 34 linking peers and a real design question, not a patch.
  **And record the machinery that worked, because it is the reason this was found at all:** the gap
  was disclosed in `CONFORMANCE-MATRIX.md`, allowlisted **by name** in `skip-provenance-gate.py`, and
  that allowlist's own doc says removing the entry is part of closing the gap. An honestly-labelled
  `Not root-caused.` with a named enforcement hook is what a later session picks up; a reverted
  ladder and a restored `316P` would have left nothing to find.

- **A SHARED LIBRARY'S LIFETIME ASSUMPTION IS PART OF ITS ABI, AND "the process exits" IS AN
  ASSUMPTION ABOUT THE CALLER THAT NO CALLER IS TOLD ABOUT.** Candidate (first occurrence, found
  2026-09-04 while measuring `cobol`'s capacity work; the enforcement point is exact and the blast
  radius is the whole hybrid-FFI tier). `libentitycore_codec` leaks an entire `ec_value` tree on
  **every** `ec_encode_ecf` and `cc_content_hash` — both on the per-request path — and the reason is
  written in its own source: *"the harness + ABI calls are short-lived; we malloc value nodes and
  never free the tree (process exits)"*. That is true of the conformance harness it was developed
  against and **false of every long-running peer that links it**, which is what the library exists
  for. Measured on `cobol`: **~1 KB per dispatched request, 23.3 MB per `--profile core` suite**,
  tracking requests rather than connections (a connection-heavy category costs 80 kB per run; a
  request-heavy one 419 kB over ~449 requests). Unbounded and remotely triggerable.
  **Three things generalize, and the third is why it survived.** (a) **Bisect before attributing** —
  this was found while raising `cobol`'s buffers 8×, which is exactly the change you would blame;
  measuring `HEAD` gave **23.3 MB/suite before against 22.3 MB after**, so it is neither new nor
  worsened, and saying so is the finding. (b) **`grep -c 'free('` on an allocating module is a
  one-line audit** — four hits in `ecf.c`, none of them a value node. (c) **The comment even names
  the fix — *"a v2 arena (`ec_arena_*`) replaces this for the long-running peer decode path"* — and
  `ec_arena_new()` is `malloc(1)`.** The arena is honestly documented as unnecessary *for decode*
  (which borrows spans); nobody noticed that made the sentence's promise about *encode* vacuous. So
  this is the standing **"a deferral comment is a conformance claim with no gate on it"** rule
  landing in SHARED code, where the deferral was resolved on one path and quietly inherited on the
  other. **Enforcement: for any FFI entry point that constructs an owned tree, the same function
  must free it — and a library whose correctness depends on the caller being short-lived must say so
  in its HEADER, where a consumer reads it, not in an implementation comment.**
  **FIXED the same day, and the verification is the part worth copying, because a wrong `free` in a
  library seven peers link is strictly worse than the leak it removes.** A recursive `ev_free`, a
  release at every entry point that builds a tree **on every exit path including the error ones**,
  and child arrays switched to a ZEROING allocator so a partially built tree is walkable — the
  decoder fills them element by element and can fail partway, which is the difference between "free
  on the error path" and a wild pointer. Two leaks were worse than the encode one and neither was in
  the original hypothesis: `ec_envelope_find_signature_for` leaked one tree **per included entity**,
  both its `continue`s skipping the release, and the decoder leaked its partial tree on **every
  malformed input** — remotely triggerable by bad bytes alone, with no valid request needed.
  **Verified at four levels, in this order:** the codec's own regression suite and the 71-vector ECF
  corpus; `cobol` three times, byte-identical to its committed report; the **full 46-peer census** —
  46/46 conforming, all comparable, **exactly 2 of 34 868 severities different** from the tracked
  reports and both the documented `t1_1_concurrent_demux` timing flake; and the leak itself, which
  goes from +22.7 MB per suite to **flat from the first suite onward**.
  **And the 13 agility-corpus failures the harness reports are IDENTICAL at HEAD** — that harness
  does not implement those vector kinds — which is only knowable by running it at HEAD. A red you
  did not cause looks exactly like one you did.

- **THE ECF CORPUS'S `map_keys` VECTORS ARE ALL `encode_equal` — THE S2 AXIS TESTS THE ENCODER'S KEY
  ORDERING AND SAYS NOTHING ABOUT DECODE-SIDE REJECTION, AND A PEER CAN BE 71/71 WHILE ACCEPTING
  NON-CANONICAL BYTES ON THE WIRE.** RATIFIED 2026-09-14, and it is *conformance-green-can-be-vacuous*
  on the axis we consume rather than on the one we author. Found twice the same session, from
  opposite directions, which is what makes it a fact rather than a reading:
  - Reading the corpus: all six `map_keys` vectors are `kind=encode_equal` (*"text keys sort by
    encoded length first"*, *"same-length text keys sort lexicographically"*, …). **There is no
    duplicate-key REJECT vector anywhere in it.**
  - Measuring a peer: `java`'s `CanonicalCbor.decode` — the `envelopeOfFrame` wire path — **accepts
    a non-minimal integer head (`0x18 0x01`) and out-of-order map keys**, while its corpus run is
    71/71 throughout.
  - **And it is not one peer. `elixir` and `common-lisp` accept the same non-minimal head**
    (`Cbor.decode(<<0x18, 0x01>>)` → `{:ok, 1}`; `(cbor-decode #(#x18 #x01))` → `1`), found
    independently a day later by a different agent writing the *"non-canonical but NOT the tag arm"*
    discriminator. `elixir`'s `arg/2` and `common-lisp`'s `%dec-arg` never compare the decoded value
    against its minimal encoding. **Three peers, one shape, two independent discoveries, and all
    three are 71/71 on the corpus** — while `ruby`, `python` and `go` refuse it. That split is the
    measurement: the corpus cannot be what makes the difference, because all six pass it.
  **DELIBERATELY NOT FIXED, and the reason is the rule rather than the timidity:** it is a CODEC
  change, outside the sweep's rule set, with unmeasured blast radius on both S2 and S4 — and
  smoothing it into a §4.11 sweep commit would bury a real finding inside an unrelated one. It is
  recorded IN-TREE on each peer instead (a named skipped test on `elixir`, a printed-but-uncounted
  note in `common-lisp`'s gate, so a pre-existing gap cannot hold the gate red) **so that changing
  it is a decision and not a drift.**
  **This corroborates `entity-system-conformance`'s X13** (*four peers accept a hello carrying a
  CBOR tag, six accept duplicate map keys*) rather than competing with it: their probe measures a
  surface our S2 axis is structurally blind to. It is also the other half of the `put-probe`
  duplicate-key episode already recorded here, where `csharp` refused what 37 peers accepted.
  **Enforcement: an `encode_equal` corpus is an ENCODER test. Before citing an S2 row as evidence a
  peer's decoder is canonical, check the vector KINDS** — and treat any canonicalization rule with
  no reject-direction vector as ungated, whatever the pass count says. The reject-direction
  coverage is architecture's to author (`GUIDE-CONFORMANCE` §7.0 — we author none of it); ours is
  to stop reading a green encoder axis as a decoder claim.

- **AN ACCEPT-SIDE RULE IS NEW IMPLEMENTATION ON EVERY PEER, AND THE PEERS WHOSE `put` "WORKED"
  WERE THE ONES AUTHORING THE SUBMITTER'S CONTENT.** RATIFIED 2026-09-07, §6.3's `0.8.2.11` put
  admission ladder landed on all 46 peers (`shared/findings/put-admission-wire-census.md`). Arch's
  instruction — *"do not size the work from the assumption that they are conformant and this is a
  re-vendor"* — was right and the measurement was the maximum bad case: **0 of 46 implemented any
  row**; **36 accepted a two-key `{type, data}` submission and STORED it**, holding an entity under
  a hash nobody supplied; **10 bound a path to content that did not hash to the hash they were
  given** (a §1.8 failure the code table does not touch). Final shape: **+4,201 / −128 across 56
  files**, one ladder authored from the spec and propagated, 46 of 46 at 6 of 6.
  **Three things generalize past this rule.**
  - **The ladder had to REMOVE adjacent defects rather than sit beside them, and each was a
    DEFAULT or a FALLBACK doing authoring work.** `sql` defaulted an absent `type` to
    `"primitive/any"` — storing an entity under a type the submitter never sent, the same class as
    authoring its hash, one field over. `ada` and `datalog` treated a present-but-MALFORMED entity
    as the §6.3 REMOVAL case and **unbound the path**: a destructive reading of a value the spec
    says to refuse. Enforcement: on any receipt path, grep for a default applied to a field the
    submitter is required to supply, and check that the delete arm is `absent OR null` and not
    `absent OR unparseable`.
  - **A CONSTRUCTOR THAT COMPUTES IS THE DEFECT; NAME THE RECEIPT CONSTRUCTOR AND SAY WHERE IT MAY
    BE CALLED FROM.** Peers whose entity type only had an authoring constructor gained one
    (`Entity.admitted` / `ent-admitted` / `Ent_Admitted` / `admittedType:data:hash:`) whose doc
    comment states it is reachable only from the ladder that just verified those bytes. Where an
    existing `of_cbor`/`from_cbor` already recomputed and refused on a carried mismatch, step 2
    routes through it — **verifying is the opposite of authoring, and reusing the verifier is
    cheaper and safer than a second comparison.**
  - **NAME THE CODES A PEER CAN VERIFY, NOT THE CODES ITS CONSTRUCTION PATH WILL SERIALISE.** Every
    peer's `hashDigestLen` is its own: a fixed 33-byte hash field (`c` `cpp` `fortran` + the ISA
    trio) or a SHA-256-only primitive means `0x00` alone. So the SAME input answers
    `unsupported_content_hash_format` on different codes on different peers — which is the honest
    answer, and copying one peer's table across the cohort would have been a claim none of them
    could keep. This is §4.7's construction-vs-verification asymmetry as a per-peer fact.

- **WHEN A PEER ALREADY HAS A FAILURE FLAG, ITS FAILURE SET IS NOT THE SPEC'S — mapping the whole
  flag to a new sentinel imports every refusal the peer happens to bundle into it.** Candidate
  (first occurrence, 2026-09-14, `apl`, and the census is the only thing that caught it). Landing
  §5.4's total `canonicalize` meant making a matcher wrapper return `NEVER_MATCH` where it had been
  ignoring an existing `invalid`/`ok`/`Option` failure. On five peers that flag carries exactly the
  three reserved prefixes and the obvious mapping is correct. **On `apl` it does not**:
  `CapCanonicalize` also refuses a null byte, an empty segment, and — the one that bit — **an
  absolute path whose first segment is not a peer_id**, which is §5.4's `validate_absolute_path` and
  which §5.4 says explicitly is *"NOT called on patterns"*. Mapping the flag turned every `/*/…`
  peer-wildcard pattern unmatchable: **6 FAILs, every foreign-namespace check and three id-scope
  ones.** **Enforcement: enumerate the arms of the existing flag before reusing it, and map only the
  ones the spec's own function names.** The tell is that the wrapper reads as a one-line change and
  the peers where it is wrong look identical to the peers where it is right — only a per-check census
  diff separates them, which is why a cohort sweep of a matcher is not done without one.
  **THE SAME QUESTION HAS A POSITIVE ANSWER AND IT IS WORTH ASKING FIRST: WHEN A PEER ALREADY
  SEPARATES THE CAUSES, READ ITS EXISTING CODES BEFORE WRITING A CLASSIFIER.** 2026-09-15, `forth`.
  §4.11 assigns four pre-admission causes three different codes, and the peer answered
  `non_canonical_ecf` to all of them — while its decoder was ALREADY throwing `E-TAG-REJECTED`,
  `E-NON-CANONICAL-ECF`, `E-TRUNCATED-INPUT` and `E-INCLUDED-KEY-MISMATCH` as distinct values, and
  `serve-conn` was discarding the code with `2drop drop` before `reject-frame` could see it. The
  arms mapped 1:1 onto the section's causes and the whole fix was to stop dropping the code — no
  strict walker, no second pass. **Ask what the peer's existing failure set already distinguishes
  before deciding it distinguishes nothing**; the `apl` direction (the flag carries MORE than the
  spec's arms) and this one (it carries EXACTLY them, unread) are the same enumeration.
  **RATIFIED 2026-09-16 — A THIRD DIRECTION, AND IT IS THE ONE THE SESSION WRITING THE RULE WALKED
  INTO TWICE: THE CONSTRUCTOR'S NAME IS NOT THE MAPPING.** `fortran` and `unison` both carry decoder
  error kinds whose names read like wire codes — `EC_NON_CANONICAL_ECF` / `NonCanonicalEcf` beside
  `EC_TAG_REJECTED` / `TagRejected` — and both of my first cuts folded them together, because the
  name matches the code `non_canonical_ecf`. **§4.11 scopes that code to CBOR TAG-POLICY VIOLATIONS
  SPECIFICALLY**; an indefinite length, a non-minimal head or a duplicate key is a *framing* fault
  owing `invalid_request`. Measured both times as pa-probe **`D6` WRONG CODE**, which is the arm that
  exists for it. Same session, same hour, second peer — so the pull is the resemblance rather than
  carelessness. **Enforcement: map the spec's CAUSES to codes in one function, and derive the
  mapping from the section's own table, never from the constructor names.** `unison`'s §3.1 miskeyed
  key was the same defect one step earlier — it was *filed* under `NonCanonicalEcf` at the raise site,
  so no mapping could have recovered `hash_mismatch`; it needed its own `IncludedKeyMismatch` arm
  (which `rust` has had all along). **A cause that two codes must distinguish needs two constructors,
  and a shared one is a mapping that was decided before you got there.**

- **A REFUSAL REACHED BY `throw` INTO A GENERIC CATCH IS NOT THE REFUSAL THE SOURCE APPEARS TO
  STATE — and the clause that states it can be DEAD CODE that has never once run.** Candidate
  (`prolog` 2026-09-01, but it is the standing "a source grep is not a conformance census" rule
  with the sharpest example yet). `authorized_dispatch/5` did `throw(not_local)` for the §1.4
  foreign-namespace case, and the clause *directly below it* answered `404 handler_not_found`
  (later `400 invalid_request`) — which reads, to any reader and to any grep, as the refusal.
  **A `throw/1` does not fall through to the next clause.** It unwound to `dispatch/4`'s
  `catch`, where the generic `chain_error_outcome/2` turned it into **`500 internal_error`**.
  Measured on the wire; a source read clears the peer completely.
  The second clause had never executed in the peer's entire history, and nothing noticed because
  no vector exercised the input until PD-1 landed one. **Enforcement: for any refusal implemented
  as a raised/thrown condition, name the handler that catches it and check that the handler
  produces the status the refusal intends** — a generic catch-all is a 500 factory, and in a
  language with clause-indexed dispatch a fallback clause beside a `throw` is the shape most
  likely to be mistaken for one.

- **A REFUSAL THAT EXISTS BUT CANNOT BE REACHED IS A §4.9(c) SILENT DROP — check that the answer
  path is REACHABLE, not just present.** Candidate (`apl` 2026-08-30, but it is the third time in
  three days that a §4.9(c) drop has been the finding, after the ISA op-ladder and `cobol`). `apl`
  already had a correct `400 non_canonical_ecf` branch in `OnFrame`, written and committed. It was
  dead code: the `WirePeek` that recovers the `request_id` used the **strict** decoder, so a frame
  carrying a major-type-6 tag returned `ok=0` two lines earlier and was dropped on the floor. The
  peer scored CAP-6a **WARN** — *"3 capability_denied, 3 transport-drop"* — while reading, in source,
  as if it answered. **Grepping for the status code finds this code and clears the peer.** What
  finds it is asking which decode the answer path depends on. The cohort-standard salvage decode
  (strict decoder byte-unchanged; salvage used ONLY to recover the id) took CAP-6a to PASS on all
  six variants **and cut the run from 149 s to 89 s**, because each dropped frame had been billing
  its caller a full timeout — the same "presents as slow, is actually wrong" signature as the ISA
  trio's op ladder.

- **THE §2.4a NEGATIVE HALF NEEDS A CONSTRUCTOR, NOT AN ASSERTION — a refusal observed through the raw
  primitive is the bypass the rule exists to forbid.** RATIFIED 2026-09-02 across five peers.
  `hash-format-sha-384.2` was **inverted upstream**: it used to assert that re-hashing the fixture
  `system/peer` under `content_hash_format = 0x01` SUCCEEDS; §4.5a **item 1a** pins `system/peer` to the
  ECFv1-SHA-256 floor **unconditionally**, so the construction cannot exist and the vector now asserts
  the refusal. The corpus's `verifier_requirement` is the load-bearing clause — *"The refusal MUST be
  observed through the pinned peer-entity constructor"* — and every harness that touched this vector
  called the **raw digest function**, which is exactly the hand-built bypass that let a forbidden
  construction score green. So the work is a **peer change, not a test edit**: separate the §4.5a
  AUTHORING entry point from the digest primitive and refuse there — `haskell`
  `ContentHash.authorContentHash` (routed through by `Identity.identityOfSeed`, so the pin is a
  constraint the peer EXECUTES rather than a property it happens to have), `ocaml`
  `Peer_identity.build_peer` (result-typed; `~home` kept so the caller must still say what it is
  authoring under), `csharp` `Entity.Create`, `elixir`/`ruby` `Hash.author_content_hash`.
  **The guard goes on the AUTHORING path ONLY** — the receive path recomputes under the format an
  entity declares, which is wire acceptance and a separate surface item 1a does not speak to.
  **Two corollaries, and the second is the wider one.** (a) `ocaml` and `csharp` had carried this as a
  *comment saying it was owed* — the standing "a deferral comment is a conformance claim with no gate
  on it", in a file whose whole job is to be the gate. (b) **`elixir` and `ruby` dispatch on the
  vector's `kind` and both ended in `_ -> []`, so when upstream changed the kind from
  `content_hash_under_format` to `construct_reject` the branch SWALLOWED it** — no gate, no skip, no
  message, and the suite reported the same confident green having never asked. An unhandled kind is now
  a named FAILURE in both, and `haskell` asserts the corpus's full id set. **Enforcement: a
  corpus-driven harness must fail on a vector it cannot drive, and a name-driven one must assert the
  corpus's id set** — the count is the only thing that distinguishes "all pins pass" from "the pins I
  happen to know about pass" (`elixir`/`ruby` went 34 → 36 gates, which is what said the vector was
  being asked at all).

- **TWO SITES FOR ONE REFUSAL, AND ONLY THE ONE THAT RUNS FIRST IS OBSERVABLE — so correcting the
  other is a measurable NO-OP that reads as "the fix did not work."** RATIFIED 2026-09-08 (`sql`),
  and it is the `ec_content_hash` link-order lesson moved INSIDE a single peer: there two
  implementations of one symbol and the linker chose; here two implementations of one §6.6
  resolution-miss and the call order chose. `sql` answered `404 not_found` where §3.3's 404 row
  (0.8.2.7) pins `handler_not_found`. The previous session changed the host's `resolve_handler()`
  miss at `peer.c:1010`, measured no change, and correctly concluded the answer came from
  somewhere else — then handed off the wrong somewhere ("a too-broad row in the `handler` table").
  **`verify_ladder.sql` carries its OWN resolution-miss rung, spelled `not_found`, and
  `project_and_verify` runs BEFORE `resolve_handler`**, so the host arm is unreachable for an
  unregistered path and the handler table was never suspect.
  **One TRACE print settled it in one run and no amount of reading would have**: the trace showed
  `resolve_handler` was only ever called with `system/tree`, i.e. the probe URI never reached the
  line under repair. That is A1 (trace a value before you theorize) pointed at *control flow*
  rather than at data. **Enforcement: when a fix to a refusal produces no measurable change, do
  not look for a second cause — instrument the site and confirm it EXECUTES.** And when a peer
  carries the same refusal at two layers, say so at both, name which one the wire observes, and
  keep the spellings in step: the backstop is worth keeping, silently diverging is not.
  and was wrong in both directions once measured: `ruby` was listed as having no
  established-gate yet returns 409; `sql` carries the 409 string yet returns **200**;
  `rust-wasm`/`rust-wasm-wasmtime` carry neither string yet return **401** (they are thin
  transport seams over the `rust` crate and inherit its fix — corroboration, not independent
  data points). Ask the running peer.
