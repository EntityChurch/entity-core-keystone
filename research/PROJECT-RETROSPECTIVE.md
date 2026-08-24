# entity-core-keystone — Project Retrospective

**The capstone synthesis.** Where we started, how we got here, what we built, and — the part that
outlives any single peer — **what generating entity-core onto 45 programming substrates taught us
about the protocol, about the substrates, and about the method itself.**

This is a *narrative* document, not a status snapshot. Its backbone is
[`SUBSTRATE-TAKEAWAYS.md`](SUBSTRATE-TAKEAWAYS.md) (the operational "what translates / what needs a
seam / what doesn't"); its factual ground truth is [`CONFORMANCE-MATRIX.md`](../CONFORMANCE-MATRIX.md)
(per-peer landings), [`LANDSCAPE.md`](LANDSCAPE.md) (the roster), [`PARADIGM-MAP.md`](PARADIGM-MAP.md)
(the territory), and [`stewardship/SPEC-FINDINGS-LOG.md`](stewardship/SPEC-FINDINGS-LOG.md) (the
findings register). Where those disagree with this document on a number, they win — this is the reading,
not the record.

It is also intended to be the **core reference** for what this project is: readable by an adopter, an
architect, or a researcher who has never seen the repo. Sections 1–3 are the "what and why"; sections
4–8 are the analysis; sections 9–11 are the forward look. If you read one section, read §4 (what we
learned about the protocol) and §8 (is the protocol at its minimum).

---

## 1. What this is

**entity-core** is a protocol — a wire format (canonical CBOR / ECF), a content-addressed entity model,
an Ed25519/Ed448 signature and capability-delegation scheme, and a small dispatch/authority state
machine — plus an ecosystem of independent implementations built as a **polyrepo** (ADR-0010). One spec,
upstream; several ground-up reference implementations (`entity-core-{go,rust,py}`); formal models; and
**this repo**, the canonical conformance anchor.

`entity-core-keystone` does three things:

1. **It is the conformance anchor** — *provided, not mandatory*. Anyone may build a ground-up peer
   instead; the keystone exists so they don't *have* to, and so there is a common bar. That bar is two
   oracles built from `entity-core-go`: `wire-conformance` (the byte-exact codec oracle, the lower bar)
   and `validate-peer` (the live-peer oracle, the higher bar). "Green report or no publish."

2. **It is a generator.** The `/entity-rosetta` skill produces a full core-protocol peer
   (`entity-core-protocol-<lang>`) for a target language from the pinned spec snapshot + the conformance
   oracles + a per-language profile. The generator's phases (S1 research/profile → S2 codec → S3 peer
   machinery → S4 conformance → S5 publish) are *loose LLM guidance driven by an overseer*, not a
   deterministic pipeline.

3. **It owns the codec C-ABI** — `libentitycore_codec`, a language-agnostic contract with
   interchangeable Rust and C implementations, so substrates without mature canonical-CBOR + Ed25519
   stacks can consume the hard parts through FFI while still authoring the protocol interior themselves.

**The thesis — and the reason this document exists.** *Generating peers is the means; spec refinement is
the end.* Every peer we build is an attempt to read the spec from a substrate the spec's authors did not
have in mind, and every place two honest readings diverge, or a substrate can't cleanly express a MUST,
or the oracle passes a peer that doesn't actually implement a primitive, is a **finding** that feeds back
to architecture. The peers are the instrument; the protocol is the specimen.

**The method, stated as a method.** What we actually ran here is a controlled experiment that is rarely
run at this scale: *implement one non-trivial protocol, faithfully, in as many genuinely different
computing substrates as exist, and watch what stays invariant and what strains.* At N=3 (the usual
number of reference implementations a protocol gets) you cannot tell an intrinsic property of the
protocol from an accident of the three languages you picked. At N=45, spanning ~80 years of language
design and every major computational model, the accidents cancel and the invariants stand out. That
differential — *what survives translation across the whole territory* — is the project's real output, and
it happens to land on what we regard as a fundamental substrate of computing (a content-addressed,
capability-authorized entity protocol), which is what makes the invariants worth writing down.

---

## 2. Where we started, and how we got here

The roster was **seeded from architecture's top-40 cross-language matrix** (`LANDSCAPE.md`) — a survey of
which languages had credible native CBOR + Ed25519 stacks, which wanted FFI, and which shared a runtime
(JVM, .NET, BEAM, C-interop). The build then ran in waves, each chosen to probe a different axis:

- **First wave — mainstream, native-codec.** C#/.NET first (mature ecosystem, native codec, F# nearly
  free downstream); TypeScript; C (both a target and the FFI bridge for everyone else); then the
  ground-up trio's own substrates (Rust, Go, Python) already covered by the reference impls. These
  established the generator and the profile discipline.

- **The distant-idiom peers.** OCaml (strict ML), Haskell (lazy, pure, the first native-Ed448 peer),
  Common Lisp (pure-Lisp crypto, CLOS multiple dispatch), Elixir (BEAM actor), Zig / Odin / Nim / Crystal
  / Julia (the fixed-width-int + metaprogramming-codec cluster), Swift (ARC / actor / the string-model
  axis). These closed the number-model, memory-model, and crypto-availability axes.

- **The pre-release slate + the alien-substrate sweep.** Kotlin, PHP, C++, Dart (reach), COBOL (the first
  genuine "can the wire even fit" discovery bet), then Tcl, Rexx, Forth, Smalltalk, Fortran, APL — the
  everything-is-a-string, native-decimal, stack-machine, pure-object, and array-model probes. This sweep
  is where the codec-corpus findings (F29/F30) landed and then dried up: **the wire-surface discovery
  well went dry around peer 15 and stayed dry.**

- **The bare-machine and ISA arc.** A hand-written x86-64 assembly peer (not generated — the ultimate
  "barest substrate" stress test), then ports to ARM64 and RISC-V. This produced the coupling insight
  (ISA portability × how-much-you-hand-roll are coupled axes) and confirmed same-register-class ports are
  near-free while cross-class ports need the oracle to catch an arg-register seam bug.

- **The WebAssembly arc.** A hand-authored WAT peer (the WASM analog of the asm peer), the same Rust peer
  cross-compiled *unmodified* to `wasm32-wasip1`, and that module run under wasmtime AOT. This produced
  the execution-mode-is-conformance finding and the "portable compute is ~1% over native; the whole cost
  is the transport-ABI seam" measurement.

- **The visual-paradigm probes.** Node-RED (flow-graph), TurboWarp/Scratch (imperative blocks), Pure Data
  (reactive patch) — exploratory, mostly non-deployable, kept as community-readable references. Their
  payoff was a *method* finding (decomposition surfaces bugs) more than a language finding.

- **The authority-as-query frontier.** SQL (SQLite) and Datalog (embedded Ascent) — built not as
  substrate probes but as *spec-discovery* probes, on the hypothesis that authorization is historically a
  database/logic problem. This was the last productive vein, and it produced F40/F41.

The end state: **42 gate-green peers + 3 visual-paradigm probes** — 45 substrates — every major
spec-discovery axis exhausted, the declarative-query/logic frontier closed. `dev` is clean at the
handoff. No build work is queued; the generative phase is complete.

---

## 3. The territory we covered

`PARADIGM-MAP.md` is the full cartography; the compressed version is that the cohort spans, on **every
axis that could plausibly strain a wire+authority protocol**:

| Axis | Range probed | Verdict |
|---|---|---|
| **Integer model** | fixed-width signed (Fortran, COBOL) · fixed-width unsigned (Zig/Odin/C# u64) · bignum (Elixir/Python/Ruby/Lisp/Haskell/Smalltalk) · decimal (Rexx) | Head-form is a *substrate* artifact, not a protocol property |
| **Float model** | IEEE-native (Forth `SF!`/`DF!`) · hand-rolled shortest-float · decimal | Shortest-float ladder is the universal hand-roll |
| **String / byte model** | UTF-8-native · grapheme (Swift) · everything-is-a-string (Tcl/Rexx) · no byte or map type at all (Scratch) | Opaque-handle pattern covers the substrates that can't hold the value |
| **Object model** | class-based · pure message-passing (Smalltalk) · **pure prototype/delegation (Io)** · CLOS multiple-dispatch · multiple-dispatch (Julia) | §6.6 resolution renders in each idiom natively |
| **Concurrency (§7b/§6.11)** | actor (Swift/Elixir) · STM (Haskell) · CSP (Go) · thread+lock/async · single-thread event loop (Pd/Io/Scratch) · **dataflow-variable (Oz)** | **Four** structural store-safety shapes; the demux cost varies by shape |
| **Execution model** | compiled · interpreted (wasm) · JIT · AOT · bare-metal asm · three ISAs (x86-64/ARM64/RISC-V) · stack-VM (WAT) | Portable compute ~1% over native; cost is the transport seam |
| **Crypto availability** | native-stdlib · native-audited-lib incl. Ed448 · native-pure-lang (CL) · gap→hybrid-FFI | Ed448 is the fault line; hybrid-FFI is opt-in |
| **Computational paradigm** | imperative · OO · functional (ML + Lisp) · logic top-down (Prolog) · **logic bottom-up (Datalog)** · **relational query (SQL)** · array (APL) · concatenative (Forth) · visual/reactive | Wire+dispatch fits all; authority *interior* fits query/logic **more legibly** |

`PARADIGM-MAP.md` classifies each family by a **viability filter**: NATIVE (authors the full interior) ·
HYBRID-FFI (interior native, codec/Ed448 via FFI) · QUERY-NATIVE (the authority *logic* is naturally the
paradigm) · WRAPPER-ONLY (can't author the interior — a façade) · STUNT · SAME-FAMILY. The filter matters
because it is the same filter the **extension layer** will use (§10): a substrate that can only *wrap*
core is a substrate you cannot author extensions in.

**What "complete" means.** Every axis above that could strain the protocol is now mapped. What remains is
explicitly *not* new axes: catalog completeness (Scala, Objective-C, Lua, Pascal — same substrates,
different rows), inaccessible runtimes (Simulink, spreadsheets — wrapper-only), dead academic languages,
and same-family ISAs/Lisps/arrays. The picking is deliberately slim, and *that slimness is the evidence
the landscape is near-complete* — not that we missed a category. The one region that could still teach us
about the protocol rather than the substrate was authority-as-query, and it is now closed.

---

## 4. What we learned about the *protocol*

This is the section the whole exercise exists to produce.

### 4.1 The headline

**The wire contract and the dispatch *logic* are substrate-neutral to an unusual degree; the friction is
concentrated in a small, predictable, now fully-mapped set of wire-touching axes.** The substrate
overwhelmingly determines *how much seam* you need — not *whether* the protocol fits. It fit everywhere we
tried, including two visual paradigms and the bare machine. The only two places it genuinely *strains* a
substrate are small and precisely located: **bignum-free integer width** (fixed-width languages must
carry the CBOR head-form + the `[2⁶³, 2⁶⁴−1]` self-test) and **thread-local-free concurrency** (Scratch
has no per-request variable scope, so it *structurally* cannot process requests concurrently — it must
serialize or cooperatively yield). Neither is a defect; both are the substrate failing to provide
something the protocol reasonably assumes, and both are one-line profile branches.

That portability, demonstrated concretely across 45 substrates, *is itself the primary result.* A spec
that lands unchanged on compiled, interpreted, array, stack, pure-object, prototype, decimal, dataflow,
and visual substrates is not accidentally baked to one runtime model. Most protocols never get this test;
entity-core passed it.

### 4.2 The spec-discovery yield: F1 → F41

The findings register runs from F1 to F41 (with gaps — some ids were merged or renumbered across branch
merges, and the entries split across `arch` / `research` / `operator` tags, not all spec-side). The exact
count matters less than their *distribution over time*, which is the important thing:

- **The wire surface saturated early.** Findings on the byte-level contract — the ECF fixture (F1), the
  empty-map hash (F5), large-uint coverage (F7), FFI symbol hygiene (F9), array-of-maps head boundaries
  (F29), the tag-reject scanner (F30) — clustered in the first ~15 peers and **stopped**. By the
  alien-substrate sweep (Tcl/Rexx/Forth/Smalltalk/Fortran/APL), the last corpus asks (F29/F30) closed and
  nothing new arrived. Every distinct integer/float/string/byte, crypto, concurrency, object-model, and
  execution-mode axis had been probed, and the well was dry. **Adding language #N stopped teaching us
  about the wire around peer 15, and never resumed.** This is a *finding about the finding process*: past
  the point where the wire-touching axes are saturated, breadth buys generator robustness, not spec
  discovery.

- **The authority interior was the last productive vein.** The findings that kept coming — and the
  deepest ones — were not about bytes. They were about the *dispatch and authority semantics*: the
  auth-vs-authz status boundary (F14/F20/F32), the §6.5 auth-before-resolve invariant (F31), the
  cross-peer capability-resource canonicalization surface (the §PR-8 dispatch + chain-attenuation
  surfaces, closed 6-way), and finally the authority-as-query pair (F40/F41). This is the region where
  substrate diversity kept paying, because different substrates *force different readings of the same
  authority prose.*

### 4.3 The CBOR story — the one thing that never comes for free

**Canonical CBOR (ECF) is the single most universal "doesn't come for free."** *No platform library
suffices* — not Rust `ciborium`, not .NET `System.Formats.Cbor`, not `cborg`, not `SwiftCBOR`, not any of
them. Every peer, in every language with a CBOR library, still hand-rolls three things on top of it: the
**shortest-float ladder** (f16/f32/f64 minimization — RFC 8949 §4.2.2 is a *suggestion*, ECF makes it a
MUST), the **recursive major-type-6 tag-reject** (ECF forbids tags anywhere in the tree; libraries accept
them), and the **length-then-lexicographic key sort on encoded key bytes** (some libraries do bytewise,
some do nothing). This finding replicated *eight-plus times* (the "A-005" pattern in the ambiguity logs) —
across ML, Lisp, BEAM, systems, and array languages — until it was simply assumed.

Two structural consequences fell out of it:

1. **It justifies the C-ABI codec.** Because canonical ECF is a from-scratch job in every language
   anyway, a single well-tested C/Rust implementation behind `libentitycore_codec` is *more* trustworthy
   than N hand-rolls, and languages without the appetite can consume it. The FFI layer is not a crutch;
   it is the rational response to "no library will ever do this for you."
2. **It makes a from-spec C codec reasonable.** The same reasoning that says "you'll hand-roll it anyway"
   says the reference C codec is a fair amount of work but not exotic work.

A caution the polyglot friction sharpens, and which §8.3 picks up: **most of this cost is intrinsic to
"canonical CBOR," but not all of it.** RFC 8949 §4.2 deliberately leaves canonicalization choices to the
application (which is why no stock encoder is ECF-exact, and why the IETF is standardizing CDE + per-app
profiles — ECF is structurally one such profile). Tag-reject and key-sort are forced by the
content-addressing requirement. The **shortest-float ladder is not** — it is a *chosen* profile point, and
the direct comparator (IPLD's DAG-CBOR) chose the opposite (f64-always). That distinction is the seam
between "forced cost" and "chosen cost," and it is where §8 looks for reductions.

A subtle reconciliation surfaced here and is worth recording: the byte-exact ordering target is the Go
encoder's RFC 8949 **§4.2.1 Core Deterministic** (bytewise-lexicographic on encoded keys), while the
C-ABI spec prose described it as "length-then-lex (CTAP2 / §4.2.3)." For the core entity maps (all
text-string keys) the two orderings *coincide*, and C# `Ctap2Canonical` was verified byte-identical to
the fixture including the 23-vs-24 length boundary — but the wording should be reconciled to §4.2.1 (F4's
residual doc nit). *Two canonicalization rules that agree on the corpus but are described inconsistently*
is exactly the kind of latent interop hazard the polyglot method is good at flushing out.

### 4.4 The crypto story — a spectrum with one fault line

Crypto availability is not binary; it is a **spectrum the S1 profile must classify each peer onto**:

1. **native-stdlib** — Ed25519 + SHA in the standard library (Go, recent JDK, Odin `core:crypto`).
2. **native-audited-lib including Ed448** — Haskell `crypton`, Elixir/Erlang OTP `:crypto` (OpenSSL).
   These are the *full-agility* peers.
3. **native-pure-language** — Common Lisp `ironclad` (pure-Lisp Ed25519 + Ed448 + SHA, KAT-gated; a
   larger trust surface than an audited C primitive, but genuinely FFI-free).
4. **gap → hybrid-FFI** — OCaml, Zig, Swift, Julia, Nim, Crystal: Ed25519 + SHA are native, but **Ed448
   is the fault line** — the one primitive that most often forces the FFI seam, via `libentitycore_codec`.

The durable design lesson: **Ed25519 + SHA are broadly native; Ed448 is where the seam appears.** And the
seam is deliberately scoped to an **opt-in sub-library**, so the shipped default core peer stays
self-contained and FFI-free — a peer that needs Ed448 agility opts into the FFI dependency; a peer that
doesn't, ships clean. That the two curves are separable in the dependency graph *because* they are
separable in the wire format is a genuinely clean property. The friction data (Ed448 is the single most
common FFI trigger) initially reads as a cost worth questioning — but under the **timeless-design target**
(§8.2a) the agility is *coherent, not excess*: a frozen-core protocol that promises never to reopen core
must carry the algorithm table up front, or "add an algorithm" becomes "reopen the core." §8.4 works this
through; the short version is that the WireGuard "one suite, no agility" comparison targets a *mutable*
protocol and does not transfer to a frozen-core one. The remaining questions are narrow (is selection
downgrade-free; is Ed448 the right *second* entry), not "drop the agility."

### 4.5 The integer head-form — a substrate artifact, cleanly separated

The CBOR integer head-form (whether `2⁶³` encodes as a 9-byte `0x1b…` head) and the `[2⁶³, 2⁶⁴−1]`
self-test are load-bearing **only** for fixed-width languages (OCaml int63, C# ulong, TS bigint, Zig u64).
**Bignum languages carry the entire integer range free.** The protocol does not care about integer width;
the substrate does. The correct move — which the profile discipline enforces — is to *branch the profile
by language class* and never treat the head-form as a protocol requirement. That the protocol lets you do
this cleanly (the wire is unambiguous; only the local representation varies) is another small design win.

### 4.6 The concurrency story — four structural shapes

There turned out to be exactly **four structurally-distinct ways a substrate satisfies §7b store-safety
and the §6.11 handler-outbound demux** (correlating an out-of-order `EXECUTE_RESPONSE` back to the
handler that originated the outbound EXECUTE):

| Shape | Peers | §6.11 demux | Cost |
|---|---|---|---|
| Actor-isolation / STM / CSP | Swift, Elixir / Haskell / Go | mailbox · transactional retry · reply channel | ~free (structural) |
| Threads + lock / async | C, Zig, Java, Rust, … | correlation map (request_id → waiter) | a tax |
| Single-thread event loop | Pd, TurboWarp, Io | cooperative yield + one in-flight slot | a yield tax |
| **Dataflow variables** | **Oz/Mozart** | **the variable *is* the demux** | ~free |

The dataflow-variable shape (Oz) is the cleanest §6.11 substrate in the whole cohort: a single-assignment
variable per pending request *is* the correlation map — the reader binds it when the response arrives, the
handler `{Wait}`s on it, dispatch never blocks, and reentry cannot deadlock. No side table, no yield
discipline. It sits exactly opposite the single-thread event loop, which pays the demux as a
cooperative-yield tax. That the protocol's reentry contract maps *this* cleanly onto a paradigm as exotic
as declarative dataflow is a strong signal the contract is expressed at the right level of abstraction —
it constrains the *behavior* (deliver-or-signal, no head-of-line blocking) without assuming a
concurrency mechanism.

### 4.7 Authority-as-query — the deepest protocol insight

The SQL and Datalog peers were the only probes built to interrogate the *protocol* rather than the
substrate, and they returned the exercise's sharpest protocol result (full write-up:
[`evaluations/authority-as-query.md`](evaluations/authority-as-query.md)):

**Authorization is a query; the protocol around it is a state machine.** Everything that is a *pure
function of the projected request facts* — the §5.2 verify ladder, the §5.5 delegation-chain closure,
§5.5a scope-match, §3.6 K-of-N, §6.6 handler resolution — expresses **cleanly and often more legibly than
the imperative spec prose** in both a relational query language and a deductive one. The §5.5 delegation
closure is a `WITH RECURSIVE` CTE / a two-rule transitive closure to least fixpoint — *the exact shape of
the trust-management logics* (SecPAL, Binder, DKAL) that the security literature has used for delegation
for two decades. K-of-N is `HAVING count(DISTINCT signer) >= k`. §6.6 is `ORDER BY length(pattern) DESC`.
Everything *stateful-sequential* (§6.5 dispatch ordering, the §4 handshake, framing, crypto, store I/O)
rightly leaks to the host and the query language fights it.

Two spec-shaped findings came out of it — and they are the most valuable in the whole log because they
are about *how the spec could make correctness structural rather than conventional*:

- **F40 (surfaced by SQL as a real ALLOW bug):** §3.6 scope matching is **typed** — *id-scope* dims
  compare literally, *path-scope* dims compare under §1.4 canonicalization — but the prose reads as one
  uniform `matches_scope`. Encoding it in SQL forced the distinction into the open; the fix *is* the
  split. Two peers guessing the typing differently would disagree on ALLOW for a mixed-dim grant, and no
  vector pins it. A latent interop hazard, made explicit by the relational encoding.
- **F41 (surfaced by Datalog):** the whole §5/§6.6 decision surface is a **monotone deductive system**.
  Authored as bottom-up rules, *fail-closed* becomes "no derived `allow` tuple = deny" (a structural
  property an implementation cannot forget on a new code path, not a fallthrough) and §5.5a's
  "one grant must cover all four dims" becomes a single join (cannot silently drift across edits). No
  wire or verdict changes — every peer already computes the same answer — but specifying the verdict *as
  a derivation* would turn two silently-violable MUSTs into invariants.

And the meta-observation, which is itself a datum: **the wrapper-guard held through S4 on both peers.**
Completing the full live-peer handler surface added *zero* imperative allow/deny to either dispatch path —
the verdict never migrated out of the authored query/rule interior. That the authority logic *stays*
inside the declarative encoding even under the pressure of the higher conformance bar is the strongest
possible evidence that authority genuinely *is* a query, not merely expressible as one.

### 4.8 The two recurring spec-shape families

Standing back from the individual findings, the open arch surface (F32–F41, aggregated in the digest)
clusters into two families that are the most reusable lessons about how a spec and its conformance oracle
co-evolve:

1. **Conformance-green can be vacuous** (F34, F35). A rejection-only oracle category lets a fail-closed
   peer pass without implementing the primitive at all — `multisig` was once 100% malformed→403, so a
   peer that *never verified a threshold signature* passed it. F34 (no vector flips a granter/capability
   signature over an unchanged cap hash) and F35 (the §7a reentry-echo services an inbound reentrant
   EXECUTE with *no §5.2 verification*, so the outbound-authorization seam is never gated) are the same
   shape on the security surface: **the oracle passes a peer that doesn't do the thing.** The keystone
   payoff is the *finding* — an untested, potentially inconsistently-implemented core primitive — as much
   as the fix. The discipline it installed: always add an accept-path test in the direction the oracle
   can't cover.
2. **Silently-violable MUST-prose** (F38, F39, F40, F41). A correctness property that no vector gates:
   mint-timestamp precision (F38 — second-truncation makes same-scope same-second mints hash-identical on
   a content-addressed protocol, and the marathon 403-cascades; *only the full profile exposes it*),
   the open-seed dual resource form (F39), typed scope matching (F40), and the whole authority derivation
   (F41). These are places where the spec says MUST in prose but nothing enforces it, so two faithful
   implementations can diverge. The polyglot method is unusually good at finding them, because a
   substrate whose idioms don't match the prose's hidden assumptions *forces* the assumption into the
   open.

---

## 5. What we learned about *building* (the methodology)

The findings above came from **how** we built, not **which** language — so the method is a result too.

- **The overseer + per-stage sub-agent model.** A peer is built by an overseer that holds the whole
  picture, delegating bounded stages (codec, a handler category, a conformance run) to sub-agents. The
  overseer owns the profile and the GO-gate; the sub-agents own the mechanical work.
  (`protocol-generator/shared/lifecycle/ORCHESTRATION.md`.)

- **The profile decides; the agent doesn't.** Library, error-model, async-style, naming, and packaging
  are all driven by `profile.toml` + `templates/`. An unauthorized decision (picking "the popular
  logger") is a bug; a genuinely underspecified choice goes to the ambiguity log. No language-specific
  syntax ever leaks into `shared/`. This is what keeps 45 peers from becoming 45 bespoke opinions.

- **GO-gate-first, and oracle-pin/fingerprint.** Conformance is the contract, not the version number.
  Every published number is `N·0F @ <oracle-commit>` with the P/W/F/S breakdown; a skip counts as a
  failure. When the oracle re-normalized (`e8524ed` → `cc1970f`), the cohort's core-gate verdict was
  carried forward *provably* via a **comment/format-invariant fingerprint** of the 16-category set + the
  53-type floor (`8261a03…`), not re-asserted by hand — so "0-FAIL" means the same gate for every peer.

- **The wrapper-guard — the single most transferable discipline.** *Author the protocol interior in the
  language; do not wrap a delegated engine.* The visual probes made this concrete: folding §5.2 into one
  boolean **masked three real conformance bugs** (a single-401 grantee carve-out, chain-depth-before-authz,
  and unchecked revocation), recovered only by making the ladder visible on the canvas. A *folded verdict
  is a hiding place.* This generalizes to every peer and every substrate, and it is why the SQL/Datalog
  wrapper-guard result (§4.7) is meaningful rather than tautological.

- **Decomposition surfaces bugs.** The corollary: a single collapsed `dispatch(frame)` call is not a
  paradigm probe, it is a wrapper — and it hides defects. Decomposing folded logic into named units (a
  dispatch spine + one procedure per handler) is both a legibility requirement and a *bug-finding*
  technique.

- **The FFI-seam doctrine.** Draw the FFI seam at what the substrate *genuinely* can't do
  (bytes/maps/sockets/crypto/store) and author everything else. Values the substrate can't hold ride as
  opaque handles; readable fields stay plain. This kept even the assembly and WAT peers *authoring the
  authority interior* rather than shelling out.

- **The cross-peer differential as a first-class debugging tool.** Io's "single-threaded throughput
  ceiling" verdict was *disproven by Oz passing the same checks with slower crypto* — a slower peer
  clearing a bar a faster one can't is a contradiction a ceiling can't explain. It forced re-measurement,
  which found two fixable loop-blocking bugs and retracted the ceiling. A "my substrate just can't" claim
  is only credible once no sibling with a heavier seam has already done it. This is codified in the
  honesty doctrine: **an unreconciled ceiling contradicted by the cohort is an overclaim in the
  pessimistic direction — as much a misreport as a false green.**

- **Verify without the real runtime, when you must.** For substrates where running the real thing is
  hard, an *oracle-driven interpreter of the actual authored artifact* (TurboWarp's `run-blocks.mjs`
  running the real `project.json` block graph against `validate-peer`) gives a faithful, low-risk, real
  number each iteration, with the real-VM run as the final confirmation.

---

## 6. Dynamics visible only at scale

Some things only appear when you hold 45 implementations at once — the reason this exercise sees what a
three-language effort cannot:

- **"Two peers found it independently" is a promotion rule.** When the *same* lesson lands from two
  unrelated substrates, it stops being an anecdote and becomes a **cohort rule.** The resilience-frame
  lesson (a request dispatcher must catch the host's *root* error class → 500, not just the codec's
  condition family) landed independently from Oz (`"" == nil` → an escaped raise) and Smalltalk (one
  `doesNotUnderstand:` cascaded 229 FAILs) — two no-static-check substrates, same root cause, so it is
  now a rule for *all* such substrates. Same for the memory-primary signature-ingestion cap (Io + Rexx)
  and the vacuous-green trap (surfaced on `multisig`, re-derived on the Datalog EDB-dedup path). *You
  cannot see a cohort rule with one peer; the second, unrelated confirmation is the whole signal.*

- **Coupled axes only show up when both ends are built.** "Protocol on three ISAs" and "protocol on the
  bare machine, fastest" turned out to be a *coupled* choice: the FFI-hybrid asm peer is easy on one ISA
  but pays a cross-arch library cost on a second ISA, so pushing toward a pure-asm codec buys ISA
  portability at the cost of per-request throughput. You only discover the coupling by building both the
  x86-64 L1 peer and its ARM64/RISC-V ports.

- **Portable compute is nearly free; the cost is the transport seam.** The decisive control experiment —
  the *same* Rust peer compiled as a native ELF vs as wasm runs within ~1% — was only possible because we
  had both, on one runtime. The generalization (default to *compiling* an existing peer for a new
  execution substrate; reserve hand-authoring for the hot loop) is a scale result, not a single-peer
  observation.

- **The discovery curve itself is a measurement.** Watching *when* findings stop arriving (the wire well
  drying at ~15, the authority vein producing to ~40) is only legible across the whole sequence. It is
  what lets us say "the landscape is near-complete" with evidence rather than hope: the derivative of the
  findings-count went to zero on the wire surface and stayed positive-then-zero on the authority surface,
  in a way no individual peer could show.

---

## 7. The honesty posture (ADR-0012), stated precisely

The project's credibility rests on not overclaiming, so the claims are bounded exactly:

- **Cohort-consistent ≠ independent convergence.** The generated peers share a **generation lineage**
  (one generator, one overseer methodology), **one author's conformance vectors**, and — for the
  FFI-hybrid peers — **the same C-ABI codec**. A cohort of 42 peers all passing is therefore
  *cohort-consistent*, which is real evidence of the spec's implementability and the generator's
  reliability, but it is **not** the same as independent teams independently arriving at the same wire
  bytes. The only genuinely independent bases are the three ground-up reference implementations
  (`entity-core-{go,rust,py}`). The ISA ports are the sharpest case: `asm-arm64` and `riscv64` are
  *byte-identical* to the x86-64 sibling's verdict precisely *because* they share its lineage and FFI the
  same `.so` — the signal there is substrate mechanics, explicitly not convergence. We say this on every
  such row.

- **Every number is reproducible and oracle-pinned.** `N·0F @ <oracle-commit>` with P/W/F/S; a skip is a
  failure; a failure is never labeled "pre-existing" without bisecting; the full-suite total (665) is
  extension-inflated and **non-gating** — the gating number is `--profile core` 0-FAIL, and the
  fingerprint proves it is the same gate across the oracle re-normalization.

- **Conformance-green ≠ correct.** Where a test asserts the wrong thing, or a category is rejection-only,
  green is vacuous (§4.8, F34/F35). The honesty rule and the vacuous-green family are the same coin.

- **Ceilings are claims too.** A pessimistic "the substrate can't" is held to the same evidentiary bar as
  an optimistic green (§6, the Io/Oz retraction).

---

## 8. Is the protocol at its reduced minimum? — the design assessment

This is the crux, and it needs a sharper instrument than the rest of the retrospective, because the
obvious argument for it is **wrong** and worth dismantling first.

### 8.1 What convergence does and does not prove

It is tempting to argue: "45 maximally-different substrates produced byte-identical output and forced no
wire change, therefore the design is minimal." **That inference does not hold, and we do not make it.**
Byte-identical convergence across N implementations is a property of the specification's *determinism and
implementability* — it says the spec is unambiguous enough that independent readings land on the same
bytes. A **bloated** protocol that was nonetheless precisely specified would converge exactly as cleanly.
Convergence proves the spec is a good *function* (same input → same output everywhere); it says nothing
about whether that function is the *smallest* one meeting the requirements. We have never claimed the
absolute minimum, and the convergence data cannot establish it.

What convergence *does* earn is worth stating precisely, because it is not nothing:
- **Determinism** — the wire form is a genuine function of the logical value (a hard prerequisite for
  content-addressing to work at all).
- **Unambiguity** — 45 independent readings did not diverge on the wire (71/71 codec, byte-identical), so
  the spec carries no load-bearing ambiguity on the encoded surface.
- **Implementability across the whole substrate landscape** — no substrate hit a wall requiring a wire
  change or a new primitive.

Those are the properties the sweep actually measured. Minimality is a *different* question and needs a
different method.

### 8.2 The tractable form of the minimality question

Minimality is only assessable if you first **separate what is mathematically forced/derived from what is
a chosen design dimension**, and then hunt — *within the chosen set only* — for (a) redundancy (two
mechanisms doing one job, or a field derivable from others) and (b) friction in excess of the information
the mechanism carries. The forced parts are minimal by necessity (removing them breaks a requirement);
the chosen parts are where non-minimality can hide, because a choice always had alternatives.

**Forced / mathematically-derived — minimal by necessity:**
- *That a canonical encoding exists.* Content-addressing requires one byte form per logical value; two
  encodings → two hashes → the identity model breaks. Derived, not chosen. (IPLD's DAG-CBOR and the
  IETF's deterministic-CBOR work reach the same necessity from the same requirement — external
  corroboration this is intrinsic.)
- *That there is exactly one encoding per value (tag-rejection, definite lengths).* A direct corollary of
  "canonical." DAG-CBOR forbids the same tag surface for the same reason — strong evidence tag-reject is
  intrinsic to content-addressed CBOR, not entity-core excess.
- *That a signature primitive exists.* Authority + cross-peer verification requires it.
- *The authority decision is a monotone derivation (F41).* The sharpest minimality-**positive** result in
  the project: the §5/§6.6 verdict corresponds to a least fixpoint over the projected facts — a canonical
  mathematical object. When a subsystem maps onto a known-minimal structure (here the
  trust-management-logic / Datalog form the security literature has used for delegation for two decades),
  it is *at* its minimum by construction. F40's typed scope-match is the same story: a structure the spec
  already implicitly has, minimal once made explicit.
- *Two wire message types (EXECUTE / EXECUTE_RESPONSE).* Already reduced from a richer model (F3 removed a
  stale HELLO/IDENTIFY/QUERY/ERROR set); everything else is an *operation*, not a message type. A
  deliberate, already-executed reduction.

**Chosen design dimensions — where minimality is actually in question:**
- the base encoding (CBOR) and, separately, its *canonicalization profile*;
- whether the entity model carries floating-point at all;
- the signature-scheme *agility* (Ed25519 **and** Ed448);
- minor picks (Base58 peer-ids, SHA-256) with conventional alternatives and low concern.

There is a further correction to the optimization target itself, and it reframes what "chosen" even
means here.

### 8.2a The optimization target is *timeless minimality*, not *smallest-today*

entity-core is a **frozen-core / timeless design**: the core protocol is meant to be specified once,
tabled, and *never reopened*. Crypto may be added over time, but core protocol does not get amended to do
it. That changes the minimality function. The naive target — "smallest spec that meets today's
requirements" — is the wrong one; the right target is **the smallest spec that never has to be reopened.**
Those differ precisely in how they treat *up-front generality*: generality that a mutable protocol would
defer (add it when needed, in a later version) is, for a frozen-core protocol, *load-bearing now* —
because "add it later" means reopening the thing you promised never to reopen.

This distinction dissolves part of the naive minimality critique. A design that bakes in an
extension/agility mechanism, a universal namespace, or a general capability model is not carrying *fat*
if the alternative is a future core amendment — it is paying the minimal generality that buys
immutability. So the correct question for each chosen dimension is not "is this the smallest thing that
works today?" but **"is this the minimal generality required to never reopen the core?"** The two
candidates below are re-examined under *that* target, and both come out weaker than the first pass framed
them.

### 8.3 The encoding layer — float profile (friction, not a minimality defect)

The shortest-float ladder is the cohort's most-replicated codec friction (§4.3), and the first pass
floated it as a reduction candidate against DAG-CBOR's f64-always. Re-examined, it **does not hold as a
minimality finding**, for three reasons:

1. **The friction is neutralized by our model, not intrinsic to it.** CBOR *does* define canonical
   floats; the ECF profile pins them. IPLD's DAG-CBOR chose f64-always not because shortest-float is
   unimplementable but because IPLD is an *uncoordinated* ecosystem — many independent encoders, no shared
   conformance oracle — so it removed the degree of freedom that implementers were getting wrong in the
   field. entity-core is the *opposite* situation: a keystone + a byte-exact conformance corpus that every
   one of 45 substrates passed. The exact failure mode DAG-CBOR's rule prevents is the one our apparatus
   already prevents. So the comparator's *reason* does not transfer.
2. **The empirical signal is absence.** Across 45 substrates — assembly upward — no float defect ever
   reached the wire. If shortest-float were a genuine minimality hazard we would have a vector failing
   somewhere; we do not. Floats are rare-to-absent in the actual entity model (timestamps are ms-ints,
   F38), so the ladder is cost paid once per implementation, not an ongoing correctness risk.
3. It is a **friction** observation, not a **minimality** one — and it is friction the conformance model
   absorbs. Recorded as such (F42, reframed) and *dismissed* as a design-review item.

The honest residue: the ladder is a real per-implementation *cost*, worth a line in the friction ledger,
but with the keystone + corpus in place it is not evidence the encoding is non-minimal, and no reduction
is warranted.

### 8.4 The crypto layer — agility under a timeless-design target

The first pass framed Ed25519+Ed448 agility as a reduction candidate against WireGuard's single fixed
suite. Under the timeless-design target (§8.2a) that framing **inverts**. WireGuard and entity-core are
optimizing *different* things:

- **WireGuard** optimizes a *mutable* protocol: no agility, one suite, and if a primitive breaks it ships
  a new protocol *version*. Agility is unnecessary precisely *because* WireGuard is willing to reopen and
  reversion itself.
- **entity-core** optimizes a *frozen* core: it promises never to reopen core protocol. For that promise,
  built-in crypto agility is not excess — it is *the mechanism that keeps the promise*. Adding an algorithm
  later must not require a core amendment, so the agility table has to exist up front. Ed448 was chosen
  deliberately as the second algorithm exactly to exercise and prove that table from day one, not because
  a single request needs it.

So the WireGuard comparison, correctly read, *supports* entity-core's choice rather than indicting it:
the two designs make opposite agility decisions because they make opposite immutability decisions, and
each is coherent with its own goal. The security-literature caution about agility (downgrade surfaces,
config sprawl, audit burden) is real and worth carrying — but it targets *runtime-negotiated* agility with
a large combinatorial suite space, which is not what a fixed, spec-tabled two-entry algorithm table with
per-key (not per-session-negotiated) selection is. The residual, much narrower, legitimately-open
questions are therefore *not* "should core drop Ed448": they are (a) is the *selection* mechanism free of
a downgrade surface (per-key/tabled, not negotiated — appears yes, worth an explicit statement), and
(b) is Ed448 specifically the right second entry, or would a different second algorithm exercise the table
as well at less FFI cost. Both are refinements within a sound design, not a reduction. F43 is reframed
accordingly: the agility is coherent with the timeless-design goal; only the selection-surface and the
choice-of-second-algorithm remain as narrow notes.

### 8.5 A redundancy checked and cleared

The **dual "signature" construction** (F36 — the corpus/codec `signature` signs canonical ECF bytes;
§7.3 signs the content_hash) was checked as a possible redundancy: two signed messages under one word. It
is **not** true redundancy — the two serve different layers (a codec-level raw-signer primitive vs the
protocol-level entity signature), and neither is derivable from the other in a way that removes a use.
The residual issue is exactly what F36 already says: a naming/doc hazard, not a duplicated mechanism.

### 8.6 The protocol-logic layer — the authority, capability, and message model

The encoding/crypto layer above is the *substrate of the substrate*. The layer that actually is
"entity-core" — the message exchange, the authority algorithms, the capability system, the namespace — is
where the minimality question has more to say, and where the cohort's most distinctive asset applies: we
built the authority interior in **three different logic paradigms** (top-down Prolog, bottom-up Datalog,
relational SQL) plus the imperative cohort. That triangulation is the sharpest instrument we have for the
*logic*, because a structure that expresses natively in all three logic forms *and* the imperative one is
almost certainly at (or near) its intrinsic shape.

**8.6.1 The authority core is a minimal relational structure — with exactly three necessary
non-relational complications.** All three logic paradigms expressed the §5 authority interior *natively*
and converged on identical wire behavior. Prolog wrote §5.5 chain verification as a recursive relation
where **deny *is* conjunction-failure** — no boolean flag, no `if (!ok) return DENY`, the spec's "valid
iff …, recursively" written verbatim (`verify_chain/3`). Datalog derived `allow` as a least fixpoint
(deny = absence of a tuple, F41). SQL wrote the chain as a recursive CTE. Three independent logic forms,
one structure — strong evidence the authority core is *intrinsically* relational and carries no fat.

But each paradigm, at exactly one point, hit something the pure relational form could **not** express — and
those three points are the same three places, which is the real result:

- **Prolog (A-PL-006): the verdict is not a boolean, it is a *typed* deny.** Prolog failure is
  mono-valued — it means "no," and cannot carry "no, the *401* kind vs the *403* kind." The one verdict
  that must diverge in status *class* (the §5.5 unresolvable-grantee → 401, distinct from every 403 deny
  around it) forced a *second channel* (a thrown marker), because relational failure alone collapses it
  into the 403s. This says the auth/authz split (401 vs 403) is a **genuine kind distinction**, not a
  numbering choice — the same thing F14/F20/F32 chased in the status prose, here proven structurally by the
  paradigm that makes mono-valued failure first-class.
- **Datalog (F41): the derivation is monotone, but revocation and expiry are not.** Grants compose
  monotonically (more grants → more authority); revocation and TTL are the non-monotone overlays. The
  design already *isolates* the non-monotone part to the smallest possible surface (temporal guards fold
  into the chain walk; the harder revoke-*cascade* semantics are pushed to an extension, F19, while core
  keeps revocation as check-at-use). Isolating non-monotonicity to a minimal overlay over a monotone core
  is itself a minimality-positive structural choice.
- **SQL (F40): scope matching is typed, not uniform.** id-scope dims compare literally; path-scope dims
  canonicalize. The relational encoding forced the hidden typing into the open (as a real ALLOW bug whose
  fix *is* the split).

The finding: **the authority core is a minimal relational structure with exactly three necessary,
load-bearing, non-redundant complications — a typed verdict, a monotone-core-plus-non-monotone-guards
temporal model, and typed scope matching.** None is fat; each is forced by a real requirement (authn ≠
authz; capabilities must expire and revoke; peer-ids ≠ resource paths). The spec under-specified two of
them in prose (F32, F40) but the *structure* is minimal. This is a much stronger minimality result than
anything at the encoding layer, and it is only visible because we implemented the logic three different
ways.

**8.6.2 Dispatch uniformity — one verb, one path, one namespace.** The message model is aggressively
reduced and the cohort corroborates the reduction is real, not accidental: **two wire message types
(EXECUTE / EXECUTE_RESPONSE)**, and *everything else is an operation on a handler in one universal
namespace* — connect/authenticate, tree, capability, handler-register, and even compute are handlers
dispatched through the *same* §6.6 `(handler, operation)` path. Three structurally different dispatch
mechanisms reached byte-identical §6.6 behavior — an imperative match-ladder, CLOS's metaobject method
table, and **Prolog's clause database as the router** (adding an operation = adding a clause, selected by
unification + first-argument indexing). That §6.6 admits all three means it is specified at the right
*altitude*: it names the dispatch **key**, not a mechanism. Dispatch uniformity (one path for core,
extensions, and compute alike) is the logic-layer analogue of the forced-skeleton minimality — and it is
what makes the extension story (§10) "just another handler on the same path" rather than a new surface.

**8.6.3 The capability system — comprehensive, with one sharp edge that is the price of a real strength.**
Inventory of the core primitives, each exercised by live peers: **mint** (`:request`, grantee = author),
**delegate** (`:delegate`, self-attenuating, same-peer-only, 501 on cross-peer — F13), **revoke**
(check-at-use → 403 core; cascade = extension — F19), **4-dim typed scope** (F40) over a
**granter-relative namespace** (F39), **K-of-N multisig** (root-of-chain only), **chain attenuation**
(§5.5 recursive, per-link granter-frame canonicalization), and **temporal** bounds. The model is
*comprehensive* for core authority — nothing we tried to express (mint, attenuate, threshold, revoke,
expire, delegate, cross-peer-present) fell outside it.

Its sharpest edge is a genuine finding, and the most-corroborated authorization result in the whole
project: the **§PR-8 6-way convergent bug.** All six reference implementations (Go, Rust, Py + three
keystone peers) *independently* mis-handled **granter-frame canonicalization of a capability's resource
across a delegation chain** — each accepted a cross-peer capability it should have denied, until the rule
was tightened (cross-peer caps MUST use explicit resource form; per-link granter-frame canonicalization
in the chain walk). Six independent-ish readings making the *same* authorization error is the strongest
possible signal that a rule was under-specified at exactly that point. And the root cause is instructive:
it is the price of the capability system's best property. entity-core scopes are **granter-relative** — a
grant of `*` means `/{granter}/*`, not the universe (F39) — which gives **automatic least-privilege**: a
capability *cannot* escape its granter's namespace by construction, so over-broad grants are structurally
contained. That relativity is a real security-minimality win (least-privilege is the default, not an
opt-in). But relativity is also exactly what makes per-link canonicalization in a chain subtle enough to
trip six implementations. So the capability system's greatest strength and its sharpest implementation
hazard are the *same* design choice, and the honest assessment is: the choice is right (the alternative, a
flat absolute namespace, would be trivial to canonicalize but would lose least-privilege-by-default), and
the cost is that the spec must state the per-frame canonicalization with unusual care — which, post-§PR-8,
it now does.

**8.6.4 The one under-probed corner (a vacuous-green risk) — refined by the full-spec read in §8.7.4.**
This was written from the running peers before the end-to-end spec read; §8.7.4 narrows it, and the
narrowed form is the one to carry. Two capability features looked, from the peers alone, like they might
be *unexercised on the accept path*: general **caveats** (attenuation predicates beyond the 4 scope dims)
and **non-root threshold placement** (K-of-N appeared root-only). The full read resolves half of it —
multisig is *deliberately* root-only (§5.5 M3, §9.1), so that is not a gap — and clarifies the other
half: the caveat *mechanism* is fully specified and §9.1 **MUST** (constraints/allowances byte-equality
attenuation §5.6; delegation-caveat depth/ttl §5.7). What genuinely remains is only whether the oracle
exercises those attenuation MUSTs on the **accept** path or only the reject path — a coverage question in
the vacuous-green family (§4.8), tracked as **F44** and detailed in §8.7.4. Not a defect; not a missing
mechanism; an oracle-coverage gap.

### 8.7 The full-spec read — the MUST/MAY split *is* the forced-vs-chosen partition

The analyses above worked mostly from the authority interior and the substrate friction. To close the
minimality question honestly, we then read the pinned core spec end to end — every section, every
algorithm (`spec-data/v0.8.0/ENTITY-CORE-PROTOCOL.md`, 4,184 lines). The decisive discovery is that
**the spec already partitions itself along exactly the forced-vs-chosen line this section has been
reconstructing — and it calls that partition MUST (§9.1) vs MAY (§9.3).** We did not have to impose the
frame; §9 *is* the frame, and §9.0 states the thesis outright: *"core = the live hooks; everything above =
optional and replaceable."*

**8.7.1 The mandatory core is genuinely minimal — Ed25519 + SHA-256 only.** The §9.1 MUST list is the
forced skeleton, and it is tight: wire framing, ECF, hash-validation/fidelity, the two message types,
the envelope, the connection handshake, the full capability machinery (verify algorithm, `matches_scope`,
4-dim attenuation + constraints/allowances, delegation chain, delegation caveats, multi-sig), tree
get/put with the two-level check, the handler machinery, and the §6.13 hooks. Crucially, **"Additional key
types beyond Ed25519" and "Additional hash formats beyond SHA-256" are both §9.3 MAY.** This *resolves*
the two candidates the earlier passes chased:

- **F43 (crypto agility) is not merely coherent — it is already at the minimal structure.** Core MUST is
  *one* curve (Ed25519); Ed448 and the tabled PQ algorithms (ML-DSA, SLH-DSA, FALCON, all reserved in the
  §1.5 `key_type` table) are MAY. The default core peer is Ed25519-only and FFI-free *by the MUST/MAY
  split itself*; the Ed448 friction lands only on peers that opt into a MAY. There is no reduction to
  make — the spec already mandates exactly one primitive and tables the rest for timeless migration. And
  the §1.5 table reserving the NIST PQ suites corrects my earlier aside: the agility genuinely *is* the
  PQ-migration mechanism, the strongest possible justification under the frozen-core target.
- **F42 (float / hash-format friction) lives entirely in the MAY layer too.** SHA-256 is the sole MUST
  hash; the multi-format machinery (§1.2/§1.2a) and its two-address-space complexity are all MAY,
  correctly quarantined (single-format networks recommended; heterogeneous = experimental). The minimal
  core touches none of it.

So both encoding/crypto candidates don't just dissolve on argument — they were **never in the mandatory
core to begin with.** The spec's own floor is SHA-256 + Ed25519 + the machinery + the hooks.

**8.7.2 The tree boundary you can defend: composable → extension.** The core tree handler is **two
operations, `get` and `put`** (§6.3), and the §9.5a vector set shows `put` carries **CAS** (via an
`expected_hash` field — zero-hash = create-if-absent, non-zero = swap-if-current) and **delete** (via a
`system/deletion-marker`) as *modes*, not new operations. Everything richer — snapshot, diff, merge,
extract, tracked, non-default trees — is EXTENSION-TREE. The line is principled: **CAS is core precisely
because atomic conditional-write cannot be composed race-free from unconditional get + put; every
operation that *can* be composed from the primitives is pushed to the extension.** This is a textbook
minimal-primitive-set boundary, and it directly answers "was leaving the complex tree ops to the
extension the right call?" — yes, and the criterion (composability) is the reason.

**8.7.3 What the full read confirmed the spec already internalized.** Several of this retrospective's own
findings turned out to be *already folded into the core spec* — the keystone→arch loop is visible in the
text:

- **§6.13 "Extensibility Hook Presence" is the vacuous-green family, made normative.** It literally cites
  *"generated and hand-written peers built precisely to a gate that didn't check behavioral presence have
  shipped non-conformant"* — us — and pins behavioral presence (register/dispatch/emit/outbound-seam) as
  a MUST with three new validate-peer behavioral checks. §8.6.4/F44 is not a novel worry; it is the *next
  instance* of a pattern the spec already established the response to.
- **§5.8 already addresses the §PR-8 cross-peer hazard** with a normative *cross-peer chain-construction
  registry* and a "conformance topology" stating cross-peer provenance is only witnessable by a
  non-issuing third-party verifier (because same-peer verification has identity-collapse). The spec names
  the exact vacuous-green trap for capability chains.
- **§5.10 already formalizes the monotone-core / non-monotone-guard split** (§8.6.1): Layer-1
  (deterministic cross-peer cap verdict) vs Layer-2 (divergent local policy), with time and revocation as
  *declared* Layer-1 inputs. This is much of what F41's authority-as-derivation appendix asks for, already
  present as verdict-determinism prose.
- **§1.4 independently names the namespace relativity as "the single most-recurring cross-impl bug
  class"** — the same finding §8.6.3 reached from the capability side, here at the path layer, in the
  spec's own words. Confirmation from two directions that granter/peer-relative addressing is the design's
  sharpest hazard *and* its least-privilege-by-default strength.
- **§6.8 defends the confused-deputy hazard in both directions** ("no silent escalation" + "propagated
  caller capability is not a dispatch gate") — the capability model is comprehensive on the classic
  capability-system attack.
- **§1.9 and §1.11 are the spec's own minimality discipline**: §1.9 explicitly separates the
  "structural/mathematical" layer (would be rediscovered by any implementation — forced) from the
  "design/naming" layer (chosen convention), and §1.11 minimizes the entire normative surface to *boundary
  bytes*, leaving internal architecture free. The spec was built with the forced-vs-chosen distinction in
  hand.

**8.7.4 The genuine residues from the full read.** After all of the above, two small *current* items
survive as things arch might act on (§8.7.5 adds one further *forward-looking* note, F46):

- **F44, narrowed.** The caveat *mechanism* is not absent — it is §9.1 MUST (constraint key-retention +
  byte-equality, allowance key-containment + byte-equality, §5.6; delegation-caveat depth/ttl, §5.7). And
  "non-root thresholds" is *not* a gap: multi-sig is deliberately **root-only** (§5.5 M3, §9.1). So F44
  collapses to a single precise question: are the constraint/allowance/delegation-caveat *accept paths*
  exercised by an oracle vector, or only their reject paths? A MUST mechanism with only rejection coverage
  is the vacuous-green shape (§4.8), and §6.13's precedent is exactly how arch closes such gaps — a
  behavioral accept-path vector.
- **F45 (new, minor).** §6.5's `ingest_envelope_signatures` binds *every* `system/signature` in
  `envelope.included` at its invariant-pointer path. The request's *own* author signature has
  `target == the request root hash` — unique per request — and is consumed inline by `verify_request`,
  never looked up post-dispatch, so binding it grows a memory-primary store by one entity per request.
  Two peers hit this independently (Io A-IO-022, Rexx A-RX-014) and it was adjudicated impl-side ("spec
  §6.5 is fine"). Reading the literal algorithm, it *does* prescribe the growth; a one-line spec note
  ("signatures whose target is the request root are consumed inline and need not be persisted") would
  spare every future memory-primary peer the rediscovery. Low priority, offered as a clarity note, not a
  correctness defect.

**8.7.5 Completing the read — the type system (§2) and the handshake (§4).** The final two sections the
first full pass had only touched via findings both came back clean, and the handshake produced the
decisive close on the crypto-agility question.

*The type system (§2) is minimal and progressive.* It is **leveled** (§2.11): Level 0 "unaware" is a
*fully functional* protocol participant — the type system is opt-in enrichment, not a participation
requirement. Level 1 publishes the self-describing type vocabulary as data; Level 2 adds structural
validation; *constraint* validation (ranges, patterns, enums) and the rich type operations (compare,
converge, adopt, reconcile) are all pushed to EXTENSION-TYPE. Core carries only the structural vocabulary.
Single inheritance only (§2.9 — no multiple inheritance), a clean field-spec "exactly one of
type_ref/array_of/map_of/union_of/type_param" invariant (§2.2), eight primitives one-per-CBOR-major-type
(§2.4), and open-types-preserve-unknown-fields (§2.10, forced by content-addressing). The elegant core is
the **four-address-primitive basis** (§2.6): content (hash), naming (path), type (name), identity
(peer-id) — an orthogonal decomposition of "how anything is addressed," one dedicated type each. Nothing
to reduce; the one non-trivial generality (generics via `type_params`/`type_args`) is inert for
non-validating peers.

*The handshake (§4) is minimal and closes F43.* The mandatory handshake is **two round-trips** — `hello`
(negotiation + nonce) and `authenticate` (proof-of-possession + initial capability) — all carried over the
*same* EXECUTE/EXECUTE_RESPONSE types (they are operations on the single pre-authorized path
`system/protocol/connect`, §4.2), with the symmetric reverse-`authenticate` (leg 3) **deferred** until a
serving-initiator use case surfaces (F15; YAGNI). Proof-of-possession is three necessary checks
(nonce-echo/replay §4.6.1, signature/possession §4.6.2, identity-binding §4.6.3), and the 401
(authentication) vs post-handshake 403 (authorization) boundary is stated cleanly — the spec side of the
F14/F20/F32 lineage.

The decisive finding is in **§4.5's negotiation typology**, and it *fully closes F43's last residual
note*: negotiated hello fields are either a **"single active value"** (hash_formats, compression,
encryption — not identity-bound, collapsed to one per connection) or an **"accept-set"** (`key_types`).
`key_type` is an accept-set *because it is identity-bound* — each peer signs with the fixed key its
identity holds and cannot adopt another, so there is **no single "connection key_type" to downgrade.** The
advertised set is what a peer can *verify*, and negotiation is only a mutual-verifiability check. This
means the crypto-agility downgrade attack the security literature warns about — a MITM forcing both sides
onto a weaker mutually-supported algorithm — is **structurally impossible** on entity-core's signature
agility, and the spec's accept-set-vs-single-active-value distinction exists precisely to guarantee it.
So F43 is closed on all three angles: minimal-by-MUST/MAY (§8.7.1), the timeless-design PQ-migration
mechanism (§8.4), and now *downgrade-free by identity-binding* (§4.5). No residual notes.

Two more confirmations and one new forward-looking item fell out of §4:
- **§4.8/§4.9/§4.10 are more keystone findings folded into the spec** — store-safety, resilience
  (deliver-or-signal), and resource-bounds, each citing "generated peers" and "the §7b concurrency gate."
  §4.8 even names the recognized pattern ("the connection-level analog of … §5.8 … all three close gaps
  where the protocol's silence on a structural property allowed impls to make a buggy choice"). The
  keystone→arch loop again, and the spec has an explicit meta-pattern for this class.
- **F46 (new, forward-looking, low).** The `hello` negotiation is *not* transcript-authenticated: the
  `authenticate` signature covers `{peer_id, public_key, key_type, nonce}` but **not** the negotiated
  single-active-values. This is benign today — `key_type` is identity-bound (can't be downgraded),
  `hash_formats` can only be forced down to the secure SHA-256 floor, and compression/encryption are
  unspecified §9.3-MAY placeholders. But it is a real constraint for the future: **any security-bearing
  negotiated parameter added later — notably a specified frame-encryption mechanism — must be
  transcript-bound into the `authenticate` signature (or run over an already-confidential transport) to
  prevent a MITM downgrade.** Not a current defect (nothing security-bearing is negotiated unauthenticated
  today); a design constraint recorded for whoever specifies frame encryption.

### 8.8 Verdict

**The wire and dispatch core is proven *unambiguous and implementable across the whole substrate
landscape*; it is not proven *minimal in the absolute*, and this analysis does not claim it is.** But
after reading the full spec, the picture is sharper still, and it favors the design substantially:

- **The mandatory core is minimal by the spec's own construction.** §9.1 MUST vs §9.3 MAY *is* the
  forced-vs-chosen partition, and the MUST floor is SHA-256 + Ed25519 + the capability machinery + tree
  get/put(+CAS/delete) + the §6.13 hooks — nothing removable, and all agility/extension already on the MAY
  side. The two encoding/crypto candidates (F42/F43) were never in the mandatory core; they dissolve.
- **The forced skeleton is minimal by construction, and the authority logic is minimal in a way we can
  substantiate**: three independent logic paradigms converged on one relational structure whose only
  irreducibilities are three necessary complications (typed verdict, non-monotone temporal guards, typed
  scope); the message model is one verb / one path / one universal namespace; the tree boundary is drawn at
  composability. Several of the retrospective's own findings turned out already folded into the spec
  (§5.8, §5.10, §6.13, §1.4, §1.9) — the design was built with, and keeps hardening under, the
  forced-vs-chosen discipline.
- **The capability system is comprehensive for core authority** — confused-deputy defended both ways
  (§6.8), attenuation fully specified (§5.6/§5.7 MUST), cross-peer provenance registered and topology-gated
  (§5.8) — with its sharpest edge (granter/peer-relative canonicalization) being the price of its best
  property (least-privilege-by-default), a trade the spec itself flags (§1.4).

So the corrected bottom line, after reading **every section of the core spec**: **we do not claim absolute
minimum, but the mandatory core is minimal by the spec's own MUST/MAY construction, the protocol logic
shows triangulated evidence of being at its intrinsic structure, the type system and handshake are both
minimal (leveled/opt-in type system; a two-round-trip identity-bound handshake), and the full
section-by-section read found no redundancy to remove and no complex-tree-in-core miscall — the boundary
choices are principled.** The residue routed to architecture is small and precise: **F44** (one
accept-path coverage question), **F45** (a one-line §6.5 clarity note), **F46** (a forward-looking
transcript-authentication constraint for any future security-bearing negotiated parameter), and the
already-open **F32–F41** conformance/prose items. **F42 and F43 are closed** — they live entirely in the
MAY layer where the spec already put them, and F43 is additionally downgrade-free by identity-binding
(§4.5), so the crypto-agility critique is structurally inapplicable.

The durable methodological lesson stands and is reinforced: **convergence proves determinism, not
minimality** — but implementing the *logic* in several genuinely different logic paradigms, and finding
they converge on one structure whose only irreducibilities are forced, is about as close to a minimality
argument as an empirical method can get.

---

## 9. Steady state — what maintenance looks like now

The generative phase is over; the maintenance phase is **tier-gated re-runs against amendments**
(`LANDSCAPE.md` tier policy). A Tier-1 lockstep set re-runs on every amendment; lower tiers catch up as
capacity allows — the tier system exists precisely so the roster can grow without the maintenance cost
growing linearly. Core-protocol churn has been near-zero for a long while.

Two things get re-run with special attention on any §5 change: the **SQL and Datalog authority
interiors**, because an authority amendment that the imperative cohort would absorb as a code diff shows
up *there* as a **diff to the derivation** — the clearest possible read on whether a change is monotone
and fail-closed-preserving. That is the standing value of having authored authority as a query.

Adding language #N is *not* on the maintenance path unless a community asks: it buys catalog completeness
and generator robustness, not spec discovery, and the roadmap says so plainly
(`COMPLETENESS-ROADMAP.md`).

---

## 10. Forward — the generator pattern carries to the extension layer

The keystone is only the connection to **core protocol.** The long-term goal is bigger, and this project
was the proof-of-method for it.

The ecosystem is split the way the spec is split:

```
   core protocol  ──anchored by──▶  entity-core-keystone        (this repo: core peers + codec C-ABI)
   entity-systems ──anchored by──▶  entity-systems-generator    (the parallel: extensions + SDK)
   architecture   ──authored by──▶  the spec + the standard-extension definitions
```

`entity-core-keystone` generates *core-protocol* peers. The standard extensions (TREE, CONTENT, IDENTITY,
ATTESTATION, QUORUM, REGISTRY, RELAY) are deliberately **out of scope here** — a community installs those
atop a generated core peer. The parallel-level repo for the extension layer (an *entity-systems
generator*, not called a "keystone" there) will do for the extensions + SDK what this repo did for core:
seed a peer from the spec + oracles + a profile, drive it through the conformance loop, and feed
ambiguities back to the entity-systems architecture.

**What this project de-risks for that phase:**

- **The process is proven.** The overseer + sub-agent model, the profile discipline, the GO-gate,
  the oracle-pin/fingerprint mechanism, the wrapper-guard, and the FFI-seam doctrine all transfer
  unchanged. The extension generator inherits a working methodology, not a blank page.
- **The viability filter is the graduation gate.** `PARADIGM-MAP.md`'s NATIVE / HYBRID-FFI /
  QUERY-NATIVE / WRAPPER-ONLY classes were built as the filter for *which substrates can author
  extensions.* A substrate that could only wrap core (Node-RED) cannot author an extension; a substrate
  that authored the core interior natively (the NATIVE/HYBRID cohort) can. We already know, per substrate,
  which peers graduate — that survey is done.
- **The seed is reusable.** The generated core peers are the substrate onto which extensions install.
  Because they *author* the §6.6 dispatch path (rather than wrapping it), an extension is "just another
  §6.6 handler dispatching through the same path" — dispatch uniformity means the extension layer plugs
  into a surface the core peers already expose. Compute-as-a-handler is the archetype: transferable
  compute is an entity-native handler on the same dispatch path, not a bolt-on.

The endgame the sequence points at: not just *core* on every substrate, but the *full extension set +
SDK* on every substrate — so a peer authored in any of these 45 languages can consume transferable
compute, integrate with the rest of the entity system, and be a full-fledged participant in the
ecosystem, wherever it runs. This project proved the seeding and the process at the core layer; the
extension layer is the same machine pointed at a larger spec.

---

## 11. As a research artifact

The exercise is publishable on its own terms, and worth stating in general form because the insight is
not specific to entity-core: **implementing one protocol across the full breadth of the
programming-substrate landscape is a spec-design instrument, and it measures things N=3 cannot.**

The generalizable claims:

1. **The invariants of a design are what survive translation across the whole territory, and you can only
   see them by translating across the whole territory.** At N=45 the language accidents cancel; what is
   left (here: substrate-neutral wire + dispatch, friction concentrated on two mapped axes) is a property
   of the *protocol.*
2. **The discovery curve is itself data.** *When* findings stop arriving, and *which surface* keeps
   producing them, tells you where a design is saturated and where it is still soft — a measurement of
   completeness with a derivative you can actually watch.
3. **Cross-substrate differentials debug both the implementations and the spec.** A property that two
   maximally-different substrates express differently, or a ceiling one clears that another can't, is a
   finding — about the code *or* the specification.
4. **Some semantics have a natural home paradigm.** Authorization *is* a query / a monotone derivation
   (the trust-management-logic literature said so; our SQL/Datalog peers demonstrated it holds for a live
   protocol under a conformance oracle). Discovering the natural paradigm of a subsystem is a design
   insight you get for free from a wide-enough implementation sweep.

The same experiment run on a trivial protocol ("ping-pong in 45 languages") would still yield method
insights — but it would have little to say about *design*, because there is no design to stress. Running
it on what we take to be a fundamental substrate of computing — a content-addressed, capability-authorized
entity protocol — is what turns "an interesting polyglot exercise" into a genuine instrument for
interrogating a foundational protocol. What that instrument returned, stated without overclaim (§8):
the spec is **deterministic, unambiguous, and implementable** across the entire substrate landscape
(measured, 71/71 byte-identical); its **mandatory core is minimal by the spec's own MUST/MAY construction**
(§9.1 MUST = SHA-256 + Ed25519 + the machinery + the hooks; all agility and extensions are §9.3 MAY — the
forced-vs-chosen partition is the spec's own); and — the strongest result — its **authority logic shows
triangulated minimality**, converging on one relational structure across three independent logic paradigms
(Prolog, Datalog, SQL) whose only irreducibilities are three *forced* complications (a typed verdict,
non-monotone temporal guards, typed scope). The encoding/crypto "reduction candidates" the first pass
floated **were never in the mandatory core** — a full section-by-section spec read (§8.7) placed both in
the MAY layer, closing them. It did **not** — and could not — prove the protocol is at its absolute
minimum; convergence is not a minimality proof. But the MUST/MAY split, the three-paradigm triangulation
of the authority logic, and a full read that found no redundancy to remove and no complex-tree-in-core
miscall together come about as close to a minimality argument as an empirical method reaches — and the
residue is small and precise: an oracle **accept-path coverage** question for the attenuation MUSTs (F44)
and a one-line §6.5 clarity note (F45), not a redundancy.

---

## See also

- **Backbone (operational):** [`SUBSTRATE-TAKEAWAYS.md`](SUBSTRATE-TAKEAWAYS.md) ·
  [`AGENTS.md` "Durable cross-language lessons"](../AGENTS.md)
- **Territory + queue:** [`PARADIGM-MAP.md`](PARADIGM-MAP.md) ·
  [`COMPLETENESS-ROADMAP.md`](COMPLETENESS-ROADMAP.md) · [`LANDSCAPE.md`](LANDSCAPE.md)
- **Per-peer ground truth:** [`CONFORMANCE-MATRIX.md`](../CONFORMANCE-MATRIX.md)
- **Deep-dives:** [`evaluations/authority-as-query.md`](evaluations/authority-as-query.md) ·
  [`evaluations/visual-paradigms.md`](evaluations/visual-paradigms.md) ·
  [`evaluations/wasm-codegen-comparison.md`](evaluations/wasm-codegen-comparison.md)
- **Findings register + arch routing:** [`stewardship/SPEC-FINDINGS-LOG.md`](stewardship/SPEC-FINDINGS-LOG.md) ·
  the F32–F41 aggregate digest in `stewardship/`
