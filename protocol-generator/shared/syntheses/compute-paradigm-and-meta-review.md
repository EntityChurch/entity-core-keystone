# Compute as paradigm · meta-review of the critical review · generation-readiness — corrected

**Date:** 2026-07-19 · **Stance:** third-order review. The retrospective was the builder's view; the
red-team + synthesis were the prosecution and the reconciliation; **this doc reviews *that* review** —
specifically its treatment of compute (RT-15) — and closes three lineage blind-spots the whole
project-survey never drew. It also **corrects two framing errors this analysis itself made** in its first
pass (the ratchet applies to the reviewer too). Companion to
[`synthesis-reconciliation.md`](synthesis-reconciliation.md) and
[`red-team-critical-review.md`](red-team-critical-review.md); both left unmodified.

Compute-corpus citations are to the read-only architecture sibling
(`entity-system-architecture/{specs,guides,docs}`); external-lineage citations are in §6.

---

## 0. Two corrections this analysis owes before it earns anything

The first pass of this review made two errors sharp enough to invalidate its conclusions if uncorrected.
Naming them first, because a meta-review that can't audit itself has no standing to audit RT-15.

- **C1 — "can Keystone generate the compute *extension*" was the wrong question.** Keystone is never
  asked to *build the compute runtime*. It is **given** the runtime (entity-core-go + the compute
  extension + workbench-go, bundled as a target spec) and asked to **author a peer expressed in
  entity-compute subgraphs** against it — the same shape as generating a Go peer, except the *target
  language* is the compute IR and the *runtime* is the given extension. §5 is rewritten around this.
- **C2 — the paradigm is the substrate, not the lambda calculus.** The first pass located the novelty at
  "content-addressed functional code" (which is just Unison, §6). That mislocates it. **Nothing forces the
  substrate to be functional** — compute-lambda is one *frontend*; compute-imperative / compute-datalog are
  equally admissible over the same backend. The invariant — and the actual paradigm — is the **forced
  mathematical structure of the substrate** (content-addressing, reactivity, emission, cascades,
  determinism), into which any computational language lowers. §1–§3 are rebuilt on this.

A third correction, procedural: the first pass kept re-raising "there is no compute oracle" as if it were
the headline. **That was a tic and it was wrong.** `validate-peer` already exercises compute cross-peer,
including *transferable* compute, against entity-core go/rust/py. The oracle **exists as a running
mechanism**; what it lacks is (a) vendoring as a standalone portable corpus and (b) full edge-case
coverage. Stated once, correctly, in §5 — not as a drumbeat.

---

## 1. The paradigm question, answered — substrate, not language

**Is entity-native compute a new paradigm of computing?**

Not of *computation* — and not because it's "just functional." It's not a new theory of computability for
the deeper reason C2 names: **the computational language is swappable.** You could ship a second compute
extension tomorrow — imperative, relational, logic — and the system would be unchanged in everything that
matters, because those extensions are **frontends over a fixed backend.** A paradigm claim pinned to the
choice of lambda calculus would be pinning it to the one part that is incidental.

The paradigm is the **substrate**, and the substrate's structure is **forced, not chosen.** Once you commit
to *deterministic, content-addressed, distributed, capability-authorized* computation, the rest is largely
entailed:

- **Content-addressing forces free structural sharing and memoization** — identical structure ⇒ identical
  name ⇒ valid reuse, with no proof layer. Not designed; entailed. ("The hash *is* the version," GUIDE-CORE
  §3.)
- **Determinism-at-the-materialized-boundary is one root for six payoffs** — transferability, replay/
  save-state, lockstep-with-structurally-impossible-desync, free memoization, safe compilation, and
  **reactivity invariant under compilation** (RUNTIME-CONTRACT §9–§9.1, §10). This is the single sharpest
  result in the whole corpus and it survives every correction below.
- **Reactivity is not added — it's the dependency edges read backwards.** The impure `lookup/tree` edges
  *are* the reactive graph; recompute skips unchanged subtrees (GUIDE-CORE §6). This is self-adjusting
  computation (§6) — and content-addressing makes the dirty-check *free*: hash-inequality **is** the change
  signal, so the change-propagation bookkeeping the ancestors maintained collapses into the store.
- **Emission / cascade bounds are forced by termination** of that reactive propagation (`cascade_limit`).

So the honest verdict: **a new paradigm of *system organization*, not of computation.** It belongs to the
family of von Neumann's stored-program, Unix's "everything is a file," Codd's relational model, the web's
URL+REST, the ledger — organizing paradigms, which is where the historical leverage actually is. None of
*those* was a new theory of computability either. The precise structural fact that earns the entry:

> **Computation is dissolved into the same content-addressed substrate as identity, authority, storage, and
> messaging.** A program, a value, a capability, a message, and a stored fact are *one kind of thing* — a
> content-addressed entity — and "running a program" is handler dispatch through the same §6.6 path as
> everything else (dispatch uniformity, a core MUST). The system is a **distributed compiler whose object
> code is its own database.**

The operator's instinct that this has "the character of a discovered structure rather than an invented
language" is the right register — but *"discovered not invented"* is not itself the interesting claim
(every good design is discovered in that weak sense). The load-bearing claim is narrower and testable:
**the entity system is a *substrate*, in the strong sense** — and that is the frame §1b makes precise.

---

## 1b. Grounding: entity-core is a *hard information substrate* (the methodology frame)

This isn't a new metaphor — it's the project's own academic-methodology analysis, which already classifies
the entity system as a **hard information substrate** in the *same domain-type as the genetic code*. Pulling
it in so the paradigm claim anchors to the existing corpus rather than drifting.
*(Source: the entity-lab-legacy methodology notes — `biology_domain_analysis/analysis-genetic-code-sub-domain.md`,
`abstract_info_domain_analysis/analysis-abstract-information-substrate.md`. Treated as vocabulary/frame,
not ground truth; the current `SYSTEM-ARCHITECTURE.md` layer model is the operational version.)*

Three results from that frame do real work here:

1. **The master variable is evaluator-determinism.** The abstract-substrate analysis finds that a substrate
   becomes **"hard" — a deterministic information machine — exactly when its evaluator crosses a determinism
   threshold (Ev ≥ Ev4).** Biology and the entity system are both "hard"; below the threshold a substrate
   "processes information but unreliably." This *is* the "determinism is the master property" result of §1,
   already formalized — and it says the entity system's determinism discipline (canonical CBOR, integer/
   fixed-point, boundary-hashing) is not one feature among many but **the property that makes it a substrate
   at all.**

2. **Self-referential encoding = crystallization.** The genetic-code analysis names the code's key emergent
   property as *"the code encodes its own reading machinery"* (ribosomal proteins, tRNAs, aaRS are all
   translated *by* the code), and calls this **the crystallization mechanism itself** — the code freezes
   precisely because it and its reader become mutually dependent. **This is not an analogy for the
   self-hosting compute peer; it is the same structural property.** The endgame "the system expressed in
   entity-native compute over a minimal native bootstrap evaluator" (GUIDE-CORE §6) *is* the code encoding
   its own reader. Which sharpens CRC-3 in both directions: the self-hosting peer is not an optional
   flourish (it is the substrate's crystallization property), **and** it is genuinely unbuilt — so by this
   frame, **entity-core is a hard substrate that has not yet crystallized its self-referential encoding.**
   The compute extension is the machinery that *would* close that loop; today it's an interpreter written in
   the host language, not yet the code reading itself.

3. **The genetic-code dispatch parallel is already drawn** (that analysis, Step 11): codon→entity-type,
   amino-acid→handler, tRNA→type/handler registry, aaRS→capability-verification, wobble-degeneracy→multiple
   implementations per type, start/stop→message framing, and **crystallization→"frozen at protocol
   specification."** The entity system is analyzed there as one instance of an *abstract information code*
   with a recurring 6-primitive structure. So "is it a new paradigm" was, in the project's own terms,
   already answered: it's a **member of the information-substrate domain-type**, and the fresh question is
   the *strong-substrate test* below.

**The strong-substrate test — and why the families matter.** What makes something a substrate (vs. just a
system) is **generativity + hosting**: a minimal, frozen core that can *transform itself to support* other
systems — the way genetic code, from a fixed codon table, expresses unboundedly many organisms. The abstract
analysis names this as `Full Op` — *"generative output: output that produces new encoding."* In the entity
system, **compute is what provides `Full Op`** — the substrate producing new programs/handlers/encodings
from within itself (dispatch uniformity: a new handler is just an entity). So the real test of the paradigm
claim is not lineage but **hosting**: *can the substrate host the paradigms that other systems were built
as?* If entity-core can host Unison's code-as-data, Croquet's deterministic replication, and Adapton's
incremental reactivity — subsuming each as a corollary rather than duplicating or conflicting — then it is a
substrate in the strong sense. That reframes §6 from a lineage survey into a **substrate-hosting probe**,
and it is exactly the operator's question ("does the substrate host them? is there conflict? does Unison's
hashing conflict with ours?"). §6 is being rebuilt on this basis as the primary-source research lands.

---

## 2. What this actually teaches (kept, because it survives the corrections)

1. **On languages.** 45 conformant substrates, compute needing "no new primitive," and "the innovation is
   the *lowering toolkit*, not a language" (GUIDE-CORE §8) are the same lesson from two sides: **the
   essential core of computation is tiny and old, and the diversity of programming languages is mostly
   diversity of *frontend ergonomics and effect models*, not of computational essence.** The frontend/IR/
   backend split, taken seriously, makes "a language" a thin lowering pass over a substrate-universal IR —
   and makes the operator's "thousands of languages compiling to entity-subgraph IR as their backend"
   the literal architecture, not a metaphor.
2. **On what "a program" is.** When code is content-addressed data in the same store as everything else, an
   entire category of accidental complexity — dependency resolution, build reproducibility, cache
   invalidation, memoization proofs, versioning — collapses into content-addressing. Unison proved this for
   a *language*; the entity system extends it to a *whole distributed system* (§6).
3. **Determinism-at-the-boundary as the master property** (§1, third bullet) — the teachable design
   principle: choose the one seam where you enforce determinism, and a dozen distributed-systems problems
   become corollaries.
4. **On architecture.** "Everything is a port; effects are declared, not performed" (RUNTIME-CONTRACT §8)
   elevates the pure/impure boundary from an FP nicety to *the* architectural seam — validated against real
   interactive programs, not theory — and the gradient backend (interpret → memoize → native, one IR,
   compilation optional, anchored on the same boundary) is a real answer to the flexibility-vs-speed
   tension: don't choose, make it a dial.

---

## 3. The deflation (the honest counter-weight)

Every bit of §1–§2 is demonstrated in **one lineage** (the go-centric cohort), on **toys** (Life / Snake /
Tetris / Asteroids), with the self-hosting endgame **unbuilt and undesigned** (§5.4). By the project's own
§7 honesty standard, **compute is the *least* independently-verified part of the system** — which is exactly
what sets up the meta-review of RT-15.

---

## 4. Meta-review of the critical review — where RT-15 relaxed its own discipline

RT-15 (RED-TEAM §6e) crowns compute "the strongest single core-vindication datum." That verdict is the one
place the red-team dropped the standard it held the retrospective to. The red-team caught the
retrospective's **acquittal bias** (RT-E5: a review that removed nothing); on compute it exhibited the
mirror image — a **conviction bias**. Six findings.

- **CRC-1 — "sufficient to host its central paradigm" is a category inflation.** The receipts prove core
  *doesn't obstruct* compute (seams pre-drawn: `expression_path` §3.7, entity-native dispatch §6.6, emit).
  Real foresight. But "zero forced *core* change" is the *definition* of a well-behaved extension — QUORUM,
  IDENTITY, TREE all clear it. And calling compute *the* central paradigm, then celebrating that core hosts
  it, is circular: you picked the extension that fits best and crowned it central. Honest form: *core left
  the right seams and compute fits them.*
- **CRC-2 — "no new primitive" is measured against toys, and RT-15 drops the qualifier.** RUNTIME-CONTRACT
  is scrupulous ("still one workload"; Life "near the top of the range") and lists *named amendment
  candidates in flight* (indexed map/fold, `range`, `group_by`, array-concat, sum-types/`match`). RT-15
  imports "no new primitive" flat. Honest form: *no new primitive for the interactive-sim workload class
  probed so far.*
- **CRC-3 — the strongest version of the claim (self-hosting) is undesigned, and the framing borrows its
  credibility.** "The peer itself as a hostable compute program over a minimal native bootstrap evaluator"
  (GUIDE-CORE §6) is the endgame the "central paradigm" rhetoric leans on — and it has **no design** (§5.4).
  The corpus's own deepest frontier pointer, `EXPLORATION-NATIVE-COMPUTE-PEER.md`, is a **dangling citation
  — the file does not exist.**
- **CRC-4 — RT-15 inverts the project's own honesty gradient.** Core-protocol has three independent bases
  *plus* 45 substrates. Compute has go/rust/py — same arch author, same value-model proposals, zero
  non-cohort impls, zero keystone-generated compute peers. So compute is simultaneously the strongest
  *conceptual* vindication (core anticipated it) and the **weakest empirical** one — filed purely as
  "strongest."
- **CRC-5 (narrow) — the interpreted tier is cross-tested; the *compiled* tier would benefit from vendoring
  the existing oracle.** Compute is ratified where it counts: `validate-peer` exercises it cross-peer,
  including *transferable* compute, against go/rust/py — the interpreted tier is not an open question. The
  only genuine residue is that the running oracle is **not yet vendored as a standalone portable corpus**
  (RUNTIME-CONTRACT §13.9), which is what a future *compiled/native* rung (§12.5 posture 2) would verify
  against. A finish-the-vendoring item scoped to the compiled tier, **not** a gap in current compute
  conformance. (Right-sized down from the first pass's over-statement.)
- **CRC-6 — WITHDRAWN.** An earlier draft flagged "three-way ratified" as unverified because source
  *version markers* differed (Go/Rust/Py/workbench). Withdrawn: the value model **is** ratified — validated
  cross-peer in `validate-peer` — and workbench-go is simply further along on *additional* compute work, not
  out of sync on the ratified model. Source-file version strings are not a ratification signal; treating them
  as one was the same version-fixation error the retro warns about. No arch action.

None of this says compute is weak. It says the *verdict language* over-runs the *evidence* — the identical
RT-E critique the red-team leveled at the retrospective, recurring one level up.

---

## 5. Generation-readiness — corrected (peer *in* compute, given the runtime)

The real question: **given the compute runtime as a target spec, can the generator author a peer expressed
in entity-compute subgraphs — and what's missing?** Two sub-questions with opposite readiness.

### 5.1 The target is well-defined; the peer-in-compute is an authoring problem, not a runtime problem

The runtime is a *given* (entity-core-go + `ext/compute` + workbench-go, bundled). The generator's job is to
**produce the subgraph**, not the evaluator. The spec floor is fully built and normative — `EXTENSION-
COMPUTE.md §10.1`: 16 expression opcodes + 4 value/result/error types + 9 builtins + a trampolined
budget/depth evaluator + the reactive engine. And compute is not a TREE/CONTENT-style extension in
keystone's framing — it's an **entity-native handler riding core through the same §6.6 path a generated
peer already authors.** So a peer-in-compute is an **S3-authored subgraph layer**, targetable.

### 5.2 The missing piece is the frontend/lowering compiler — the "generator language"

The transferable subgraph **exists as an artifact** — workbench-go's builder + lowering toolkit
(`compute_builder.go` v3.18; `compute_lower.go` with `LowerRecurse`, `LowerMatch`, `LowerRecord`) already
emits it, and it runs on go/rust/py. **But workbench-go manhandles Go → subgraph** — the lowering is written
*in Go, by hand*, per construct. There is no **language-agnostic generator** that says how to *produce* the
subgraph from a spec. That is the snake-eating-its-tail gap the operator named: the subgraph IR is a fine
*backend* (thousands of languages could target it → transferable compute → run through the compressor /
boundary optimizer), but **the frontend compiler that emits it is the unbuilt part.** This — not an oracle —
is the substantive missing capability.

### 5.3 Two secondary gaps (real, but not the blocker)

- **Keystone has no extension-contract / buildout model at all.** Every generated peer is core-only by
  charter (`AGENTS.md`; `CONFORMANCE-MATRIX.md`). The peers that *do* run compute (rust/py/go) are
  **ground-up, not keystone-generated** — so they are a strong *reference template* but would need reworking
  into the keystone generation model. This is the "any-systems-generator" (`entity-systems-generator`)
  problem the retrospective §10 already names — a keystone-analog for the extension/SDK layer, **named but
  unbuilt**.
- **The oracle needs vendoring + edge-case expansion, not invention** (CRC-5). It runs today; it isn't a
  standalone portable corpus yet. A finishing task, tracked, not a from-scratch dependency.

### 5.4 The self-hosting endgame — the genome — is genuinely undesigned (but closer than "undesigned" for the evaluator)

"The system expressed in entity-native compute over a minimal native bootstrap evaluator" (GUIDE-CORE §6) is
the deep endgame. Status, precisely:

- **You still need a native bootstrap, irreducibly** — `SYSTEM-ARCHITECTURE.md §2` `L_native`: "Evaluator,
  primitive I/O, platform bindings. A few hundred lines per platform. Irreducible minimum." A native kernel
  runs the *first* IR; the genome is minimal-cell-machinery + everything-else-as-IR. `L_native` is already
  marked complete for go/rust/py.
- **The intermediate runtime shrinks to that kernel** — the §4 claim: a peer with `L_native + L0 + L1 + L2 +
  COMPUTE` "can acquire everything else through entity exchange." Everything above the kernel is IR.
- **The evaluator half is effectively designed already** — the **Axis-1 §13 design** (resolved-node walker
  + lexical addressing + live frames + boundary contract) *is* the spec for the compute core of the bootstrap
  evaluator; built and measured (34–163×/tick).
- **What's genuinely unbuilt/undesigned:** (a) the **self-hosting compiler** that reads tree IR (= §5.2's
  frontend compiler, one level up), and (b) the **re-expression of the protocol machinery itself**
  (handshake, verify_request, capability chain) as subgraph — the "compile what we already have into
  entity-native compute" aspiration. The frontier doc that would hold this is the dangling citation of CRC-3.

### 5.5 So "go build the entity-core native compute peer" means, concretely:

1. **Bundle the runtime as a target spec** — entity-core-go + `ext/compute` + workbench-go's builder/lowering
   as the reference, + `EXTENSION-COMPUTE §10.1` as the contract. (Have it.)
2. **Build the frontend/lowering compiler** as a *generatable* artifact, not hand-written Go — the missing
   "generator language" (§5.2). *This is the substantive new build.*
3. **Stand up the `entity-systems-generator`** (extension-contract/buildout model) — or teach keystone
   extensions; either way, the ground-up rust/py/go compute impls are the template, not the deliverable.
4. **Vendor + expand the compute oracle for the compiled tier** (finish, don't invent) — the interpreted
   tier is already cross-tested in `validate-peer`; vendoring it as a portable corpus is what a future
   compiled/native rung would converge against (CRC-5).

---

## 6. The substrate-hosting probe — three families, primary-source, run against §1b's test

The §1b strong-substrate test is: does the frozen minimal core **host** the paradigms other systems were
built *as* — subsuming rather than duplicating them? Three deep primary-source probes (Unison, Croquet/
TeaTime, self-adjusting computation) answer it, and the entity-side verdicts are **verified against the
actual spec + `ext/compute` source**, not asserted. Verdict up front: **the substrate PASSES.** It hosts all
three; it subsumes each ancestor's engineered-at-cost mechanism; there is exactly **one genuine gap**
(concurrent-input ordering), **no true conflict** (the one clash, floats, entity wins), and each family
yields borrowables that *sharpen* the substrate rather than patch it. Each ancestor engineered **one**
property that is a **corollary** here.

*(This corrects the first pass's framing: the point is not "lineage" for its own sake — it is the
substrate-hosting test. Naming an ancestor is trivial; running the substrate against it is the work.)*

### 6.1 Unison — content-addressed code · HOSTS + SUBSUMES + **BUILDABLE keystone target**

**Mechanism** (primary: unison-lang.org/docs; `unisonweb/unison` runtime source). Hashes the *type-checked
AST* (names excluded, dependencies replaced by their own hashes) → **SHA3-512, base32Hex**; mutually-recursive
cycles get a **cycle-hash + component index** (`#x.n`) — a worked scheme for content-addressing *cyclic*
definition graphs, not just DAGs. **Abilities** = algebraic effects (interface + handler + **resume-with-
value**). Runs **standalone** (UCM, or a self-contained `.uc` bytecode artifact; Haskell interpreter, no
native codegen); Unison Cloud is optional. Distributed = ship code, receiver requests the hashes it's missing.

**Build verdict — BUILDABLE** (verified against the runtime's builtin table, `unison-runtime/.../Builtin.hs`):
native raw TCP byte sockets, SHA-256, Ed25519 sign/verify, `Bytes` + big-endian `Nat` encoders + full bitwise
ops + IEEE-754 bit access (`Float.toRepresentation`), fixed-width 64-bit `Nat`/`Int`. Strongest crypto tier —
**no FFI seam**. Two S1-profile notes: canonical CBOR is the usual per-peer hand-roll (all primitives
present); `Nat`/`Int` wrap semantics are documented only by width → pin by the `[2⁶³, 2⁶⁴−1]` head-form
self-test. Ships as `.uc` bytecode (packaging note, not a blocker).

**Host verdict — HOSTS, no hash conflict.** Unison content-addresses the *peer's own source* (SHA3-512 over
the AST); entity content-addresses the *runtime data/wire* (SHA-256 over canonical CBOR the program builds by
hand). Different function, input, and layer; sockets hand you raw `Bytes`, so canonical CBOR is unobstructed.
**Subsumption:** entity's compute extension *is* Unison's code-as-content-addressed-data move — but as one
extension over a general substrate rather than the entire language. **Unison ≈ "the compute extension
promoted to a whole language + toolchain"** → it is the best available **reference design** for compute, not
something to adopt.

**The probe's own payoff — the identity-model axis.** Every prior keystone substrate was novel on a
*wire-touching* axis (int width / float / crypto / string model). **Unison is the first candidate host whose
*own identity model* is content-addressed** — building an entity peer in it is content-addressing hosting
content-addressing, and the clean no-conflict result *is* the finding: the substrate absorbs a host that
shares its central idea without interference. That axis has never been probed.

**Borrowables:** (1) **cyclic-definition hashing** — a canonical scheme for hashing mutually-recursive /
shared-sub-term IR; the tree-of-entities compute IR has mutual recursion (`LowerRecurse`) and must answer
this — *check whether compute already has a canonical answer; if not, borrow `#x.n`.* (2) **dependency-
resolution-by-hash transfer** as the standard compute-code-distribution protocol (generalizes §5.8 closure
transfer: ship IR, receiver pulls missing hashes). (3) **names as separate mutable metadata over immutable
hashes** (rename/refactor without changing identity) — programs-as-entities will need the same name↔hash
indirection. (4) **abilities** as a *typed* model for "effects declared as data" (statically tracked, meaning
supplied by a swappable handler).

### 6.2 Croquet / TeaTime — deterministic replicated computation · SUBSUMES + one CONFLICT (entity wins) + one **GAP**

**Mechanism** (primary: the 2003 VPRI paper read in full; Freudenberg's engineering blog for the realized
system). TeaTime replicates **messages, not state** (each replica computes its own state from the same
inputs); **temporal reflection** = objects as pseudo-time histories with native rollback via a distributed
two-phase commit. The *realized* system (Croquet.io/Multisynq) resolves ordering with a **reflector**: a dumb
central **sequencer + heartbeat, no computation**, that timestamps and **totally-orders external (user)
inputs** and echoes them to all peers; internal scheduled events are ordered by `(now, offset, message-
number)`. The model must be **100% deterministic** — no globals/async/wall-clock, `Math.random` overridden to
a seeded replicated PRNG — and **floats are used freely, betting on IEEE-754/ECMAScript determinism**.
Late-join = serialize + encrypt + upload a snapshot, then replay reflector messages.

**Verdict — SUBSUMES the substrate, CONFLICTS on one technique (entity wins), GAP on ordering.**
- **SUBSUMES** determinism, snapshot, rollback: a Croquet snapshot ≡ an entity **content-addressed state
  hash** (intrinsic, vs serialize-encrypt-upload); Croquet enforces *by discipline* what entity enforces
  *structurally.*
- **CONFLICT, and entity wins it:** Croquet **bets on float determinism**; entity **excludes float**
  (integer/fixed-point). Croquet's float bet is the fragile part of its stack and would not survive its own
  cross-platform ambition — entity's exclusion is vindicated head-to-head.
- **GAP — the real finding: concurrent-input ordering.** Entity's "deterministic replication is free" is true
  for *replay given an agreed input order* — it does **not** decide the canonical order of concurrent inputs
  from multiple peers, which is a sequencing/consensus problem. The runtime-contract's "sync input streams" +
  "tick barrier" quietly *assume* that order exists. This is exactly the problem Croquet's reflector solves,
  and it is where Croquet did its hardest engineering.

**Borrowable — the reflector-as-sequencer, made entity-native.** A per-session tick-sequencer publishes each
tick's **ordered input-batch as a content-addressed entity**, with **same-tick inputs ordered by their
content hash** as the deterministic tie-break (the entity-native analog of Croquet's "message number").
Composes perfectly, duplicates no substrate machinery, and turns the hand-wavy "tick barrier" into a defined
mechanism. (A Croquet "island" ≈ an entity compute-program `state₀ + step` with input ports; the *only*
non-native piece is that sequencer service — application-level, not a substrate change.)

### 6.3 Self-adjusting computation / Adapton / Incremental — incremental reactivity · SUBSUMES detection; the correctness worry **verified and REFUTED**

**Mechanism** (primary: Acar's CMU thesis; the Adapton PLDI'14 paper read page-by-page; Jane Street's
`incremental` source). SAC = a **dynamic dependence graph** + change-propagation (re-run affected readers;
O(1) tracking; cost ∝ *trace distance* = size of the change, not the input — why it's near-optimal for small
edits). **Adapton adds demand-driven**: a `set` only **dirties**; nothing recomputes until an output is
**re-forced**, and then only the dirty subgraph *reachable from that demand* is repaired ("switching" — prior
IC didn't do this). **Incremental adds height-ordered stabilization**: recompute in topological/height order
so each node fires **at most once, after all its inputs are current** → no glitch, no diamond re-fire; plus
demand-gating (only "necessary" nodes — those feeding an observer — recompute). Two orthogonal axes:
**(A) demand-gating** (Adapton + Incremental) and **(B) ordered stabilization** (Incremental).

**Entity verdict — VERIFIED against `ext/compute/engine.go` + EXTENSION-COMPUTE §7:**
- **Change detection — SUBSUMED, free.** Content-addressing *is* the dirty-check: hash-inequality is the
  change signal, skipping unchanged subtrees needs no dirty-flag bookkeeping. At least as strong as SAC/
  Adapton memoization, and cleaner (structural + global).
- **Dependency graph — entity HAS it** (not relying on content-addressing alone). `walkTreeLookups` collects
  every `lookup/tree` path into the §7.1 dependency index; those reads *are* the DDG's read-edges.
- **Demand-gating — INSTALL-GATED eager, not auto-demand-gated (a deliberate design point, not a flaw).**
  Reactive re-eval fires **only for explicitly `install`ed subgraphs** (spec §: an un-installed expression
  MUST NOT reactively re-evaluate). So entity has **coarse *explicit* demand** (installing a subgraph =
  declaring a live materialized view) vs Adapton's **fine *automatic* demand**. This fits entity's "every
  output is a persisted content-addressed entity" model (which *wants* eager materialization — the Adapton
  probe conceded this). The one real efficiency residue: an installed view you *transiently* stop observing is
  still maintained eagerly.
- **The correctness worry — REFUTED.** The Adapton probe feared entity's `cascade_limit` might *silently
  truncate* propagation before fixpoint, leaving inconsistent-but-valid-looking state. Verified false: on
  `cascadeDepth ≥ DefaultMaxCascadeDepth` the engine **freezes the subgraph and writes a `compute/error` at
  `result_path`, skipping further triggers** (`engine.go:350–352`; spec status `"frozen"`; re-install is the
  documented recovery). **Fail-loud and observable, not silently wrong.** Purity + content-addressing give
  confluence (the converged value is order-independent), so the residual is **efficiency/latency** (diamonds
  redundantly recompute without height-ordering; a transient-staleness read window exists because re-eval runs
  in a background goroutine) — **not corruption.** The spec sprung the trap.

**Borrowables (efficiency/latency/liveness — NOT gap-closers, since the correctness worry is refuted):**
(1) **Height-ordered stabilization** (Incremental) — the higher-value, lower-clash borrow: kills diamond
re-fires and the transient window, and offers a *principled* "process-until-the-heap-empties" liveness bound
+ structural cycle detection that could **replace the blunt `cascade_limit`-then-freeze** with a cleaner
story. (2) **Demand-driven laziness** (Adapton) as an **opt-in second mode** for the "fan-out, few observers"
class — gated behind the store-materialization tension (pure laziness fights "every output persisted"),
resolved à la Adapton's inner/outer split (a per-computation annotation, not a global switch).

### 6.4 Synthesis — the substrate-hosting test PASSES

Three previously-separate research lineages, each of which **engineered one property at cost** — Unison the
content-addressed code, Croquet the deterministic replication, Adapton/Incremental the incremental
reactivity — are all **corollaries of one content-addressed, dispatch-uniform, deterministic substrate**
here, plus capability-authority + a wire protocol. Against §1b's test — *does the frozen core host the
paradigms others were built as, subsuming not duplicating?* — the answer is **yes, empirically**: it hosts
all three, subsumes each hard-won mechanism, has **one genuine gap** (concurrent-input ordering — borrowable,
and entity-native via a content-hash tie-break), **no true conflict** (the float clash it wins), and each
family yields borrowables that sharpen it.

This is a **stronger and more honest** claim than "a new/fifth paradigm": entity-core is a **hard information
substrate (§1b) that demonstrably hosts-and-subsumes the three deepest content-addressed / deterministic-
replication / incremental-reactivity systems the field has produced** — inventing none of them, converging
all of them. That *is* the substrate property (§1b: generativity + hosting), shown rather than asserted.
"Unison family" was the right instinct for the *language*; the *system* is the **Unison × Croquet × Adapton
convergence**, and the convergence is the point.

### 6.5 Concrete routes (research → action)

- **Unison as a keystone target → `LANDSCAPE.md`.** A novel **identity-model-axis** substrate (the first
  content-addressed host), **BUILDABLE**, strongest crypto tier. A real candidate to round out the keystone
  space — and the one probe of the three that is literally "build a peer on it" (Croquet and Adapton are a
  framework and a library, not peer-hosting languages, so they are conceptual-fit probes, done here).
- **Croquet input-ordering → the runtime-contract's open questions** (§10.1 tick barrier, §12.7 fairness):
  name the sequencer model (reflector analog; ordered input-batch as a content-addressed entity; content-hash
  tie-break) — an entity-native, no-duplication answer to a currently-*assumed* problem.
- **Unison borrowables → compute:** cyclic-definition hashing (check-then-borrow), dependency-resolution-by-
  hash as compute-code-distribution (generalizes §5.8), names-as-metadata, abilities-as-typed-effects.
- **Adapton/Incremental → the reactive engine (borrows, not gaps):** height-ordered stabilization (evaluate
  as a cleaner replacement for `cascade_limit`-then-freeze) + an opt-in demand-driven mode. Framed as
  efficiency/latency/liveness, since the correctness worry is refuted (freeze is fail-loud).

---

## 7. Bottom line

- **Paradigm:** a **hard information substrate** (§1b — the project's own genetic-code frame), not a new
  paradigm of *computation*; the forced content-addressed reactive structure into which any language lowers
  as a frontend (lambda is incidental). Its self-referential-encoding (the self-hosting peer) is the
  substrate's *crystallization* property — real, and genuinely **not yet built** (CRC-3). The strong claim,
  now shown not asserted (§6): it **hosts and subsumes** the three deepest content-addressed / deterministic-
  replication / incremental-reactivity systems in the field — the **Unison × Croquet × Adapton convergence**,
  inventing none, converging all.
- **Meta-review:** RT-15 over-claims compute in mirror-image of the acquittal bias it caught in the
  retrospective (CRC-1…4; CRC-5 narrowed to compiled-tier vendoring; CRC-6 withdrawn — compute is ratified
  via `validate-peer`). Right-size the RT-15 verdict language; no arch action.
- **Generation:** the peer-in-compute is a well-targeted **authoring** problem given the runtime. The
  substantive missing build is the **language-agnostic frontend/lowering compiler** (workbench-go currently
  hand-lowers in Go); secondary are the **`entity-systems-generator`** (extension buildout, named/unbuilt)
  and vendoring the compute oracle for the compiled tier. Self-hosting genome undesigned except its evaluator
  half (Axis-1 §13).
- **Substrate probes (§6):** the substrate-hosting test **passes**. One genuine gap (Croquet input-ordering,
  borrowable), one buildable new keystone target (Unison, on the untested identity-model axis), and a set of
  borrowables (cyclic-hashing, dep-sync-by-hash, height-ordered stabilization, opt-in demand-driven, the
  reflector-sequencer) — each a sharpening, none a structural fix.

---

*Third-order review. Corrects its own C1/C2/tic before auditing RT-15. Entity-side §6 verdicts verified
against `ext/compute` source + EXTENSION-COMPUTE §7; family mechanisms from primary sources (Unison docs +
runtime; the 2003 VPRI Croquet paper; Acar's thesis + Adapton PLDI'14 + Jane Street `incremental`). Spec/
corpus citations read-only. No sibling-repo writes. Companions unmodified.*
