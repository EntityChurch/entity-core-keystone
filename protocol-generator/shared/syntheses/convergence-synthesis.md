# Convergence Synthesis — takeaways, substrate/extension classification, and the divergence analysis

**Date:** 2026-07-19 · **Role:** capstone of the convergence research thread — ties together
[`compute-paradigm-and-meta-review.md`](compute-paradigm-and-meta-review.md) (paradigm
placement + meta-review of RT-15) and [`convergence-map.md`](convergence-map.md) (the
detailed per-tradition map), and turns them into **decision-grade takeaways for architecture**. Nine research
traditions probed from primary sources across the two docs; this one does the two analyses the operator asked
for — the **substrate-vs-extension classification** of every finding, and the **divergence / choice-point
analysis** — and routes the residue to arch.

**The two operative questions** (the operator's framing, adopted as the spine):
1. **Substrate or extension?** For anything the survey surfaces: does it belong *in* core, or is it correctly
   built *above* core as an extension? The substrate thesis is that if the core is right, everything else
   fits as an extension — so the *default* answer is "extension," and a substrate-touch is the exception that
   must justify itself.
2. **Choice-point or invariant?** Entity-core was *derived from mathematical constraints, not designed* — so
   the question is which of its properties are **forced/attractor** (the same across every valid content-
   addressed federation substrate — the "core before the divergence") and which are **choice-points** (where
   a different goal yields a coherent *version-B/C*). Locating the choice-points is where the design leverage
   is, and where "is entity's pick optimal or just one option?" gets answered.

---

## 1. Headline — filtered through substrate-vs-extension, the survey is a *vindication*

Nine traditions (Unison · Croquet/TeaTime · Adapton/Incremental · blockchain/smart-contracts · differential
dataflow · CRDTs · object-capability/CapTP · actor model · federation [ActivityPub/Matrix/Nostr/ATProto]).
When every finding is classified as substrate vs extension, **~85% lands as "correctly an extension" or
"below the wire"** — i.e. the traditions overwhelmingly show entity *correctly declined* to bake into core
what belongs above it. That is the substrate proving its altitude, not a gap list. The residue that genuinely
touches core is tiny and precise (§3): a few **clarifications of already-emergent invariants**, **one**
plausible **wire-level improvement candidate** (promise pipelining), and a handful of **choice-points that
should be documented as decisions** rather than left implicit.

> **The convergence survey's net result is not "entity is missing things." It is "entity is a substrate at
> the right altitude, sitting on an invariant kernel that three independent federation designs re-derive, and
> the things it 'lacks' are the things a substrate is *supposed* to leave to extensions — built above, paid
> for by whoever needs them."**

---

## 2. The substrate/extension classification (the operational output)

Every surfaced finding, sorted by where it belongs. This *is* the answer to "substrate or extension?" for
each, and it is the filter arch should apply to anything new.

### 2.1 BELOW CORE — implementation/profile concern, invisible on the wire
- **Actor-isolation** as a peer's store-safety mechanism (already one of the four keystone concurrency
  shapes — a `profile.toml` choice).
- **Salsa / differential-dataflow / timely** as a peer's *internal* reactive-engine implementation (a Rust
  peer could build its reactive engine on Salsa; adds no wire/spec signal).

### 2.2 EXTENSION — built above the substrate; the core enables-but-doesn't-mandate; pay the cost you chose
*(The largest bucket — and the vindication. Each is a whole other system's paradigm, hostable on entity's
primitives without a core change.)*
- **The ordering seam** (reflector → BFT → consensus) for deliberately-shared state — Croquet + blockchain.
- **CRDT-typed paths** for multi-writer collaborative data — dissolves the ordering gap where it applies.
- **Matrix-style shared-room state** — a deterministic reduce (power-weighted LWW over signed events) over
  per-peer single-writer logs; needs only {signed entities, content-hash links, subscription, deterministic
  compute} entity already has. *The sharpest "surely this needs core?" case — and it doesn't.*
- **Smart-contract / on-chain adjudication** — entity's authority interior authorable as a contract for
  scopes that want consensus anyway.
- **ActivityPub** social vocabulary · **Nostr** event conventions · **ATProto** repo schema + firehose — all
  application/vocabulary layers over the substrate.
- **The actor programming model** (actors = entities, sends = EXECUTEs, mailboxes = inbox, supervisors =
  supervisor-handlers).
- **Compute-side:** the language-agnostic frontend/lowering compiler (the generation finding); demand-driven
  lazy reactive mode (Salsa/Adapton); height-ordered stabilization; cyclic-definition hashing (Unison);
  distributed frontier progress-tracking (Naiad — heavyweight, only if correct distributed reactivity is
  ever needed); columnar op-log encoding (Automerge — only if CRDT paths land).

### 2.3 CORE CLARIFICATION — make an already-emergent invariant explicit; no new machinery
- **Single-writer-ownership as *the* stated consistency model.** The most important architectural fact of the
  survey (verified against §1.4): entity's default answer to distributed consistency is **single-writer per
  namespace** (the web/git/DNS pattern) — the "fourth option" the CRDT trilemma omits. This should be stated
  *as* the model, with the quadrilemma (single-writer / consensus / det-replication / CRDT-merge) as the
  frame, so the "ordering gap" reads correctly as "the cost of *opting out* of single-writer for shared
  state," not a hole.
- **Revocation as an eventual OR-Set** (RT-9, via CRDTs) — name the convergence-window semantics precisely:
  "use-vs-revoke" is an eventual remove-wins policy, *not* a hard invariant. Don't market "no cap used after
  revocation" as absolute.
- **Membrane-style transitive revocation** (ocap) — confirm the grant-chain-walk already gives region-scoped
  revocation (a revoked link breaks every chain through it) and state it as a *structural invariant* (à la
  F41), not an emergent accident.
- **Document the two conscious conflicts** (§4 of the map): the *speakable-content-hash-names* trade vs
  ocap's topology-hiding, and the *authority/CRDT wall* (authority-bearing state provably cannot be a CRDT).

### 2.4 CORE IMPROVEMENT CANDIDATE — *none survive the minimality bar* (corrected)
- **Promise pipelining** (CapTP/E) — first classified here as the one plausible wire-level addition. **On
  inspection it is a composition, not a primitive, and does not earn core.** Pipelining is "send a call that
  forward-references the result of a not-yet-returned prior call" — which is *structurally a continuation*: a
  suspended computation awaiting a result. You get the same effect by **transferring a CONTINUATION that
  handles the chaining** (EXTENSION-CONTINUATION + INBOX) — it is an **X+M composition** (§ align doc), the
  same shape async delivery takes. So it is genuinely useful but **buildable above core**, and the minimality
  discipline is decisive: *"would it be useful? yes. can you do it in the extensions? yes. then it is not a
  pure primitive, and core stays minimal"* — a peer that never needs pipelining must not be forced to
  implement it. **Reclassified to §2.2 (extension).** Net: the survey yields **zero** genuine core additions —
  a stronger vindication than the first pass claimed.

### 2.5 DOCUMENTED DECISION — a choice-point that should be explicit, not implicit (→ §3)
- **Key-rotation location** (identity-core vs above-core), **identity-binding rationale** (why `hash(pubkey)`),
  and **interaction/resilience posture** (deliver-or-signal vs let-it-crash). These are entity's real
  choice-points; §3 is their analysis.

---

## 3. The divergence analysis — the invariant kernel and the choice-points

This is the deep deliverable: separating what is **forced** (the "core before the divergence," an attractor
every valid content-addressed federation substrate lands on) from what is a **choice-point** (where a
different goal gives a coherent version-B/C). Grounded in the actor probe (one choice-point) and the
federation probe (Nostr/ATProto/Matrix as "entity with one constraint changed").

### 3.1 The invariant kernel — forced regardless of goals

Three independent federation designs (entity, Nostr, ATProto) plus the actor lineage converge on these; the
trustless traditions (CapTP, blockchain) *re-derive* them the moment they cross a trust boundary. This is the
"something more fundamental inside, before the divergence":

1. **Identity is cryptographic** — a keypair, or a hash of one. No probed system has non-crypto identity.
2. **Content-addressing forces a canonical encoding.** Every content-addressing system (Nostr id, entity
   entity-hash, ATProto CID, Matrix event id) had to *define a canonicalization*. The *need* is invariant;
   the *encoding family* is a choice. (Independently re-confirms the keystone's "no platform lib suffices for
   canonical ECF.")
3. **The entire cryptographic dependency surface is two primitives: a hash + a signature.**
4. **Self-certification ⇒ single-writer is the authority attractor.** A signature establishes truth without
   agreement, so per-identity single-writer namespaces fall out for free — entity, ATProto, Nostr converged
   independently. Shared mutable state is the *only* thing that breaks self-certification, and it forces a
   merge/resolution rule (Matrix's state-res). **Single-writer is a genuine attractor, not merely entity's
   preference.**
5. **Untrusted transport that can omit but not forge.** Invariant across the self-certifying systems.
6. **(from the actor probe)** per-unit **serialization**, **isolation / no shared mutable state**, and
   **interaction only by messages to addressable named units** — and, critically, **content-addressing is
   *orthogonal* to the sync/async interaction choice** (a version-B actor-entity keeps the whole crypto
   layer). So the crypto/content-addressed kernel survives *every* divergence probed.

### 3.2 The choice-point table — where valid version-A/B/C substrates diverge

| Choice-point | entity's pick (A) | Coherent version-B/C | Traceable to which entity goal | Verdict |
|---|---|---|---|---|
| **Identity binding** | `hash(pubkey)` (= a `did:plc` genesis frozen, no op-log) | raw-key (Nostr) / mutable op-log DID (ATProto) | frozen-timeless-id + **algorithm-agility** (fixed-width id independent of key alg → PQ-swap without format change) | **choice, goal-forced** — but see rotation ↓ |
| **Key rotation** | **none at identity** (lost key = lost identity) | ATProto rotation op-log; entity's own EXTENSION-IDENTITY quorum-relocation | rotation deliberately placed **above core** (F-PQ) | **coherent IF documented** — the one "possibly incomplete" finding (§3.3) |
| **Interaction + resilience** | sync request/response + **deliver-or-signal** (§4.9) | async mailbox + at-most-once + **let-it-crash**/supervision (actor) | per-request **liveness contract** + built-in correlation | **choice, version-B coherent**; entity's is *stricter* than any sibling |
| **Shared-state model** | single-writer only (shared = opt-in extension) | Matrix state-res / consensus / CRDT | no-coordination-by-default | **attractor** (3 of 4 converge; Matrix pays) |
| **Encoding suite** | canonical CBOR | JSON (Nostr) / DAG-CBOR (ATProto) | content-addressing needs *a* canonical encoding | **attractor (canonicalize) + choice (CBOR)**; CBOR mildly superior to Nostr's JSON |
| **Crypto suite** | Ed25519 + SHA-256 | Schnorr/secp256k1 (Nostr) | timeless-core → **made swappable** (agility) | **choice, made a non-choice by agility** |
| **Determinism scope** | structural (integer/fixed-point, no float) | not needed if no shared compute | **transferable compute** requires it | **choice, goal-forced** |

### 3.3 The one "possibly incomplete" finding — key rotation, and its resolution

The federation contrast surfaced exactly one place a sibling's choice suggests entity might be *incomplete*
rather than merely *different*: **ATProto keeps genesis self-certification (a content-hash id) *and* supports
key rotation/recovery via a signed rotation op-log; entity's `hash(pubkey)` supports neither rotation nor
recovery at the identity layer.** Resolution, stated precisely for arch:
- **It is coherent, because entity puts rotation/continuity *above* core** — EXTENSION-IDENTITY relocates the
  principal onto a quorum handle (RT-1′/F-PQ). Rotation is an *authority* concern, not an *identity* concern.
- **But it must be an explicit, documented decision**, not an implicit consequence of `hash(pubkey)` — the
  federation probe is the second independent derivation (after F-PQ) that the rotation story needs to be
  first-class.
- **ATProto's self-certifying rotation op-log is a second valid design for that extension layer**, alongside
  EXTENSION-IDENTITY's quorum-relocation. A real design input: the identity extension has (at least) two
  attractor-consistent mechanisms to choose between — quorum-handle relocation vs a did:plc-style op-log —
  and should choose deliberately. (Both keep the core `hash(pubkey)` identity unchanged; both live above it.)

### 3.4 The verdict — attractor on the kernel, goal-forced on the choices

**Entity-core sits at a genuine attractor on its invariant kernel, and at goal-forced choice-points
elsewhere.** On content-addressing→canonicalization, self-certification→single-writer, and {hash+signature},
multiple independent designs converge and the departer (Matrix) visibly pays — that is the "core before the
divergence," and it is forced. On identity-binding, interaction, encoding, crypto-suite, and determinism-
scope, entity selected one valid option, and **each selection traces cleanly to a stated goal** (agility →
hashed id + swappable suite; per-request liveness → deliver-or-signal; transferable compute → structural
determinism; no-coordination-by-default → single-writer).

That makes **"derived, not designed" rigorous** in a *first-pass, keystone-independent* form: the *kernel* is
forced (an attractor every content-addressed federation substrate lands on), and the *choices* trace to
goals.

**[CORRECTION — the "version-B, same kernel, different goals" framing was wrong; see
`substrate-theory-alignment.md`.]** A subsequent alignment with the academic substrate theory
(which independently reached the same place via a different method) supplies the accurate frame: there is
**one coordinate system** (six primitives), entity sits at the **(Full everything) join** of the two real
attractors (content-store + message-dispatch), and Nostr / ATProto / the actor model are **lower/partial
positions dominated by entity** — you can *degrade* entity to their behavior (run wide-open, or as a public
store), but you cannot *climb* their kernels to entity's without adding the primitives they lack (which is
just *becoming* entity). So they are **not** "version-B siblings." **BUT the version-A/B/C question is left
open, not closed:** genuinely-incompatible-but-*capable* substrates at *different points* remain possible; the
live candidate is the **interaction axis** (sync `X` vs async `X+M`), unresolved. The two standing results
hold regardless: **one** choice (rotation-location) a sibling suggests entity should make explicit, and
**two** (deliver-or-signal, CBOR-over-JSON) where entity's choice is *superior* to a sibling's.

---

## 4. What goes back to architecture (prioritized)

Keystone routes; arch analyzes and decides. Nothing here is a keystone design decision.

**A. Core-touching — evaluate deliberately (small, precise):**
1. *(Withdrawn — promise pipelining was here; on inspection it is a continuation-shaped X+M composition,
   buildable as an extension, §2.4. No wire-level addition survives the minimality bar.)*
2. **Document the consistency model as single-writer-ownership + the quadrilemma** (§2.3) — reframes the
   "ordering gap" correctly as an opt-out cost, not a hole.
3. **Make the key-rotation-location decision explicit** (§3.3) — rotation lives above core (EXTENSION-IDENTITY);
   state it, and choose between quorum-relocation and a did:plc-style op-log for that extension. (Connects
   F-PQ; second independent derivation.)
4. **Clarify two revocation invariants** (§2.3): revocation-as-eventual-OR-Set (RT-9), and membrane-style
   region-scoped transitive revocation as a structural invariant of the chain-walk (verify §5.5).

**B. Documented decisions / conscious trades — state them, don't change them:**
- Identity `hash(pubkey)` rationale = algorithm-agility + directory-independence (vs raw-key / DID).
- Interaction = deliver-or-signal, deliberately stricter than the actor/Nostr/ATProto siblings.
- The speakable-names-vs-topology-hiding trade (vs ocap); the authority/CRDT wall.

**C. Extension-design inputs (for the `entity-systems-generator` / extension layer, not core):**
- The ordering seam (trust-sized: reflector/BFT), CRDT-typed paths, Matrix-style shared-state-as-reduce,
  the actor programming model, ActivityPub/Nostr/ATProto vocabularies — all confirmed buildable on core
  primitives; each is an extension-authoring guide waiting to be written.
- Compute-side borrowables (§2.2): Salsa lazy mode, cyclic-def hashing, height-ordered stabilization,
  dependency-sync-by-hash, frontier progress-tracking (deferred).

**D. Keystone-side:**
- **Unison as a keystone target** (`LANDSCAPE.md`) — buildable (native TCP/SHA-256/Ed25519/CBOR primitives,
  strongest crypto tier), and the *identity-model-axis* probe (first content-addressed host — an axis no
  wire-touching substrate tested). The one family that is a real peer-build target.
- The generation-readiness picture (paradigm doc §5): the missing build is the language-agnostic
  frontend/lowering compiler; the oracle is vendor-and-expand, not invent.

**Positive results arch can rely on (not action items):** the substrate-hosting test **passes in every
subsystem** — entity hosts and subsumes all nine traditions; its invariant kernel is an attractor three
independent federation designs re-derive; its choice-points trace to goals; and the handful of gaps are
correctly extension-shaped. This is the "the substrate is right" result, earned by adversarial breadth.

---

## 5. Bottom line

The convergence survey set out to close the blind-spots the paradigm review opened (Unison/Croquet/Adapton),
and widened to nine traditions across every subsystem. Filtered through the operator's two questions:

- **Substrate-or-extension:** the survey is ~85%+ **vindication** — the traditions show entity correctly left
  to extensions what a substrate should. **Zero** genuine core additions survive the minimality bar (promise
  pipelining, the last candidate, is a continuation-shaped composition — §2.4); the residue is a few
  *clarifications of emergent invariants* and one *decision to document* (rotation).
- **Choice-point-or-invariant:** entity-core = a **forced invariant kernel** (keystone-independent form:
  cryptographic identity + content-addressing ⇒ canonical encoding + {hash, signature} + self-certification ⇒
  single-writer + omit-not-forge transport) **plus a choice-point selection**. This *independently reached*
  the academic team's six-primitive substrate theory ({E,I,T,M,X,P}, the manifestation-landscape coordinate
  system) — a **convergence of two independent pathways**, aligned in
  `substrate-theory-alignment.md` **without collapsing either into the other** (the convergence is
  the evidence; both await external validation). The "version-B, same kernel, different goals" phrasing is
  **corrected** there to the coordinate-system/partial-level-lattice frame, and the version-A/B/C question is
  **kept open**, not closed.

The strongest single sentence for architecture: **entity-core is the (Full-everything) position that unifies
the two attractors of the content-addressed-substrate coordinate system — the immutable store and the message
dispatcher — with the paradigms of a dozen neighboring traditions all hostable above it as compositions; and
that this was reached independently by the keystone convergence survey *and* the academic substrate analysis
is the corroboration, pending external validation of either.**

---

*Capstone of the convergence thread. Ties `compute-paradigm-and-meta-review.md` +
`convergence-map.md` (both carry the primary-source detail). Nine traditions, primary sources;
entity-side claims verified against `spec-data/v0.8.0` / `ext/compute` where checkable. Read-only on all
siblings; no cross-repo writes. Routes to architecture; makes no core decision.*
