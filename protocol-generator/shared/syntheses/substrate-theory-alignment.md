# Substrate-Theory Alignment — the keystone convergence pathway meets the academic six-primitive analysis

**Date:** 2026-07-19 · **Role:** aligns the keystone convergence survey
([`CONVERGENCE-MAP`](convergence-map.md) + [`CONVERGENCE-SYNTHESIS`](convergence-synthesis.md),
standard CS terminology, external systems) with the **academic team's entity-system substrate analysis**
(their own methodology + terminology, the six primitives `{E,I,T,M,X,P}`). It records where the two agree,
corrects two keystone mis-framings the alignment exposed, and — importantly — **does not collapse either
pathway into the other.**

## 0. The epistemic frame (read first — it governs how this doc may be used)

The keystone convergence survey was run **without reference to the academic substrate theory** — from real
external systems (Unison, Croquet, Adapton, blockchain, CRDTs, ocap, actor, federation) in standard
computer-science terms. It reached conclusions that the academic team's substrate domain-analysis
**independently reached first**, by a different method (the 12-step primitive-extraction methodology) in
different terminology.

**That convergence is the value, and it is fragile.** Two rules:

1. **Do not collapse the keystone pathway into the academic terminology.** The keystone docs stay in their
   own external-systems, standard-CS framing. The moment keystone re-expresses its findings *in* the academic
   theory's terms, it stops being an independent witness and becomes the academic theory talking to itself —
   *"consuming our own stuff."* This doc maps the correspondence; it does not rewrite the keystone pathway.
2. **This is internal cross-corroboration, not external validation.** *Neither* pathway is externally
   validated or released yet. Two internal pathways agreeing raises confidence; it is not proof. Statements
   here are "the keystone survey and the academic analysis agree that X," never "X is established."

With that: the alignment is strong, and it is worth recording precisely because it was independent.

## 1. The academic six-primitive analysis, in brief (their theory, faithfully, flagged as internal)

*(Source: the internal methodology corpus, `entity_domain_analysis/analysis-entity-system-substrate.md`,
"Entity System Substrate: Canonical Domain Analysis." Represented faithfully; this is the academic team's
not-yet-released theory, cited for alignment, not adopted as keystone's own voice.)*

- **Six primitives** `{E,I,T,M,X,P}`: **E** (Entity — typed data), **I** (Identity — hash(canonical(E))),
  **T** (Tree — paths→hashes), **M** (Emit — Store/Bind/Notify), **X** (Execution — handler dispatch),
  **P** (Peer — identity + capability boundary).
- **3+2+1 structure:** `{E,I,T}` **primordial** (eternal information, no time/agency) · `{M,X}` **temporal**
  (time + computational agency) · `{P}` **spatial** (position/perspective).
- **The evaluator variable:** **X is a Kd4 (deterministic) evaluator** — the structural property that makes
  the entity system a *hard* substrate (the analysis's central variable, the same role biology's ribosome
  plays). Below Kd4: an information *tool*; at Kd4: an information *substrate*.
- **The coordinate-system claim:** the six primitives "define the **coordinate system** for all digital
  information substrates. The entity system occupies a specific **high position**. Other software occupies
  lower positions. The entity system is **the map AND a point on the map**." And "(Full everything) is a
  **target, not an attractor** — no existing system fully occupies it."
- **Manifestation landscape (their placements):** Git `(FullE,FullI,T2,M0,X0,P0)`; IPFS `(…P1)`; Nix
  `(…T3,X1)`; **AT Protocol `(E2,FullI,T2,M1,X1,P2)` — "closest alignment; all gaps fences not walls"**;
  **Nostr `(E2,FullI,T0,M1,X1,P2)` — "flat"**; Urbit `(E1,I0,…)`; HTTP/REST `(E1,I0,T2,M0,X1,P1)`;
  **Actor model `(E0,I0,T0,M2,X2,P2)` — "message dispatch; no content identity, no tree."**
- **Two attractors** in the space: (1) content-addressed immutable store (Git/IPFS/Nix), (2)
  message-dispatch-with-structure (HTTP/Actor/RPC). Entity is neither attractor — it is the **join** at Full
  everything.
- **Extensions = bridge primitives** connecting the substrate `{E,I,T,M,X,P}` to the application-architecture
  surface. (This grounds keystone's substrate-vs-extension test.)

## 2. The mapping — keystone's independent kernel ↔ the six primitives

The keystone survey derived an "invariant kernel" from external systems. It maps cleanly onto the academic
primitives — which is the convergence datum:

| Keystone finding (external-systems terms) | Academic primitive(s) | Note |
|---|---|---|
| cryptographic identity + content-addressing | **E + I** (the "EI = content-addressing, constitutive" pair) | keystone's #1 kernel item = the academic core pair |
| content-addressing *forces* canonical encoding | the **canonical()** inside **I** = hash(canonical(E)) | keystone derived the *necessity*; academic encodes it *in* I |
| single-writer ownership (web/git/DNS) | **P** (capability boundary) + the **TP** pair (paths peer-namespaced) | keystone's "quadrilemma 4th option" = P's boundary semantics |
| determinism as the master property | **X at Kd4** (evaluator determinism) | keystone's "master property" = the academic's central hard-substrate variable — the strongest single convergence |
| self-certification (omit-not-forge transport) | **E+I** + signatures | keystone derived it from federation; academic from encoding |
| "the substrate hosts/subsumes the traditions" | entity at **(Full everything)** dominates lower positions | keystone's hosting test = the academic's lattice domination |

Two independent derivations, one structure. The keystone pathway adds **mechanism-level detail** the
position-placement does not carry (the specific borrowables, the per-tradition host/subsume/conflict
verdicts) and **six traditions the academic landscape did not place** (§7).

## 3. The version-A/B/C question — corrected framing, kept open

**Correction (keystone was wrong; the academic frame is right).** The synthesis first cast Nostr/ATProto/
actor as "version-B siblings — same kernel, different goals." That is inaccurate. In the coordinate-system
frame they are **lower/partial positions dominated by entity**: Nostr at `X1` (no open dispatch) + `T0` (no
tree) + `E2` (not self-describing) literally *cannot* host compute or rich types or a namespace **without
adding the primitives it lacks — i.e. without becoming entity.** The lattice is a **partial order**: entity
*dominates*, so it can **degrade** to their behavior (run wide-open capabilities, or as a public content store
— the operator's IPFS point) but they cannot **climb** to entity's. "Remove from entity" is easy; "add
compute/capabilities to Nostr's kernel" is a rebuild. So they are not equal-but-different siblings.

**But the question is NOT closed** (operator's steer, and correct). The coordinate-domination picture is the
*leaning* conclusion, not a proof that entity is the *unique* worthwhile position. Genuinely **incompatible
yet capable** substrates — occupying a *different point* that is not simply dominated — remain possible. The
**live candidate is the interaction axis** (§4): a substrate built on async `X+M` as its interaction
primitive rather than sync `X`. The academic landscape's own **Actor model `(E0,I0,T0,M2,X2,P2)`** is the
message-dispatch attractor *without* the information core.

**RESOLVED (§9, via the async/durability investigation) — and the operator's "not closed" instinct is
vindicated.** The interaction axis is a **genuine incompatible-but-capable fork**, not a domination — but the
fork is the **delivery/resilience *contract*** (entity's **deliver-or-signal** liveness guarantee vs the
actor's **best-effort fire-and-forget + supervision**), **with content-addressing orthogonal** to the choice.
*(An earlier draft mis-located the fork as "content-addressing vs statefulness" and is corrected in §9 — you
can content-address stateful data; entity does.)* A peer commits to one contract; entity's pick traces to a
liveness goal. A real version-A/B at a "different point," not a novel kernel. See §9.

## 4. The interaction axis — why request/response is more primitive than async (the one open choice-point, analyzed)

The operator's question — *"is request/response more primitive than async, or is that REST-brain?"* — resolves
through the primitive structure, and it is **structural, not familiarity**:

- **X is the invariant.** X is a **Kd4 deterministic evaluator** — a *function*: input → **result**. A
  deterministic evaluator *has a return value* by its nature.
- **Request/response is X in its native shape** — the evaluator returns its value to the caller.
- **Async-mailbox is X *decoupled from its result through M*** — dispatch fires (X), the result comes back
  later as an emitted/inboxed entity (M). That is an **`X+M` composition**, and it is *exactly* the
  CONTINUATION + INBOX extensions.

So request/response is more primitive because it is **X alone**; async is **X∘M**, two primitives composed.
This is why entity kept sync in core (X) and put async above (CONTINUATION/INBOX = X+M) — and why "getting
async *into* core fundamentally requires a lot of choices" (operator): you would be pulling M's
emit/ordering/inbox semantics *into* the evaluator. The academic **Actor `(…,M2,X2,P2)`** confirms the shape:
its "async" is X leaning on M — but *without* `{E,I,T}`, so it has no deterministic-result contract to
decouple in the first place. Entity's X *is* Kd4, so it returns, and *recovers* async by composing with M.
**Open caveat (§3):** "more primitive" establishes the layering, not that an async-primitive substrate is
*incoherent* — only that within entity's kernel, sync is the lower layer and async the composition.

## 5. Promise pipelining — corrected to an extension composition (the minimality bar in action)

First-pass keystone called promise pipelining "the one plausible core addition." **Corrected: it is a
composition, not a primitive.** Pipelining = "forward-reference the result of a not-yet-returned call" =
**structurally a continuation** (a suspended computation awaiting a result). You obtain the same effect by
**transferring a CONTINUATION that resolves the chain** — an `X+M` composition, the same shape as async (§4).
The minimality discipline is decisive and is the whole point of the core/extension boundary:

> *Would pipelining be useful? Yes. Can you build it in the extensions? Yes. Then it is not a pure primitive,
> and core stays minimal* — a peer that never needs pipelining must not be forced to implement it. Core is
> minimal **so there is nowhere for design bugs to hide** (the confidence that the logic is right comes from
> irreducibility); that discipline is exactly what earns the frozen-1.0 claim, and it applies to extensions
> too.

Net: **the entire nine-tradition survey yields zero primitives that earn a place in core** — a stronger
vindication than the first pass. Everything is a clarification of an emergent invariant, a documented
decision, or a composition/extension.

## 6. The coral-reef pattern — substrate-enabled, extension-served (the piece keystone first missed)

The operator's "coral reef" — a peer's **static, signed self-representation** that dumb infrastructure serves
while the peer is offline — is real and grounded in the primordial core:
- **`{E,I}` + detached signatures = self-certification.** The core spec makes a capability/entity "attestable
  **apart from where it lives**" via a detached signature (required for anything relayed cross-peer). So a
  peer's signed entities are **self-validating** without the origin online.
- **Served by a `P5` "peer role" (relay / archive / CDN)** — an *extension* (EXTENSION-RELAY / EXTENSION-
  NETWORK), not a core mechanism. Substrate *enables* (self-certification from `{E,I}`); extension *serves*.
- **Integrity + authenticity are free; confidentiality is opt-in.** Signatures give integrity/authenticity
  with no session, which is *why* public serving is safe for those properties. Entity has **only optional
  negotiated frame-encryption** ("empty = no encryption"), **not full session encryption** — a deliberate,
  coherent trade: self-certification needs no session for integrity. The genuine residue (operator's own
  point): public signed content exposes a *different* threat class — traffic analysis, metadata correlation,
  replay of public entities — orthogonal to the integrity the substrate guarantees. **Worth documenting as a
  conscious confidentiality trade**, not a gap; it is the same self-certification-vs-session boundary
  ATProto's relays and Nostr's relays sit on.

## 7. Placing the keystone-probed systems into the manifestation landscape (keystone's contribution)

The academic landscape placed Git/IPFS/Nix/Holochain/ATProto/Nostr/Urbit/HTTP/Actor. The keystone survey adds
the traditions it did not — approximate placements (keystone-side mapping, flagged approximate; the *point* is
that they all fall *inside* the one coordinate space, confirming the framing):

| System (keystone-probed) | Approx. position | Reading |
|---|---|---|
| **Unison** | `(FullE, FullI, T2, M0, X4, P1)` | content-addressed code + compute, *no* reactive emit / thin peer — the `{E,I}`+X-compute corner without `{M,P}` |
| **Croquet/TeaTime** | `(E1, ~I1, T1, M2, X2, P3)` | message-dispatch + deterministic replication; *no* content-addressing (I low) — attractor-2 + replication |
| **Blockchain/contracts** | `(FullE, FullI, T2, M1, X2, P-consensus)` | content-addressed + contracts + a *consensus* elaboration on P; the store attractor + dispatch + global order |
| **CRDTs** | *not a substrate* — an **M** elaboration | a merge-semantics for Emit; a data-type discipline, not a position |
| **object-capability/CapTP** | `(E0/E1, I0, T0/T1, M1, X2, P2)` | capability dispatch (X+P) *without* content-addressing — re-derives `{I,P}`-crypto at the trust boundary |
| **differential dataflow** | *not a substrate* — an **M×X** elaboration | distributed incremental *emit+execute*; a mechanism, not a position |

Two things fall out, both confirming the academic frame: every probed tradition is either a **lower/partial
position** or an **elaboration of a single primitive** (CRDT→M, DD→M×X, ocap→X+P) — none is a rival
full-substrate, and none is content-addressed *and* dispatch-complete *and* peer-bounded at once. Entity
remains the sole occupant of the join.

## 8. Meta-result

Two independent research pathways — the keystone convergence survey (external systems, standard CS terms) and
the academic substrate analysis (12-step methodology, `{E,I,T,M,X,P}`) — **converge on the same structure**:
a minimal content-addressed, self-certifying substrate with a **Kd4 deterministic evaluator**, single-writer
authority, sitting at the **join of the store and dispatch attractors**, hosting every neighboring paradigm
above it as a composition. The keystone pathway independently corrected itself to this frame and, in doing so,
**resolved the async question** (sync = X, async = X+M), **downgraded its last core candidate** (pipelining =
X+M composition → zero core additions), and **grounded the coral-reef pattern** ({E,I}+detached-sig, P5-served).

The convergence is corroboration. It is **not** external validation — both pathways are internal and
unreleased — and this doc is deliberately the *only* place the two are mapped together, so the keystone
pathway stays usable as an independent witness. Keep it that way: cite the convergence, don't dissolve the
independence.

## 9. The interaction axis resolved — a genuine delivery-contract fork (async/durability investigation)

The one genuinely-open choice-point (§3/§4) is now resolved — grounded in the entity design history
(`entity-system-architecture`), not asserted. The resolution *vindicates* the operator's "not closed"
instinct: it is a **real incompatible-but-capable fork** ("different points" — the operator's phrase), not a
domination.

**[CORRECTION — retracts an over-generalization from an earlier pass.]** A prior draft argued "delivery
guarantees need mutable state; mutable state breaks content-addressing; so a version-B must drop the immutable
core (= the actor model at E0,I0,T0)." **That is wrong and is withdrawn.** You *can* content-address stateful
data — that is entity's own model (M/Emit = store a new immutable entity + rebind; "versioning by
construction"). A delivery queue / delivered-set / dedup window / ack log can all be content-addressed tree
entities (entity's "Kafka shape" composition does exactly this). So there is **no** law that delivery-state
can't be content-addressed, and the version-B chain built on it collapses.

**What the receipt actually establishes (narrow, correct).** GUIDE-MULTISIG's *"a use-count would make
verification stateful … which breaks the content-addressed-immutable model"* is about **capability
*verification*, not content-addressing in general.** A cap's validity is *designed to be a pure, stateless
function* of (chain + observed revocations + t) — which is exactly what lets it be **verified offline by
anyone** (the coral-reef / self-certification property, §6). A per-use count would force verification to
consult external mutable use-state, sacrificing that stateless-verifiability — so **at-most-once is pushed to
handlers** (stateful by nature). This is specific to the *cap layer's portability goal*, not a universal.

**Why delivery guarantees are above core (the real, correct reasons — *not* content-addressing):**
1. **Minimality / composability** — already reachable in pieces (INBOX + CONTINUATION + TRANSACTION +
   REVISION); DURABILITY's own post-mortem: the space "was already covered three ways." A coordination
   contract on top doesn't earn core.
2. **Agnosticism** — durable queues / acks / supervision are runtime machinery a wire-boundary protocol can't
   mandate without assuming a runtime (the BEAM point, §10). *This leg stands.*
3. **Policy-choice** — at-most-once / at-least-once / exactly-once are *different trade-offs different apps
   want*; a universal substrate must not pick one for everyone.
4. **(narrow) cap-statelessness** — at-most-once specifically can't be a *capability* property without losing
   offline-verifiability (above).

So the boundary is well-justified by **minimality + agnosticism + policy** — not "doubly forced by
content-addressing." Drop that framing.

**Version-B, corrected — and it restores what the actor probe had right.** The genuine interaction-axis fork
is **not** content-addressing-vs-statefulness; it is the **delivery / resilience *contract*:**
- **Entity: deliver-or-signal** (§4.9) — every admitted request gets a response or an explicit signal; no
  silent drops; the peer stays up. A **liveness guarantee**. (Entity's async fire-and-forget *honors* it: you
  get a 202, and the later delivery is itself a request that also gets deliver-or-signal — async is a *mode
  within* the contract, not a break from it.)
- **Actor: best-effort fire-and-forget** — at-most-once, may be **silently dropped**, no response guarantee;
  reliability is the app's job; failure handled by external supervisor restart (let-it-crash).

These are genuinely different **core contracts** — a peer commits to one — and **content-addressing is
orthogonal to the choice** (both forks can have it; the actor model historically lacks it, but nothing forces
that). This is the operator's exact frame: *capable substrates, incompatible because they chose different
points.* Design-incompatible, real, open — and entity's pick (deliver-or-signal, a liveness guarantee) traces
cleanly to a goal, like every other choice-point. (This is the "dual resilience philosophies" fork the actor
probe identified; the content-addressing argument of the earlier draft was a wrong turn away from it.)

**What entity's X+M actually composes to** (the split, confirmed by the design history): sync request/response
(core X), **async fire-and-forget** (X+M: `deliver_to` + 202-ack + inbox — normative, mature), and
**reactive/deferred** (standing/suspended continuations + subscription). Entity *does* async — three shapes.
What it does **not** provide as *primitives* are the **delivery guarantees** — above core by minimality +
agnosticism + policy (above). The retracted **EXTENSION-DURABILITY** is the discipline *working*: the arch
team caught itself importing message-queue/log-system vocabulary "without a deployment driver" — the repo's
own canonical anti-example ("apparatus ≫ property; the property could have been one V7 sentence").

**The honest residue** (real, unresolved, but correctly *above* core — and arch already tracks all of it; NOT
new keystone findings): (a) durable at-least-once delivery survives only as a *deployment convention* (the
"Kafka shape": retained tree entry + pull-by-`request_id`), not a substrate guarantee; (b) **cross-peer
continuation resumption** is an open L2/G2 gap (chains stay within one peer today); (c) the **durable-execution
collector + crash-mid-flight re-fire** is an *open correctness gap* (RESTART §6.1: "nothing triggers re-fire
of the stuck computation"); (d) **consensus/Raft** is named-and-deferred, never designed (peer-compositions
give clustering-*adjacent* shapes — recovery cluster, service pool — but strong cross-member consistency punts
to "app-level 2PC or quorum-attested ops"). The single slice that might legitimately return to core is the
narrowest: a one-line "MUST return an explicit refusal rather than silently drop a request-side marker" rule
(deferred).

## 10. The agnosticism axis — protocol-not-runtime, and why it discriminates

A high-level design property the first survey under-weighted, and it is **explicit and load-bearing**, not
emergent. The core spec pins conformance **at the wire boundary and nowhere else**: *"the conformance contract
is at the boundary — what bytes a peer emits and accepts. Not internal architecture: how it stores data,
represents entities, what optimizations it applies are all implementation choices"* (§540); *"interop is
preserved by the wire protocol and content addressing, **not by shared internal storage architecture**"*
(§536); and the **concurrency model itself is impl-free** — §1842/§3772 bless "single-writer actor/mailbox,
Lwt promises, async-task-per-frame, native registry" all as valid *internal* shapes. The **45-substrate
result is the empirical proof.**

This axis **discriminates** the traditions sharply:
- **Protocol-agnostic (wire protocol, any-language):** HTTP/REST (the exemplar; entity retains its
  open-dispatch, X2), IPFS, Nostr, ATProto.
- **Runtime-bound (a specific VM supplies the semantics):** Erlang/BEAM (the actor model — supervision,
  mailboxes, hot-reload, at-most-once are *BEAM features, not protocol*), EVM (contracts locked to bytecode),
  Unison (*is* a language + Haskell runtime).

The discriminator: **the protocol-agnostic systems are all at *lower positions*** (Nostr/ATProto: X1, no
compute; REST: E1/I0, no content-addressing). **Entity is the only system that is *both* a language-agnostic
wire protocol *and* a full `{E,I,T,M,X,P}` hard-substrate at Kd4** — the join, now on the agnosticism axis.
And this is the deeper "adopt-a-paradigm-and-lock-yourself-in" point (operator): the actor model adopted
async-mailbox+supervision *as semantics*, and inherited the **runtime lock** (BEAM). Entity specified only the
protocol/math and left the paradigm to implementers — which is *why* it ports, and *why* async-with-guarantees
(the part that would drag in a runtime) stayed above core (§9). **The boundary is justified by minimality +
agnosticism + policy-choice (§9), independently of any content-addressing argument** — a well-placed line,
though not the "doubly forced by content-addressing" framing an earlier draft claimed (retracted, §9).

---

*Alignment layer. The academic six-primitive analysis is represented faithfully as the internal, not-yet-
released theory it is; the keystone convergence docs remain in their own external-systems framing as the
independent witness. Corrects the version-B conflation (→ coordinate-system, question kept open), the
pipelining classification (→ extension), and adds the async and coral-reef reconciliations. Read-only on all
siblings; no cross-repo writes.*
