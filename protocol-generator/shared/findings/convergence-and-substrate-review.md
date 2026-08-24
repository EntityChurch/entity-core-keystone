# HANDOFF-TO-ARCH — Convergence & substrate review (the paradigm / cross-tradition thread)

**Date:** 2026-07-19 · **From:** keystone (research). **To:** architecture (pull on your own schedule).
**Status:** research thread complete; routed for arch analysis. **Nothing here is a keystone design
decision, and nothing was written into any sibling repo.**

## 0. What this is, and its provenance

A capstone route-out of a multi-pass research thread that started as a red-team of the compute-paradigm claim
and widened into a **convergence survey against a dozen neighboring research traditions**, then reconciled
against arch's own substrate analysis. The four source docs (in `research/`, primary-source and
spec-verified where checkable):

| Doc | What it carries |
|---|---|
| `protocol-generator/shared/syntheses/compute-paradigm-and-meta-review.md` | paradigm placement + meta-review of RT-15 (CRC-1…6) |
| `protocol-generator/shared/syntheses/convergence-map.md` | per-tradition host/subsume/conflict/borrowable map (Unison, Croquet, Adapton/DD, blockchain, CRDT, ocap) |
| `protocol-generator/shared/syntheses/convergence-synthesis.md` | takeaways + the substrate/extension classification |
| `protocol-generator/shared/syntheses/substrate-theory-alignment.md` | alignment with arch's six-primitive analysis; async/agnosticism resolution; corrections |

**Epistemic frame (please read before using §2).** The keystone survey was run from **external systems in
standard CS terminology, independent of arch's substrate theory**, and *independently reached a consistent
structure*. That independence is the value — it is a second pathway, not a re-statement of arch's own work.
This handoff routes the **world-facing findings**; where it notes convergence with the six-primitive analysis,
that is offered as **cross-corroboration for arch**, and neither pathway is externally validated yet. Keep the
keystone pathway in its own terms; don't dissolve it back into the theory it corroborates.

## 1. Headline

The substrate-hosting test **passes across every subsystem** — entity hosts and subsumes the paradigms a
dozen traditions were built *as*, each as a composition/extension. Filtered through "substrate or extension?",
the survey is **overwhelmingly vindication**, and after the minimality bar, **zero new primitives earn a place
in core** (the last candidate, promise pipelining, is a continuation-shaped composition). The residue is a few
**documentation/clarification** items and a set of **extension-design inputs** — plus the honest open items
arch already tracks.

## 2. Cross-corroboration (for arch — not an action item)

An outside-in convergence survey independently reproduced the core of arch's substrate analysis: a minimal
**content-addressed, self-certifying substrate** with a **deterministic (Kd4) evaluator**, **single-writer
authority**, sitting at the **join of the store and dispatch attractors**, hosting neighboring paradigms above
it. The keystone "kernel" maps onto `{E,I}` + `X-at-Kd4` + `P`; the keystone "hosting test" is the lattice
domination in your manifestation landscape. Keystone also **extended that landscape** with six traditions it
did not place (Unison, Croquet/TeaTime, Adapton/DD, blockchain, CRDTs, ocap/CapTP) — all falling *inside* the
one coordinate space, none a rival full-substrate. Detail: `SUBSTRATE-THEORY-ALIGNMENT` §2, §7.

## 3. Core-touching — documentation / clarification only (no new primitives)

1. **State the consistency model as single-writer-ownership.** The default answer to distributed consistency
   is single-writer per namespace (the web/git/DNS pattern) — the "fourth option" the CRDT trilemma omits.
   Stating it as *the model* (with the quadrilemma — single-writer / consensus / det-replication / CRDT-merge
   — as the frame) makes the "ordering gap" read correctly as *the cost of opting out of single-writer for
   shared state*, not a hole. (`CONVERGENCE-MAP` §2; `SYNTHESIS` §2.3.)
2. **Clarify two revocation invariants** (emergent today; make structural):
   - **Revocation is an eventual OR-Set (remove-wins policy), not a hard invariant.** The convergence window
     is a CRDT eventual property; "no cap used after revocation" must not be marketed as absolute. This is the
     precise formal frame for **RT-9**. (`CONVERGENCE-MAP` §3.2c.)
   - **Membrane-style region-scoped transitive revocation** — confirm the chain-walk already gives it (a
     revoked link breaks every chain through it) and state it as a structural invariant (à la F41). **Verify
     §5.5.** (`CONVERGENCE-MAP` §3.4.)
3. **One narrow slice that *might* return to core** (already your deferred item): a one-line "MUST return an
   explicit refusal rather than silently drop a request-side delivery marker" rule — the narrowest survivor of
   the retracted DURABILITY. Deferred; noted for completeness. (`ALIGNMENT` §9.)

## 4. Documented decisions / conscious trades — state them; don't change them

1. **The interaction / delivery-contract fork (the resolved open question).** Entity's **deliver-or-signal**
   (a per-request liveness guarantee) is a genuine, incompatible-but-capable *"different point"* vs the actor
   world's **best-effort fire-and-forget + supervision**. It is a real version-A/B at the *already-known*
   message-dispatch attractor — **content-addressing is orthogonal to the choice.** Async is not missing:
   entity ships three shapes (sync = core X; async fire-and-forget = X+M via `deliver_to`+inbox; reactive =
   continuations+subscription). What is correctly *above* core is **delivery *guarantees*** (at-most-once,
   durable, supervision) — by **minimality** (composable from INBOX+CONTINUATION+TRANSACTION+REVISION),
   **agnosticism** (runtime machinery a wire protocol can't mandate), and **policy-choice** (which guarantee
   is per-app). *(Note: a keystone draft briefly argued a "content-addressing forbids stateful delivery"
   structural reason — **retracted**; you can content-address stateful data, entity does. The correct
   justification is the three reasons above + the narrow point that at-most-once can't be a **capability**
   property without losing offline-verifiability.)* (`ALIGNMENT` §9.)
2. **Identity `hash(pubkey)` + key rotation.** The `hash(pubkey)` binding buys algorithm-agility +
   directory-independence but gives **no key rotation at the identity layer** — a lost key is a lost identity.
   Coherent *because* rotation lives above core (EXTENSION-IDENTITY quorum-relocation, **F-PQ**), but it
   should be an **explicit documented decision.** The federation contrast is the second independent derivation
   of F-PQ, and it surfaces a **second valid extension design**: an ATProto `did:plc`-style self-certifying
   rotation op-log (entity's `peer_id` ≈ a did:plc genesis frozen with no op-log). The disposable-peer / actor
   tradition is the rationale for keeping it above core; choose deliberately. (`SYNTHESIS` §3.3; `ALIGNMENT`
   §3.)
3. **Language-agnosticism (protocol-not-runtime) as the load-bearing design invariant.** Conformance is at the
   wire boundary only (§536/§540); the concurrency model itself is impl-free (§1842). This is *explicit and
   empirically proven* (45 substrates), and it is the deeper reason paradigm-bundled semantics (actor
   supervision, EVM execution) stay out of core: adopting a paradigm *as semantics* imports a runtime lock.
   Worth stating as a first-class principle. (`ALIGNMENT` §10.)
4. **Two conscious trades to state:** the **speakable-content-hash-names** trade vs ocap's topology-hiding
   (entity restores safety at the authority layer, not the topology layer); and the **authority/CRDT wall**
   (capability/multisig/invariant-bearing state provably cannot be a CRDT). (`CONVERGENCE-MAP` §3.4, §3.2c.)

## 5. Extension-design inputs (for the `entity-systems-generator` / extension layer — not core)

Confirmed buildable on core primitives; each is an extension-authoring guide waiting to be written:
- **A trust-sized ordering seam** (reflector-class single sequencer → BFT; never PoW) for shared-state scopes
  — the entity-native form publishes each tick's ordered input-batch as a content-addressed entity, same-tick
  ties broken by content hash. (`CONVERGENCE-MAP` §2.4.)
- **CRDT-typed tree paths** (negotiated path-type class) for multi-writer collaborative data — dissolves the
  ordering gap where it applies; op-based CRDT ≡ entity's stream-sync; causal delivery from dependency hashes.
- **Matrix-style shared room state** as a deterministic reduce over per-peer single-writer logs.
- **The actor programming model** (actors=entities, sends=EXECUTEs, mailboxes=inbox, supervisors=handlers).
- **ActivityPub / Nostr / ATProto vocabularies** over the substrate (replacing location-authority with
  content-authority).
- **Compute borrowables:** Salsa red-green as the concrete blueprint for an opt-in lazy reactive mode
  (entity's content-hash = Salsa's green-check, a native fit); cyclic-definition hashing (Unison `#x.n` — for
  hashing mutually-recursive IR; *check whether compute already has a canonical answer first*); height-ordered
  stabilization (a cleaner replacement for `cascade_limit`-then-freeze); dependency-sync-by-hash as compute-
  code distribution; **promise pipelining as a continuation composition** (useful, extension-level, not core).

## 6. Keystone-side (our own follow-through, noted for visibility)

- **Unison as a keystone target** (`LANDSCAPE.md`) — buildable (native TCP/SHA-256/Ed25519/byte-exact-CBOR
  primitives, strongest crypto tier, no FFI), and a *novel identity-model-axis probe* (the first content-
  addressed host — an axis no wire-touching substrate has tested).
- **Generation-readiness for a compute-bearing peer** (`PARADIGM-META-REVIEW` §5): the substantive missing
  build is the **language-agnostic frontend/lowering compiler** (workbench-go hand-lowers in Go today); the
  compute oracle is **vendor-and-expand**, not invent; extensions route to the (unbuilt) `entity-systems-
  generator`, not keystone.

## 7. Confirmed-open — arch already tracks these; keystone corroborates from the convergence angle

Not new findings — the honest residue, correctly above core:
- **Durable at-least-once delivery** survives only as a *deployment convention* (the "Kafka shape"), not a
  substrate guarantee (retracted EXTENSION-DURABILITY, no replacement).
- **Cross-peer continuation resumption** — open L2/G2 dispatch-capability-provenance gap; chains stay within
  one peer today.
- **Durable-execution collector + crash-mid-flight re-fire** — an *open correctness gap* (RESTART §6.1); the
  COMPUTE §7 retention clause is the invariant, but the collector/checkpoint/across-restart-root-set is
  deferred.
- **Consensus / Raft** — named-and-deferred, never designed; peer-compositions give clustering-*adjacent*
  shapes but strong cross-member consistency punts to app-level 2PC / quorum-attested ops.

## 8. Positive results arch can rely on (not action items)

- The substrate-hosting test passes across a dozen traditions; **zero** new core primitives survive minimality.
- The **core/extension boundary is well-placed and independently justified** — for async specifically, by
  minimality + agnosticism + policy (content-addressing orthogonal).
- The **invariant kernel is an attractor** three independent federation designs (entity, Nostr, ATProto)
  re-derive, and which trustless traditions (CapTP, blockchain) re-derive at the trust boundary.
- The **choice-points trace to goals** (agility → hashed id + swappable suite; liveness → deliver-or-signal;
  transferable compute → structural determinism; no-coordination-by-default → single-writer); the one genuine
  open fork (interaction contract) is resolved as a real, capable "different point," not a threat to the kernel.
- Two places entity is **superior** to a sibling, not just different: deliver-or-signal (stricter than
  actor/Nostr/ATProto), and CBOR-over-JSON (Nostr pays for JSON canonicalization).

---

*Routes the convergence/substrate research thread to architecture. Source docs in `research/` carry the
primary-source detail and the corrections (the retracted content-addressing-vs-statefulness argument is
withdrawn there; the correct justification stands). Keystone pathway kept in its own external-systems framing
as an independent witness. Read-only on all siblings; no cross-repo writes; arch pulls on its own schedule.*
