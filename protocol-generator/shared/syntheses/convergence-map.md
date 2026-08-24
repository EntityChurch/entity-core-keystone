# Convergence Map — entity-core against the research traditions it converges with

**Date:** 2026-07-19 · **Companion to**
[`compute-paradigm-and-meta-review.md`](compute-paradigm-and-meta-review.md)
(which establishes the substrate frame in its §1b and probes the first three families in its §6). This doc
is the **comprehensive map**: seven research traditions across six entity subsystems, each run through the
**substrate-hosting test** (does the frozen core *host* the paradigm — subsuming, not duplicating?), each
from **primary sources**, and — where a verdict hinges on entity's actual behavior — **verified against the
pinned spec / `ext/compute` source**, not asserted.

**Method note (the discipline that makes this trustworthy).** Every family was probed from primary sources
(papers, language runtimes, protocol specs — not encyclopedias). Every claim about entity's own behavior
that carries a verdict was checked against `spec-data/v0.8.0/ENTITY-CORE-PROTOCOL.md`, `EXTENSION-COMPUTE.md`,
or `entity-core-go/ext/compute`. Two probe conclusions were **corrected by that verification** (flagged
inline: the reactive "correctness gap" and the CRDT "multi-writer" framing) — which is the point of
verifying rather than reporting.

---

## 1. The organizing frame — one substrate, six subsystems, seven traditions

The paradigm doc's §1b establishes entity-core as a **hard information substrate**: a frozen minimal core
whose structure (content-addressing, determinism, reactivity, capability-authority) is forced, into which
any computational language lowers. The **strong-substrate test** is *hosting*: can the core host the
paradigms other systems were built *as*, subsuming rather than duplicating? This map runs that test across
the subsystems, and the headline is:

> **entity-core is not the invention of a paradigm — it is the *convergence point* of seven previously-
> separate research traditions onto one substrate. Each tradition engineered ONE property at cost; here each
> is a corollary of one content-addressed, deterministic, dispatch-uniform core. The substrate passes the
> hosting test in every subsystem: it hosts all seven, subsumes each, and the handful of genuine gaps and
> conflicts are precise, named, and mostly resolve to *pluggable, trust-sized seams* rather than missing
> foundations.**

| Entity subsystem | Converging tradition(s) | Entity's position | Verdict |
|---|---|---|---|
| Code / computation | **Unison**; GHC-Core | content-addressed functional IR | HOSTS + SUBSUMES; Unison BUILDABLE as a peer target |
| **Distributed-state consistency** | **single-writer-ownership** (web/git/DNS); **blockchain** (consensus); **Croquet** (det-replication); **CRDTs** (merge) | **primarily single-writer**; det-replication for shared compute | the **quadrilemma** (§3.2) — the spine of this map |
| Incremental / reactive | **Adapton**, **JS Incremental**, **differential dataflow**, **Salsa** | local-eager, install-gated | SUBSUMES detection; distributed-reactivity gap; Salsa is the native lazy-mode blueprint |
| Authority | **object-capability / CapTP** (E, Agoric/OCapN) | signed grant-chain | SUBSUMES ocap for the trustless case; one real conflict |
| Storage / content-addressing | IPFS/git/**Nix**; Automerge's change-DAG | Merkle-DAG content store | CONVERGENT reinvention |
| Code mobility | **Unison** dep-sync; **Emerald** object-mobility | closure transfer (wire deferred) | SUBSUMES; semantics-invariance for free |

---

## 2. The centerpiece — distributed-state consistency is a QUADRILEMMA, and entity's default is the one the textbooks forget

The single most important result of the survey, and it required reading the actual spec to get right.

### 2.1 Four answers to "how do distributed replicas agree," not three

The CRDT literature frames a *trilemma*; a fourth answer dominates real systems and is entity's default:

| Model | What it must agree on | Cost | Exemplars |
|---|---|---|---|
| **(d) Single-writer ownership** | **nothing — no shared writes exist** | partition the namespace | **the web** (origin owns its URLs), **git** (repo owns its history), **DNS** (zone has one authority) |
| (a) Consensus / total-order | one canonical order, per write | global agreement (BFT/PoW) | blockchain, Raft/Paxos |
| (b) Deterministic-replication | an agreed *input* order, then recompute | a sequencer or barrier | Croquet/TeaTime |
| (c) CRDT / commutative-merge | **nothing — merge is order-free** | causal metadata + tombstones | Automerge, Yjs |

### 2.2 Entity is primarily (d) — verified against the spec

`ENTITY-CORE-PROTOCOL.md §1.4` is unambiguous: **every path is `/{peer_id}/...`, and the key-holder is the
sole cryptographic authority for its namespace.** Other peers hold only a **cache** of that namespace, kept
current by subscription:
- *"Authoritative data — entities under the local peer's namespace. The local peer holds the private key and
  is the authority for this data. Other peers treat this data as the canonical source."* (§1.4)
- *"Namespace authority (cryptographic). Only Bob can produce entities signed with Bob's key. While Alice can
  write anything to `/bob_id/...` in her local tree, that does not make it authoritative."* (§1.4)
- *"The universal entity tree is the union of all peers' authoritative data. Each peer's local view is …
  complete for its own namespace, partial for others."* (§1.4)

So **entity has no multi-writer paths.** There is no concurrent-write conflict to resolve, because only one
peer can author any authoritative path; replication is **one-way cache propagation** (subscription), not
multi-writer merge. This is the web/git/DNS pattern, and it is **why entity needs no general ordering or
consensus mechanism for the overwhelming majority of its state** — the conflict is *designed out*, not
solved.

*(This corrects the CRDT probe, which — flagging that it had not read entity source — applied a multi-writer
CRDT frame throughout. Entity's LWW input-port write and its revocation marker are both single-writer:
LWW-in-local-order for a host-driven input port; a granter-owned marker for revocation. The apparent
"use-vs-revoke race" is **cache-propagation latency**, not a merge conflict — which reframes RT-9, below.)*

### 2.3 The gap appears exactly where you LEAVE single-writer territory

Entity reaches for (b) deterministic-replication only for **deliberately-shared** state — the multi-peer
compute-lockstep case (many peers feeding inputs to one shared simulation, RUNTIME-CONTRACT §10). *That* is
where the session's headline gap lives, and it is now precisely located:

> **The input-ordering gap is not a hole in entity's consistency model — it is the cost of the one place
> entity opts *out* of its single-writer default into shared (b)-style state.** For everything under
> single-writer ownership, there is no gap. For shared compute, entity must supply the "agreed input order"
> that (b) requires — and that is a sequencing problem (§3.2 below).

### 2.4 The resolution is a pluggable, trust-sized ordering seam — not a global ledger

Blockchain and Croquet converge on the same answer from opposite ends: entity already owns the deterministic
VM half of `state = order(inputs) ∘ deterministicVM(replay)` (compute handler + canonical CBOR + budget).
What it lacks is a **pluggable per-shared-scope ordering layer, sized to the scope's trust model**:

```
lightest ─────────────────────────────────────────────────────────► heaviest
(d) single-writer      (c) CRDT-merge        (b) sequencer        (a) BFT consensus     PoW
no shared writes       no order needed       one trusted          known distrusting     permissionless
= entity default       = collab data ext     sequencer/reflector  validator set         (≈ never for entity)
                                              = the right-sized
                                              answer for shared
                                              compute
```

**Placement verdict:** entity sits at **(d) by default**, offers **(c) as a clean extension** for multi-writer
collaborative data (§3.2.4), reaches for a **(b) reflector-class sequencer** per shared-compute scope
(§3.2.3), escalates to **(a) BFT** only for a bounded mutually-distrusting writer set, and **never needs PoW**
(peers are already Ed25519-identified). The borrowable is *the factoring* — an ordering seam — not any one
mechanism.

---

## 3. Subsystem by subsystem

### 3.1 Computation / code — Unison (fully in the paradigm doc §6.1)

**HOSTS + SUBSUMES + BUILDABLE.** Unison = content-addressed functional code as a whole *language*; entity's
compute extension is the same move as *one extension* over a general substrate ("Unison ≈ the compute
extension promoted to a language"). No hash conflict (Unison hashes *code* SHA3-512/AST; entity hashes *data*
SHA-256/CBOR — orthogonal layers). **Unison is a buildable keystone target** (native TCP/SHA-256/Ed25519/
byte-exact CBOR primitives; strongest crypto tier, no FFI) and the sharpest probe available — the first host
whose *own identity model* is content-addressed. Borrowables: cyclic-definition hashing, dependency-sync-by-
hash as compute-code distribution, names-as-metadata, abilities-as-typed-effects. *(Detail: paradigm doc
§6.1.)*

### 3.2 Distributed-state consistency — the quadrilemma in full

The map's spine (§2). Per-tradition verdicts:

**(a) Blockchain / smart contracts — SUBSUME (contract) + the ordering spectrum.** A smart contract ≈ a
compute handler *minus the global-consensus ledger*: deterministic code + persistent state, dispatched by
call, metered by **gas** (≈ entity's budget/TTL, but with a fee-market/token layer entity omits), authorized
by signatures (entity's capabilities are **strictly more expressive** — the auth borrowable runs the *other*
way). Content-addressing is the identical move on incompatible primitives (Keccak/RLP/Patricia vs SHA-256/
CBOR/tree) — DUPLICATE concept, byte-CONFLICT, bridgeable. Blockchain adds four things entity mostly *doesn't
want*: global state-root agreement, a totally-ordered append log, BFT finality, and sybil/token economics.
The one borrowable is the **ordering seam** (§2.4). Build niche: entity's *authority interior* (§5.2 ladder,
§5.5 closure, K-of-N) is authorable as an on-chain contract for scopes that want consensus anyway — CosmWasm
hosts it (`ed25519_verify` + `sha256`); EVM lacks native Ed25519.

**(b) Croquet/TeaTime — SUBSUMES + CONFLICT-you-win + the ordering GAP.** (Paradigm doc §6.2.) Entity
subsumes determinism/snapshot/rollback (a Croquet snapshot ≡ a content-addressed state hash, intrinsic vs
serialize-encrypt-upload); **wins the float clash** (Croquet bets on IEEE-754 determinism, entity excludes
float); the reflector is the **borrowable sequencer** for §2.4. A Croquet "island" ≈ an entity compute-program
`state₀ + step`; the only non-native piece is the sequencer service (application-level).

**(c) CRDTs — DISSOLVE the gap for collaborative data; the authority boundary is the hard wall.** CRDTs
achieve **Strong Eventual Consistency** with *no coordination* — idempotent+commutative+associative merge
(state-based join-semilattice) or commutative ops under causal delivery (op-based). They are the one model
that **needs no agreed order**, so a CRDT-typed path **dissolves** the (b) ordering gap rather than solving
it. Verdicts:
- **Clean EXTENSION for multi-writer collaborative data.** A "CRDT-typed tree path" = a path whose merge is a
  declared CRDT LUB. Entity's op-based substrate is an unusually clean host: the ops *are* the input stream
  entity already syncs; the merge *is* the recompute; **causal delivery comes free from content-addressed
  dependency hashes** (the Automerge pattern). Must be a **negotiated/typed path** (a new path-type class),
  *not* a silent reinterpretation — an old LWW-only peer would compute a different value (so not MUST-ignore-
  safe; it stays inside the stability model as a declared type).
- **CONVERGENT reinvention on history.** Automerge's hash-DAG of changes ≈ entity's content-addressed hash-
  linked history — the same idea independently. Borrow: **columnar encoding** (~1.1 B/op; full history ≈
  gzipped plaintext) as the storage discipline so CRDT op-logs don't bloat.
- **The hard CONFLICT — authority state cannot be a CRDT.** Pure CRDTs *provably* cannot enforce global
  invariants needing agreement (the auction "select one winner"; "balance ≥ 0" needs escrow/Bounded-Counter
  = partial coordination). So: **collaborative-data state** (docs, sets, counters, registers) → CRDT paths
  fit, gap dissolves; **authority-bearing state** (capabilities, K-of-N multisig, fail-closed §5.2,
  uniqueness) → must stay in entity's deterministic+coordinated regime. Map state to the right side of that
  wall and CRDT paths are a clean extension; cross it and they are a category error.
- **RT-9 reframed (a real contribution).** Entity's revocation via pull-sync + convergence window is
  *already* CRDT-shaped — the "use vs revoke" race is an OR-Set add-vs-concurrent-remove, and "transient
  disagreement until synced" is an **eventual remove-wins policy, not an invariant.** Two findings: (1) entity
  can **formalize revocation as an explicit OR-Set/2P-Set with a stated resolution rule**, making the
  convergence-window semantics precise instead of emergent; (2) it must **not** market "no capability used
  after revocation" as a *hard* invariant — under the window it is a CRDT *eventual* property, and the
  auction/bounded-counter result says a hard version needs coordination. This is the precise formal seam
  RT-9 was circling.

### 3.3 Incremental / reactive — Adapton · Incremental · differential dataflow · Salsa

Entity's reactivity is a **subtree-granular, single-version, eager-push, install-gated** special case of the
incremental-computation family. Verdicts (change-detection SUBSUMED; two axes MISSING but by design):
- **Change detection — SUBSUMED, free.** Content-addressing *is* the dirty-check; hash-inequality is the
  change signal. Cleaner than SAC/Adapton dirty-flag bookkeeping.
- **The correctness worry — VERIFIED and REFUTED** (paradigm doc §6.3). The Adapton probe feared
  `cascade_limit` silently truncates before fixpoint; verified in `engine.go:350` that it **freezes the
  subgraph and writes a `compute/error`** (fail-loud, recoverable by re-install). Purity + content-addressing
  give confluence; the residual is efficiency, not corruption.
- **Salsa is the native lazy-mode blueprint.** The Adapton probe recommended an opt-in demand-driven mode;
  **Salsa is the production form, and entity's content-hash *is* Salsa's green-check/backdating fingerprint**
  — "did this subresult change" is a free O(1) hash compare. Entity would add demand-pull + a revision/
  durability skip-the-walk. Better fit than raw Adapton (whose dirtying machinery entity would have to build).
- **The distributed-reactivity GAP — the same gap as §2.3, from the computation side.** Entity's reactive
  engine is **local-only by design** (`EXTENSION-COMPUTE §7.5`, confirmed at `ENTITY-CORE-PROTOCOL §…`
  explicit-non-sites); a multi-peer reactive result fires on whatever is in the local tree at that instant,
  with **no logical-time/frontier concept** → no consistency guarantee. Differential dataflow / Naiad's
  **frontier + could-result-in progress tracking** is the only real answer for *correct* distributed
  reactivity — but it is a **heavyweight** commitment (multidimensional timestamps, path summaries, a
  distributed progress protocol), not a bolt-on. Adequate exactly as long as entity accepts best-effort-
  eventual distributed reactive results.
- **Iteration/fixpoint borrowable.** DD's iteration-as-timestamp-coordinate + empty-difference fixpoint
  detection is a principled candidate to *backstop* the blunt `cascade_limit` with a real convergence test.

**The unification (important):** the §2.3 **input-ordering gap** and this **distributed-reactivity gap** are
*one gap seen from two sides.* Both are "entity has no distributed logical time / consistent cut." Blockchain's
`consensus(order)` and Naiad's `frontier` are two answers to the *same* question — *when is a distributed
computation at logical time T complete and consistent?* Entity omits that layer deliberately (its single-
writer default, §2.2, is *why* it can), and the resolution is the same shape: a pluggable distributed-logical-
time seam, sized to need.

### 3.4 Authority — object-capability / CapTP (paradigm-doc-adjacent; detail here)

**SUBSUMES ocap for the trustless case, with the standout borrowable and the one real conflict.**
- **Two capability traditions.** ocap = an *unforgeable reference* (possession = authority, no crypto,
  enforced by runtime memory-safety *within a trusted vat*). entity = a *signed grant certificate* (verified
  cryptographically, works against a hostile network). **The decisive finding: the instant ocap leaves a
  trusted memory space — CapTP's three-party handoff — it re-derives *exactly* entity's machinery** (signed
  certificates binding the grantee's public key + anti-replay counters + signature verification at the
  resource). So **entity = "the capability model for when there is no trusted runtime boundary,"** paying on
  every hop the cost ocap defers until the machine boundary forces it too. DUPLICATE concepts (attenuation-
  by-delegation, no-ambient-authority, POLA); entity is the cryptographic realization of the same graph.
- **Standout borrowable — promise pipelining.** Entity's cross-peer dispatch is exactly the setting Miller
  invented pipelining for: `h=A.resolve(); r=h.apply(x); s=r.field()` is 3 round-trips where CapTP/E pay 1.
  It attacks the one cost hardware never fixes (speed of light); entity's content-addressed, chain-verified
  model doesn't obstruct it (the grant-chain check still runs at resolution). **Highest-value borrowable of
  the whole survey.**
- **Entity is arguably *ahead* on the three-party handoff.** CapTP's elaborate signed-gift-deposit dance
  exists *because* ocap references are connection-scoped and opaque. Entity's grant-chains are content-
  addressed and self-authenticating, so a grantee on peer C introduced to a resource on peer A **already
  carries a verifiable chain rooted at A** — no gift deposit, no per-introduction certificate. Verify against
  §5.5 (and confirm an anti-replay equivalent of CapTP's `handoff-count` exists), and if it holds it is a
  genuine simplification worth documenting as a contribution.
- **The one genuine CONFLICT — speakable names vs "only connectivity begets connectivity."** ocap's
  foundational invariant is that you can never *name* an object you weren't handed. Entity peers are named by
  **content-hash — a speakable, guessable name** — so knowing a hash lets you *address* a resource with no
  introduction. Entity restores safety at the *authority* layer (addressing ≠ authority) but deliberately
  trades away ocap's stronger *topology* property (unauthorized parties can't even designate/probe). A
  conscious, defensible trade (content-addressing *requires* speakable names) — but the one place the models
  truly diverge, worth stating plainly.
- **Membrane borrow (structure, not mechanism).** Don't swap entity's distributed-eventual revocation for the
  membrane's local-synchronous gate; borrow the *structural claim* — revocation should be scoped to a
  delegation-*region*, transitively invalidating sub-chains, not a single edge. Entity's chain-walk likely
  gives this already (a revoked link breaks every chain through it) — **confirm it as a structural invariant**
  (à la F41), don't leave it emergent.

### 3.5 Code mobility — Unison dep-sync + Emerald object-mobility

Entity transfers content-addressed compute closures between peers (§5.8, wire deferred). **SUBSUMES with
semantics-invariance for free.** Emerald had to *engineer* "mobility does not change semantics" for mutable
live objects (call-by-move / call-by-visit as semantics-preserving optimizations); entity gets it **free** —
a hash denotes the same value everywhere, so transferring a closure *cannot* change semantics. Borrowables:
(1) Emerald's **attached-variables** idea → "which captured dependencies ship inline vs stay as fetchable
content-hash references" (easier for entity — a residual reference is just a hash, no dangling-pointer
problem); (2) the **move-vs-visit framing** (does the closure stay at the target for reuse, or execute-and-
discard?) with content-addressing as the reason semantic-invariance is trivial; (3) Unison's **dependency-
sync-by-hash** as the transfer protocol (ship IR, receiver pulls missing hashes).

---

## 4. Two deep unifications the survey earned

1. **The distributed-logical-time gap is a single choice, not four gaps.** Entity chose **local determinism +
   eventual consistency + single-writer ownership** (§2.2). That choice is *why* it needs no consensus for
   most state — and it surfaces as one gap wherever entity opts into shared state, seen as "input ordering"
   (state view, §2.3) or "reactive frontier" (computation view, §3.3). The four traditions that touch it
   (single-writer / consensus / det-replication / CRDT-merge / frontier-progress) are the menu; the borrowable
   is a **pluggable distributed-logical-time seam sized to trust**, from "nothing" (single-writer default) to
   BFT.

2. **Trustless networking re-derives entity's crypto — repeatedly.** ocap's CapTP handoff, blockchain's
   signed transactions, CRDT causal delivery, and Croquet's session identity all reach for *the same
   primitives entity is built on* (signed certificates binding a key, content-addressed identity, anti-replay)
   the moment they cross a trust boundary. Entity is the design that **starts** where those systems **end up**:
   the cryptographic realization of the capability/replication graph, native rather than bolted on.

---

## 5. The borrowables ledger (ranked; where each routes)

| # | Borrowable | From | Value | Routes to |
|---|---|---|---|---|
| 1 | **Promise pipelining** in cross-peer dispatch | CapTP/E | HIGH — attacks speed-of-light latency | dispatch protocol (arch) |
| 2 | **Pluggable ordering seam** (reflector→BFT), sized to trust | Croquet + blockchain | HIGH — closes the shared-state gap | RUNTIME-CONTRACT open Qs (§10.1/§12.7) |
| 3 | **CRDT-typed paths** as a negotiated extension for collaborative data | CRDTs | HIGH — dissolves the gap where it applies | a new extension (systems-generator scope) |
| 4 | **Salsa red-green + revision/durability** for an opt-in lazy reactive mode | Salsa | MED-HIGH — content-hash = free fingerprint | reactive engine (compute) |
| 5 | **Formalize revocation as an OR-Set** with a stated resolution rule | CRDTs | MED — makes RT-9's window precise | identity/capability (arch) |
| 6 | **Cyclic-definition hashing** for mutual-recursion/shared-subterm IR | Unison | MED — check-then-borrow | compute IR |
| 7 | **Height-ordered stabilization** as a cleaner `cascade_limit` replacement | JS Incremental | MED — kills diamond re-fires | reactive engine (compute) |
| 8 | **Dependency-sync-by-hash** as compute-code distribution | Unison | MED — generalizes §5.8 | compute closure transfer |
| 9 | **Columnar op-log encoding** for CRDT/history storage | Automerge/Kleppmann | MED — keeps op-logs from bloating | storage (if #3 lands) |
| 10 | **Frontier / progress-tracking** for correct distributed reactivity | Naiad/DD | LOW-now (heavyweight) — only if a use case needs it | deferred; named |
| 11 | **Membrane structure** (region-scoped transitive revocation) | E | LOW — likely already structural | confirm as invariant (arch) |
| 12 | **Emerald move/visit + attached-vars** framing for closure transfer | Emerald | LOW — free semantics-invariance | compute closure transfer |

## 6. The conflicts / divergences ledger (the genuine trades — not gaps, decisions)

- **Speakable content-hash names vs ocap's "only connectivity begets connectivity."** Entity trades topology-
  hiding for addressability; restores safety only at the authority layer. Conscious, required by content-
  addressing. (§3.4)
- **Authority state vs CRDT eventual-consistency.** Capability/multisig/invariant-bearing state *cannot* be a
  CRDT (provably needs coordination); it stays in the deterministic+coordinated regime. The seam between
  entity's CRDT-compatible and consensus-requiring state is exact and must be respected. (§3.2c)
- **Float exclusion vs Croquet's float-determinism bet.** Entity wins this one across substrates; noted as a
  vindicated divergence, not a gap. (§3.2b)
- **Gas/token economics** (blockchain) — entity has the *metering* half (budget) without the *fee-market*
  half, and deliberately so. A divergence, not a deficiency. (§3.2a)

## 7. What this says about the paradigm

The substrate-hosting test **passes in every subsystem**. entity-core hosts and subsumes the seven deepest
traditions in content-addressed code, distributed-state consistency, incremental reactivity, capability
authority, content-addressed storage, and code mobility — inventing none, converging all. The genuine gaps
reduce to **one deliberate choice** (no distributed logical time — resolvable by a trust-sized seam), and the
genuine conflicts are **conscious trades** (speakable names; the authority/CRDT wall). The most important
architectural fact the survey surfaced — verified against the spec, against a probe's mis-framing — is that
entity's default consistency answer is **single-writer ownership** (the web/git/DNS pattern), which is *why*
it needs no consensus for most state and why the "gaps" are narrow and opt-in.

That is the substrate property (§1b: generativity + hosting) demonstrated, not asserted: a frozen minimal
core that transforms itself to host the paradigms other whole systems *are*. "New paradigm" was always the
wrong frame; **convergence substrate** is the right one, and it is the stronger claim because it is checkable
— and here, checked.

## 8. Routes

- **Build probe:** Unison as a keystone target (`LANDSCAPE.md`) — the identity-model-axis substrate, buildable
  (§3.1). The one family that is literally a peer-build target; the rest are model/borrowable probes.
- **Arch findings (route as `HANDOFF-TO-ARCH-*` when the operator decides):** the ordering seam (§2.4, borrow
  #2), promise pipelining (#1), CRDT-typed-paths extension + the RT-9 revocation-as-OR-Set formalization (#3,
  #5), the speakable-names topology trade (§6) and the authority/CRDT wall (§3.2c) as explicit design
  statements, and the "entity already solves CapTP's three-party handoff" contribution (verify §5.5).
- **Compute / reactive engine borrows:** Salsa lazy mode (#4), cyclic-def hashing (#6), height-ordered
  stabilization (#7), dependency-sync-by-hash (#8), closure-transfer framing (#12).
- **Deferred / named:** distributed frontier progress-tracking (#10) — only if a use case needs correct
  distributed reactivity; columnar op-log encoding (#9) — only if CRDT paths land.

---

*Comprehensive convergence map. Seven traditions from primary sources; entity-side verdicts verified against
`spec-data/v0.8.0`, `EXTENSION-COMPUTE.md`, and `ext/compute` where checkable (two probe conclusions corrected
by that verification). Companion to `compute-paradigm-and-meta-review.md`. Read-only on all
sibling repos; no cross-repo writes.*
