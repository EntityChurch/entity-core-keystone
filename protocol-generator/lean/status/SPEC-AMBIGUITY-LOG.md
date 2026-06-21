# entity-core-protocol-lean — Spec Ambiguity Log (S3 discipline)

Every guess + every proof-surfaced spec gap goes here. The proof track adds a NEW
class: items surfaced by *attempting a formal proof* (a proof needing an unstated
hypothesis = under-specified precondition; a counterexample = a spec defect). These
escalate to architecture via `research/stewardship/` after S4 dedup.

**Status legend:** OPEN · RESOLVED · ESCALATED · verify-against-existing (= flagged by
the proof track in S1/1b; must be diffed against the cohort logs in S4 before any
escalation — several are likely already known).

---

## Proof-track findings (S1/1b — the Lean-1b provability ledger)

These are *candidates from desk analysis*; each is re-confirmed (or dropped) when the
actual proof is attempted in S2/S3. None blocks Track A conformance.

### A-LEAN-1 — `now()` sampled per-link vs the §5.10 deterministic-verdict claim
**verify-against-existing.** §5.5 `verify_capability_chain` evaluates temporal validity
with `t = now()` *inside the per-link loop* (V7:2630), but §5.10 requires the Layer-1
verdict to "be a function of the chain and these Layer-1 inputs only… identical across
conformant peers." Wall-clock is neither chain-observable nor cross-peer-identical, and
per-link re-sampling means the verdict isn't a function of one time value. Proving T4
(determinism) **forces** `now` to a single explicit parameter sampled once at entry,
and forces §5.10 to declare time part of "Layer-1 state." *Surfaced-by:* T4 factoring.

### A-LEAN-2 — revocation is "Layer-1 deterministic" (§5.10) yet reads the local mutable tree (§5.1)
**verify-against-existing.** §5.10 lists revocation among Layer-1 (cross-peer-deterministic)
inputs; §5.1 `is_revoked` reads `ctx.entity_tree.get(marker_path)` — local mutable state.
A pure `verifyChain(chain, included, localPeer, now)` cannot include revocation without
adding tree-state as an explicit input, contradicting "function of the chain only."
Reconcile: revocation is Layer-2, OR the determinism claim is qualified "relative to a
fixed tree snapshot." *Surfaced-by:* T4 factoring (the clean theorem excludes revocation,
matching the core-peer `supports_revocation=false` path).

### A-LEAN-3 — §5.6 `scope_subset` canonicalization frame is stale vs §5.5a Amendment 1
**verify-against-existing (likely already logged).** `scope_subset(child, parent, local_peer_id)`
(V7:2802) canonicalizes both sides against `local_peer_id`, but §5.5a Amendment 1
(V7:2725, surface 2) normatively requires per-link attenuation to canonicalize each side
against THAT link's own granter `peer_id`. Internal spec inconsistency; the Lean model
uses the normative per-link granter frame. Almost certainly the v7.73 granter-frame
erratum the keystone already shipped (`v773-pr8-v2a-keystone-closeout`) — the proof
*confirms* it, does not find it new. *Surfaced-by:* T5a modeling.

### A-LEAN-4 — `matches_pattern` used as a pattern-subset test (T5a transitivity crux)
**verify-against-existing.** `scope_subset` decides "child ⊑ parent" via
`matches_pattern(canon child, canon parent)`, but `matches_pattern` (V7:2401) is defined
over (concrete-path, pattern) and treats arg1 as a literal string. Global attenuation
(leaf authority ⊆ root) follows from per-link checks only if this relation is a
transitive preorder; transitivity across the `/*/` peer-wildcard recursion is non-obvious.
Proving it certifies the security heart of delegation; a 3-pattern counterexample is a
spec defect (highest signal). *Surfaced-by:* T5a — the highest-value proof in the set.

### A-LEAN-CRYPTO — Ed448 deferred (not a defect; scope note)
Ed448 (crypto-agility higher bar) deferred, as for most peers. Sourced via libentitycore_codec
C-ABI when in scope (1c crypto-FFI spike proved the mechanism). Ed25519/SHA-256 floor unaffected.

---

## Minor / low-priority (1b §4)

- **decoder tag tension:** ECF §9.2.2 ("Decoders MUST… Preserve unknown tags") vs §6.3
  ("MUST reject… MUST NOT preserve" tags on data fields). Reconciled by layering
  (generic decoder preserves; protocol-message layer rejects). Not a proof target;
  flag in S4 if it bites. **OPEN-minor.**

---

---

## S2 outcomes (codec build + Track-B T2/T3)

**No new codec-layer finding; the proofs CONFIRM the spec.** S2 surfaced no
spec ambiguity in the codec. Two notes:

- **Float "same value" equality (1a §5 T3 / §7 had flagged this as a likely
  A-LEAN candidate) — RESOLVED in the spec's favour.** Proving T3 forced the
  question "widens back to the *same value* — bit-equality or numeric-equality?"
  The answer is **pinned by ECF Rule 4a** (the spec gives exact bytes for NaN /
  ±0 / ±Inf) and by Rule 4 (bit round-trip for finite values). The Lean proof
  models exactly this (bit round-trip + Rule-4a special bytes) and closes
  cleanly — `encode_nan`/`encode_inf` proved parametric over the whole special
  class. So the precondition 1a worried might be missing is in fact present.
  **Not a finding; a confirmation.** (`status/FORMALIZATION-REPORT.md` T3.)

- **No codec guesses to log.** The ECF spec (§4.1, §9.1) is precise enough that
  the encoder/decoder required no under-specified judgement calls. Decoder
  leniency on non-canonical f16 specials matches the cohort and is a known
  implementation latitude, not a spec gap.

The proof-track findings **A-LEAN-1..4 remain OPEN/verify-against-existing** —
they live in the verdict/attenuation layer (T4/T5) and surface in S3, not S2.

---

## S3 Track-B outcomes (the verdict/attenuation proofs)

All four A-LEAN candidates were re-examined by *actually proving* T4/T5 against the
running pure verdict core (`src/EntityCore/Capability.lean`). Proofs in
`proofs/EntityCoreProofs/CapabilityProofs.lean`; per-theorem ledger in
`status/FORMALIZATION-REPORT.md`. **No counterexample anywhere — the spec holds.**

### A-LEAN-4 — `matchesSeg` transitivity → **RESOLVED in the spec's favour.**
The crux. `matchesSeg` (the §5.4 segment matcher) is **proven transitive**
(`matchesSeg_trans`, axioms `[propext]` only — Classical-free). A brute-force
search over all segment lists ≤ length 3 across `{a,b,*,""}` first found **0
counterexamples in 2345 constrained triples**; the proof then certified it for
all inputs. The `/*/` peer-wildcard (one segment) vs trailing `/*` (≥1 segment)
interaction — the worry — never desyncs lengths, because a `"*"` segment is
*always* a wildcard, never a literal. **Consequence:** per-link §5.6 attenuation
checks provably compose to global *leaf authority ⊆ root authority*
(`isAttenuated_trans`) — delegation never broadens. The security heart of
delegation is machine-certified. **No spec change needed; no escalation.**

### A-LEAN-3 — §5.6 stale `local_peer_id` frame vs §5.5a per-link granter frame → **CONFIRMED (dedup: = the shipped v7.73 erratum).**
The transitivity lift only composes *because* the shared middle link
canonicalizes on its own granter frame, used on BOTH of its chain edges (this is
literally what the generic `all_any_compose` combinator consumes). The proof thus
*confirms* the v7.73 granter-frame erratum is load-bearing for the security
property — not merely a bugfix. **Already shipped + logged cohort-wide
(`v773-pr8-v2a-keystone-closeout`); the proof corroborates, finds nothing new.**
Per the dedup discipline: **NOT re-escalated.**

### A-LEAN-1 — `now()` per-link vs §5.10 deterministic verdict → **CONFIRMED, now precise.**
The running peer samples `now` once (`Peer.verifyRequest`) and the pure
`verifyChain` takes it as one explicit `UInt64` param. Two theorems make A-LEAN-1
exact: `walk_time_stable` (the walk's ONLY coupling to `now` is the per-link
`temporalOk`; agree there ⇒ identical verdict) and `verifyChain_time_independent`
(a chain with no TTLs is *fully* time-independent). So the §5.10 "function of the
chain and Layer-1 inputs only" claim is satisfiable **iff** time is sampled once
and declared a Layer-1 input — exactly the factoring. **The finding stands for
arch (a §5.5/§5.10 wording reconciliation); the proofs sharpen, not drop it.**

### A-LEAN-2 — revocation "Layer-1 deterministic" (§5.10) vs local-tree read (§5.1) → **CONFIRMED structurally.**
`verifyChain` provably does **not** consult revocation — it is not a field of
`ResolvedChain`; `isRevoked` is a `Peer` store read composed *outside* the proven
core. The clean pure-core theorem exists *because* revocation was excluded. So
"Layer-1 verdict is deterministic" holds for the pure core precisely by excluding
revocation, which §5.10 lists as Layer-1. **The §5.10-vs-§5.1 tension stands for
arch (revocation is Layer-2, or determinism is "relative to a tree snapshot").**

### A-LEAN-FORMALIZATION (NEW, tooling note — not a spec finding)
The `#print axioms` honesty audit surfaced that every lemma whose *statement*
mentions path canonicalization (`scopeSubset_trans`, `grantSubset_trans`,
`isAttenuated_trans`, the `verifyChain_*` set) carries `Classical.choice` — traced
NOT to any proof tactic but to Lean's **stdlib `String.splitOn`** (well-founded
recursion), which `canonSegs`/`splitSegs` call. The matcher-level core
(`matchesSeg_trans`, `all_any_compose`, `chainExceedsDepth_iff`) stays
`[propext]`-clean. **Zero `sorryAx` anywhere.** This is a benign formalization
artifact, recorded for honesty (a real proof-track payoff: the axiom audit even
exposes which standard-library primitives the spec's path model rides on).

*(S3 peer-build guesses, if any arise, append below per S3 discipline.)*
