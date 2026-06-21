# entity-core-protocol-lean — FORMALIZATION REPORT (Track B)

**A new keystone artifact type** (alongside the conformance scorecard): the
per-theorem record of what the Lean peer *proves* about the protocol, what it
can't (yet), and what that tells us about the spec. The proof track exists to
find the preconditions nine empirically-agreeing peers shared silently —
a proof that needs an unstated hypothesis is an under-specified precondition; a
counterexample is a spec defect (highest signal).

**Stance (user-directed, memory `lean-proof-vs-spec-stance`):** build the peer
first (Track A is the floor); prove what's feasible; don't force the infeasible;
a can't-prove-as-written outcome may rise to a spec change but only *after* the
peer works and the proofs are validated; never block/weaken Track A. Honest
outcomes — proved / proved-with-added-hypothesis / infeasible-here-but-sound /
counterexample — are all acceptable; this report records which is which.

**Honesty gate.** Every theorem below passes `#print axioms` with
`[propext, Quot.sound]` only (the standard kernel axioms) — **no `sorryAx`**.
The proven functions are the kernel-reducible *running* code (Lean has no
extraction gap, S1 1a #1), modulo the single declared opaque boundary
`Float.toBits` (and the `@[extern]` crypto, which is the spec's own trust line).

---

## Status as of S3 — Track B complete

The verdict/attenuation layer is proven. **The headline result: the §5.6
delegation-attenuation check provably composes to the global security property
*a leaf capability's effective authority is a subset of the root's* — delegation
never broadens.** It reduces to one fact, `matchesSeg` transitivity, which is
proven Classical-free and was first stress-tested by a 0-counterexample brute
force. Full ledger below; all theorems pass `#print axioms` with **no `sorryAx`**.

| ID | Theorem | Layer | Outcome | Consequence |
|----|---------|-------|---------|-------------|
| T3a | `tryHalf_widens` / `trySingle_widens` | codec | **PROVED** | gate **soundness**: the narrow gates accept a width only when it widens back **bit-identically** → an emitted shorter form is value-preserving (Rule 4) |
| T3b | `encode_uses_half/single/double` | codec | **PROVED** | ladder **dispatch**: the encoder emits f16 iff the f16 gate accepts, f32 iff f16 rejects ∧ f32 accepts, f64 iff both reject — an exact case characterization of `encodeFloatBits` |
| T3c | `encode_nan`, `encode_inf` | codec | **PROVED (parametric)** | Rule 4a holds for the **whole special class**: every NaN bit pattern → `F9 7E00`; every ±Inf → matching f16. Confirms the spec pins these unambiguously |
| T3↺ | **encoder losslessness** (T3a ∘ T3b) | codec | **PROVED (corollary)** | every emitted form widens back to the input bits exactly — the encoder never loses information at the bit level (f16/f32 by gate soundness, f64 trivially) |
| T3↓ | **strict minimality** (no shorter form exists) | codec | **NOT PROVED — see "what Lean can't yet say"** | needs gate *completeness*; the proven theorems give "narrowest **gate-accepted** width", not "narrowest **possible**" |
| T2r | `lexCmp_self`, `keyCmp_self`, `keyLe_refl` | codec | **PROVED** | the canonical key comparator is reflexive — a sort never spuriously rejects equal keys |
| T2t | `keyLe` totality | codec | **DEFERRED (time-boxed)** | reduces to `lexCmp` swap-antisymmetry; routine math, but `split_ifs`/`simp` would not fire on the swapped 4-way `if`-nest after `fun_induction`. Scope boundary, **not** a defect — totality witnessed by 69/69 conformance + the cohort |
| T1 | `Canonical(b) → encode(decode b) = b` | codec | **DEFERRED** | needs a kernel-reducible (total) `decode`; the shipped decoder is `partial`. A total decode (well-founded on unconsumed-input length) is the Track-B refinement |
| T4 | `verifyChain` factors as `f(chain,localPeer,now)`; time-stable | verdict | **PROVED (S3)** | `walk_time_stable` + `verifyChain_time_stable` + `verifyChain_time_independent`: `now` enters at one place per link (A-LEAN-1); revocation provably excluded (A-LEAN-2) |
| T5a-core | `matchesSeg` transitive | verdict | **PROVED (S3) — `[propext]`, Classical-free** | the §5.4 matcher is a transitive relation; **no counterexample** → A-LEAN-4 resolved in the spec's favour |
| T5a | attenuation monotone (leaf ⊆ root) | verdict | **PROVED (S3)** | `isAttenuated_trans` via `scopeSubset_trans`/`grantSubset_trans` + `all_any_compose`: delegation never broadens. The §5.5a granter frame is load-bearing (A-LEAN-3) |
| T5b | depth pre-check = structural length test; root short-circuit | verdict | **PROVED (S3)** | `chainExceedsDepth_iff` (`[propext]`) + `verifyChain_foreign_root`; `walk`/`verifyChain` total by acceptance (structural recursion) |
| **T5c** | **the verdict ENFORCES the per-edge check, end-to-end** | verdict | **PROVED (S3)** | `walk_allow_cons` (allow ⇒ each edge `edgeOk`) + `edgeOk_atten` + the reflexivity chain + the closed **`allowed_chain_leaf_atten_root`** (allow ⇒ leaf ⊆ root). Closes the loop from "the step composes" to "the verdict runs the step" |
| T6 | §5.2 dispatch-gate defaults + full per-link extraction | verdict | **PROVED (S3)** | `checkPermission_no_grants_deny` + `matchesScope_excl_override` + `checkResourceScope_no_targets_deny`; `walk_allow_link_facts` (allow ⇒ every link signed/temporal/grantee-resolvable) + `edgeOk_caveats` (§5.7) |
| **T7** | **§PR-8 dispatch frame split (the V2(a) invariant)** | verdict | **PROVED (S3)** | `grantPattern_namespace_isolation`: a granter-framed grant resource can't authorize a different peer's namespace (the 6-way-FAIL surface). `matchesSeg_head_lit` `[propext]`-clean; `canonSegs`-roots-relative-at-granter is the documented canonicalization contract |

## What S2 taught us about the spec

**The codec layer is provably sound as written.** T3 turned the shortest-float
ladder (which all nine cohort peers independently re-derived) into a machine-
checked theorem, and the Rule-4a specials proved *parametric over the entire
special class* — strictly stronger than the sample-byte conformance vectors. No
codec-layer spec finding emerged: ECF §4.1 Rule 4/4a and the key-ordering rules
hold up under formalization. This is the keystone-positive result for S2 — the
dry empirical well does **not** mean the spec is unverifiable; it means the codec
rules are *correct*, now provably.

The discovery-bearing proofs (T4/T5, where 1b predicted A-LEAN-1..4) are in the
verdict/attenuation layer and belong to S3. They re-confirm or drop when the
actual proofs are attempted, per the stance.

## What Lean *can* and *can't yet* say about T3 (read this before trusting "minimality")

This is the precision the proof track exists to surface — exactly what is and
isn't established, stated honestly.

**Fully proved (airtight):**
- **Losslessness.** For any non-special `bits`, the form `encodeFloatBits`
  emits, when widened back, equals `bits` exactly. (f16/f32 via gate soundness
  `tryHalf_widens`/`trySingle_widens`; f64 trivially since it carries `bits`
  verbatim.) The encoder destroys no information — the strongest *operationally*
  relevant float property, and it is proved.
- **Dispatch.** `encodeFloatBits` emits exactly: f16 if the f16 gate accepts;
  else f32 if the f32 gate accepts; else f64. A complete case characterization.
- **Rule 4a.** Every special bit pattern maps to its canonical bytes, parametric
  over the whole class — strictly stronger than the sample-byte vectors.

**Not yet proved — gate completeness, and therefore *strict* minimality.**
The gates are `tryHalf bits = if widen16 (doubleToHalf bits) == bits then …`.
We proved gate **soundness** (accept ⇒ exact widening). We did **not** prove gate
**completeness**: `(∃ h, widen16 h = bits) → tryHalf bits = some h`, i.e. that
`doubleToHalf` *finds* the f16 whenever one exists. Equivalently, the left-inverse
`doubleToHalf (widen16 h) = h`. Consequently `encode_uses_double`'s hypothesis
`tryHalf bits = none` means "the **candidate** `doubleToHalf bits` didn't round-
trip", not the full "**no** f16 represents `bits`". So the proven statement is
*"narrowest **gate-accepted** width"*, not *"narrowest **possible** IEEE form"*.

**Why it's true anyway, and why it's only a documentation caveat — not a bug.**
The candidate generators truncate the mantissa and map the exponent: if `bits`
*is* exactly f16-representable, its low 42 mantissa bits are 0 and its exponent
is in range, so truncation reproduces the exact f16 and the gate accepts. So
completeness *holds* operationally (and the 14 float conformance vectors —
including the discriminating `65503 → f32` / `100000 → f32` / `1.1 → f64` cases —
confirm it empirically). It simply isn't *formalized*: the left-inverse proof is
a bit-level case analysis across normal/subnormal/zero/inf, plausibly a target
for `BitVec` + `bv_decide`, deferred. **Until then, write "lossless + correct
dispatch", not "provably minimal".** This is precisely the soundness-vs-
completeness gap the formalization makes visible where the conformance vectors
alone would let "minimality" pass unexamined.

## Deferred-with-reason (the honest scope boundaries)

- **T3 gate completeness / strict minimality** — see the section just above. The
  encoder is proved lossless + correctly-dispatching; "no shorter form exists"
  needs the `doubleToHalf (widen16 h) = h` left-inverse (bit-level case analysis;
  `bv_decide` candidate). Operationally true (truncation + conformance vectors).

- **T2 totality** — mathematically routine; the obstruction is purely Lean-4.29
  tactic automation (`split_ifs`/`split` would not fire on the post-`fun_induction`
  swapped `if`-nest, and `simp` cannot do `<`-asymmetry on its own). A manual
  case-analysis proof is feasible with more time; revisit alongside T1.
- **T1 round-trip** — blocked on a total `decode`. The encoder is total and
  proven; the decoder is `partial` for Track A. Writing a kernel-reducible decode
  (well-founded recursion on unconsumed-input length, per 1b's `(dec)` note)
  unlocks both T1 directions (`decode(encode v) = some v` and the §10.3
  `Canonical(b) → encode(decode b) = b` anti-canonicalization property).

Neither deferral weakened Track A: the peer's codec is 69/69 conformant
regardless of proof status.

---

## What S3 proved — the attenuation/verdict layer (read for the T5a precision)

This is the discovery-bearing layer 1b predicted (A-LEAN-1..4). Outcome: **every
candidate confirms or resolves in the spec's favour; zero counterexamples.** The
dry empirical well (eight peers, no new spec defect) is matched here by a dry
*proof* well — but, as with S2's codec, "dry" means **the rules are correct, now
provably**, not that proof found nothing. The proof found the *reason* delegation
is safe.

### T5a — attenuation is monotone (THE result)

**Fully proved (airtight core):** `matchesSeg_trans` — the §5.4 segment matcher is
transitive — depends on `[propext]` only (Classical-free, no `Quot.sound`). The
proof is induction on the path with a four-way case on the pattern head; the one
dangerous interaction (a trailing `/*` absorbing many segments while a `/*/`
peer-wildcard absorbs exactly one) cannot break transitivity because a `"*"`
segment is *always* a wildcard, never matched as a literal — so the desync
branches carry a false hypothesis and close. De-risked first by brute force: **0
counterexamples in 2345 constrained triples** over `{a,b,*,""}` to length 3.

**Proved (lifted, with a documented stdlib axiom):** `scopeSubset_trans` →
`grantSubset_trans` → `isAttenuated_trans` compose the per-link check into the
global property **leaf effective authority ⊆ root authority**. The plumbing is one
reusable combinator, `all_any_compose` (`[propext, Quot.sound]`), which lifts a
transitive per-element relation through the `List.all`/`List.any` "every X covered
by some Y" shape. The lift theorems additionally report `Classical.choice` — see
the honesty note below; it is **not** from any tactic.

**What this does and does NOT say (soundness vs completeness, stated honestly):**
- It says: *the structural attenuation CHECK composes* — if each adjacent link
  passes §5.6, the leaf's grants are provably a subset of the root's, and the
  leaf's expiry provably does not exceed the root's. Delegation, as checked,
  never broadens. This is the security guarantee the per-link design relies on,
  and it was previously only assumed.
- It does NOT say: that the check is *complete* w.r.t. some external semantic
  notion of authority beyond the spec's own grammar, nor anything about the
  opaque boundaries the shell resolves — signature validity (`sigValid`, FFI
  Ed25519), granter-identity resolution (`granterPeer`, a store lookup), and
  grantee resolvability are RESOLVED Bool/Option inputs, exactly as `Float.toBits`
  is the float boundary. The theorem is "modulo the declared crypto/store
  boundary", which is the spec's own trust line.

### A-LEAN-3 made formal — the granter frame is load-bearing

The composition works only because the shared middle link canonicalizes on **its
own** granter frame, used on both of its chain edges. In `all_any_compose` the
middle list `ys` is read with `R_AB`'s right slot and `R_BC`'s left slot — for
those to agree the frame must be identical, which is exactly the §5.5a per-link
granter-frame discipline (the v7.73 erratum). So the proof does not merely *use*
the erratum; it shows the erratum is **what makes attenuation provably monotone**.
A stale `local_peer_id` frame (the pre-Amendment §5.6 text) would break the lift.

### T4 — the verdict factoring (A-LEAN-1/2 confirmed and made precise)

`verifyChain` is a pure total `def` of `(ResolvedChain, localPeer, now)` — so
determinism is structural. The substantive theorems pin down *time*:
`walk_time_stable` proves the walk's only coupling to `now` is the per-link
`temporalOk`, and `verifyChain_time_independent` proves a chain with no TTLs is
fully time-independent. Revocation is provably **absent** from the pure core (not
a field of `ResolvedChain`). So the §5.10 "deterministic Layer-1 verdict" claim is
satisfiable iff (a) time is sampled once and declared Layer-1, and (b) revocation
is Layer-2 — the two factorings, now machine-evident. These remain **open wording
reconciliations for arch** (the proof sharpens, does not drop them).

### T5b — termination & depth

`walk`/`verifyChain` are accepted as total `def`s (structural recursion on the
link list) — Lean machine-verifies termination by accepting them; with no
`partial` there is no obligation left to state. `chainExceedsDepth_iff`
(`[propext]`) confirms the §4.10(b) interception is a pure structural length test,
correctly gateable before the authz walk (→ `400`, distinct from `403`).

## Honesty gate — the `Classical.choice` nuance (important)

Every S3 theorem passes `#print axioms` with **no `sorryAx`**. Two axiom profiles
appear, and the distinction is the point:
- `matchesSeg_trans`, `chainExceedsDepth_iff` → `[propext]` (airtight).
- `all_any_compose` → `[propext, Quot.sound]`.
- `scopeSubset_trans`, `grantSubset_trans`, `isAttenuated_trans`, the
  `verifyChain_*`/`walk_time_stable` set → `[propext, Classical.choice,
  Quot.sound]`.

The `Classical.choice` is **inherited from Lean's standard library `String.splitOn`**
(well-founded recursion), which `canonSegs`/`splitSegs` call — *any* statement
that mentions path canonicalization pulls it transitively. It is **not** introduced
by a proof tactic (verified by bisection: a bare `theorem foo : canonSegs f p =
canonSegs f p := rfl` already carries it). This is a benign formalization artifact
of building on the stdlib path splitter, not a proof weakness — and the axiom
audit *surfacing* it is itself a small proof-track payoff. The security-critical
core (`matchesSeg_trans`) is deliberately stdlib-`splitOn`-free and stays airtight.

## T5c/T6 — what the end-to-end + dispatch proofs add (the "did we extract it all" pass)

A review pass asked whether `isAttenuated_trans` alone fully
certifies the security heart. It did **not** — it proved the per-edge check
*composes*, but not that the verdict *applies* it, and said nothing about the §5.2
dispatch gate (the other half of authority). Both gaps are now closed:

- **T5c — the verdict enforces the check, end-to-end.** `walk_allow_cons` proves
  `walk … = allow` implies every adjacent edge passed `edgeOk` (which contains
  `isAttenuated`); `edgeOk_atten` exposes the per-link granter frames (hard-fail on
  a `none` frame, §5.5a §4); the reflexivity chain (`matchesSeg_refl` →
  `scopeSubset_refl` → `grantSubset_refl` → `isAttenuated_refl`) gives the
  single-link base; and **`allowed_chain_leaf_atten_root`** folds them with
  `isAttenuated_trans` into the closed theorem: *an allowed chain's leaf entity is
  a genuine attenuation of its root entity.* With `verifyChain_foreign_root`
  (root-granter must be local), this is the full statement of **"a requester only
  ever wields authority the local peer actually delegated."** The verdict cannot
  `allow` a chain whose leaf broadens the root.

- **T6 — dispatch-gate defaults.** `checkPermission_no_grants_deny` proves a token
  with no grants is denied (deny-by-default — no authority without an explicit
  grant). `matchesScope_excl_override` proves a value in a scope's exclude set is
  never matched — **an exclude cannot be bypassed by any include** (§5.4
  deny-override). `checkResourceScope_no_targets_deny` adds the resource gate's own
  deny-by-default (no targets ⇒ no access). These are the security-critical
  defaults of the §5.2 gate. **Completeness:** `walk_allow_link_facts` (allow ⇒
  every link is signed, temporally valid, grantee-resolvable) and `edgeOk_caveats`
  (§5.7) close the "the verdict applies the *full* per-link check" story — the
  capstone is no longer attenuation-only; cryptographic authorship is named.

- **T7 — the §PR-8 dispatch frame split (the V2(a) invariant, the dangerous one).**
  `grantPattern_namespace_isolation`: a granter-framed grant resource pattern
  provably **cannot authorize a target in a different peer's namespace** — the
  dispatch-side analogue of A-LEAN-3, on the exact code (`checkResourceScope`) whose
  cap-resource canonicalization **FAILed 6-way pre-fix** (latent because granter ==
  verifier byte-collapses on self-issued caps). The matcher core
  (`matchesSeg_head_lit`: a literal pattern head forces the target head) is
  `[propext]`-clean. The one carried hypothesis (`hframed`: `canonSegs granterPeer`
  roots a *relative* pattern at `/{granterPeer}/…`) is the **canonicalization
  contract** — proving it from `String.splitOn` internals is mechanical stdlib
  plumbing (the same path-splitting boundary the running peer rides on); the
  *security logic* — framing ⇒ namespace isolation — is what is proved. This moves
  the most empirically-dangerous authority surface from suite-territory into proof.

This is the soundness story Lean is uniquely positioned to give: the interior of
the authority logic is now proven, which is exactly what lets the security *suite*
(fuzzing, live adversarial authz, concurrency/resource testing) narrow its focus
to the boundary — the parser, the resolve layer, and the IO shell (see "Limits"
below).

## Limits of the proof layer — where Lean stops and another tool takes over

The proof layer is bounded by four walls; each is owned by a different tool. This
is the honest map of what formal proof can and cannot certify for this peer:

1. **The crypto wall (`@[extern]`).** Ed25519 / SHA-256 / Ed448 are opaque axioms
   — the spec's own trust line (V7 cites them, does not define them). Lean proves
   nothing here and should not; formal crypto is a separate multi-year effort
   (EverCrypt / fiat-crypto). *Owned by:* the audited library + FIPS KAT vectors +
   the existing FFI-vs-native byte-equality cross-check.
2. **The IO-shell wall (transport / store / concurrency).** The resolve layer,
   socket demux, §6.11 reentry, the `Std.Mutex` store, §7b concurrency — effectful
   and/or interleaved. Core Lean (no separation logic, no concurrency calculus)
   cannot reason about them. *Owned by:* the §7b concurrency conformance gate,
   stress/race testing.
3. **The adversarial-input wall (the parser).** Lean proves the verdict correct on
   *well-formed* `ResolvedLink` inputs; it does not explore the hostile input space
   (malformed CBOR, oversized payloads, protocol confusion) nor prove the
   `partial` decoder rejects all bad bytes. *Owned by:* coverage-guided fuzzing of
   the decode path + the validate-peer `encoding`-rejection / `resource_bounds`
   categories. **Lean does not get us to the security suite here.**
4. **The resolve-layer wall (the shell↔pure seam).** The proofs assume the shell
   built `ResolvedLink` correctly (resolved the right granter frame, verified the
   sig, collected the full chain). If the shell resolves *wrong*, the proof is
   vacuous for that input. **This is also where the T7 frame-split's `hframed`
   hypothesis lives**: the proof shows framing ⇒ isolation, but trusts the shell to
   *frame relative patterns at the granter* — which is exactly where the 6-way
   V2(a) bug lived. *Owned by:* live two-peer adversarial authz scenarios (forged /
   foreign / over-deep caps), **and the forged-cap matrix must explicitly include
   "shell resolves the granter frame wrong"** — that is precisely the case that
   makes T7 vacuous. Shrinkable (a total `collectChain` pulls chain-collection into
   the proven layer) but the crypto/store reads stay opaque.
   - **Multi-sig (K-of-N) root authority is here, not in the proven model.** `walk`
     is the §5.5 *single-sig* path; `ResolvedChain.rootGranterIsLocal` collapses the
     root check to one `Bool`. The M6 threshold logic (local peer in the signer set
     AND signed; threshold ≥ 2; defensive dedupe) is entirely shell-resolved and
     opaque to the proof. Threshold-signature counting is its own bug-prone surface;
     it is either a future proof target (the counting is provable if lifted into the
     pure layer) or named here as shell-owned + covered by live multi-sig
     adversarial tests.

5. **The spec↔model-fidelity wall (the foundational assumption).** "No extraction
   gap" closes **proof ↔ code** (the proven functions *are* the running peer's
   code). It does **not** close **code ↔ spec** — that Lean's `verifyChain` /
   `checkResourceScope` are faithful transcriptions of V7 §5.5/§5.6. The entire
   proof is *relative to the model being the spec.* That link is owned by **Track A
   conformance** (validate-peer vs the cohort oracle), not by proof. The full trust
   chain: **`spec ─conformance─ peer code ─no-extraction-gap─ proven functions`.**
   It is the one assumption that, if wrong, makes everything above vacuous quietly.

**Net (calibrated):** for the **chain verdict**, Lean collapses *"is the authority
logic correct"* to near-certainty (attenuation-monotone + every-link-checked, the
full §5.5 walk). For the **dispatch gate**, the defaults AND the PR-8 frame-split
isolation (T7) are now proven — the previous "defaults-only" caveat is closed,
modulo the `hframed` canonicalization contract (wall 4). The security suite owns
*"does the implementation correctly feed that logic and reject hostile inputs"* —
complementary, non-overlapping; proof does not replace a security suite, it shrinks
the surface the suite must cover to the boundary, and (via the trust chain) rests on
conformance keeping the model honest.

## Deferred / future Track-B refinements

- **Total `collectChain` (the T5b depth bound at the source).** The parent-walk
  depth enforcement lives in the `partial` shell `collectChain`; lifting it to a
  fuel-bounded total function would let the >64 rejection be proved at the walk,
  not just characterized as a length predicate. Mirrors the S2 total-`decode`
  refinement; budget with T1.
- The S2 deferrals (T1 round-trip, T2 totality, T3 strict minimality) are
  unchanged.
