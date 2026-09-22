# entity-core-keystone — Red-Team / Critical Review (adversarial companion to the Project Retrospective)

**Date:** 2026-07-18 · **Status:** FIVE-dimension review complete (spec-minimality + security/design + the
extension boundary + a full implementation-history mine of all 427 A-* entries + the compute central-paradigm
angle + a blind-spots coverage sweep). Net: **zero novel in-core *defects*** (the one in-core bug is the
already-filed F37); **core is sufficient for its own central paradigm (compute, RT-15 — the strongest
vindication)**; the coverage well is confirmed dry. Residue: RT-13 (two concurrency-contract MUSTs), RT-14
(Go-ism hex-case), RT-10 (suspend-seam-naming, LOW), F-PQ (extension-layer), W6 (design proposal), and the
epistemic verdict-language right-sizing (RT-E → W5). RT-1 → RT-1′, RT-2 → a proposal, RT-3 rebutted (RT-14 =
its receipt), RT-6..RT-15 added, multisig/op-leak/clock-skew/Lean-§5.10/DoS refuted-or-already-fixed. ·
**Stance:** deliberately adversarial. **Companion to** [`research/PROJECT-RETROSPECTIVE.md`](../../../research/PROJECT-RETROSPECTIVE.md) — the retrospective is
left **untouched**; this doc stands beside it as the prosecution. A later synthesis pass will reconcile the
two.

## 0. Purpose and rules of engagement

The retrospective is the builder's view, and it is careful and mostly right. This document exists because a
builder's view of its own creation is structurally prone to acquittal — every reduction candidate the
retrospective raised, it ultimately dismissed (§7 below on why that pattern is itself a signal). The goal
here is **not** to prove the design is bad. It is to attack it as hard as an honest external reviewer would,
so that whatever survives the attack we can *trust*, and whatever the attack breaks we can *fix once* — which
is the whole point of a timeless-1.0 target.

**The framing correction that governs this whole doc:** the question is **"is this the right design?"** — not
"is it the absolute minimum?" Minimality is one lens among several; where it appears below it is a proxy for
"is there fluff we'd rip out, or a simpler shape that's more correct." The design *goal* of timelessness
(specify once, table it, be done, grounded in math/CS) is **legitimate and conceded** throughout — it is a
goal, not a defense, and nothing below disputes it.

**Honest-prosecutor rules** (self-imposed, because the user explicitly demanded receipts not rhetoric):
- Every substantive claim cites the spec section or source symbol, or it is downgraded to "structural risk /
  unverified."
- Attacks that did not survive contact with the source are **retracted in §6, with the receipts that killed
  them.** A red-team that only lists its hits is a press release.
- The project's real achievements are stated plainly in §8, so the eventual reconciliation is grounded and
  not a whiplash.

Spec citations are to the pinned snapshot `protocol-generator/shared/spec-data/v0.8.0/ENTITY-CORE-PROTOCOL.md`
(read-only boundary; never modified for this review).

---

## 1. Executive summary — the ranked slate

| # | Finding | Kind | Verified? | Severity |
|---|---|---|---|---|
| **RT-1′** | *(Original "core drew the identity line wrong" WITHDRAWN.)* **Verified + corrected:** the identity-extension **PQ-migration story is incomplete** — routine rotation (§4.3) needs the old key (useless post-break); compromise recovery (§4.4) is quorum-signed but the spec never requires the recovery quorum on an unbroken algorithm; cross-algorithm rotation is SILENT; enabling proposal has no file. **BUT the governing test vindicates core** — core provides the agility primitives and does NOT block an extension fix. Routes to identity/quorum, not core. | Substantive → **extension** gap | ✅ direct read §4.3/§4.4/§9.4/§9.5 | **Med** (core: vindicated) |
| **RT-2** | The §PR-8 6-way bug is a real foot-gun — but the useful output is a **concrete better design** (W6: mint-time resource absolutization) that makes the verify-time granter-frame bug class structurally impossible. The spec is already halfway there (explicit form for cross-peer). Plus: "six independent" overcounts (3 cohort + 3 independent, all vs one oracle). | Substantive / security + design | ✅ confirmed vs §5.5a + findings-log + §7 | **Med–High** |
| **RT-3** | ~~Both oracles derive from one impl (Go), propagating Go's choices as false convergence.~~ **Largely REBUTTED by source audit** (§4). Wire oracle is spec-corpus-driven + cross-impl-diffed (no privileged impl); privileged-Go-encoder pattern was explicitly retracted and a past instance removed. Residual is narrow: one Go-reflection dependency in the type-system gate + the cohort-*lineage* (not Go-specific) agreement risk the project already names. | Substantive / methodology | ✅ audited — strong form rebutted, narrow residual | **Low** (down from Med–High) |
| **RT-4** | **F44 residual**: broad accept-path coverage *does* exist (multisig accept vector, authz attenuating from real grants, capability 200 paths — audit-confirmed). The narrow open gap is whether **constraint / allowance / delegation-caveat attenuation** specifically is exercised on the accept path. | Substantive / coverage | ✅ narrowed vs oracle audit + findings-log | **Low–Med** (down from Med) |
| **RT-5** | **F45** may be under-rated. §4.10 per-request bounds do **not** bound *cumulative* store growth from §6.5 signature ingestion; on a no-eviction memory-primary peer that is monotonic, not "just wasteful." | Substantive / minor | ✅ confirmed vs §6.5, §4.10 | **Low** |
| **RT-6** | **Anti-replay security rests on a SHOULD.** The nonce-*echo* check is MUST (§4.6), but nonce **freshness / single-use / unpredictability** (§4.6 "Hardening") is only **SHOULD** — a conformant peer with a weak or reused nonce is replay-vulnerable. The security property should be a MUST, even if only weakly conformance-testable. | Substantive / security | ✅ confirmed vs §4.6 (1803/1811) | **Low–Med** |
| **RT-7** | **Hash-agility ≠ crypto-agility** — the retro treats F42/F43 as parallel "chosen MAY dimensions," but signature-agility *composes* (live heterogeneous network fine) while hash-agility *fragments* the content-address space (heterogeneous = two address spaces, §1.5/§441; wholesale-network-migration-only). Both share RT-1's "core provides the knob, migration is unsolved." | Substantive / design + framing | ✅ confirmed vs §1.5, §441, §4.5a | **Med** |
| **RT-8** | **Resolution-first dispatch leaks handler existence** — §6.7 returns 404 (not-found) vs 403 (denied), so any *connected* peer can enumerate a peer's installed handler patterns with zero grants. Acknowledged + mitigable in-spec, but a reconnaissance default. | Substantive / security | ✅ confirmed vs §6.7 (3461) | **Low** |
| **RT-9** | **Revocation posture is weak-by-default** (the eventual-consistency itself is conceded as physics). The fail-safe (validation-time re-check) is only **MAY**; propagation latency is unspecified. An un-synced peer will validate a revoked cap (spec says so: §5.10, EXT-IDENTITY §6.4/§9.6) — unavoidable, but the *defaults* around the unavoidable window could be stronger. | Substantive / security posture | ✅ confirmed vs §5.10 + EXT-IDENTITY | **Low–Med** |
| **RT-10** | **CONTINUATION's dispatch-suspension seam** (§3.8/§3.9 `suspend()` + `chain_depth` threading) is a **core-dispatcher hook specified only in an extension** — no counterpart in core text. Optional (sync-only peers skip it), but a boundary-documentation gap. *(Needs re-verification vs the pinned V8 snapshot — one input read a sibling copy.)* | Substantive / boundary | 🔶 confirmed, pending snapshot re-check | **Low** |
| **RT-11 (= F37)** | **In-core defect, but ALREADY FILED (not novel):** the identity primitive is `system/peer-id` in core (§2.8 + all type_refs) vs `system/identity/peer-id` in the type-system bootstrap (§4.4/§4.8/App. A) — a Level-2 resolution break + namespace violation. **This is F37**, surfaced by the Pd build (A-PD-012), handoff written, in the F32–F41 digest. Red-team re-derived it from spec-reading; corroboration, not discovery. | Core correctness (known) | ✅ verified directly + matched to F37 | **Med–High** (already queued) |
| **RT-12 (= F37 note)** | **Bootstrap count "14" vs ≥15** — already the "secondary" note in the F37 handoff. Corroborated, not new. | Core editorial (known) | ✅ verified | **Low** (already queued) |
| **RT-13 (NEW)** | **Concurrency-contract under-specification pattern** (from the implementation-history mine): §4.8 never states shared-entity refcounts MUST be atomic/lock-guarded (A-C-009 → use-after-free under the live gate); §1.6 never states frame-write atomicity under concurrent dispatch (A-IO-002 → interleaved-frame corruption on a yielding write). Both are unstated MUSTs *free on GC/atomic-write substrates, load-bearing on manual-memory/yielding ones* — the class spec-reading can't see. **UNCAPTURED** (absent from F1–F46). | Substantive / core (concurrency) | ✅ mined + capture-checked | **Med** |
| **RT-14 (NEW = RT-3 receipt)** | **Address hex-case is a de-facto Go-ism** (A-CL-009): tree-path content-hash hex is lowercase *only* because the Go ref impl's `hex.EncodeToString` defaults lowercase; the spec never says so. Uppercase-hex substrates pass self-loopback, fail the oracle. **This is the concrete "Go convention became de-facto spec" receipt RT-3 asked for**, caught in the wild. UNCAPTURED. | Substantive / core (+ RT-3) | ✅ mined | **Low–Med** |
| **RT-15 (5th dimension — VINDICATION)** | **Core is sufficient for its own central paradigm (compute).** The entity-native minimal evaluator rides the frozen core cleanly — its seams (`expression_path` §3.7, entity-native dispatch §6.6, emit §6.10/§6.13c) are *already in the frozen V8 text*; the axis-1 prototype forced **no new primitive**. Compute self-bounds; core's §4.9/§4.10/§6.11c backstop suffices. The only core touch near the track (`chain_depth`→§3.11 bounds) is **network-forced + additive**, not compute-forced. | Substantive / core-vindication | ✅ spec-verified + prototype-corroborated (*not* independent keystone build) | **N/A — positive** |
| **RT-E1** | The central minimality claim is **circular**: "the mandatory core is minimal because §9.1 labels it MUST." That is deference to the designers' own partition, not an independent finding of irreducibility. | Epistemic | ✅ vs retro §8.7 | **High (epistemic)** |
| **RT-E2** | ~~"Timeless minimality" is a blanket absolution.~~ **LARGELY RETRACTED** — the timeless frame is the correct, load-bearing rationale and argues *for* core minimality (you live with the core forever; growth lives in extensions; agility = the mutable parts are swappable). Residue is a wording note only. | Epistemic | ✅ retracted on review | **Low** (was Med) |
| **RT-E3** | "Triangulated-minimal" oversells **one** paradigm (relational/logic) as three independent witnesses. Three relational dialects agreeing proves the structure is *relational*, not *minimal*. Expressibility ≠ minimality — the same error §8.1 warned about. | Epistemic | ✅ vs retro §8.6 | **Med** |
| **RT-E4** | The §8 argument sections **contradict the §7 honesty posture**: §7 disclaims independence/convergence-as-strength, then §8 leans on exactly that framing for the load-bearing conclusions. | Epistemic (internal contradiction) | ✅ vs retro §7 vs §8 | **High (epistemic)** |
| **RT-E5** | Meta-tell: a "critical" minimality review that removed **nothing** from the design, dissolving every candidate via a freshly-introduced frame, is exhibiting the acquittal bias a self-review is prone to. | Epistemic | ✅ vs retro §8.3–8.8 | **Med** |

**Retracted / rebutted after verification (§6):** performance/DoS-surface-unaddressed (killed by §4.10);
unbounded chain-walk DoS (killed by §4.10(b)/§2456 `max_depth=64`); Base58 as a serious wart
(presentation-only, canonical form mandated); and **RT-3's strong "Go defines and checks" form** (killed by
the oracle-source audit — see §4).

**The finding that survives verification as possibly-wrong-today is RT-1′** (the PQ *migration mechanism* is
self-defeating + unspecified — note the original "core drew the identity line wrong" charge was WITHDRAWN;
the boundary is fine). RT-2 produced a concrete better design (W6). RT-4/RT-9/RT-6 are real but narrower.
RT-3 largely fell to its own audit — the honest outcome, and a point *in the project's favor*. The RT-E
series is about whether the retrospective's *verdict* is earned, independent of any single finding. A
red-team that lands one strong substantive hit, produces one design proposal, narrows several, and retracts
others after checking the source is doing its job — the goal was never a body count.

---

## 2. RT-1 → RT-1′ — PQ migration is an unfinished *identity-extension* gap; core is vindicated (MED)

*(Original RT-1 "core drew the identity line wrong" is withdrawn. After a direct read of the rotation
mechanism, the finding is real but narrower than the first draft, and — by the governing "can an extension
fix it without a core change?" test — it lands against the identity/quorum extensions, not the frozen core.)*

### The claim under attack
Retrospective §8.7.1: *"the agility genuinely **is** the PQ-migration mechanism, the strongest possible
justification under the frozen-core target."* §8.4: built-in agility *"is the mechanism that keeps the
promise [never reopen core]."* This is the load-bearing justification for keeping a crypto-algorithm table
in the frozen core, and it is used to **close F43**.

### What the spec actually says (receipts)
Identity in entity-core is a pure function of `(public_key, key_type)`:

- **§1.5:** `PeerID := Base58(varint(key_type) || varint(hash_type) || digest)` — the peer_id is
  `Base58(key_type || hash_type || hash(pubkey))`, "stable across the peer's life **unless its key
  changes**."
- **§1.3 / §3.5 / §1.5 v7.65 contract:** `content_hash(system/peer)` is "a **pure function of
  `(public_key, key_type)`**." All identity-internal references — the `signer` on signatures, the `granter`
  and `grantee` on capabilities (§3.6) — reference this `content_hash`.
- **§5.5:** capability chains are rooted at that peer content_hash.

Therefore, changing `key_type` (Ed25519 → any PQ algorithm) changes the public_key **and** the key_type →
a **different content_hash → a different peer_id → a different identity.** Every capability chain rooted at
the old identity is void against the new one.

And the spec is explicit that migration-with-continuity is **not core**:

- **§1.5a:** *"The core protocol **alone** gives each peer a self-rooted identity ... This is sufficient for
  ... peers that **don't need recovery ... or [key] rotation**."*
- **§1.5a / §4.7:** *rotatable* presence, recovery, and "stable cross-peer recognition **across
  rotations**" are provided by **`EXTENSION-IDENTITY`**, a composition layer over **`EXTENSION-ATTESTATION`
  + `EXTENSION-QUORUM`** — a three-extension stack, explicitly out of the core floor and out of the
  retrospective's minimality scope.

### What I got wrong, and what survives (recalibrated after review + an EXTENSION-IDENTITY audit)
My first draft attacked "core doesn't do identity migration" as if the core/extension line were drawn
wrong. **That framing is withdrawn — it was the same strawman error I nearly made elsewhere.** Two
concessions, both correct:

1. **"Keys are your identity" is deliberate and right.** Content-addressed identity means the key *is* the
   name; switching keys = a new identity, by design. That is not a defect — it is what keeps identity a pure
   function of the key with no mutable core state, which is exactly what a minimal, timeless core wants. The
   design never promised identity transfer across a key switch, and it shouldn't.
2. **The core/extension boundary is coherent — there is NO missing core hook.** An EXTENSION-IDENTITY audit
   confirms it delivers continuity by *relocating* the principal off the key onto a **quorum** (the quorum's
   content-hash is the durable handle; EXTENSION-IDENTITY §2.1, §11.4), built entirely on core primitives
   (signatures, caps, tree, quorum-as-entities). Core §1.5 (v7.69) deliberately keeps cross-key recognition
   "never in the core verification algorithm," and the extension respects that exactly (§9.5: old-key caps
   die on retirement — continuity-by-relocation, not continuity-of-the-core-identity). So core did *not*
   draw the line wrong. Concede fully.

**A real finding survives underneath — but I verified it directly and it is narrower (and more accurate)
than the subagent framing. Applying the governing test — "can an extension fix this without a core change?"
— it lands as an EXTENSION gap, not a core defect, which is the outcome that VINDICATES core.**

### RT-1′ — The identity extension's PQ-migration story is incomplete and doesn't robustly survive a primitive break (MED; core supports the fix)
The retrospective's claim "agility **is** the PQ-migration mechanism" is fine for the *protocol* reading
(the key_type/hash_type tables let new identities/networks adopt PQ without reopening core — true, correct,
in core). Cross-algorithm continuity of an *existing* identity is EXTENSION territory (the quorum-handle
model). I read the actual rotation mechanism (EXTENSION-IDENTITY §4.3/§4.4/§9.4/§9.5) — receipts, with a
self-correction of the first draft:

- **Routine rotation (`identity-rotation-handoff`, §4.3) needs the old key** — "dual-sig: both `attesting`
  (old) and `attested` (new) keypairs sign," and it is explicitly "when the old cert's key is still
  available." So the *proactive/graceful* path is useless once the old algorithm is broken (an adversary
  who can forge the old key forges the handoff). Proactive migration would have to happen *before* the break.
- **Compromise recovery (`identity-rotation-recovery`, §4.4) does NOT need the old key** — it is quorum
  K-of-N signed (`attesting: quorum_id`). *(This corrects my first draft, which wrongly said "succession is
  authenticated by the outgoing algorithm" universally — recovery is authenticated by the quorum, not the
  old key.)* **But** its security then rests on the quorum constituents' algorithm, and the spec **never
  requires the recovery quorum to be on a stronger/independent (unbroken) algorithm.** In the realistic
  homogeneous deployment — an Ed25519 identity with an Ed25519 recovery quorum — recovery after an Ed25519
  break is forgeable too. So there is *no specified guarantee* of an unbroken recovery path across a break.
- **Cross-algorithm rotation (a `key_type` change at `attested`) is entirely SILENT.** EXTENSION-IDENTITY's
  "multi-key" is *role*-based (controller / agent / identifier for device hygiene, §11.4) — **not**
  algorithm-based. No text addresses a key_type change at rotation, hybrid (old+new algorithm) signing, or
  PQ migration. The referenced `PROPOSAL-MULTIKEY-MULTIHASH-ALIGNMENT` has **no proposal file anywhere in
  the arch repo** (verified — the whole substrate-proposal stack is referenced in specs but absent as
  files), and its content is not reflected in the current identity-spec text.

### Applying the governing test — core is vindicated
Can the extension fix this **without a core change?** **Yes, as far as I can determine** — and that is the
answer that matters:
- Core provides `key_type`/`hash_type` agility with reserved ranges and no wire break (§1.5) — sufficient
  primitives for a new identity of a different algorithm.
- A "multi-algorithm identity" is necessarily a higher-layer construct over multiple core (pubkey,key_type)
  identities bound by a quorum handle — which is *exactly what EXTENSION-IDENTITY already does* for
  multi-device. Core does not need to change to allow it.
- Nothing in core *blocks* an extension from specifying: cross-algorithm rotation, hybrid signing during a
  transition window, and a requirement that recovery quorums be provisioned on a stronger/independent
  algorithm ahead of a break.

So this is **not a core-protocol defect and core does not force bad design** — it passes your test. It is a
genuine, unfinished **identity-extension** gap: the PQ-survival story is incomplete, and as currently
specified the recovery path has no guaranteed unbroken anchor. Worth fixing before the ecosystem leans on it,
but it routes to identity/quorum, not to the frozen core. *(It still reinforces RT-7: for both signatures
and hashes, core provides the knob and the live-migration story lives — unfinished — above core.)*

### Proposed disposition
- **Do NOT re-open F43, and do NOT file F-PQ against core.** Core is vindicated on this axis by the governing
  test. The §4.5 "downgrade-free by identity-binding" sub-result stands separately.
- **File F-PQ against the identity/quorum EXTENSIONS (MED):** specify cross-algorithm rotation; require the
  recovery quorum to sit on a stronger/independent algorithm provisioned ahead of a break; add hybrid
  signing for the transition window. Write/land `PROPOSAL-MULTIKEY-MULTIHASH-ALIGNMENT` (or successor) — it
  is named but has no file.
- **The one core-side thing to keep honest:** confirm no core assumption silently couples "one identity =
  one key_type" in a way an extension can't route around. My read says the quorum-handle model already
  routes around it (core identity stays per-key; the *principal* is the quorum), so core is clear — but this
  is the sentence to double-check if F-PQ ever escalates.

---

## 3. RT-2 — The §PR-8 six-way bug indicts understandability; the "independence" is overcounted (HIGH)

### The claim under attack
Retrospective §8.6.3 frames the §PR-8 bug — six implementations independently mis-handling granter-frame
canonicalization — as *"the strongest possible signal that a rule was under-specified"* and casts
granter-relativity as *"the price of its best property (least-privilege-by-default)."*

### Receipts
Confirmed in `SPEC-FINDINGS-LOG.md` (§PR-8 rows): the vector
`captok_form_dispatch_minted_pl_presented_xpeer` was **ACCEPTED 200 pre-fix (6-way convergent FAIL) →
denied 403 post-fix.** Six impls: keystone OCaml/C#/TS + Go/Rust/Py. The bug was an **over-acceptance /
privilege-escalation** (accepting a cross-peer capability that MUST be denied), and it was invisible until a
new vector was authored — the oracle did not catch it on its own.

### The design challenge, met: is there a better design, or is this irreducible?
The fair objection (raised in review): calling something a foot-gun is empty without a better design on the
table — a forever-substrate has real essential complexity, and "this part is tricky, get it right" is a
legitimate spec statement, not automatically a defect. So the burden is to produce a concretely simpler
design or concede the complexity is irreducible. **After reading §5.5a in full, there is a concretely
better design, and the spec is already halfway to it.**

The mechanism (§5.5a): a capability's resource patterns canonicalize against the **granter's** peer_id, at
**verify** time. A bare `*` means `/{granter}/*`. The bug is canonicalizing against the *verifier's* peer_id
instead — invisible for same-peer caps (the two frames coincide, byte-identical) and only exposed
cross-peer. Both documented bug-shapes (canon-against-wrong-frame; wildcard-shortcircuit-before-canon,
§5.5a footnote) are verify-time-canonicalization bugs.

The decisive observation from §5.5a itself: **a bare relative resource is only ever valid at root-mint over
the granter's own resources.** The moment a cap is *delegated* (mid-chain granter Bob delegates access to
Alice's resource) or points *cross-peer*, the resource frame (the owner, Alice) is **not** the granter frame
(Bob) — so relative-to-granter is meaningless there, and the spec **already mandates explicit absolute form**
for exactly those cases (§5.5a "cross-peer dispatch caps MUST use explicit resource form," the E4 fix).

That is the whole finding: relative forms are valid *only* in the one case (root-mint, granter = resource
owner = the local peer) where **mint-time absolutization is trivial** — the minter unambiguously knows its
own canonical peer_id. So the better design is: **canonicalize resource patterns to absolute form at MINT
time, store/transmit absolute, and do pure absolute matching at verify.** Consequences:
- The entire verify-time granter-frame bug class becomes **structurally impossible** — you cannot
  canonicalize against the wrong frame if there is no verify-time canonicalization. The property is
  correct-by-construction, not correct-by-careful-prose.
- The cost is small and bounded: the resource string denormalizes the granter's peer_id (redundant with the
  cap's `granter` field), and the symbolic "`*` = my namespace" convenience is lost — but per the delegation
  analysis that convenience was never valid past root-mint anyway.
- **The spec already went halfway** (mandating absolute form for cross-peer) — which is itself evidence the
  direction is sound. The finding is that stopping halfway is what *preserves the latency*: keeping
  verify-time relative canonicalization for same-peer caps is exactly what makes the bug hide (same-peer
  relative ≡ absolute) until a cross-peer cap trips it. Going all the way to mint-time absolutization trades
  one redundant peer_id string for eliminating a security-critical bug class that beat 6/6 implementations.

**Honest caveat:** this is offered as a *proposal to pressure-test*, not a proven win. The thing to hunt for
is a capability shape whose resource frame genuinely cannot be resolved at mint (e.g. a lazily-minted
role-derived cap, or the §1.5 rule-3 "mint without pubkey" case). The rule-3 case is about the *target
peer's* id-form, orthogonal to the *granter* frame (the granter is always the local peer at mint), so it
does not obviously block absolutization — but it is the first place to look for a counterexample. If no such
shape exists, RT-2 is a genuine simplification for a 1.0; if one does, the complexity is irreducible and the
retrospective's "state it with care" response is the correct one, honestly earned.

### The independence overcount (this prong stands)
"Six independent readings" overcounts independence — and the retro's own §7 says so. §7 states
plainly: *"cohort-consistent ≠ independent convergence ... the only genuinely independent bases are the
three ground-up reference implementations (go, rust, py)."* So the "6-way" is **3 independent + 3
cohort-lineage** peers — and all six were tuned against **one Go-derived oracle** (see RT-3). The correct
reading of PR-8 is: *three independent bases plus a shared-lineage cohort all made the same error, and the
shared oracle did not encode the rule that would have caught it.* That is still a strong "under-specified"
signal — but it is also a strong signal about the **oracle's blind spot**, which the retro does not draw.

### Proposed disposition
- Keep §PR-8 CLOSED (the fix is real and 6-way). But **open a design-review item (W6): mint-time resource
  absolutization** as a candidate simplification that would make the whole granter-frame bug class
  structurally impossible. Pressure-test it against the "resource frame unknowable at mint" counterexample
  hunt above; if it survives, it is a real correctness-by-construction win worth landing before 1.0 (when
  changing it becomes prohibitively expensive, per the timeless-cost argument). If it fails, retract to "irreducible
  essential complexity, correctly flagged" — an honest outcome either way.
- **Record the meta-finding** regardless: the most-corroborated authorization bug in the project was (i) the
  *natural* reading for six implementers and (ii) invisible to the oracle until hand-authored. Both point at
  hardening the *method* (feeds RT-4) and at the correct-by-construction principle (feeds W6).

---

## 4. RT-3 — "The oracle is Go, so convergence is monoculture" — LARGELY REBUTTED by source audit (LOW)

### The claim I brought — and why I checked it hard
The strong form: both oracles are built from `entity-core-go`, so peers are tuned to **Go's reading** of the
spec; where the spec is ambiguous, the oracle propagates Go's choice as false convergence, and genuinely open
ambiguities are invisible to a Go-derived oracle ("Go defines and checks"). The user explicitly demanded
this claim be backed by source receipts or retracted. I ran a source audit of the actual oracle
(`cmd/internal/validate/*`, `cmd/validate-peer`, `cmd/internal/wire-conformance` in the read-only
`entity-core-go` sibling) against the spec. **The strong form does not survive.**

### What the audit found (receipts — this is the honest result)
**The wire oracle is not self-referential.** The vector corpus is authored in the *spec* repo
(`entity-core-protocol/specs/test-vectors/ecf-conformance/conformance-vectors-v1.diag`), hand-authored
against `ENTITY-CBOR-ENCODING.md Appendix E`, with canonical bytes filled in by *cross-impl byte-equality*,
not Go's emission. The `conformance` category (`conformance.go:diffEncodeEqual` / `diffDecodeReject`) is an
N-way diff requiring **all impls to agree**; a single-impl run returns `WarnCheck("cross-impl gate requires
2+")` — **Go is a participant, never the referee.**

**The privileged-encoder pattern was explicitly retracted, and a past Go-ism was found and removed.**
`GUIDE-CONFORMANCE.md §3.4`: *"The earlier proposal text named Go's `core/ecf.go` as the reference
encoder… That framing is **retracted**… No impl is privileged."* A historical instance where
`ecf_key_ordering` validated against Go's `ecf.Encode` was caught (keystone finding) and rewritten to a
direct structural walk (`ecf_keyorder.go:verifyCanonicalKeyOrder`, with a comment refusing the
"privileged-encoder anti-pattern"). **This is the process working** — exactly the correction my finding
assumed hadn't happened.

**The security categories deliberately carry accept paths — implementing our own vacuous-green lesson.**
`multisig.go:runMultiSig` includes `valid_2of3_peer_signed_accepted`, whose docstring says verbatim:
*"Without it, the whole category is rejection-only, so a peer that simply fail-closes… passes identically to
a genuine implementation."* `authz.go` attenuates from the peer's **real authenticated grants**
(`client.Grants()`, `buildAttenuatedChildCap`), not a fail-closed default; `capability.go` has explicit
`200` happy paths.

**A genuinely-ambiguous point is left open, not pinned to Go — the direct counter-example.** For the
`delegate` zero-parent case the impls split (Go=400, Rust/Py=404). The live oracle accepts `501 | 400 | 404`
and only WARNs otherwise — it is *more lenient than Go's own pinned answer*. If the monoculture mechanism
were operating, this is exactly where it would silently enforce Go's 400; it does not.

**The status-code surface is spec-normative, not Go-isms:** §3.3 status table, §4.7 connect-error
"normative MUST-emit contract," §4.10(b) `400 chain_depth_exceeded`, §5.2a verdict-to-status. Where the spec
resolved an ambiguity by fiat (`unresolvable_grantee → 401`), the resolution lives *in the spec*.

### The narrow residual (what actually survives)
- **Finding-1 (MODERATE, bounded): the type-system required-field gate references Go's reflected registry.**
  `typesystem.go:runTypeSystem` builds a reference registry via Go reflection over Go structs +
  hand-authored `OverrideField` tables; a required-field type-ref divergence FAILs. A *missing* override
  would silently make Go's reflected rendering (e.g. Go `uint64 → primitive/uint`) the gate. **Cushioned**
  by: a spec-deterministic `content_hash` comparison *first* (identical hash → PASS independent of Go),
  optional-field divergences downgraded to WARN, and the keystone's own "render natively; Go vectors are a
  *drift* target" doctrine. This is the one real "Go's reading is the gate" instance — bounded to
  under-specified rendering corners.
- **The real monoculture axis is cohort-*lineage*, not Go.** `conformance.go` can pass by consensus
  (`allErrored` "pass-by-consensus"); agreement can be vacuously wrong. But this is a property of shared
  generation lineage + agreement-based gating, which the project **already names** (GUIDE §304: *"all six
  generated peers independently re-wrapped `value`… cohort agreement ≠ conformance… Don't predict cohort
  conformance from the reference impls"*; AGENTS.md: "cohort-consistent, not independent convergence"). The
  cross-impl diff is the *mitigation*, and it has caught real cohort-wide bugs (the `value` re-wrap; the
  `AUTHZ-ATTENUATION-FOREIGN-GRANTER` family where "all 5 non-Go impls FAILed").

### Honest disposition
I withdraw the strong RT-3. The residual is (a) Finding-1's bounded type-system Go-reflection dependency,
(b) the cohort-lineage risk the project already documents, and (c) **RT-14 — the one concrete "Go convention
became de-facto spec" instance the implementation-history mine actually caught in the wild:** tree-path hex
is lowercase *only* because Go's `hex.EncodeToString` defaults lowercase, never stated normatively (A-CL-009).
That is exactly the monoculture mechanism this finding hypothesized — small blast radius, real, and now with
a receipt. The corresponding work-stream (**W2 — a second
independent `validate-peer`**) is still worth doing, but for the **cohort-lineage** axis, not because "Go
defines and checks" — that specific charge is false, and the codebase has the receipts to prove it. This
outcome should raise, not lower, confidence in the conformance method; it is one of the strongest points in
the project's favor that the audit surfaced.

---

## 5. RT-4 — The F44 residual: constraint/allowance/caveat *attenuation* accept-path coverage (LOW–MED)

### First, the concession (audit-driven)
My opening framing — "authz accept-path correctness is unsubstantiated cohort-wide" — was **too broad**, and
the oracle audit corrects it. Broad accept-path coverage **does** exist: `multisig` has an accept vector
(`valid_2of3_peer_signed_accepted`) that genuinely satisfies a threshold with the peer's real key; `authz`
attenuates from real authenticated grants (not a fail-closed default); `capability` has `200` happy paths.
So the cohort is *not* passing the whole authorization surface vacuously. RT-4 shrinks to F44's actual,
narrower residual.

### The residual (receipts)
`SPEC-FINDINGS-LOG.md` F44 (OPEN): the **mechanism** is §9.1 **MUST** — constraint key-retention +
byte-equality, allowance key-containment + byte-equality (§5.6); delegation-caveat depth/ttl (§5.7). The
precise open question is whether the **constraint / allowance / delegation-caveat attenuation** predicates
specifically are exercised on the **accept** path (a cap that, after a constraint is added or an allowance is
dropped, must still ALLOW the narrowed action), or only on the reject path. The audit confirmed accept-path
coverage for *multisig / authz / delegate*, but did **not** surface a constraint-added / allowance-dropped /
caveat-honored **accept** vector. A §9.1-MUST predicate with only reject-path coverage is the vacuous-green
shape (cf. the historical `multisig` 100%-reject state, F34/F35).

### Why it still matters (narrowly)
This is now a *specific* coverage gap, not a systemic one: a peer could fail-closed on the attenuation
predicates and still pass, so we cannot presently assert the cohort implements §5.6/§5.7 attenuation
*correctly in the allow direction.* Given RT-2 (six impls got a neighboring canonicalization rule wrong
until a vector forced it), an untested attenuation accept-path is exactly the kind of place a latent
cohort-wide divergence could sit.

### Proposed disposition
- Keep F44 OPEN, framed precisely as above (not the broad version I first wrote).
- **Work-stream W3:** author accept-path vectors for constraint-added / allowance-dropped / caveat depth+ttl
  honored, and re-run the cohort. Low effort, closes the one authorization corner the audit left dark.

---

## 6. RT-5 — F45 may be under-rated: per-request bounds ≠ cumulative bound (LOW)

`SPEC-FINDINGS-LOG.md` F45 calls §6.5's per-request signature binding "not a correctness defect ... just
wasteful," low priority. Reading it against §4.10: the resource bounds are **per-request** (max payload,
max chain depth). Nothing in §4.10 bounds the **cumulative** growth of a memory-primary store from §6.5
`ingest_envelope_signatures` binding one unique request-root signature per request. On a no-eviction
memory-primary peer that is **monotonic growth over the peer's lifetime**, which the per-request caps do not
address — closer to a slow resource-exhaustion path than to "just wasteful." Two peers hit it independently
(Io A-IO-022, Rexx A-RX-014).

**Conceded counter:** content-addressed stores dedupe, and identity/handshake/cap signatures are reused →
idempotent; only the *unique per-request* signature grows, so it is bounded by traffic and trivially fixed
(don't persist a signature whose target is the request root). So this is minor — but it should be recorded
as *"per-request bounds do not imply a cumulative bound"* rather than dismissed as a doc nit, because that
gap is a small instance of a general spec discipline (bound the sum, not just the item).

---

## 6b. Second-pass angles (shifting perspective — replay, agility asymmetry, dispatch, revocation, boundary)

New surfaces probed on a second pass, from different angles than the minimality lens. Some landed; the
refuted ones are in §8.

### RT-6 — Anti-replay security rests on a SHOULD (LOW–MED)
The handshake's replay resistance is the nonce-echo: the responder issues a per-connection nonce, the
initiator echoes it in `authenticate`, and a mismatch/pre-hello nonce MUST be rejected 401 (§4.6, line
1803). That *check* is MUST. But the property the check depends on — that the nonce is **fresh, ≥32-byte
CSPRNG, and single-use** — is only **SHOULD** (§4.6 "Hardening," line 1811). A peer that uses a predictable
or reused nonce passes conformance (the echo check still fires) yet is **replay-vulnerable**: capture an
`authenticate` for a predictable/reused nonce and replay it. This is the vacuous-green shape one level up —
the mechanism is mandated, the *security* of the mechanism is optional, and RNG quality is hard to
conformance-test so nothing catches it. **Fix:** elevate "nonce MUST be unpredictable and single-use" to a
normative MUST (a semantic MUST even if only weakly testable), so a reused-nonce peer is non-conformant by
the letter, not just by good taste. (`hello.timestamp` is correctly *not* an anti-replay input, line 1811 —
that part is right.)

### RT-7 — Hash-agility ≠ crypto-agility; the retro's parallel treatment blurs a real asymmetry (MED)
The retrospective treats F42 (hash-format agility) and F43 (crypto agility) as parallel "chosen MAY
dimensions that both dissolve." They are **not** parallel in operational character:

- **Signature agility composes.** Each identity signs with its own key; verifiers check against an
  advertised accept-set (§4.5); a live network of mixed algorithms interoperates fine. No fragmentation.
- **Hash agility fragments the address space.** `content_hash` *is* the identity of every entity, so two
  peers on different `content_hash_format`s inhabit **two content-address spaces**: "a lookup in one address
  space will not find content authored in the other ... nothing matches by hash across the two" (§1.5/§441).
  §4.5a keeps one active format per connection precisely so the question doesn't arise on the wire.
  Heterogeneous hashing is **experimental / out-of-v1**, and cross-form correlation needs a bridge-translator
  extension.

So hash-agility is not "agility" in the composable sense — it is **wholesale-network-migration-or-nothing**,
and coordinating a wholesale hash migration across a decentralized network is a hard, arguably-unsolved
operational problem. That makes hash-agility share **exactly RT-1′'s gap**: core provides the *knob* (use a
different hash) but the *migration* of a live network's installed content is unsolved and shoved to
experimental/extension territory. The finding is precision + reinforcement: the "agility = we survive a
break without reopening core" story is true for the knob in *both* dimensions and unproven for the migration
in *both* dimensions. Worth stating plainly rather than letting the parallel F42/F43 framing imply hash-
agility is as clean as signature-agility.

### RT-8 — Resolution-first dispatch leaks *handler* existence (LOW) — but NOT operation existence (that expansion refuted)
§6.7 (line 3461) is explicit and honest: dispatch resolves the handler *before* the permission check (it
must — §5.2 `check_permission` needs the resolved handler pattern as input), so an unauthorized request to an
**unregistered** handler returns `404 handler_not_found` while an unauthorized request to a **registered**
one returns `403 capability_denied`. Consequently **any connected peer can enumerate a peer's installed
handler namespace** by reading status codes. The spec documents the trade-off and offers a deployment-level
mask (a network boundary or a deployment-wide cap-check above §6.5). Severity is low — authenticated-peer
reconnaissance (a connection/handshake is required), documented, mitigable — but a reconnaissance-friendly
*default* for a foundational substrate, worth a paranoid-deployment note and possibly a spec-level "MAY
return 404 for authz-denied to mask existence" option.

**A tempting expansion — operation-existence leak via `501 unsupported_operation` — is REFUTED** (I traced
the dispatch order to check, because the intuition "we return 501 for unsupported ops, so it leaks which ops
exist" is reasonable). The order is: `verify_request` → `resolve_handler` (404) → **`check_permission`**
(403 on handler+**operation**+peer+resource, §6.7 Layer 1) → **handler body** (which emits `501`). The `501`
is emitted by the handler body, which runs **only after `check_permission` passes** — and `check_permission`
gates the *operation* dimension against the caller's cap. So an **unauthorized** caller is stopped at `403`
and never reaches the `501` branch; `501` is reachable only by a caller already authorized for that operation
(learning "an op I'm allowed to call isn't implemented here" is inside my own authority envelope, not a
leak). The full pre-authorization structural-leak surface therefore reduces to the one `404` handler-existence
leak (plus a minor `chain_depth_exceeded` config-value hint). Operation-existence does not leak.

### RT-9 — Revocation posture is weak-by-default (the eventual-consistency *itself* is conceded as physics) (LOW–MED)
**Concession first:** that cross-peer revocation is *eventually* consistent is physics, not a design flaw —
you cannot move a revocation to an offline/un-synced peer faster than information travels, and no protocol
escapes that. So the *window's existence* is not the finding; drop that framing. What remains is the
**default posture** around a window that must exist. Core owns the revocation *mechanism* (marker at
`system/capability/revocations/{hash}`, `is_revoked` in `verify_request`, §5.5/§6.2). What core does **not**
own — and no extension owns as a subsystem — is
**cross-peer propagation**: it rides generic pull-based subscription sync. The consequence is stated bluntly
in the specs themselves: "**A peer that has observed a controller-cert but not yet its revocation will
validate caps the controller can no longer authorize ... The convergence window is an adversarial surface**"
(EXT-IDENTITY §6.4); "a real exposure that the architecture bounds rather than eliminates" (§9.6); core
§5.10 classes revocation as a *convergent* Layer-1 input ("determinism holds only given the same set of
*observed* revocation entries"). So a revoked capability **still verifies** at an un-synced peer. This is a
designed, documented eventual-consistency window — not a stealth hole — but the **default posture is weak**
in two specific, fixable ways: (1) the validation-time re-check that would shrink the window is only a
**MAY** (should be at least SHOULD, arguably MUST for cross-peer caps); (2) the propagation-latency bound is
left "per-backend" / unspecified, so a deployment cannot reason about its exposure window without
out-of-band knowledge. For a security-critical primitive, "revocation is eventually consistent, the
fail-safe is optional, and the latency is unspecified" is a posture worth challenging before 1.0.

### RT-10 — A core-dispatcher hook that lives only in an extension spec (LOW) — VERIFIED vs pinned V8, and split
Re-verified directly against `spec-data/v0.8.0` (the compute-track pass, §6e, closed the "needs
re-verification" flag): **confirmed, not retracted, and it is precisely a boundary-documentation gap.**
- `suspend`/`suspension` appears in core **exactly once** — a tree-path table row (line 3242) *pointing to
  the continuation extension's namespace*; there is **no `suspend()` seam / register-suspension-handler in
  core text.** The execution-context advancement `chain_depth` counter is **absent from core** (core's
  `chain_depth` is the *capability-delegation* depth, §4.10(b) — a different concept). The seam lives only in
  `EXTENSION-CONTINUATION §3.9`.
- But it is **MAY-level and backward-compatible by construction** ("if no suspension handler is registered,
  the dispatch layer returns the error response … preserves backward compatibility with sync-only peers"),
  and it rides only core-already-present machinery (`system/bounds` ttl/budget §3.11 + the dispatcher's TTL
  decrement). It forces **no** core change.
- The precise finding: it is a **fourth dispatcher-internal seam that maps onto none of the three §6.13
  hooks** (register / outbound-dispatch / emit). **Split disposition:** the `chain_depth`-wiring half is
  *already being actioned* by the in-flight `PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION` (promotes it to a core
  §3.11 field — see §6e/RT-15); the `suspend()`-seam-naming half remains an open LOW boundary-doc item (name
  the optional seam in core §6.13 as an explicit MAY, or state core dispatch has no suspension concept and
  continuations layer it entirely above).

## 6c. The type system — design vindicated, but two concrete IN-CORE defects (RT-11/RT-12)

A hard red-team pass on the type system (core §2 + `ENTITY-NATIVE-TYPE-SYSTEM.md` + EXTENSION-TYPE). The
**design holds emphatically** — and this is important, because it means the review is not just finding
extension/epistemic issues; it also confirms the type-system *design* is right:
- **"Opt-in enrichment" is TRUE, and now precisely characterized (F-TS-3).** Core wire/dispatch/authz depend
  only on the entity **`type` string tag** (`resolve_handler` checks `entity.type == "system/handler"`;
  `find_signature` on `== "system/signature"`) and on **structural field access** (`matches_scope` reads
  `include/exclude`) — never on the type **registry/resolution/validation**, which are all Level-1+ and
  genuinely opt-in. The F40 typed-scope distinction "accesses these fields structurally and works uniformly"
  with zero type-awareness at verification. A Level-0 peer is fully functional. *(Suggested one-liner for
  §2.11: state that Level 0 still dispatches on the `type` string; what it opts out of is `system/type/*`.)*
- **Extensions build real richness with zero core changes (F-TS-7).** EXTENSION-TYPE adds constraints via an
  open-type `constraints` field, dispatches them through core §6.6, and adds compare/converge/adopt/reconcile
  as handler ops — no core change. The governing test passes emphatically.
- **Refuted:** content-addressing type-confusion (hash covers `{type,data}`, type-blind canonicalization,
  §2.10 forbids dropping unknown fields); generics genuinely inert for non-validating peers (`type_args` live
  on definitions, never instances); bootstrap circularity cleanly cut; the four-address-primitive basis is
  orthogonal and non-redundant.

The pass also re-derived two genuine defects inside the frozen core — but **these are NOT novel red-team
discoveries: they are the already-filed F37 (+ its secondary count note).** F37 was surfaced by the *Pure
Data peer build* (A-PD-012, S3.7–3.8), written up in
`protocol-generator/shared/findings/F37-peer-id-naming-appendix-b.md`, and folded into the
F32–F41 aggregate digest — it is already queued for arch, not something the review found first. This is
itself the point the implementation-history review (below) is about: **the implementation dimension already
caught the one concrete in-core defect** before this spec-read re-found it. (The only fresh, minor angle: the
retrospective's §8.7.5 praise of the "four-address-primitive basis" doesn't cross-reference F37 — a tiny
completeness gap in *that doc*, not evidence the finding was missed project-wide.)

### RT-11 / F-TS-1 = F37 (MED–HIGH, in core, ALREADY FILED) — the identity primitive has two contradictory canonical names
Independently re-derived here by direct read; **already known as F37 (A-PD-012), handoff written, pending
arch pull.** Verified directly:
- `ENTITY-CORE-PROTOCOL.md` uses **`system/peer-id`** — 9 occurrences, including the §2.8 definition
  (*"`system/peer-id` is `primitive/string`"*) and every `type_ref` (connect/hello, authenticate). Zero uses
  of the other form.
- `ENTITY-NATIVE-TYPE-SYSTEM.md` bootstraps **`system/identity/peer-id`** (§4.4 table row 14, the §4.8
  definition, the normative Appendix A test vector, and the §526 "four address primitives" rationale) — but
  then uses bare `system/peer-id` at §1453 and §2399, contradicting *itself*.

Two consequences: (1) **Level-2 resolution break** — a validating peer resolving `type_ref: "system/peer-id"`
(as core mandates) does `lookup("system/type/system/peer-id")`, which the bootstrap never populated (it
registered `system/identity/peer-id`) → unresolvable, in exactly the "the name IS the interop contract" seam.
(2) **Namespace-ownership violation** — core §2 mandates extension types live at `system/{ext}/*`, so a *core
bootstrap* primitive named `system/identity/peer-id` squats EXTENSION-IDENTITY's namespace (which
`ENTITY-NATIVE-TYPE-SYSTEM.md` §10.1 itself says that extension owns). Blast radius is bounded (only Level-2
type-resolution, which is opt-in), so not a wire break — but it is a concrete, buildable spec-correctness
defect in the pinned core, and the two core normative documents flatly disagree. *(Interesting cross-check:
the Go oracle's type-system gate uses `OverrideField(TypeHello, "peer_id", {TypeRef:"system/peer-id"})` —
i.e. it sided with the **core** doc's name, which is why the cohort didn't trip over it; the type-system
doc's bootstrap name is the outlier.)* **Disposition: ALREADY FILED as F37 (handoff exists, in the F32–F41
digest) — the recommendation there is core's `system/peer-id` (majority + oracle-aligned). No new action;
this red-team pass corroborates F37 from a second (spec-read) direction.**

### RT-12 / F-TS-2 = the F37 secondary note (LOW, in core, ALREADY FILED) — bootstrap cardinality "14" vs ≥15
`ENTITY-NATIVE-TYPE-SYSTEM.md` says "**14** bootstrap types" in a normative MUST (§4.4; also §2.6/§11.2 —
verified at §134/§392/§412), but the enumerated set is larger (`entity` = #15; deletion-marker also core,
§530). **This is exactly the "Secondary, same table" note already in the F37 handoff** — not a new finding.
Corroborated; fix it in the same F37 reconciliation.

## 6d. The fourth attack dimension — implementation-history mine (RT-13/RT-14)

Full write-up: [`implementation-history-review.md`](implementation-history-review.md).
The first three passes attacked core by *reading the spec*; this one attacks from *what the 45 builds
revealed* — the class of signal (like A-PL-006's 401-vs-403) that is invisible on paper and only a real peer
surfaces. All 427 `A-*` ambiguity-log entries across 43 logs were re-mined in four paradigm clusters,
filtered (S) substrate-idiosyncratic vs (C) core-signal, each (C) capture-checked against F1–F46.

**Result: overwhelming core paradigm-neutrality, re-verified against the raw record** — the vast majority of
the 427 are (S); every (C) that landed an F-finding is a corroboration of a known item; the declarative/
logic/proof cluster is the only one that taught us about the protocol. Two genuinely-new uncaptured signals:

- **RT-13 — the concurrency-contract under-specification pattern.** §4.8 (atomic-refcount, A-C-009) and §1.6
  (frame-write atomicity, A-IO-002): unstated MUSTs that the runtime provides for free on GC/atomic-write
  substrates but that corrupt state/wire on manual-memory/yielding ones. The class of gap spec-reading
  structurally can't see (the reader is on an easy substrate in their head). Both absent from F1–F46. →
  one HANDOFF-TO-ARCH, two one-line normative notes; same "silently-violable MUST-prose" family the project
  already closes routinely.
- **RT-14 — hex-case is a de-facto Go-ism (A-CL-009).** The concrete receipt RT-3 wanted: lowercase tree-path
  hex is normative *nowhere* — it's just Go's `hex.EncodeToString` default, which propagated cohort-wide. →
  one normative sentence; folds into the RT-3 residual.

Smaller uncaptured items (batch to the arch digest): `format_code=128` construct-vs-receive asymmetry (3×
convergent prose gap), `unregister` type-ownership/refcount (2× convergent), the §1.1 scalar-`data`
accept-path vector, and the A-ADA-011 params-is-an-entity altitude note.

**Two honesty corrections this pass** (same discipline that caught F37): the cluster reports flagged the Lean
§5.10 findings (A-LEAN-1 time, A-LEAN-2 revocation) as "top uncaptured," but direct read of the pinned §5.10
shows both are **already landed as the v7.76 amendments** (time = a declared once-per-verdict Layer-1 input;
revocation = a convergent Layer-1 input) — the Lean proof vector *drove* those fixes. A keystone→arch win,
not a gap. Re-derive against the pinned snapshot before calling anything uncaptured.

The meta-result: **spec-reading and implementation-mining both bottom out at the same tiny residue** (two
unstated-MUST notes + a hex-case sentence). That convergence is itself strong evidence the core is close to
done.

## 6e. The fifth attack dimension — compute, the central paradigm (RT-15, VINDICATION)

The deepest test of whether the frozen core is actually complete: **can the system's central paradigm —
running the entity system *inside itself* via an entity-native minimal evaluator — be built purely on core
primitives, or does compute reveal core is under-provisioned for the one thing it exists to host?** Reviewed
against the in-flight compute track (EXTENSION-COMPUTE + proposals + the 07-16/07-18 handoffs + the axis-1
prototype), framed strictly as *core implications* (arch owns the compute design).

**Answer: CORE IS SUFFICIENT. Compute-as-a-handler rides the frozen core with zero core change forced by the
compute-as-central-paradigm design — and the seams were *designed into* core, not bolted on.** Receipts:
- **`expression_path` is a core field** (§3.7, on `system/handler/manifest` + `system/handler`): "dispatch
  evaluates the compute expression at this path instead of calling language-native code (EXTENSION-COMPUTE)."
- **Core §6.6 itself specifies the entity-native dispatch mechanism** ("Native vs entity-native execution"):
  dispatch "sets `ctx.capability = handler_grant` … `ctx.subgraph_root = expression_path`." The
  eval-with-pre-populated-scope seam the evaluator needs is *core-named*.
- **Dispatch uniformity is a core MUST** (§6.6 v7.74 B3): no branching on `is_compute()`/`is_native()`; the
  "substrate fork at resolution time" carve-out blesses branching on *which evaluator* runs the body, never
  on *which authorization model* applies.
- **§6.10 names compute as an emit consumer**; §6.13(c) pins the emit hook as a behavioral MUST. `compute/*`
  is a core top-level type namespace; §6.6 states the philosophy ("handlers dissolve into compute expressions
  at paths").
- Corroboration from the build side: the axis-1 interpreter prototype + the runtime-contract exploration
  both concluded **"No new primitive for correctness"** — the evaluator was built and works against
  core+extension without a core change.

**The one core touch near the track is `chain_depth` → core §3.11 `system/bounds` — and it is NETWORK-forced,
additive, and a defect-fix, not "compute under-provisions core."** The in-flight
`PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION` pins the forcing case to NETWORK's `maintain-peer`/reconnect graph
(compute is a co-beneficiary), completes the *existing* `cascade_depth` pattern ("the mechanism already
exists — read the source, don't invent"), needs no wire-core renumber, and resolves a self-contradiction
already latent in the landed spec (per-step TTL refill vs the claimed global chain bound). This is the split
`chain_depth` half of RT-10.

**Bounds/resilience: no §4.10 amendment forced.** A Turing-complete-ish evaluator-as-handler self-bounds
(§10.1 budget-decrement-per-step MUST; §5.4 depth cap 1024; `max_compute_operations`/`max_compute_depth`).
Core's contribution is deliberately handler-agnostic and already sufficient as the backstop: §4.10 governs
*structural* admission (envelope size, cap-chain depth — orthogonal to compute steps), §4.9 requires the peer
to stay responsive regardless of any handler, and §6.11(c)'s per-request deadline (503) is the ultimate stop
on a runaway evaluator. Correct layering: core self-bounds admission+resilience; compute self-bounds
evaluation (deterministic-across-peers, hence properly an extension semantic). Parallelization / sharding /
whole-state-tick and the standing-continuation model all stay in extension+host+app-convention ("zero
core-go dependency"; the standing continuation is a wire change with "no new opcode/cap/error code").

**Honest caveat (carry this precisely):** this is a **spec-level** result — the seams exist and are
sufficient in the frozen text — corroborated by arch's axis-1 prototype's own "no new primitive" conclusion.
It is **not** an independent from-scratch build of the evaluator on a keystone-generated peer (no keystone
peer ships the compute extension; extensions are out of keystone scope). So it is *cohort-consistent with
arch's prototype, not independent convergence* — stated to the §7-honesty standard. Even with that caveat, it
is the strongest single core-vindication datum in the review: the frozen core hosts the paradigm it was built
for without needing to reopen.

## 7. The epistemic findings — is the *verdict* earned?

### RT-E1 — The minimality claim is circular (HIGH, epistemic)
The retrospective's decisive move (§8.7): *"the spec partitions itself into §9.1 MUST vs §9.3 MAY, and that
partition **is** the forced-vs-chosen partition ... §9 **is** the frame."* This is the fallacy dressed as
the triumph. **The designers decided what goes in MUST.** "The mandatory core is minimal because §9.1 labels
it MUST" is deference to the artifact's self-description, not an independent finding of irreducibility. §8.1
correctly warns "convergence proves determinism, not minimality" — and then §8.7 commits a sibling error:
it accepts the designers' MUST list *as* the definition of "forced." The hard question — for each MUST item,
show it cannot be removed or demoted to an extension without breaking a genuine requirement — is precisely
what gets outsourced to the label. Concretely: is the **full** capability machinery (4-dim typed scope *and*
constraints *and* allowances *and* delegation caveats *and* K-of-N) actually *forced*, or is it a rich chosen
design stamped MUST? The retrospective never independently derives irreducibility for these; it reads §9.1.
**The headline verdict "minimal by the spec's own construction" is therefore close to vacuous** — of course
the mandatory core is what the spec mandates.

*(This does not prove the core is non-minimal. It proves we have not shown it minimal — we asserted it via
the labels. The honest verdict is "plausibly minimal; proven implementable and deterministic; minimality
outsourced to the designers' partition.")*

### RT-E2 — "Timeless minimality as blanket absolution" — LARGELY RETRACTED (epistemic)
**This attack was itself an overreaction, and I withdraw most of it.** On reflection (and review pushback),
the timeless frame is not an escape hatch — it is the **correct and load-bearing design rationale**, and it
argues *for* aggressive core minimality, not against it: because the core is what you live with forever, and
because behavioral growth happens in the **extensions** that ride on top, the core must be as small and
reduced as possible. Crypto/hash agility is the *right* expression of this, not fat: the mutable components
(the specific hash, the specific signature algorithm) are precisely the parts that will need to change when a
primitive breaks or quantum arrives, so the core is built to *not care which one* — it understands the
algorithms' **properties**, not their identities. That is minimal generality doing exactly its job. The
retrospective's use of the frame for the agility case is sound.

The only residue worth keeping is a **presentation** note, not a substantive one: §8.2a *introduced* the
frame at the same moment it used it to dispatch the two open candidates, which reads as motivated even though
the frame is correct. The fix is ordering/framing (state the timeless rationale as a first-class premise up
front, then evaluate candidates under it), not a change to any conclusion. **Net: RT-E2 downgraded from a
finding to a wording suggestion; the substance is conceded to the design.** (And it sharpens RT-E1, which
stands: *because* core minimality matters this intensely — you live with every included byte forever — the
"is each MUST item actually irreducible?" question deserves an independent answer, not deference to the
label.)

### RT-E3 — "Triangulated-minimal" oversells one witness as three (MED, epistemic)
Prolog + Datalog + SQL all expressing the authority interior natively (§8.6) proves it is **relational.** It
does not prove it is **minimal** — a bloated relational schema also expresses cleanly in all three, because
all three *are the same paradigm* (declarative relational/logic) in different dialects. That is one witness
in three dialects, not three independent witnesses. "Expresses in all three → at intrinsic shape → carries
no fat" is the §8.1 error resurfacing as *expressibility ≠ minimality.* Sharper still: F40 (typed scope) is
quietly the **opposite** of what the retro concludes — the relational encoding "forcing the split" between
id-scope and path-scope may be evidence the design **overloaded one `matches_scope` across two things that
should not share a mechanism.** A non-minimality signal is being read as a minimality confirmation.

### RT-E4 — §8 contradicts §7 (HIGH, epistemic — the fairest framing of the whole critique)
§7 (honesty posture) is genuinely rigorous and disclaims exactly the moves §8 then makes:
- §7: *"cohort-consistent ≠ independent convergence ... the only genuinely independent bases are go/rust/py."*
  §8.6.3: PR-8 as "six independent-ish readings ... the strongest possible signal." (The "-ish" hedge does
  not survive into the conclusion.)
- §7: *"conformance-green ≠ correct ... rejection-only is vacuous."* §8.8: the verdict rests on cohort-wide
  passing anyway (and RT-4 shows a rejection-only gap is still OPEN on the authz accept-path).
- §8.1: *"convergence proves determinism, not minimality."* §8.6/§8.8: convergence-flavored arguments
  (triangulation, cohort agreement) are then used *for* minimality.

The retrospective's own honesty section is the sharpest available critique of its own conclusions. The fix is
not to weaken §7 — it is to **bring §8's conclusions down to what §7 licenses.**

### RT-E5 — The review that removed nothing (MED, epistemic)
Every reduction candidate raised was dismissed: float → dismissed; crypto agility → "structurally
inapplicable"; dual-signature → "checked and cleared"; tree boundary → "principled." The single actionable
residue (F44) is a *test-coverage* gap, not a design change. A minimality review that starts with "let's find
reductions" and ends having removed **nothing from the design itself**, dissolving each candidate via a
frame constructed for the purpose, is exhibiting precisely the acquittal bias a self-review is prone to. The
uniformity of the acquittals is itself the finding. (This is *why* an adversarial companion doc and an
independent oracle both matter.)

---

## 8. Attacks that did NOT survive verification — retracted, with receipts

Honesty requires listing the swings that missed. Each of these was in my opening salvo and is **withdrawn**:

- **"Performance / DoS surface is barely examined."** ❌ Refuted by **§4.10** (v7.75): max inbound
  payload/envelope size is a **MUST** (`413 payload_too_large`, default 16 MiB, framed as *allocation-
  safety*); max capability-chain depth is a **MUST** (`400 chain_depth_exceeded`, default 64, explicitly
  citing "O(depth) signature verifications ... attacker-controlled chain unboundedly"); keeps-serving under
  load is **§4.9**; store-safety is **§4.8**. All are in the §9.1 floor under **both** profiles and gated by
  the `resource_bounds` + `concurrency` categories. The spec even notes these MUSTs *"ratify observed
  convergence"* (6/6 peers already enforced payload cap; 4/6 the depth cap) — another keystone→arch fold.
  The DoS surface is addressed.
- **"Unbounded recursive chain-walk is a DoS."** ❌ Same refutation — §4.10(b) and §2456 (`max_depth = 64`,
  cycle detection §3868) bound it.
- **"Base58 peer-ids are a serious wart (multiple incompatible alphabets)."** ❌ Overstated. Base58 is
  **presentation/routing** only (§1.5); entity-internal identity is `content_hash` (§1.3), canonical form is
  **mandated** (§1.5 v7.65 contract, one canonical `hash_type` per `key_type`), and the alphabet is pinned.
  A minor "why Base58 over base32/multibase" taste question remains, but it is not a correctness or interop
  hazard. Dropped.
- **RT-3 strong form: "the oracle is Go, so convergence is monoculture."** ❌ Largely rebutted by the
  oracle-source audit — the wire oracle is spec-corpus-driven and cross-impl-diffed with no privileged impl,
  the privileged-Go-encoder pattern was explicitly retracted (with a past instance removed), and ambiguous
  points are left open rather than pinned to Go. Full receipts in §4; only a narrow, bounded residual
  survives. This is the most important retraction, and a point in the project's favor.
- **"Clock skew breaks the §5.10 Layer-1 determinism claim."** ❌ Pre-empted by the spec. §5.10 / §5.5
  (v7.76) make the evaluation timestamp `t` a **declared per-verdict input**, sampled once and applied to
  every link; the determinism MUST is explicitly *conditioned* on "the same Layer-1 state **and the same
  `t`**," and the spec openly states two peers at materially different `t` near a TTL boundary "legitimately
  reach different verdicts — this is not a Layer-1 leak, because `t` is an enumerated input rather than
  concealed state." The attack fails because the design anticipated it. *(Residual precision note, folded
  into RT-E4: "deterministic cross-peer verdict" is real but conditioned on shared `t`, not absolute at a
  shared real instant — worth reading with that condition attached.)*
- **"A peer can hijack `system/` dispatch / cross-peer handler injection / prefix-shadowing
  nondeterminism."** ❌ Refuted. §192: "there is no mechanism to install a handler in another peer's
  namespace" (no cross-peer injection). §6.6 longest-prefix resolution is deterministic and can only capture
  a *subtree* (a longer prefix), never hijack a parent handler; taking over an existing handler path
  requires an authz'd tree write to that path. The dispatch model is more robust than the attack assumed.
- **"Replay across connections."** ❌ Refuted by the nonce-echo MUST (§4.6, line 1803) — a captured
  `authenticate` is bound to a per-connection nonce and rejected on another connection. *(The residual is
  RT-6: the nonce **quality** that makes this hold is only SHOULD.)*
- **"Multisig root-only forces bad design / blocks threshold authority."** ❌ Refuted — and it *vindicates*
  core by the governing test. The block is real (§3.6: `grantee` is a single hash, `granter` is polymorphic,
  so §5.5's `hash_equals(parent.grantee, child.granter)` can never link a mid-chain multi-granter). But
  **arbitrary-depth threshold authority is buildable on unchanged core** via the *parallel* K-of-N mechanism:
  EXTENSION-QUORUM verifies K-of-N over any entity hash (orthogonal to the cap chain — "Quorum validation
  MUST NOT call `verify_capability_chain`"), and EXTENSION-IDENTITY models a quorum-rooted identity that
  holds an ordinary single-sig cap, so the cap chain sees a single resolved identity hash while the
  threshold gates who controls it. That is the composition the ecosystem already ships. Joint accounts,
  escrow, dual control, threshold recovery — all layerable without a core change. The one genuinely-deferred
  primitive ("K parties each atomically co-sign *this specific mid-chain delegation act*") needs polymorphic
  `grantee`, which §5.5 explicitly scopes as a **future additive amendment, not a blocker** — it never
  renumbers the locked wire core. So root-only is a clean minimal boundary (like tree get/put), not a forced
  limitation.
- **"Operation-existence leaks via 501."** ❌ Refuted by dispatch ordering — see RT-8 (the `501` is
  post-`check_permission`, so an unauthorized caller never reaches it).

The residual honest point from this section is narrow and worth keeping: the conformance suite verifies
**correctness-under-bounds, not throughput** (§3975: "checks clean coded rejection + keeps-serving, NOT
absolute throughput or a particular limit value"). So the project has **no performance/throughput data at
all** — which is *fine*, because the retrospective makes no throughput claim; it would only become a problem
if someone later reads "45 substrates passed" as "45 substrates perform." Record it as a scope boundary, not
a defect.

---

## 9. What the project got right (so the reconciliation is grounded)

An adversarial doc that implied "you did nothing" would itself be a misreport — and the user explicitly
rejected that framing. On the record, verified:

- **The portability result is real and large.** A wire contract that lands unchanged on 45 substrates —
  compiled, interpreted, array, stack, prototype, dataflow, visual, bare-metal — is a genuine achievement;
  most protocols never get this test. (What it proves is *determinism + implementability*, per §8.1 — which
  is exactly what it should be read as.)
- **The operational-hardening story is strong**, and it came *from* this method: §4.8/§4.9/§4.10 store-
  safety, resilience, and resource-bounds are keystone findings folded into the spec, ratifying observed
  cross-impl convergence. This is the keystone→arch loop working, and it directly refuted my DoS attack.
- **The §7 honesty posture is exemplary** — cohort-consistent ≠ independent, every number oracle-pinned,
  vacuous-green named as a first-class hazard, ceilings held to the same bar as greens. The RT-E critiques
  are "live up to §7," not "§7 is wrong."
- **The conformance method is more robust than my attack assumed** (this is what killed the strong RT-3, §4):
  the wire oracle is spec-corpus-driven and cross-impl-diffed with **no privileged implementation**; the
  privileged-Go-encoder pattern was *explicitly retracted* and a real past instance found and removed;
  security categories carry deliberate accept-path vectors that cite our own vacuous-green lesson by name;
  and a genuinely-ambiguous point is left *open* rather than pinned to Go. A red-team expects to find the
  monoculture trap wide open; instead the project had already engineered against it, with citations. That is
  a strong, verified positive.
- **The authority-as-query insight (F40/F41) is a real contribution**, independent of the triangulation
  overclaim: it identifies where correctness could be made *structural* (fail-closed as "no derived allow
  tuple"; the four-dim conjunction as a single join) rather than conventional. That is a genuine design
  improvement the spec should absorb.
- **The core/extension line is principled — including the one I attacked.** The tree boundary at
  *composability* (CAS/delete as modes, everything composable → EXTENSION-TREE) is a textbook
  minimal-primitive criterion. And the identity line RT-1 first accused of being drawn wrong turned out
  **coherent**: identity = key by design, continuity relocated to a quorum in EXTENSION-IDENTITY on core
  primitives with *no missing core hook*. I withdrew that attack (§2). The surviving RT-1′ is about the PQ
  *migration mechanism*, not the boundary.
- **Several attacks died because the spec had already anticipated them** — a strong signal of design
  maturity, not just the absence of bugs: clock-skew determinism (`t` as a declared input, §5.10),
  cross-peer handler injection (structurally impossible, §192), replay-across-connections (nonce-echo MUST,
  §4.6), and DoS (§4.10). A red-team that keeps finding the trap already sprung is reviewing a careful
  design.
- **Where a real exposure exists, the spec names it honestly** — the revocation convergence window is
  documented in the spec's own words as "a real exposure that the architecture bounds rather than
  eliminates" (RT-9). The critique there is about default posture (re-check demoted to MAY), not concealment.
- **The type-system design and the multisig-root-only boundary both survived a hard, dedicated probe.** The
  type system is genuinely opt-in past Level 0 and extensions build constraints/compare/converge on it with
  zero core changes (RT-11's defects are *naming*, not design). Multisig-root-only is a clean minimal
  boundary: threshold authority of arbitrary depth is buildable on unchanged core via QUORUM+IDENTITY
  composition, exactly as the ecosystem already ships it. Both are strong "core is the right design" results
  produced *by* the adversarial pass.

---

## 10. Proposed dispositions and candidate work-streams

**Finding-status changes to propose (keystone routes; arch pulls):**
1. **File F-PQ against the identity/quorum EXTENSIONS (MED); do NOT re-open F43; core is vindicated.** Per
   RT-1′ (direct-read): PQ migration is incomplete — routine rotation needs the old key, compromise recovery
   has no required unbroken anchor, cross-algorithm rotation is silent, the enabling proposal has no file. By
   the governing test, core provides the primitives and does not block the fix, so this routes to
   identity/quorum, not core. Keep §4.5 downgrade-free as a standing positive.
2. **Escalate F44's framing** per RT-4 — narrow but real: constraint/allowance/caveat attenuation
   accept-path coverage is unconfirmed (broad accept-path coverage otherwise exists — audit-confirmed).
3. **Close RT-3's strong form; record the narrow residual** — Finding-1 (type-system Go-reflection gate,
   moderate/bounded) + the cohort-lineage agreement risk (already project-documented). Not a "Go defines and
   checks" finding.
4. **Re-file F45** per RT-5 — "per-request bounds ≠ cumulative bound," minor but a real class.
5. **F37 (= RT-11/RT-12) — ALREADY FILED; no new action.** The red-team independently re-derived the
   identity-primitive name split and the 14-vs-15 count from spec-reading; both are already the F37 handoff
   (surfaced by the Pd build, A-PD-012) and in the F32–F41 digest. This pass *corroborates* F37 from a second
   direction — worth noting to arch as "two independent derivations agree," nothing more.
7. **New low/med items:** RT-6 (elevate nonce freshness SHOULD→MUST), RT-9 (revocation re-check MAY→SHOULD
   for cross-peer caps; specify a propagation-latency expectation), RT-8 (optional 404-masking), RT-10
   (document the continuation suspension seam in core — re-verify vs pinned snapshot first).

**Work-streams (the "fix once" list for a timeless 1.0):**
- **W1 — Cross-algorithm PQ-migration (from RT-1′/F-PQ). IDENTITY/QUORUM extension work, high value.**
  Specify hybrid signing during a transition and a requirement that recovery quorums be provisioned on a
  stronger/independent algorithm *ahead* of a break; prove the mechanism survives the threat it exists for;
  write/land `PROPOSAL-MULTIKEY-MULTIHASH-ALIGNMENT` (or successor — it is named but has no file). Not a
  core-1.0 blocker (core provides the primitives), but foundational: the ecosystem shouldn't lean on identity
  before it survives a primitive break. Keep one core-side eye on the "one identity = one key_type" coupling
  check noted in §2.
- **W2 — Second independent oracle (from RT-2 + RT-3 residual).** A `validate-peer` built from rust or py,
  run differentially against the Go one. Targets the **cohort-lineage** agreement risk (the real residual),
  not the rebutted "Go defines and checks" charge. Would have caught the Finding-1 type-system Go-reflection
  dependency directly.
- **W3 — Accept-path authorization vectors (from RT-4/RT-2).** Author from the spec, cover the ALLOW
  direction on constraints/allowances/caveats, re-run the cohort.
- **W4 — Correctness-as-structure absorption (from F40/F41).** Fold the authority-as-derivation appendix so
  the two silently-violable MUSTs become invariants.
- **W5 — Right-size the verdict language** in the eventual synthesis (not the retro itself): from "minimal by
  the spec's own construction" to "implementable + deterministic across the landscape; plausibly minimal,
  with minimality outsourced to the designers' MUST/MAY partition and not independently proven."
- **W6 — Mint-time resource absolutization (from RT-2).** Pressure-test the design that makes the
  granter-frame bug class structurally impossible; land it before 1.0 if it survives the counterexample hunt.
- **W7 — Revocation posture (from RT-9).** Decide whether cross-peer caps demand a validation-time re-check
  (MAY→SHOULD/MUST) and a stated propagation-latency expectation, so deployments can reason about the window.

---

## 11. Bottom line

Stripped of rhetoric, after verification the slate is honest and short:

- **The review found NO novel in-core defect.** It re-derived one known in-core bug — the `system/peer-id`
  vs `system/identity/peer-id` name split (+ the 14-vs-15 count) — but that is **F37**, already surfaced by
  the Pure Data build (A-PD-012) and already handed to arch. The red-team corroborates it from a second
  (spec-read) direction; it is not a discovery. Tellingly, the *implementation dimension already caught the
  one concrete in-core defect* — which is the whole argument for the implementation-history review as the
  next attack surface.
- **RT-1′ (→ F-PQ) is real but it VINDICATES core.** The system's PQ-migration story is incomplete — routine
  rotation needs the old key, compromise recovery has no *required* unbroken anchor, cross-algorithm rotation
  is unspecified, the enabling proposal has no file. But by the governing test it is an **identity/quorum
  extension** gap: core provides the agility primitives and does not block an extension fix (W1 routes to
  identity, not core). *(My first draft over-claimed "authenticated by the outgoing algorithm" universally;
  direct read corrected it — recovery is quorum-signed. Verifying myself caught my own overreach.)* This is
  the single most important thing for the ecosystem to finish before leaning on it, but it is not a
  core-1.0 blocker.
- **RT-2 turned into a concrete proposal:** the §PR-8 bug is a real foot-gun *and* there is a better design
  (W6, mint-time absolutization) that makes the bug class structurally impossible — the spec is already
  halfway there. Pressure-test it; land it if it survives. Plus: "six independent" overcounts.
- **RT-4 shrank to one coverage corner** (attenuation accept-path vectors, W3); **RT-3 was rebutted by its
  own audit** (the method had already engineered against the monoculture trap — a *win* the red-team
  surfaced), with RT-14 as its one concrete receipt; **RT-6/7/8/9/10** are a spread of low-to-med real items
  (nonce-freshness-as-SHOULD, hash-agility asymmetry, dispatch info-leak, revocation eventual-consistency
  posture, a continuation seam documented only in an extension).
- **The fourth attack dimension (implementation-history mine of all 427 A-* entries, §6d) re-confirmed core
  paradigm-neutrality from the raw record** and added exactly two small uncaptured items: **RT-13** (the
  §1.6/§4.8 concurrency-contract unstated-MUSTs, invisible on easy substrates) and **RT-14** (hex-case
  Go-ism). Both are one-line normative notes. It also *corrected two over-claims* — the Lean §5.10 findings
  are already landed as v7.76 (a proof-vector success). Spec-reading and implementation-mining bottoming out
  at the same tiny residue is itself strong evidence the core is close to done.
- **The fifth dimension (compute, §6e / RT-15) is the strongest single vindication:** the system's *central
  paradigm* — the entity-native minimal evaluator — rides the frozen core with **zero forced core change**;
  its seams were designed into core (`expression_path`, entity-native dispatch, emit) and the prototype
  needed "no new primitive." The one core touch near the track (`chain_depth`→§3.11) is network-forced +
  additive, already in-flight. And the **blind-spots sweep confirms the coverage well is dry** — no unprobed
  wire-touching axis; the only technically-untouched corners (big-endian, EBCDIC hosts) are
  covered-by-construction (spec pins byte order + UTF-8), robustness-catch only, zero spec-ambiguity potential.
  A frozen core that hosts the paradigm it was built for, across every substrate axis that exists, without
  reopening — that is the whole case, earned by attack.
- **The RT-E series is the durable takeaway:** the minimality *verdict* is the designers' MUST/MAY partition
  restated (RT-E1), triangulation proves relational-not-minimal (RT-E3), and §8's conclusions outrun the
  bounds §7 sets (RT-E4). (RT-E2 — "timeless as blanket absolution" — was itself retracted; the timeless
  frame is the correct, load-bearing rationale for aggressive core minimality.) The fix is
  to bring the verdict's language down to what the evidence licenses (W5) — the retrospective *proved*
  determinism + implementability across 45 substrates (a genuinely large result) and *asserted* minimality.

None of this says the design is bad — the opposite, in most places. The core *design* held up under a hard,
multi-angle assault: the conformance method, §4.10 DoS hardening, the type-system opt-in model, the
multisig-root-only boundary, dispatch determinism, and clock-skew handling all came out **stronger** than the
attack assumed, several because the spec had already sprung the trap. The honest residue is small and
precise: **zero novel in-core defects** (the one in-core bug re-derived is the already-filed F37, caught
first by the implementation), **one unfinished foundational extension mechanism (F-PQ — core supports the
fix)**, **one design simplification worth landing (W6, mint-time absolutization)**, a spread of low-med
posture/coverage items (RT-4/6/7/8/9/10), and the epistemic point that the retrospective's *verdict*
over-claims what its *evidence* earns (RT-E, → W5).

The governing test — "does core force bad design, or can extensions evolve their gaps without touching
core?" — came back **overwhelmingly on the good side**: every substantive attack that could have indicted
core (identity migration, threshold authority, type richness, DoS, dispatch) resolved to "core provides the
primitives; the gap, where one exists, is fixable above core." The only in-core bug is F37 (a naming
inconsistency, already queued), not a structural flaw. That is a genuinely strong result for a
frozen-core-1.0 claim — earned by attack, not assumed. Next: take these piece by piece; the reconciliation with the retrospective is the
interesting part.

---

*Companion to `research/PROJECT-RETROSPECTIVE.md` (unmodified). Spec citations to `spec-data/v0.8.0` (read-only).
No sibling-repo writes. This doc is the prosecution; the synthesis pass will judge.*
