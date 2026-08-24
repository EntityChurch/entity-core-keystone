# HANDOFF-TO-ARCH — Aggregate digest: the open spec surface (F32–F41)

**Date:** 2026-07-17 · **Owner:** `arch` · **Type:** consolidation (indexes 7 prior handoffs; supersedes
none of them — they remain the detail-of-record). **Severity, in aggregate: none blocks a peer.** Every
finding below is either already fixed keystone-side, or a case where the surfacing peer followed the
spec-faithful / oracle-conformant reading and passed the gate. This is a *request for arch to action on
its own schedule*, batched so like resolves with like.

## Why this exists

The open keystone→arch surface accumulated as **10 findings across 7 `HANDOFF-TO-ARCH-*` docs**, each
written in isolation as its probe surfaced it. Architecture pulls on its own cadence and otherwise has to
reconstruct the whole picture from 7 files. This digest is the single navigable front door: one table,
grouped by **resolution type** (so arch can batch), plus the **two recurring families** that are the most
reusable lessons about how the spec and its oracle co-evolve. The source handoffs are indexed at the end
and are **not** deleted (archive-don't-delete).

A separate final section carries the **minimality-analysis outputs (F42–F46)** from the retrospective
(`research/PROJECT-RETROSPECTIVE.md` §8), which now includes a **full section-by-section read of the pinned core
spec** (§8.7, all 4,184 lines). F42 (float/hash) and F43 (crypto agility) are **closed** — the full read
shows they were never in the mandatory core (§9.1 MUST is SHA-256 + Ed25519; all agility is §9.3 MAY), and
F43 is additionally downgrade-free by design (§4.5 identity-bound `key_type`). Three small residues remain
actionable: **F44** (narrowed to an accept-path coverage question), **F45** (a one-line §6.5 clarity note),
and **F46** (a forward-looking transcript-authentication constraint). They are kept distinct from the
F32–F41 conformance/spec findings because they are design/coverage-level, not gaps between an
implementation and the spec.

**Source of truth:** [`SPEC-FINDINGS-LOG.md`](../../../research/stewardship/SPEC-FINDINGS-LOG.md) — the status sweep at its top is
authoritative; statuses there override this digest if they have moved. Read that first.

> **Correction vs the setup handoff.** The synthesis-setup note
> (`docs/status/HANDOFF-2026-07-16-next-project-synthesis-and-arch-aggregation.md`) framed the open set as
> "9 findings (F33–F41)." Verifying against the findings-log sweep, the open set is **10 (F32–F41)**: F32
> (auth-class status reconciliation, surfaced by Nim/Julia, 2026-07-12) has its own handoff — the oldest
> of the seven — and was omitted from that table because it predates the F33+ cluster. It belongs here:
> it is the same *spec-prose-not-back-propagated-across-an-amendment* family as F36/F37, and directly in
> the F20/F31 lineage. Included below.

(Scope note: **F11** — the extensibility spike — is *not* an arch spec ask; it is a keystone-internal /
research gate-tracked item and stays out of this digest. The digest is spec-side findings only.)

---

## At-a-glance — the whole open surface

Grouped by resolution type. "Keystone state" = what the surfacing peer(s) already do; most followed the
correct reading, so these are findings, not blockers.

| F | Spec surface | One-line ask | Provenance | Keystone state |
|---|---|---|---|---|
| **F32** | §4.2/§4.4 body vs §5.2a enumeration | Reconcile body text: no-/bad-`author` on a non-`connect` path is **auth-class → 401**, capability-absent stays authz → 403; split the blanket "missing either → 403" | Nim (A-NIM-009), corroborated Julia | Both follow §5.2a→401, oracle-conformant, `682·0F` |
| **F36** | ECF `signature` category vs §7.3 | One-line note distinguishing "ECF-signature" (`sign(seed, ECF{type,data})`, corpus/codec) from "content_hash signature" (§7.3, protocol) — same word, two signed messages | asm-x86_64 (A-ASM-018) | Correct construction empirically pinned (golden = ECF-bytes) |
| **F37** | §4.8 vs §10.1/Appendix B (type-name) | Pick ONE canonical peer-id name; regenerate **Appendix B** from the primary `:=` defs (it is systemically stale); fix §4.4 "14"→15 count | Pure Data (A-PD-012) | Pd binds **both** names so every `type_ref` resolves; green |
| **F33** | §6.11 T2.1 completeness assertion | Distinguish silent-drop (§4.9(c)) from conformant graceful-slowdown/back-pressure; model a back-pressurable producer, or document the floor + required compiled execution mode | wasm-wat | Green via `--enable-jit` (interpreter crypto too slow) |
| **F34** | oracle security/authz coverage | Add `tampered_capability_signature` (flip a **granter/cap** sig over an unchanged cap hash) — symmetric to `tampered_signature` which covers only the *author* sig | wasm-wat | wasm-wat verifies both sigs per request |
| **F35** | oracle §7a reentry-echo | Have the reentry-echo (or a sibling probe) verify author-sig + cap-chain on the inbound reentrant EXECUTE, so §7a gates the **outbound seam's authorization** | wasm-wat | wasm-wat ships the full authorized envelope, not the vacuous minimal one |
| **F38** | §created_at precision | GUIDE note: `created_at` MUST be ms-precision (mints otherwise distinguishable) — second-truncation aliases content-addressed mints | Pure Data (A-PD-016) | **Fixed** (ms wall clock at every mint site) |
| **F39** | §5.5a open-seed resource form | One GUIDE sentence: a universal seed needs BOTH `["*", "/*/*"]` — bare `*` is granter-local, can't cover foreign namespaces | Pure Data (A-PD-017) | **Fixed** (seed + shared `seed-policy/README.md`) |
| **F40** | §3.6 scope matching | GUIDE clarification: matching is **typed** — id dims literal, path dims canonicalized (§1.4); not one uniform `matches_scope` | SQL (A-SQL-008) | **Fixed** — the split *is* the fix (was a real ALLOW bug) |
| **F41** | §5/§6.6 decision surface | Informative **authority-as-derivation appendix** to GUIDE-CONFORMANCE — specify the verdict as a monotone derivation so fail-closed + the §5.5a within-grant conjunction are structural invariants | Datalog (A-DL-013) | No wire/verdict change; every peer already computes it |

---

## Grouped by resolution type (batch like with like)

### A. Spec-prose reconciliation — documentation drift from real amendments (F32, F36, F37)
No logic is wrong; body text and consolidated references lagged behind amendments that changed the
authoritative source. Cheapest class to resolve (wording + a regen), and the one with the clearest
"two implementers reading different sections diverge" interop hazard.
- **F32** — the §5.2a auth-class amendment (v7.73) split the two auth fields across the auth/authz
  boundary (author-absent → 401, capability-absent → 403), but §4.2 bullet 3 and §4.4 still say the
  blanket "without auth fields → 403" / "missing either → 403." Reconcile the body to §5.2a (or
  cross-reference §5.2a as authoritative-on-the-tuple). *In the F20/F31 lineage — F20 fixed the oracle/memo
  side, F32 names the spec-body text F20's fix implied but didn't touch.*
- **F36** — the corpus `signature` category signs canonical ECF bytes; §7.3 signs the content_hash. Same
  word, two signed messages. One clarifying note prevents an implementer wiring §7.3 content_hash-signing
  and failing the corpus `signature` vectors with no pointer.
- **F37** — the peer-identity primitive is `system/identity/peer-id` in §4.8 bootstrap but `system/peer-id`
  in §10.1 + Appendix B (and the oracle carries only the latter). Broader: **Appendix B is systemically
  stale vs the primary `:=` definitions** (`primitive/any` vs `core/entity`, etc.). Pick one name +
  regenerate Appendix B from the primary defs; fix the §4.4 "14"→15 bootstrap-type count.

### B. Oracle coverage / probe design — the "vacuous-green" family (F33, F34, F35)
The oracle can pass a peer that doesn't implement/authorize the thing. These need a *vector or probe*, not
a spec edit (F33 additionally has a spec-clarity component). See Family 1 below.
- **F34** — add `tampered_capability_signature`. Note (for arch's benefit): a *sound* memoize-by-(cap-hash,
  signature) is a legitimate §4.10(b) headroom lever; the gap is only that memoize-by-cap-hash-**alone**
  passes today.
- **F35** — the §7a reentry-echo (`handleReentryEcho`) services the inbound reentrant EXECUTE with **no
  §5.2 verification** — so §7a t1_1/t1_2 pass even if the peer originates an unsigned/unauthorized
  outbound EXECUTE. Verify author-sig + cap-chain on the reentrant EXECUTE.
- **F33** — the §6.11 T2.1 "zero drops" completeness assertion imports a *de-facto absolute throughput
  floor* (fixed load × fixed client deadline × shared run timeout), conflating a §4.9(c) silent drop with a
  conformant graceful slowdown. Either distinguish late-vs-lost, model a back-pressurable producer, or
  document the floor + the required compiled execution mode (the wasm execution-mode analysis in the
  wasm-dialer handoff is the FYI context).

### C. GUIDE notes — small clarifications, mostly already fixed keystone-side (F38, F39, F40)
Correctness properties no vector gates; each is a sentence or short note in GUIDE-CONFORMANCE. All three
are already fixed on the keystone side — the ask is to make the property *specified*, not merely
conventional. See Family 2 below.

### D. Informative appendix — the one design-level suggestion (F41)
The highest-leverage item, and additive (an appendix, not a break). The §5/§6.6 decision surface is a
monotone deductive system; specifying the verdict *as a derivation* makes fail-closed and the §5.5a
within-grant conjunction structural invariants an implementation cannot violate silently, rather than
MUST-prose it can drift from. No peer's computed answer changes. Retrospective analysis:
[`protocol-generator/shared/evaluations/authority-as-query.md`](../evaluations/authority-as-query.md); project-level framing in
[`research/PROJECT-RETROSPECTIVE.md`](../../../research/PROJECT-RETROSPECTIVE.md) §4.7–§8.

---

## The two families (the reusable lessons)

These two framings recur across the findings and are the most transferable output for how the spec + the
oracle should co-evolve. They are also documented at project level in `PROJECT-RETROSPECTIVE.md` §4.8.

### Family 1 — *conformance-green can be vacuous* (F34, F35; F33 adjacent)
A rejection-only oracle category, or a probe that skips verification, lets a fail-closed peer pass
**without implementing the primitive.** `multisig` was once 100%-malformed→403 — a peer that never
verified a threshold signature passed it. F34 (cap-sig never tampered over an unchanged hash) and F35 (the
reentry-echo never verifies the reentrant EXECUTE) are the same shape on the security surface: the oracle
green-lights a peer that doesn't do the thing. **Ask:** wherever a security/authz category is
rejection-only, add an accept-path (or tamper-path) vector in the direction the oracle can't currently
cover. The keystone-side discipline this installed — always add an accept-path test the oracle can't
reach — is what surfaced the Datalog EDB-dedup K-of-N bug (A-DL-012) that the rejection-only category
would never have caught.

### Family 2 — *silently-violable MUST-prose* (F38, F39, F40, F41)
A correctness property the prose states as a MUST but no vector gates, so two faithful implementations can
diverge: mint-timestamp precision (F38 — second-truncation makes same-scope same-second mints
hash-identical on a content-addressed protocol → the marathon 403-cascades; *only the full profile
exposes it, isolated category runs stay green*), the open-seed dual resource form (F39), typed scope
matching (F40 — surfaced as a real ALLOW bug), and the whole authority derivation (F41). **Ask:** where
practical, promote the property from prose to either a vector (F38 is a natural marathon/re-mint vector) or
a structural specification (F41's derivation appendix). The polyglot method is unusually good at finding
these because a substrate whose idioms don't share the prose's hidden assumptions forces the assumption
into the open.

---

## Minimality-analysis outputs (F42 / F43 / F44 / F45)

From the retrospective's **minimality analysis** (`research/PROJECT-RETROSPECTIVE.md` §8), which corrected an
earlier over-claim (45-peer byte-identical convergence proves the spec is *deterministic, unambiguous, and
implementable* — **not** *minimal*), went up a layer from encoding/crypto to the **protocol logic** (using
the three logic-paradigm implementations Prolog/Datalog/SQL as the instrument), and finally **read the
pinned core spec end to end, every section and algorithm** (§8.7).

**The decisive result of the full-spec read: the spec's own MUST (§9.1) vs MAY (§9.3) split *is* the
forced-vs-chosen minimality partition** — §9.0 states it outright ("core = the live hooks; everything
above = optional and replaceable"). This **closes both encoding/crypto candidates** — they were never in
the mandatory core:

- **F42 — CLOSED.** SHA-256 is the sole §9.1-MUST hash; "additional hash formats" is §9.3 MAY. The
  shortest-float ladder + the multi-format / two-address-space machinery are all opt-in; the mandatory
  core touches none of it. (Empirically, no float defect reached the wire across 45 substrates; the
  keystone+corpus prevents the uncoordinated-ecosystem failure mode DAG-CBOR's f64-always answered.)
- **F43 — CLOSED.** §9.1 MUST is **Ed25519 only**; "additional key types beyond Ed25519" is §9.3 MAY. The
  default core peer is one-curve + FFI-free *by the MUST/MAY split itself*; Ed448 friction lands only on
  peers opting into a MAY. The §1.5 `key_type` table reserves the NIST PQ suites (ML-DSA/SLH-DSA/FALCON) —
  the agility genuinely IS the frozen-core PQ-migration mechanism. **And it is downgrade-free by design:**
  §4.5 classifies `key_type` as an *identity-bound accept-set*, not a negotiated single value — each peer
  signs with the fixed key its identity holds, so there is no "connection key_type" a MITM could downgrade.
  The crypto-agility downgrade attack is structurally impossible. WireGuard (a *mutable* protocol) is the
  wrong comparator on all counts. No reduction to make.

**Three small residues remain — the only items from the minimality work worth arch action:**

| F | Surface | The item | Ask |
|---|---|---|---|
| **F44** (narrowed) | capability accept-path coverage | The caveat *mechanism* is **not** absent — it is §9.1 MUST (constraint key-retention + byte-equality; allowance key-containment; delegation-caveat depth/ttl — §5.6/§5.7). "Non-root thresholds" is **not** a gap — multisig is deliberately root-only (§5.5 M3). So the only open question: are the constraint/allowance/caveat **accept paths** oracle-tested, or only their reject paths? (A MUST mechanism with rejection-only coverage is the vacuous-green shape.) | Add an accept-path attenuation vector (constraint added / allowance dropped / caveat depth+ttl honored) — the §6.13 behavioral-presence pattern. |
| **F45** (low) | §6.5 clarity note | `ingest_envelope_signatures` binds *every* included `system/signature` at its invariant path; the request's own author sig (`target == request root`, unique per request) is consumed inline by `verify_request` and never looked up post-dispatch, so binding it grows a memory-primary store per request. Two peers hit it (Io A-IO-022, Rexx A-RX-014), previously adjudicated impl-side; the literal algorithm does prescribe the growth. | Optional one-line §6.5 note: "signatures whose target is the request root are consumed inline and need not be persisted." Not a correctness defect. |
| **F46** (forward-looking, low) | §4 handshake transcript integrity | The `hello` negotiation is not transcript-authenticated — the §4.6 `authenticate` signature covers `{peer_id, public_key, key_type, nonce}` but not the negotiated single-active-values (§4.5). Benign today (`key_type` identity-bound → F43; `hash_formats` downgrades only to the secure SHA-256 floor; compression/encryption are unspecified §9.3-MAY placeholders). **Not a current defect.** | When a security-bearing negotiated parameter is specified — notably a frame-encryption mechanism — bind the negotiated params into the `authenticate` signature (or require an already-confidential transport) to prevent MITM downgrade. |

**The full read also confirmed several of the keystone's own findings are *already folded into the core
spec*** (the keystone→arch loop, visible in the text — no action needed, recorded as validation):

- **§6.13** "Extensibility Hook Presence" IS the vacuous-green family made normative — it cites *"generated
  peers … shipped non-conformant"* (us) and pins behavioral presence as MUST + three new validate-peer
  checks. F44 is the *next instance* of a pattern the spec already responds to.
- **§5.8** already addresses the §PR-8 cross-peer hazard: a normative cross-peer chain-construction
  registry + a conformance-topology rule (cross-peer provenance is only witnessable by a non-issuing
  third-party verifier).
- **§5.10** already formalizes the monotone-core / non-monotone-guard split (Layer-1 deterministic verdict
  vs Layer-2 local policy; time + revocation as *declared* Layer-1 inputs) — much of what F41 asks for.
- **§1.4** independently names the peer-relative/absolute path relativity as "the single most-recurring
  cross-impl bug class" — the §PR-8 finding at the path layer, in the spec's own words.

The positive result behind all of it: implementing the authority interior in **three independent logic
paradigms** converged on **one relational structure** whose only irreducibilities are three *forced,
non-redundant* complications — a **typed verdict** (401-vs-403; Prolog's mono-valued failure needed a
second channel, A-PL-006), **non-monotone temporal/revocation guards** over a monotone core (F41), and
**typed scope matching** (F40) — plus confirmed **dispatch uniformity** and a **principled tree boundary**
(core = get/put with CAS/delete as modes; composable-from-primitives → EXTENSION-TREE). The durable
methodological lesson: **convergence proves determinism, not minimality** — but the MUST/MAY split, the
three-paradigm triangulation, and the full section read together are about as close to a minimality
argument as an empirical method reaches.

---

## Index of source handoffs (detail-of-record — not superseded, not deleted)

| Handoff | Findings | Surfaced by |
|---|---|---|
| `F32-auth-class-status.md` | F32 | Nim (A-NIM-009) + Julia |
| `asm-018-signature-construction.md` | F36 | asm-x86_64 (A-ASM-018) |
| `concurrency-latency-floor-and-cap-sig-coverage.md` | F33, F34 | wasm-wat |
| `wasm-dialer-parity-F35-and-execution-mode.md` | F35 (+ execution-mode FYI) | wasm-wat |
| `F37-peer-id-naming-appendix-b.md` | F37 | Pure Data (A-PD-012) |
| `F38-mint-timestamp-precision.md` | F38, F39 | Pure Data (A-PD-016/017) |
| `protocol-generator/shared/evaluations/authority-as-query.md` (the SQL/Datalog survey) | F40, F41 | SQL (A-SQL-008) + Datalog (A-DL-013) |

## Guardrails

- This digest is a **request**; keystone fixes stay keystone-side. Arch pulls on its own schedule. A
  direct cross-repo commit lands as an unprovenanced surprise (AGENTS.md boundary) — the digest exists so
  arch can action a batch cleanly, not so anyone edits the spec from here.
- Nothing here is blocking. If arch resolves none of it, every peer stays gate-green; these harden the
  *spec's* legibility and the *oracle's* coverage, not any peer's conformance.
- When acting on a finding that cites a spec section, **re-grep the spec head first** — the findings-log
  cells are append-only history, and the lesson `[[feedback_ratified_proposal_is_not_folded_spec]]`
  applies (ratification ≠ folded; a status cell ≠ current state).
