# HANDOFF-TO-ARCH — F32: §4.2 / §4.4 body text vs §5.2a auth-class status

**Date:** 2026-07-12 · **Finding:** F32 (`research/stewardship/SPEC-FINDINGS-LOG.md`)
**Owner:** `arch` (spec-body reconciliation) · **Severity:** documentation-reconciliation debt
(cross-impl status divergence on a MUST-emit tuple) · **Blocks:** nothing
**Lineage:** extends **F20** (auth-class-401 disposition) · related **F31** (§6.5 auth-before-resolve)
**Spec surface:** ENTITY-CORE-PROTOCOL.md @ `spec-data/v0.8.0` (V8; core wire byte-unchanged V7→V8)

> Keystone cannot edit `spec-data/**` (immutable, boundary). This is a request for arch to
> reconcile the normative body text on its own schedule; no local patch was made. Derived
> from the **spec**, not the oracle's Go source.

## The contradiction

Three normative statements disagree on the status code a peer MUST emit for a **non-`connect`
EXECUTE whose `author` is absent** (equivalently: an envelope with no verified signer):

| Source (ENTITY-CORE-PROTOCOL.md) | Says author-absent → | Class |
|---|---|---|
| **§4.2 Pre-Authorization Rules**, bullet 3 (~L1593): *"EXECUTE targeting any other path without auth fields MUST be rejected (status **403**)."* | **403** | (blanket) |
| **§4.4** request-auth statement (~L1893): *"Every authenticated EXECUTE MUST include `author` and `capability`… Peers MUST reject requests missing **either** with status **403**."* | **403** | (blanket) |
| **§5.2a Verdict-to-status enumeration (normative, v7.73)**, row (~L2263): `Request-time (§5.2 step 2) \| Author absent \| **401** \| authentication_failed \| **auth**` | **401** | auth-class |

§5.2a's discriminator (~L2256) is explicit: a request-time failure is **auth-class (401)** when
*"the EXECUTE itself cannot be authenticated (no/bad author, no/bad/missing signature) — the
envelope has no verified signer"*, and **authz-class (403)** only when *"the EXECUTE **is**
authenticated but the verified signer's capability does not authorize the operation."*

So the two auth *fields* split across the auth/authz boundary:

- **`capability` absent → 403** (`capability_denied`, authz) — §5.2a row (~L2269) **agrees** with §4.4.
- **`author` absent → 401** (`authentication_failed`, auth) — §5.2a row (~L2263) **contradicts**
  §4.2 bullet 3's blanket 403 and §4.4's *"missing **either** → 403."*

The older §4.2/§4.4 phrasings predate the v7.73 auth/authz split and were not back-propagated to
it. §5.2a is the newer, load-bearing, conformance-vector-pinned enumeration
(`AUTHZ-*` / `security` categories); the §3.3 status table remains authoritative on the tuple,
and §5.2a routes each surface to its row.

## Why it matters

`result.data.code` + `status` are a **MUST-emit contract** (~L1815: *"clients key error handling
off `result.data.code` … an impl that … returns a different status is non-conformant"*). An
implementer reading only §4.2/§4.4 emits **403** for a no-`author` EXECUTE; one reading §5.2a
emits **401**. Two peers, each conformant to the section they read, **diverge on the wire** for
the same input — exactly the class §5.2a exists to prevent.

## Corroboration (this session — Julia + Nim, parallel builds)

Surfaced by the **Nim** peer at S3 (A-NIM-009) while walking §4.2 and §5.2a together; independently
corroborated by the **Julia** peer (same auth-before-resolve trichotomy). Both are **`validate-peer
--profile core` PASS, 682·0F @ `cc1970f`** (Nim 293P/293W/0F/96S; Julia 292P/294W/0F/96S). Both
peers **follow §5.2a → 401** and pass the oracle's `security` category (which pins the auth rows at
401), so **the 401 reading is the oracle-conformant one** — consistent with:

- **F31** — §6.5 authenticates *before* resolving a handler (unauthenticated unknown-handler → 401,
  not 404); each peer's smoke gate exercises this live.
- **F20** — request-time signature/author/signer-mismatch are **auth-class 401**, not 403; F20
  corrected the *oracle/memo* side. **F32 is the un-reconciled *spec-body* text F20's fix implies
  but never touched.**

(This is *cohort-consistent corroboration, not independent convergence*, ADR-0012: both peers share
the keystone generation lineage. The signal is that a fresh substrate re-reading §4.2 + §5.2a
surfaces the same body-text conflict, not that two independent code bases converged.)

## The ask

Reconcile the §4.2 bullet 3 + §4.4 body text with the §5.2a enumeration so the spec speaks with one
voice on the tuple. A no-/bad-`author` (or absent/invalid signature) EXECUTE on a non-`connect` path
is **auth-class → 401 `authentication_failed`**; **`capability` absent remains authz-class → 403
`capability_denied`**. Concretely, either:

1. Split the phrasings — §4.2 bullet 3: *"without a verifiable `author`/signature → **401**
   (auth-class, §5.2a); with a verified signer but no authorizing `capability` → **403**"*; §4.4:
   drop *"missing **either** → 403"* in favor of the per-field split; **or**
2. Add an explicit *"see §5.2a (authoritative on the (status, code) tuple)"* cross-reference to both
   §4.2 bullet 3 and §4.4, so the enumeration governs.

## Disposition

**Not a peer bug** (both peers follow §5.2a and pass the gate). **Not a spec-*logic* defect** (§5.2a
is correct and internally consistent). A **documentation-reconciliation debt** left by the v7.73
amendment. Does not block any phase. Keystone will keep following §5.2a (401) in all generated peers.
