# entity-core-protocol-lean — PHASE S3 — TRACK A + TRACK B COMPLETE

> **STATUS: Track A GREEN + Track B PROVEN.** Track A:
> `validate-peer --profile core` = **576 total · 291 pass · 196 warn · 89 skip ·
> 0 FAIL · PASS** on the go `62044c5` oracle; full peer live over TCP.
> **Track B (the proofs) is done** — `lake build EntityCoreProofs` green, 9 new
> theorems, **zero `sorryAx`**. Headline: **T5a attenuation-monotone is PROVEN**
> (`matchesSeg` transitive, Classical-free; lifted to leaf-authority ⊆
> root-authority — delegation never broadens). Plus T4 verdict time-stability and
> T5b depth/termination. All four A-LEAN candidates resolve/confirm in the spec's
> favour — **no counterexample.** Ledger: `status/FORMALIZATION-REPORT.md`;
> findings: `status/SPEC-AMBIGUITY-LOG.md` (S3 Track-B section); a Track-B
> proof-vector handoff was routed to architecture.
> **Next = S5 packaging + the optional Track-B refinements (chain-level corollary,
> total `collectChain`).**

---


Done by hand (the proof-vector peer warrants direct
attention). Builds in `containers/lean-toolchain` (Lean 4.29.1), codec `.so` at
`/codec`. Oracle: the existing v7.75-matched `output/s4-oracles/{validate-peer,
entity-peer}` (go `62044c5`) — NOT go HEAD (`9e099b9` = Phase P, beyond the
`spec-data/v7.75` this peer targets). No re-vendor needed.

S3 is the big phase: the running peer → `validate-peer --profile core` (Track A,
the unchanged bar) **and** the T4/T5 verdict/attenuation proofs (Track B, where
the A-LEAN findings live). This is a multi-session build; this file tracks it.

## Done so far

### The pure verdict/capability core — the design crux (committed `5ac99f8`)
`src/EntityCore/Capability.lean` — the §5 verification core as a **pure total
Lean function**, so it is simultaneously the running verdict AND the Track-B
proof surface. The deliberate factorings (each realizing a 1b finding):

- **`verifyChain (rc : ResolvedChain) (localPeer) (now) : ChainVerdict`** — pure,
  total. Determinism is then a free corollary (**T4**).
- **TIME explicit**: a single `now : UInt64` parameter, sampled once by the shell
  — not `now()` re-sampled per link (cohort `capability.ml:361`). → **A-LEAN-1**.
- **REVOCATION excluded** from the pure core (the core-peer `supports_revocation
  = false` path); `is_revoked` reads the local tree, so it cannot live in a
  function "of the chain and Layer-1 inputs only" (§5.10). → **A-LEAN-2**. The
  running `verifyRequest` (shell, TBD) composes this core with the unproven
  revocation + Layer-2 post-gate.
- **CRYPTO verify is opaque FFI** → per-link signature validity is a *resolved*
  `Bool` (`ResolvedLink.sigValid`), the `Float.toBits`-style boundary. The §5.5a
  granter frame (a store lookup) is likewise resolved into
  `ResolvedLink.granterPeer`. The pure core reasons about structural linkage,
  attenuation, temporal validity, and depth — never the primitive.
- **§5.4 patterns as SEGMENT LISTS** (`matchesSeg : List String → List String →
  Bool`): structurally recursive → total (no string-termination pain) and
  tractable for the **T5a** subset-transitivity proof, faithful to the grammar
  (bare `*`, leading `/*/` = one segment, trailing `/*` = ≥1, else exact). This
  is the running matcher too — no prove-vs-run gap. The shell splits strings.
- Also: **§5.6** `scopeSubset`/`grantSubset`/`isAttenuated` (the **T5a** surface,
  per-side §5.5a granter frames on the resource dimension); **§5.7**
  `checkDelegationCaveats`; **§4.10(b)** `chainExceedsDepth` (**T5b**); the **§5.2**
  `checkPermission` dispatch-authz gate.

Supporting layers committed alongside:
- `src/EntityCore/Model.lean` — `Entity`/`Envelope` views over the codec `Value`
  + pure field accessors (`mapGet`/`textField`/`bytesField`/`uintField`), `hex`.
- `src/EntityCore/Identity.lean` — `peerIdOfPubkey` (§1.5 Ed25519 identity-
  multihash; re-confirms the cohort A-OC-007/A-SW-008 §7.4-vs-§1.5 divergence) +
  the §5.5 `verifySignature` crypto boundary.
- FFI: `ec_ed25519_keygen` (peer identity at boot) + `ec_ed25519_verify` (chain
  boundary) added to the shim + `Crypto.lean`. **No C-ABI change** — both already
  exist in the C-ABI; keygen suffices for the peer's own identity (validate-peer
  dials whatever peer listens, so a fresh per-boot identity is fine).

### Faithfulness selftest (committed next)
`Selftest.lean` (`selftest` exe) — 14/14 PASS. De-risks the novel segment-model
matcher + attenuation BEFORE the shell or the proofs depend on it: trailing/`*`
depth rules, leading `/*/` one-segment rule, bare-`*`-canonicalizes-to-frame, and
the **§PR-8/§5.5a granter-frame discipline** — `scopeSubset` of a foreign-granted
bare `*` across different frames is correctly NOT a subset (the v7.73 V2(a) fix,
now validated in pure form), while same-frame IS.

Conformance 69/69 unregressed; proofs still axiom-clean `[propext, Quot.sound]`.

## Next (this phase, not yet done)
1. **Transport + store + dispatch shell (IO)** — the 1c `transport` spike is the
   seam (FFI socket shim, dedicated-thread `recv`, `Std.Mutex` store — the §7b
   OCaml posture). Wire framing, message loop. The unproven shell that calls the
   pure verdict core.
2. **Resolve layer** — parse envelope → collect chain (resolve parents via
   store/included) → resolve granter peer_ids + verify sigs (FFI) → build
   `ResolvedChain`; the §5.2 `verifyRequest` authn (sig/author → 401) + revocation
   + Layer-2 post-gate wrapping the pure core.
3. **v7.74 foundations**: register (§6.13a), outbound closure (§6.13b — likely
   from-zero like OCaml), emit (§6.10), peer-owner cap + seed-policy (§6.9a), §7a
   conformance handlers (`--validate` off by default, reentry over inbound conn).
4. **Converge `validate-peer --profile core`** (576 total) + origination-core 3/3.
5. **Track B — prove T4/T5** against the now-stable pure core:
   - **T4**: verdict determinism corollary + document the factoring (A-LEAN-1/2).
   - **T5a** (highest discovery): `matchesSeg` subset-transitivity = a transitive
     preorder, ⇒ per-link attenuation composes to leaf ⊆ root — OR a 3-pattern
     counterexample (spec defect). Surfaces A-LEAN-3 (stale §5.6 frame, likely
     already the shipped v7.73 erratum) + A-LEAN-4.
   - **T5b**: `chainExceedsDepth` ↔ over-depth; the shipped 400 pre-check sound.
   The segment model was chosen precisely to make T5a tractable.
