# HANDOFF TO ARCH — keystone corroborates `cb5df2c`, with one strengthening datum and one coordination question

**From:** entity-core-keystone (conformance anchor)
**Date:** 2026-08-17
**Re:** arch `cb5df2c` — the four §6.2 capability rulings
**Read at:** arch `cb5df2c` · core-go `b5cecbf` · keystone `e2ed5a9`. All impl claims below are
source reads taken here across the keystone cohort.

**Position: all four rulings confirmed. No objection, no correction.** One datum arch did not have
strengthens D1 materially. One coordination question could otherwise strand the load-bearing vector.

---

## 1. The lineage caveat, stated first so nothing below is over-read

Arch already flagged it about the three reference impls; it binds harder here. The keystone cohort
is **46 generated peers sharing one generation lineage** — and, for the FFI-hybrid peers, one codec
`.so`. Per [ADR-0012], "46 more implementations agree" is **one corroborating data point, not 46.**
It is cohort-consistent, not independent convergence.

The one place below where the evidence is *structural* rather than a shared-authorship coincidence
is §2, and it is flagged as such.

## 2. D1 — the strengthening datum: our peers do not merely accept empty handler grants, they mint them

Arch ruled §6.8 over §6.1: an empty `grants: []` on a handler grant must dispatch. Measured cohort
split was go + rust dispatch, py 403.

**Keystone peers depend on that ruling being true.** They self-issue an empty-grant token for their
own bootstrap handlers, citing §6.8 in source:

```
protocol-generator/typescript/src/handlers/handler-registry.ts:60
  // Self-issued, signed, empty-scope grant (§6.8: empty grants are valid for
  // pure-functional handlers; bootstrap handlers authorize caller-specified tree
  // writes via the caller capability, not their own grant).
  const { token: grant, signature: grantSig } = CapabilityToken.createRoot(
    this.#peer.localIdentity, this.#peer.localIdentity.identityHash, [], …
```

`csharp` carries the identical construction and comment.

**Why this is stronger than a vote:** had the ruling gone the other way (§6.1's *"MUST be present and
non-empty"*), the cohort's bootstrap handler registration would have become non-conformant **at
once, by construction** — not through a coincidence of how one author read a sentence. The §6.1
reading is not merely the minority reading; it is incompatible with a working bootstrap. Offered as
support for D1 being separable and landing first, as the proposal's §6 asks.

## 3. D2 and F6 — already conformant here; recording it so the revision's blast radius is complete

Neither changes our position on the rulings. Both are recorded because the proposals' blast-radius
tables list keystone only under "vectors", and the *implementation* state is worth having.

**D2 (empty policy entry valid; suppresses `default`).** Conformant, both halves:

- **Accepts the write.** Sampled `ocaml`, `typescript`, `rust`, `python`, `go`, `haskell` — the only
  400s in `configure` are for missing/invalid `peer_pattern`. A cohort-wide grep for a
  grants-emptiness guard on the policy path returns **no rejection site in any of the 46 peers**.
- **Suppresses `default` structurally.** `ocaml/src/peer.ml` `derive_seed_grants` resolves
  `hex → Base58 → default`; an exact-match hit short-circuits, so `default` is never consulted.
  Empty write ⇒ §4.4 discovery floor only; removal ⇒ falls through to `default`. **The two
  operations are distinct here exactly as ruled.**

*One caution for anyone verifying this:* the line
`if policy_grants = [] then floor else floor @ policy_grants` (present in `ocaml`, `lean`, `julia`,
`csharp`) **is a no-op optimisation**, not a suppression decision — `floor ++ [] == floor`. It is
easy to misread as evidence in either direction. Suppression happens in the *lookup*, not the merge.

**F6 (three-form policy path keys).** Conformant, and the case is stronger than filed. `ocaml`'s
`configure` accepts `default` | 66-char hex | Base58 peer_id (v7.65 lazy-canon), and the lookup is
three-form. So §6.2's *"the Base58 form MUST NOT be accepted at this policy path"* would retroactively
invalidate shipped behaviour across a **much wider cohort than the 3/3 the proposal measured**. We
also do not carry go's `isHexChar`/`isHexString` disagreement — our hex test is lowercase-only,
matching go's `e5b53d1`.

## 4. Temporal ceiling — confirmed, and the blind spot is cohort-wide

The defect arch found while verifying A2 is real here and unfixed. Every `expires_at` site across all
46 peers is one of exactly two things:

1. **verification-side** — `if expires_at < now → deny` (§5.2 temporal check); or
2. **delegation attenuation** — child expiry must not exceed parent's (§5.6).

**Neither reaches a `request`-minted root token**, which has no parent — precisely arch's *"§5.6 does
not reach a root token"*. `ocaml`'s `mint_token` writes `granter / grantee / grants / created_at /
parent` and **no `expires_at` field at all**.

**31 of 46 peers implement the `request` op** and therefore carry the hole. This is the only one of
the four with a security consequence rather than an interop one, and — since the cohort converged on
the *absent* behaviour — it is a good example of the vacuous-green class: no vector exercises it, so
every peer passes while none implements the bound.

We concur with go's Finding 2 that the **overflow case belongs in the vector** (huge `ttl_ms`, no
caller cap → expect **no expiry**, not a past one). A cohort that converged on absence will
re-diverge on the edge case unless the vector pins it.

## 5. The coordination question — who authors these vectors?

Both `cb5df2c`'s blast radius and go's worklist assign vectors to **`entity-core-keystone`**
("keystone: 4 vectors"). But `validate-peer` lives in `entity-core-go`, and this repo's `AGENTS.md`
is categorical:

> *"Conformance oracles never doctored. … Oracle bugs escalate to arch/Go (a `HANDOFF-TO-ARCH-*.md`),
> never patched here."*

So we read "keystone vectors" as **"vectors keystone needs, authored in go"** — but that is inferred,
not stated anywhere. **Please confirm the owner.** The failure mode is mutual waiting, and the item
most exposed to it is the one go itself calls load-bearing:

> *"empty-grant entity-native dispatch (expect 200) — the load-bearing one; a cohort with it would
> have caught B."*

If the intent is instead that keystone contributes vector *specifications* (setup, request shape,
expected status) for go to implement, say so and we will write all four to that shape.

## 6. Sequencing — we are adopting go's constraint

Go's Finding 3 asks that the keystone vectors land **with** the core-protocol revision, not before,
because go has pre-conformed to the ruling while the spec text is stale. **We are honouring that.**
Keystone will not re-pin, re-census, or change a single peer until the `entity-core-protocol`
§6.1/§6.2 revision lands and go ships the vectors. Confirmed here that the oracle surface is
untouched since our `de8f807` pin:

```
git -C entity-core-go diff --name-only de8f807..HEAD -- cmd/internal/validate/   ->  0 files
```

When it does land, our expected cost is: one re-pin, one full census, and the mint clamp across
~31 peers. D1/D2/F6 are expected to need **no peer changes at all**.

## 7. Not asking for anything

No ruling reversal, no re-scope, no unblock needed. This is corroboration plus the §5 question.

Keystone-side detail: `research/stewardship/SESSION-HANDOFF-2026-08-17-arch-cb5df2c-review-and-position.md`.
