# HANDOFF TO ARCH — 2026-07-19 — Unison peer (#43): two spec findings + one oracle-fact correction

**From:** entity-core-keystone (protocol-generator arm)
**Peer:** `entity-core-protocol-unison` — S1→S5 complete, `682·0F @ cc1970f`, `Result: PASS`
**Proposed finding IDs:** **F42**, **F43** (numbering for arch to confirm — latest referenced is F41)
**Routing:** keystone → arch per `AGENTS.md`. Written in this repo; arch pulls on its own schedule.

---

## Summary

Unison was built as a coverage / generator-robustness peer, on the standing expectation that
the wire surface is dry. That held for the *wire* — but the run surfaced **two genuine
spec-shaped defects**, both in the identity / policy-matching area rather than the codec, plus
**one correction to a fact about the oracle** that the keystone's own durable-lessons file was
asserting incorrectly.

Both findings cost real iterations: each was found by implementing the spec *literally* and
having the oracle reject the result. That is the failure mode worth caring about — a
conformant-by-the-text implementation that fails the vectors.

---

## F42 (proposed) — §3013's "exactly one of two forms" contradicts v7.65 §3.6 rule 3

**Severity:** correctness-of-text. A peer that implements §3013 as written **fails
`PEER-PATTERN-2`.**

§3013 enumerates the seed-policy `peer_pattern` forms as either `{caller_peer_hex}` or
`default`, and closes the enumeration explicitly:

> *"No other pattern forms are defined."*

But `PEER-PATTERN-2` requires the peer to **accept a Base58 peer_id** as a pattern for an
unknown peer in the pending-canonicalization state (v7.65 §3.6 rule 3). These cannot both be
true. The enumeration is closed; the vector requires a third form.

**Observed:** the Unison peer implemented §3013 literally — two forms, reject anything else —
and was rejected by the oracle. Fixing it required accepting the transitional Base58 form,
which §3013 says does not exist.

**Ask:** have §3013 either (a) name the transitional Base58 peer_id form directly, or (b)
cross-reference §3.6 rule 3 and drop the "no other forms are defined" closure — so the
enumeration is exhaustive *as written*. This is a text fix, not a behaviour change: the
implementations already have to accept the third form to pass.

**Keystone ref:** `protocol-generator/unison/status/SPEC-AMBIGUITY-LOG.md` → `A-UN-015`.

---

## F43 (proposed) — the unsupported-key_type check's ORDER relative to identity binding is unstated

**Severity:** ambiguity with a fail-closed-looking wrong answer. Same family as the
already-landed **F31** 401-vs-404 auth-ordering ruling, and asks for the same treatment.

Two requirements are each individually clear:

- §426 mandates `400 unsupported_key_type` for an unrecognised key type.
- §4.6 / §1.3 mandate the peer_id ↔ public_key binding check.

**Nothing states which fires first.** The natural implementation — derive the expected peer_id
under the supported key_type, then compare — makes an *unknown key type* indistinguishable from
an *impersonation attempt*, and so returns `401 identity_mismatch`. That is a defensible reading
of the text and is **wrong** per `AGILITY-UNKNOWN-1`, which expects `400 unsupported_key_type`.

**Ask:** state that key_type support is validated **before** identity binding, exactly as F31
fixed the resolution-vs-authentication ordering.

**Secondary consequence, currently unstated anywhere.** Key type `0xFD` has no canonical
`key_type` *string* (§431), so the only in-band signal of the key type is the **leading varint of
the Base58-encoded peer_id**. That means correctly returning `400 unsupported_key_type` **requires
a Base58 decoder in every peer**, before any identity work. For a peer with no crypto library to
lean on this is a non-trivial obligation, and it is not called out in the agility section. Worth an
explicit note.

**Keystone ref:** `A-UN-016`.

---

## Correction (not a spec finding) — `multisig` is no longer a rejection-only category

This one is keystone's own error, recorded here because it has been shaping how peers are built.

The keystone durable-lessons file asserted that the `multisig` oracle category is
*"100% malformed→403"* and therefore **vacuously passable** by a fail-closed peer that
implements no K-of-N at all.

**At `cc1970f` that is false.** The category ships `valid_2of3_peer_signed_accepted`, a genuine
accept vector. Against the Unison peer it was a **hard FAIL** while the peer was fail-closed on
multi-granter capabilities, and it passes only after real §3.6 K-of-N landed. The category
therefore *does* gate the accept path.

The *lesson* ("add an accept-path unit in the direction the oracle can't cover") remains correct
and is retained. The *factual claim* about this category is stale and has been corrected in
`AGENTS.md`, with the general rule added: **re-check a category's accept/reject mix against the
current oracle pin before calling it rejection-only.**

No action needed from arch — flagged so the record is consistent, and in case the same stale claim
appears in architecture-side docs.

---

## Operational note for the oracle (FYI, no spec change)

`validate-peer`'s default `-timeout 60s` is a **global** budget, not per-category. A slow peer
consumed it in two categories, after which **seven core categories reported `budget_exhausted`** —
which gates as FAIL but is *rendered with a skip-shaped message* that reads like a §9.0 carve-out.
Diagnosing that as a latency problem rather than as seven independent category failures was the
highest-leverage move of the phase.

If it is cheap to do, distinguishing `budget_exhausted` from a carve-out skip in the output would
save future implementers a genuinely misleading detour. Keystone-side rule already recorded: **fix
peer latency; never raise `-timeout`** — raising it manufactures a green report over a peer that
degrades under connection churn.

---

## Substrate datums (research ledger, no arch action)

Recorded for the crypto-availability and concurrency taxonomies:

- **A managed runtime with no C FFI is a distinct crypto tier.** Unison has no general C FFI, so
  the `libentitycore_codec` hybrid-FFI hatch used by OCaml/Zig/Swift is *structurally* unavailable.
  Agility can only be pure-language or deferred. (Deferred here; Ed448/SHA-384 WARN, they don't gate.)
- **A runtime can ship sign/verify and still ship no key derivation.** UCM exposes
  `crypto.Ed25519.sign.impl` / `verify.impl` — with the pubkey as an explicit *argument* — but no
  keygen. The peer therefore contains a hand-written GF(2²⁵⁵−19) Ed25519 key derivation (base-2¹⁶
  limb arithmetic, twisted-Edwards scalar multiplication, point compression). This is the sharpest
  crypto-spectrum data point the cohort has produced.
- **Algebraic effects are a fifth *route* to the actor guarantee, not a fifth shape** — `fork` +
  a single `MVar` store (`take → pure fn → put`) reaches one-owner serialized mutation through the
  effect system; §6.11 demux is a per-request `Promise`, i.e. the dataflow-variable pattern in
  different dress.
- **Content-addressed codebases are drivable headlessly.** UCM is interactive by design, but
  `ucm transcript` / `ucm run.file` support a fully non-interactive, offline, container-bound build
  — the generator-robustness question this peer was chosen to answer.

---

## Honesty statement

`682·0F @ cc1970f` (292P/294W/0F/96S), `--profile core`, oracle **not re-pinned and not doctored**,
every skip oracle-emitted with a stated reason (no `-allow-skip`). Codec 71/71. origination-core 3/3.

Two deliberate non-claims: **(1)** Ed448/SHA-384 agility is deferred; **(2)** the supplementary
peer-side multisig accept unit is **authored but UNVERIFIED** — it has never run green (a Unison
*parse* error in the test source, not a peer defect), so the accept path is substantiated by the
oracle leg alone. That leg is sufficient for the gate, and the unit is tracked as open.

This peer is keystone-generated and shares a generation lineage with the cohort:
**cohort-consistent, not independent convergence** (ADR-0012).
