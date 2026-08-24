# HANDOFF-TO-ARCH — F29: ECF corpus coverage gap (array-of-maps, ≥24-byte inner string)

> **✅ RESOLVED 2026-07-12 — archived.** Arch added `nested.5`/`nested.6` to the ECF corpus
> (`entity-core-protocol` @ `be54baf`); keystone re-vendored `9695b1f1…` (71 vectors) and re-ran
> the cohort **71/71 across 27 codec peers**. See `SPEC-FINDINGS-LOG.md` **F29** and
> `docs/status/HANDOFF-2026-07-12-f29-f30-revendor.md`. Kept for provenance; no action outstanding.

**From:** entity-core-keystone (stewardship) · **To:** architecture (owns the ECF corpus)
**Date:** 2026-07-12 · **Finding:** F29 (`research/stewardship/SPEC-FINDINGS-LOG.md`)
**Class:** test-surface gap — **not a spec defect.** No V7/V8 normative change requested.
**Routing:** per the bidirectional contract in `AGENTS.md`; keystone cannot edit the
SHA-pinned corpus (it's a boundary), so this is an ask, not a patch.

## The ask (one sentence)

Add a covering vector to the pinned ECF corpus
(`protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`) that
exercises **an array whose elements are maps carrying a text string ≥24 bytes** — so the
CBOR head-form boundary *inside an array element* is tested at the S2 codec layer, closing
the gap cohort-wide.

## Why it matters — a codec can be 69/69-green yet carry a latent encoder bug

The 69-vector v0.8.0 corpus has **no vector exercising an array-of-maps whose inner map
carries a text string ≥24 bytes** — i.e. the CBOR 1-byte-head → head+1-length-byte
boundary (RFC 8949 §3: minor 0–23 inline vs minor 24 = "one length byte follows")
occurring *inside an array element*, one nesting level down.

In the 53-type §9.5 floor, the only array-of-refs is `union_of` in
`system/capability/token`, so this shape is **first reachable at S4 type-registry publish**,
not in the S2 codec corpus. The consequence is concrete: a peer's array/map encoder can have
a defective `+1-byte-head` branch, pass **69/69** on the corpus, and only fault when it
publishes the 53 types at S4 — or never, if that path isn't exercised. This is the
"conformance-green can be vacuous" pattern made concrete on the *encoder*.

## Evidence it's real (not hypothetical)

- **Forth #25 — `A-FT-017`** (`protocol-generator/forth/status/SPEC-AMBIGUITY-LOG.md`): the
  `emit-head` +1-byte case dropped a stack cell — a genuine S2 encoder defect. It was
  **hidden clean through S2 (69/69 green)** and surfaced only at S4 type-registry publish,
  exactly on this shape. Fixed in Forth; the *corpus* that let it hide is unchanged.
- **Smalltalk #26** (this session): S2 was likewise **69/69 byte-identical** on the same
  corpus. Any peer whose head encoder has an analogous branch shares the same blind spot —
  the corpus cannot distinguish a correct encoder from one with this latent bug. The gap is
  **cohort-wide**, not Forth-specific.

## Precisely what would close it

A vector of shape (CBOR diagnostic sketch):

```
[ {"k": "<a ≥24-byte, <256-byte text value>"},
  {"k": "<another such value>"} ]      # array → map element → text head with 1 length byte
```

- **Primary:** at least one array element is a map whose value is a text string of length in
  **[24, 255]** (the 1→2-byte head-form boundary; minor 24, `0x78`).
- **Ideally also:** a companion element (or a second vector) with a text value of length
  **≥256** (the 2-byte head-form boundary; minor 25, `0x79`) — same class of encoder bug,
  next boundary up.
- Byte-locked cross-impl as usual (Go × Rust × Python), added to
  `conformance-vectors-v1` with the SHA re-published in `MANIFEST.md` / ENTITY-CBOR-ENCODING
  Appendix E, exactly as the F7 `int.15/16/17` boundary vectors were folded (v1.5→v1.6).

Any semantically equivalent vector that forces the inner-element head-length boundary is
fine — the shape is the requirement, not the literal keys/values above.

## Boundaries honored

- Keystone did **not** edit the corpus or any spec-data (SHA-pinned, immutable).
- No arch-repo write; this doc sits in keystone's `research/stewardship/` for arch to pull in
  on its own schedule.
- Not urgent — every affected peer is individually fixed (Forth) or green with the shape
  independently checked; this closes the *test surface* so the next peer can't re-hide it.

## References

- `research/stewardship/SPEC-FINDINGS-LOG.md` — F29 (pipe-table row + status sweep)
- `protocol-generator/forth/status/SPEC-AMBIGUITY-LOG.md` — A-FT-017
- `protocol-generator/shared/test-vectors/v0.8.0/` — the corpus + `MANIFEST.md`
- RFC 8949 §3 (CBOR head forms); the F7 fold as the precedent for a corpus boundary-vector add
