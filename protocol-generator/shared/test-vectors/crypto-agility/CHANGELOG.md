# Crypto-Agility Conformance Corpus — Changelog

**This file is the corpus's version.** The directory is named for what the corpus
tests and the artifacts carry no version stamp; what changed, when, why, and who
re-blessed it lives here instead. An integer in a filename says only that
something moved — and in practice it did not even say that, because it was never
once incremented.

A conformance citation names `(spec-version, corpus-name, artifact sha256)`. The
sha is the exact identifier; this file is the narrative behind it.

**Vectors are never removed.** A landed vector stays a conformance criterion. A
vector that is wrong is corrected in place and the correction is recorded here.

---

## 2026-08-22 — de-versioned; the second copy is gone

**No vector value changed and the artifact did not move**
(`b5484e84dd2cddfa7d3cc8a041deba92cb29615aedb2180e31d8b6910ac5b648`, 10874 B,
before and after).

The corpus had two committed copies: a `v767/` working copy and this
de-versioned publish form. They collapse into this one.

- `v767/` is deleted. It was named for spec revision v7.67 — the revision that
  birthed the corpus, retired for the 0.8.x line — and the corpus had since been
  re-stamped under different rules, so the name was true when written and false
  afterward.
- `agility-SEEDS.md` → `SEEDS.md`; `agility-vectors-v1.{diag,cbor}` →
  `agility-vectors.{diag,cbor}`.
- The `.cbor` byte-identity invariant between the two copies retires with the
  second copy. What replaces it is the source-produces-artifact gate, which is
  the check that actually catches drift.

**Why the two-copy structure went, stated once because the cost was real.** The
copies drifted four separate times in one week: five of thirteen shared vector
descriptions diverged, a width correction reached one copy and not the other, the
seed document gained normative process rules in the working copy that the
published copy never received, and a de-versioning transform that touched an
encoded field would have silently produced two different artifacts at the next
rebuild. Every one of those was created by the second copy existing.

The corpus-process rules that lived in the working copy's `SEEDS.md` §§4.1–4.4
and §5 are not lost — they were never seed pins, and they now live in
`GUIDE-CONFORMANCE` §5.1a–§5.1d, which is where procedure belongs.

## 2026-08-13 — `hash-format-sha-384.2.rehash` inverted

Artifact 9742 B → 10874 B.

`ENTITY-CORE-PROTOCOL` §4.5a item 1a pins the `system/peer` entity to the
ECFv1-SHA-256 floor unconditionally: its data is wholly recoverable from the
public peer-id, so it is never hold-and-fetch and has no home format. This vector
had been asserting that the same fixture could be re-hashed under
`content_hash_format = 0x01` and pinning the result — **the exact construction
item 1a forbids.**

- `kind` moves from `content_hash_under_format` to `construct_reject`.
- The three SHA-384 pins are removed; the retired value is recorded in `SEEDS.md`
  §1.2 as history, not as an expectation.
- `expected_behavior`, `verifier_requirement` and `floor_form` are added. The
  verifier **MUST** route through the pinned constructor: the vector stayed green
  for a week only because the harness hand-built the entity and so bypassed the
  code that would have refused it.

**Coverage lost, recorded because inverting is not free.** This was the corpus's
only *positive* SHA-384 content-hash vector. SHA-384 digest computation over an
entity is now exercised only by refusal. A replacement positive vector belongs on
a non-`system/peer` type — one that legitimately carries a home format — and is
**owed**.

## 2026-08-12 — M3/M6 re-stamped to floor form

Six expectations across `MATRIX-M3` and `MATRIX-M6` were stale after item 1a
moved `system/peer` to the floor. One cause, six symptoms: peer A's content hash
moves to the floor, so the root cap that references it via `granter.hash` moves,
so the signature over that content hash moves.

- `expected_peer_a_content_hash_sha384` → `peer_a_content_hash`. The `_sha384`
  suffix was always a divergence from the ratified shape, and under item 1a it
  named a knob that cannot exist.
- Values move from SHA-384-form (`01…`, 49 B) to floor-form (`00…`, 33 B).

Every `peer_b` SHA-256 assertion stayed green throughout, which is what proves
the cause was singular: peer B was already at the floor and item 1a did not move
it.

## 2026-08-12 — F16 widths swept back into the `.diag` source

Six literals were wrong **in the source** and correct in the build artifact — the
inverse of the usual direction, and the reason it survived two months:

- Ed448 secret seeds carried 58 bytes where RFC 8032 `SeedSize` is **57**
  (`key-type-ed448.1.pubkey`, `.4.signature`, `matrix.M2`, `matrix.M6`).
- The `experimental-test` `public_key` carried 63 bytes where the spec pins
  **64** (`hash-format-sha-384.1.inherited_sha256_pin`, `.2.rehash`).

The June regeneration corrected the artifact and nobody swept the source, so the
artifact-is-expected gate reported clean throughout — correctly, because the
artifact *was* what it was expected to be. Nothing asserted that the source still
produced it. **This is the entire case for the second gate.**

## 2026-06-21 — v0.8.0 public release

Corpus published in the initial public release.

## 2026-06-10 — F16: artifact regenerated

The artifact was decoded end-to-end during an independent implementation's
bring-up and found internally inconsistent with its own source: the seed and
public-key widths above, plus **all twelve** Phase-2 `expected_*` fields still
carrying the literal text `TBD-COHORT-ROUND-TRIP`.

The three-way "byte-equal" agreement had compared cryptographic outputs and the
file's sha256 — and never decoded the file. Superseded artifact sha
`4d8dfced…`; regenerated to `8e7c5232…` (9236 B). No cryptographic pin changed.

**The discipline this produced:** a byte gate MUST decode the artifact and assert
structural invariants against the source. Comparing shas across implementations
proves they produced identical bytes; it does not prove the bytes are correct.

## 2026-06-10 — Phase 2 byte-pinned

`MATRIX-M2`, `MATRIX-M3`, `MATRIX-M6` pinned from a three-way cross-impl
round-trip; all seven gates per vector byte-equal.

The round-trip surfaced one latent cross-impl divergence: an unconstrained
capability scope dimension was emitting `{include: null}` (`0xf6`) in one
implementation and `{include: []}` (`0x80`) in the other two. Ruled to `[]` — both
halves were already bound by `ENTITY-CBOR-ENCODING` §232 and §3.6
`list-of(pattern)` typing, so no spec change was needed.

## 2026-06-09 — Phase 1 byte-pinned

Five Phase-1 vectors (`KEY-TYPE-ED448-1`, `HASH-FORMAT-SHA-384-1`,
`VARINT-MULTIBYTE-1`, `VARINT-RESERVED-FF-1`, `FORMAT-CODE-INTERPRETATION-1`)
byte-equal across three independently written implementations.

Phase 1 is byte-pinned in the strong sense precisely because three implementations
produced it independently. Phases 3a and 3b (BLAKE3, ML-DSA-65) remain deferred
with no seeds pinned.
