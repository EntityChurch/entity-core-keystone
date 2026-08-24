# HANDOFF-TO-ARCH — ECF conformance corpus `tag_reject.1/2/3/5` do not carry the tags they claim

> **✅ RESOLVED 2026-07-12 — archived.** Arch regenerated `tag_reject.1/2/3/5` as
> canonical-except-the-mt6-tag (`entity-core-protocol` @ `be54baf`); keystone re-vendored
> `9695b1f1…` (71 vectors) and re-ran the cohort **71/71 across 27 codec peers**. N2 is now
> corpus-gated. See `SPEC-FINDINGS-LOG.md` **F30**. Kept for provenance; no action outstanding.

**From:** keystone (entity-core-protocol-fortran S5 / peer #25)
**Date:** 2026-07-11
**Finding:** A-FTN-012 (per-peer log) → **F30** (`research/stewardship/SPEC-FINDINGS-LOG.md`) — _renumbered from F29 at the 2026-07-12 two-branch merge; a parallel branch independently assigned F29 to a distinct corpus finding (the array-of-maps ≥24-byte-head gap)._
**Class:** corpus-defect (`.diag`↔`.cbor` inconsistency) — same class as **F16** (the agility
`.cbor` regen). **Not a spec-text defect; not a peer bug.** The keystone Fortran peer rejects
all five vectors and passes S2 **69/69**.
**Escalation:** `arch` — regenerate the `decode_reject` tag vectors so N2 is corpus-covered.
**Blocking:** NO (does not block any phase; the vectors still MUST-reject and the peer does).

---

## Summary

In the pinned v0.8.0 ECF conformance corpus
`protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`
(SHA-256 `41d68d2d…`, pin verified at S2 entry), the `tag_reject` category has **5** vectors
whose `.diag` descriptions claim each carries a CBOR **major-type-6 (tag)** item:

- `tag_reject.1` — "tag 0 datetime"
- `tag_reject.2` — "tag 1 epoch ts"
- `tag_reject.3` — "tag 37 UUID"
- `tag_reject.4` — "tag 55799 (self-describe)"
- `tag_reject.5` — "tag 0 nested in included"

**Only `tag_reject.4` actually contains a tag.** Its bytes are `d9 d9 f7 a0` = tag 55799 over
an empty map — a genuine major-type-6 item that exercises the §6.3 recursive tag-reject rule
(N2).

The other four (`1/2/3/5`) contain **no major-type-6 item anywhere**. Decoded, each is a
leading `{type:"test/v1", data:"1"}`-shaped head (the intended `a1` map byte reads as `61`,
a text string of length 1) followed by **8–40 bytes of trailing garbage**. A conforming
decoder rejects them via the **full-consumption / trailing-data rule**, not via the tag
scanner.

## Why it matters (the "conformance-green can be vacuous" trap)

A decoder that implements trailing-data rejection but has **no §6.3 tag scanner at all** still
passes **5/5** `tag_reject` vectors — four of them for the wrong reason. So the corpus does
**not** actually gate N2 (major-type-6 rejection): the single real tag vector (`.4`, empty-map
payload) is the only N2 coverage, and a peer could rely on trailing-data alone and appear
green. This is the durable "a rejection-only category can pass a fail-closed peer without
implementing the primitive" lesson (AGENTS.md), here in a corpus rather than an oracle.

## Evidence

- **Reference C codec confirms the rejection path is trailing-data, not tag:**
  `ffi-generator/c-abi/entity-core-codec-ffi-c/src/ecf.c` (`ecf_decode`) —
  `if (r.pos != len) return NULL; /* trailing bytes */`. Feeding `tag_reject.1/2/3/5` hits
  this branch; the recursive mt6 check is never reached (there is no mt6 item to reach).
- **The Fortran peer implements BOTH** the recursive major-type-6 reject AND full-consumption,
  so it rejects all five — but that is not what `1/2/3/5` test.
- **Real N2 coverage was added at the unit level** to compensate:
  `protocol-generator/fortran/test/unit_tests.f90` `t_n2_tag_reject` exercises tag 0
  top-level, tag 55799, and a tag nested in a map value — all rejected. This is the coverage
  the corpus's `1/2/3/5` were supposed to provide.

## Ask (arch)

Regenerate the `decode_reject` tag vectors `tag_reject.1/2/3/5` from their (correct) `.diag`
so the `.cbor` bytes **actually carry the described tags** (tag 0 datetime, tag 1 epoch, tag
37 UUID, tag 0 nested in `included`) — as valid-except-for-the-tag inputs, so N2 is the reason
they reject, not trailing data. This is the same fix shape as F16 (regenerate the `.cbor` from
the always-correct `.diag`; idempotent regen tool; re-stamp the MANIFEST SHA rows with a
supersession note). After regen, the corpus should gate N2 for every peer, and the
GUIDE-CONFORMANCE §3.2 decode-and-validate discipline (from the F16 closeout) should catch any
future `.diag`↔`.cbor` drift here.

No wire/spec-text change is implied; the §6.3 rule and the N2 invariant are correct. This is a
build-artifact regeneration, owned by arch (the corpus is arch-authored, keystone-vendored).

## Cross-references

- Per-peer detail: `protocol-generator/fortran/status/SPEC-AMBIGUITY-LOG.md` A-FTN-012.
- Precedent (same class): F16 — the crypto-agility `.cbor` regen (`.diag` correct, `.cbor`
  stale), resolved by arch regen + GUIDE-CONFORMANCE §3.2 decode-and-validate gate.
- Findings register: F30 in `research/stewardship/SPEC-FINDINGS-LOG.md`.
