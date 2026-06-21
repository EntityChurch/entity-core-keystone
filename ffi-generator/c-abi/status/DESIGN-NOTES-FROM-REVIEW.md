# FFI Codec — Design Notes from Review (pre-implementation)

**Status:** Operator notes pending architecture ratification. **`arch/DESIGN-v1.md` remains authoritative** — these are proposed deltas + design-time constraints captured before step 8 (hand-authoring the crate), not edits to the design doc.
**Source:** arch review memo `c0513c8` + first-hand read of V7 7.56 / `ENTITY-CBOR-ENCODING.md` 1.4.

## Codec-side conformance invariants to honor at implementation time

These are the codec-relevant entries of the bug-class playbook (`research/diagnostics/conformance-invariants.md`). Pinning them here so the crate is built right the first time rather than patched at S2/S4.

| Inv | Constraint on the crate |
|---|---|
| **N1** | Format-code / key-type / hash-type framing MUST go through real LEB128 **varint primitives**, not "read/write 1 byte." Current codes (`0x00`–`0x02`, `0x01`) are single-byte today; a fixed-width impl breaks silently at the first code ≥ `0x80`. Ship a synthetic ≥`0x80` test-vector to prove the primitive. |
| **N2** | The decode path MUST run an **explicit recursive major-type-6 (tag) scanner** over all `data` regions and reject with `DECODE_ERROR` / surface `400 non_canonical_ecf` to callers. Do not rely on `ciborium` defaults. MUST NOT strip / preserve / interpret tags. |
| **N3** | Empty-params / empty-map encodes as the single byte **`0xA0`**. Assert `ec_content_hash` of the empty-data entity equals fixture vector `content_hash.1` (`{type:"system/empty", data:{}}` → `005f3139e342…0ca396b`) — guards against serializer "optimization." (The old Appendix A.1 hash `44136fa3…` was wrong; F5 RESOLVED, arch `23db254`.) |
| **N4** | **Entity fidelity** (V7 §1.8): decoded entities must be forwardable as their **original bytes**, never a re-encode. See proposed surface addition below. |

## Proposed FFI surface addition (for arch ratification)

`DESIGN-v1.md` §"Hash + entity" exports `ec_decode_entity` returning type+data slices into an arena. To satisfy **N4** without forcing every consuming peer to re-implement byte-retention, propose **one** of:

- **(a)** `ec_decode_entity` additionally returns a borrowed slice spanning the **exact original entity bytes** of the input it decoded (zero-copy; lifetime tied to the caller's input buffer, consistent with DESIGN-v1 rule 1 "all inputs are borrowed"), **or**
- **(b)** a dedicated `ec_entity_original_bytes(bytes_ptr, len, out_ptr, out_len_ptr) -> int32_t` that validates and hands back the canonical original-byte span for a single entity.

Preference: **(a)** — no new entry point, and it naturally pairs original bytes with the decoded view at the moment fidelity matters. Either keeps the "pure functions, caller-managed memory, no callbacks" discipline of DESIGN-v1 intact.

**Not in codec scope** (correctly deferred to peer machinery per DESIGN-v1 "deferred to v2" + the playbook's peer-side N5–N8): envelope `included` preservation (N5), inbound concurrency (N6), reentrant transport / `request_id` demux (N7), capability-chain verdict determinism (N8). Noted here only so the boundary is explicit.

## Reference-encoder pin (test-vectors)

Per finding **F1** (`research/stewardship/SPEC-FINDINGS-LOG.md`), the spec's declared Appendix E fixture is not committed. The crate's byte-identity cross-check (DESIGN-v1 "Conformance test") is therefore measured against vectors generated from **`entity-core-go/core/ecf/ecf.go:Encode`** (the reference encoder Appendix E §E.4 itself names — Go has the cleanest cross-impl history). Generate test-vectors in parallel with the crate so byte-identity is measurable from the first commit.

## Open for arch

1. Ratify N4 surface addition — option (a) vs (b).
2. Confirm reference-encoder pin (Go `core/ecf`) as the interim source of truth until F1 fixture lands.
