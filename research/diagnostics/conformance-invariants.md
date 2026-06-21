# Conformance Invariants — Bug-Class Playbook (N1–N8)

**Status:** Normative-by-reference (pins V7 invariants; the spec is authoritative on any disagreement).
**Origin:** Architecture review memo `c0513c8`, folded from the bug classes that bit **all three reference implementations** (Go, Rust, Python) and were found + fixed in 2026-05. Pinned here so the keystone pipeline **enforces them at design time, not rediscovers them at S4.**

> Why this doc exists: each of N1–N8 is a place where a correct-looking implementation silently diverges on the wire. Reference impls hit them in production. A generated peer will hit the same ones unless the generator is told up front. The diagnostic playbook (`validate-peer-usage.md`) is for *symptoms after the fact*; this doc is for *prevention before the fact*.

## How to read this table

- **Layer** — `codec` items are enforceable at **S2** (the FFI crate + every native codec, byte-checkable against test-vectors). `peer` items are **S3/S4** machinery, caught by `validate-peer` (some only by convergence mode).
- **Enforcement point** — where in the keystone pipeline this MUST be checked.
- Every codec item (N1–N3) MUST have corresponding **test-vectors** so byte-identity makes the bug impossible to ship silently (see `protocol-generator/shared/test-vectors/v0.8.0/`).

---

## Codec-side (S2 — relevant to the FFI crate, step 8, directly)

### N1 — Varint format-code framing is LEB128, not a fixed byte
**V7:** §1.2 (hash format codes), §1.5 (peer-id key_type/hash_type), §7.3 (multicodec-style LEB128, NORMATIVE).
The currently allocated codes (`0x00`/`0x01`/`0x02`; key_type/hash_type `0x01`) are all < `0x80`, so each encodes as a single byte — **byte-identical to a fixed-width field today**. The trap: hard-coding "read 1 byte" instead of a varint primitive. Future codes ≥ `0x80` extend to 2+ bytes and a fixed-width impl breaks silently.
**Design-time action:** implement real `varint_encode`/`varint_decode` primitives in the codec; route all format-code/key-type/hash-type framing through them. Add a test-vector with a synthetic ≥`0x80` code to prove the primitive (even though no such code is allocated yet).

### N2 — Tag rejection requires an explicit scanner
**V7:** `ENTITY-CBOR-ENCODING.md` §6.3 (Option B — reject on receive), V7 §1.11 (boundary conformance).
Receivers MUST reject any CBOR **major-type-6** item appearing anywhere in a `data` field, at any nesting depth (top-level, nested arrays/maps, inside `included` entities' data), with `400 non_canonical_ecf`. Many CBOR libraries silently accept/strip/interpret tags by default — so the decoder needs an **explicit tag scanner**, not library defaults. MUST NOT strip, preserve, or interpret.
**Design-time action:** decode path runs a recursive major-type-6 scan over every `data` region; reject on hit. Exception: tag 55799 as a *file* marker only — never on the wire. Covered by the `tag_reject` test-vector category.

### N3 — Empty-params canonical shape is `0xA0`
**V7:** §3.2 (empty-params normative shape). `params` with no parameters is a `primitive/any` entity whose `data` is the **empty CBOR map — single byte `0xA0`**, giving a stable cross-impl content_hash. Serializer "optimizations" (emitting null, omitting the field, or a non-minimal map) corrupt the hash.
**Design-time action:** pin the empty-map encoding as `0xA0` in a test-vector; assert the empty-params entity hashes identically across the FFI crate and every native codec. **Hash note (F5 — RESOLVED):** the spec's old Appendix A.1 `empty_map` hash `44136fa3…` was wrong; arch patched it (commit `23db254`). The empty-data boundary is now pinned by fixture vector `content_hash.1` over the full entity `{type:"system/empty", data:{}}` → content_hash `005f3139e342…0ca396b`. (It is *not* `sha256(0xA0)`; F5's initial `c19a797f…` guess was the hash of the bare `0xA0`, the wrong preimage.) The `0xA0` *encoding* invariant was always correct and is unaffected.

### N4 — Entity fidelity: never re-serialize on forward *(codec surface + peer)*
**V7:** §1.8 (Entity Fidelity), §7.2 (validate on receipt). This is the **Class-A bug class** — same family as the W1/W2 `cbor2` float16 bug. After validating a received entity's hash, an impl MUST forward the **original bytes**, never a re-encode of its decoded form (a lossy decode → re-encode changes bytes → breaks the hash and any signature over it).
**Design-time action:** the decode surface must let callers retain the **original wire bytes** alongside the decoded structure. **Resolved:** `ec_decode_entity` hands back a borrowed slice of the exact input bytes (option (a)), with an optional `ec_entity_original_bytes()` convenience — normative in `ffi-generator/c-abi/spec/ENTITY-CODEC-C-ABI-V1.md` §3.4/§4.1. See `ffi-generator/c-abi/status/DESIGN-NOTES-FROM-REVIEW.md` for the original framing.

---

## Peer-side (S3/S4 — pin now, enforce at peer build)

### N5 — Envelope `included` preservation, request **and** result side
**V7:** §3.1, §3.3 (v7.49/v7.51). The `included` map MUST survive across **every** dispatch surface (local / internal / remote) and MUST NOT be dropped before the wire — on both the request side (EXECUTE) and the result side (multi-entity results carried as `system/envelope`). **All three reference impls shipped real bugs here.**
**Enforcement:** S3 dispatch + emit pathway; `validate-peer` `encoding`/`origination`.

### N6 — Inbound frame processing concurrent with outbound dispatch
**V7:** §4.8 (normative, correctness not perf). While a handler processes an inbound frame, the peer MUST keep reading/dispatching frames **and** sending outbound EXECUTEs on the same connection without waiting for that handler. Forbids any architecture where inbound blocks on outbound. **All three impls had "F9b" bugs here.**
**Enforcement:** S3 connection model; surfaces in `validate-peer` as `connection_broken`/`recv_timeout` (see `validate-peer-usage.md`).

### N7 — Reentrant transport + `request_id` demux
**V7:** §6.11 (transport reentry contract), §6.12 (per-request transport error codes: `recv_timeout` 503 / `connection_broken` 503 / `protocol_error` 502). Replies arrive out of order; correlation is by `(author, request_id)`. The transport must be reentrant (a handler issuing a sub-request mustn't deadlock the reader).
**Enforcement:** S3 processor loop + request demux; `validate-peer` `origination`.

### N8 — Capability-chain verdict determinism
**V7:** §5.10 (verdict determinism + policy layering, normative). Layer-1 verdict (crypto + structural linkage + attenuation) MUST be **identical across peers** given the same chain state; Layer-2 local policy MAY diverge. Tested by `validate-peer` **convergence mode** (multi-peer).
**Enforcement:** S3 capability system; S4 convergence run (`-peers …`, see `validate-peer-usage.md`).

---

## Cross-references

- Codec phase contract: `protocol-generator/shared/lifecycle/PHASE-S2-CODEC.md`
- Peer phase contract: `protocol-generator/shared/lifecycle/PHASE-S3-PEER.md`
- Codec C-ABI spec (canonical) + `ec_entity_original_bytes()`: `ffi-generator/c-abi/spec/ENTITY-CODEC-C-ABI-V1.md` (lineage: `ffi-generator/c-abi/arch/DESIGN-v1.md` + `…/status/DESIGN-NOTES-FROM-REVIEW.md`)
- Symptom-side debugging: `research/diagnostics/validate-peer-usage.md`
- Spec snapshot: `protocol-generator/shared/spec-data/v0.8.0/` (authoritative text for every §-pointer above)
- Source review: arch memo `c0513c8`
