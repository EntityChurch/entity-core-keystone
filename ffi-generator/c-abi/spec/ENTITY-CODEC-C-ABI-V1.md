# Entity Codec C-ABI Specification

**Version:** 1.1
**Status:** Normative (keystone-authored; not part of V7 core protocol)
**v1.1:** adds the crypto-agility symbol surface (§4.1a, §4.3a) — additive only; the v1.0 Ed25519+SHA-256 floor and every existing signature are unchanged, so this is a minor bump (§9). Decision G2 (per-algorithm symbols, "Option A") is recorded in §4.3a.
**Spec layer:** binding contract. Sits *below* the language peers (`entity-core-protocol-<lang>`) and *beside* the core protocol specs (`spec-data/v0.8.0/`). It does not amend the protocol spec; it specifies a C-ABI surface over the ECF codec that the spec defines.

This specification defines a **single C Application Binary Interface** over the Entity Canonical Form (ECF) codec, peer-id, and crypto primitives of the Entity Core Protocol. It is a language-agnostic contract. **Implementations** of this contract (`entity-core-codec-ffi-rust`, `entity-core-codec-ffi-c`, and any future impl) are interchangeable: a consumer links one shared library and is unaware of which implementation produced it.

> **The normative conformance contract for this specification is §10 (Conformance).** An implementation is conformant iff (a) it exports every symbol in §4 with the declared semantics, and (b) for every test vector it produces **byte-identical encoded output** to — and agrees functionally with — the Go, Rust, and Python reference implementations. The body of this spec defines *what* the ABI is; §10 is *how* conformance is verified. Conformance proves *correct against the test surface*, not *provably bug-free* (keystone standard S8).

---

> **Notation.**
> - **MUST**, **MUST NOT**, **SHOULD**, **MAY** per RFC 2119.
> - Byte sequences shown as hex: `A0`, `F9 7E00`.
> - C signatures use `int32_t` return / `(ptr, len)` argument pairs throughout (§5).
> - "Original bytes" / "wire bytes" mean the exact input octets, never a re-encode (§6, N4).
> - §-pointers into the protocol spec refer to `protocol-generator/shared/spec-data/v0.8.0/`.

---

## 1. Introduction

### 1.1 Purpose

This document specifies a stable C ABI exposing the small, performance-critical, cross-language-correctness surface of the Entity Core Protocol:

- ECF encoding + content-hash computation
- Entity decode with original-byte fidelity
- Peer-id parse/format
- Ed25519 keygen/sign/verify, SHA-256
- Envelope root-hash verification + signature lookup

Everything above this layer — wire framing, connection management, dispatch, capability chains — is **out of scope** and implemented natively by each peer (§11). This is the hybrid split: the codec is the small surface where every language must agree to the byte; the peer machinery is the large surface where native idiom wins.

### 1.2 Why this layer exists

Across the language landscape, CBOR libraries are **not** reliably canonical. Evaluated impls (`research/evaluations/`, the Go/Rust/Python reference history) show that no surveyed CBOR library, out of the box:

- minimizes floats to shortest round-tripping precision (RFC 8949 §4.2 Rule 4 / ECF Rule 4a),
- sorts map keys by encoded-length-then-lexicographic,
- rejects CBOR tags (major-type-6) on receive, and
- preserves original bytes on decode (entity fidelity, V7 §1.8),

*all at once*. Each reference impl had to hand-roll the canonical layer. This ABI gives ecosystems without a credible native canonical-CBOR + Ed25519 stack a drop-in, conformance-proven codec — and gives native-codec ecosystems a bit-identical cross-check oracle.

### 1.3 Scope

| In scope | Out of scope (peer machinery / v2) |
|---|---|
| ECF encode/decode, content_hash | Wire framing, length-prefixing |
| Peer-id parse/format | Connection / transport management |
| Ed25519 (keygen/sign/verify), SHA-256 | Dispatch, capability-chain validation |
| Envelope root-hash verify, signature lookup | Async / streaming / callbacks |
| Original-byte fidelity on decode | `included`-preservation policy (peer, N5) |

### 1.4 Terminology

| Term | Definition |
|---|---|
| ECF | Entity Canonical Form — the deterministic encoding used for hashing (`ENTITY-CBOR-ENCODING.md`) |
| ABI | This C Application Binary Interface — the contract all implementations conform to |
| Implementation / impl | A library that conforms to this ABI (`entity-core-codec-ffi-rust`, `…-c`, …) |
| Arena | A caller-owned region holding decoded-entity bodies across calls (§5, §4.1) |
| Reference impl | The hand-written Go / Rust / Python peers, used as conformance oracles |

---

## 2. Architecture: one ABI, many implementations

```
                    ENTITY-CODEC-C-ABI-V1.md   (this spec — canonical)
                    entitycore_codec.h         (machine-readable face)
                              │ conform to
            ┌─────────────────┼─────────────────┐
   entity-core-codec-ffi-rust │   entity-core-codec-ffi-c   │  (future impls)
   (ciborium/dalek/sha2)      │   (libcbor/tinycbor +       │
                              │    libsodium/monocypher)    │
            └─────────────────┴─────────────────┘
                              │ all build →
                  libentitycore_codec.{so,dylib,dll}   (same name, same header)
                              │ consumed by
        entity-core-protocol-<lang> peers + native-codec cross-check
```

**The spec is canonical; implementations conform or they are wrong (keystone standard S5).** No implementation owns the contract. Architecture/keystone owns the spec; the generator (eventually) emits the implementations from it — they are leaf outputs of a language-agnostic spec, exactly as `entity-core-protocol-<lang>` peers are.

### 2.1 Interchangeability (the drop-in property)

All conforming implementations:

- export the **same symbols** (§4) with the **same semantics**,
- ship the **same C header** (`entitycore_codec.h`),
- build to the **same artifact name** — `libentitycore_codec.so` / `.dylib` / `.dll` — with **no `-rust` / `-c` suffix**. A consumer swaps the binary without recompiling or re-binding.

**Implementations differ only in binary, not in interface or output.** Binaries are obviously not byte-identical to each other; their *codec output* MUST be (§10). Provenance (which impl, which version, which spec version) is carried in **build/version metadata**, queryable at runtime via §4.6 — never in the filename.

### 2.2 Implementation independence + cross-feeding

Implementations are developed **independently** (neither anchors to the other's bugs) but **cross-feed**: a divergence surfaced in one is a candidate bug in the other and a candidate ambiguity in this spec (S3). Sequencing is not strictly parallel and order is not prescribed; both MUST pass §10 against the same vector corpus.

---

## 3. Canonical-enforcement obligations (NON-NEGOTIABLE)

Every implementation MUST enforce the following regardless of which underlying CBOR/crypto library it links. **A library dependency MAY provide primitives; it MUST NOT be trusted for the canonical guarantees.** These mirror conformance-invariants N1–N4 (`research/diagnostics/conformance-invariants.md`).

### 3.1 (N1) Format-code framing is LEB128 varint, not a fixed byte

Hash format codes (V7 §1.2), peer-id `key_type`/`hash_type` (V7 §1.5), and multicodec framing (V7 §7.3) MUST be encoded/decoded as LEB128 varints via the §4.1 primitives — **not** as a hard-coded single byte. Currently allocated codes (`0x00`/`0x01`/`0x02`) are < `0x80` and encode identically today; a fixed-width impl breaks silently at the first code ≥ `0x80`. Conformance includes a synthetic ≥`0x80` vector.

### 3.2 (N2) Tag rejection requires an explicit recursive scanner

The decode path MUST reject any CBOR **major-type-6** item appearing anywhere in a `data` field, at any nesting depth, returning `EC_DECODE_ERROR` (the peer surfaces `400 non_canonical_ecf`). Implementations MUST NOT rely on library defaults (which commonly accept/strip/interpret tags) and MUST NOT strip, preserve, or interpret tags. (File marker tag 55799 is never valid on the wire.)

### 3.3 (N3) Empty params/map encodes as the single byte `0xA0`

An empty CBOR map MUST encode as exactly `0xA0`. Serializer "optimizations" (null, omitted field, non-minimal map) are non-conformant. (F5 — RESOLVED: the old Appendix A.1 `empty_map` hash `44136fa3…` was wrong and arch patched it; the empty-data boundary is now pinned by fixture vector `content_hash.1` over `{type:"system/empty", data:{}}` → `005f3139e342…0ca396b`. The `0xA0` encoding requirement was always correct and is unaffected. See `SPEC-FINDINGS-LOG.md` F5.)

### 3.4 (N4) Entity fidelity — never re-serialize on forward

Per V7 §1.8, after a hash is validated the original bytes MUST be forwarded, never a re-encode of the decoded structure. The decode surface MUST therefore hand the caller the **exact original wire bytes** alongside the decoded view (§4.1, resolved as option (a)).

### 3.5 Shortest-float minimization

Per RFC 8949 §4.2 Rule 4 + ECF Rule 4a, floats MUST encode to the shortest precision that round-trips, with exact f16 encodings for specials: NaN `F9 7E00`, −0 `F9 8000`, +Inf `F9 7C00`, −Inf `F9 FC00`. No surveyed library does this automatically; the implementation owns it. Conformance pins `1.0`, `1.5`, `32768.0` (`F9 7800`), `65504.0` (`F9 7BFF`), NaN, ±Inf, ±0.

### 3.6 Canonical map-key ordering

Map keys MUST be sorted by **encoded length, then bytewise lexicographic** (the CTAP2 canonical rule, RFC 8949 §4.2.1 length-first variant). Conformance pins the `map_keys` category.

---

## 4. Symbol surface

All functions return `int32_t` (§7 error codes) unless noted. All buffers are `(ptr, len)` pairs (§5). The authoritative declarations live in `entitycore_codec.h` (this spec's machine-readable face); the tables below are normative on semantics.

### 4.1 ECF / hash / entity

| Symbol | Signature (abbrev.) | Behavior |
|---|---|---|
| `ec_encode_ecf` | `(type_ptr,type_len, data_ptr,data_len, out_ptr,out_cap, out_len_ptr)` | ECF-encode `{type, data}` to caller buffer; `EC_OUT_OF_SPACE` writes required size to `out_len_ptr`. Enforces §3.5/§3.6. |
| `ec_content_hash` | `(type_ptr,type_len, data_ptr,data_len, out_ptr)` | `content_hash = varint(format_code 0x00) ‖ SHA256(ECF({type,data}))`; writes 33 bytes. |
| `ec_decode_entity` | `(bytes_ptr,len, arena, out_type_ptr,out_type_len, out_data_ptr,out_data_len, out_orig_ptr,out_orig_len)` | Decode entity into `type`+`data` slices in `arena`; **AND (N4, option a)** write `out_orig_ptr`/`out_orig_len` = a borrowed slice of the **exact original input bytes** of the decoded entity (lifetime tied to the caller's `bytes_ptr` buffer per §5 rule 1). Runs the §3.2 tag scanner; rejects with `EC_DECODE_ERROR`. |
| `ec_hash_format_code_encode` | `(code:uint64, out_ptr,out_cap, out_len_ptr)` | LEB128-encode a format code (N1 primitive). |
| `ec_hash_format_code_decode` | `(in_ptr,in_len, out_code:*uint64, out_consumed:*size_t)` | LEB128-decode a format code (N1 primitive). |

A standalone `ec_entity_original_bytes(bytes_ptr,len, out_ptr,out_len_ptr)` MAY be provided as a convenience that validates a single entity and returns its original-byte span; it is OPTIONAL because `ec_decode_entity` already satisfies N4.

#### 4.1a Format-aware content_hash (v1.1)

| Symbol | Signature (abbrev.) | Behavior |
|---|---|---|
| `ec_content_hash_with_format` | `(type_ptr,type_len, data_ptr,data_len, format_code:uint64, out_ptr,out_cap, out_len_ptr)` | `varint(format_code) ‖ DIGEST_format(ECF({type,data}))`. **Supported codes (V7 §1.2 seed table): `0x00` → SHA-256 (33 B), `0x01` → SHA-384 (49 B).** Variable-length output honors the `EC_OUT_OF_SPACE` protocol. **Any unsupported code → `EC_DECODE_ERROR`** (`unsupported_content_hash_format`); this is an *interpretation* error per V7 §1.2 (v7.68), not a routing miss. `ec_content_hash` (§4.1) is the `0x00` SHA-256 convenience alias. |
| `ec_encode_bare_value` | `(in_ptr,in_len, out_ptr,out_cap, out_len_ptr)` | **Test-only (not a protocol surface).** Decodes one canonical ECF value and re-encodes it through the bare canonical encoder, making the Class-A encoder core reachable across the ABI for the cross-impl differential (closes finding F6). Canonical CBOR in → canonical CBOR out (identity for canonical input). |

### 4.2 Peer ID

| Symbol | Behavior |
|---|---|
| `ec_peerid_parse` | Parse `Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)` → key_type, hash_type, digest (V7 §1.5). Bitcoin alphabet. |
| `ec_peerid_format` | Format the above to a Base58 string into the caller buffer. |

### 4.3 Crypto

| Symbol | Behavior |
|---|---|
| `ec_ed25519_keygen` | Writes 32-byte priv + 32-byte pub. |
| `ec_ed25519_sign` | Signs message; writes 64-byte signature. |
| `ec_ed25519_verify` | `EC_OK` if valid; `EC_SIGNATURE_INVALID` otherwise. |
| `ec_sha256` | SHA-256; writes 32 bytes. |

#### 4.3a Crypto agility (v1.1) — per-algorithm symbols (decision G2)

**Decision G2 — Option A (per-algorithm symbols), ratified.** The agility surface adds one symbol per algorithm rather than a generic `ec_hash(code,…)` / `ec_sign(key_type,…)` dispatcher. Rationale, grounded in this spec: the v1.0 crypto surface is *already* per-algorithm (`ec_ed25519_*`, `ec_sha256`), while only the §3.1/N1 **framing** layer is generic (LEB128 codes round-trip arbitrary `key_type`/`hash_type`/`format_code`). Option A extends the established pattern, keeps each symbol simple/auditable, keeps the cross-impl differential legible (one symbol = one algorithm), and lets new algorithms land as **validated-not-required** exports without disturbing the Ed25519+SHA-256 conformance floor. The seed-table switch stays at the call site, not inside the library.

| Symbol | Behavior |
|---|---|
| `ec_sha384` | SHA-384 (content_hash_format `0x01` digest); writes 48 bytes. |
| `ec_ed448_keygen` | Writes 57-byte priv (seed) + 57-byte pub (RFC 8032 Ed448, key_type `0x02`). |
| `ec_ed448_seed_to_pubkey` | Derive the 57-byte public key from a 57-byte seed. |
| `ec_ed448_sign` | Ed448 pure (no context) sign; writes the 114-byte signature. |
| `ec_ed448_verify` | `EC_OK` if valid; `EC_SIGNATURE_INVALID` otherwise. |

**Conformance status (v1.1).** Ed25519 + SHA-256 + SHA-384 are the implemented floor across conforming impls. **Ed448 is validated-not-required:** an implementation MAY return `EC_INTERNAL_ERROR` for the `ec_ed448_*` symbols if it has not yet bound an Ed448 provider (libsodium has none), declaring so via `ec_impl_info`. The reference Rust impl (`ed448-goldilocks`) carries Ed448 today; the C impl defers it pending a crypto-library decision (S6/S11) and the regeneration of the v7.67 agility corpus (finding F16). Phase-3a/3b families (BLAKE3, ML-DSA) are out of scope here (v7.67 §13.7).

### 4.4 Envelope verification

| Symbol | Behavior |
|---|---|
| `ec_envelope_verify_root_hash` | Decode envelope; verify `root.content_hash` matches the encoded root entity. |
| `ec_envelope_find_signature_for` | Scan `included` for a `system/signature` entity with `data.target == target_hash`; return its bytes. |

### 4.5 Arena management

| Symbol | Behavior |
|---|---|
| `ec_arena_new` | `() → ec_arena_t*` — allocate a caller-owned arena for decoded entity bodies. |
| `ec_arena_reset` | Free all allocations within; keep the arena. |
| `ec_arena_free` | Free the arena entirely. |

### 4.6 Introspection (provenance, since the artifact name is shared)

| Symbol | Behavior |
|---|---|
| `ec_abi_version` | `() → const char*` — this ABI spec version (e.g. `"1.0"`). All conforming impls return the same value for a given ABI revision. |
| `ec_impl_info` | `() → const char*` — implementation provenance string: impl id (`"rust"`/`"c"`), impl version, conformed spec-data version (e.g. `"rust 0.1.0 / ecf-c-abi 1.0 / spec-data v7.56"`). This is how consumers tell which library they linked — not the filename. |

---

## 5. Lifetime + memory rules (the FFI ergonomic discipline)

1. **All inputs are borrowed.** The callee does not retain input pointers past return. (N4 original-byte slices from `ec_decode_entity` are borrowed from the caller's input buffer and are valid only as long as it is.)
2. **All output buffers are caller-allocated.** On `EC_OUT_OF_SPACE` the callee writes the required size to `out_len_ptr` so the caller can grow and retry. No callee-side `malloc` for outputs.
3. **Decoded entity bodies live in an `ec_arena_t`** — the only deviation from rule 2, because CBOR decode produces variable-size nested structures needing a stable region. Caller creates, decode writes, caller resets/frees.
4. **Strings are not null-terminated.** Always `(ptr, len)`. (Exception: the `const char*` introspection strings in §4.6, which are static and null-terminated.)
5. **No callbacks in v1.** No async, no state held across calls beyond the caller-managed arena. Callbacks, if ever needed, are v2 with copy-before-return semantics.
6. **Panics/aborts MUST NOT cross the boundary.** Any internal fault is caught and returned as `EC_INTERNAL_ERROR`; the process is left in a defined state.

---

## 6. Error codes

```
EC_OK                0    success
EC_INVALID_ARGUMENT -1    null pointer where required, length mismatch
EC_OUT_OF_SPACE     -2    out buffer too small; required size written to out_len_ptr
EC_DECODE_ERROR     -3    CBOR malformed OR non-canonical (tag present, §3.2)
EC_ENCODE_ERROR     -4    input invalid for canonical encoding
EC_HASH_MISMATCH    -5    envelope verify: declared hash != computed
EC_SIGNATURE_INVALID -6   Ed25519 verify failed
EC_KEY_INVALID      -7    Ed25519 key format error
EC_PEERID_INVALID   -8    Base58 decode failed or length wrong
EC_ARENA_EXHAUSTED  -9    decoded data exceeds arena capacity
EC_INTERNAL_ERROR   -99   caught internal fault (§5 rule 6); SHOULD never fire in v1
```

All implementations MUST use identical numeric values (a consumer's error handling is impl-independent).

---

## 7. Library output requirements

Every implementation, on every platform, MUST produce:

1. **A self-contained shared library** — `libentitycore_codec.so` (Linux), `libentitycore_codec.dylib` (macOS), `entitycore_codec.dll` (Windows). All third-party dependencies (CBOR, crypto) **statically linked in**. The consumer needs no runtime dependency hunt: drop the file in, link, run.
2. **A static library** — `.a` (Unix) / `.lib` (Windows) — for consumers that prefer static linking end-to-end.
3. **The shared header** — identical `entitycore_codec.h` across impls.

Dynamic linkage to third-party CBOR/crypto libraries in the shipped artifact is non-conformant; system C runtime + OS crypto-primitive libraries are the only permitted external dynamic dependencies, and only where unavoidable per platform.

### 7.1 Build matrix (minimum for v1)

| Platform | Target | Artifact |
|---|---|---|
| Linux x86_64 | `x86_64-unknown-linux-gnu` / native | `libentitycore_codec.so` |
| Linux aarch64 | `aarch64-unknown-linux-gnu` / native | `libentitycore_codec.so` |
| macOS arm64 | `aarch64-apple-darwin` / native | `libentitycore_codec.dylib` |

macOS x86_64 and Windows x86_64 are v1 nice-to-have. WASM is a future shape (`ffi-generator/wasm-abi/`), not this spec.

---

## 8. Build + supply-chain discipline (keystone S1 + supply-chain pin rule)

These are hard requirements on *how* implementations are built, not just what they output.

1. **Containers only (S1).** Every build/test/conformance run happens in a `containers/<toolchain>/` Podman image (fedora:43 base). **No host installs, no host filesystem writes outside the working tree's `output/`.** Nothing is grabbed or installed locally.
2. **Pin everything.** Every dependency — base image, language toolchain, every crate / C library / system package — is **version-pinned** (no floating ranges, no `latest`). Lockfiles committed.
3. **30-day cool-down pin.** Every pinned version MUST be **at least 30 days old** at pin time. This is the supply-chain mitigation we can apply without per-dependency review: a freshly-compromised release is most often caught and yanked within its first weeks, so a 30-day-old pin dodges the common attack window. It does not catch everything; it is the floor, applied uniformly. When a CVE forces a newer version, that is an explicit, logged exception.
4. **Re-pin deliberately.** Version bumps are intentional and reviewed, re-applying the 30-day rule — never incidental drift.

---

## 9. Versioning

- **ABI version** (`ec_abi_version`) tracks this spec. Additive symbol additions bump the minor; any change to an existing symbol's semantics or signature, or any error-code change, bumps the major and is a new spec document (`ENTITY-CODEC-C-ABI-V2.md`).
- **Impl version** (in `ec_impl_info`) is per-implementation and independent of the ABI version.
- **Spec-data binding.** Each impl declares the `spec-data/<version>/` it conforms to (e.g. `v7.56`) in `ec_impl_info` and its `MANIFEST.md`.

---

## 10. Conformance (the normative contract)

An implementation is conformant iff **all** hold:

1. **Surface.** Exports every §4 symbol with §5/§6 semantics; `entitycore_codec.h` matches.
2. **Byte-identical output.** For every vector in `protocol-generator/shared/test-vectors/v0.8.0/`, `ec_encode_ecf` / `ec_content_hash` produce **byte-identical output** to the Go, Rust, and Python reference encoders, and reject every non-canonical vector (§3.2/§3.3).
3. **Functional equivalence.** Decode (incl. N4 original bytes), peer-id round-trip, Ed25519, SHA-256, and envelope verification behave identically to the references on the vector corpus.
4. **Invariants.** N1 (synthetic ≥`0x80` varint), N2 (`tag_reject`), N3 (`0xA0`), N4 (original-byte fidelity), §3.5 (float specials), §3.6 (`map_keys`) all pass.
5. **Output requirements.** §7 artifacts build under §8 discipline.

### 10.1 The differential matrix

Conformance is measured by a shared harness (`ffi-generator/c-abi/conformance/`) that `dlopen`s **any** conforming `libentitycore_codec.*`, runs the corpus, and cross-checks every output against the three reference impls. With both FFI impls present this is a **5-way agreement** (Go · Rust · Python · rust-ffi · c-ffi). Any pairwise disagreement localizes the bug; a unanimous disagreement against an impl indicts that impl; a disagreement that splits the references indicts the **spec** and is logged as an ambiguity (S3). **No green differential → no publish (S7).**

> NOTE: The reference-impl corpus is generated from `entity-core-go/core/ecf/ecf.go` until the spec's own Appendix E fixture is committed (finding F1). The Go encoder is the interim source of truth for byte-identity.

---

## 11. Deferred to v2 (out of scope)

- Async + streaming (needs callbacks)
- Capability-chain validation (peer machinery, N8)
- Wire framing / length-prefixing (peer machinery)
- Connection management (peer machinery)
- `included`-preservation policy across dispatch surfaces (peer machinery, N5)
- Inspect taps across FFI

A consuming language needing these implements them natively above the codec. That is the point of the hybrid split (§1.1): the codec is the small, perf-critical, cross-language-correctness surface; everything else is native.

---

## Lineage

This spec promotes and supersedes the architecture-authored `ffi-generator/c-abi/arch/DESIGN-v1.md` (Rust-only, single-impl framing). The contract surface, lifetime rules, and error codes originate there and were reviewed in arch memo `c0513c8`. Changes in this version: (1) the contract is recast as a language-agnostic spec with multiple conforming implementations (Rust **and** C); (2) N1 varint primitives and N4 original-byte fidelity (option a) are folded in as normative; (3) shared artifact name + version-metadata provenance (§2.1, §4.6); (4) static-self-contained output requirement (§7); (5) explicit supply-chain pin discipline (§8); (6) conformance recast as a multi-reference differential (§10). `DESIGN-v1.md` is retained as lineage.

## Cross-references

- ECF / canonical CBOR: `protocol-generator/shared/spec-data/v0.8.0/ENTITY-CBOR-ENCODING.md`
- Core protocol: `…/spec-data/v0.8.0/ENTITY-CORE-PROTOCOL.md`
- Conformance invariants N1–N8: `research/diagnostics/conformance-invariants.md`
- Test vectors: `protocol-generator/shared/test-vectors/v0.8.0/`
- Machine-readable face: `ffi-generator/c-abi/spec/entitycore_codec.h`
- Snapshot manifest: `ffi-generator/c-abi/spec/MANIFEST.md`
- Arch lineage: `ffi-generator/c-abi/arch/DESIGN-v1.md`
