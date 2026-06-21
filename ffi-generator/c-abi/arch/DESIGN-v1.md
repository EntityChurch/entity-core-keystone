# `entity-core-codec-ffi` — Design v1

> **⚠ SUPERSEDED — lineage only.** This arch-authored, Rust-only, single-impl design has been promoted into the language-agnostic, multi-implementation **`../spec/ENTITY-CODEC-C-ABI-V1.md`** (the canonical contract). The contract surface, lifetime rules, and error codes here originate this lineage and were reviewed in arch memo `c0513c8`. Read the spec for current truth; this doc is retained for history. Paths below referencing `ffi-generator/rust-c-abi/…` predate the rename to `ffi-generator/c-abi/`.

**Status:** Design — architecture-authored. **Superseded by `../spec/ENTITY-CODEC-C-ABI-V1.md`.**
**Owner:** Architecture initially. Migration: once protocol-generator is solid, regenerate from spec (target=Rust, profile=ffi-codec-only). Closes the dogfood loop.

## What this is

A standalone Rust crate exporting the ECF codec primitives via C ABI. Consumed by:
- Languages with poor canonical-CBOR or Ed25519 library support (via FFI / P/Invoke / N-API / cffi / etc.)
- Native-codec languages for **bit-identical conformance cross-check** (if your native output disagrees with this on a vector, your native is wrong)
- Eventually: future browser WASM target (`ffi-generator/rust-wasm/`), serving the CDN-corridor browser-peer story

**Crate name:** `entity-core-codec-ffi`
**Artifact names:** `libentitycore_codec.so` (Linux), `libentitycore_codec.dylib` (macOS), `entitycore_codec.dll` (Windows)
**Underlying Rust dependencies:** `ciborium` (canonical CBOR), `ed25519-dalek` (Ed25519), `sha2` (SHA-256)

## Scope: what gets exported

Pure functions only. **No callbacks. No async. No state held across calls beyond what the caller manages explicitly.** This is the discipline that keeps FFI ergonomic.

### Hash + entity

| Symbol | Signature | Behavior |
|---|---|---|
| `ec_encode_ecf` | `(type_ptr, type_len, data_ptr, data_len, out_ptr, out_cap, out_len_ptr) → int32_t` | ECF-encode `{type, data}` (CBOR); write to caller-allocated buffer; return 0 on success, negative error code on failure |
| `ec_content_hash` | `(type_ptr, type_len, data_ptr, data_len, out_ptr) → int32_t` | Compute content_hash = format_code(0x00) ‖ SHA256(ECF({type, data})); writes 33 bytes |
| `ec_decode_entity` | `(bytes_ptr, len, type_out_ptr, type_len_ptr, data_out_ptr, data_len_ptr) → int32_t` | Decode CBOR-encoded entity into type + data slices; out pointers reference internal arena (see lifetime rules) |

### Peer ID

| Symbol | Signature | Behavior |
|---|---|---|
| `ec_peerid_parse` | `(base58_ptr, base58_len, out_key_type_ptr, out_hash_type_ptr, out_digest_ptr, out_digest_len_ptr) → int32_t` | Parse Base58(key_type ‖ hash_type ‖ digest); 0 = ok |
| `ec_peerid_format` | `(key_type, hash_type, digest_ptr, digest_len, out_ptr, out_cap, out_len_ptr) → int32_t` | Format peer-id as Base58 string; 0 = ok |

### Crypto

| Symbol | Signature | Behavior |
|---|---|---|
| `ec_ed25519_keygen` | `(out_priv_ptr, out_pub_ptr) → int32_t` | Generate keypair; writes 32 priv + 32 pub bytes |
| `ec_ed25519_sign` | `(priv_ptr, msg_ptr, msg_len, out_sig_ptr) → int32_t` | Sign 64 bytes |
| `ec_ed25519_verify` | `(pub_ptr, msg_ptr, msg_len, sig_ptr) → int32_t` | 0 = valid, negative = invalid/error |
| `ec_sha256` | `(data_ptr, data_len, out_ptr) → int32_t` | SHA-256; writes 32 bytes |

### Envelope verification

| Symbol | Signature | Behavior |
|---|---|---|
| `ec_envelope_verify_root_hash` | `(envelope_bytes_ptr, envelope_bytes_len) → int32_t` | Decode envelope; verify root.content_hash matches the encoded root entity; 0 = ok |
| `ec_envelope_find_signature_for` | `(envelope_bytes_ptr, envelope_bytes_len, target_hash_ptr, out_signature_entity_ptr, out_len_ptr) → int32_t` | Scan `included` for `system/signature` entity with `data.target == target_hash`; return entity bytes |

### Arena management

| Symbol | Signature | Behavior |
|---|---|---|
| `ec_arena_new` | `() → ec_arena_t*` | Allocate a new arena for decoded entities (caller-owned) |
| `ec_arena_reset` | `(arena) → void` | Free all allocations in arena |
| `ec_arena_free` | `(arena) → void` | Free arena entirely |

## Lifetime + memory rules (the FFI ergonomic discipline)

1. **All inputs are borrowed.** Caller's buffers; callee does not retain pointers past return.
2. **All output buffers are caller-allocated.** Callee writes into them; returns required size on `OUT_OF_SPACE` so caller can grow + retry. No callee-side `malloc` for outputs.
3. **Decoded entity bodies live in an `ec_arena_t`** — caller creates the arena, decode functions write into it, caller resets/frees. This is the only deviation from rule 2; it exists because CBOR decode produces variable-size nested structures that need a stable region.
4. **Strings are not null-terminated.** Always `(ptr, len)` pairs.
5. **No callbacks v1.** Eliminates the worst FFI ergonomics. If we ever need callbacks (e.g. for streaming inspect output across FFI), they go in v2 with strict copy-before-return semantics.

## Error codes

```
0       OK
-1      INVALID_ARGUMENT  (null pointer where required, length mismatch)
-2      OUT_OF_SPACE       (out buffer too small; out_len_ptr written with required size)
-3      DECODE_ERROR       (CBOR malformed)
-4      ENCODE_ERROR       (input invalid for canonical encoding)
-5      HASH_MISMATCH       (envelope verification: declared hash != computed)
-6      SIGNATURE_INVALID   (Ed25519 verify failed)
-7      KEY_INVALID         (Ed25519 key format error)
-8      PEERID_INVALID      (Base58 decode failed or length wrong)
-9      ARENA_EXHAUSTED     (decoded data exceeds arena's pre-allocated capacity)
-99     INTERNAL_ERROR      (panic in Rust caught at FFI boundary; should never fire in v1)
```

## Build matrix

| Platform | Target triple | Output artifact |
|---|---|---|
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `libentitycore_codec.so` |
| Linux aarch64 | `aarch64-unknown-linux-gnu` | `libentitycore_codec.so` |
| macOS x86_64 | `x86_64-apple-darwin` | `libentitycore_codec.dylib` |
| macOS arm64 | `aarch64-apple-darwin` | `libentitycore_codec.dylib` |
| Windows x86_64 | `x86_64-pc-windows-gnu` | `entitycore_codec.dll` |
| WASM | `wasm32-unknown-unknown` | (future — `ffi-generator/rust-wasm/`) |

Built via `containers/cargo/Containerfile` (operators set up).

## C header

Generated via `cbindgen` from the Rust source. Header lives at `ffi-generator/rust-c-abi/output/include/entitycore_codec.h`. Caller-language profiles reference it for FFI declarations.

## Conformance test

Pure-codec round-trip against `entity-core-go/cmd/internal/wire-conformance` test vectors. Required green before any consuming language enters S2.

## What's deferred to v2

- Async + streaming (would need callbacks)
- Capability chain validation (out of codec scope; lives in peer machinery, not codec)
- Wire framing (out of codec scope; lives in peer machinery)
- Connection management (out of codec scope)
- Inspect taps across FFI

If a consuming language needs these, it implements them natively above the codec layer. That's the point of the hybrid split — codec is the small, perf-critical, cross-language-correctness surface; everything else is native.

## v1 acceptance criteria

- All exports above implemented + tested in pure Rust
- C header generated cleanly
- Build matrix: Linux x86_64 + Linux aarch64 + macOS arm64 at minimum (Windows + macOS x86_64 nice-to-have for v1)
- Conformance against `wire-conformance` test vectors: 100% pass
- `bridge_smoke.c`-style test runner exercises every export end-to-end
