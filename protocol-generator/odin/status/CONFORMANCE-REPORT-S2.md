# entity-core-protocol-odin — S2 Conformance Report

**Date:** 2026-07-12
**Phase:** S2 (codec)
**Peer:** `entity-core-protocol-odin` (corroboration / generator-robustness, T3)
**Odin:** `dev-2026-06:285f6d8` (pinned container `entity-core-keystone/odin-toolchain:latest`)
**Gate:** `odin test test` — sealed offline (`--network=none`), leak-checked under `mem.Tracking_Allocator`.

## Result: 71 · 0F  (71/71 PASS, 0 fail, 0 skip)

- **Corpus:** `shared/test-vectors/ecf-conformance/conformance-vectors.cbor`
  SHA-256 `9695b1f1d939cfdfdd4297f8ad32122d424b1ec180cfae74c92d509d88f7c6dc`
  (66 `encode_equal` + 5 `decode_reject` = 71 vectors).
- **Oracle provenance:** vendored byte-identical from arch `entity-core-protocol`
  commit `be54baf`; 3-way Go × Rust × Python cross-blessed (Appendix E.4).
- **Byte-comparison basis:** the corpus is decoded by THIS peer's own hand-rolled
  decoder (a decoder bug is itself a conformance failure, §E.3), then each vector's
  produced bytes are compared bit-for-bit with the pinned `canonical`.

### Per-category breakdown (71/71)

| Category | Pass/Total | Notes |
|---|---|---|
| `float` | 14/14 | Rule 4 f16/f32/f64 ladder + Rule 4a specials (NaN 0x7e00, ±Inf, -0.0, 65503→f32, 1.1→f64) |
| `int` | 14/14 | mt0/mt1 minimal-head at all boundaries incl. 2⁶³-1 (int.10) |
| `map_keys` | 6/6 | length-then-lex over ENCODED key bytes; mixed text+byte keys (map_keys.5) |
| `length` | 8/8 | definite-length only; empty containers; 23/24 boundaries |
| `primitive` | 6/6 | null/true/false single-byte; mixed-primitive maps |
| `nested` | 6/6 | incl. F29 nested.5/.6 array-of-maps inner text-head boundary (minor-24/25) |
| `tag_reject` | 5/5 | §6.3 recursive major-6 reject (tags 0/1/37/55799 + nested-in-included) |
| `content_hash` | 4/4 | varint(fc) ‖ SHA-256(ECF({type,data})); synthetic fc=128 multi-byte varint (content_hash.4) |
| `peer_id` | 3/3 | Base58(varint(kt)‖varint(ht)‖digest) ECF-as-text; synthetic kt=128 (peer_id.3) |
| `signature` | 3/3 | deterministic Ed25519 over canonical ECF; byte-pinned sigs reproduced |
| `envelope` | 2/2 | root+included carrier shape under the same map-key rules |

## Adjacent units (beyond the corpus)

- **Fixed-width u64 head-form self-test `[2⁶³, 2⁶⁴-1]`** — PASS. Encodes 2⁶³, 2⁶³-1,
  2⁶⁴-1, and 2³² through the minor-27 (8-byte-argument) head and round-trips them;
  plus `nint(2⁶⁴-1)` → `3b ffffffffffffffff` (= -2⁶⁴). The band a signed i64 cannot
  hold — the fixed-width-int-class obligation (like Zig/Forth/Fortran).
- **Native Ed25519 KAT accept-path** — PASS. Two independent KATs against the pure-Odin
  `core:crypto/ed25519`:
  1. Corpus signature.1 (all-zero seed) → byte-pinned 64-byte signature reproduced,
     then derive-pubkey → verify accept path (the direction a rejection-only oracle
     can't cover), plus a tampered-byte negative control that MUST NOT verify.
  2. RFC 8032 §7.1 test vector 1 (seed `9d61b19d…`, empty message) → pinned pubkey
     `d75a9801…` and signature `e5564300…` reproduced. This gates the unaudited native
     crypto floor (A-ODIN-004): any RFC-8032 deviation fails loudly.

## Memory / leak discipline

The conformance run executes under `mem.Tracking_Allocator`; after an explicit
free of all codec + harness allocations and `free_all(context.temp_allocator)`,
`len(allocation_map) == 0` and `len(bad_free_array) == 0`. Free-correctness is a
first-class conformance concern on this no-GC substrate (profile [memory]).

## Honest framing (ADR-0012)

This is a **corroboration / generator-robustness** peer, not spec-discovery — the
discovery well is dry on the current wire surface (28+-peer cohort; discovery axes
saturated). A green verdict here is **cohort-consistent, not independent
convergence**: the corpus bytes were authored by a 3-way Go × Rust × Python round,
and this peer reproducing them confirms the generator handles a fresh
syntax/packaging/error-idiom shape (no-exceptions value-return errors, no-GC context
allocators, no package manager) plus a native pure-Odin crypto floor. It does not add
an independent fourth witness to the canonical bytes.

## Reproduce

```
cd protocol-generator/odin && ./run-s2.sh
# or, from repo root:
. tools/podman-caps.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
  -w /work/protocol-generator/odin entity-core-keystone/odin-toolchain:latest sh -c 'odin test test'
```
