# Entity Codec C-ABI spec — Manifest

**ABI version:** 1.1
**Conforms-to spec-data:** `protocol-generator/shared/spec-data/v0.8.0/` (Entity Core Protocol 0.8.0, ECF 1.5 — byte-unchanged since the V7 line)

## What this is

The canonical, language-agnostic contract for the Entity codec C ABI. Keystone-authored (it is **not** part of the V7 core protocol — V7 defines ECF; this defines a C-ABI surface over it). Implementations conform to it; it does not conform to any implementation.

## Files

| File | Role |
|---|---|
| `ENTITY-CODEC-C-ABI-V1.md` | Normative spec — symbols, semantics, lifetimes, error codes, canonical obligations, conformance |
| `entitycore_codec.h` | Machine-readable header — the C face of the spec; shipped unchanged by every impl |
| `MANIFEST.md` | This file |

## Conforming implementations

| Impl | Location | Stack | Status (ABI 1.1 / spec-data v7.71) |
|---|---|---|---|
| `entity-core-codec-ffi-rust` | `ffi-generator/c-abi/entity-core-codec-ffi-rust/` | hand-written ECF encoder + hand-rolled decoder · `ed25519-dalek` 2.2.0 · `sha2` 0.10.9 (SHA-256 + SHA-384) · `bs58` 0.5.1 · `ed448-goldilocks` 0.14.0-pre.13 + `ed448` 0.5.0 · `rand` 0.8.5 | **Full v1.1.** Exports 26/27 (`ec_entity_original_bytes` absent — spec §4.1 OPTIONAL). **Carries Ed448.** **No independent corpus harness in-tree**: verified only by the cross-impl differential, which is a mutual check. Needs the network to build (no vendored crate closure). |
| `entity-core-codec-ffi-c` | `ffi-generator/c-abi/entity-core-codec-ffi-c/` | hand-rolled CBOR + Base58 · `libsodium` 1.0.22 (SHA-256 + Ed25519) · hand-rolled SHA-384 · vendored OpenSSL 3.3.2 curve448 + SHAKE256 for Ed448 · CMake/C11 | **Full v1.1.** Exports 27/27. ECF corpus **71/71**, `regression_test` **12/12**. **Carries Ed448** (vendored curve448, not libsodium — the earlier "Ed448 deferred" note is withdrawn; the differential drives ed448 sign/verify on both impls). |

Both build `libentitycore_codec.{so,dylib,dll}` (same name) + static lib + this header. Interchangeable per spec §2.1; **cross-validated 101/101 probes** through the real ABI boundary (`conformance/abi_differential.c`, dlmopen C↔Rust), Ed448 included.

**Read that count precisely: 101 is a count of PROBES over the 19 of 27 spec-declared symbols the differential drives** — not a statement about the other 8. The differential now prints both figures, plus any export asymmetry between the two impls, because a green run over an unstated surface is how `ec_entity_original_bytes` stayed invisible: exported by C, absent from Rust, and never driven. Run `ffi-generator/c-abi/run-ffi-gate.sh` for the current numbers.

## Conformance source of truth

Byte-identity is measured against the Go/Rust/Python reference encoders via `ffi-generator/c-abi/conformance/`. Until the spec's Appendix E fixture is committed (finding F1, `research/stewardship/SPEC-FINDINGS-LOG.md`), `entity-core-go/core/ecf/ecf.go` is the interim source of truth.

## Lineage

Promotes `ffi-generator/c-abi/arch/DESIGN-v1.md` (arch-authored, reviewed in memo `c0513c8`). See the "Lineage" section of the spec for the delta.

## Immutability

Treat a stamped ABI version like spec-data: additive changes bump the minor in place during draft; a breaking change creates `ENTITY-CODEC-C-ABI-V2.md`. The `(spec-version, ABI-version)` pair is the reproducibility coordinate for conformance.
