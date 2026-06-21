# ffi-generator/

FFI binding generation. Sibling concern to `protocol-generator/`, not subordinate.

## Children (by binding *shape*)

- **`c-abi/`** — the C-ABI codec shape. A single language-agnostic contract (`c-abi/spec/ENTITY-CODEC-C-ABI-V1.md` + `entitycore_codec.h`) with multiple interchangeable conforming implementations: `entity-core-codec-ffi-rust` and `entity-core-codec-ffi-c` (more possible). All build the same `libentitycore_codec.{so,dylib,dll}`, consumed by FFI-strategy language profiles and by native-codec profiles for byte-identical cross-check. See `c-abi/README.md`.
- **(future) `wasm-abi/`** — Rust codec compiled to WebAssembly for browser peers. Overlaps with CDN-corridor browser-peer work in `entity-core-architecture`.
- **(future) other binding shapes as needed.**

A *shape* is a binding target (C ABI, WASM, …). Each shape owns its spec + conformance + one-or-more implementations underneath. Implementations are leaf outputs of the shape's spec, the same spec→output relationship `protocol-generator/` has with language peers.

## Why parallel to `protocol-generator/`, not nested

Different output families: protocol-generator emits native peer code per language; ffi-generator emits binding crates per binding shape × output target. They share `protocol-generator/shared/spec-data/` at the input layer, but their workflows are independent.

## Status

`c-abi/` is the first shape. **Canonical spec landed** (`c-abi/spec/ENTITY-CODEC-C-ABI-V1.md` + `entitycore_codec.h`); the two implementations (`entity-core-codec-ffi-{rust,c}`) are not-started (operators). Lineage: arch's `c-abi/arch/DESIGN-v1.md`, now superseded by the spec.
