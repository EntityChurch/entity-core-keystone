# ffi-generator/c-abi/

The **C-ABI codec binding shape**: a single language-agnostic C ABI over the ECF codec, with multiple interchangeable implementations.

```
c-abi/
  spec/                          THE canonical contract
    ENTITY-CODEC-C-ABI-V1.md     normative spec (symbols, semantics, conformance)
    entitycore_codec.h           machine-readable header (shipped by every impl)
    MANIFEST.md                  ABI version + spec-data binding + impl registry
  entity-core-codec-ffi-rust/    conforming impl (Rust) — named for eventual repo extraction (S10)
  entity-core-codec-ffi-c/       conforming impl (C)    — named for eventual repo extraction (S10)
  conformance/                   shared harness: dlopen any conforming .so, run vectors, 5-way differential
  status/                        build matrix · conformance reports · DESIGN-NOTES-FROM-REVIEW.md
  arch/                          DESIGN-v1.md — arch-authored lineage (superseded by spec/)
```

## The model

The **spec is canonical; implementations conform or they are wrong** (S5). `entity-core-codec-ffi-rust` and `entity-core-codec-ffi-c` are independent leaf outputs of one spec — like `entity-core-protocol-<lang>` peers, but for a binding shape. They:

- export the same symbols (`entitycore_codec.h`),
- build to the same artifact name `libentitycore_codec.{so,dylib,dll}` (no `-rust`/`-c` suffix — drop-in interchangeable; provenance via `ec_impl_info()`),
- must produce **byte-identical codec output**, cross-checked against the Go/Rust/Python reference impls.

The binaries are not byte-identical (impossible, different toolchains); the *output* is. See spec §2.1, §10.

## Why two impls

Confidence by redundancy + reach. Two independent readings of the spec that must agree to the byte = a 5-way agreement matrix (Go · Rust · Python · rust-ffi · c-ffi); any disagreement localizes a bug or indicts the spec (S3). C gives the widest platform/embedded reach with no Rust toolchain; Rust reuses audited crates. We may publish one, the other, or both.

## Build sequence (per impl)

The impls don't run the S1–S5 peer pipeline. They follow this sequence — build it and see what breaks:

1. The spec (`spec/`) is canonical.
2. Implement against it in `entity-core-codec-ffi-{rust,c}/src/` (stacks decided in `research/evaluations/ffi-{rust,c}.md`).
3. (rust) `cbindgen` diff-check the generated header against `spec/entitycore_codec.h`.
4. Run the `conformance/` differential (5-way byte-identity vs Go/Rust/Py).
5. Iterate on whatever the differential breaks on.
6. Publish — operator decision, no auto-publish.

All under Podman, deps pinned ≥30 days old (S1/S11).

## Build + supply-chain (S1 + pin rule)

Podman/Containerfiles only — no host installs, nothing grabbed locally. Every dependency pinned, and pinned to a version **≥ 30 days old** (supply-chain cool-down; spec §8). Output is a **self-contained statically-linked** library — no runtime dependency hunt for consumers (spec §7).

## Status

- ✅ `spec/` — canonical ABI spec + header + manifest landed (this pass)
- ⏳ `entity-core-codec-ffi-rust/src/` — implementation
- ⏳ `entity-core-codec-ffi-c/src/` — implementation
- ⏳ `conformance/` — differential harness
- ⏳ build matrix · conformance reports
