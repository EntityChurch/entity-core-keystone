# entity-core-codec-ffi-rust

A **conforming implementation** of the Entity Codec C-ABI (`../spec/ENTITY-CODEC-C-ABI-V1.md`), in Rust.

Named as a future standalone repo (S10) — it lifts out of the keystone tree cleanly if/when extraction is warranted.

## Conforms to

`../spec/ENTITY-CODEC-C-ABI-V1.md` (ABI 1.0) over `spec-data/v0.8.0`. Ships the spec's `entitycore_codec.h` unchanged. Builds `libentitycore_codec.{so,dylib,dll}` + static lib — **same artifact name** as the C impl (interchangeable; provenance via `ec_impl_info()`).

## Stack (decided — see `research/evaluations/ffi-rust.md`)

- **CBOR: hand-write the ECF encoder; `minicbor` 2.2.1 as a decode tokenizer only.** No CBOR crate is trusted for canonicality — sort, shortest-float, tag-reject, and raw-byte fidelity are enforced in this crate (spec §3). minicbor reads/validates; encode is ours.
- **Ed25519:** `ed25519-dalek` 2.2.0 (NOT 3.0 rc) + `rand_core` 0.6.4 (`OsRng`, not `ThreadRng`); transitive `curve25519-dalek` ≥ 4.1.3.
- **SHA-256:** `sha2` 0.10.9 (stay off the new/breaking 0.11).
- **Base58:** `bs58` 0.5.1 (Bitcoin alphabet default).
- **float16:** `half` 2.4.x.
- **Header:** `cbindgen` 0.29.2 as a **CI diff-check** against the canonical `../spec/entitycore_codec.h` — not the source of truth.

All pins ≥ 30 days old (re-check at impl time, S11). `crate-type = ["cdylib","staticlib"]`, statically self-contained (spec §7). **catch_unwind at every FFI boundary** → int error code, never abort the host. Build the shipped `.so` on an old-glibc base; macOS arm64 needs a macOS runner.

## Build + run the harness (container, from repo root)

```
# 1. build the pinned cargo image (once)
podman build --memory=4g --memory-swap=4g -t entity-core-keystone/cargo:latest -f containers/cargo/Containerfile containers/cargo
podman volume create kc-cargo            # persistent crate cache across runs

# 2. compile: libentitycore_codec.{so,a} + the conformance-harness bin
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm -v "$PWD":/work:Z -v kc-cargo:/cargo entity-core-keystone/cargo:latest \
  sh -c "cd /work/ffi-generator/c-abi/entity-core-codec-ffi-rust && cargo build --release"

# 3. run the first-pass harness against the vendored fixture
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm -v "$PWD":/work:Z -v kc-cargo:/cargo entity-core-keystone/cargo:latest \
  sh -c "cd /work/ffi-generator/c-abi/entity-core-codec-ffi-rust && \
    ./target/release/conformance_harness \
    /work/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"
```

Artifacts land in `target/release/` (gitignored): `libentitycore_codec.so` (608K, deps
statically linked — `ldd` shows only libc/libgcc_s/ld-linux, satisfying §7) + `.a`.

## Status — first pass GREEN

**`conformance_harness`: 69/69 byte-identical to the vendored cross-blessed fixture.**
All categories pass: float·int·length·map_keys·primitive·nested·envelope (bare encoder),
content_hash (incl. the F5-corrected empty-entity hash `005f3139e3…`), peer_id (incl. N1
varint `key_type=128`), signature (deterministic Ed25519), tag_reject (N2). The corpus has
69 byte-vectors; the LOCK report's "71" adds 2 cross-impl metadata checks (N/A to one impl).

### First-pass scope / not-yet-done (next session)

- **Decoder is hand-rolled** (`src/decode.rs`); ffi-rust.md's decided stack wires `minicbor`
  2.2.1 as the tokenizer/validator. The hand-written *encoder* (the load-bearing decision)
  is final. Wire minicbor for the production decode/N4 path.
- **Stubbed exports** (no vector drives them yet, return `EC_INTERNAL_ERROR`): `ec_ed25519_keygen`
  (needs `OsRng`/rand_core 0.6, R2), `ec_envelope_verify_root_hash`, `ec_envelope_find_signature_for`.
- **Arena trio** (`ec_arena_new/reset/free`) not yet defined — full N4 arena decode is first-pass scope.
- **Harness links the crate (rlib), not `dlopen`.** The impl-agnostic 5-way `dlopen` harness in
  `../conformance/` is the next step, and it surfaces **finding F6** (`SPEC-FINDINGS-LOG.md`):
  the bare encoder core isn't reachable through the entity-shaped ABI.

See `../status/DESIGN-NOTES-FROM-REVIEW.md` for the N1–N4 design-time notes.
