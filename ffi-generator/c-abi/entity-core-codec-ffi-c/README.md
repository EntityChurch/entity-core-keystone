# entity-core-codec-ffi-c

A **conforming implementation** of the Entity Codec C-ABI (`../spec/ENTITY-CODEC-C-ABI-V1.md`), in C.

Named as a future standalone repo (S10) — it lifts out of the keystone tree cleanly if/when extraction is warranted.

## Conforms to

`../spec/ENTITY-CODEC-C-ABI-V1.md` (ABI 1.0) over `spec-data/v0.8.0`. Ships the spec's `entitycore_codec.h` unchanged. Builds `libentitycore_codec.{so,dylib,dll}` + static lib — **same artifact name** as the Rust impl (interchangeable; provenance via `ec_impl_info()`).

## Stack (decided — see `research/evaluations/ffi-c.md`)

- **CBOR: hand-roll** (encode + decode, one `ecf.c`). No library — libcbor (DOM/alloc), tinycbor (churn), and QCBOR (determinism is alpha-only) all lose once we hand-enforce sort/shortest-float/tag-reject/raw-byte fidelity (spec §3). The ECF surface is a few hundred lines; decode operates over the input buffer and returns exact slices (N4).
- **SHA-256 + Ed25519:** `libsodium` 1.0.21 (high-level `crypto_sign_*` / `crypto_hash_sha256`). **NOT monocypher** — it has no SHA-256 (confirmed: BLAKE2b + SHA-512 only), which ECF requires. CVE-2025-69277 is in a low-level point validator we don't call.
- **Base58:** hand-roll (~40 lines, Bitcoin alphabet).
- **Build:** CMake + C11, in `containers/c-toolchain/`. libsodium **statically + privately linked** (localize its symbols), `-fvisibility=hidden`, `-fPIC`; one `.a` + one `.so/.dylib/.dll`.

Widest reach: every platform has a C toolchain; this is the impl FFI ecosystems (Zig, Odin, Nim, Lua, OCaml, embedded) link without any Rust toolchain. libsodium pinned ≥ 30 days old (re-check at impl time, S11); statically self-contained (spec §7). Fallback if a no-libc target appears: monocypher + a conformance-pinned public-domain SHA-256 — explicit S6 decision, not the default.

## Layout

- `src/ecf.{h,c}` — hand-written canonical encoder + decoder + LEB128 + the value model (twin of the Rust impl's `value`/`encode`/`decode`). Owns every canonical guarantee (N1–N4, shortest-float, key sort).
- `src/base58.{h,c}` — Bitcoin-alphabet Base58 (hand-rolled long division).
- `src/codec.c` + `src/codec_core.h` — the `ec_*` ABI exports + shared core helpers (`cc_*`), wrapping `ecf.c` + libsodium. Twin of the Rust `lib.rs`.
- `src/conformance_harness.c` — loads the vendored fixture, drives each vector, diffs bytes.
- `src/regression_test.c` — encoder regressions beyond the corpus (F7 uint64 gap, float specials, i64::MIN).
- `include/entitycore_codec.h` — the spec's canonical header, **shipped verbatim** (SHA matches `../spec/entitycore_codec.h`).
- `export.map` — linker version script: exports **only** `ec_*`, localizes everything else (libsodium). See F9: do NOT add `-fvisibility=hidden` (it would zero out the exports with a verbatim header).
- `CMakeLists.txt` — builds `libentitycore_codec.{so,a}` (libsodium static + private), the harness, and the regression test.

## Build + run (container, from repo root)

```sh
# 1. build the pinned c-toolchain image (once)
podman build --memory=4g --memory-swap=4g -t entity-core-keystone/c-toolchain:latest \
  -f containers/c-toolchain/Containerfile containers/c-toolchain

# 2. configure + compile → libentitycore_codec.{so,a} + conformance_harness + regression_test
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm -v "$PWD":/work:Z entity-core-keystone/c-toolchain:latest \
  sh -c "cd /work/ffi-generator/c-abi/entity-core-codec-ffi-c && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"

# 3. run the regression test + first-pass conformance harness
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm -v "$PWD":/work:Z entity-core-keystone/c-toolchain:latest \
  sh -c "cd /work/ffi-generator/c-abi/entity-core-codec-ffi-c/build && \
    ./regression_test && \
    ./conformance_harness /work/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"
```

Artifacts land in `build/` (gitignored): `libentitycore_codec.so` (~2 MB; `ldd` shows only libc → self-contained, §7) + `libentitycore_codec.a` (libsodium objects bundled in via an `ar` MRI merge).

## Conformance

`../conformance/` runs the test-vector corpus and the cross-impl differential. No green → no publish (S7).

The impl-agnostic `dlopen` differential (`../conformance/abi_differential.c`) loads this `.so` **and** the Rust `.so` (each in its own link-map namespace via `dlmopen`, since they share a soname) and asserts byte-identical results across the reachable ABI — the first test that crosses the actual C-ABI boundary (the per-impl harnesses link their core directly):

```sh
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm -v "$PWD":/work:Z entity-core-keystone/c-toolchain:latest sh -c '
  cd /work/ffi-generator/c-abi/conformance && gcc -std=c11 -O2 -o /tmp/diff abi_differential.c -ldl && \
  /tmp/diff /work/ffi-generator/c-abi/entity-core-codec-ffi-c/build/libentitycore_codec.so \
            /work/ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release/libentitycore_codec.so'
```

## Status — first pass GREEN

**`conformance_harness`: 69/69 byte-identical** to the vendored cross-blessed fixture (all categories: float·int·length·map_keys·primitive·nested·envelope · content_hash incl. F5 empty-entity hash · peer_id incl. N1 `key_type=128` · signature deterministic Ed25519 · tag_reject N2). **`regression_test`: 12/12.** **`abi_differential` vs the Rust `.so`: 48/48** through the real `dlopen` boundary — the 4th/5th validation (Go·Rust·Py blessed the fixture; rust-ffi + c-ffi each 69/69; now C↔Rust agree across the ABI itself).

`.so` exports exactly the 19 ABI symbols (`nm -D`), libsodium localized, self-contained.

### First-pass scope / not-yet-done (matches the Rust first pass)

- **Stubbed exports** (no vector drives them; return `EC_INTERNAL_ERROR`): `ec_envelope_verify_root_hash`, `ec_envelope_find_signature_for`. (`ec_ed25519_keygen` **is** implemented here via libsodium's CSPRNG — strictly better than the Rust stub; no vector drives it.)
- **Arena trio** (`ec_arena_new/reset/free`) returns NULL/no-op — full N4 arena decode is first-pass scope; the decode path currently uses borrowed input spans (`ec_decode_entity`).
- **Bare encoder not reachable through the entity-shaped ABI** (finding F6) — the `dlopen` differential covers Class-A transitively via `ec_content_hash`/`ec_encode_ecf`; a direct Class-A 5-way differential needs the F6 bare-encode test hook.

See `../status/DESIGN-NOTES-FROM-REVIEW.md` for the N1–N4 design-time notes.
