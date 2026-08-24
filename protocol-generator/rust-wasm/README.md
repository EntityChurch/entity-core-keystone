# entity-core-protocol-rust-wasm

The generated Rust core-protocol peer (`../rust`), cross-compiled **unmodified** to
`wasm32-wasip1` and run under WasmEdge. The sibling of the hand-authored WAT peer
(`../wasm-wat`) — the two WebAssembly flavors: one *authored in* WAT, one *compiled* from Rust.
Both run on the same runtime so the head-to-head isolates codegen.

## Status

`validate-peer --profile core` → **Result: PASS — 682 · 291P · 294W · 0F · 97S @ `cc1970f`**
(full cohort parity with `wasm-wat`). See `status/PHASE-S3.md`.

## Layout

- `src/main.rs` — the ENTIRE wasm-specific surface: a single-threaded `poll_oneoff` transport
  seam + the §7a reentrant-outbound pump. The protocol payload is the `../rust` library
  (path dep), unchanged.
- `Cargo.toml` / `Cargo.lock` — path dep on `entity-core-protocol-rust` + the `wasmedge_wasi_socket`
  socket binding (bin-only).
- `Makefile` — `make peer` cross-builds + stages `out/peer.wasm`.
- `run-s4.sh` — conformance harness (WasmEdge `--run-mode=jit`, drives the Go `validate-peer`
  oracle over loopback).
- `profile.toml`, `arch/PROFILE-RATIONALE.md` — the S1 profile + rationale.

## Build & test (in-container)

```sh
# from the repo root; mount a cargo cache at /cargo (first build fetches crates once)
podman run --memory=6g --memory-swap=6g --pids-limit=2048 --cpus=4 --rm \
  -v "$PWD":/work:Z -v <cargo-cache>:/cargo:Z \
  localhost/entity-core-keystone/rust-wasm-toolchain:latest \
  sh /work/protocol-generator/rust-wasm/run-s4.sh
```

Container: `containers/rust-wasm-toolchain/` (fedora:43 + rust + `rust-std-static-wasm32-wasip1`
+ wasmedge + wabt + binaryen).
