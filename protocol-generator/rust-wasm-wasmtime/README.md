# entity-core-protocol-rust-wasm-wasmtime

The generated Rust core-protocol peer (`../rust`), cross-compiled **unmodified** to
`wasm32-wasip1` and run under **wasmtime**, precompiled to native Cranelift code
(`wasmtime compile` → `.cwasm`). The **production compile-once-run-native** counterpart to
`../rust-wasm` (which runs the SAME module under WasmEdge/JIT). Same interior, same target —
only the runtime + execution mode + socket seam differ, so this isolates the **AOT** column.

## Status

`validate-peer --profile core` → **Result: PASS — 682 · 291P · 294W · 0F · 97S @ `cc1970f`**
(full cohort parity with `rust-wasm` / `wasm-wat`), running the AOT `.cwasm`. See
`status/PHASE-S3.md`. **AOT warmup ~5.7 ms** (native engages) vs WasmEdge JIT's ~3 s; sizes
`.wasm` 242 KB / `.cwasm` 904 KB.

## Why wasip1, not wasip2

`wasmtime compile` (AOT) is WASI-version-agnostic, so wasip1 answers the compile-once-native
question as a **controlled comparison** — same codegen artifact as the WasmEdge column, only
the runtime + exec-mode change. wasip2 would add a second variable (a different socket ABI)
and cost the no-rustup rule (fedora ships no wasip2 std). It's a deferred forward-ABI probe.

## Layout

- `src/main.rs` — the ENTIRE wasm-specific surface: a single-threaded `poll_oneoff` seam over
  a **host-preopened** listener (`-S tcplisten` + standard wasip1 `sock_accept`, via the `wasi`
  crate) + the §7a reentrant-outbound pump. The framing/pump/dispatch above the `sock` module
  are ported verbatim from `../rust-wasm`; the protocol payload is the `../rust` lib, unchanged.
- `Cargo.toml` / `Cargo.lock` — path dep on `entity-core-protocol-rust` + the `wasi` (0.11.1)
  preview1 binding (bin-only). NO WasmEdge extension.
- `Makefile` — `make peer` cross-builds `out/peer.wasm`; `make aot` also `wasmtime compile`s
  `out/peer.cwasm` (the native artifact).
- `run-s4.sh` — conformance harness (wasmtime AOT by default; `MODE=wasm` runs the module JIT
  for the AOT-vs-JIT-warmup datapoint). Drives the Go `validate-peer` oracle over loopback.
- `status/` — `PHASE-S3.md`, `CONFORMANCE-REPORT.json`, `warmup.sh` (the AOT/JIT warmup probe).

## Build & test (in-container)

```sh
# from the repo root; mount a cargo cache at /cargo (first build fetches the wasi crate once)
podman run --memory=6g --memory-swap=6g --pids-limit=2048 --cpus=4 --rm --network=none \
  -v "$PWD":/work:Z -v <cargo-cache>:/cargo:Z \
  localhost/entity-core-keystone/rust-wasm-wasmtime-toolchain:latest \
  sh /work/protocol-generator/rust-wasm-wasmtime/run-s4.sh
```

Container: `containers/rust-wasm-wasmtime-toolchain/` (fedora:43 + rust +
`rust-std-static-wasm32-wasip1` + wabt + binaryen + a **checksum-pinned wasmtime v46.0.1**).
Note: `out/peer.cwasm` is wasmtime-46.0.1-specific — a deploy-time recompile artifact, not
portable across wasmtime versions.
