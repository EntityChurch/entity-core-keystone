# rust-wasm — Profile Rationale

Why this peer exists and why its profile is shaped the way it is. Companion to
`../profile.toml`; the live status is `../status/PHASE-S3.md`.

## What it is

The generated Rust peer (`protocol-generator/rust`) cross-compiled to `wasm32-wasip1` and run
under WasmEdge. It is a **path-dep crate**, not a fork: the whole protocol payload is the
`entity-core-protocol` library, byte-for-byte the native peer's, and this crate adds only a wasm
binary target — `src/main.rs`, the transport seam.

## Why build it — two goals

1. **The codegen comparison.** The hand-authored `wasm-wat` peer authors the protocol *in* WAT
   from spec; this peer *compiles* an existing Rust peer to wasm. Both run on the same WasmEdge
   runtime, so a head-to-head (module size, sustained-load + churn latency, verify cost) isolates
   the one variable that differs — hand-written WAT vs Rust→LLVM→wasm codegen. That comparison is
   the concrete research payoff (`research/evaluations/wasm-codegen-comparison.md`).
2. **The transportable-compute layer.** The larger arc (NAD native peers, the computational
   genome) needs the smallest substrate-specific layer you can ship from the tree and bootstrap
   onto an arbitrary architecture. This peer *measures* that layer empirically: how much of a real
   peer is portable payload, and how much is irreducibly host-specific. Answer here — payload:
   ~4,000 lines cross-compiled with zero changes; host seam: one 336-line file.

## Key profile decisions

- **Codec = native (inherited), NOT a seam.** Unlike `wasm-wat` (no CBOR/crypto stack → must
  merge a compiled codec), the Rust peer carries its own hand-rolled ECF codec + ed25519-dalek +
  sha2, and they cross-compile to wasm cleanly. That is the essence of "compile a whole peer": the
  codec comes along. No FFI, no seam, in the codec path.
- **Async = single-threaded evented, though the native peer is threaded.** wasm32-wasip1 has no
  threads and `std::net` does not function; the seam replaces thread-per-connection with a
  `poll_oneoff` loop. The interior is unchanged — §7a reentry runs through the same
  `Conn.outbound` hook, driven by a single-threaded reentrant pump. The *seam* owns the
  concurrency-model difference; `Peer::dispatch` is identical to native.
- **Socket crate confined to the bin.** `wasmedge_wasi_socket` binds WasmEdge's non-standard
  `sock_*` extension. It lives only in `src/main.rs` (the seam) — the wasm analog of the asm peer
  linking libc for sockets. The interior's dep-minimization (ed25519-dalek + sha2 only) is intact,
  and `#![forbid(unsafe_code)]` stays on the lib (the raw-FFI unsafe is the bin's, a separate
  compilation unit).
- **JIT + single-send framing are transport contracts, not choices.** `--run-mode=jit` (crypto at
  µs not ms) and one-contiguous-write framing (defeating the Nagle/delayed-ACK churn stall) are
  both forced by the runtime + §6.11 robustness; see PHASE-S3.

## Honesty framing (ADR-0012)

Substrate probe, corroboration tier. `--profile core` 0-FAIL is expected as corroboration, NOT
independent convergence: shared Rust generation lineage AND shared crypto crates with the native
peer. The independent datapoints are (a) "the unmodified interior cross-compiles," (b) the wasm
transport seam, and (c) the codegen comparison — not the codec bytes.
