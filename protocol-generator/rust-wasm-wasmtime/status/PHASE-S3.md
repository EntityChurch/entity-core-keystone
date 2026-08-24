# PHASE-S3 — entity-core-protocol-rust-wasm-wasmtime (Rust→wasm under wasmtime AOT)

The PRODUCTION compile-once-run-native WASM peer: the SAME `wasm32-wasip1` module as
`../rust-wasm`, run under **wasmtime** and precompiled to native Cranelift code
(`wasmtime compile` → `.cwasm`). Closes the open WASM production question the WasmEdge
peers left — WasmEdge 0.17's AOT is inert (runs at interpreter speed); wasmtime's is real.

## ✅ FULL COHORT PARITY (2026-07-15) — `--profile core` Result: PASS

**682 total / 291 pass / 294 warn / 0 FAIL / 97 skip @ oracle `cc1970f`** — `run-s4.sh` →
**Result: PASS**, **no `-allow-skip`**, running the AOT `.cwasm` (`--allow-precompiled`).
Byte-for-byte the same P/W/F/S as `../rust-wasm` (WasmEdge) and `../wasm-wat` — the same
interior, the same wasip1 codegen, only the runtime + execution-mode + socket seam changed.
Concurrency 5/5 PASS (t1_1/t1_2/t1_3/t2_1/t2_2) — the §6.11 10k-churn probes pass **at
AOT-native speed with no per-boot JIT warmup**, and the "experimental" `-S tcplisten` path
held under churn. Launch:
`wasmtime run -S preview2=n -S tcplisten=127.0.0.1:7777 --allow-precompiled out/peer.cwasm --debug-open-grants --validate`.

## What actually changed vs ../rust-wasm — ONE variable, isolated

Deliberately reuses `wasm32-wasip1` (not wasip2): `wasmtime compile` is WASI-version-
agnostic, so wasip1 answers the compile-once-native question as a **controlled comparison**
against the WasmEdge/JIT column — same codegen artifact, only runtime + exec-mode differ.
wasip2 would add a second variable (a different socket ABI) and cost the no-rustup rule
(fedora ships no wasip2 std); it is a deferred forward-ABI probe, not a prerequisite.

- **The interior is byte-identical** to `../rust-wasm` (same `../rust` path dep, same
  `entity_core_protocol` lib). `out/peer.wasm` = **241,993 B** ≈ rust-wasm's 242 KB.
- **The socket seam** (`src/main.rs`) is the only real diff, and only in its `sock` module:
  - `../rust-wasm` (WasmEdge): the guest SELF-BINDS via WasmEdge's non-standard `sock_*`
    extension (`sock_open/bind/listen`) through `wasmedge_wasi_socket`.
  - this peer (wasmtime): the HOST preopens the listener (`-S tcplisten`); the guest finds
    it as a preopened fd (`find_listener`: scan fds 3.. for a STREAM socket) and accepts
    with the **standard wasip1 `sock_accept`**. recv/send are `fd_read`/`fd_write`, readiness
    is `poll_oneoff` — all standard `wasi`-crate preview1, no WasmEdge extension. That is what
    makes the module wasmtime-portable and AOT-compilable.
  - The framing (`write_frame_oneshot`), the §7a reentrant-outbound pump (`pump_outbound`),
    and the deferred-inbound serialization are **ported VERBATIM** from `../rust-wasm` — they
    are ABI-neutral. `Peer::dispatch` and every handler are called UNCHANGED.

## The AOT payoff — measured (`status/warmup.sh`, in-container)

`wasmtime compile out/peer.wasm -o out/peer.cwasm` → native Cranelift code, executed
directly. Cold warmup (process launch → `LISTENING`), same runtime, three runs:

| Mode | Warmup | Notes |
|---|---|---|
| **wasmtime AOT** (`.cwasm`) | **~5.7 ms** (steady) | precompiled native — no compile at boot |
| wasmtime JIT (`.wasm`) | ~7 ms warm / ~68 ms first | Cranelift compiles at load (first incl. cold binary load) |
| WasmEdge JIT (prior column) | ~3 s | (eval `wasm-codegen-comparison.md`) |

The result the phase set out to prove: **native code truly engages** (unlike WasmEdge 0.17's
inert AOT), full conformance passes at that speed, and per-boot compile is eliminated. On
wasmtime even JIT warmup is already ~500× cheaper than WasmEdge's; AOT removes the residue and
yields a deploy-time artifact that boots as native.

- **Size:** `.wasm` 241,993 B (portable module) vs `.cwasm` 904,560 B (AOT native). The
  `.cwasm` is **wasmtime-46.0.1-specific** — a deploy-time recompile artifact, NOT portable
  across wasmtime versions; re-pin the runtime and rebuild the `.cwasm` together.

## Toolchain / supply-chain (S11)

`containers/rust-wasm-wasmtime-toolchain/`: fedora:43 + rust/cargo + `rust-std-static-
wasm32-wasip1` (all distro, NO rustup) + wabt/binaryen, plus **wasmtime v46.0.1** as a
**checksum-pinned upstream release** (not in fedora — verified `dnf list wasmtime` → nothing;
`sha256 9ae0b17e…edb62`). wasmtime is the only out-of-distro component; the wasip1-not-wasip2
choice is what keeps the rest distro-pure.

## No new spec finding

Substrate-dynamics + the production story, not spec-discovery (the wire axes are saturated —
well dry). Cohort-consistent, NOT independent convergence (shared Rust generation lineage +
shared crypto crates with the native peer, ADR-0012). The AOT warmup/size result is folded
into `research/SUBSTRATE-TAKEAWAYS.md §4` and `protocol-generator/shared/evaluations/wasm-codegen-comparison.md`.
