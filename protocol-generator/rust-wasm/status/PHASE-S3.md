# PHASE-S3 — entity-core-protocol-rust-wasm (the Rust peer compiled to WebAssembly)

The COMPILED WASM peer: the generated Rust peer's library, cross-compiled UNMODIFIED to
`wasm32-wasip1` + a single-threaded WebAssembly transport seam. Sibling of the hand-authored
`wasm-wat` peer; both run on WasmEdge so the head-to-head isolates codegen.

## ✅ FULL COHORT PARITY (2026-07-15) — `--profile core` Result: PASS

**682 total / 291 pass / 294 warn / 0 FAIL / 97 skip @ oracle `cc1970f`** — `run-s4.sh` →
**Result: PASS**, **no `-allow-skip`**. Byte-for-byte the same P/W/F/S as the hand-authored
`wasm-wat` peer (291P/294W/0F/97S), on the same runtime. Launch:
`wasmedge --run-mode=jit out/peer.wasm --debug-open-grants --validate`. Concurrency 5/5 PASS
(t1_1/t1_2/t1_3/t2_1/t2_2), §7a reentry via the single-threaded pump, genuine handshake +
authorization. The 96 §9.0-carve-out skips (TREE/CONTENT/… extensions) + 1 local-env skip
(multisig on-disk-key accept path) are exempt from the gate, identical to the cohort.

## The headline result — the interior cross-compiles UNMODIFIED

The ~4,000-line protocol interior (`../rust` lib: canonical-ECF codec, §5 capability
verification, §6 dispatch, §9.5 type floor, ed25519-dalek + sha2 + curve25519-dalek) compiled
to `wasm32-wasip1` with **zero source changes** (clean build, 2.5s). Even the wasm-hostile
touchpoints resolved for free:

- **`random_nonce()`** — its existing `/dev/urandom`-fails fallback (SHA-256 of
  counter‖SystemTime‖stack-addr) is exactly what triggers in the WASI sandbox; unique per
  handshake, no change needed.
- **`SystemTime::now()`** (capability/nonce timestamps) — works on wasip1 (WASI clock).
- **`std::net` / `std::thread` / `RwLock`** — *compile* on wasip1 (they just don't *function*
  at runtime), so the lib builds; the transport seam replaces the parts that would run.

This is the transportable-layer thesis made literal: the payload is substrate-neutral; only
the ~one-file host seam changes. `src/main.rs` (336 lines) is the ENTIRE wasm-specific surface.

## The transport seam — the concurrency model lives here, not in the interior

Native runs thread-per-connection + a condvar-blocked outbound reentry. wasm has no threads,
so `src/main.rs` does the same work single-threaded:

- **`poll_oneoff` readiness loop** (via `wasmedge_wasi_socket`) multiplexes the listener + all
  live connections; non-blocking accept; §1.6 frame reassembly per connection.
- **§7a same-connection reentry → a reentrant pump** (`pump_outbound`): send the outbound
  EXECUTE, then pump THIS fd until the correlated reply; inbound requests seen mid-pump are
  DEFERRED and drained after — serializing exactly like the native per-conn mutex, with no
  reentrant `&mut Conn` borrow. `Peer::dispatch` and every handler are called **byte-identical
  to native**: the reentry seam is an `Arc<OutboundFn>` the handler clones out of `Conn`, so the
  closure captures only the seam's socket state, never `Conn`. The seam absorbs the whole
  thread→poll difference.

## The two substrate findings that mattered (build-lessons, not spec)

1. **Single-send framing is load-bearing on connection churn.** `wire::write_frame` ships the
   4-byte length prefix and the body as TWO writes; Nagle then holds the body awaiting the
   prefix's ACK — a ~40–200 ms delayed-ACK stall on every cold round trip. Under §6.11 t2_2
   (connection churn) one such stall (~330 ms observed) times out the validator → the peer
   "hung" at ~cycle 91. Combining prefix+body into ONE contiguous `write_all`
   (`write_frame_oneshot`) fixed it — t2_2 went 30s-timeout → 250ms-pass. The hand-authored WAT
   peer hit and fixed the identical bug (host.wat `on_readable`); the finding is transport-model,
   not language.
2. **JIT is the crypto-execution-mode contract** (same as wasm-wat). WasmEdge's interpreter runs
   Ed25519 verify at ~ms, so §5.2's two per-request verifies cannot sustain the §6.11 10k-request
   probes; `--run-mode=jit` (~µs/verify) is required. No auth-caching shortcut (which
   `security.tampered_signature` proves is non-conformant). `--run-mode=jit` is the non-deprecated
   form of wasm-wat's `--enable-jit` on WasmEdge 0.17.1.

## Preliminary size datapoint (full comparison in the eval)

`out/peer.wasm` = **247,596 bytes** (opt-level=s + LTO + strip), vs the hand-authored
`wasm-wat` peer.wasm = **347,644 bytes** — the LLVM-compiled Rust peer is ~29% smaller. Not yet
apples-apples (different codec inclusion); the head-to-head (size + t2_1/t2_2 timing + verify
latency, both under WasmEdge 0.17.1 JIT) is in `protocol-generator/shared/evaluations/wasm-codegen-comparison.md`.

## No new spec finding

The wire axes are saturated (well dry, as expected for a substrate probe). The two findings above
are transport/execution-mode build-lessons, folded into `research/SUBSTRATE-TAKEAWAYS.md §4`.
Cohort-consistent, NOT independent convergence (shared Rust generation lineage + shared crypto
crates with the native peer, ADR-0012).
