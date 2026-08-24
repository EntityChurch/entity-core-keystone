# WASM codegen head-to-head: hand-authored WAT vs compiled Rust

Two peers implement entity-core on the **same WebAssembly runtime** (WasmEdge 0.17.1,
`--run-mode=jit`), differing in ONE variable — how the `.wasm` is produced:

- **`wasm-wat`** — the protocol authored directly in WebAssembly text (`.wat`) from spec, with
  the Rust C-ABI codec compiled to wasm and `wasm-merge`d in as a seam.
- **`rust-wasm`** — the generated Rust peer's library compiled (LLVM) to `wasm32-wasip1`,
  UNMODIFIED, behind a single-threaded socket transport seam (`src/main.rs`).

Both are `--profile core` **0-FAIL @ `cc1970f`** (291P/294W/0F/97S — identical P/W/F/S). So this
is a clean isolation of **codegen**: hand-written WAT vs Rust→LLVM→wasm. This doc is the answer to
"why is one better than the other, and what does it say about the optimal architecture for a
*transportable compute layer*" (the NAD-native / computational-genome arc).

## Measured (all on WasmEdge 0.17.1 JIT, fedora:43 container, one loopback, `--network=none`)

| Metric | rust-wasm (compiled) | wasm-wat (hand-authored) | Delta |
|---|---|---|---|
| **Module size** (total) | **247,596 B** | 347,644 B | rust-wasm **−29%** |
|   · code section | 222,248 B | 283,559 B | −22% |
|   · data section | 23,470 B | 61,280 B | −62% |
|   · defined functions | 452 | 559 | — |
| **JIT warmup** (boot→LISTENING) | **~3.1 s** | ~4.3 s | rust-wasm **−28%** |
| **t2_1 sustained** (10k req, 1 conn) | 2.39 s | **1.35 s** | wasm-wat **1.8× faster** |
| **t2_2 connection churn** | 258 ms | **150 ms** | wasm-wat **1.7× faster** |
| **concurrency category** (total) | 2.98 s | **1.56 s** | wasm-wat 1.9× |
| **dev effort** | reuse whole peer + **336-line** seam | **559 fns** authored in WAT from spec | rust-wasm ≪ |

Plus the cross-substrate control — **the same Rust peer as native ELF vs as wasm**:

| | full `--profile core` wall |
|---|---|
| rust-wasm (Rust→wasm, JIT) | 23.06 s |
| native Rust peer (ELF) | 22.82 s |
| **wasm/JIT overhead vs native** | **~1%** |

### The 20s outlier — excluded from the codegen comparison (it's interior behavior)

Both peers' full-core wall is dominated by one check, `security.chain_content_hash_substitution`,
which hits a **20 s validator settle-window**. This is a property of the **Rust interior**, not the
substrate: the native Rust ELF peer shows the identical **20 s** (total 22.82 s), and so does
rust-wasm (23.06 s) — they track to ~1%. The `wasm-wat` peer's *different* (hand-WAT) interior
happens to return a response that lets the validator conclude immediately (0 s). So the raw full-core
totals (23 s vs 6.6 s) compare *interiors*, not codegen; the throughput rows above (t2_1/t2_2) are the
clean codegen signal. (The Rust peer passes the check — this is latency, not a conformance defect —
and fixing it would be an interior change, out of scope for a peer that reuses the interior verbatim.)

## Why each wins where it does

**Compiled Rust is smaller + warms faster + is ~free to build.**
- **Size (−29%).** LLVM's dead-code elimination + LTO + `opt-level=s` + `strip` yield a tighter
  module than hand-written WAT, and the compiled peer carries its codec *natively* (one crate,
  deduped) rather than `wasm-merge`ing a separately-compiled codec.wasm (whose data section — 61 KB
  vs 23 KB — carries the duplication). Smaller module → **less to JIT** → the 28% faster warmup
  follows directly (JIT compile time scales with code size; WasmEdge's `optimize` pass is the bulk of
  both boots).
- **Effort.** rust-wasm reused a *whole existing peer* (the `../rust` library, path-dep, zero source
  changes) and added one 336-line host file. wasm-wat hand-authored ~559 functions of interior from
  spec. For "stand up a conformant peer on a new substrate," compiling wins by a wide margin.

**Hand-authored WAT is faster per request (~1.8×).**
- The WAT peer's request loop is purpose-built: static memory offsets, in-place framing, no
  allocator, no abstraction layers. The Rust peer pays an **abstraction tax** on the hot path — a
  `Vec` per frame (`encode()`, the one-shot framing buffer, `envelope_of_frame`), `HashMap` demux
  lookups, and the `wasmedge_wasi_socket` copies — none of which LLVM can fully elide across the
  crate boundary. Under a 10k-request storm that tax is the whole 1.8× gap.

**wasm costs ~1% over native — for the SAME peer.** With JIT engaged (Ed25519 at ~µs, per
SUBSTRATE-TAKEAWAYS §4), a crypto-heavy per-request protocol compiled to wasm runs within ~1% of the
native ELF build of the identical code. The portability is nearly free *at the compute layer*.

## Architecture takeaways (for the transportable / NAD-native compute layer)

1. **Portable compute is ~free; the seam is the cost.** The ~1% wasm-vs-native overhead means the
   choice of *portable substrate* (wasm) is not where the budget goes — the whole per-substrate cost
   is the **transport ABI seam** (sockets/host imports), exactly as the substrate sweep predicted
   ("the wire portability boundary is the transport ABI, not the protocol logic"). A bootstrap that
   ships a peer as wasm from the tree pays for the seam, not the compute.
2. **Default to compiling; hand-author only the hot loop.** For a deployable unit you want small +
   fast-to-instantiate + cheap-to-produce → compile a real peer (rust-wasm wins size, warmup, effort).
   Reach for hand-authoring (or teaching the compiler to elide per-request allocation) ONLY when
   steady-state throughput dominates — that buys ~1.8× and ~100 KB, at 3–4× the authoring cost. The
   comparison *quantifies the price of not hand-authoring*: ≈100 KB + ≈1.8× throughput.
3. **The transportable payload really is the interior.** rust-wasm cross-compiled ~4,000 lines of
   protocol interior with **zero** source changes; only a 336-line host seam is substrate-specific.
   That is the empirical shape of the "minimal transportable layer": a large substrate-neutral payload
   + a tiny host shim. A generator that emits `{interior, per-substrate seam}` is the natural factoring.
4. **Two transport lessons generalize to any compiled-wasm peer** (folded into SUBSTRATE-TAKEAWAYS §4):
   **single-send framing** (ship `[len][payload]` in one write — two sends let Nagle stall the body
   ~40–200 ms on cold round trips, which fails §6.11 churn), and **JIT is the crypto execution-mode
   contract** (interpreter ~ms/verify times out the robustness probes). Both were needed here exactly
   as the hand-authored peer needed them — they are substrate/runtime properties, not codegen artifacts.

## The third column: wasmtime AOT (compile-once-run-native)

The two columns above share ONE runtime (WasmEdge 0.17.1 JIT), so they isolate *codegen*. A
third peer — `protocol-generator/rust-wasm-wasmtime/` — isolates the **runtime + execution
mode** instead: the SAME `rust-wasm` wasip1 module, run under **wasmtime** and precompiled to
native Cranelift code (`wasmtime compile` → `.cwasm`). This answers the open production question
the WasmEdge peers left: **WasmEdge 0.17's AOT is inert** (the `wasmedge compile` artifact runs
at interpreter speed — only JIT engages native code, at a per-boot cost), whereas wasmtime's AOT
is real native code executed directly.

Deliberately wasip1, not wasip2: `wasmtime compile` is WASI-version-agnostic, so wasip1 keeps
this a **controlled** change — same codegen artifact, only runtime + exec-mode move. wasip2
would add a second variable (a different socket ABI) and cost the no-rustup rule (fedora ships
no wasip2 std); it is a deferred forward-ABI probe. Only the socket seam changed: WasmEdge's
self-bind (`sock_open/bind/listen`) → a **host-preopened listener** (`-S tcplisten`) + the
standard wasip1 `sock_accept`/`poll_oneoff` (the `wasi` crate). The interior is byte-identical
(`out/peer.wasm` 241,993 B ≈ rust-wasm's 242 KB); framing + the §7a reentrant pump port verbatim.

Conformance is full parity — **`--profile core` 682·291P·294W·0F·97S @ `cc1970f`**, the §6.11
10k-churn probes (t2_1/t2_2) passing at native speed (the "experimental" `-S tcplisten` held).

| Metric | wasmtime **AOT** (`.cwasm`) | wasmtime JIT (`.wasm`) | WasmEdge JIT (`.wasm`) |
|---|---|---|---|
| **Warmup** (boot→LISTENING) | **~5.7 ms** (steady) | ~7 ms warm / ~68 ms first† | ~3.1 s |
| Execution | precompiled native, no boot compile | Cranelift compiles at load | native only via JIT (AOT inert) |
| Artifact size | 904,560 B (`.cwasm`, native) | 241,993 B (`.wasm`) | 247,596 B (`.wasm`) |
| `--profile core` | 291P/0F | 291P/0F | 291P/0F |

† first-JIT includes cold wasmtime-binary load; the Cranelift compile of the 242 KB module is the
small residual over AOT. Numbers are `status/warmup.sh`, 3 runs, same container.

**Reading it:** the headline warmup win (~3 s → ~ms, ~500×) came from **WasmEdge → wasmtime**, not
from AOT per se — wasmtime's Cranelift JIT is already ~ms. AOT's marginal gain is removing the
residual per-boot compile (~68 ms → ~5.7 ms) AND, more importantly, producing a **deploy-time
native artifact that boots with zero compile**. That is the production-packaging story:
compile-once-run-native, proven to engage real native code (unlike WasmEdge 0.17) and to hold full
per-request-crypto conformance at that speed. Cost: the `.cwasm` is **wasmtime-version-specific**
(46.0.1 here) — a deploy-time recompile artifact, not a portable one; pin the runtime, rebuild the
`.cwasm` on any runtime bump. This reconfirms the thesis a third time: **portable compute is ~free;
the per-substrate cost is the transport seam** — here just self-bind → host-preopened-listener.

## Method / reproduction

- Size: `wasm-objdump -h out/peer.wasm` in `containers/rust-wasm-toolchain`. AOT: `wc -c
  out/peer.cwasm` in `containers/rust-wasm-wasmtime-toolchain`.
- wasmtime AOT warmup/conformance: `protocol-generator/rust-wasm-wasmtime/{status/warmup.sh,run-s4.sh}`
  in `containers/rust-wasm-wasmtime-toolchain` (wasmtime v46.0.1, checksum-pinned;
  `-S preview2=n -S tcplisten=127.0.0.1:PORT --allow-precompiled out/peer.cwasm`).
- Timing: launch `wasmedge --run-mode=jit out/peer.wasm --debug-open-grants --validate`, time to the
  `LISTENING` line (warmup), then `validate-peer -profile core [-category concurrency]`, one peer per
  container invocation (distinct netns → no port contention). Native control: `entity-peer-host`
  (ELF) with `--name conformance` (0x11×32 seed) on the same oracle.
- Runtime pinned to WasmEdge **0.17.1** for BOTH peers (the WAT peer was originally measured on
  0.17.0, since retired from fedora; re-measured here on 0.17.1 so the head-to-head is single-runtime).

## Verdict

For a **transportable compute layer**, compiling an existing peer to wasm is the right default:
smaller, faster to instantiate, and near-free to produce, at ~1% compute overhead vs native. The
hand-authored WAT peer remains the reference for *how small and fast the loop can get* (~1.8× the
throughput, ~100 KB less) — the specialization you graft onto the hot path once the deployable unit's
shape is fixed, not the way to stand one up.

For **deployment**, run that compiled module on a mature-AOT runtime: wasmtime AOT boots the peer
as native code in ~5.7 ms (vs WasmEdge JIT's ~3 s) with a compile-once-run-native `.cwasm`, full
conformance intact — the production-packaging answer WasmEdge 0.17's inert AOT couldn't give. The
one string attached is version-pinning the `.cwasm` to the runtime. See the third-column section.
