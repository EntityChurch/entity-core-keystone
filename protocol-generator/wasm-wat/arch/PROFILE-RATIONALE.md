# PROFILE-RATIONALE — entity-core-protocol-wasm-wat

Why each S1 profile choice was made. The wasm-wat peer is a **substrate probe**, not a
language-idiom probe: it documents how the protocol maps onto a bounded-linear-memory
virtual ISA with imported-only I/O, no fork, no threads. It is the WASM analog of the
hand-written asm peer and the assembly track's forward pointer (SESSION-2026-07-13). Expected
spec-discovery yield is **low** (the wire-touching axes are saturated by the cohort); the
payoff is **generator-robustness + substrate-dynamics**, and the honest framing is
cohort-consistent corroboration, not independent convergence (ADR-0012) — with the extra
caveat that the codec bytes share the Rust codec's lineage, so the independent datapoint is
the hand-authored authority **interior + WAT transport**, not the codec.

Unlike most S1 profiles, the load-bearing decisions here were settled by **evidence, not
guesswork**: two hand-authored spikes (`src/echo.wat`, `src/ffi-smoke.wat`) proved the two
hard unknowns green before the profile was written.

## Runtime = WasmEdge 0.17.0 (A-WAT-001)

The peer must open a **real listening TCP socket from raw WAT** — the harness points the Go
`validate-peer` oracle at `127.0.0.1:PORT` over loopback. The research (SESSION note + the
socket survey) established that standard WASI preview1 has **no** sockets and WASI 0.2
`wasi:sockets` is **Component-Model-only** (unreachable from hand-authored core WAT). Two
runtimes expose *flat* Berkeley-socket function imports that raw WAT can `(import …)`
directly: **Wasmer WASIX** and **WasmEdge**. Chose **WasmEdge** because:

1. It ships in the **fedora:43 repos** (`wasmedge-0.17.0-1.fc43`) — dnf-pinnable, S11-clean,
   **no `curl | sh`** external-binary fetch (which the harness classifier correctly blocks,
   and which the ecosystem's "system toolchains, minimal deps" stance discourages anyway).
2. Its core runtime exposes the flat `wasi_snapshot_preview1` socket extension
   (`sock_open`/`bind`/`listen`/`accept`/`recv`/`send`) as plain imports — the WASM analog of
   the asm peer calling Linux socket syscalls. **No native host code, no Component Model.**

The alternative — a custom Wasmtime/Rust host embedding the module — was rejected: it puts
transport in *our* native code, re-opening the exact wrapper critique the asm peer avoided.
With WasmEdge the runtime plays the kernel; the WAT drives the sockets. **Proven** in
`echo.wat`: a hand-authored listener does a verbatim loopback echo round-trip, and the
fiddly `WasiAddress{buf,size=4}` + IPv4-octet V1 layout was correct first try.

## Codec strategy = SEAM (compiled codec.wasm merged) (A-WAT-002)

WAT has no CBOR/Ed25519/SHA/base58 — nothing, like asm. But unlike asm (which can `dlopen` a
native `.so`), a WASM module cannot load native code; the codec must be *in the wasm world*.
Two sub-decisions:

1. **Which codec impl.** The **Rust** codec (`entity-core-codec-ffi-rust`), not the C one.
   The C impl statically links **libsodium**, which is painful to target wasm32-wasi; the
   Rust impl's pure-Rust `ed25519-dalek`/`sha2`/`ed448-goldilocks` compile to
   `wasm32-wasip1` **cleanly** (proven — the `ed448-goldilocks` pre-release + `getrandom`
   wildcards both built fine; getrandom resolves to WASI `random_get`). It exports the full
   C-ABI `ec_*` symbols + its memory, importing only WASI.
2. **How to link it to the hand-authored interior on a stock runtime.** The codec API is
   pointer-based (`ec_sha256(ptr,len,out)`), so the codec must read/write the *interior's*
   memory. Two separately-compiled modules each own their own memory → naive juxtaposition
   breaks pointer-passing. **Solution:** the codec exports its memory; the interior
   **imports the codec's memory** + the `ec_*` funcs; **binaryen `wasm-merge`** fuses the two
   into ONE module over ONE shared memory. wasm-merge is the "linker" (the `ld`/`.so`-link
   analog). The interior parks its scratch **high** (≥ `0x200000`, above the codec's ~1.1
   MiB data/stack/heap) after `memory.grow`, so the two regions never collide. **Proven** in
   `ffi-smoke.wat`: `ec_sha256("abc")` returns the byte-exact KAT digest across the seam on
   stock WasmEdge.

This is the WASM realization of the keystone's hybrid-FFI doctrine: hand-roll the authority
interior + transport; seam the parts not worth re-deriving per substrate (canonical CBOR +
crypto). The **envelope + EXECUTE/RESPONSE data-map** canonical CBOR is still hand-rolled in
WAT (`ec_encode_ecf` only covers entity-shaped data — the same Level-1 split as asm A-ASM-004,
here A-WAT-004). A fully hand-rolled-WAT codec (no seam) is a documented later stretch.

**Open (A-WAT-005):** `codec.wasm` is currently the cargo `target/` output. Like
`libentitycore_codec.so`, it should become a reproducible, provenance-clean **committed
build output** — an `ffi-generator` wasm shape (the README already names a future
`rust-wasm`/`wasm-abi` shape). Cross-arm; route through `research/`, don't reach into
`ffi-generator/` unilaterally. Formalize before S4/publish.

## Concurrency = single-threaded poll loop + pending_tab demux — SUBSTRATE-FORCED (A-WAT-006)

WASM has **no fork** and (at Level 1) **no threads**, so the fork-per-connection model the asm
peer ultimately used is simply unavailable. This is not a choice to agonize over — the
substrate *forces* the single-threaded event loop, which is exactly the concurrency template
**A-ASM-014 already validated**: a request/response frame router + a `pending_tab`
{echo_rid → dispatch_rid} table handles §7a.2a one-socket reentry (validator-as-peer-B) with
neither fork nor threads. Multiple simultaneous connections multiplex cooperatively via WASI
`poll_oneoff` over non-blocking socket fds — interleaved progress, no head-of-line blocking
for the core category (the TurboWarp #32 cooperative-yield lesson; genuine parallelism for
`t1_3_no_head_of_line` is beyond the core floor, as on asm). This peer thus *inherits* the
hardest design answer from the asm session rather than re-deriving it — the whole reason the
asm work named WASM as its forward pointer. The one detail to confirm in increment 3 (a
potential ambiguity): the exact non-blocking-flag mechanism (`fd_fdstat_set_flags`
`FDFLAGS_NONBLOCK`) under WasmEdge.

## Memory = one imported linear memory; interior scratch high; trap-on-OOB backstop

ONE bounded linear memory, and it is the **codec's** (the interior imports it). No malloc/GC.
The A-ASM-010 discipline — size buffers to the 16-MiB entity cap, drain + 413 an over-cap
frame, never OOB — is **more** load-bearing here than on asm: a bounds violation **traps the
whole module** (a WASM peer is one process; there is no per-fork blast radius to absorb a
crash). Frame-cap (§1.6) is likewise load-bearing on a single memory + single thread. So every
buffer op is bounds-checked in WAT *before* the access, and the trap is treated as the
last-resort backstop, not a handled path.

## Error model = i32 status + branch; traps fatal

No language error model — WASM offers i32/i64 returns, structured control flow, and traps. The
seam's `ec_*` return `int32_t` status; protocol verdicts are integers, mapped at the dispatch
boundary to §5.2a/§6.12 status codes. Same `errno` shape as asm, with the sharper rule that a
trap is unrecoverable (see [memory]).

## Build = wat2wasm + wasm-merge; run WasmEdge

`wat2wasm` (wabt) assembles each hand-authored `.wat`; `wasm-merge` (binaryen) fuses the
interior modules + `codec.wasm` into one module; WasmEdge runs it. The standard `build` verb
is the interface (the `echo`/`ffi-smoke` verbs are the S1 spike self-checks). Entry is the
interior's `_start` (kept by `--rename-export-conflicts`).

## Toolchain pins (S11)

- `wabt 1.0.37-2.fc43` — `wat2wasm` / `wasm-validate` / `wasm-objdump`; fedora:43 stock. The
  WAT assembler; no LLVM path.
- `wasmedge 0.17.0-1.fc43` — the runtime; flat `wasi_snapshot_preview1` sockets built in.
  fedora:43 stock.
- `binaryen 126-1.fc43` — `wasm-merge`, the seam linker. fedora:43 stock.
- `rust-std-static-wasm32-wasip1` (fedora:43) — only to **build** `codec.wasm` in a
  rust-capable container; not needed for the peer build itself.

All fedora-pinned, no external fetch — mirrored in `containers/wasm-wat-toolchain/Containerfile`.
