# PHASE-S1 — entity-core-protocol-wasm-wat (Research + Profile)

**Status: COMPLETE.** The profile is authored (`profile.toml`), the rationale recorded
(`arch/PROFILE-RATIONALE.md`), and — unusually for S1 — the two load-bearing unknowns were
retired with **green hand-authored spikes** before the profile was written. No blocking
`TBD`s remain; increment 3 (the authority-interior port) is unblocked.

## What this peer is

The hand-authored **WebAssembly-text (`.wat`)** peer — the WASM analog of the hand-written asm
peer and the assembly track's forward pointer (SESSION-2026-07-13, lessons 1–2). A
substrate-probe on the corroboration tier: a bounded-linear-memory virtual ISA, no fork, no
threads, imported-only I/O. Value = generator-robustness + substrate-dynamics, **not**
spec-discovery (the wire axes are saturated). Honesty: cohort-consistent, not independent
convergence (ADR-0012); and the codec bytes share the Rust codec's lineage, so the independent
datapoint is the hand-authored authority **interior + WAT transport**.

The natively-authored-WAT flavor of the two WASM peers in COMPLETENESS-ROADMAP §2 (the sibling
Rust→WASM cross-compiler peer takes the other host model — coordinate ownership before it
starts).

## Decisions (all evidence-backed — see arch/PROFILE-RATIONALE.md)

| Axis | Decision | Evidence |
|---|---|---|
| Runtime | **WasmEdge 0.17.0** (fedora-packaged; flat `wasi_snapshot_preview1` sockets from raw WAT) | socket survey + `echo.wat` PASS |
| Sockets | flat `sock_open/bind/listen/accept/recv/send` imports — WASM "syscalls", **no native host, no Component Model** | `echo.wat` verbatim echo |
| Codec | **SEAM**: Rust codec → wasm32-wasip1 (exports `ec_*` + memory), `wasm-merge`'d into the interior over ONE shared memory | `ffi-smoke.wat` `ec_sha256` KAT PASS |
| Envelope CBOR | hand-rolled in WAT (small fixed-shape maps) — `ec_encode_ecf` only covers entity-shaped data | A-WAT-004 (= asm A-ASM-004) |
| Concurrency | single-threaded `poll_oneoff` loop + `pending_tab` demux — **substrate-forced** (no fork/threads); direct port of asm A-ASM-014 | A-WAT-006 |
| Memory | one imported linear memory (the codec's); interior scratch high; trap-on-OOB is fatal → 16-MiB-cap discipline matters more | A-ASM-010 ported |
| Integer model | fixed-width i32/i64 → carries the head-form self-test `[2⁶³, 2⁶⁴−1]` | SUBSTRATE-TAKEAWAYS integer note |

## Spikes (the S1 de-risk — committed to dev)

- **`echo.wat`** (increment 1) — hand-authored TCP listener on `127.0.0.1:7777` via WASIX
  sockets; verbatim loopback echo; `make echo` PASS. Socket layer measured **~40 lines WAT**
  (the transport stack is the runtime's — we are not building a socket stack). Commit `b933076`.
- **`ffi-smoke.wat`** (increment 2) — the codec seam: `ec_sha256("abc")` through the merged
  `codec.wasm` matches the KAT byte-exact; `make ffi-smoke` PASS on stock WasmEdge. Proves
  hand-authored WAT + compiled codec share one memory with no native host. Commit `85a0035`.

## Toolchain (S11, all fedora:43 stock — `containers/wasm-wat-toolchain/`)

`wabt-1.0.37-2.fc43` (wat2wasm) · `wasmedge-0.17.0-1.fc43` (runtime) · `binaryen-126-1.fc43`
(wasm-merge) · `rust-std-static-wasm32-wasip1` (to build `codec.wasm` only). No `curl | sh`,
no external binary fetch.

## Open items carried into later phases (not blocking S1)

- **A-WAT-005** — `codec.wasm` provenance/home: should become a committed `ffi-generator` wasm
  shape artifact (like the `.so`), not the cargo `target/` output. Cross-arm; formalize before
  S4/publish.
- **A-WAT-006 detail** — confirm the non-blocking-flag mechanism (`fd_fdstat_set_flags`
  `FDFLAGS_NONBLOCK`) under WasmEdge during the increment-3 event-loop build.

## Handoff → increment 3 (authority-interior port)

All known-good porting from asm, no remaining unknowns: hand-roll the envelope + data-map CBOR
(A-WAT-004); the non-blocking event loop + `pending_tab` demux; §6.5/§6.6 dispatch + handler
resolution; §5.2 verify; §5.5 K-of-N multisig accept; scope; §6.9a revoke/delegate; the
path/tree store (canon/listing/delete); register/unregister; configure. Then the corpus
selfcheck (WAT analog of asm `selfcheck.s`) and `run-s4.sh` → validate-peer `--profile core`,
0-FAIL target at oracle `cc1970f`.
