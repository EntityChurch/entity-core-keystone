# SPEC-AMBIGUITY-LOG — entity-core-protocol-wasm-wat

Per-peer log of substrate decisions, profile choices, and any spec ambiguities surfaced
during the build (the asm peer's A-ASM-NNN convention, here A-WAT-NNN). Most entries are
**substrate/profile decisions**, not spec defects — this is a substrate probe on a saturated
wire surface, so a spec-discovery finding would be the exception. Genuine spec ambiguities (if
any) are additionally routed per AGENTS-STANDARD (log locally, escalate upstream via
`research/`); nothing here is a spec defect so far.

Legend: **[decision]** a build/profile choice · **[finding]** something the substrate taught
· **[open]** carried into a later phase.

---

- **A-WAT-001 [decision] — Runtime + sockets = WasmEdge flat `wasi_snapshot_preview1`.**
  WASI preview1 has no sockets; WASI 0.2 `wasi:sockets` is Component-Model-only (not
  hand-authorable in core WAT). WasmEdge (fedora-packaged) exposes flat Berkeley-socket
  imports raw WAT can call directly — the WASM analog of asm syscalls, no native host, no
  Component Model. Chosen over Wasmer WASIX because it's dnf-pinnable (S11-clean, no
  `curl | sh`). **Proven:** `echo.wat` verbatim loopback echo. See PROFILE-RATIONALE.

- **A-WAT-002 [decision] — Codec strategy = SEAM (Rust codec → wasm, `wasm-merge`'d).**
  A WASM module can't `dlopen` native code, so the codec must live in the wasm world. The
  Rust codec compiles to wasm32-wasip1 cleanly (pure-Rust crypto); the C codec's static
  libsodium does not. The interior imports the codec's exported memory + `ec_*`; binaryen
  `wasm-merge` fuses them over one shared memory (the `ld` analog) on a stock runtime.
  **Proven:** `ffi-smoke.wat` `ec_sha256("abc")` KAT byte-exact. See PROFILE-RATIONALE.

- **A-WAT-003 [decision] — Ed448 agility deferred.** `ec_ed448_*` is compiled into
  `codec.wasm` (the Rust codec carries it) but agility is not in the core floor; deferred like
  the cohort. Mirrors asm A-ASM-002.

- **A-WAT-004 [decision] — Envelope/data-map CBOR hand-rolled in WAT.** The seam's
  `ec_encode_ecf` decomposes *entities*, not the envelope `{root, included}` map nor the
  EXECUTE/RESPONSE `data` map. Those small fixed-shape maps are hand-rolled in WAT with keys
  emitted pre-sorted; the shortest-float ladder / tag-reject / general key-sort stay behind
  the seam. Direct analog of asm A-ASM-004. LEB128 head-form for the envelope integers is
  hand-rolled too.

- **A-WAT-005 [open] — `codec.wasm` committed-artifact home.** Currently the cargo `target/`
  output, built ad-hoc. Like `libentitycore_codec.so` it should be a reproducible,
  provenance-clean committed build output — an `ffi-generator` wasm shape (the README names a
  future `rust-wasm`/`wasm-abi` shape). Cross-arm: route through `research/` / a HANDOFF note;
  do NOT reach into `ffi-generator/` unilaterally. Formalize before S4/publish.

- **A-WAT-006 [decision + open] — Concurrency is substrate-forced: single-thread poll +
  `pending_tab`.** No fork, no threads (Level 1), so the asm peer's eventual fork-per-connection
  model is unavailable — the substrate forces the single-threaded event loop, which is exactly
  the A-ASM-014 template (request/response frame router + `pending_tab` demux for §7a.2a
  one-socket reentry). Multiple connections multiplex cooperatively via WASI `poll_oneoff` over
  non-blocking fds. **[open]** confirm the non-blocking-flag mechanism (`fd_fdstat_set_flags`
  `FDFLAGS_NONBLOCK`) under WasmEdge in increment 3.

- **A-WAT-007 [finding] — Trap-on-OOB has no blast-radius absorber.** On asm, an over-cap frame
  crashed one *fork* (A-ASM-010); the connection multiplex survived in other forks. A WASM peer
  is a *single process/module*, so a bounds trap kills everything. The A-ASM-010 discipline
  (size to the 16-MiB cap, drain + 413, bounds-check every buffer op *before* the access)
  is therefore sharper here — the trap is a last-resort backstop, never a handled path.
  Frame-cap (§1.6) is load-bearing on the single memory + single thread (the TurboWarp lesson).
