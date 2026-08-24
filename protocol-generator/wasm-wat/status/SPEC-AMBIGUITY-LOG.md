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

- **A-WAT-008 [finding + decision] — the `peers` grant dimension was never checked at dispatch;
  fixed per `peers-grant-dimension-oracle-gap.md`.** `$grant_scope_ok`
  / `$op_scope_ok` walked `operations`→`handlers`→`resources` only; `"peers"` (`$t_035`) was
  parsed into the seed-grant type-registry entity but never read back — a §5.2 MUST-violation
  (handoff §0/§1). Fixed: `$derive_handler` now also derives `g_tpp`/`g_tplen`
  (`extract_peer` — the EXECUTE uri's first path segment when it is peer-id-shaped
  [`$is_peer_id_seg`, ≥46-char base58, byte-exact parity with `rust/src/peer/capability.rs`
  `is_peer_id`], else `local_peer_id`); a new `$peers_scope_ok(grant, target, tlen)` defaults an
  absent `peers` key to `{include:[local_peer_id]}` and otherwise checks include (reusing
  `$resource_matches` — the same literal bare-`*`/trailing-`/*`/exact matcher already used for
  `resources`, since wasm-wat applies no per-dimension frame canonicalization) AND NOT exclude;
  wired into both `$grant_scope_ok` and `$op_scope_ok`'s per-grant loop.
  **Scope decision:** implemented include+exclude for `peers` specifically (mirroring
  `rust`/`python`'s `check_permission` exactly, since the task named them as the reference
  shape), but did **not** retrofit `exclude` onto the pre-existing `operations`/`handlers`/
  `resources` checks — that is the separate, already-tracked F40 id-scope-typing gap
  (`F40-asymmetry-audit.md` lists wasm-wat among the 13 peers with
  `id-scope` "type-declared but not acted on"). Confirmed via a direct A/B run against the
  pinned oracle (fceb61f) with this fix stashed vs. applied: **identical** result both ways —
  `718 total (294 P / 322 W / 1 F / 101 S)`, the sole FAIL being the pre-existing
  `authz.f40_id_scope_exclude_literal` (operations-dimension canonicalization, unrelated to this
  fix) — so this change adds zero new FAILs. (The baseline `output/scratch/census/wasm-wat.json`
  reads `719` total / 0 FAIL from 2026-07-28; the `719`→`718` delta reproduces identically with
  and without this fix — `authz.f40_id_scope_include_control` not appearing in either run — so
  it is pre-existing oracle/harness run-to-run variance, not a regression from this change.)
  New offline regression guard (`src/dispatch-test.wat` / `make dispatch-test`): the go-oracle
  has zero vector coverage of the `peers` dimension (handoff §0), so this is the only guard —
  4 assertions, default-scope accept/reject + explicit include/exclude accept/reject, plus two
  `is_peer_id_seg` sanity checks.
