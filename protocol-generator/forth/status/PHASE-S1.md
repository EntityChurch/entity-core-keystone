# entity-core-protocol-forth — Phase S1 summary (COMPLETE)

**Phase:** S1 (research + profile authoring)
**Date:** 2026-07-11
**Peer:** #25 — the fourth alien-substrate probe (after Tcl #23 EIAS, Rexx #24
native-decimal), and the FIRST stack-machine peer.
**Status:** COMPLETE — profile + rationale + ambiguity log + container authored AND
built; every S1 substrate assumption verified in-container. No blocking items.

## The probe (why this peer exists)

Forth is the **stack-machine / concatenative / typeless** probe — LANDSCAPE's "stack
machine / no types — generator stress." It is deliberately NOT a wire-axis probe (the
wire-discovery well is dry after 15+ peers); its value is **generator robustness on a
maximally-unlike control/data model**. Every prior peer had named variables, typed
values, and structured records to hang the recursive canonical-CBOR encoder and the §5
capability chain-walk on. Forth removes all three: RPN, a single shared data stack, no
named locals by idiom, no value type, and a "struct" that is only an offset into an
ALLOTed buffer. The question: can the recursive codec + chain-walk be expressed
IDIOMATICALLY on a stack substrate, or does it force awkward stack choreography that
reads as translated? Corroboration-first — a fresh spec finding is the upside, not the
expectation. See `arch/PROFILE-RATIONALE.md`.

## Done

- **`profile.toml`** — PROMPT-CONSTANTS authored fresh from the V8 spec-data + gforth
  research. FFI-hybrid: hand-rolled pure-Forth canonical CBOR (the stack-machine probe)
  + crypto over the C-ABI via gforth's in-process libcc FFI. gforth 0.7.3 (the only
  Forth fedora:43 packages). Fixed-width 64-bit cells → the fixed-width-int class.
- **`containers/forth-toolchain/Containerfile`** — pinned recipe, BUILT this session
  (`entity-core-keystone/forth-toolchain:latest`). **All substrate probes passed at
  image-build time:**
  - **gforth 0.7.3** confirmed (`gforth-0.7.3-36.fc43`).
  - **Cell width = 64-bit** (`1 cells` = 8 bytes) → uint64 in one unsigned cell; the
    fixed-width class (A-FT-001).
  - **Big-endian uint64 byte assembly** (mask+shift loop into an ALLOTed buffer; all-ones
    → byte0=0xFF byte7=0xFF).
  - **Native IEEE float bits**: `1.0e0 df!` → `0x3F` MSB (f64), `sf!` → `0x3F` MSB (f32).
    The float bits are REACHABLE NATIVELY (A-FT-002) — a real win over Rexx's decimal
    hand-roll; only the f16 leg + shortest-float ladder stay hand-rolled bit arithmetic.
  - **RECURSE** (recursive words) works — the CBOR encoder is recursive.
  - **In-process C FFI** (A-FT-005, the KEY differentiator): built an external
    `libecfake.so` exporting an `ec_*`-shaped symbol `(ptr,len,out)->int32`, bound it via
    `s" ecfake" add-lib` in a `c-library`, and CALLED it correctly in-process (status 0,
    expected result). This is a genuine libffi binding (libtool+gcc wrapper .so, dlopen'd)
    — NOT Rexx's dead rxfuncadd. Crypto binds directly; no subprocess/FIFO/co-process.
  - **unix/socket.fs loads** (A-FT-008) — a native in-process BSD-socket wordset; no
    co-process daemon needed (contrast Rexx A-RX-008).

## Findings / decisions (resolved at S1)

- **A-FT-005 (in-process libcc FFI) is the KEY differentiator vs Rexx.** gforth's
  `c-function` is a real in-process libffi call, verified against an external `.so` with
  the exact `ec_*` `(ptr,len,out)->int` shape. So the entire Rexx S3 transport pain
  (rxfuncadd dead → subprocess helper → co-process FIFO daemon → the FIFO-corruption
  finding A-RX-011) does NOT arise: crypto is a direct call, sockets are native.
  **GOTCHA banked:** the libcc wrapper `.so` is CACHED in `~/.gforth/libcc-named` keyed
  by c-library NAME — a stale cache silently binds an old `.so` missing new symbols
  (this bit the S1 probe once). Clear `~/.gforth/libcc-named` + `libcc-tmp` on a
  symbol-set change; the Containerfile probe does this.
- **A-FT-002 (native float bits) makes the float codec materially easier than Rexx.**
  gforth's SF!/DF! yield real IEEE bits; only the f16 leg + shortest ladder are
  hand-rolled (from real bits). Framed, exercised against the `float` vectors at S2.
- **A-FT-001/004 already de-risked** by the container probe: fixed-width 64-bit cells
  (head-form carrier, [2^63,2^64-1] boundary discipline) and byte-native (addr,len)
  strings (no char-length trap).
- **A-FT-000 (the stack-machine generator-stress probe)** is framed, carried into S2/S3:
  the codec value rep is offset-word structs over ALLOTed buffers + explicitly-tagged
  values; the verdict (idiomatic vs translated) is a review judgment at S2/S3.

## Cohort context (FFI-hybrid single-threaded family)

Forth joins COBOL (#22) / Tcl (#23) / Rexx (#24) as an FFI-hybrid single-thread-select
peer. The family now spans the crypto-availability + float-model gamut: decimal-only
float hand-roll (Rexx, hardest) → native-float-bits (Forth) crypto-gap substrates, all
reaching the same wire. Forth's binding is the CLEANEST of the four (in-process libffi
+ native sockets, no co-process). The novel axis is off-wire (stack-machine control/data
model), so per the peer-selection compass this adds **generator robustness**, not a fresh
wire finding — the expected and intended payoff.

## Exit criteria — MET

Profile authored (PROMPT-CONSTANTS complete, no TBD blocking S2 — only publish URLs
TBD-on-first-publish, non-blocking as across the cohort); container built and every
substrate primitive the codec depends on verified in-container; rationale + ambiguity log
written; no blocking-severity items. **Next: S2** — the hand-rolled canonical CBOR codec
(pure Forth, native float bits), base58/varint/peer_id, and the libcc crypto binding to
libentitycore_codec; target the full v0.8.0 corpus 69/69 (or the FFI differential).
