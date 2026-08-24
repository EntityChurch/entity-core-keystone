# entity-core-protocol-rexx — Phase S1 summary (COMPLETE)

**Phase:** S1 (research + profile authoring)
**Date:** 2026-07-11
**Peer:** #24 — the second alien-substrate probe (after Tcl #23).
**Status:** ✅ **COMPLETE** — profile + rationale + ambiguity log + container authored
AND built; every S1 substrate assumption verified in-container. No blocking items.

## The probe (why this peer exists)

Rexx is the **native-DECIMAL number model** probe. Unlike every prior peer — including
Tcl (which had a native IEEE float + `binary format R/Q`) — **Rexx has no binary
numeric type at all**: values are character strings, arithmetic is arbitrary-precision
DECIMAL (`NUMERIC DIGITS`), there is no IEEE float type, and no built-in reads or
writes IEEE bits. So the question: can a peer whose entire numeric model is decimal
carry ECF's binary integer tower + IEEE-754 float tower exactly — computing every
mantissa/exponent bit and every shortest-float decision in decimal arithmetic —
without the spec's numeric determinism leaking into ad-hoc convention? The
float/number-model axis is the highest fresh-yield surface left (peer-selection
compass). See `arch/PROFILE-RATIONALE.md`.

## Done

- **`profile.toml`** — PROMPT-CONSTANTS authored fresh from the V8 spec-data + Regina
  research. FFI-hybrid: hand-rolled pure-Rexx canonical CBOR (the decimal probe) +
  crypto over the C-ABI. Classic ANSI Rexx (Regina 3.9.6, NOT ooRexx — objects would
  blunt the probe). NUMERIC DIGITS 40 for the uint64 boundary + hash math.
- **`containers/rexx-toolchain/Containerfile`** — pinned recipe, BUILT this session.
  **All substrate probes passed** (`entity-core-keystone/rexx-toolchain:latest`):
  - **Regina REXX 3.9.6** confirmed.
  - **`D2C(n,8)` is native big-endian + `C2D` round-trips the uint64 boundary**
    (`2**64-1` → `FFFFFFFFFFFFFFFF` → back). The integer tower is FREE and clean —
    contrast Tcl's `binary format` (A-RX-001).
  - **Decimal arithmetic is exact**: `0.1 + 0.2 = 0.3` (the confirmation that there
    is no binary float creeping in — A-RX-002).
  - **`BITAND`/`BITXOR`** work (the CBOR + float bit engine).
  - **`LENGTH` counts BYTES** — the A-TCL-002 char-vs-byte-length trap does NOT arise
    here (Regina is byte-oriented, no Unicode type; A-RX-004). Simpler than Tcl on
    this seam.
  - **`rexxsaa.h` present** (regina-rexx-devel) — the crypto/net C ext is buildable.

## Findings / decisions (resolved at S1)

- **A-RX-008 — RxSock NOT packaged (RESOLVED, pivot).** fedora:43's `regina-rexx`
  ships only RexxUtil (`libregutil`) + `librxtest*`; there is **no RxSock**
  (`rxfuncadd 'SockLoadFuncs','rxsock',…` → rc 60; `find` confirms no `librxsock`).
  So the TCP substrate is folded into the SAME C external-function extension that
  carries crypto — the **COBOL `netshim.c` pattern**: one C ext exposes BSD-socket
  primitives (`EcNetListen/Accept/Connect/Send/Recv/Select/Close/Nodelay`) as Regina
  external functions alongside the `ec_*` crypto. Cleaner + more robust than chasing a
  missing package; de-risks S3. Profile `[async]` + `[deps]` updated.
- **A-RX-002 is the headline probe** (no binary float): confirmed the substrate is
  decimal-only; the S2 float codec must hand-compute IEEE bits — the deepest hand-roll
  in the cohort. Framed, not yet exercised.
- **A-RX-001/004 already de-risked** by the container probe: native big-endian ints
  and byte-native strings (no char-length trap) both work.

## Exit criteria — MET

Profile authored (PROMPT-CONSTANTS complete, no TBD blocking S2); container built and
every substrate primitive the codec depends on verified. **Next: S2** — the hand-rolled
canonical CBOR codec, the decimal→IEEE float probe, base58/varint/peer_id, and the
crypto/net C ext; target the full v0.8.0 corpus 69/69.
