# entity-core-protocol-rexx — Profile Rationale (S1)

For architecture review. Why the `profile.toml` decisions are what they are, and what
this peer is meant to surface. Peer #24, the second alien-substrate probe.

## The axis: native-decimal number model (highest fresh yield left)

The peer-selection compass says spec-discovery yield is *substrate*-bound and lives on
the wire-touching axes (integer width / float model / crypto availability / string
model). After 23 peers, integer-width and crypto-availability are saturated; the
**float/number model** from a genuinely alien base is the least-saturated surface. Tcl
(#23) probed the string/encoding axis (EIAS) but still had a native IEEE float type and
`binary format R/Q` to reach its bits.

Rexx removes the last binary numeric crutch. **There is no binary numeric type at
all:** every value is a character string; arithmetic is arbitrary-precision DECIMAL
(`NUMERIC DIGITS`); there is no IEEE float type and no built-in that reads or writes
IEEE bits. So the ECF binary integer tower (mt0/1) and IEEE-754 float tower (mt7,
shortest-form ladder) must be reproduced from a decimal base — every mantissa/exponent
bit computed by decimal arithmetic. That is the probe (A-RX-002): does the spec's
numeric determinism survive a round-trip through a substrate that shares none of its
binary assumptions?

## Codec: FFI-hybrid (native decimal CBOR + C-ABI crypto)

- **CBOR hand-rolled in pure Rexx** — the eighth peer to confirm no platform lib gives
  canonical ECF (A-005). The *integer* half is unusually clean: `D2C(n,len)` is native
  big-endian and `C2D` is exact to `NUMERIC DIGITS` (verified at S1). The *float* half
  is the deepest hand-roll in the cohort — even f32/f64 have no helper, unlike Tcl.
- **Crypto over the C-ABI** — Regina has no crypto, so `libentitycore_codec` is bound
  from the start via a C external-function extension (Regina SAA API, `rexxsaa.h`),
  the COBOL/Tcl FFI-hybrid shape. Ed25519 + SHA cross the boundary; everything else is
  pure Rexx.

## Interpreter: Regina, not ooRexx

fedora:43 packages **Regina 3.9.6** (classic ANSI Rexx); ooRexx is not packaged and
would blunt the probe anyway — its object model reintroduces typed values, defeating
the point. Classic Rexx is the pure decimal-string substrate we want to stress.

## Concurrency + transport: single-thread select, sockets via the C ext

Classic Rexx has no threads. The S1 container build disproved the RxSock assumption
(fedora Regina ships no RxSock — A-RX-008), so sockets are folded into the crypto C
ext (the COBOL `netshim.c` pattern): one C ext exposes `EcNet*` BSD-socket primitives
alongside the `ec_*` crypto. The peer is a single-threaded `EcNetSelect` loop →
structural §7b store-safety (one interp, one thread, no lock); §6.11 reentry is a
manual pump (the correlation-map tax the non-actor/non-CSP peers pay).

## What we expect

Corroboration/robustness first — a fresh spec finding is the upside, not the
expectation. The most likely finding surface is the shortest-float selection under a
decimal↔IEEE round-trip (is any float vector's canonical form ambiguous without a
stated rounding mode?). Most likely outcome: the spec is tight, the peer computes the
IEEE bits exactly from decimal, and the probe closes as corroboration — which is itself
the answer (the spec is precise enough to force even a decimal-only substrate to carry
the binary numeric tower with no side-channel).
