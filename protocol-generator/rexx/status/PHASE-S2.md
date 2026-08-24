# entity-core-protocol-rexx — Phase S2 summary (COMPLETE)

**Phase:** S2 (codec layer)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/rexx-toolchain:latest` (Regina Rexx **3.9.6**)
**Status:** ✅ **COMPLETE — full pinned-corpus gate 69/69 (0 fail, 0 skip).**
Reproduce: `./run-s2.sh` → `make test` (container-bound, `--network=none`).
Report: `status/CONFORMANCE-REPORT.md`.

The decimal-number-model probe is fully validated: a substrate with **no binary
numeric type at all** reproduced ECF's binary integer tower AND IEEE-754 float tower
byte-identically to the corpus — every mantissa/exponent bit computed in decimal
arithmetic. No spec defect surfaced (A-RX-002/003 = corroboration, like Tcl).

## Done

- **`src/cbor.rex`** — the pure-Rexx canonical CBOR (ECF) codec, the paradigm probe:
  encode/decode over an internal self-delimiting tagged-value STRING (EIAS-aligned).
  The integer tower is native + clean (`D2C(n,len)` big-endian, `C2D` exact to
  `NUMERIC DIGITS 200`). The **FLOAT tower is fully hand-rolled** — Rexx has no IEEE
  type and no bit-view built-in, so f16/f32/f64 encode/decode + the shortest-float
  ladder + canonical NaN 0x7e00 are computed with `%` (shift-right), `//` (mask),
  `*2**k` (shift-left) and `D2C`; the codec round-trip stays in IEEE-bit-space (a
  decoded float is stored as its f64 pattern; encode narrows down the ladder).
- **`src/{varint,base58,peerid}.rex`** — pure Rexx (decimal bignum base-256↔base-58);
  peer_id all 3 pass (incl. the N1 multi-byte varint peer_id.3).
- **`src/ext/eccrypto.c`** — the crypto helper BINARY (A-RX-005 pivot; see findings),
  binding `libentitycore_codec` SHA-256/384 + Ed25519 over a hex stem-pipe. Built by
  `make ext` (gitignored). content_hash + signature pass, incl. `content_hash.4`
  (multi-byte varint format code, which COBOL honest-skipped).
- **`test/{spike,conformance}.rex`**, `Makefile`, `run-s2.sh`.

## Findings / decisions (S2)

- **A-RX-002 (the float probe) — CLOSED as corroboration.** The decimal substrate
  encodes/decodes every IEEE float vector exactly (14 float vectors green). The spec's
  numeric determinism (shortest-form ladder, canonical NaN/±Inf/±0, uint64 boundary)
  survives a substrate that shares NONE of its binary assumptions. No spec-precision
  finding — the deepest hand-roll in the cohort, and it holds.
- **A-RX-005 — RESOLVED (pivot to a helper binary).** fedora Regina 3.9.6 does NOT
  load dynamic external-function libraries via `rxfuncadd` (rc 60 even for the
  built-in `regutil`; `strace` shows no dlopen attempt). But `ADDRESS SYSTEM cmd WITH
  INPUT STEM / OUTPUT STEM` works. So the crypto crosses the C-ABI via a standalone
  `eccrypto` helper binary over a hex stem-pipe — still FFI-hybrid, at the process
  boundary. Simpler C than an SAA extension. The original SAA C-ext was written and
  discarded when `rxfuncadd` proved non-functional.
- **Two banked Regina lessons** (durable, in `SPEC-AMBIGUITY-LOG.md`): (1) Rexx
  forbids an EXPRESSION subscript (`idx.(j-1)`) — a compound-var tail must be a plain
  symbol; the mis-parse becomes a silent shell command. (2) Regina does NOT propagate
  a SYNTAX condition across a `CALL` boundary to a caller's `SIGNAL ON SYNTAX` (only a
  same-routine or MAIN-level trap fires), so the reject/unwind is the classic-Rexx
  **RC-flag** (`EC.!OK`), not exceptions — which also simplifies the S3 dispatch.

## Exit criteria — MET

Full-corpus 69/69 green. **Next: S3** — the live networked peer. The RC-flag error
model + the helper-binary crypto both carry into S3; the transport folds BSD sockets
into the same helper-binary bridge (A-RX-008, the COBOL netshim shape).
