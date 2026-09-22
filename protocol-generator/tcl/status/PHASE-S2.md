# entity-core-protocol-tcl — Phase S2 summary (COMPLETE)

**Phase:** S2 (codec layer)
**Date:** 2026-07-10 → 2026-07-11
**Container:** `entity-core-keystone/tcl-toolchain:latest` (built this session; Tcl 9.0.2)
**Status:** ✅ **COMPLETE — full pinned-corpus gate 69/69 (0 fail, 0 skip).**
Reproduce: `./run-s2.sh` → `make test`. Report: `status/CONFORMANCE-REPORT.md`.
The EIAS paradigm probe is fully validated: the pure-Tcl canonical CBOR codec, the
base58/varint peer_id, and the crypto-shim content_hash/signature are all byte-
identical to the corpus — including `content_hash.4` (multi-byte varint format code,
which COBOL honest-skipped). No spec defect surfaced (A-TCL-001/003 = corroboration).

## Done

- **Toolchain image built** (`containers/tcl-toolchain/Containerfile`) — resolves
  A-TCL-004 (**Tcl 9.0.2** on fedora:43, the preferred modern major) and the EIAS
  probe primitives (UTF-8 byte-length ≠ char-length confirmed; `binary` IEEE f32/f64
  + uint64 round-trip confirmed).
- **`src/cbor.tcl`** — the pure-Tcl canonical CBOR (ECF) codec, the paradigm probe:
  encode/decode over an **explicit tagged-value representation** (`{int N}` / `{bytes B}`
  / `{text S}` / `{array L}` / `{map KV}` / `{float F}` / `{bool}` / `{null}` /
  `{simple N}`). Canonical rules: minimal int/length heads, length-then-lex map-key
  sort on encoded key bytes, shortest-float ladder f16→f32→f64 (hand-rolled f16 bit
  arithmetic, A-TCL-006), recursive major-type-6 tag rejection (N2), full-consume +
  minimal-head re-validation on decode.
- **`test/spike.tcl`** — hand-picked vectors from the pinned v0.8.0 corpus across
  float / int / length / map_keys / primitive / nested / tag_reject +
  non-canonical-reject: **46 pass / 0 fail**.

## Findings / decisions

- **A-TCL-005 pivot** (cffi → C-extension shim): fedora:43 has no `tcl-cffi`; the
  crypto binding is a self-contained C shim via the Tcl stubs API (de-risked
  in-container). ffi-hybrid strategy unchanged. Profile + ambiguity log updated.
- **A-TCL-001/002/003 confirmed working** (no spec defect yet): the explicit
  tagged-value rep carries byte-vs-text (map_keys.5), int-vs-float intent, and UTF-8
  byte length correctly. The spec's major-type discipline cleanly obliges an explicit
  type tag — EIAS forced no side-channel. Corroboration so far; a finding is filed
  only if the full corpus surfaces an under-specified core field kind.
- **The `b` vs `$b` bug** (banked lesson): early spike failed 36/46 — every recursive
  codec call passed the bareword `b` instead of `$b`, so the codec operated on the
  literal string "b". Fixed by passing `$b` (buffer by value) at every call site. A
  Tcl-idiom trap worth flagging for S3.

## Remaining S2 work (next increment)

1. **`src/base58.tcl` + `src/varint.tcl`** (pure Tcl) → enables **peer_id** (base58 of
   `key_type‖hash_type‖digest` with LEB128 varints; N1) — no crypto, pure Tcl.
2. **`src/ffi/entitycore_tcl.c`** — the C-extension shim (SHA-256/384 + Ed25519
   seed→pub/sign/verify over `libentitycore_codec`), a `Makefile` to build it +
   `libentitycore_codec.so` in-container.
3. **Class B**: content_hash (format-code varint ‖ SHA-256 of canonical ECF),
   signature (Ed25519 sign of canonical entity bytes), envelope.
4. **`test/conformance.tcl`** — walk the pinned `conformance-vectors.cbor` (decode
   with our own decoder), assert every encode_equal byte-identical + every
   decode_reject throws. Target: full corpus green → S2 gate closed.

## Exit criteria — PARTIAL

Class A codec proven (spike 46/0). Full-corpus + Class-B green is the remaining gate
before S3.
