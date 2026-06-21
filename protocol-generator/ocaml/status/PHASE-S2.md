# entity-core-protocol-ocaml — Phase S2 (Codec) Summary

**Status: COMPLETE — 69/69 wire-conformance, first run, 0 fixes**

## What was built (`src/`, library `entitycore_codec`)
| Module | Responsibility |
|---|---|
| `cbor.ml`    | Canonical ECF encode/decode; half-float (f16) minimisation; length-then-lex map ordering; recursive tag rejection; `Uint/Nint of int64` (unsigned, full 64-bit range) |
| `varint.ml`  | LEB128 encode/decode (N1) |
| `base58.ml`  | Bitcoin-alphabet encode + decode (leading-zero preserving) |
| `hash.ml`    | `content_hash = varint(fc) ‖ HASH(ECF({type,data}))`; SHA-256/384 via digestif |
| `peer_id.ml` | `Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)` + parse |
| `sign.ml`    | Ed25519 sign/verify/pub via mirage-crypto-ec |

Tests: `test/conformance.ml` (loads the normative fixture, byte-checks all 69) +
`test/selftest.ml` (uncovered-range probes).

## How conformance works here
The `conformance-vectors-v1.cbor` fixture carries its own cross-blessed `canonical`
bytes per vector, so S2 is self-contained — the harness decodes the fixture and
compares byte-for-byte. The Go `wire-conformance` binary is the fixture
producer/cross-blesser, not a runtime checker; no live oracle needed at S2.

## Key implementation notes (the corners that mattered)
- **OCaml int63 (A-OC-001):** CBOR integers carried as `Int64` interpreted unsigned
  (`Int64.unsigned_compare` for all width decisions) — native `int` truncates at 2^62
  and can't hold corpus `int.10` (2^63-1).
- **Half-float:** round-to-nearest-even f64→f16, emitted only when it round-trips
  bit-exactly through f16→f64 (so an imperfect subnormal path can never emit wrong
  canonical bytes — only fall back to f32/f64). f32 via `Int32.bits_of_float`. NaN
  canonicalised to `f97e00`; ±0/±Inf via bitwise equality. Passes the f16/f32/f64
  boundary vectors (65472/65503/65504) exactly.
- **Map ordering:** sort entries by the *encoded* key bytes, length-first then
  bytewise-lex — covers text-key, byte-key, and mixed-key vectors.
- **format_code 128 (A-OC-004):** emitted as `varint(128) ‖ sha256(ECF)` on the
  construction side (passes `content_hash.4`); the receive-side rejection asymmetry
  vs `VARINT-MULTIBYTE-1` is logged for arch.

## Exit criteria
All 69 vectors PASS · selftests PASS · `dune build` clean (warnings-as-errors) ·
ambiguity log has no blocking codec items · container reproducible. **S2 PASS.**

## Not in this phase (S3+, next session)
- Peer machinery (connection, dispatch, capability, store, processor) — needs the
  eio async decision validated and the F12/v7.73 spec resync.
- Agility corpus (Ed448 + SHA-384 matrix) — gated on A-OC-002.
- `.mli` interfaces for the codec modules (author before S5).
