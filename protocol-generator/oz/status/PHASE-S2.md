# PHASE-S2 — codec layer — entity-core-protocol-oz

**Date:** 2026-07-15. **Verdict: COMPLETE — gate green on the first full run.**

## Gate

```
make s2  (in mozart-toolchain, sealed --network=none)
=== conformance: 71 vectors — 71 pass / 0 fail ===
```

Pinned corpus `protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`
(66 encode_equal + 5 decode_reject, the F29/F30 finalized 71). The corpus is decoded
with our own decoder (bootstrapping); Class B (content_hash / signature) crosses the
entity-codec-daemon live — so the green run co-proves the co-process seam:
`Open.pipe` spawn + binary framing + ec_sha256/ec_ed25519_sign round-trips.

## What was built

| Piece | File | Notes |
|---|---|---|
| Canonical CBOR | `src/cbor.oz` | tagged rep; minimal heads; length-then-lex key sort; dup-key reject; definite-only; recursive mt6 tag reject; UTF-8 validity; `DecodeCanonical` = structural decode + byte-identical re-encode compare (full canonical enforcement in one primitive) |
| Float tower | in `src/cbor.oz` | A-OZ-002: floats carried as exact binary64 bit patterns (bignum ints); shortest-form f16/f32/f64 ladder + Rule 4a specials in PURE integer arithmetic (odd-mantissa/exponent decomposition; subnormals exact); f16/f32 widening exact — no VM float arithmetic anywhere |
| LEB128 varint | `src/varint.oz` | N1: real varint primitives (multi-byte pinned by content_hash.4 / peer_id.3) |
| Base58 | `src/base58.oz` | Bitcoin alphabet, bignum div/mod, leading-zero `1`s |
| peer_id | `src/peerid.oz` | Base58(varint(kt) ‖ varint(ht) ‖ digest), width-agnostic |
| Daemon | `src/daemon/eccodecd.c` + `DAEMON-PROTOCOL.md` | the entity-codec-daemon convention (A-OZ-004): binary length-prefixed framing over stdin/stdout; ops SHA256/SHA384/ED25519_{PUB,SIGN,VERIFY}/ED448_*/NOW(ms)/RND; rpath'd against the ffi-c `libentitycore_codec` build |
| Daemon client | `src/crypto.oz` | port agent owns the pipe (one owning thread; requests carry dataflow reply variables) |
| Harness | `test/conformance.oz`, `run-s2.sh`, `Makefile` | hand-rolled (no Oz test framework) |

## Notes for S3

- N3 (empty map = `0xA0`) covered by length.2; N2 tag scanner recursive (tag_reject.5
  nested-included case passes); N4 original-byte fidelity is an S3 entity-layer
  concern (keep decoded-frame original bytes alongside values).
- The bignum claim (A-OZ-001) held through the full int battery incl. the u64
  boundary vectors.
- Agility corpus (8 vectors) not run as a byte gate here (cohort convention: the
  live crypto_agility category at S4 covers the surface); the daemon carries the
  ed448/sha384 ops it would need.

No new ambiguities beyond A-OZ-001…004 (see SPEC-AMBIGUITY-LOG.md).
