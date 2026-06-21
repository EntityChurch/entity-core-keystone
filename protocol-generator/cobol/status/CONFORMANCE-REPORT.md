# entity-core-protocol-cobol — Conformance Report

## S2 codec — ECF corpus (v0.8.0), FFI-hybrid

**Result: PASS — 68 pass / 0 fail / 1 skip** against the pinned normative fixture
`conformance-vectors-v1.cbor` (69 vectors), byte-identical to **both** conforming
C-ABI impls (`entity-core-codec-ffi-c` and `-rust` — provenance-independent per
`ec_impl_info`). Harness: `test/codec-selftest.cob` (+ `src/cbor.cob`, `test/fileio.c`).

| Category | Vectors | Path | Result |
|---|---|---|---|
| float | 14 | COBOL transcoder (passthrough; minimization deferred to FFI) | 14 PASS |
| int | 14 | COBOL transcoder (minimal-head re-derivation) | 14 PASS |
| length | 8 | COBOL transcoder (text/bytes length boundaries) | 8 PASS |
| primitive | 6 | COBOL transcoder (true/false/null/simple) | 6 PASS |
| map_keys | 6 | COBOL transcoder (length-then-lex canonical sort) | 6 PASS |
| nested | 4 | COBOL transcoder (recursive) | 4 PASS |
| envelope | 2 | COBOL transcoder (root/included structural) | 2 PASS |
| content_hash | 4 | FFI `ec_content_hash[_with_format]` over COBOL-built data | 3 PASS, 1 SKIP |
| peer_id | 3 | FFI `ec_peerid_format`, wrapped as canonical CBOR text | 3 PASS |
| signature | 3 | FFI `ec_encode_ecf` + `ec_ed25519_sign` (signs ECF bytes) | 3 PASS |
| tag_reject | 5 | COBOL decoder: reject tag (N2) OR trailing data | 5 PASS |

**The one skip — content_hash.4 (format_code 0x80):** an honest, vector-sanctioned
skip. The C-ABI supports content_hash formats `0x00`/`0x01` only; the vector's own
note says *"impls that don't yet support arbitrary codes report unsupported rather
than emit wrong bytes."* `ec_content_hash_with_format(…, 128, …)` returns
`EC_DECODE_ERROR`, exactly that carve-out. Not a failure (S5: verified correct, not
relaxed).

### What the FFI-hybrid split exercises (A-CBL-002)

- **COBOL canonical CBOR value codec** (`src/cbor.cob`): the recursive
  canonicalizing transcoder genuinely re-derives minimal integer heads and
  re-sorts map keys (length-then-lex) — proven by `test/cbor-unit.cob` feeding
  *non-canonical* inputs (a 2-byte-encoded 24 → 1-byte; unsorted maps → sorted),
  which the canonical corpus can't (its inputs are pre-canonical). 8/8 green.
- **FFI** (`libentitycore_codec`): all crypto, SHA-2, entity 2-key framing +
  hashing, base58/peer-id, and Ed25519 signing — byte-exact, no COBOL crypto.

## S3 / S4 / S5

Pending — see `STATUS.md` and the per-phase docs.
