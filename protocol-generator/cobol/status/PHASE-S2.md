# entity-core-protocol-cobol — Phase S2 summary

**Status:** COMPLETE. **Gate:** codec corpus 68/0/1 (PASS).

## Built

- `src/cbor.cob` — the canonical CBOR value codec (A-CBL-002): recursive
  canonicalizing transcoder (`cbor-canon`) + `emit-head` (minimal-int) +
  navigation primitives (`cbor-read-head`, `cbor-skip`, `cbor-find-key`).
- `test/cbor-unit.cob` — 8/8 transcoder unit tests (minimization + map sort that
  the canonical corpus can't exercise).
- `test/codec-selftest.cob` + `test/fileio.c` — corpus harness: walks the pinned
  `conformance-vectors-v1.cbor`, dispatches structural→transcoder, crypto→FFI,
  reject→decoder. 68 pass / 0 fail / 1 honest skip vs **both** C and Rust C-ABI impls.

## Decisions / findings

- **FFI-hybrid split confirmed working** (A-CBL-002): COBOL owns the canonical CBOR
  value layer; FFI owns crypto/SHA-2/entity-framing/peer-id/signing.
- **Signatures sign the ECF bytes** of the entity (`ec_encode_ecf` then
  `ec_ed25519_sign`), per the OCaml reference — not the content_hash.
- **peer_id canonical = CBOR text** wrapping the base58 string (FFI returns raw).
- **A-CBL-003** (new): `tag_reject.1/2/3` contain no tag bytes — they reject via
  trailing-data; full-consume checking is required, not just N2 tag-reject.
- **content_hash.4 skip**: format_code 0x80 unsupported by the C-ABI, per the
  vector's own carve-out (verified correct, not relaxed — S5).

## COBOL lessons banked for S3

- RECURSIVE programs need ALL per-frame state in LOCAL-STORAGE (WORKING-STORAGE is
  static — corrupts recursion). The transcoder + map-sort proved this.
- 1-byte numeric view = `PIC 9(2) COMP-X` (9(3) is 2 bytes).
- Reserved words bite: `STATUS`, `CURSOR` → renamed.
- FFI: `-fstatic-call` + `-L… -lentitycore_codec`; `BY REFERENCE buf(off:len)`
  passes the slice address; `BY VALUE` for size_t; `RETURNING` for int32.

## Exit criteria — met

Codec conformance green (68/0/1) byte-identical to both reference C-ABI impls;
unit tests green; ambiguity log updated; codec compiles clean. Next: **S3 peer
machinery** (identity/store/wire/dispatch/capability/transport over this codec + FFI).
