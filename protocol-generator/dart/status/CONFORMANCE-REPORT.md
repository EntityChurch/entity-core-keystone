# entity-core-protocol-dart — S2 wire-conformance report

**Corpus:** v7.71 (`protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`)
· **Image:** `entity-core-keystone/dart-toolchain:latest` (Dart SDK 3.11.6, sealed `--network=none`)
· **Result: 69/69 wire-conformance PASS, 0 FAIL · all self-tests PASS.**

## Gate

```
== ECF conformance: 69/69 PASS, 0 FAIL ==
All tests passed!   (17 package:test cases: 1 conformance group + 16 self-tests)
dart analyze --fatal-infos: No issues found!
```

Run via `./run-s2.sh` (`podman run --rm --network=none -v <repo-root>:/work:Z` → `dart pub get
--offline && dart analyze --fatal-infos && dart test`). The harness
(`lib/src/conformance/harness.dart`) decodes the normative fixture with THIS peer's OWN decoder (a
decoder bug is itself a conformance failure), runs each vector through the codec, and byte-compares
against the embedded cross-blessed `canonical` bytes.

## Corpus coverage (69 testable vectors)

| Category | Count | Path |
|---|---|---|
| float | 14 | plain ECF encode (f16/f32/f64 shortest ladder + Rule-4a specials) |
| int | 14 | plain ECF encode (minimal head; corpus tops at i64::MAX) |
| length | 8 | plain ECF encode (empty/boundary array/map/text/bytes) |
| map_keys | 6 | plain ECF encode (length-first then byte-lex; text+bytes keys) |
| primitive | 6 | plain ECF encode (null/bool/empty) |
| tag_reject | 5 | **decode_reject** — recursive major-type-6 tag scan (N2) |
| content_hash | 4 | varint(format_code) ‖ SHA-256(ECF({type,data})); fc=128 exercises N1 |
| nested | 4 | plain ECF encode |
| peer_id | 3 | CBOR-text(Base58(varint(kt)‖varint(ht)‖digest)); kt=128 exercises N1 |
| signature | 3 | Ed25519_sign(seed, ECF({type,data})) — raw 64-byte sig |
| envelope | 2 | plain ECF encode (bytes-keyed included map; full map-sort) |

Kinds: 64 `encode_equal` + 5 `decode_reject` = 69.

## Pinned conformance invariants (N1–N3)

- **N1** (varint framing): format-code / key-type / hash-type all route through the LEB128
  `Varint` primitive, not fixed bytes. `content_hash.4` (fc=128) + `peer_id.3` (kt=128) pass;
  self-test asserts `varint(128) -> 0x80 0x01`.
- **N2** (recursive tag reject): the decoder rejects CBOR major-type-6 at any depth.
  `tag_reject.1–5` pass (incl. `tag_reject.4` bare 55799 `d9 d9 f7` at the top level and
  `tag_reject.5` nested-in-included). Self-test asserts a `TagRejected` error.
- **N3** (empty map = `0xA0`): falls out of the generic map encoder. `length.2` passes; self-test
  asserts the single byte.

## Beyond-corpus self-tests (the codec-review-heuristic — author what the oracle can't see)

The corpus' `int` vectors top out at **i64::MAX** (`int.10` = 9223372036854775807). The
**[2^63, 2^64-1]** uint64 head-form band and the **-2^64** nint argument are NOT in the corpus —
exactly the band a signed-int or a bare 53-bit web int silently truncates (F7 / A-DART-006). We
author the coverage:

- **uint64 band:** `2^64-1 -> 1bffffffffffffffff`, `2^63 -> 1b8000000000000000`,
  `-2^64 -> 3bffffffffffffffff`; round-trip across the band — all via the **BigInt** carrier.
- **dart2js WEB-INT smoke** (`tool/web_int_smoke.dart`, `./run-s2.sh web`): the codec is compiled
  with `dart compile js` and **executed under node** (in-image, sealed offline). The band encodes
  byte-identically under JS-`number` semantics:
  `WEB-INT SMOKE: PASS (4 band values, no truncation)` — proving the BigInt carrier is web-safe
  (a bare `int` would 53-bit-truncate). This is the A-DART-006 proof obligation, discharged by
  EXECUTION, not just compilation.
- **float ladder boundaries:** f16-max 65504.0, smallest f16 subnormal, f32-not-f16 65503.0, f64
  1.1, all four Rule-4a specials.
- **Ed25519 RFC-8032 KAT:** all-zero seed → the known public key
  (`3b6a27bc…8b59da29`); sign/verify/tamper round-trip.
- **peer_id §1.5 canonical form (A-DART-010):** a 32-byte Ed25519 pubkey →
  `(key_type=0x01, hash_type=0x00, digest=raw pubkey)` — NOT the §7.4 SHA-256 form. (The corpus uses
  opaque digests, so this construction would only fail at the S4 handshake; baked in + asserted now.)
- **base58 leading-zero preservation** round-trip.

## S5 discipline

No vector was patched, skipped, or relaxed. The codec is byte-identical to the corpus as written.
