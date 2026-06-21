# entity-core-protocol-php — Phase S2 (Codec) Summary

**Release "reach" peer** (slate row 2) · **2nd
dynamic/scripting peer** (after Ruby #12) · **Status: COMPLETE — wire-conformance
69/69 byte-identical, GREEN.**

## Result: the gate is GREEN

| Gate | Result |
|---|---|
| **Wire-conformance corpus (v0.8.0)** | **69/69 PASS** — 64 `encode_equal` byte-identical + 5 `decode_reject` correctly rejected (2 meta rows skipped) |
| Codec spike (GMP uint64 band, f16/f32/f64 ladder, length-first map order, base58) | PASS |
| Ed25519 crypto self-tests (determinism, seed→pubkey, tamper-reject, sign-over-ECF) | PASS |
| Full PHPUnit suite | **OK (25 tests, 51 assertions), 0 deprecations** |
| Container build (ext-sodium + ext-gmp live) | PASS (build-time assertion: ed25519 64B sig, gmp>2^63, sha256+sha384) |

Run with `./run-s2.sh` (sealed-offline `--network=none`, image
`entity-core-keystone/php-toolchain:latest`, repo root mounted for the vendored
fixtures).

## The PHP-specific headline risks — all proven clean

1. **The GMP uint64 head-form carrier (A-PHP-003) — the #1 correctness risk.**
   PROVEN. CBOR integer head-form is carried as native `int` for the `< 2^63`
   common path and as `\GMP` for the `[2^63, 2^64-1]` band. The 8 wire bytes for
   the high band are assembled from the GMP value via `gmp_export` (zero-padded
   big-endian) — **never an int cast, never a float**. Decode computes in GMP and
   demotes to native int only when the value fits exactly. The spike goes BEYOND
   the corpus (which tops out at `int.10` = 2^63-1): synthetic `int.15/16/17`
   cover 2^63, 2^63+7, and 2^64-1 (max uint64), all byte-exact, all decoding back
   to `\GMP` (asserted to NOT be a lossy native type). 2^64 is rejected. The
   negative band (`-2^63-1`) is carried via GMP through the `-1-n` argument.
2. **f16 hand-roll (A-PHP-004).** PROVEN. PHP `pack`/`unpack` have no half-float
   code, so f16 is hand-assembled from the binary64 bits with the exponent-range
   `[-14,15]` guard + low-42-mantissa-bits-zero exactness guard; the four Rule-4a
   specials (`f97e00` NaN / `f97c00` +Inf / `f9fc00` -Inf / `f98000` -0.0) take
   their fixed bytes. The full ladder (f16→f32→f64, with the 65503→f32 /
   65504→f16 boundary) is corpus-green.
3. **Canonical CBOR.** Length-first (CTAP2) map ordering on encoded key bytes,
   shortest-int/shortest-float, recursive major-type-6 (tag) rejection at any
   depth, indefinite-length + non-minimal-argument + reserved-additional-info
   rejection, strict-ascending map-key-order rejection on decode (rejects
   duplicates + non-canonical order). All hand-rolled; all corpus-green.
4. **Ed25519 + SHA-256 via ext-sodium + stdlib hash().** The §9.1 floor crypto,
   native, zero Composer dep. Deterministic (RFC-8032 PureEdDSA) — the
   byte-pinned `signature.1..3` corpus vectors pass, which IS the strongest
   RFC-8032 KAT available (independently locked Go×Rust×Python). **Ed448 stays
   deferred** (A-PHP-002) — no ext-ffi pulled.

## What was built (`protocol-generator/php/`)

- `src/Cbor.php` — the hand-rolled canonical ECF encoder/decoder (byte-cursor over
  a binary string; the GMP carrier + f16 ladder live here).
- `src/Cursor.php`, `src/Varint.php` (LEB128, N1), `src/Base58.php` (Bitcoin
  alphabet, GMP-backed), `src/Hash.php` (content_hash, N1 varint prefix),
  `src/PeerId.php` (§1.5 size-cutoff), `src/Signature.php` (ext-sodium Ed25519),
  `src/KeyType.php` (8.1 backed enum).
- Value model: `src/ByteString.php` (major-2 seam), `src/EcfMap.php` (byte-keyed
  maps the corpus carries; A-PHP-007), `src/Float64.php` (explicit-float helper).
- Exceptions: `src/EntityCoreException.php` → `CodecException` →
  {`NonCanonicalEcfException` → `TagRejectedException`, `TruncatedInputException`,
  `UnsupportedValueException`} (the profile hierarchy, codec subset).
- `src/Conformance.php` + `src/ConformanceResult.php` — the corpus runner
  (decodes with THIS peer's decoder; dispatch by id-category).
- `tests/ConformanceTest.php` (the 69/69 gate), `tests/CodecSpikeTest.php` (the
  load-bearing spikes), `tests/CryptoKatTest.php`, `tests/CorpusPaths.php`.
- `composer.json` (zero runtime deps; PHPUnit 11.2.0 dev-only, pinned exactly,
  >30-day), `phpunit.xml`, `run-s2.sh`, `.gitignore`.
- `containers/php-toolchain/Containerfile` — BUILT this phase (the S1→S2
  transition). ext-sodium built-in; ext-gmp installed; build-time crypto+carrier
  assertion GREEN.

## S5 discipline honored

No test was relaxed and no vector doctored. Every disagreement during bring-up was
a CODE bug, fixed in code: (1) PHP-8 `1.0/0.0` throws → detect -0.0 by bit pattern;
(2) PHP has no `ldexp()` → reconstruct f16 via `m * (2.0 ** e)`. Both logged
(A-PHP-008), both byte-faithful.

## Ambiguity log

8 entries (A-PHP-001..008), **none blocking**, **no new spec defect** (PHP is a
corroboration-only reach peer — it corroborated the inherited cohort findings).
A-PHP-007 (value-model wrappers) + A-PHP-008 (no-ldexp / -0.0-bit-detect) are the
two PHP-impl notes this phase added; both are impl details with no spec impact.

## What S3 (peer machinery) must watch

1. **`data` is an arbitrary ECF value (A-JAVA-010).** The decoder already returns
   `data` as a general value (string / `EcfMap` / list / int / `\GMP` / `ByteString`
   / float) — S3 must NEVER assume it is a map. The `EcfMap` accessor is `->get()`
   / `->hasTextKey()`; entity field access must go through it, not array-index.
2. **The value model (A-PHP-007).** S3 builds envelopes / caps / messages on
   `EcfMap` + `ByteString`. Map keys that are content-hash BYTES must be
   `ByteString`, not PHP strings (which encode as text). The encoder canonicalizes
   ordering, so S3 builds maps in any order.
3. **The GMP carrier crosses into peer logic.** Any head-form value S3 compares
   (sequence numbers, sizes, the §4.10 chain-depth = 64 / payload = 16 MiB bounds)
   may be `int` OR `\GMP` off the wire — compare via GMP or demote carefully; never
   `(int)` a `\GMP` that may exceed `PHP_INT_MAX`.
4. **Concurrency = single-thread `stream_select` event loop (A-PHP-005).** Not
   exercised at S2; validate end-to-end at S3 (the §6.11 request_id demux, the
   §4.8 sequential-CAS store, TCP_NODELAY plumbing — fall back to a setsockopt via
   ext-sockets if the stream context proves insufficient).
5. **Ed448 stays deferred** (A-PHP-002) — the §7a/§7b core gate (`validate-peer
   --profile core`) is the Ed25519+SHA-256 floor; do not pull ext-ffi.
6. **§7a/§7b scaffolding comes from GUIDE-CONFORMANCE.md, not spec-data** (the
   profile `conformance_scaffolding` note) — a spec-data-only read at S3 would miss
   the register/outbound/emit handlers and fail S4.

## Exit criteria

wire-conformance 69/69 GREEN · codec module lints clean (`php -l` all files) ·
spike + crypto self-tests GREEN · ambiguity log has no blocking items · container
builds with ext-sodium + ext-gmp live. **S2 PASS.**
