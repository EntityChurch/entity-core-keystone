# Crystal — Phase S2 (CODEC) summary

**Date:** 2026-07-12
**Spec-data:** v0.8.0 (V8), pinned snapshot
**Outcome:** hand-rolled canonical-ECF codec **71/71 byte-identical** on the
wire-conformance corpus, + fixed-width uint64 head-form self-test + Ed25519
sign→verify accept path. Gate green. No blocking ambiguities.

## Verdict

**71·0F @ `be54baf` — P71 / W0 / F0 / S0** (`--profile core`), corpus SHA-256
`9695b1f1…c6dc` (matches MANIFEST pin). Gate `crystal spec` = **89 examples, 0
failures**, run sealed-offline (`--network=none`) in
`entity-core-keystone/crystal-toolchain:latest` (Crystal 1.20.2 / LLVM 20.1.8 /
libsodium 1.0.18). See `CONFORMANCE-REPORT.{md,json}` for the per-category table.

Categories: float 14, int 14, map_keys 6, length 8, primitive 6, nested 6,
content_hash 4, peer_id 3, signature 3, envelope 2, tag_reject 5 = **71**.

## What was built (`src/entity_core/`)

- **`cbor.cr`** — the codec core. Tagged **`EcValue`** union (`Nil | Bool | EcInt |
  Float64 | String | Bytes | Array | ::Hash`). The text/byte distinction is a STATIC
  TYPE distinction (`String` vs `Bytes`) since Crystal `String` is UTF-8-validated —
  not the Ruby peer's encoding-tagged String. Integers modeled by **`EcInt(major,
  arg : UInt64)`** to carry the full `[0, 2^64-1]` / `[-2^64, -1]` head-form on
  fixed-width ints (the profile trap). Encode: minimal int head, shortest-float
  ladder (f16→f32→f64 with round-trip + all-ones-exp overflow guard; Rule 4a
  specials), length-then-lex map-key sort over ENCODED key bytes. Decode:
  non-minimal-arg reject, indefinite reject, reserved-info reject, duplicate-key
  reject, recursive major-6 tag reject (N2), UTF-8 validation, trailing-byte reject,
  depth cap 64. Bytes cursor, IO::Memory buffers.
- **`varint.cr`** — LEB128 (N1), UInt64 domain (multi-byte codes ≥ 0x80).
- **`base58.cr`** — Bitcoin alphabet, BigInt-backed (a 32/57-byte digest exceeds a
  fixed-width int); leading-zero → '1'.
- **`hash.cr`** — content_hash = varint(format_code) ‖ SHA-256(ECF({type, data})).
  format_code is caller-supplied (construction-side, not registry-gated — §4.7
  asymmetry; content_hash.4 exercises code 128). SHA-256 native `Digest::SHA256`;
  SHA-384 branch via `OpenSSL::Digest`.
- **`peer_id.cr`** — Base58(varint(kt) ‖ varint(ht) ‖ digest); §1.5 size cutoff for
  `from_public_key`. peer_id.3 exercises kt=128 multi-byte varint.
- **`signature.cr`** — Ed25519 via a DIRECT in-process libsodium C binding
  (`@[Link("sodium")] lib LibSodium` + `crypto_sign_seed_keypair` /
  `crypto_sign_detached` / `crypto_sign_verify_detached`). No shard. RFC-8032
  deterministic → byte-pinned sigs reproduce (signature.1/.2/.3 all match).
- **`conformance.cr`** — the harness (ported from the Ruby reference): decodes the
  corpus with THIS decoder, dispatches by id-category, byte-compares.
- **`error.cr`, `entity_core.cr`** — exception tree + entrypoint.

## Extra units (the direction the corpus can't cover)

- **Fixed-width uint64 head-form self-test** — `2^63`, `2^64-1`, `2^63-1` (native
  Int64), `-2^64` min-nint all carry the 9-byte head; full-range decode round-trip.
  This is the Ruby-overfit trap: `native_bignum` does NOT hold on Crystal.
- **Ed25519 accept path** — `sign`→`verify` true, tampered-sig and wrong-message
  both false (the "conformance-green can be vacuous" lesson: the corpus `signature`
  category is encode-side byte-pin only; a fail-closed peer needs the accept path
  tested independently).

## Spike-first (per S1 guidance)

The `map_keys.*` and `float.*` vectors were the target of the first compile — the
byte-key length-first sort (`map_keys.5`) and the f16 ladder (`float.9`/`.10`/`.12`
boundaries) are the fiddly seams. Both passed on the first clean compile; the full
codec then passed the remaining categories with no per-vector fixes.

## Ambiguities

No new blocking items. Added **A-CRY-007** (non-blocking, operator): map keys are
arbitrary `EcValue`s incl. byte strings (not `String`) — a Crystal-substrate
modeling consequence of the (unambiguous) spec, plus the `EntityCore::Hash` vs stdlib
`::Hash` naming-collision note. The S1 profile decided every library/idiom choice;
nothing required a spec guess.

## Honest framing (ADR-0012)

**Corroboration / generator-robustness — cohort-consistent, NOT independent
convergence.** This peer passes one author's 3-way (Go × Rust × Python) cross-blessed
corpus at oracle `be54baf`; a green verdict corroborates that the generator lands the
canonical ECF codec on a compiled, statically-typed, fixed-width-integer,
libsodium-backed substrate whose idiom seams deliberately differ from the Ruby peer.
It does not add an independent producer of the canonical bytes. The discovery well is
dry on the current wire surface; no new spec finding surfaced this run.

## Files produced

`src/entity_core/{error,varint,base58,cbor,hash,peer_id,signature,conformance}.cr`,
`src/entity_core.cr`, `bin/entity-core-peer.cr`, `spec/{spec_helper,conformance_spec,
codec_spec,signature_spec}.cr`, `tools/report.cr`, `shard.yml`, `shard.lock`,
`run-s2.sh`, `status/CONFORMANCE-REPORT.{md,json}`, `status/PHASE-S2.md`.

## Next (S3)

Peer machinery (register / outbound / emit / §7a reentry / §5.2a verdict-to-status)
atop this green codec; the CSP fiber-per-connection loop (A-CRY-005). The `bin/`
target is the S4 validate-peer / wire-conformance oracle-driver seam.
