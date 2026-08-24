# Odin — Phase S2 (Codec) summary

**Date:** 2026-07-12
**Spec-data:** v0.8.0 (V8)
**Outcome:** hand-rolled canonical-CBOR codec + content_hash + peer_id + native
Ed25519 signature, **71/71** wire-conformance byte-identical, plus the fixed-width
u64 head-form self-test and a native `core:crypto/ed25519` KAT accept-path.
Leak-clean under `mem.Tracking_Allocator`. Gate: `odin test test`, sealed offline.

## Gate result: 71 · 0F (71/71 PASS)

Full breakdown in `CONFORMANCE-REPORT.{md,json}`. Every category green:
float 14, int 14, map_keys 6, length 8, primitive 6, nested 6, tag_reject 5,
content_hash 4, peer_id 3, signature 3, envelope 2.

No vector failed on any run; no vector was skipped or patched; the corpus was not
touched. The corpus is decoded by this peer's OWN hand-rolled decoder (§E.3), so a
decoder bug would itself have been a conformance failure.

## What was built (package `entity_core`, src/*.odin)

| File | Contents |
|---|---|
| `errors.odin` | `Codec_Error` value-enum (no exceptions; `.None` == success) |
| `model.odin` | `Ec_Value` tagged union (arbitrary ECF `data`, A-JAVA-010); owned-tree free |
| `varint.odin` | multicodec LEB128 encode/decode (N1) |
| `cbor.odin` | canonical encoder (float ladder, length-then-lex map sort, minimal head) + decoder (recursive tag-reject N2, minimal-arg enforcement, dup-key, UTF-8, trailing-byte reject) |
| `base58.odin` | Bitcoin-alphabet Base58 (byte-wise long division; no core:math/big) |
| `hash.odin` | `content_hash` = varint(fc) ‖ SHA-256(ECF({type,data})); native core:crypto/sha2 |
| `peer_id.odin` | `peer_id_format`/`_parse`/`_from_public_key` (§1.5 size-cutoff) |
| `signature.odin` | native pure-Odin Ed25519 sign/verify/pubkey (core:crypto/ed25519) |
| `conformance.odin` | the harness (decode corpus with own decoder; dispatch by id category; byte-compare) |
| `test/conformance_test.odin` | 71/71 gate + u64/nint head-form self-tests + 2 Ed25519 KATs, all leak-checked |

## Idiom seams exercised (the generator-robustness payoff)

- **No-exceptions value-return errors** — `Codec_Error` enum threaded with
  `or_return`; every fallible proc with a trailing error return names its returns
  (an Odin `or_return` requirement discovered during the build). No panic on any
  protocol-input fault.
- **No-GC context allocators** — encode into a caller/temp buffer, decode returns an
  owned tree freed by `value_destroy`; the whole run is proven leak-free under a
  tracking allocator (a discipline the GC'd peers never authored). Notable gotcha:
  the leak assertion must run AFTER an explicit free, not rely on a `defer` (defers
  fire after the inline check) — restructured accordingly.
- **Distinct-slice cast syntax** — Odin parses `[]T(x)` as a call; a cast from a
  `distinct []u8` needs `([]T)(x)`. Purely mechanical, but a fresh-syntax trap the
  generator now knows.
- **Corpus compiled-in via `#load`** — hermetic, zero runtime IO, so the `--network=none`
  run needs no filesystem access to the vectors.

## Native crypto corroboration (the interesting bit)

The Ed25519/SHA floor is native pure-Odin (`core:crypto/{ed25519,sha2}`), FFI-free.
Beyond the 3 corpus signature vectors it is gated by two independent KATs: the
corpus's own deterministic all-zero-seed signature (byte-pinned + a verify accept
path + a tampered-byte negative control) AND RFC 8032 §7.1 vector 1 (pinned pubkey +
signature). A fresh independent RFC-8032 implementation re-deriving the same bytes —
a genuine corroboration signal, and the unaudited-crypto caveat (A-ODIN-004) is now
oracle-gated rather than asserted.

## New ambiguity-log entries

- **A-ODIN-006** — integer value model: `u64` pattern, head-form derived (not stored).
- **A-ODIN-007** — content_hash construction serialises the caller's format_code
  (§4.7 asymmetry); the registry gate is S3 verify-side, not here.
- **A-ODIN-008** — Base58 via byte-wise long division (no core:math/big on the floor).

All three are operator-local / spec-derived; none are blocking, none are a spec
ambiguity. Consistent with the dry-well framing — no new spec finding surfaced (as
expected for a corroboration peer on a saturated wire surface).

## Honest framing (ADR-0012)

Corroboration / generator-robustness. **Cohort-consistent, not independent
convergence** — the corpus bytes are a 3-way Go × Rust × Python authored artifact
(`be54baf`), and this peer reproducing them adds generator robustness on a fresh
shape + a native-crypto re-derivation, NOT a fourth independent witness to the
canonical bytes.

## Next (S3+)

Peer machinery (register/outbound/emit/owner-cap/§7a, §4.8/§4.9/§4.10 substrate) on
the raw-thread + manual-mutex model (A-ODIN-003); the §4.7 verify-side format-code
registry gate (A-ODIN-007); Ed448 stays deferred (A-ODIN-002).
