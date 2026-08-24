# entity-core-protocol-apl — Phase S2 summary (COMPLETE)

**Phase:** S2 (codec layer)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/apl-toolchain:latest` (GNU APL 1.9, source-built)
**Status:** ✅ **COMPLETE — full pinned-corpus gate 69/69 (0 fail, 0 skip); unit suite ALL PASS.**
Reproduce: `./run-s2.sh` → `make test` (container-bound, `--network=none`).
Report: `status/CONFORMANCE-REPORT.md`.

The ARRAY / value-model probe is validated: a substrate whose whole codec is base-256 `⊤`/`⊥`
over octet vectors + `⍋`-graded map-key ordering reproduced ECF's full canonical wire —
including the `[2^63, 2^64-1]` uint tower (which APL cannot hold as a native scalar at all)
via an explicit **8-octet array carrier**, and the native-IEEE float tower via **hand-rolled
arithmetic bit decomposition** (no `transfer`) — byte-identically to the corpus. The numeric
probe closed as **corroboration** (the honest, expected result); no spec defect on the
numeric seam.

## Done — files created (all under `protocol-generator/apl/`)

| File | Role |
|---|---|
| `src/status.apl` | error model (status-code + signal): EC_*-aligned codes + codec leaf-reject kinds + EV_* value-kind discriminants |
| `src/varint.apl` | LEB128 varint (N1) — recursive dfn encode + →-branch decode |
| `src/cbor.apl` | **the array-model probe**: nested (kind payload) value model + canonical ECF encode/decode + octet-array uint64 carrier + hand-rolled f16/f32/f64 bit path + shortest-float ladder + N2 tag scanner + N3 empty-map + `CborScanLen` (N4) + head-form self-test |
| `src/ffi.apl` | GNU APL native-fn (`⎕FX`) loader + wrappers: EcSha256/384, EcSeedPub, EcSign, EcVerify, EcPeerid{Fmt,Parse} |
| `src/ext/ec_native.cc` | the native-fn C++ shim binding libentitycore_codec `ec_*` (crypto/base58); the ONLY compiled artifact |
| `src/entity.apl` | entity framing composed from codec + FFI: content_hash / peer_id / sign / verify (core types only) |
| `test/conformance.apl` | the S2 GATE — corpus driver (decode with our decoder, re-encode + byte-compare; Class B via FFI) |
| `test/unit_tests.apl` | N1–N4 covering tests + accept-paths (map sort, float ladder, nint, crypto sign→verify, head-form) |
| `Makefile`, `run-s2.sh` | container-bound build + gate (builds `libentitycore_codec` if absent; compiles the shim; file-redirect run) |
| `status/CONFORMANCE-REPORT.md`, `status/PHASE-S2.md`, `status/SPEC-AMBIGUITY-LOG.md` (updated) | reports |

## Findings / decisions (S2)

- **A-APL-002/003 (the octet-array uint64 carrier) — CLOSED as corroboration.** The head-form
  self-test round-trips `{0, 2^63-1, 2^63, 2^64-2, 2^64-1}` byte-exact via the octet path;
  all 14 int + 14 float vectors green. A `>2^63` scalar is never materialized (`256⊥`/`256⊤`
  only below `2^63`; the minimal-head ladder compares octet ranges). **No spec-precision
  finding** — the array model expresses the "integer head-form is a fixed-width artifact"
  lesson exactly, and the spec forces even a no-wide-exact-integer substrate to carry the full
  unsigned tower as explicit bytes.
- **A-APL-012 (GNU APL control flow — NEW, real generator lesson).** GNU APL 1.9's `--script`
  reader rejects the `:If`/`:For` control-structure extension AND the dfn `:` guard entirely
  (even via `⍎`/`⎕FX`). The codec is authored as branch-free single-line dfns for pure
  transforms + classic **`→(cond)/label`-branch tradfns** for dispatch/stateful/looping paths.
  A durable idiom note for any future GNU APL peer (Dyalog has `:If`; GNU APL 1.9 does not).
- **A-APL-013 (GNU APL stdout-pipe hang — NEW harness gotcha).** `apl --script … | tee` hangs
  after `)OFF` (no exit when stdout is a pipe); a **file redirect** exits cleanly. The Makefile
  redirects to `build-*.log`, then `cat` + `grep` the greppable marker.
- **A-APL-014 (native-fn FFI get_near_int — NEW GNU-APL-FFI gotcha).** APL's `÷` yields a
  FloatCell even for exact division, so octet vectors built through any `÷` carry
  integer-valued float cells; the shim must read args with **`get_near_int()`** (not
  `get_int_value()`, which throws `DOMAIN_ERROR` on a FloatCell). The APL-side `≡` byte compare
  already tolerates `162.0 ≡ 162`, so only the FFI boundary was affected.
- **Float bit path — tractable via arithmetic.** The 5-bit / 8-bit exponent masks must use
  `2^k`-modulo (`32|`, `256|`), not `(2^k − 1)`-modulo — a mask-modulus bug that bit ONLY the
  Inf/NaN cases (all-ones exponent), fixed and covered by the float unit tests. The
  round-trip-verify ladder (downcast then up-cast and compare octets) guards exactness.
- **N1–N4** each has a covering unit test; the crypto **accept path** (sign→verify + tamper
  reject) is genuine, not vacuous.

## What S3 must know

- **The codec surface is ready + reusable.** `CborEncode` / `CborDecode` (returns
  `(value consumed rc)`) / `CborScanLen` (N4 original-byte span) / `ContentHash` /
  `PeeridFormat` / `PeeridParse` / `Sign` / `Verify`. Load order:
  `status → varint → cbor → ffi → entity` (encoded in the Makefile `$(MODS)`).
- **Control flow is `→`-branch tradfns, NOT `:If`** (A-APL-012). The S3 `⎕FIO[40]` select
  loop, dispatcher, and §6.11 reentry pump must follow the same idiom. Sockets are native
  `⎕FIO` (no C net-shim — A-APL-006); confirm the `--safe` gating + TCP_NODELAY `⎕FIO` code.
- **FFI args cross with `get_near_int` semantics** (A-APL-014); build/gate output must be
  file-redirected, never piped (A-APL-013).
- **Value model is a nested (kind payload) pair** with an explicit EV_* major-type
  discriminant (A-APL-011); decode threads position through workspace globals gBuf/gPos/gRc
  (single image, one thread — §7b store-safety structural).
- **Pins confirmed** at S2: 3 spec-data + 2 corpus SHA-256, all match MANIFEST.
- **Next: S3** — the live networked peer.
