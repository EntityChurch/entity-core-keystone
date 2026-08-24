# entity-core-protocol-nim — Phase S2 summary

**Phase:** S2 (codec layer)
**Date:** 2026-07-12
**Spec surface:** v0.8.0 / V8 (`protocol-generator/shared/spec-data/v0.8.0/`)
**Corpus:** `test-vectors/v0.8.0/conformance-vectors-v1.cbor` (71 vectors; sha256
`9695b1f1…7c6dc`, the F29/F30 re-vendor)
**Exit status:** ✅ S2 complete — **wire-conformance 71/71 PASS, 0 FAIL**, first
compile-run, 0 codec fixes. Container built + sha-verified. No blocking ambiguity.

## Gate result

**`wire-conformance` = 71/71 PASS, 0 FAIL** (byte-identical to the cross-blessed
corpus). Per-category: float 14/14 · int 14/14 · map_keys 6/6 · length 8/8 ·
primitive 6/6 · nested 6/6 · tag_reject 5/5 · content_hash 4/4 · peer_id 3/3 ·
signature 3/3 · envelope 2/2. Full breakdown in `CONFORMANCE-REPORT.{md,json}`.

**Fixed-width head-form self-test (A-NIM-002):** `[2^63, 2^64-1]` round-trip
**PASS** on the native **`uint64`** carrier — proven at compile time (a `static:`
block in `src/ecf.nim` runs the encoder in the Nim VM) AND at run time (encode →
decode → re-encode byte-identity). A signed-int64 carrier would overflow this
band; the uint64 carrier does not. Built `--overflowChecks:on`; every decoder
read is explicitly bound-checked.

## What was built

Native hand-rolled codec under `src/` (profile [codec] strategy = native; the
`ffi` fallback was NOT needed):

| Module | Role |
|---|---|
| `src/errors.nim` | exception hierarchy (EcError → EcCodecError / EcCryptoError); fail-closed rejects, `{.raises.}` effect tracking |
| `src/ecf.nim` | canonical ECF encoder/decoder — `template` head emission (compile-time inlined major-type selection), shortest-float f16/f32/f64 ladder, length-then-lex map ordering, recursive mt6 tag reject (N2), full uint64/nint range, `static:` compile-time self-test |
| `src/varint.nim` | multicodec-style LEB128 (N1) |
| `src/base58.nim` | Bitcoin-alphabet long-division encode/decode |
| `src/content_hash.nim` | `varint(fc) ‖ SHA256(ECF({type,data}))` |
| `src/peer_id.nim` | `Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)` + parse |
| `src/crypto.nim` | libsodium via native `{.importc, header:"sodium.h".}` — Ed25519 (deterministic detached) + SHA-256 |
| `src/entity_core_protocol.nim` | umbrella re-export |
| `tests/tconformance.nim` | the wire-conformance harness (loads corpus, byte-identity + self-test) |
| `entity_core_protocol.nimble` | manifest (`nimble conformance` task) |
| `run-wire-conformance.sh` | container-sealed gate runner |

## Container (A-NIM-005 resolved)

`containers/nim-toolchain/Containerfile` built as
`entity-core-keystone/nim-toolchain:latest` (fedora:43 + Nim 2.2.2 + gcc C-backend
+ libsodium static/devel). The fail-closed sha256 sentinel was **filled +
verified**: `nim-2.2.2.tar.xz` sha256
`7fcc9b87ac9c0ba5a489fdc26e2d8480ce96a3ca622100d6267ef92135fd8a1f`, cross-checked
against BOTH the tarball download AND the official `nim-2.2.2.tar.xz.sha256`
sidecar (both matched). Nim bootstraps cleanly from source (`build.sh` + `koch
tools`). Built with the standard capped invocation (`$PODMAN_BUILD_CAPS`, caps
not overridden).

## Ambiguity-log deltas

No new blocking items; no new findings (corroboration peer). S2 confirm-items
from S1 resolved:

- **A-NIM-001** (codec native vs LANDSCAPE `ffi`) — **CONFIRMED native.** The
  hand-rolled canonical spike passed 71/71 first-run; `ffi` fallback unused.
- **A-NIM-003** (libsodium `{.importc.}` binding) — **CONFIRMED.** SHA-256 +
  deterministic Ed25519 link + run in-container; content_hash + signature vectors
  green.
- **A-NIM-005** (Nim tarball sha256) — **RESOLVED.** Digest filled + verified;
  image built.
- **A-NIM-002** (fixed-width self-test) — **ENFORCED + PASSING** (compile-time +
  run-time).

## Boundaries honored

Wrote ONLY under `protocol-generator/nim/` and `containers/nim-toolchain/`. Did
NOT touch `CONFORMANCE-MATRIX.md`, `research/LANDSCAPE.md`,
`research/stewardship/*`, `docs/status/*`, spec-data, or the corpus (all
overseer/arch-owned). No git write commands run — tree left dirty for the
overseer to DCO-sign-commit.

## What S3 does next

Peer machinery (V8 Layers 1–4): store (plain `std/tables`, structurally race-free
under the single `asyncdispatch` event thread — A-NIM-006), dispatch (§6.6 /
§6.11 reentry via a request_id pending table), transport (`asyncnet` +
TCP_NODELAY), identity/capability, the §9.5 53-type registry (render-from-model),
and the §7a validate handlers + §7b/§4.10 conformance scaffolding from
GUIDE-CONFORMANCE. Cohort-settled traps are pre-baked in `profile.toml [spec]`.
