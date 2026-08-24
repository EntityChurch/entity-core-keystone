# entity-core-protocol-datalog — Phase S2 (Codec/Crypto Seam) Summary

**Deductive-logic / query-native spec-discovery probe** · **probe tier (‡,
seam-hybrid)** · S2 completed 2026-07-16 · **Verdict: GATE GREEN** (71/71 vectors +
9/9 seam unit tests, in-container / capped / offline).

## What S2 built

The **codec/crypto SEAM half** of the Rust host — `src/codec_ffi.rs`: thin, safe
Rust `extern "C"` wrappers over `libentitycore_codec` (C-ABI 1.1). This is the peer's
ONLY crypto/CBOR/bytes surface (codec_strategy = ffi, per profile). Canonical CBOR,
content_hash, peer-id, Ed25519/Ed448, SHA-256/384 all cross this boundary. Datalog
holds no bytes and does no crypto — the host establishes facts here; the engine
derives `allow` (S3). **Nothing above the seam was built** (no sockets, framing,
dispatch, handshake, or `ascent!` rules — those are S3).

## Deliverables

| Path | Role |
|---|---|
| `Cargo.toml` | crate `entity-core-protocol-datalog`; lib target; `ascent =0.8.0` declared + pinned (unused at S2 — frozen for S3) |
| `Cargo.lock` | full transitive pin (30 packages incl. ascent/ascent_base/ascent_macro 0.8.0); un-ignored via root `.gitignore` negation (S11) |
| `build.rs` | links `libentitycore_codec` at `$ENTITY_CODEC_DIR` (rpath) — mirrors the GO-gate crate |
| `src/lib.rs` | crate root; `pub mod codec_ffi` (only the seam exists at S2) |
| `src/codec_ffi.rs` | THE S2 ARTIFACT — safe seam over the C-ABI + KAT/N1–N4 unit tests |
| `tests/conformance.rs` | wire-conformance GATE: a harness-only CBOR fixture reader drives all 71 v0.8.0 vectors through the seam |
| `run-s2.sh` | container-bound (`datalog-toolchain`), capped (`$PODMAN_RUN_CAPS`), offline (`--network=none`) |
| `status/CONFORMANCE-REPORT.md` | the green report |
| `status/PHASE-S2.md` | this file |
| `.gitignore` | build outputs (root already ignores `**/target/`; local file documents the `/tmp` target choice) |

## Gate

**Byte-identity, self-contained** (the fixture carries cross-blessed canonical bytes —
no running Go oracle at S2). `./run-s2.sh`:

- **71/71 wire-conformance PASS** (encode byte-identity + decode_reject rejection).
- **9/9 seam unit tests PASS** — provenance, SHA-256/384 KATs, Ed25519 roundtrip,
  signature.1 byte-exact, N1–N4.
- **Lint GREEN** — fmt --check + clippy -D warnings.

See `status/CONFORMANCE-REPORT.md` for the full output, the per-category dispatch
table, and N1–N4 coverage.

## Findings / ambiguity log

- **A-DL-003 — RESOLVED by byte-identity.** The v7.71-labelled `libentitycore_codec`
  produces byte-identical output for all 71 v0.8.0 vectors → the core wire IS
  unchanged across V7→V8 (proved, not assumed). No arch handoff warranted.
- **A-DL-008 (new) — content_hash.4 (format_code 128) dual-acceptance.** The C-ABI
  reports `unsupported_content_hash_format` for the synthetic ≥ 0x80 code; the vector
  permits either that OR the canonical bytes. Counted as the conformant
  report-unsupported branch (a `note:`, not a FAIL).
- **A-DL-009 (new) — SELinux build-seam.** `CARGO_TARGET_DIR` must be container-local
  (`/tmp`), not the `:Z` bind mount, or `ld` denies writing Ascent's proc-macro
  dylib. Build-tooling note; `Cargo.lock` still persists to the host.

## Notes for S3

1. The seam exposes clean Rust fns S3's fact-asserter calls: `ed25519_verify` (→
   assert `verified_signer`), `content_hash` / `encode_ecf` (mint/hash tokens),
   `decode_entity` (with N4 `.original` for forwarding), `peerid_{format,parse}`.
   **Datalog never crosses this seam** — the host verifies, then asserts readable
   facts.
2. `ascent` is already pinned in `Cargo.lock` (frozen closure). S3 adds
   `src/authority.rs` (the `ascent! { … }` §5.2/§5.5/§6.6/K-of-N rules), `src/host.rs`
   (sockets/§1.6 framing/dispatch/fact assertion), `src/main.rs` (the `--name
   NAME --validate` startup), and flips `[lib]` → add the `[[bin]]`.
3. Pre-resolved cohort traps still owed at S3: A-PD-016 (ms-precision mint
   `created_at`), A-PD-017 (open/debug seed dual-form `["*","/*/*"]`), §1.6 frame-cap,
   the resilience frame → 500, and the mandatory K-of-N accept-path unit test (A-DL-006).
4. N4 fidelity: forward `DecodedEntity.original` on any pass-through — never a
   re-encode of the decoded `data`.
