# Crystal — Phase S1 (Profile) summary

**Date:** 2026-07-12
**Spec-data:** v0.8.0 (V8), the pinned snapshot
**Outcome:** profile authored, container built + verified, ambiguity log clean
(no blocking items). Ready for S2 (codec).

## Decisions made

| Axis | Decision | Divergence from Ruby peer (the overfit check) |
|---|---|---|
| Codec | native hand-rolled canonical CBOR | same as Ruby (A-005 pattern) — but on a typed/compiled substrate |
| Integer model | **fixed-width `UInt64`** + head-form + `[2^63,2^64-1]` self-test | **DIVERGES** — Ruby is bignum (`native_bignum=true`, no trap) |
| Ed25519 | **direct libsodium C binding** (`lib`/`fun`) | **DIVERGES** — Ruby uses stdlib openssl (Crystal stdlib openssl has no PKey) |
| SHA | native `Digest::SHA256/512`; SHA-384 via `OpenSSL::Digest` | Ruby had native SHA-384 too; Crystal splits |
| Ed448 | deferred (libsodium has none; FFI-hybrid future) | **DIVERGES** — Ruby had native Ed448 via openssl |
| Error model | exceptions + nilable-union `?` | same idiom family, compiled/typed |
| Concurrency | **CSP fibers**, single-thread default | **DIVERGES** — Ruby is GVL OS-threads |
| Build/test | shards + stdlib `spec` | analogous to Ruby bundler + minitest |

The five wire/runtime-touching divergences (integer model, Ed25519 route, SHA-384
split, Ed448, concurrency) are exactly the axes a Ruby-template overfit would get
wrong — the reason this peer earns its place as a generator-robustness probe.

## Toolchain verified in-container

- `Crystal 1.20.2 [2482c62c1] (2026-05-15)`, LLVM 20.1.8
- `Shards 0.20.0`
- `libsodium 1.0.18` (pkg-config resolves it)
- image: `entity-core-keystone/crystal-toolchain:latest` (711 MB)

## Honest framing (ADR-0012)

Corroboration / generator-robustness peer — NOT spec-discovery (the discovery
well is dry on the current wire surface). A green conformance verdict here is
**cohort-consistent, not independent convergence** (shares the generation
lineage). This is stated in the eventual CONFORMANCE-MATRIX row + S4 report.

## Files produced

- `profile.toml` — complete, no TBD
- `arch/PROFILE-RATIONALE.md`
- `status/SPEC-AMBIGUITY-LOG.md` — A-CRY-001..006, none blocking
- `containers/crystal-toolchain/Containerfile` — built + verified
- `status/PHASE-S1.md` — this file

## Next (S2)

Spike the `map_keys` + `float` vectors through the hand-rolled encoder first
(cheap insurance per PHASE-S1), then build the full codec to `wire-conformance`
71/71 byte-identical vs `entity-core-codec-ffi`, plus the `[2^63,2^64-1]`
head-form self-test and a libsodium Ed25519 accept-path unit.
