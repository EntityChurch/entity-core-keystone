# Odin — Phase S1 (Profile) summary

**Date:** 2026-07-12
**Spec-data:** v0.8.0 (V8), the pinned snapshot
**Outcome:** profile authored, container built + verified, ambiguity log clean
(no blocking items). Ready for S2 (codec).

## Decisions made

| Axis | Decision | Class / note |
|---|---|---|
| Codec | native hand-rolled canonical CBOR | stdlib `core:encoding/cbor` is canonical-*aware* but wrong map-order + no tag-reject → hand-roll (A-005) |
| Integer model | **fixed-width `u64`** + head-form + `[2^63,2^64-1]` self-test | fixed-width class (Zig/Forth/Fortran) |
| Ed25519 + SHA | **native pure-Odin `core:crypto`** | native-pure-lang tier (Dart/CL); unaudited (A-ODIN-004) |
| Ed448 | deferred (core:crypto has none; FFI-hybrid future) | Zig/C/C++/Ada posture |
| Error model | **no exceptions** — value-return + `or_return`/`or_else` | distinct from Zig's `!T` |
| Memory | **no GC** — implicit `context` allocator; tracking-allocator in tests | Zig class, different allocator model |
| Concurrency | raw OS threads (`core:thread`); manual `sync.Mutex` §7b | raw-thread class; §6.11 = correlation-map tax |
| Build/test | `odin build`/`test` + `core:testing` | compiler-is-build-system; zero external framework |
| Packaging | **no package manager** — git-subtree vendoring; tag = publish | decentralized-by-absence |

## Toolchain verified in-container

- `odin version dev-2026-06:285f6d8`
- LLVM from Fedora 43 (supported 17-22 window), clang present
- `core:crypto/ed25519`, `core:crypto/sha2`, `core:encoding/cbor`
  (`coding`/`tags`/`marshal`), `core:math/big` — all confirmed present
- image: `entity-core-keystone/odin-toolchain:latest` (~1.95 GB — LLVM + Odin
  source tree)

## Honest framing (ADR-0012)

Corroboration / generator-robustness peer — NOT spec-discovery (the well is dry).
Value: a no-exceptions/value-error idiom, no-package-manager packaging, no-GC
context allocators, and a **native pure-Odin crypto corroboration**. A green
verdict is **cohort-consistent, not independent convergence**.

## Files produced

- `profile.toml` — complete, no TBD
- `arch/PROFILE-RATIONALE.md`
- `status/SPEC-AMBIGUITY-LOG.md` — A-ODIN-001..005, none blocking
- `containers/odin-toolchain/Containerfile` — built + verified
- `status/PHASE-S1.md` — this file

## Next (S2)

Spike the `map_keys` + `float` vectors through the hand-rolled encoder first
(cross-check the float ladder against `core:encoding/cbor`), then build the full
codec to `wire-conformance` 71/71 byte-identical vs `entity-core-codec-ffi`, plus
the `[2^63,2^64-1]` head-form self-test and a native `core:crypto/ed25519` KAT
accept-path unit (proving the pure-Odin RFC-8032 impl matches the vectors).
