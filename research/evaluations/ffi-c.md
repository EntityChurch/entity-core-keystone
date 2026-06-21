# Evaluation — `entity-core-codec-ffi-c`

**Author:** operator (FFI review pass)
**Purpose:** Ground the library/stack choices for the C implementation of the codec C-ABI (`ffi-generator/c-abi/spec/`) with an audit trail, before writing it. Supply-chain pin discipline: only depend on releases that have passed the ≥30-day cool-down.

## Headline decision: hand-roll CBOR + Base58; libsodium for SHA-256 + Ed25519

The only third-party dependency is **libsodium**. Self-contained, statically-linkable, one well-audited dep, no Rust toolchain, maximum portability — and every canonical guarantee lives in our own code, which the spec demands.

### CBOR — hand-roll (do NOT pull a library)

| Lib | Latest | License | Why it loses |
|---|---|---|---|
| `libcbor` | 0.13.0 | MIT | DOM-tree + allocation; obscures raw-byte fidelity; determinism not its job; pre-1.0. Overkill. |
| `tinycbor` | 0.6.x / 7.0 line | MIT | Closest (streaming, low-level) but tags/float-min/CTAP2 ordering are still ours; 0.5→0.6→7.0 churn is risk. Kept as fallback primitive if hand-roll proves costly. |
| `QCBOR` | 1.6.1 stable (2024-03); 2.0 **alpha-6** only | BSD-3 | Tempting (explicitly targets CDE/dCBOR determinism) — **but determinism lives only in the 2.x alpha**, no stable release → fails the ≥30-day-stable pin rule. Re-evaluate on a future V7 bump. |
| **hand-roll** | — | Apache-2.0 (ours) | **Wins.** |

The ECF surface is a small deterministic subset; our four hard requirements — (a) shortest-float/float16 with exact specials, (b) CTAP2 length-then-bytewise key ordering, (c) reject major-type-6 anywhere, (d) byte-exact raw-slice round-trip — are exactly what a general library does differently or leaves to the caller. A correct encoder + decoder for this subset is a few hundred lines of straight-line C, no allocation in the hot path (decode operates over the input buffer and returns exact slices). Notes: keep encode+decode in one `ecf.c`; float minimization is the fiddliest part (try double→float→half, re-decode and compare, hardcode F9 7E00 / F9 8000 / F9 7C00 / F9 FC00); reject tags by failing on major type 6 in the decode dispatch.

### Crypto — libsodium (NOT monocypher)

**Resolved explicitly: monocypher does NOT provide SHA-256.** Per the monocypher manual it ships BLAKE2b + SHA-512 (optional, for its EdDSA) + Argon2 + ChaCha20-Poly1305 + X25519 + EdDSA — **no SHA-256 anywhere**. ECF needs SHA-256 for content hashing, so monocypher alone is disqualified.

Options were (A) libsodium — SHA-256 *and* SHA-512 *and* RFC-8032 Ed25519 in one audited lib; (B) monocypher + a bolted-on public-domain `sha256.c`. **Choose libsodium:** for an artifact whose entire reason to exist is conformance, the audit depth + single-source-of-SHA-256 outweigh monocypher's size win; bolting an unaudited SHA-256 reintroduces the trust problem we pay crypto to avoid. libsodium statically links cleanly (`--enable-static --disable-shared`) and downstream FFI ecosystems consume the final `.a`/`.so`, not libsodium directly. *Fallback* (if a future no-libc/constrained target can't host libsodium): monocypher + a conformance-pinned public-domain SHA-256 — but that's an explicit profile/ambiguity-log decision (S6), not the default.

### Base58 — hand-roll

~40 lines of long-division encode/decode, Bitcoin alphabet. Trezor's `base58.c` is a fine sanity reference but its vendoring license isn't cleanly stated; a dep for something this small is pure liability. Hand-roll; `wire-conformance` confirms it.

## Recommended stack + pins

| Component | Choice | Pin (≥30-day cool-down satisfied) | License | CVE notes |
|---|---|---|---|---|
| CBOR (ECF) | **hand-roll** | n/a (ours) | Apache-2.0 | — |
| SHA-256 + Ed25519 | **libsodium** | **1.0.21** | ISC | CVE-2025-69277 (low-level `crypto_core_ed25519_is_valid_point`) **does not affect us** — we use high-level `crypto_sign_*` / `crypto_hash_sha256`. CVE-2025-15444 is a Perl-wrapper packaging issue, not libsodium. |
| Base58 (Bitcoin) | **hand-roll** | n/a (ours) | Apache-2.0 | — |
| Build | **CMake** (in container), **C11** | CMake ≥3.20 | BSD | — |

## Build + drop-in `.so/.a` gotchas

- **C11**, `-std=c11 -pedantic` — widest reach across target toolchains + embedding ecosystems (Zig/Odin/Nim/Lua/OCaml). C99 only if a constrained target demands it.
- **CMake** drives both outputs from one `add_library` pair: `libentitycore_codec.a` (static) + `.so/.dylib/.dll` (shared); **link libsodium statically and privately** into both so the artifact is self-contained (spec §7). Build inside `containers/c-toolchain/` (S1); `make extract` pattern to `output/`.
- **Symbol hygiene:** `-fvisibility=hidden`, export only the `int32_t (ptr,len)` ABI entry points (version script / `__attribute__((visibility("default")))`); **localize libsodium's symbols** (version script / `objcopy --localize-hidden`) so an embedder linking their own libsodium doesn't collide. Build `-fPIC`. Public header leaks no libsodium/CBOR types — only stdint + buffers (matches the canonical `entitycore_codec.h`).
- **Cross-compile:** linux x86_64/aarch64 via the fedora container cross toolchains (or `zig cc` — strong, dependency-light, and Zig is already a downstream consumer); macOS arm64 needs osxcross/SDK or a native runner. Build/bundle the matching libsodium static archive per triple.
- Determinism is in our code, but verify float/half logic if any big-endian/unusual-FP target is in scope.

## Risks / gotchas (carry into implementation)

- **monocypher has no SHA-256** — confirmed; don't adopt expecting one.
- **QCBOR determinism is alpha-only** — not shippable under the stable-pin rule until a 2.x stable lands.
- **libsodium symbol collisions** when an embedder also links it — localize/version-script private symbols.
- **Float minimization is the highest-bug-density part** of the hand-roll — lean on `wire-conformance` + the four hardcoded specials.
- **Per-triple libsodium** — bundle the matching static archive for each platform; `zig cc` simplifies the matrix.
- **S6:** libsodium is a library choice the **profile must authorize** + S11-pin — record it, don't treat as an agent pick. Underspecified behavior (float tie-breaks, NaN payloads, decode strictness) → SPEC-AMBIGUITY-LOG, no silent guesses.

## Cross-reference

Spec: `ffi-generator/c-abi/spec/ENTITY-CODEC-C-ABI-V1.md` (§3 canonical obligations, §7 static output, §8 pins). Sibling impl: `research/evaluations/ffi-rust.md`. Invariants: `research/diagnostics/conformance-invariants.md` (N1–N4). Needs `containers/c-toolchain/` (not yet authored).
