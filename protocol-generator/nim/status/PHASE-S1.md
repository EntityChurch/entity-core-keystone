# entity-core-protocol-nim — Phase S1 summary

**Phase:** S1 (profile research + authoring)
**Date:** 2026-07-12
**Tier:** Tier-3 (`research/LANDSCAPE.md`) — corroboration / generator-robustness
**Spec surface:** v0.8.0 / V8 (`protocol-generator/shared/spec-data/v0.8.0/`)
**Oracle target (S4):** `entity-core-go` public HEAD `cc1970f` (core-gate fingerprint
`8261a03…`, 16-category set + 53-type floor); `--profile core` target = **0 FAIL**.
**Exit status:** ✅ S1 complete — profile fully populated (no `TBD`), rationale +
ambiguity log + container authored. **No blocking ambiguity items.**

## Honest framing (ADR-0012) — REQUIRED

The alien-substrate discovery well is **DRY on the current wire surface**. Nim is a
**corroboration / generator-robustness** peer, **NOT a spec-discovery bet**. A Nim peer
passing the author's vectors is **cohort-consistent, not independent convergence** — it
shares the keystone generation lineage with the rest of the cohort; it is not an
independent clean-room implementation. A fresh spec finding would be **upside, not the
expectation** — none of the S1 ambiguity entries is a finding-candidate. The steady-state
value of this peer is (1) **generator robustness** — proving the pipeline produces an
idiomatic peer on a compiles-to-C, ARC/ORC-GC substrate whose headline axis is
**compile-time metaprogramming** (a macro/template-driven canonical codec) — and (2)
**re-running the cohort against each amendment**. It is not language #N for discovery's
sake; the wire-surface discovery axes (integer width / float model / crypto availability
/ string model) are all already covered by the existing cohort. Nim's genuine
generator-stress contribution is off-wire: the compile-time-metaprogrammed codec + the
native-C-interop crypto binding on a deterministic-GC substrate.

## What Nim is here for

Nim **compiles to C**, is statically typed, and uses ARC/ORC deterministic GC. Its
distinctive generator-stress axis is **compile-time metaprogramming** (`macro` /
`template` / `{.compileTime.}` / `static:`): the canonical ECF encoder/decoder is
expressed with compile-time major-type dispatch and zero runtime reflection — the Zig
`comptime` "render from the model" result carried onto a GC'd, C-backend substrate. Its
crypto story is the C peer's exact one — **libsodium via native `{.importc.}` interop** —
which is idiomatic precisely because Nim emits C. The nearest precedents studied (not
copied): **C** (Nim→C; libsodium; native hand-rolled codec; fixed-width uint64) and
**Zig** (compile-time dispatch codec; std-crypto-adjacent; the head-form self-test).

## Decisions (see `arch/PROFILE-RATIONALE.md` for the why)

| Surface | Decision |
|---|---|
| Codec strategy | **native** — hand-rolled canonical ECF via compile-time macro/template dispatch. **Deviates from LANDSCAPE's `ffi` guess** (A-NIM-001; the profile decides). `ffi` = documented S2 fallback. |
| CBOR | hand-rolled (A-005, Nth native peer); `seq[byte]` encoder + `openArray[byte]` index-walk decoder; f16 leg hand-rolled; macro/template compile-time major-type dispatch |
| Crypto floor | **libsodium via native `{.importc.}` C interop** (Ed25519 + SHA-256) — the C peer's choice, idiomatic because Nim→C. nimcrypto SHA-256 = FFI-free fallback only. |
| Ed448 / SHA-384 | **DEFERRED** (libsodium has no Ed448) → opt-in hybrid-FFI sub-library (C-ABI `ec_ed448_*` or OpenSSL) when agility lands (A-NIM-004) |
| Integer model | **fixed-width uint64** — maps directly to the head form; **mandatory `[2^63, 2^64-1]` self-test** (fixed-width trap; A-NIM-002) |
| String model | **static byte-vs-text** — `seq[byte]` (mt2) vs `string` (mt3); Nim `string` len is BYTE count (no EIAS trap; A-NIM-007) |
| Error model | **exceptions + `{.raises.}` effect tracking** (compiler-enforced exception sets); absent = `Option[T]`; `results` pkg rejected (A-NIM-008) |
| Memory | **ARC/ORC deterministic GC** (`--mm:orc`) — a third memory idiom (deterministic destructors + move semantics; neither tracing-GC nor manual malloc/free) |
| Concurrency | **asyncdispatch single-threaded event loop** — structural §7b store-safety; §6.11 reentry ~free (PHP/Tcl/Dart class, 4th event-loop substrate; A-NIM-006) |
| Naming | types PascalCase, procs/vars camelCase, const PascalCase, modules snake_case; lowercase tree-path hex (A-CL-009; Nim `toHex` is uppercase → force lower) |
| Build / test | `nimble` + `nim c` (→ C → gcc); stdlib **`unittest`** (`nimble test`, auto-discover `tests/t*.nim`) |
| Packaging | nimble git-indexed registry (`nim-lang/packages` PR); publish deferred like the cohort |
| Nim version | 2.2.2 (fallback 2.0.14); verified tarball install, fail-closed sha256 sentinel (A-NIM-005) |
| Container | `containers/nim-toolchain/Containerfile` authored (fedora:43 + pinned Nim + gcc C-backend + libsodium static/devel) |

## Ambiguity log state

`status/SPEC-AMBIGUITY-LOG.md` — 8 entries, **NO blocking items**, **none a finding-
candidate** (corroboration peer):
- **A-NIM-001** — codec native (vs LANDSCAPE `ffi`): research/profile-decides,
  non-blocking; S2 spike confirms, `ffi` fallback documented.
- **A-NIM-003 / 005** — S2 build gates: libsodium `{.importc.}` binding (trivial
  in-container); Nim tarball sha256 + exact patch (fail-closed sentinel). Both
  non-blocking with fallbacks.
- **A-NIM-002 / 006 / 007 / 008** — local decisions (fixed-width head-form self-test;
  asyncdispatch event loop; static byte-vs-text; exceptions + `{.raises.}`).
- **A-NIM-004** — Ed448 agility deferred (floor ships first).

Cohort-settled traps pre-resolved in `profile.toml [spec]` so S3/S4 do not re-burn them:
peer_id §1.5 canonical form (raw 32-byte pubkey, hash_type 0x00), lowercase tree-path
hex, §5.2 401/403/401 trichotomy, entity `data` as an arbitrary ECF value, §4.10
resource_bounds (413 / 400 chain_depth_exceeded / 503), §7b concurrency gate (structural
here), §5.10 verdict-timestamp determinism.

## What S2 does next

1. Build `containers/nim-toolchain:latest`; resolve **A-NIM-005** (Nim patch + tarball
   sha256; fill the fail-closed sentinel) and **A-NIM-003** (libsodium `{.importc.}`
   binding + static link — de-risk with a trivial in-container Ed25519/SHA-256 KAT).
2. Hand-roll `src/ecf.nim` (+ `base58.nim`, `varint.nim`) with macro/template compile-time
   dispatch. **First spike: the `float` and `map_keys` v0.8.0 vectors**
   (`protocol-generator/shared/test-vectors/ecf-conformance/`) — the shortest-float f16 ladder +
   length-then-lex CTAP2 ordering are the highest-bug-density legs.
3. Add the **`[2^63, 2^64-1]` head-form self-test** (fixed-width axis; A-NIM-002) as a
   codec gate — a signed-int64 carrier would silently overflow.
4. Byte-identity vs the **`wire-conformance`** oracle (71-vector v0.8.0 corpus) → 71/71,
   0 FAIL before S3.

**Codec-strategy note carried to S2:** authored `native` on the (very likely) assumption
the hand-rolled canonical spike passes — Nim's byte-manipulation + native uint64 + macros
make this a clean fit (the C/Zig result). If the spike unexpectedly fails, the documented
fallback is `ffi` (consume `libentitycore_codec`), but that forfeits the independent codec
+ the metaprogramming probe, so it is a last resort, not the default.

## Boundaries honored

Wrote ONLY under `protocol-generator/nim/` and `containers/nim-toolchain/`. Did NOT touch
`CONFORMANCE-MATRIX.md`, `research/LANDSCAPE.md`, `research/stewardship/*`, or
`docs/status/*` (overseer-owned). No git write commands run — tree left dirty for the
overseer to review + DCO-sign-commit. S1 no-toolchain boundary honored: the Containerfile
is authored, not built (no `podman build` this phase).

## Time / scope

S1 = research + authoring only. Profile has every field populated (no `TBD`). Container
authored + specified. Ambiguity log has no blocking items. **Ready for S2.**
