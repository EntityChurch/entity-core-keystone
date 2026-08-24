# entity-core-protocol-julia — PHASE-S1 (Profile) report

**Phase:** S1 (profile research + authoring) · **Target:** Julia · **Date:** 2026-07-12
**Spec:** v0.8.0 / V8 (pinned snapshot) · **Oracle:** cc1970f (S4/S2 confirm)
**Status:** COMPLETE — all deliverables produced, no blocking-severity ambiguity.

## Honest framing (ADR-0012) — REQUIRED

The alien-substrate spec-discovery well is **DRY** on the current wire surface. Julia is a
**corroboration / generator-robustness** peer (LANDSCAPE Tier 3), **NOT** spec-discovery. A
Julia peer passing the author's vectors is **cohort-consistent, not independent
convergence** — it shares the generation lineage and validates against one author's oracle;
that is corroboration, not an independent second implementation. A fresh spec finding is
**upside, not the expectation.** Julia's value is corroborating the settled cohort on a
fresh substrate and exercising generator robustness on its novel *idiom* axes (multiple
dispatch, native UInt64+BigInt, UTF-8-native strings, Task concurrency) — none of which is
wire-novel enough to expect a finding.

## Deliverables (S1 gate)

| Deliverable | Path | State |
|---|---|---|
| profile.toml | `protocol-generator/julia/profile.toml` | written, every field populated, no blocking TBD |
| rationale | `protocol-generator/julia/arch/PROFILE-RATIONALE.md` | written |
| container | `containers/julia-toolchain/Containerfile` | authored (fedora:43 + pinned Julia tarball; sha256 sentinel → S2) |
| ambiguity log | `protocol-generator/julia/status/SPEC-AMBIGUITY-LOG.md` | 8 entries, all non-blocking |
| phase report | `protocol-generator/julia/status/PHASE-S1.md` | this file |

## Key decisions

1. **Codec strategy = NATIVE** (not the keystone C-ABI FFI-hybrid). Hand-rolled canonical
   CBOR in pure Julia (A-005 pattern; `CBOR.jl` declined — no ECF guarantees), SHA-256/384
   from the `SHA` **stdlib**, Ed25519 from **system libsodium via `ccall`** (the
   native-audited-lib crypto tier, Elixir/Haskell class — Sodium.jl declined for the
   network-fetch + thin-need reasons). base58 + varint hand-rolled over BigInt. The shipped
   floor peer is **self-contained**: Julia stdlib + system libsodium, zero registered
   packages, no `libentitycore_codec` — the container builds `--network=none`.

2. **Crypto floor + Ed448.** Floor = Ed25519 (libsodium ccall) + SHA-256/384 (stdlib),
   native. Ed448 agility is **deferred** to an **opt-in hybrid-FFI sub-package** over the
   C-ABI (`ec_ed448_*`) because libsodium has **no Ed448** — the Ed448-only-FFI shape
   OCaml/Zig/Swift reached (native floor + FFI-Ed448). Out of scope for `--profile core`.

3. **Numeric = fixed-width UInt64 wire carrier + BigInt values (hybrid).** `UInt64` exactly
   covers the CBOR uint64 argument tower `[0, 2^64-1]` — a native, natural, exact-width
   unsigned carrier (no Fortran signed-carrier trap, no unsigned gap). Because it is
   fixed-width, the `[2^63, 2^64-1]` **head-form self-test is MANDATORY** (the C# `ulong` /
   Zig `u64` class). `BigInt` (GMP) carries reconstructed application values free. Floats
   native IEEE-754 (`Float64`/`Float32`, and `Float16` **native** — only the shortest-float
   ladder is hand-rolled). **Corroborates C#/Zig; does not break the numeric axis.**

4. **String/encoding = UTF-8-native.** `String` is UTF-8 internally → CBOR text length is
   byte length via `ncodeunits`/`sizeof`, never `length` (code points). The Tcl A-TCL-002
   char-vs-byte trap, avoided by construction. Byte strings are `Vector{UInt8}`.

5. **Multiple dispatch codec.** `encode`/`decode` dispatched on value type — the fresh
   CLOS/Smalltalk double-dispatch shape, but the **opposite** of Tcl EIAS: the type system
   makes major-type selection natural (`String`→mt3, `Vector{UInt8}`→mt2, `Integer`→mt0/1,
   `AbstractFloat`→mt7), no explicit tag/side-channel.

6. **Concurrency = single-threaded Task scheduler** (coroutines over libuv). §7b store-safety
   **structural** (cooperative yield at I/O only, no lock); §6.11 reentry a plain `Channel`
   handoff (no cross-thread demux). The PHP/Dart/Tcl event-loop result on a fourth substrate.
   Multithreading (`Threads.@spawn`) noted, out of scope for core.

7. **Error model = exceptions** (custom `<: Exception` structs; the C#/TS/Java/Tcl family);
   absent = `nothing` (clean singleton, no empty-value collision).

8. **Packaging/toolchain.** `Pkg` + `Project.toml`; JIT (LLVM) — "build" = precompile+load.
   `Test` stdlib for tests. Publish = git tag + General-registry registration (UUID minted
   at S5). Apache-2.0. Container: fedora:43 + official julialang.org tarball pinned by
   version + sha256 (Zig pattern), system libsodium for the ccall.

## Ambiguity log summary — NO blocking items

8 entries, all **non-blocking** (S1 exit criteria met):
A-JULIA-001 (version/sha256 → verify at S2) · 002 (CBOR.jl declined) · 003 (libsodium ccall
vs Sodium.jl) · 004 (Ed448 opt-in FFI, deferred) · 005 (single-thread Task scheduler) · 006
(dispatch exclusivity → verify S2) · 007 (byte-length strings) · 008 (UInt64 self-test).
None requires an overseer decision before S2.

## Handoff to S2 (codec)

- Run the canonical-CBOR **spike first** (push `map_keys` + `float` vectors through the
  hand-rolled encoder) before the full build — the documented cheap insurance; `ffi` is the
  fallback if it fails (not expected).
- Fill + verify `JULIA_SHA256` in the container and confirm the exact Julia patch (A-001).
- Confirm the libsodium `crypto_sign_*` symbol/ABI via ccall (A-003) and the
  multiple-dispatch branch exclusivity (A-006).
- Gate: `wire-conformance` byte-identical (69/69, 0 fail).

## Time

Single S1 sub-agent pass: cold-start reads (constants + S1/orchestration prompts + tcl/zig/
fortran/cobol precedents + LANDSCAPE Julia row) → profile authoring → rationale → container
→ logs. No `podman build` (S1 is authoring-only; toolchain provisioned at S2).
