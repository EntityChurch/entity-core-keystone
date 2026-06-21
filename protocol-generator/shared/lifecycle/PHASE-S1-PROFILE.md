# Phase S1 — Profile research + authoring

> Loaded by `/entity-rosetta <lang> --phase profile` or as first phase of full `/entity-rosetta <lang>`.

## Objective

Survey the target language's ecosystem and author a complete `protocol-generator/<lang>/profile.toml`. This is the input to every subsequent phase — get it right.

## What you research

| Surface | What to find |
|---|---|
| **CBOR library** | Canonical CBOR support (RFC 8949 §4.2 deterministic encoding). Maturity, audit history, last release date, GitHub stars (rough proxy). Multiple candidates → pick one with reasoning |
| **Ed25519 library** | Signature + key generation + verification. Audited if possible. Native crypto preferred over libsodium binding where mature |
| **SHA-256** | Universal; just note which standard library provides it |
| **Varint / leb128** | Some languages need a small impl for the multikey varint format codes (V7 §1.5, §7.3). Check |
| **Build system** | What an idiomatic project uses (`dotnet` / `cargo` / `gradle` / `npm` / `mvn` / `mix` / …) |
| **Test framework** | What the ecosystem standard is |
| **Async story** | Native async (e.g. .NET `Task`, JS `Promise`, Rust `async fn`)? Or callback-based? Or thread-based? |
| **Error model** | Exceptions, `Result<T, E>`, `Either`, error returns, panics — what's idiomatic |
| **Naming conventions** | PascalCase / camelCase / snake_case / kebab-case per identifier kind |
| **Packaging target** | NuGet / Maven Central / npm / PyPI / crates.io / Hex / Hackage / … |
| **License convention** | Apache-2.0 default per S9; ecosystem may prefer MIT |
| **Container base** | Fedora 43 + toolchain layer (see `containers/<toolchain>/`); pick an existing one or specify the new one needed |

**Pin discipline (S11):** every library version you record in the profile MUST be pinned exactly (no floating ranges) and **≥ 30 days old** at authoring time — the supply-chain cool-down. Note each library's release date in `PROFILE-RATIONALE.md`; flag in the ambiguity log if the only viable version is too new.

## What you write

`protocol-generator/<lang>/profile.toml` — see `protocol-generator/csharp/profile.toml` for the reference example. All fields documented; copy and adapt.

## What you also write

`protocol-generator/<lang>/arch/PROFILE-RATIONALE.md` — short prose document explaining WHY each profile choice was made. This is the audit trail when a future operator asks "why did we pick `cbor-x` over `cbor`?". One paragraph per major choice.

## Container

If the target language doesn't have an existing `containers/<toolchain>/Containerfile`, you author one based on `containers/base/Containerfile`. Include the language's toolchain + any deps the profile references.

## Codec strategy decision

Per the matrix in `research/LANDSCAPE.md` tier assignment + your library survey, pick:

- `codec_strategy = "native"` if the ecosystem has mature canonical CBOR + audited Ed25519 → use native libraries
- `codec_strategy = "ffi"` if either is immature → consume the codec C-ABI (`libentitycore_codec`, from `entity-core-codec-ffi-{rust,c}`; spec at `ffi-generator/c-abi/spec/`) via the language's FFI primitive
- `codec_strategy = "interop"` if the language shares a runtime with a sibling that already has a native codec (e.g. Clojure on JVM can interop with the Java codec)

**Reality check on "native":** no surveyed CBOR library — Rust `ciborium`, .NET `System.Formats.Cbor`, Python `cbor2`, and others — gives ECF's canonical guarantees out of the box. Shortest-float/float16 minimization, length-then-lexicographic map-key ordering, major-type-6 tag rejection, and raw-byte fidelity are **yours to enforce on top of the library** regardless (see `research/evaluations/csharp.md` R1–R4, `research/evaluations/ffi-rust.md`, and conformance invariants N1–N4). "native" means the *primitives + crypto* are native, not that canonicality is free — both the Rust and C FFI impls hand-write the canonical layer too. Where this enforcement looks expensive or a library actively fights it, run a quick **spike** (push the `map_keys` + `float` test-vectors through the candidate lib) before committing the full S2 build — cheap insurance; `ffi` is the documented fallback if the spike fails.

Document the choice + reasoning in `arch/PROFILE-RATIONALE.md`.

## Phase output

- `protocol-generator/<lang>/profile.toml` — complete
- `protocol-generator/<lang>/arch/PROFILE-RATIONALE.md` — written
- `protocol-generator/<lang>/status/SPEC-AMBIGUITY-LOG.md` — initialized; entries logged if ambiguity surfaced
- `protocol-generator/<lang>/status/PHASE-S1.md` — phase summary, time spent, decisions made
- (if new toolchain) `containers/<toolchain>/Containerfile` — written

## Phase exit criteria

Profile.toml has every field populated (none left as `"TBD"`); rationale doc written; container exists or is specified; ambiguity log has no blocking-severity items.
