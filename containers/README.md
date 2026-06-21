# containers/

Podman base images per toolchain. All build/test/conformance work happens inside one of these.

## Layout

- **`base/`** — `fedora:43` + shared tooling (git, curl, make, gcc, openssl-devel, libsodium-devel, python3, jq). Everything else builds on this.
- **`dotnet9/`** — `.NET 9 SDK` + the conformance oracles (`validate-peer`, `wire-conformance` from `entity-core-go`). Used by csharp profile.
- **`node24/`** — `Node 24 LTS` for JS / TypeScript profiles (Node 20 is EOL mid-2026). Native Ed25519+Ed448+SHA-2 via `node:crypto`; offline-by-default network policy (`--network=none` after a one-time `npm ci` populates the `/npm-cache` volume). Used by the typescript profile.
- **`openjdk21/`** — `OpenJDK 21` for Java / Kotlin / Scala / Clojure profiles.
- **`cargo/`** — Rust toolchain. Builds `entity-core-codec-ffi-rust` (and future Rust/WASM FFI outputs).
- **`c-toolchain/`** — C compiler + `libsodium`/`monocypher` + `libcbor`/`tinycbor`, for `entity-core-codec-ffi-c`. *(to author — needed for the C codec impl)*
- **`ghc/`** — `GHC` for Haskell.
- **`beam/`** — Erlang/Elixir runtime.

Per-language Containerfiles layer their toolchain on top of `base/`. New language → new subdirectory + Containerfile.

## Supply-chain pins (S11)

Every image pins its base, toolchain, and packages to explicit versions that are **≥ 30 days old** at pin time (no `latest` for dependencies, no floating ranges) — the supply-chain cool-down. Image *tags* may use `:latest` for local convenience, but the contents are pinned. CVE-forced newer pins are explicit + logged. See CLAUDE.md S11.

## Build

```
podman build --memory=4g --memory-swap=4g -t entity-core-keystone/base:latest -f base/Containerfile ..
podman build --memory=4g --memory-swap=4g -t entity-core-keystone/dotnet9:latest -f dotnet9/Containerfile ..
# etc.
```

(Build context is repo root — Containerfiles reference paths into `../protocol-generator/`, `../ffi-generator/`, etc.)

## Image naming convention

`entity-core-keystone/<toolchain>:latest`

## Conformance oracle inclusion

Each language image pulls in `validate-peer` and `wire-conformance` binaries built from `entity-core-go`. Options:
- `COPY --from` a pre-built entity-core-go image
- Multi-stage build: clone entity-core-go, build the binaries, copy them in
- Pre-build outside Podman and `COPY ./bin/`

Decision per-image; document in the Containerfile.
