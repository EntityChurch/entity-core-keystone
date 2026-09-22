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

## Every image must build from a clean pull. Two rules, both enforced.

An image nobody can rebuild is not a build recipe, it is a local accident. Both ways
that used to happen are now closed structurally rather than per-incident.

**1. Every pinned RPM comes from Koji, never from a rolling dnf repo.**

Fedora's `fedora`/`updates` repos carry only the CURRENT + recent build of each package.
A `Containerfile` pinning an exact NVR (`gcc-15.2.1-7.fc43`) builds fine until that NVR
is superseded, then fails with `No match for argument` — sometimes within hours, not
months (`clang` rotted twice in one day during the 2026-07-27/28 sweep; eleven images
broke at once on 2026-07-27). Koji, the build system that *produces* those RPMs, retains
every NVR ever built, forever, at a stable URL.

This used to be handled reactively — convert the one package that broke, leave the rest.
That policy left 36 of 46 images on rolling pins and guaranteed a next time. **As of
2026-08-27 all 58 pinned RPMs across all 13 affected images are Koji-fetched, and a
rolling dnf NVR pin is no longer an accepted state.** Verify with:

```
python3 tools/koji-pin.py scan       # must report 0 rolling pins
python3 tools/koji-pin.py verify     # every recorded pin still resolves + digest matches
```

To pin a new package, do not hand-resolve it — `tools/koji-pin.py` knows the SRPM
mapping (the source name is often not the binary name: `gcc-c++`/`libasan` ⇐ `gcc`;
`cargo`/`clippy`/`rustfmt` ⇐ `rust`; `clang`/`libcxx*` ⇐ `llvm`, **not** `clang`;
`glibc-static` and the cross sysroots ⇐ `glibc`; `gcc-riscv64-linux-gnu` ⇐ `cross-gcc`,
**not** `gcc`) and falls back to `dnf repoquery` when it doesn't:

```
python3 tools/koji-pin.py resolve containers/<image>   # prints the koji-fetch block
```

It downloads each RPM to record its SHA-256. That digest is the integrity control —
Koji's raw archive predates distro GPG signing.

**2. Every base image is pinned by digest, never by tag.**

A tag is republished in place; a digest is not. `fedora:43` moved between 2026-06-17 and
2026-08-27, so an image pinning the tag floated on whatever the registry served that day.
All bases now carry `@sha256:…` with the tag kept in a comment for readability.

**Enforcement — `tools/cold-build-gate.sh`.** Builds every image with `--no-cache` and
fails on any that doesn't. This is the only thing that actually asks the adopter's
question, because the layer cache and the already-present local images hide a broken
recipe from the machine that authored it. A pin nobody re-checks is a claim, not an
anchor. Run it before a release and whenever `containers/` changes:

```
tools/cold-build-gate.sh              # all images, from scratch
tools/cold-build-gate.sh c-toolchain  # one image
```

Record a deliberate re-pin with a one-line `RE-PIN (<date>): …` comment in the
Containerfile. Full rationale, and the "why not just cache the RPMs locally" reasoning
(rejected — not portable): `containers/koji-fetch.sh`'s header and AGENTS.md's
Setup/environment section.

## Conformance oracle inclusion

Each language image pulls in `validate-peer` and `wire-conformance` binaries built from `entity-core-go`. Options:
- `COPY --from` a pre-built entity-core-go image
- Multi-stage build: clone entity-core-go, build the binaries, copy them in
- Pre-build outside Podman and `COPY ./bin/`

Decision per-image; document in the Containerfile.
