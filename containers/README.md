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

## When a pinned dnf package NVR ages out (`No match for argument`)

Fedora's `fedora`/`updates` repos only carry the CURRENT + recent build of each
package. A `Containerfile` pinning an exact NVR (`gcc-15.2.1-7.fc43`) will build fine
for a while and then start failing with `No match for argument` the moment that NVR is
superseded — sometimes within hours, not months (`clang` rotted twice in one day during
the 2026-07-27/28 sweep). This is not a "something's wrong with our setup" bug; it's
what pinning against a rolling repo does. Recipe, once it happens:

1. **Confirm it's rot, not a typo.** Inside `containers/base` (or any built image):
   `dnf list --showduplicates <pkg>` — if your pinned NVR isn't in the list, it's gone
   from the repo, permanently (the repo doesn't keep history).
2. **Pick the fix per package, not per image:**
   - **First time this exact package has rotted** → re-pin it to the freshest available
     NVR from `dnf list --showduplicates` (the old, now-abandoned approach) — fine as a
     one-off, but expect to repeat this indefinitely for a volatile package.
   - **A package that has rotted before, or one in the volatile families (gcc, gcc-c++,
     gcc-gnat, libstdc++\*, libasan, libubsan, binutils, rust, cargo, clippy, rustfmt,
     clang, libcxx\*, dotnet-sdk-9.0\*)** → koji-pin it instead (see below). This is the
     one that actually stops recurring.
3. **To koji-pin a package:**
   1. Find its **Koji source-package (SRPM) name** — not always the binary name. Verify
      with a HEAD request, don't assume:
      `curl -sSI https://kojipkgs.fedoraproject.org/packages/<guess>/<ver>/<rel>/x86_64/<binary>-<ver>-<rel>.x86_64.rpm`
      (known mappings: `gcc*`/`libstdc++*`/`libasan`/`libubsan` ⇐ `gcc`;
      `rust`/`cargo`/`clippy`/`rustfmt` ⇐ `rust`; `clang`/`libcxx*` ⇐ `llvm`, **not**
      `clang`; `dotnet-sdk-9.0` ⇐ `dotnet9.0`).
   2. Download the RPM and compute its SHA-256 (`sha256sum`) — this is the integrity
      floor since Koji's raw archive predates distro GPG signing.
   3. In the `Containerfile`, add (mirroring any of the nine already-converted images —
      `c-toolchain` is the smallest example):
      ```
      COPY containers/koji-fetch.sh /usr/local/bin/koji-fetch.sh
      RUN chmod +x /usr/local/bin/koji-fetch.sh \
          && koji-fetch.sh <source-pkg> <version> <release> \
              <binary-pkg>:<sha256> [<binary-pkg2>:<sha256> ...] \
          && dnf install -y /tmp/rpms/*.rpm <other, still dnf-repo-pinned packages> \
          && rm -rf /tmp/rpms \
          && dnf clean all
      ```
   4. Rebuild (`podman build -t entity-core-keystone/<toolchain>:latest -f
      containers/<toolchain>/Containerfile .`) and confirm it's clean from a fresh build,
      not just cache — `--no-cache` if in doubt.
4. **Record it.** A one-line `RE-PIN (<date>): ...` comment in the Containerfile is
   enough; it doesn't need its own stewardship doc unless something about the rot itself
   was surprising (e.g. it recurred same-day, or the package family wasn't on the
   known-volatile list above — both are worth a note back to AGENTS.md).

Full rationale + the "why not just cache the RPMs locally" reasoning (rejected — not
portable):`containers/koji-fetch.sh`'s header comment and AGENTS.md's Setup/environment
section. Session detail: `research/stewardship/SESSION-2026-07-28-container-harness-
stabilization.md`.

## Conformance oracle inclusion

Each language image pulls in `validate-peer` and `wire-conformance` binaries built from `entity-core-go`. Options:
- `COPY --from` a pre-built entity-core-go image
- Multi-stage build: clone entity-core-go, build the binaries, copy them in
- Pre-build outside Podman and `COPY ./bin/`

Decision per-image; document in the Containerfile.
