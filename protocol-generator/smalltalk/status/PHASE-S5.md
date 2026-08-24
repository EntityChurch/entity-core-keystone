# entity-core-protocol-smalltalk — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (packaging + publish)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/pharo-toolchain:latest` (Pharo 13.0 build.732 on the
Linux-x86_64 stable VM, fedora:43, libsodium 1.0.22)
**Status:** ✅ **Packaging COMPLETE** — `make dist` produces a source tarball
(`dist/entity-core-protocol-smalltalk-0.1.0-pre.tar.gz`, ~117 KB) whose packaged `bin/peer.st`
**plain-boots to `LISTENING`** verified from a clean unpack outside the source tree (no
`--validate`, no `--debug-open-grants` — the production-safe default path). Registry publish
**deferred** (`0.1.0-pre`), matching the cohort convention (Pharo has no binary registry).

## Done — the S5 artifacts

- **`README.md`** — what the peer is (the FIRST pure-object / live-image / message-passing probe
  #26; Pharo 13.0; FFI-hybrid — pure-Smalltalk canonical CBOR as a polymorphic `encodeOn:`
  double-dispatch + crypto/SHA over `libentitycore_codec` via in-process UFFI `ffiCall:module:`),
  how to install (Metacello baseline / `make image` load), build (`make ffi`), test
  (`run-s2.sh`/`run-s3.sh`), run (`pharo --headless entity-core.image bin/peer.st`, options via
  ENV), and the **conformance badge** (`682·0F @ cc1970f`, linking `status/CONFORMANCE-REPORT.md`).
- **`CHANGELOG.md`** — the `0.1.0-pre` entry; states literally **"tracks Entity Core v0.8.0
  (V8)"** and the oracle `cc1970f`. Full conformance breakdown + the four S4 code-bug fixes.
- **`LICENSE`** — Apache-2.0 (the keystone default). Unlike Forth on GPLv3+ gforth, the Pharo
  image + VM are **MIT-licensed**, so there is **no copyleft-runtime note** to make: distributing
  Apache-2.0 `.st` source that runs on the MIT Pharo VM is clean (README documents this).
- **`LOAD.md`** — the load/run stub: the live-image model (file-in Tonel packages + snapshot,
  the A-ST-010 single-doit class-visibility constraint), the `libentitycore_codec` runtime
  dependency (built from the FFI repo, `LD_LIBRARY_PATH`-pointed), the Metacello baseline consumer
  load, and the `pharo --headless entity-core.image bin/peer.st` invocation (ENV options + the
  keypair-free `EC_PEER_SEED` smoke).
- **Package metadata (Pharo-idiomatic).** The distribution IS the Tonel `src/` tree +
  `load.st` (the single source of truth for load order) + a documented **Metacello
  `baseline: 'EntityCore'`** consumer load (LOAD.md/README). There is NO foreign manifest —
  Pharo has no `Cargo.toml`/`package.json` analogue; a Metacello baseline is a load recipe, and
  the source tree is the package (a git repo + baseline, per the profile `[publishing]`).
- **`Makefile` `dist` target** — the profile's `package_command`. Pharo has **no binary package
  registry** (the catalog is a listing, not a store), so the "package" is a **source tarball** of
  the Tonel `src/` tree + `tests/` + `bin/peer.st` + the run/conformance scripts (`run-s2/s3/s4` +
  origination) + `profile.toml` + `load.st` + `status/` + `arch/` + `.github/` + `LICENSE` +
  `README.md` + `CHANGELOG.md` + `LOAD.md`. The saved `.image`/`.changes`/`.sources` are BUILD
  artifacts (`make image` regenerates them) — gitignored, NOT shipped. `libentitycore_codec` is a
  **runtime dependency documented by its CMake recipe**, not bundled as a binary — the consumer
  builds the `.so`. Mirrors the COBOL/Rexx/Forth `make dist`.
- **`.github/workflows/smalltalk.yml`** — the Podman-based offline conformance gate (S2 codec +
  S3 peer + S4 `--profile core` 0-FAIL, asserting `summary.failed == 0` on the JSON report),
  committed for reviewability, **not wired to any runner/CD** — no deploy, no registry push
  (matches the prolog/zig/haskell/forth offline-gate cohort pattern; rexx/tcl/cobol ship none, so
  this is additive, not divergent).
- **`status/SPEC-AMBIGUITY-LOG.md`** — finalized: all 18 items **A-ST-000..017** tagged RESOLVED
  (at their stage) or research-owned; **none open, none arch-escalated**. Final closeout status
  added at the log head.

## Verified (the "package plain-boots" gate)

`make dist` → extract the tarball into a clean scratch dir (outside the worktree) → build the
codec floor (`libentitycore_codec.so`, a documented runtime dep not in the tarball) → load the
Tonel packages into a fresh base image + snapshot → run the packaged `bin/peer.st` **PLAIN**
(`EC_PEER_PORT=7825 EC_PEER_SEED=ab`, NO `--validate`, NO `--debug-open-grants`) with
`LD_LIBRARY_PATH` pointed at the codec build → reaches **`LISTENING 7825`**. The distributed
artifact is runnable, and the shipped default peer boots without the §7a validate handlers and
without the degenerate open-grants seed (production-safe). Reproduce (container-bound, capped,
sealed-offline):

```sh
. tools/podman-caps.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z -w /work/protocol-generator/smalltalk \
  entity-core-keystone/pharo-toolchain:latest sh -c '
    set -e
    CODEC=/work/ffi-generator/c-abi/entity-core-codec-ffi-c
    [ -f "$CODEC/build/libentitycore_codec.so" ] || ( cd "$CODEC" && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null )
    export LD_LIBRARY_PATH="$CODEC/build"
    make dist >/dev/null
    S=$(mktemp -d); tar xzf dist/entity-core-protocol-smalltalk-0.1.0-pre.tar.gz -C "$S"
    cd "$S/entity-core-protocol-smalltalk-0.1.0-pre"
    # make image, in the clean extract: file-in the Tonel packages + snapshot a peer image
    cp /opt/pharo/image/*.image ./entity-core.image
    cp /opt/pharo/image/*.changes ./entity-core.changes
    cp /opt/pharo/image/*.sources . 2>/dev/null || true
    pharo --headless ./entity-core.image eval \
      "Smalltalk compiler evaluate: (FileLocator workingDirectory / '"'"'load.st'"'"') contents. Smalltalk snapshot: true andQuit: false. '"'"'built'"'"'"
    # PLAIN boot — no EC_PEER_VALIDATE, no EC_PEER_OPEN_GRANTS
    EC_PEER_PORT=7825 EC_PEER_SEED=ab pharo --headless ./entity-core.image bin/peer.st'
# → LISTENING 7825
```

*(The load step here files-in `load.st` and snapshots the peer image — the A-ST-010 single-doit
class-visibility constraint means the boot must run against a snapshotted image, not the load
eval. The essential gate: clean extract → codec floor → `make image` → PLAIN boot → `LISTENING`.)*

## Publishing (deferred — matches the cohort)

Per the profile `[publishing]`: Pharo has no binary registry. Publish = tag a git release
carrying this tree + the tarball + the Metacello baseline; a Pharo-catalog listing is a later,
review-gated step. `repository_url` / `registry_url` are TBD on first publish — the same deferred
`0.1.0-pre` state as OCaml/Elixir/CL/Prolog/Tcl/Rexx/Forth. `libentitycore_codec` is a
per-platform build artifact (documented in `LOAD.md`), not an indexed package. **`/entity-rosetta`
does not publish; the operator does, after review.**

## The peer is complete through the conformance gate

S1 (profile — peer #26, pure-object / live-image / message-passing generator-stress probe) → S2
(codec **69/69**, pure-Smalltalk ECF with native IEEE float bits + bignum uint64 free + in-process
UFFI crypto) → S3 (foundation self-test **25/25** + two-peer loopback smoke **6/6**; native BSD
Sockets, no co-process) → S4 (`--profile core` **682·0F** @ `cc1970f`, **Result: PASS**, genuine
2-of-3 multisig accept + 4/4 in-image unit, origination-core 3/3; **four S4 code-bug findings
surfaced + fixed** — the A-ST-016 catch-root-Error headline chief among them) → **S5 (packaged)**.

Like Tcl and Forth (and unlike Rexx, whose value concentrated at S4 with a resource-exhaustion
finding), the Smalltalk probe surfaced **no fresh spec-precision finding** on the current saturated
wire surface — clean corroboration, which is the answer the profile was built to get: the generator
is robust down to a pure-object / message-passing model (the codec IS an idiomatic `encodeOn:`
double-dispatch, not a translated procedure, A-ST-000). The distinctive engineering signal is the
**A-ST-012 pure-object polymorphic-absent-sentinel finding** (a distinguished-object sentinel is
only safe if `isAbsent` is answered by the whole `EcValue` hierarchy) and the **A-ST-016
catch-the-root-Error resilience lesson** on a no-static-check substrate — both banked for any
future dynamic / live-image peer. Reached exact Rexx/Forth parity (`682·0F`). Steady-state value is
now the Tier-tracked re-run on future amendments (LANDSCAPE tier roster; Smalltalk is a `probe`-tier
peer).

## Release-readiness checklist

| Item | State |
|---|---|
| S4 GREEN — `validate-peer --profile core` 0 FAIL @ `cc1970f` | ✅ 682·0F, Result: PASS (291P/295W/0F/96S) |
| Codec 69/69 + §9.5 53/53 byte-identical | ✅ |
| origination-core 3/3 + genuine 2-of-3 multisig accept | ✅ (4/4 in-image unit + oracle accept) |
| README.md / CHANGELOG.md / LICENSE / LOAD.md | ✅ present |
| Package metadata — Metacello baseline (Tonel) + `load.st` | ✅ documented (LOAD.md/README); no foreign manifest |
| `make dist` produces a source tarball | ✅ (~117 KB; no `.image`/`.changes`/`.sources` build artifacts shipped) |
| Packaged peer PLAIN-boots to `LISTENING` from clean unpack | ✅ verified (`EC_PEER_SEED=ab` → `LISTENING 7825`) |
| CHANGELOG states "tracks Entity Core v0.8.0 (V8)" + oracle `cc1970f` | ✅ |
| CI config (Podman offline gate, committed not wired) | ✅ `.github/workflows/smalltalk.yml` |
| Spec-ambiguity log finalized (all A-ST-* resolved/owned) | ✅ 18/18, none open, none arch-escalated |
| CONFORMANCE-MATRIX Smalltalk row + STATUS.md line | ✅ drafted (overseer reviews at the gate) |
| Version pin | `0.1.0-pre` (registry publish deferred) |

## Operator handoff (publishing is an operator step — do NOT auto-publish)

Everything above is review-gated. The operator, after arch v0.1 sign-off + a first external
Pharo consumer, promotes `0.1.0-pre` → `0.1.0`, sets `repository_url`, and tags a git release
carrying this tree + `make dist`'s tarball + the Metacello baseline. There is no `cargo publish` /
`npm publish` equivalent — a Pharo-catalog listing is the optional later step. Until then the peer
is consumed directly from the tarball / worktree, offline, per `LOAD.md` (Metacello baseline load
once `repository_url` is set).
