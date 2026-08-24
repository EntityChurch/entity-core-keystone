# entity-core-protocol-forth — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (packaging + publish)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/forth-toolchain:latest` (gforth 0.7.3, fedora:43,
libsodium 1.0.22)
**Status:** ✅ **Packaging COMPLETE** — `make dist` produces a source tarball
(`dist/entity-core-protocol-forth-0.1.0-pre.tar.gz`, ~120 KB) whose packaged `bin/peer.fs`
**boots to `LISTENING`** verified from a clean unpack outside the source tree. Registry
publish **deferred** (`0.1.0-pre`), matching the cohort convention.

## Done — the S5 artifacts

- **`README.md`** — what the peer is (the stack-machine/typeless probe #25; gforth 0.7.3;
  FFI-hybrid — pure-Forth canonical CBOR + crypto/SHA over `libentitycore_codec` via in-process
  `libcc`), how to build (`make ffi`), test (`run-s2.sh`/`run-s3.sh`), run
  (`gforth bin/peer.fs --name NAME`), and the **conformance badge** (`682·0F @ cc1970f`,
  linking `status/CONFORMANCE-REPORT.md`).
- **`CHANGELOG.md`** — the `0.1.0-pre` entry; states literally **"tracks Entity Core v0.8.0
  (V8)"** and the oracle `cc1970f`. Full conformance breakdown + the seven S4 code-bug fixes.
- **`LICENSE`** — Apache-2.0 (the keystone default). README flags the **gforth GPLv3+ runtime**
  interaction: distributing `.fs` source that runs *on* gforth is mere aggregation /
  interpretation (not a derivative of the interpreter; this tree links no GPL code), so the
  Apache-2.0 default stands — the same reasoning Rexx/COBOL applied.
- **`LOAD.md`** — the load/run stub: the `libentitycore_codec` runtime dependency (built from
  the FFI repo, env-pointed), the `make ffi` build step, the libcc cache gotcha (A-FT-005), and
  the `gforth bin/peer.fs --port … --name …` invocation (+ the keypair-free `--seed` smoke).
- **`Makefile` `dist` target** — the profile's `package_command`. Forth has **no package
  registry** (no CPAN/PyPI/crates) and **no module system**, so the "package" is a **source
  tarball** of the `.fs` tree + `bin/peer.fs` + the run/conformance scripts (`run-s2/s3/s4` +
  origination) + `profile.toml` + `status/` + `arch/` + `LICENSE` + `README.md` + `CHANGELOG.md`
  + `LOAD.md`. `libentitycore_codec` is a **runtime dependency documented by its CMake recipe**,
  not bundled as a binary — the consumer builds the `.so`. Mirrors the COBOL/Rexx `make dist`.
- **`.github/workflows/forth-conformance.yml`** — the Podman-based offline conformance gate
  (S2 codec + S3 peer + S4 `--profile core` 0-FAIL), committed for reviewability, **not wired to
  any runner/CD** — no deploy, no registry push (matches the prolog/zig/haskell offline-gate
  cohort pattern; rexx/tcl/cobol ship none, so this is additive, not divergent).
- **`status/SPEC-AMBIGUITY-LOG.md`** — finalized: all 29 items **A-FT-000..028** tagged RESOLVED
  (at their stage) or research-owned; **none open, none arch-escalated**. Final closeout status
  added at the log head.

## Verified (the "package boots" gate)

`make dist` → extract the tarball into a clean scratch dir (outside the worktree) → build the
codec floor (`libentitycore_codec.so`) → run the packaged `bin/peer.fs --port 7825 --seed ab`
with the libcc env pointed at the codec build → reaches **`LISTENING 7825`**. The distributed
artifact is runnable, not just present. Reproduce (container-bound, capped, sealed-offline):

```sh
. tools/podman-caps.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z -w /work/protocol-generator/forth \
  entity-core-keystone/forth-toolchain:latest bash -lc '
    CODEC=/work/ffi-generator/c-abi/entity-core-codec-ffi-c
    make ffi >/dev/null 2>&1 || true
    make dist
    SCRATCH=$(mktemp -d); tar xzf dist/entity-core-protocol-forth-0.1.0-pre.tar.gz -C "$SCRATCH"
    cd "$SCRATCH/entity-core-protocol-forth-0.1.0-pre"
    rm -rf $HOME/.gforth/libcc-named $HOME/.gforth/libcc-tmp
    export LIBRARY_PATH=$CODEC/build LD_LIBRARY_PATH=$CODEC/build \
           C_INCLUDE_PATH=/work/ffi-generator/c-abi/spec CPATH=/work/ffi-generator/c-abi/spec
    gforth -d 64M -r 64M -l 16M bin/peer.fs --port 7825 --seed ab'
# → LISTENING 7825
```

## Publishing (deferred — matches the cohort)

Per the profile `[publishing]`: Forth has no registry. Publish = tag a git release carrying
this tree + the tarball; a Forth-community listing is a later, review-gated step.
`repository_url` / `registry_url` are TBD on first publish — the same deferred `0.1.0-pre` state
as OCaml/Elixir/CL/Prolog/Tcl/Rexx. `libentitycore_codec` is a per-platform build artifact
(documented in `LOAD.md`), not an indexed package. **`/entity-rosetta` does not publish; the
operator does, after review.**

## The peer is complete through the conformance gate

S1 (profile — peer #25, stack-machine/typeless generator-stress probe) → S2 (codec **69/69**,
pure-Forth ECF with native IEEE float bits + in-process libcc crypto) → S3 (foundation self-test
**20/20** + two-peer loopback smoke **6/6**; native BSD sockets, no co-process) → S4
(`--profile core` **682·0F** @ `cc1970f`, **Result: PASS**, genuine 2-of-3 multisig,
origination-core 3/3; **seven S4 code-bug findings surfaced + fixed** — the concurrency payoff
A-FT-025 chief among them) → **S5 (packaged)**.

Like Tcl (and unlike Rexx, whose value concentrated at S4 with a genuine resource-exhaustion
finding), the Forth probe surfaced **no fresh spec-precision finding** on the current saturated
wire surface — clean corroboration, which is the answer the profile was built to get: the
generator is robust down to a typeless stack machine. The distinctive engineering signal is the
**cleanest FFI binding in the family** (in-process libffi `c-function`, native sockets, no
co-process) reaching exact Rexx parity (`682·0F`). Steady-state value is now the Tier-tracked
re-run on future amendments (LANDSCAPE tier roster; Forth is a `probe`-tier peer).

## Release-readiness checklist

| Item | State |
|---|---|
| S4 GREEN — `validate-peer --profile core` 0 FAIL @ `cc1970f` | ✅ 682·0F, Result: PASS |
| Codec 69/69 + §9.5 53/53 byte-identical | ✅ |
| origination-core 3/3 + genuine 2-of-3 multisig accept | ✅ |
| README.md / CHANGELOG.md / LICENSE / LOAD.md | ✅ present |
| `make dist` produces a source tarball | ✅ (~120 KB) |
| Packaged peer boots to `LISTENING` from clean unpack | ✅ verified (`--seed ab` → `LISTENING 7825`) |
| CHANGELOG states "tracks Entity Core v0.8.0 (V8)" + oracle `cc1970f` | ✅ |
| CI config (Podman offline gate, committed not wired) | ✅ `.github/workflows/forth-conformance.yml` |
| Spec-ambiguity log finalized (all A-FT-* resolved/owned) | ✅ 29/29, none open |
| CONFORMANCE-MATRIX Forth row + STATUS.md line | ✅ drafted (overseer reviews at the gate) |
| Version pin | `0.1.0-pre` (registry publish deferred) |

## Operator handoff (publishing is an operator step — do NOT auto-publish)

Everything above is review-gated. The operator, after arch v0.1 sign-off + a first external
gforth consumer, promotes `0.1.0-pre` → `0.1.0`, sets `repository_url`, and tags a git release
carrying this tree + `make dist`'s tarball. There is no `cargo publish` / `npm publish`
equivalent — a Forth-community listing is the optional later step. Until then the peer is
consumed directly from the tarball / worktree, offline, per `LOAD.md`.
