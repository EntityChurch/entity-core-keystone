# entity-core-protocol-fortran — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (packaging + publish)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/fortran-toolchain:latest` (gfortran 15.2, fedora:43)
**Status:** ✅ **Packaging COMPLETE** — `make dist` produces a source tarball whose packaged
peer **builds + boots to `LISTENING`** verified in-container. Registry publish **deferred**
(`0.1.0-pre`), matching the cohort convention.

## Release-readiness checklist

| Artifact | State | Notes |
|---|:---:|---|
| `README.md` | ✅ | What the peer is (signed-carrier uint64 probe, FFI-hybrid), build/run, conformance badge **682·0F @ cc1970f**, crypto-floor note |
| `CHANGELOG.md` | ✅ | `0.1.0-pre` entry; spec pinned "tracks ENTITY-CORE-PROTOCOL v0.8.0 (V8)" |
| `LICENSE` | ✅ | Apache-2.0 — repo-root `LICENSE` (per `profile.toml [license]`), bundled into the dist tarball (cohort convention: one canonical license, referenced not duplicated — matches Rexx) |
| `fpm.toml` | ✅ | Idiomatic fpm manifest; pins `libentitycore_codec` C-ABI **1.1** (`ec_abi_version`), gfortran 15.2.1, libsodium 1.0.22, test-drive 0.6.1; records oracle `cc1970f` + conformance line |
| CI (`.github/workflows/fortran.yml`) | ✅ | Podman offline-gate; S2 (69/69 + unit) → S3 (self-test + smoke) → S4 (`validate-peer --profile core`, asserts `summary.failed == 0`). Mirrors the compiled-peer cohort pattern (prolog/zig/haskell/swift/c); no CD, no publish |
| `make dist` | ✅ | `dist/entity-core-protocol-fortran-0.1.0-pre.tar.gz` — source distribution (16 `.f90` modules + `net_shim.c` recipe + fpm.toml + Makefile + run scripts + status + arch + LICENSE) |
| Packaged peer boots | ✅ | Extracted tarball → `make peer` (against the documented `libentitycore_codec` runtime dep) → `LISTENING 7811`. The distributed artifact is runnable, not just present |
| Ambiguity log finalized | ✅ | All 18 A-FTN items owner/escalation-tagged; S5 finalization footer added (`SPEC-AMBIGUITY-LOG.md`) |
| Conformance badge | ✅ | README links `status/CONFORMANCE-REPORT.md` (682·0F @ cc1970f) |
| S2/S3/S4 floors | ✅ | S2 69/69 · S3 18/18 + 5/5 · S4 682·0F — unregressed |

## Done

- **`make dist`** — the profile's `package_command`. Fortran is COMPILED, so the "package"
  is a **source distribution** (`dist/entity-core-protocol-fortran-0.1.0-pre.tar.gz`) of the
  16 `.f90` module tree + `bin/peer.f90` + the C net-shim **recipe** (`src/ext/net_shim.c` —
  source, not the gitignored `build/` binaries) + the tests + `fpm.toml` + `Makefile` (the
  actual container build) + `README.md` + `CHANGELOG.md` + run scripts + `status/` + `arch/`
  + the Apache-2.0 `LICENSE`. The consumer rebuilds with `make peer` (gfortran + the image
  gcc) or `fpm build`. `libentitycore_codec` is a documented runtime dep (README), rebuilt
  from the FFI repo — **not bundled**; the net-shim `.o` is rebuilt from its shipped `.c`.
- **`fpm.toml`** — the idiomatic manifest for fpm users (fpm 0.12.0). NOT the container build
  path (fpm not in fedora dnf, A-FTN-008), but `fpm build`/`fpm test`-able downstream. Pins
  the FFI artifact + toolchain per the S5 `codec_strategy = "ffi"` contract.
- **CI** — `.github/workflows/fortran.yml`, the reproducible three-gate offline runbook in
  the pinned Podman image, `--network=none`. Committed for reviewability, no runner attached
  (deferred cohort-wide); documents the gate, does not publish.
- **Verified (the "package builds + runs clean" gate):** `make dist` → extract → `make peer`
  against the codec `.so` → `LISTENING 7811`, in-container, capped, sealed-offline.

## Publishing (deferred — matches the cohort)

Per `profile.toml [publishing]`: Fortran's living distribution norm is the fpm ecosystem (an
`fpm.toml` in a git repo, discoverable via the fortran-lang registry — the CPAN/PyPI analogue,
younger). Publish = tag a git release carrying this tree + the tarball; registry inclusion is
a later, review-gated community step. `repository_url` / `registry_url` are TBD on first
publish — the same deferred `0.1.0-pre` state as OCaml / Elixir / CL / Prolog / Tcl / Rexx.
`libentitycore_codec` is a per-platform build artifact (documented in README), not an indexed
package. **Registry upload is an operator decision after review; `/entity-rosetta` never
publishes.**

## Operator handoff (deferred registry publish)

1. Review this tree + `dist/entity-core-protocol-fortran-0.1.0-pre.tar.gz`.
2. When a community pull exists: set `profile.toml [publishing] repository_url`, tag a git
   release (`0.1.0-pre` → `0.1.0` once an external consumer confirms + S4 stays green).
3. Optional fortran-lang registry submission (the `fpm.toml` is ready). Crypto floor is a
   platform build of `libentitycore_codec` (C-ABI 1.1) — document it in the release notes.
4. Ed448 / SHA-384 agility is deferred (floor is Ed25519 + SHA-256); wire the opt-in C-ABI
   `ec_ed448_*` path when an adopter scopes it.

## The peer is complete through the conformance gate

S1 (profile — peer #25, fixed-width SIGNED-ONLY numeric-model probe + native IEEE floats) →
S2 (codec **69/69**, signed-carrier uint64 tower `{0, 2⁶³−1, 2⁶³, 2⁶⁴−2, 2⁶⁴−1}` byte-exact)
→ S3 (peer machinery: self-test **18/18** + two-peer smoke **5/5**; single-thread select over
the linked C net-shim) → S4 (`--profile core` **682·0F** @ `cc1970f`, genuine 2-of-3 multisig
accept-path, §6.13(b) reentry wired live; the S4 crash-hunt surfaced the durable
SIGPIPE/EV_NONE net-shim lessons A-FTN-016/017) → **S5 (packaged)**.

The signed-carrier uint64 probe closed as **corroboration** — the spec's numeric determinism
survives a substrate whose only wide integer is signed, carried as an explicit bit pattern
with no side channel (itself the answer). The one durable *corpus* finding is **A-FTN-012**
(the `tag_reject.1/2/3/5` vectors reject via trailing-data, not the §6.3 tag scanner — a
"conformance-green can be vacuous" corpus defect), written up as
`research/stewardship/HANDOFF-TO-ARCH-2026-07-11-ftn-tag-reject-corpus.md` and logged as
**F29**. Steady-state value is now the Tier-tracked re-run on future amendments.
