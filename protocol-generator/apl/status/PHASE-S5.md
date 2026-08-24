# entity-core-protocol-apl — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (packaging + publish)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/apl-toolchain:latest` (GNU APL 1.9 source-built, fedora:43)
**Status:** ✅ **Packaging COMPLETE** — `make dist` produces a source tarball whose packaged
peer **boots to `LISTENING`** verified in-container. Registry publish **deferred**
(`0.1.0-pre`), matching the cohort convention. APL has no package registry — a git tag is the
deliverable.

## Release-readiness checklist

| Artifact | State | Notes |
|---|:---:|---|
| `README.md` | ✅ | What the peer is (array/value-model probe, FFI-hybrid), build/run, conformance badge **682·0F @ cc1970f**, crypto-floor note, GNU-APL-from-source note, A-APL-008 GPLv3-combined-binary license note |
| `CHANGELOG.md` | ✅ | `0.1.0-pre` entry; spec pinned "tracks ENTITY-CORE-PROTOCOL v0.8.0 (V8)"; records oracle `cc1970f` |
| `LICENSE` | ✅ | Apache-2.0 — repo-root `LICENSE` (per `profile.toml [license]`), bundled into the dist tarball (cohort convention: one canonical license, referenced not duplicated — matches Fortran/Rexx/Tcl) |
| CI (`.github/workflows/apl.yml`) | ✅ | Podman offline-gate; S2 (69/69 + unit) → S3 (self-test + smoke) → S4 (`validate-peer --profile core`, asserts `summary.failed == 0`). Mirrors the compiled-peer cohort pattern (prolog/zig/haskell/swift/c/fortran); no CD, no publish, no tag |
| `make dist` | ✅ | `dist/entity-core-protocol-apl-0.1.0-pre.tar.gz` — source distribution (16 `.apl` modules + `bin/peer.apl` loader + `ec_native.cc` shim source + tests + Makefile + run scripts + status + arch + LICENSE) |
| Packaged peer boots | ✅ | Extracted tarball → `make shim` (against the documented `libentitycore_codec` runtime dep + retained apl headers) → `apl --script <S3 modules> -f bin/peer.apl` → `LISTENING 7799`. The distributed artifact is runnable, not just present |
| Ambiguity log finalized | ✅ | All 17 A-APL items owner/escalation-tagged; S5 finalization footer added (`SPEC-AMBIGUITY-LOG.md`) |
| Conformance badge | ✅ | README links `status/CONFORMANCE-REPORT.md` (682·0F @ cc1970f) |
| S2/S3/S4 floors | ✅ | S2 69/69 · S3 18/18 + 5/5 · S4 682·0F — unregressed |

## Done

- **`make dist`** — the profile's `package_command`. APL is INTERPRETED, so the "package" is
  a **source distribution** (`dist/entity-core-protocol-apl-0.1.0-pre.tar.gz`) of the `.apl`
  workspace (the `src/` modules + `bin/peer.apl` loader) + the native-fn shim **source**
  (`src/ext/ec_native.cc` — source, not the gitignored `.so`) + the tests (incl. `smoke.sh`) +
  the `Makefile` (the actual container build) + `README.md` + `CHANGELOG.md` + run scripts +
  `status/` + `arch/` + the Apache-2.0 `LICENSE`. The consumer rebuilds only the shim
  (`make shim`, g++ + the retained apl source-tree headers, A-APL-009) and loads the workspace
  into apl. `libentitycore_codec` is a documented runtime dep (README), rebuilt from the FFI
  repo — **not bundled**.
- **CI** — `.github/workflows/apl.yml`, the reproducible three-gate offline runbook in the
  pinned Podman image, `--network=none`. The `run-s{2,3,4}.sh` scripts self-re-exec under
  capped Podman, so the steps just invoke them; the S4 step asserts `summary.failed == 0`.
  Committed for reviewability, no runner attached (deferred cohort-wide); documents the gate,
  does not publish/tag.
- **Verified (the "package boots clean" gate):** `make dist` → extract → `make shim` against
  the codec `.so` (paths overridden to the repo's built codec + C-ABI spec) → launch the
  packaged `bin/peer.apl` → `LISTENING 7799`, in-container, capped, sealed-offline.

## Publishing (deferred — matches the cohort)

Per `profile.toml [publishing]`: APL has **no mature package registry** — Dyalog's Tatin is
Dyalog-ecosystem specific; GNU APL workspaces are distributed as `.apl` source files. Publish
= tag a git release carrying this tree + the `make dist` tarball; there is no registry-upload
step. `repository_url` / `registry_url` are TBD on first publish — the same deferred
`0.1.0-pre` state as OCaml / Elixir / CL / Prolog / Tcl / Rexx / Fortran. `libentitycore_codec`
is a per-platform build artifact (documented in README), not an indexed package. **Registry
upload / tagging is an operator decision after review; `/entity-rosetta` never publishes.**

## Operator handoff (deferred publish)

1. Review this tree + `dist/entity-core-protocol-apl-0.1.0-pre.tar.gz`.
2. When a community pull exists: set `profile.toml [publishing] repository_url`, tag a git
   release (`0.1.0-pre` → `0.1.0` once an external consumer confirms + S4 stays green).
3. Crypto floor is a platform build of `libentitycore_codec` (C-ABI 1.1) — document it in the
   release notes. Note the A-APL-008 license posture: the compiled native-fn shim + apl form a
   GPLv3 binary (Apache-2.0 shim source is one-way compatible; no relicense needed).
4. Ed448 / SHA-384 agility is deferred (floor is Ed25519 + SHA-256; no native APL Ed448); wire
   the opt-in C-ABI `ec_ed448_*` / `ec_sha384` path when an adopter scopes it.
5. The two `⎕FIO[40]` select bugs (A-APL-015) and the `⍺∘≡¨⍵` DOMAIN ERROR (A-APL-017 trap #3)
   are candidate upstream GNU APL reports, out of scope for this peer.

## The peer is complete through the conformance gate

S1 (profile — the array/value-model alien-substrate probe + int64 silent-double-promotion
axis) → S2 (codec **69/69**, `uint64` tower `{0, 2⁶³−1, 2⁶³, 2⁶⁴−2, 2⁶⁴−1}` byte-exact via the
8-octet array carrier) → S3 (peer machinery: self-test **18/18** + two-peer smoke **5/5**;
single-thread `⎕FIO[40]` select-pump, native sockets, no C net-shim) → S4 (`--profile core`
**682·0F** @ `cc1970f`, genuine 2-of-3 multisig accept-path, §6.13(b) reentry wired live with
the single-thread reentry-serialization pattern) → **S5 (packaged)**.

The array/value-model probe closed as **corroboration** — a from-spec canonical-CBOR codec
falls out of APL's array primitives (`⊤ ⊥ ⍋`) as cleanly as from scalar bit-ops, and the
generator survived a language with no statement-level control flow in its dfn form (the `→`
-branch tradfn idiom under GNU APL 1.9's `--script`, A-APL-012). **Zero fresh wire findings**
(the well is dry on the current wire surface, as predicted), **no spec-vs-oracle divergence,
no arch handoff**. The durable yield is a reusable **GNU-APL-1.9 array-idiom + socket +
native-fn cookbook** (A-APL-012…017) for any future GNU APL peer / generator run. Steady-state
value is now the Tier-tracked re-run on future amendments.
