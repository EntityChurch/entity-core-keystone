# entity-core-protocol-rexx — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (packaging + publish)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/rexx-toolchain:latest` (Regina Rexx 3.9.6, fedora:43)
**Status:** ✅ **Packaging COMPLETE** — `make dist` produces a source tarball whose
pre-concatenated `entity-core-peer.rex` **boots to `LISTENING`** verified in-container.
Registry publish **deferred** (`0.1.0-pre`), matching the cohort convention.

## Done

- **`make dist`** — the profile's `package_command`. Rexx has **no package registry** (no
  CPAN/PyPI/crates analogue) and **no module system**, so the "package" is a **source
  tarball** (`dist/entity-core-protocol-rexx-0.1.0-pre.tar.gz`, ~150 KB) of the `.rex`
  routine tree + the two C ext **recipes** (`ext/eccrypto.c`, `ext/ecnet.c` — source, not the
  gitignored binaries) + `bin/peer.rex` + the run/conformance scripts + `profile.toml` +
  `status/` + `LICENSE` + the **`LOAD.md`** stub, and — the key artifact — a single
  **pre-concatenated `entity-core-peer.rex`**: `bin/peer.rex` ahead of the routine library
  in `S3LIB` link order, so Regina's global labels resolve across the one file and the
  consumer can `rexx entity-core-peer.rex …` directly. This is the classic-Rexx analogue of
  Tcl's `pkgIndex.tcl` — concatenation *is* the module system.
- **`LOAD.md`** — the load/run stub: the `libentitycore_codec` runtime dependency (built
  from the FFI repo, `LD_LIBRARY_PATH`-pointed), the two `make ext`/`make net` C-ext build
  steps, and the `rexx entity-core-peer.rex --port … --name …` invocation.
- **Verified (the "package loads clean" gate):** `make dist` → extract the tarball → run the
  packaged `entity-core-peer.rex` against the codec `.so` + the `ecnet` daemon → reaches
  `LISTENING 7801`. The distributed artifact is runnable, not just present.

## Publishing (deferred — matches the cohort)

Per the profile `[publishing]`: classic Rexx has no dominant binary registry. Publish = tag a
git release carrying this tree + the tarball; a RexxLA-archive / script-collection listing is
a later, review-gated community step. `repository_url` / `registry_url` are TBD on first
publish — the same deferred `0.1.0-pre` state as OCaml/Elixir/CL/Prolog/Tcl. The C ext
processes + `libentitycore_codec` are per-platform build artifacts (documented in `LOAD.md`),
not indexed packages.

## The peer is complete through the conformance gate

S1 (profile — peer #24, native-decimal number-model + EIAS probe) → S2 (codec **69/69**,
decimal→IEEE float ladder proven) → S3 (peer machinery: two-peer smoke **8/8** + self-test
**31/31**; the novel `ecnet` co-process transport) → S4 (`--profile core` **682·0F** @
`cc1970f`, genuine 2-of-3 multisig; **two §4.9/§4.10 resilience findings surfaced + fixed** —
A-RX-014 unbounded per-request signature ingest, and the §4.10(c) admission cap) → **S5
(packaged)**.

Unlike the earlier alien-substrate probes that corroborated cleanly, the Rexx probe's value
was concentrated at **S4**: its FIFO co-process substrate (A-RX-011: no in-process crypto
shim) made it the cohort's slowest peer and, under the sustained-load categories, surfaced a
**genuine resource-exhaustion finding** (A-RX-014 → arch) that a fast, low-traffic peer never
triggers. Steady-state value is now the Tier-tracked re-run on future amendments (LANDSCAPE
tier roster).
