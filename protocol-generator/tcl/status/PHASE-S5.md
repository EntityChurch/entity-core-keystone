# entity-core-protocol-tcl — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (packaging + publish)
**Date:** 2026-07-11
**Status:** ✅ **Packaging COMPLETE** — `package require entity::core` loads the whole
peer via `src/pkgIndex.tcl` (verified in-container: `entity::core 0.1`, the `peer` +
`transport` namespaces present). Registry publish **deferred** (`0.1.0-pre`), matching
the cohort convention.

## Done

- **`src/pkgIndex.tcl`** — the Tcl auto-load index (the `.asd`/`Cargo.toml` analogue).
  A single `package ifneeded entity::core 0.1 [list source … entity_core.tcl]`: the
  umbrella loader sources the whole self-guarding module graph, so `package require
  entity::core` after adding `src/` to `auto_path` loads the entire peer. Verified:
  loads clean, both namespaces resolve.
- **`tools/mkindex.tcl`** — the S5 `package_command` regenerator (profile `[build]`).
  Rewrites `pkgIndex.tcl` so the version lives in one place; verified it reproduces
  the committed index byte-for-byte (no drift). A per-file `pkg_mkIndex` scan is the
  wrong tool here (it needs every module to `package provide`, which the
  umbrella-loads-a-unit model deliberately does not — the graph is one logical
  package).

## Publishing (deferred — matches the cohort)

Per the profile `[publishing]`: Tcl has no single dominant binary registry. Publish =
tag a git release with a working `pkgIndex.tcl` (done), with Tcllib inclusion a later,
review-gated community step. `repository_url` is TBD on first publish (same deferred
state as OCaml/Elixir/CL/Prolog `0.1.0-pre`). The crypto C-extension shim
(`libentitycorecrypto.so`) is a per-platform build artifact (`make shim`), loaded by
the application via `load … Entitycorecrypto` — not indexed as a pure-Tcl package.

## The peer is complete through the conformance gate

S1 (profile) → S2 (codec 69/69) → S3 (peer 12/12) → S4 (`--profile core` **682·0F** @
`cc1970f`, genuine 2-of-3 multisig) → S5 (packaged). The alien-substrate EIAS probe
surfaced **no spec-precision finding** — clean corroboration end to end, which is the
answer the profile was built to get. Steady-state value is now the Tier-tracked re-run
on future amendments (LANDSCAPE tier roster).
