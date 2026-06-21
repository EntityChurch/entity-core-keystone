# ops/

Operational infrastructure.

- **`ci/`** — GitHub Actions (or equivalent) configurations. Podman-aware. Runs wire-conformance + validate-peer-extension-free per language on PR.
- **`release/`** — per-language release scripts; version-pin discipline; NuGet/npm/Maven/crates.io publish helpers (operators-invoked, not auto-run).

## Status

⏳ Both children to be populated by operators as the first language reaches S5.
