# entity-core-protocol-sql — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (publish / close-out)
**Date:** 2026-07-16
**Container:** `entity-core-keystone/sqlite-toolchain:latest` (SQLite 3.50.4 amalgamation,
`libentitycore_codec` C-ABI 1.1, fedora:43)
**Status:** ✅ **Packaging COMPLETE.** `make dist` produces a source tarball of the
`.sql` authority interior + the C seam host + run/conformance scripts. Registry
publish **deferred** (`0.1.0-pre`), matching the cohort convention.

## Artifacts produced

| Artifact | Path |
|---|---|
| README | `README.md` (the authority-as-query probe, the seam boundary, build/run, honest framing) |
| CHANGELOG | `CHANGELOG.md` (`v0.1.0-pre`, tracks v0.8.0 / V8; C-ABI 1.1 pinned) |
| LICENSE | `LICENSE` (Apache-2.0; SQLite public-domain + libentitycore_codec/libsodium notice) |
| Package (`make dist`) | source tarball `dist/entity-core-protocol-sql-0.1.0-pre.tar.gz` |
| Profile | `profile.toml` + `arch/PROFILE-RATIONALE.md` |
| Conformance report | `status/CONFORMANCE-REPORT.{md,json}` (oracle-pinned P/W/F/S) |
| Phase status | `status/PHASE-S1…S5.md` |
| Ambiguity log | `status/SPEC-AMBIGUITY-LOG.md` (A-SQL-001…011; S5 escalation ledger appended) |
| Harnesses | `run-s2.sh`, `run-s3.sh`, `run-s4.sh`, `run-origination-core.sh`, `Makefile` |

## Release-readiness checklist (all green)

- [x] **Live gate:** `validate-peer --profile core` → **`Result: PASS` — 682·0F @
  cc1970f** (291 P / 295 W / 0 F / 96 S). All 96 skips are auto-allowlisted §9.0
  extension carve-outs; **zero skips count as FAIL**.
- [x] **origination-core 3/3** (`run-origination-core.sh`, reference-peer-gated):
  `reference_connect`, `reference_ready`, `dispatch_outbound_reentry`.
- [x] **Wire corpus 71/71** byte-identical (`make check`; 79 with self-tests) @
  codec C-ABI 1.1.
- [x] **Authority harness 13/0F** (`make authority-check`) — the verbatim `src/sql/*.sql`
  over real Ed25519 facts; the wrapper-guard intact (verdict is authored SQL, not a
  host branch).
- [x] **Genuine 2-of-3 multisig accept** proven (the oracle `multisig` category is
  rejection-only — vacuous-green trap; A-SQL-004).
- [x] **Version-pin:** `0.1.0-pre` — tracks ENTITY-CORE-PROTOCOL v0.8.0 / V8; codec
  C-ABI 1.1 / `ec_abi_version` pinned in the CHANGELOG + `profile.toml [deps]`.
- [x] **Ambiguity log finalized** — every item resolved or named-owner-escalated
  (ledger appended to `SPEC-AMBIGUITY-LOG.md`).
- [x] **Packaging verified** — `make dist` emits the tarball of source (no gitignored
  binaries; `libentitycore_codec` + the SQLite amalgamation are documented,
  SHA-pinned build deps, not bundled).

## Version-pin discipline

`0.1.0-pre` (tracks v0.8.0 / V8). Promotion to `0.1.0` is **not** proposed — the
probe's value is the authority-as-query finding (authorization is a query; the
protocol around it is a state machine), not a deployment, and there is no external
consumer of a C+SQL peer of this shape. Seam-hybrid, cohort-consistent (ADR-0012),
not an independent reimplementation.

## Steady state

Tier: **probe** (exploratory ‡ row). Re-run `./run-s4.sh` on each amendment that
touches the wire/authority core; the value is the FINDING, not per-amendment
lockstep. The spec-discovery well is otherwise dry on the current wire surface (per
AGENTS.md), but this peer surfaced two genuinely spec-shaped items (A-SQL-007 /
A-SQL-008) from the *declarative* encoding — the payoff a relational substrate adds
over the general cohort.

## Operator handoff

- **`/entity-rosetta` does NOT publish.** No `git add` / `commit` / tag / push was
  performed — the operator commits + tags after review. `make dist` produces a
  ready-to-publish source tarball; there is no registry push (deferred, cohort
  convention).
- The oracle binaries in `output/s4-oracles/` are pin-verified (`cc1970f`) and were
  NOT rebuilt this phase (S4 already green; S5 is documentation + packaging only).
- **`CONFORMANCE-MATRIX.md` (repo root) row: NOT added by this agent** (out of the
  permitted write scope — `protocol-generator/sql/` only). Proposed row content is
  reported to the overseer.
- **A-SQL-007 / A-SQL-008 → arch:** the overseer is authoring the
  a packet in `docs/outbox/` (the id-scope/path-scope two-strategy
  clarification + the GLOB segment-anchoring note). Escalated to arch, overseer-routed.
