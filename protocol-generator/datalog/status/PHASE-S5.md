# entity-core-protocol-datalog — Phase S5 summary (COMPLETE)

**Phase:** S5 (publish / close-out)
**Date:** 2026-07-16
**Status:** artifacts complete. Registry publish deferred like the cohort
(exploratory spec-discovery probe, `0.1.0-pre`, `publish = false`).

## Artifacts produced (all under `protocol-generator/datalog/`)

| Artifact | Path |
|---|---|
| README | `README.md` (the authority-as-query probe, the seam boundary, build/run, conformance badge, honesty framing) |
| CHANGELOG | `CHANGELOG.md` (`v0.1.0-pre`; spec v0.8.0/V8, C-ABI 1.1 + `ec_abi_version`, ascent 0.8.0 pinned) |
| LICENSE | `LICENSE` (Apache-2.0; Ascent is MIT/Apache-2.0 dual) |
| Package metadata | `Cargo.toml` polished (version `0.1.0-pre`, description, keywords, categories, `rust-version`, repository placeholder) |
| Phase status | `status/PHASE-S1…S5.md` |
| Ambiguity log | `status/SPEC-AMBIGUITY-LOG.md` — finalized (14 resolved, 1 arch-escalated) |
| Conformance report | `status/CONFORMANCE-REPORT.{md,json}` (oracle-pinned P/W/F/S) |
| Harnesses | `run-s2.sh`, `run-s3.sh`, `run-s4.sh`, `run-origination-core.sh` |

No new container run at S5 — S4 is green; this phase is documentation + packaging only.

## Release-readiness checklist (all green)

- **Gate:** `validate-peer --profile core` → **`Result: PASS` — 682 · 0F @ `cc1970f`**
  (292 P / 294 W / 0 F / 96 S; `core_gate_fingerprint 8261a033…`).
- **origination-core:** 3/3 (reference-peer-gated; §6.11 `dispatch_outbound_reentry` live).
- **Multisig accept:** live 2-of-3 accept (the Ascent K-of-N counting aggregate) +
  `k_of_n_2_of_3_accept_path` / `k_of_n_duplicate_signer_does_not_inflate` unit tests.
- **Codec:** wire corpus **71/71** byte-identical via `libentitycore_codec` (C-ABI 1.1).
- **Type floor:** 53-type §9.5 floor served at `system/type/<name>`, rendered natively.
- **Lint:** 29 lib unit tests + loopback + Go-interop GREEN; `cargo clippy -D warnings`
  + `cargo fmt --check` clean.
- **Wrapper-guard:** held through S4 — zero imperative allow/deny added; the §5.2 verdict
  derives end-to-end from the `ascent!` rules (`src/authority.rs`).
- **Ambiguity log:** finalized — 14 resolved, 1 named-owner-escalated (A-DL-013 → arch,
  overseer-routed).
- **Version:** `0.1.0-pre` (tracks ENTITY-CORE-PROTOCOL v0.8.0 / V8). Promotion to
  `0.1.0` not proposed — the probe's value is the finding + the readable
  trust-management reference, not a deployment.

## Honesty framing (ADR-0012)

Tier **probe** (‡, seam-hybrid). The green gate is **cohort-consistent, NOT independent
convergence** — shared generation lineage + the same FFI codec `.so` as the pd/oz/io
seam-hybrid peers. The Ascent layer is the authored half (the §5/§6.6 authority
interior); the Rust host + C-ABI codec is the seam half. Not a deployable-tier peer.

## Steady state

Re-run this peer's harness (`run-s4.sh`) against future spec amendments. The distinctive
maintenance value is that the authority interior is **legible as rules** — an amendment
touching §5/§6.6 authority semantics is a first-class candidate to pull this peer up out
of the default tier, because the diff shows on the rule text.

## Operator handoff

- **No `git add` / `commit`** performed — the overseer commits after review.
- The oracle binaries are pin-verified (`cc1970f`, fingerprint reproduced) and were
  **NOT** rebuilt here (go HEAD moved past `cc1970f` on NETWORK work; re-pinning is a
  policy-§4 decision, not an S5 step).
- **Shared files NOT touched** by this S5 pass (out of peer-local scope):
  `CONFORMANCE-MATRIX.md`, `research/*`, `AGENTS.md`, repo-root `STATUS.md`. The overseer
  adds the matrix row and authors `protocol-generator/shared/evaluations/authority-as-query.md` +
  the `HANDOFF-TO-ARCH` for A-DL-013 (the authority-as-derivation appendix).
- **Proposed `CONFORMANCE-MATRIX.md` §1 row** (overseer to add):
  Peer `Datalog`‡ · Tier `probe` · Spec `v0.8.0` · Oracle `cc1970f` ·
  `--profile core` **682 · 0F** (Result: PASS, 292P/294W/0F/96S) · Codec **seam-hybrid**
  (authored Ascent §5/§6.6 rules + pure-Rust host over C-ABI) · Crypto **FFI** —
  `libentitycore_codec` (libsodium) · Ed448 agility **deferred** (→ FFI, C-ABI
  `ec_ed448_*`) · Publish **source (`cargo build --release`), `0.1.0-pre`**.
