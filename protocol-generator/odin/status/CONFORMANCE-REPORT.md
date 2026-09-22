<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-08) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 335 pass · 336 warn · 0 FAIL · 107 skip** (elapsed 1894 ms).
>
> That digest is the pinned `core_executed_check_set_digest`, so this number is
> comparable to every other row in `CONFORMANCE-MATRIX.md` §1 — and it is a CONTENT
> anchor, which is the only kind that survives the release boundary ([ADR-0012] Am. 1).
> The machine-readable `CONFORMANCE-REPORT.json` beside this file is the authoritative
> artifact; `tools/check-set-gate.py --tracked` gates it, and this banner is generated
> from it by `tools/status-banner.py` rather than typed.
>
> **Everything below this line predates this measurement and is retained as build
> history.** Where it disagrees with the figures above, the figures above win;
> `CONFORMANCE-MATRIX.md` §1 is authoritative for the cohort.

---

# entity-core-protocol-odin — S4 Conformance Report

**Date:** 2026-07-12
**Phase:** S4 (live-peer conformance)
**Peer:** `entity-core-protocol-odin` (corroboration / generator-robustness, T3)
**Oracle:** `validate-peer` @ **cc1970f** (`output/s4-oracles/PROVENANCE.txt`;
core_gate_fingerprint `8261a033…`)
**Profile:** `core` · **Network:** none (sealed offline) · **Toolchain:** odin
dev-2026-06:285f6d8 · **Container:** entity-core-keystone/odin-toolchain:latest

> The S2 codec report (71·0F wire-conformance) is preserved at
> `CONFORMANCE-REPORT-S2.{md,json}`. This file + `CONFORMANCE-REPORT.json` are the
> S4 live-peer gate — the JSON is the raw `validate-peer` output.

## Verdict: 292 · 0F @ cc1970f — PASS

| Metric | Count |
|---|--:|
| Pass | 292 |
| Warn | 294 |
| **Fail** | **0** |
| Skip | 96 (auto-allowlisted by the §9.0 `--profile core` carve-out) |
| Total | 682 |

**0 FAIL across every live core-profile category.** The 96 skips are the
extension surface exempt from the FAIL gate under `--profile core`. The 294 warns
are all benign (see below).

## Live categories (P/W/F/S)

connectivity 22/0/0/0 · encoding 6/0/0/0 · type_system 108/292/0/0 · handlers
35/0/0/32 · capability 12/0/0/0 · tree_operations 24/1/0/31 · security 28/0/0/1 ·
multisig 11/0/0/0 · concurrency 5/0/0/0 · resource_bounds 2/1/0/0 ·
universal_address_space 8/0/0/0 · peer_canonicalization 7/0/0/0 · format_agility
10/0/0/0 · crypto_agility 4/0/0/0 · negotiation 4/0/0/0 · authz 6/0/0/2.

## Warns — none mask a failure

- **type_system (292):** non-floor extension types a *core* peer correctly does not
  publish ("matched-if-present, not-a-FAIL-if-absent"). The 53 floor types render
  byte-identical to the Go `type-registry-vectors` set (unit-proven).
- **resource_bounds r3_connection_flood (1):** 256 connections accepted without
  refusal, peer kept serving — §4.10(c) admission SHOULD w/ external-layer carve-out.
- **tree_operations cleanup (1):** the validator's own cleanup step, non-critical.

## Accept-path coverage (oracle-uncoverable directions)

The `multisig` category is 100% rejection (11/11 deny). Added in-process accept
units (`test/peer_test.odin`, leak-checked): a genuine 2-of-3 K-of-N **Allow** +
all M3/M4/M6 deny flips; single-sig root Allow; the 53-type byte-diff; §7a echo
bootstrap. `odin test test` → 11/11 green, leak-clean.

## Honest framing (ADR-0012)

**292·0F is cohort-consistent, not independent convergence.** The oracle + type
vectors are the Go author's artifacts; one peer passing one author's vectors is
generator robustness on a fresh substrate (raw threads, no-GC context allocators,
value-return errors, no package manager), not a second independent witness to the
protocol bytes.
