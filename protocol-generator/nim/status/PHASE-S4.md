# entity-core-protocol-nim — Phase S4 summary

**Phase:** S4 (conformance)
**Date:** 2026-07-12
**Spec surface:** v0.8.0 / V8 (`protocol-generator/shared/spec-data/v0.8.0/`)
**Exit status:** ✅ S4 complete — **`validate-peer --profile core` → Result: PASS, 0 FAIL**
(**293·0F @ cc1970f** — 293 P / 293 W / 0 F / 96 S). Origination-core **3/3 PASS** with the
Go reference. Multisig accept-path live PASS + a 4/4 oracle-free unit. S2 codec (71/71) and
S3 smoke (7/7) unchanged.

## Gate

`validate-peer --profile core` at `output/s4-oracles/validate-peer` (`entity-core-go` HEAD
**cc1970f**, core-gate fingerprint **8261a033…**, NOT rebuilt/doctored). Host:
`--port 7788 --name conformance --debug-open-grants --validate`. Full P/W/F/S per category
+ WARN/SKIP justification in `CONFORMANCE-REPORT.md`. **96 skips all §9.0 extension
carve-outs (oracle-auto-allowlisted; 0 manual allow-list; none masks a core primitive).**

## What S4 built (on the S3 machinery)

The S3 dispatch chain resolved handlers to an honest `501 no_handler_body`; S4 implemented
the bodies + the full §5.2 verdict and drove the peer to green.

| Module (new / rewritten) | Role |
|---|---|
| `src/paths.nim` (new) | §1.4/§5.4 URI normalization (`entity://{peer}/…` → absolute) + canonicalize + peer/pattern matching. **The `entity://`-scheme fix was the single highest-impact change** — S3 canonicalize mangled the scheme URI, 404-ing every authenticated EXECUTE (188→6 FAIL once fixed). |
| `src/capability.nim` (new) | §5 verdict core: Scope / GrantEntry / MultiSigGranter / DelegationCaveats / CapabilityToken (total parse), §5.5 multi-link chain-walk, §3.6 K-of-N multisig root (M3 structure → M4/M6 k-of-n), §5.6 attenuation, §5.4 scope-matching, §5.2/§5.4 `check_permission` (+ §PR-8 granter frame). |
| `src/types.nim` (new) | The 53-type §9.5 floor rendered NATIVELY (TypeDef/FSpec model → the peer's own ECF codec, omit-empty), seeded at `/{peer}/system/type/<name>`. All 53 `_fetch`+`_match` byte-identical to the Go registry (drift target `shared/test-vectors/type-registry/type-registry-vectors.diag`). |
| `src/peer.nim` (rewritten) | async §6.5 chain; §5.2 `verify_request` (§5.2a status split: 401 auth / 403 authz / 400 chain_depth / 401 unresolvable_grantee / 403 capability_revoked); handler bodies — tree get/put (+ §CAS create-only + §CORE-TREE-DELETE-1 marker-filter listing), capability request (§6.2 subset → 403 scope_exceeds_authority) / revoke / configure, handler register/unregister (5 writes), §7a echo + dispatch-outbound reentry; §4.5 negotiation + §4.7 key-type reject; §6.9a seed-policy (dual-form lookup + discovery-floor union). |
| `src/transport.nim` | dispatch made async; the §6.11 `OutboundSender` closure supplied to handlers; §4.10(a) oversize → drain + `413 payload_too_large` + keep serving. |
| `src/store.nim` | tree-listing (`listChildren`) + `removeAt`. |
| `src/model.nim` | `ResourceTarget` parse + `boolField`/`arrayField`. |

## Key results

- **Multisig (§3.6):** live `valid_2of3_peer_signed_accepted` PASS (oracle co-signs as the
  peer via the provisioned keypair — genuine K-of-N accept). `tests/tmultisig.nim` adds the
  oracle-free accept-path unit (2-of-3 accepted; below-threshold / bad-threshold / non-local
  quorum rejected) — the antidote to a rejection-only category passing vacuously.
- **§6.11 reentry:** `dispatch_outbound_reentry` PASS against the Go reference;
  `t1_2_concurrent_reentry` PASS (8 concurrent, per-call value-matched). The seam is the
  asyncdispatch single-loop `io.pending` request_id demux — structurally reentry-free
  (A-NIM-006), no correlation-map tax.
- **resource_bounds:** r1 → 413 + keep-serving, r2 → 400 chain_depth_exceeded + keep-serving,
  r3 flood → WARN (§4.10(c) SHOULD; peer survives 256 conns + serves the follow-up).
- **type_system:** 108 PASS / 0 FAIL; the 292 WARN are non-floor `compute/*` extension
  vocabulary a core peer does not publish (matched-if-present).

## Boundaries honored

Wrote ONLY under `protocol-generator/nim/`. Did NOT touch `CONFORMANCE-MATRIX.md`,
`research/`, `docs/status/*`, spec-data, the corpus, or the oracles (oracle used as-is, not
rebuilt/doctored). No git writes — tree left dirty for the overseer to DCO-sign-commit.

## Spec findings

No new **blocking** ambiguity. One informational note logged (A-NIM-010: the vendored
type-vector MANIFEST's `AUTHZ-REVOKED-1` "401" annotation vs the live oracle's / §5.2a
`403 capability_revoked` — the peer follows the oracle/§5.2a and passes; flagged so the doc
note isn't mistaken for a peer bug). A-NIM-009 (§4.2 403 vs §5.2a 401) remains as logged.
