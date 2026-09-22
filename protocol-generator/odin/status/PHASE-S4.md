# Odin — Phase S4 (Conformance) summary

**Date:** 2026-07-12
**Oracle:** `validate-peer` @ **cc1970f** (`cc1970f448e0…`; core_gate_fingerprint
`8261a033…`, matches `output/s4-oracles/PROVENANCE.txt`)
**Profile:** `core` (extension-free categories; oracle auto-allowlists §9.0 skips)
**Verdict:** **292 · 0F @ cc1970f** — **PASS (0 FAIL)**

## Gate result

```
Summary: 682 total, 292 passed, 294 warned, 0 failed, 96 skipped (elapsed ~21s)
         96 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out
Result: PASS (with warnings)
```

**P/W/F/S = 292 / 294 / 0 / 96.** Every live core-profile category is 0-FAIL.

## Per-category (live checks; P/W/F/S)

| Category | P | W | F | S |
|---|--:|--:|--:|--:|
| connectivity | 22 | 0 | 0 | 0 |
| encoding | 6 | 0 | 0 | 0 |
| type_system | 108 | 292 | 0 | 0 |
| handlers | 35 | 0 | 0 | 32 |
| capability | 12 | 0 | 0 | 0 |
| tree_operations | 24 | 1 | 0 | 31 |
| security | 28 | 0 | 0 | 1 |
| multisig | 11 | 0 | 0 | 0 |
| concurrency | 5 | 0 | 0 | 0 |
| resource_bounds | 2 | 1 | 0 | 0 |
| universal_address_space | 8 | 0 | 0 | 0 |
| peer_canonicalization | 7 | 0 | 0 | 0 |
| format_agility | 10 | 0 | 0 | 0 |
| crypto_agility | 4 | 0 | 0 | 0 |
| negotiation | 4 | 0 | 0 | 0 |
| authz | 6 | 0 | 0 | 2 |

(Categories with only SKIPs are the extension surface, auto-allowlisted by the
§9.0 `--profile core` carve-out — subscriptions, compute, origination, registry,
relay, identity-as-extension, etc.)

## The three WARNs — all benign (none mask a FAIL)

1. **type_system (292)** — non-floor extension types (compute/*, registry/*,
   relay/*, subscription/*, …) that a *core* peer correctly does NOT publish:
   *"absent — outside §9.5 Core Type Floor — matched-if-present, not-a-FAIL-if-
   absent."* This is the intended behavior: a core peer never pre-publishes
   extension vocabularies (durable lesson: extensions bring their own types). The
   108 PASSes are the floor matches; the peer's own 53 render byte-identical to the
   Go vector set (proven by the `type_registry_byte_identical_to_go` unit).
2. **resource_bounds r3_connection_flood** — the peer accepted all 256 connections
   without refusal and **kept serving**. §4.10(c) admission is a SHOULD with an
   explicit external-layer carve-out (systemd/proxy/OS), so this is a WARN, not
   gated. §4.9 resilience is satisfied (no crash under the flood).
3. **tree_operations cleanup** — the *validator's own* post-test cleanup could not
   remove a test entity ("non-critical"); not a peer defect.

## Accept-path units (the directions the oracle can't cover)

The `multisig` category is 100% rejection tests (11/11 malformed→deny), which a
fail-closed peer passes vacuously. The keystone payoff is the *finding* + the fix:
`test/peer_test.odin` adds the accept direction as fast in-process units under a
tracking allocator —

- `multisig_k_of_n_accept_and_deny_flips` — a genuine 2-of-3 root (local peer in
  quorum, 2 valid sigs over the cap content_hash) → **Allow**, plus each M3/M4/M6
  invariant flip → Deny (1 sig < threshold, duplicate sig doesn't inflate the
  count, local-not-in-quorum, threshold=1, duplicate signers). Proves the multisig
  primitive is IMPLEMENTED, not just fail-closed.
- `single_sig_root_still_verifies` — the strict-superset sanity.
- `type_registry_byte_identical_to_go` — all 53 core types render byte-identical to
  the Go `type-registry-vectors` drift target.
- `echo_round_trips_params` — the §7a echo interface bootstraps under `--validate`.

## Reproduce

```
. tools/podman-caps.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/odin-toolchain:latest \
  sh /work/protocol-generator/odin/run-s4.sh -profile core \
     -json-out /work/protocol-generator/odin/status/CONFORMANCE-REPORT.json
```

Sealed offline (`--network=none`; oracle + peer share one loopback in-container).
The host is provisioned with the fixed `0x11×32` seed at `~/.entity/peers/
conformance/keypair` so the multisig accept-path probe can co-sign as the peer.

## Honest framing (ADR-0012)

**292·0F is cohort-consistent, not independent convergence.** The oracle and the
type-registry vectors are the Go author's artifacts; a single peer passing one
author's vectors is not a second independent witness. The value here is
generator robustness on a fresh raw-thread / no-GC / value-error / no-package-
manager shape, and the multisig accept-path finding is the keystone payoff as much
as the green verdict. No spec ambiguity surfaced (expected — the discovery well is
dry on this saturated wire surface; Odin is a T3 corroboration peer).
