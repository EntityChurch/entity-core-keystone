<!-- current-pin-banner:d30c3dd0d4a1 -->
> **CURRENT (2026-09-01) — spec snapshot `v0.8.2.3`, executed check set `d30c3dd0d4a1…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **756 total · 314 pass · 336 warn · 0 FAIL · 106 skip** (elapsed 3688 ms).
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

# entity-core-protocol-julia — S4 Conformance Report

**Gate:** `validate-peer --profile core` → **Result: PASS, 0 FAIL.**

```
682·0F @ cc1970f   (oracle fingerprint 8261a033…, entity-core-go @ cc1970f)
P 292 · W 294 · F 0 · S 96      (elapsed 23.7s)
```

- **F = 0.** 292 pass, 294 warn (all `type_system` non-floor vocabulary, matched-if-present),
  0 fail.
- **96 skips — all §9.0 extension carve-outs, auto-allowlisted by the oracle** (exempt from
  the FAIL gate). Bisected below: none masks a missing CORE primitive.
- **Codec floor still green:** S2 `wire-conformance` = 71/71 byte-identical (V8 corpus).
- Cohort framing (ADR-0012): Julia is a Tier-3 corroboration peer sharing the generation
  lineage; passing the author's vectors is **cohort-consistent**, not independent convergence.

## Core-profile categories (P/W/F/S)

| Category | P | W | F | S | Notes |
|---|--:|--:|--:|--:|---|
| connectivity | 22 | 0 | 0 | 0 | handshake, nonce, peer_id, protocols |
| encoding | 6 | 0 | 0 | 0 | canonical ECF wire |
| type_system | 108 | 292 | 0 | 0 | 53-type §9.5 floor byte-exact; 292 non-floor WARN (matched-if-present) |
| handlers | 35 | 0 | 0 | 32 | core register/unregister + interface ops; 32 skip = extension handlers |
| capability | 12 | 0 | 0 | 0 | request/delegate/revoke/configure; scope-widening → 403 |
| authz | 6 | 0 | 0 | 2 | 2 skip = system/role (extension vocabulary) |
| security | 28 | 0 | 0 | 1 | 1 skip = system/subscription (extension) |
| multisig | 11 | 0 | 0 | 0 | **accept-path live PASS** + all M3/M4/M6 rejection flips |
| negotiation | 4 | 0 | 0 | 0 | §4.5 hash_format/key_type reject |
| crypto_agility | 4 | 0 | 0 | 0 | |
| format_agility | 10 | 0 | 0 | 0 | incl. AGILITY-UNKNOWN-1 (unsupported key_type → 400) |
| peer_canonicalization | 7 | 0 | 0 | 0 | §1.5 identity-multihash |
| universal_address_space | 8 | 0 | 0 | 0 | §1.4 peer-relative dispatch |
| tree_operations | 24 | 1 | 0 | 31 | core get/put/list; 31 skip = EXTENSION-TREE §9 ops; 1 WARN |
| concurrency | 5 | 0 | 0 | 0 | §7b store-safety + resilience (structural on the Task scheduler) |
| resource_bounds | 2 | 1 | 0 | 0 | r1 413/close, r2 400 chain_depth_exceeded; r3 conn-flood WARN (SHOULD) |

## Skip bisection (ADR-0012 — a skip is a failure until justified)

Every skip is a §9.0 **extension** carve-out the oracle auto-allowlists — a core peer
legitimately 404s/omits these (extensions bring their own vocabulary when installed):

- **handlers ×32** — extension handlers (`handler_inbox_present`, …): "outside --profile core
  (§9.0 extension handler)".
- **tree_operations ×31** — EXTENSION-TREE §9 ops (`snapshot_*`, revision, history, …):
  "§9.0 carve-out: EXTENSION-TREE §9 op skipped under --profile core".
- **authz ×2** — `authz_delegate_grant_1`, `authz_revoked_1`: target `system/role` (extension
  vocabulary); the core peer 404s before the extension-specific check.
- **security ×1** — `handler_scope_denied`: targets `system/subscription` (extension).
- **whole extension categories ×60** — subscriptions, continuations, revision, clock, history,
  query, compute, entity_native, attestation, quorum, identity, role, durability, content,
  registry, relay, encryption, … (1 skip each = "category skipped: extension-only").

**No skip masks a missing core primitive.** `multisig`, `type_system`, `capability`,
`concurrency`, `resource_bounds` have **0 skips**.

## Non-vacuous accept-path evidence (the keystone payoff)

The `multisig` category is rejection-heavy (a fail-closed peer passes vacuously). Both the
oracle's accept probe AND a peer-side unit exercise the ALLOW direction:

- **Live:** `multisig.valid_2of3_peer_signed_accepted` → **PASS** — "peer authorized a valid
  2-of-3 multi-sig cap it co-signed (M4 quorum + M6 root-at-local)" (the oracle co-signs as
  the on-disk `--name conformance` identity).
- **Unit:** `test/multisig_accept.jl` → **8/8 PASS** — valid 2-of-3 ALLOW + the M3/M4/M6 deny
  flips (below-threshold, dup-sig-no-inflate, local-not-in-quorum, threshold∈{1}, dup-signers,
  off-root, single-sig-superset).

## Origination-core (reference-peer-gated)

Single-peer `run-s4.sh` honest-SKIPs `origination` (extension-only under core). Driven via
`run-origination-core.sh` against the Go `entity-peer` reference:

```
origination: 3 pass / 0 fail — reference_connect, reference_ready,
             dispatch_outbound_reentry (§6.11 reentry live, GUIDE-CONFORMANCE §7a.1/§7a.2a)
```

## Type registry drift (S8 target)

`test/typedefs_bytecheck.jl` → **53/53 byte-identical** to `type-registry-vectors.cbor`.
Render-from-model (Julia multiple-dispatch over the peer's own data model), not byte-ingest.

## Reproduce

```
. tools/podman-caps.sh
# gate:
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z -e PORT=7799 \
  entity-core-keystone/julia-toolchain:latest sh /work/protocol-generator/julia/run-s4.sh
# origination-core:
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z -e TPORT=7799 -e RPORT=7798 \
  entity-core-keystone/julia-toolchain:latest sh /work/protocol-generator/julia/run-origination-core.sh
```
