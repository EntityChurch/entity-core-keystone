<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-16) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 332 pass · 339 warn · 0 FAIL · 107 skip** (elapsed 19267 ms).
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

# Pure Data peer (#33) — Conformance Report

**`validate-peer --profile core` @ oracle `cc1970f` (2026-07-15):**

```
682 total · 287 PASS / 299 WARN / 0 FAIL / 96 SKIP — Result: PASS (with warnings)
```

- **0 fail-counting skips.** All 96 skips are V7 v7.72 §9.0 **extension carve-outs** the oracle
  auto-allowlists (extension categories + extension-handler and EXTENSION-TREE probes a core peer
  legitimately 404s/501s). No `-allow-skip` needed; no conditioned skips remain.
- Reproduce: `./run-s4.sh -profile core` (container-bound, `--network=none`; the pd peer runs on
  the REAL Pd runtime — `pd -nogui` — over real loopback TCP; the harness sets the cohort gate
  convention `EC_OPEN_GRANTS=1 EC_VALIDATE=1 EC_NAME=conformance`).
- Raw oracle JSON: `CONFORMANCE-REPORT.json` (same run).
- **Origination-core (§10.2, reference-peer-gated): 3/3 PASS** incl. `dispatch_outbound_reentry`,
  via `run-origination-core.sh` (pd target + Go `entity-peer` reference on shared loopback).
- Offline regression: all 10 S2/S3 targets green (`smoke frametest decodetest responsetest
  treewalktest hellotest authkat authzkat authzdenykat treegetkat`).

## Category highlights

| Category | P | W | F | S | Note |
|---|--:|--:|--:|--:|---|
| connectivity | 22 | 0 | 0 | 0 | §4.1 handshake incl. cross-connection replay |
| security | 29 | 0 | 0 | 0 | §5.2 ladder; `handler_scope_denied` incl. |
| multisig | 11 | 0 | 0 | 0 | **genuine 2-of-3 accept-path** (M3/M4/M6 K-of-N) |
| capability | 12 | 0 | 0 | 0 | request/revoke/configure/delegate, policy + markers |
| type_system | 108P-class | — | 0 | 0 | native render, byte-exact `_match` |
| handlers | 35 | 0 | 0 | 32 | core register five-write green; 32 = extension handlers |
| tree_operations | 25 | 0 | 0 | 31 | put/get/CAS/listing/delete; 31 = EXTENSION-TREE §9 ops |
| concurrency | 5 | 0 | 0 | 0 | t1_1/t1_2 (reentry)/t1_3/t2_1/t2_2 |
| resource_bounds | 2 | 1 | 0 | 0 | r1 413/close, r2 400; r3 flood WARN (kept-serving SHOULD) |
| universal_address_space | 8 | 0 | 0 | 0 | §1.4 foreign namespaces preserved absolute |
| peer_canonicalization | 7 | 0 | 0 | 0 | incl. peer_pattern lazy-canon mint |
| origination | (3/3 via `run-origination-core.sh`) | | | | reference-peer-gated |

## Skip bisection (ADR-0012 — a skip is a failure until justified)

Every one of the 96 skips is a §9.0 extension carve-out the oracle auto-allowlists: extension-only
categories (subscription, continuation, revision, query, compute, attestation, quorum, identity,
role, durability, content, registry, relay, encryption, …), the extension-handler probes
(`handler_{inbox,continuation,subscription,revision}_*`), and the EXTENSION-TREE §9 ops
(`snapshot_*`, `diff_*`, `merge_*`, `extract_*`, `tracked_*`). **No skip masks a missing core
primitive**: multisig, capability, concurrency, resource_bounds, universal_address_space,
peer_canonicalization all have 0 skips.

## Non-vacuous accept-path evidence (the keystone payoff)

- **multisig `valid_2of3_peer_signed_accepted` PASSES** — the chain walk implements real
  §3.6/§5.5 M3/M4/M6 K-of-N verification (find-signature-BY-SIGNER over `included`, root-only,
  local-in-signers-and-signed), exercised because the peer runs with a persistent on-disk
  identity (`EC_NAME`, the `--name` convention) the validator can co-sign with. Before that the
  category was 10/10 rejection-only — green **vacuously** (the classic lesson).
- **tree:put accept path** — put/get/CAS/listing round-trips, not just 4xx rejects.
- **capability accept paths** — request mints a real bounded token; configure writes a real
  policy entry; revoke writes a real marker that the §5.2 step-4 check then enforces
  (`revoked_cap_denied_on_use` PASS).

## Honesty (ADR-0012)

Cohort-consistent, **not** independent convergence: the codec/crypto surface is the shared
`libentitycore_codec` C-ABI (FFI), the peer shares the keystone generation lineage, and the gate
is one author's vectors. The peer is a **visual-paradigm probe** (reactive-patch) whose §6.5
dispatch spine, §5.2 verify ladder, §4.6 auth ladder, and §6.6 walk are authored ON THE CANVAS
(`src/main.pd`); `[ecodec]` owns bytes/CBOR/crypto/store and — after A-PD-002 proved stock
`[netreceive]` broadcasts replies — the TCP transport. It is measured as a real peer and clears
the full gate, but its purpose is paradigm visualization; it is not packaged for deployment.

Oracle provenance: `tools/oracle-pin.env` (`cc1970f`, core-gate fingerprint `8261a03…`).
Findings log: `SPEC-AMBIGUITY-LOG.md` (A-PD-016 ms-precision mints; A-PD-017 open-seed absolute
wildcard; A-PD-015/-006/-008 closed).
