<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-08) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 334 pass · 337 warn · 0 FAIL · 107 skip** (elapsed 93280 ms).
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

# entity-core-protocol-apl — S4 Conformance Report

**Gate:** `validate-peer --profile core` → **`Result: PASS`**
**Number (honest, oracle-pinned):** **682·0F @ cc1970f**
**P/W/F/S:** **291 pass / 295 warn / 0 fail / 96 skip** (682 total)
**Oracle:** `output/s4-oracles/validate-peer`, fedora:43 ELF, pinned ref **`cc1970f`**
(core-gate fingerprint `8261a033…`, `tools/oracle-pin.env`). Runs INSIDE the
`apl-toolchain` container alongside the peer over intra-container loopback, sealed-offline
(`--network=none`), resource-capped.
**Peer:** GNU APL 1.9 interpreted, launched `apl --script <S3 modules> -f bin/peer.apl --
--name conformance --port 7777 --debug-open-grants --validate`; peer_id
`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` (seed `0x11 × 32`).

## Reproduce (the exact capped, `--network=none` command)

```
./protocol-generator/apl/run-s4.sh
```

which re-execs itself under capped podman:

```
podman run $PODMAN_RUN_CAPS --rm --network=none -v <repo>:/work:Z \
  -w /work/protocol-generator/apl entity-core-keystone/apl-toolchain:latest \
  sh /work/protocol-generator/apl/run-s4.sh
```

(`$PODMAN_RUN_CAPS` from `tools/podman-caps.sh`; default oracle args `-profile core
-timeout 15m -json-out status/CONFORMANCE-REPORT.json`. `ORACLE_TIMEOUT` overrides the
budget — interpreted APL is much slower than compiled peers; the `concurrency` flood alone
is ~1m40s wall-clock, but the real gate is the per-request cap, not wall-clock.)

## Per-category result (core-profile active categories)

| Category | Pass | Warn | Fail | Skip | Notes |
|---|---:|---:|---:|---:|---|
| connectivity | 22 | 0 | 0 | 0 | |
| encoding | 6 | 0 | 0 | 0 | |
| type_system | 108 | 292 | 0 | 0 | §9.5 53-type floor PASS; 292 WARN = non-floor extension vocabulary (matched-if-present, absent → WARN, non-gating) |
| handlers | 35 | 0 | 0 | 32 | core register/interface/get; 32 skip = extension handler ops |
| capability | 12 | 0 | 0 | 0 | §5 verify/mint/delegate/revoke/configure |
| tree_operations | 24 | 1 | 0 | 31 | core get/put/list/CAS/path-flex + §9.5a CORE-TREE-{PUT,LISTING,DELETE,PATH-FLEX}-1; 31 skip = EXTENSION-TREE (snapshot/diff/extract/merge) |
| security | 28 | 0 | 0 | 1 | |
| multisig | 11 | 0 | 0 | 0 | **§5.5 M4/M6 accept-path ran GENUINE K-of-N** (see below) |
| concurrency | 4 | 1 | 0 | 0 | §6.11 reentry + churn + sustained + head-of-line all PASS; `t1_1` WARN = no parallel speedup (informational for a single-thread event loop, not a violation) |
| resource_bounds | 2 | 1 | 0 | 0 | r1 413 + r2 400 chain_depth_exceeded PASS; r3 conn-flood WARN (SHOULD) |
| universal_address_space | 8 | 0 | 0 | 0 | peer-relative≡absolute round-trip + foreign-namespace addressability + isolation |
| peer_canonicalization | 7 | 0 | 0 | 0 | |
| format_agility | 10 | 0 | 0 | 0 | |
| crypto_agility | 4 | 0 | 0 | 0 | |
| negotiation | 4 | 0 | 0 | 0 | §4.5 hash/keytype disjoint-reject |
| authz | 6 | 0 | 0 | 2 | §A4-AUTHZ code trichotomy; 2 skip = ROLE-ext cascade carve-out |

All other categories (`subscriptions`, `continuations`, `origination`, `role`, `query`,
`compute`, `attestation`, `quorum`, `identity`, `relay`, `registry`, `discovery`,
`encryption`, … — 30 categories) are **whole extension categories auto-allowlisted by the
V7 v7.72 §9.0 profile carve-out** (exempt from the FAIL gate).

## Skips — all honestly allow-listed (none counts as FAIL)

**96 skips, 0 counting as FAIL.** The oracle summary line reads exactly:
`96 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL
gate` — with NO accompanying "N skip(s) count as FAIL" line. Every skip is the profile's own
§9.0 extension carve-out (whole extension categories + extension operations inside core
categories: 32 handler-ext, 31 EXTENSION-TREE, 2 authz ROLE-ext, 1 security, + the 30
extension categories). `origination` auto-skips (extension-only under core). Nothing is
hand-allow-listed by this peer.

## Multisig accept-path — GENUINE K-of-N (not env-skip)

`multisig.valid_2of3_peer_signed_accepted` **PASS**. `run-s4.sh` provisions the peer's
persistent Ed25519 identity at `~/.entity/peers/conformance/keypair` (entity PEM = base64 of
seed `0x11 × 32`, matching the launcher default so peer_id is unchanged). The oracle looks up
that keypair (`crypto.LookupKeypairByPeerID`) and CO-SIGNS AS the peer, so the 2-of-3
multi-granter cap is genuinely verified: `VerifyMultisigRoot` requires the local peer to be
one of the N signers and counts ≥ threshold valid signatures over the cap hash. This is a
real K-of-N verification, not a fail-open/env-skip.

## Honesty notes

- `682·0F @ cc1970f` — total 682, **0 fail**, at oracle ref `cc1970f`. P/W/F/S =
  291/295/0/96.
- Warnings do not gate: 292 (type_system non-floor vocabulary, matched-if-present) + 3
  (tree_operations path-flex advisory, concurrency no-speedup, resource_bounds r3 SHOULD).
- This is a keystone-generated peer sharing the generation lineage of the cohort —
  **cohort-consistent, not independent convergence** (ADR-0012). The oracle was never
  doctored; every S4 FAIL was a peer bug fixed from the spec (A-APL-017). No spec-vs-oracle
  divergence was found → no arch handoff.
- S2 codec corpus stays green (69/69, `make conf` + unit ALL PASS); S3 offline self-test
  (18/18) + two-peer loopback smoke (5/5) stay green.
