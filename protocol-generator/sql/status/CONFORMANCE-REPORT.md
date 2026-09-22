<!-- current-pin-banner:7aa6f3de0c67 -->
> **CURRENT (2026-09-08) — spec snapshot `v0.8.2.11`, executed check set `7aa6f3de0c67…`.**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **778 total · 335 pass · 336 warn · 0 FAIL · 107 skip** (elapsed 13444 ms).
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

# SQL peer — S4 Conformance Report

**Gate:** `validate-peer --profile core` → **`Result: PASS`**
**Number (honest, oracle-pinned):** **682·0F @ cc1970f**
**P/W/F/S:** **291 pass / 295 warn / 0 fail / 96 skip** (682 total)

Reproduce: `./run-s4.sh` (writes `status/CONFORMANCE-REPORT.json`). In-container
(`entity-core-keystone/sqlite-toolchain:latest`), capped (`$PODMAN_RUN_CAPS`),
`--network=none` (the static Go oracle runs alongside the peer on loopback). Peer launched
`--name conformance --debug-open-grants --validate`; identity = the cohort deterministic
`0x11×32` seed. All 96 skips are auto-allowlisted §9.0 extension carve-outs — **zero skips
count as FAIL**.

## Honest framing (ADR-0012)

Not independent convergence: the codec/crypto is `libentitycore_codec` (shared C-ABI
lineage) and the peer shares the keystone generation lineage. This is a **cohort-consistent**
0-fail against one author's vectors, not an independent reimplementation. The oracle is the
fresh `cc1970f` build whose `core_gate_fingerprint` reproduced
(`8261a033…3bdc9bf745`) — the same core surface the 40-peer cohort converged against.

## The wrapper-guard held through S4 (the probe's point)

Every post-connect authority verdict is the **authored `src/sql/verify_ladder.sql`**, not a
host allow/deny branch. The host `project_and_verify()` projects the §5.8 authority chain
(`envelope.included` → `peer`/`cap`/`grant_scope`/`signature`/`multi_signer` tables), binds
the request row + `now_ms`, and runs the ladder for the `(status, code)` verdict; only on
`'ok'` does it run the resolved handler BODY. §6.6 resolution is the authored `resolve.sql`.
The authority-as-query harness (`make authority-check`) still passes **13/0F** over real
Ed25519 facts with the S4 ladder (the §5.5 unresolvable-grantee arm reordered — A-SQL-010).

## Per-category (gated) breakdown

| Category | P | W | F | S | Notes |
|---|--:|--:|--:|--:|---|
| connectivity | 22 | 0 | 0 | 0 | §4.1 handshake + §4.6 PoP |
| encoding | 6 | 0 | 0 | 0 | ECF canonical order + hash wire form |
| type_system | 108 | 292 | 0 | 0 | 53-type §9.5 core floor served byte-exact; extension types WARN (matched-if-present, not published) |
| handlers | 35 | 0 | 0 | 32 | MUST handler interfaces + register/unregister/grant; ext handlers auto-skip |
| capability | 12 | 0 | 0 | 0 | request/delegate/revoke/configure + revocation markers |
| tree_operations | 24 | 1 | 0 | 31 | get/put/list, CAS, path-flex, deletion-marker; EXTENSION-TREE §9 ops auto-skip |
| security | 28 | 0 | 0 | 1 | §5.2 verify_request DENY surfaces (ext handler-scope skip auto-allowlisted) |
| multisig | 11 | 0 | 0 | 0 | K-of-N — **accept path confirmed** (below) |
| concurrency | 5 | 0 | 0 | 0 | §7b store-safety + **§6.11 reentry** (correlation-map demux) |
| resource_bounds | 2 | 1 | 0 | 0 | r1 413 / r2 400 chain-depth (r3 conn-flood WARN) |
| universal_address_space | 8 | 0 | 0 | 0 | §1.4 peer-relative ≡ absolute; foreign-namespace isolation |
| peer_canonicalization | 7 | 0 | 0 | 0 | §1.5 peer-id canonical form |
| format_agility | 10 | 0 | 0 | 0 | unknown key_type at authenticate → 400 |
| crypto_agility | 4 | 0 | 0 | 0 | |
| negotiation | 4 | 0 | 0 | 0 | disjoint hash_formats / key_types hello → 400 |
| authz | 5 | 1 | 0 | 2 | §5.2 trichotomy; ROLE-ext skips auto-allowlisted |

(All other categories are whole extension categories, auto-skipped under `--profile core`.)

## Mandatory extras (the directions the core gate can't cover)

- **origination-core: 3/3 PASS** — `./run-origination-core.sh` against the Go `entity-peer`
  (B-role): `reference_connect`, `reference_ready`, **`dispatch_outbound_reentry`** all green.
  The §6.11 reentry seam is a host request_id **correlation map**: dispatch-outbound sends the
  reentry EXECUTE non-blocking + records `(orid→rid)`; the connection loop routes the reentry
  EXECUTE_RESPONSE (by request_id) back to a dispatch-outbound response → many concurrent
  pipelined reentries interleave on the single fd (`concurrency.t1_2` = 8/8).
- **multisig 2-of-3 ACCEPT** — the `multisig` oracle category is rejection-only (vacuous-green
  trap); the authored `k_of_n.sql` `GROUP BY … HAVING count(DISTINCT signer) >= k` accept path
  is proven GREEN in the S3 harness (`multisig_2of3_ACCEPT` + `k_of_n_having_accept` +
  `1of3 REJECT`), and the live `multisig` category is 11·0F.
- **71-vector wire corpus** — re-confirmed byte-identical at S4 (`make check` →
  `71/71 PASS, 0 FAIL @ codec c-abi 1.1`; 79 total with the N1–N4 + KAT self-tests).

## What is NOT claimed

- The type registry is **served from the shared Go-rendered type-registry vectors** (the one
  legitimate byte-exact exception, AGENTS.md — those shapes ARE the spec's type definitions).
  A core peer publishes only the §9.5 floor + operational + bootstrap types; extension
  vocabularies are NOT pre-published (they WARN by absence, matched-if-present).
- Codec/CBOR/crypto are delegated to `libentitycore_codec` (the seam) — this peer probes the
  **authority interior**, not the wire codec.
