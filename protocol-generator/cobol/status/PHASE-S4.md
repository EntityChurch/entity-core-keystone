# entity-core-protocol-cobol — Phase S4 status (NEAR-COMPLETE)

**Gate (`validate-peer --profile core`):**
**289 PASS / 0 FAIL / 278 WARN (VALIDATE=0); 290 PASS / 1 FAIL (VALIDATE=1).**
The single remaining FAIL is the §6.11 concurrent-reentry test (`--validate`-gated
conformance scaffolding, not core protocol) — see *Remaining*. Every core
protocol category is **0 FAIL** in the full sequential run.

Oracle: `output/s4-oracles/validate-peer` (go `33f35fd`). Host:
`build/host --name conformance --debug-open-grants [--validate]`, peer_id
`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`.

## `--profile core` scoreboard (VALIDATE=0, full sequential run)

| Category | P / W / F / S |
|---|---|
| connectivity | 22 / 0 / 0 / 0 ✅ |
| encoding | 6 / 0 / 0 / 0 ✅ |
| type_system | 108 / 276 / 0 / 0 ✅ |
| handlers | 34 / 0 / 0 / 33 ✅ |
| capability | 12 / 0 / 0 / 0 ✅ |
| tree_operations | 24 / 1 / 0 / 31 ✅ |
| security | 28 / 0 / 0 / 1 ✅ |
| multisig | 11 / 0 / 0 / 0 ✅ |
| concurrency | 3 / 0 / 0 / 2 (t1_1, t2_1, t2_2 pass) |
| resource_bounds | 2 / 1 / 0 / 0 (r1 413, r2 400, r3 flood WARN) |
| universal_address_space | 8 / 0 / 0 / 0 ✅ |
| peer_canonicalization | 7 / 0 / 0 / 0 ✅ |
| format_agility | 10 / 0 / 0 / 0 ✅ |
| crypto_agility | 4 / 0 / 0 / 0 ✅ |
| negotiation | 4 / 0 / 0 / 0 ✅ |
| authz | 6 / 0 / 0 / 2 ✅ |

**Total: 289 PASS · 0 FAIL · 278 WARN · 98 SKIP.** Run:
`sh run-s4.sh -profile core` (add `VALIDATE=1` for the §7a conformance handlers).

## Brain built this phase (the §6.5 dispatch chain)

| Module | Role |
|---|---|
| `src/capability.cob` | §5 verification core — §5.4 pattern matching, §5.2 verify_request / check_permission, §5.5 single-sig + §3.6 multisig chain verification, §5.6 attenuation (per-link §5.5a granter frame), §5.1 revocation, §4.10(b) depth pre-check, §6.6 resolve-handler, included-only authz resolution |
| `src/handlers.cob` | §6.9 bootstrap (MUST handler entities + operation manifests), §6.3 tree get/put/listing (+ deletion-marker filter + path-flex), §6.2 capability request/revoke/configure (+ §6.2 mint-time subset check), §6.13a register/unregister (5 writes), §7a echo handler |
| `src/types.cob` | §9.5 53-type registry (loads `src/core-types.dat`, b-entity-wraps each) |
| `src/connect.cob` | §4.1/§4.6 connect + §4.5 negotiation + AGILITY-UNKNOWN-1 key_type rejection (Base58 peer-id key-type-byte) |
| `src/netshim.c` | single-threaded `poll()` host: stale-revents-on-accept fix, §4.10(a) oversize **drain** (keep serving), §4.10(c) admission |
| `src/store.cob` | content + tree store, bounded; §3.9 listing |

## Remaining (the §6.11 outbound reentry seam — the one hard piece)

Under `--validate` (VALIDATE=1) two tests gate on a reentry-capable host:

- **`t1_2_concurrent_reentry`** (FAIL) — `system/validate/dispatch-outbound`
  must originate an outbound EXECUTE back to the caller over the **same inbound
  connection** (§6.11 reentry) and return the downstream response. The COBOL
  handler currently 503s (`dispatch-outbound-handler` is a stub).
- **`t1_3_no_head_of_line`** (SKIP→FAIL) — fast-not-gated-behind-slow on one
  connection; needs the same reentry/concurrent-dispatch surface.

This is the genuinely-hardest piece for a single-threaded poll-loop host (the
OCaml peer required a `transport.ml` reader-demux rewrite for it). The
implementation path: (1) pass the connection fd into `dispatch` (store it in the
256-byte conn buffer the C host already threads through); (2) a C `ec_reentry(fd,
out_frame, resp_buf)` primitive that writes the outbound frame and reads the
correlated EXECUTE_RESPONSE, demuxing by request_id for the concurrent case; (3)
build + sign the outbound EXECUTE in COBOL from the dispatch-outbound params
(reentry_capability / reentry_granter / reentry_cap_signature / value / target /
operation). Everything else (the §6.13(b) outbound-dispatch authority, the echo
half, the chain) is already in place.

## Honest assessment

S1+S2 complete; the full §6.5 dispatch chain is **live and 0-FAIL across every
core protocol category** in the sequential `--profile core` run (289 PASS). The
peer genuinely verifies capability chains (single-sig + §3.6 K-of-N multisig),
enforces §5.6 attenuation with the §5.5a per-link granter frame, registers
handlers, renders the 53-type floor byte-identically, negotiates §4.5, and
survives oversize / flood / churn (the §4.10(a) drain fix). The one remaining
gap is the §7a/§6.11 concurrent-reentry seam (opt-in conformance scaffolding,
not core protocol). No conformance is claimed that isn't demonstrated (S5/S7).
