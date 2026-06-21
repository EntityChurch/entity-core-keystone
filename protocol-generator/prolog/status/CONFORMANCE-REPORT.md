# entity-core-protocol-prolog — Conformance Report

**Peer #13** (SWI-Prolog — the cohort's first logic-programming peer) ·
**Status: GREEN** · Human-readable rendering of [`CONFORMANCE-REPORT.json`](CONFORMANCE-REPORT.json).

## Headline result

| Gate | Result |
|---|---|
| **`validate-peer --profile core`** | **653 total · 291 P · 269 W · 0 F · 93 S → `Result: PASS`** |
| machine-check | `summary.failed == 0` read straight from `CONFORMANCE-REPORT.json`; 0 FAIL entries in `checks` |
| oracle pin | **`entity-core-go @75c532e`** (vendored fedora ELF, BuildID `482ee754…`; the oracle Ruby + Go scored against) |
| S2 codec | **69/69** ECF byte-identical (through the foreign codec) + **10/10** crypto KAT |
| §9.5 type floor | **53/53** byte-identical (content_hash recomputed via the C-ABI codec, asserted == Go @75c532e) |
| S3 loopback smoke | **11/11** (handshake + dispatch + capability + 8-way request_id demux) |
| origination-core | **3/3** over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`) |

```json
{"total": 653, "passed": 291, "warned": 269, "failed": 0, "skipped": 93}
```

Peer addr `127.0.0.1:7777`, peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`. The
653-vs-576 total against the v7.75 8-peer-rerun is purely later-oracle extension categories that
auto-skip under `--profile core` (the FAIL gate + the core categories are unchanged — the same
653·0F·9xS class Ruby + Go measured against this oracle).

## Per-category breakdown (machine-rendered from the JSON)

| Category | P | W | F | S | Note |
|---|---:|---:|---:|---:|---|
| connectivity | 22 | 0 | 0 | 0 | handshake, nonce, peer_id, replay |
| encoding | 6 | 0 | 0 | 0 | |
| type_system | 108 | 266 | 0 | 0 | 53/53 §9.5 floor PASS; 266 WARN = non-floor `compute/*`/`clock/*` matched-if-present-not-FAIL-if-absent |
| handlers | 35 | 0 | 0 | 32 | core register/unregister/dispatch; 32 SKIP = extension handler sub-pins (cohort parity) |
| capability | 12 | 0 | 0 | 0 | request / revoke / configure / **delegate** |
| tree_operations | 24 | 1 | 0 | 31 | CAS, path-flex, delete-marker omission; 31 SKIP = EXTENSION-TREE §9; 1 WARN = oracle's own `cleanup` |
| security | 28 | 0 | 0 | 1 | incl. expired / not-before / temporal-chain DENY (`temporal_ok/1`, lit up at S4) |
| multisig | 11 | 0 | 0 | 0 | §3.6 K-of-N incl. the keypair-provisioned accept path |
| concurrency | 4 | 1 | 0 | 0 | t1_2 / t1_3 / t2_1 / t2_2 PASS; 1 WARN = `t1_1` no-parallel-speedup (informational) |
| resource_bounds | 2 | 1 | 0 | 0 | 413 / 400-chain-depth PASS; 1 WARN = `r3_connection_flood` (external admission SHOULD) |
| universal_address_space | 8 | 0 | 0 | 0 | absolute / peer-relative / foreign-namespace addressing |
| peer_canonicalization | 7 | 0 | 0 | 0 | |
| format_agility | 10 | 0 | 0 | 0 | incl. AGILITY-UNKNOWN-1 (key_type 0xfd → 400) |
| crypto_agility | 4 | 0 | 0 | 0 | |
| negotiation | 4 | 0 | 0 | 0 | disjoint hash_formats / key_types → 400 |
| authz | 6 | 0 | 0 | 2 | 2 SKIP = ext-vocabulary carve-outs (role / ROLE §5.5) |
| *extension categories* (subscriptions, clock, query, compute, origination, identity, role, attestation, quorum, registry, discovery, relay, …) | — | — | — | 1 each | auto-allowlisted by the §9.0 `--profile core` carve-out (exempt from the FAIL gate) |

**All 16 core categories are 0-FAIL.** Per-category counts above are read directly from the
`checks` array; `type_system` is 108 PASS / 266 WARN (374 entries) — the 53-type §9.5 floor PASSes
byte-exact and the 266 WARN are non-floor extension type vocabulary, matched-if-present.

## The three non-`type_system` WARNs (all benign, recorded honestly)

```
tree_operations  cleanup               WARN :: failed to remove test entity (non-critical)
                                              [the oracle's OWN teardown, not a peer behaviour]
concurrency      t1_1_concurrent_demux WARN :: demux + completeness 16/16 OK, but no parallel
                                              speedup observed (informational; NOT a §6.11
                                              violation — the real no-head-of-line MUST is t1_3,
                                              which PASSes)
resource_bounds  r3_connection_flood   WARN :: opened all 256 connections without refusal — §4.10(c)
                                              connection-admission is a SHOULD / external-layer
                                              carve-out (whole-cohort behaviour)
```

These are the SAME three WARNs the Ruby peer recorded (whole-cohort behaviour); none is a core
MUST and none counts toward the FAIL gate. Per the operator goal (functionality over performance),
the `t1_1` no-speedup result is *information, not a blocker* — SWI's one-native-thread-per-connection
model correctly demuxes (16/16 completeness) but shows no wall-clock parallelism on this fast
in-memory peer, and the oracle itself classifies it informational.

> The cohort-parity note: Ruby scored 268W/94S where Prolog scores 269W/93S — a one-check WARN-vs-SKIP
> swing in the late extension categories under this oracle, not a core-behaviour difference. Both are
> 653·0F with all core categories green.

## How conformance works here

The Go `validate-peer` ELF is the *runtime checker* (unlike S2's fixture-producer model): it
drives a LIVE Prolog peer over loopback and scores 653 checks. `run-s4.sh` builds the C-ABI floor
(S2), provisions the peer keypair at `~/.entity/peers/conformance/keypair` (seed `0x11×32`, so the
§3.6 multisig accept-path probe can co-sign AS the peer), boots `prolog/ec_host.pl --port 7777
--name conformance --debug-open-grants --validate`, waits for `LISTENING …`, then runs
`validate-peer -addr 127.0.0.1:7777 -profile core -timeout 180s -json-out
status/CONFORMANCE-REPORT.json`. The `-timeout` is bumped from the 1-minute default because the
`security` + `concurrency` categories run ≈70 s; the default budget-SKIPped the late categories.

## §Reproduce

In-container, sealed-offline (oracle + peer share one loopback, `--network=none`):

```sh
# from the keystone repo root:
podman run --rm --network=none -v "$PWD":/work:Z -w /work -e ORACLE_TIMEOUT=300s \
  entity-core-keystone/prolog-toolchain:latest \
  protocol-generator/prolog/run-s4.sh
#  → Result: PASS (with warnings) ; validate-peer exit rc=0
#  → asserts summary.failed == 0 in status/CONFORMANCE-REPORT.json
```

The oracle ELFs under `output/s4-oracles/` are gitignored (large binaries). Rebuild them
`CGO_ENABLED=0` from `entity-core-go @75c532e` (verify the BuildID with `readelf -n`), vendor into
`output/s4-oracles/{validate-peer,entity-peer}`. The C-ABI codec lib + the SWI foreign shim are
byte-built by `run-s2.sh` inside the image — not committed.

## What the oracle caught (the iteration loop — S4 detail)

The cross-impl oracle surfaced real bugs the loopback (self-consistent) gates could not. Full
detail in [`PHASE-S4.md`](PHASE-S4.md) §3; in brief: the **`key_type 0x00 → 0x01`** handshake
showstopper (A-PL-010a — the §1.5 key registry codes Ed25519 = 0x01, not 0x00; opaque-digest S2/S3
hid it because both loopback peers shared the wrong byte); handler operation maps + the `delegate`
op (501 → minted child); CAS / path-flex / delete-marker; §4.5 negotiation; the §6.11
dispatch-outbound reentry (which needed the A-PL-017 anonymous-mutex + A-PL-018 module-qualified-seam
fixes). Every fix is a real peer change — no hardcoded outputs, no stubbed handlers.

**Verdict: GREEN — 653·0F·93S @ 75c532e** (machine-verified `summary.failed == 0`).
