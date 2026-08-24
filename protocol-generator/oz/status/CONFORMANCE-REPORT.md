# entity-core-protocol-oz — Conformance Report

**Gate:** `validate-peer --profile core` → **Result: PASS** — **0 FAIL**.
**Oracle pin:** entity-core-go **`cc1970f`** (core-gate fingerprint `8261a033…`,
`output/s4-oracles/`, PROVENANCE matches `tools/oracle-pin.env`; not rebuilt).
**Spec:** V8 / v0.8.0 snapshot (`protocol-generator/shared/spec-data/v0.8.0/`).
**Date:** 2026-07-15.

## Headline

```
682 · 285P / 301W / 0F / 96S  @ cc1970f    Result: PASS
```

96 skips are the §9.0 extension-only category carve-outs (auto-allowlisted, exempt
from the FAIL gate) — 0 fail-counting skips. Raw JSON: `CONFORMANCE-REPORT.json`.

## Core-gate categories (per-category, from the JSON)

| Category | P | W | F | S | Notes |
|---|---:|---:|---:|---:|---|
| connectivity | 22 | 0 | 0 | 0 | handshake both legs; §6.11 request_id demux (the dataflow-variable claim) |
| encoding | 6 | 0 | 0 | 0 | canonical ECF over the S2 codec |
| type_system | 102 | 298 | 0 | 0 | §9.5 53-type floor; non-floor types WARN (matched-if-present) |
| handlers | 35 | 0 | 0 | 32 | core handler set + §6.13(a) register five-write behavioral round-trip |
| capability | 12 | 0 | 0 | 0 | §5.2/§5.5 verify, attenuation, revoke |
| tree_operations | 24 | 1 | 0 | 31 | CORE-TREE get/put/CAS/delete/listing/path-flex; §9 ext ops skip |
| security | 28 | 0 | 0 | 1 | §5.2a auth-class 401 surfaces |
| multisig | 11 | 0 | 0 | 0 | §3.6 M3 K-of-N reject paths (accept path covered by the unit test below) |
| concurrency | 4 | 1 | 0 | 0 | §4.8/§6.11 demux + §4.9 T2.1/T2.2 (dataflow-thread-per-connection) |
| resource_bounds | 2 | 1 | 0 | 0 | §4.10(a) 413 keeps-serving, §4.10(b) 400 chain-depth; (c) WARN |
| universal_address_space | 8 | 0 | 0 | 0 | §1.4 foreign-namespace paths |
| peer_canonicalization | 7 | 0 | 0 | 0 | §1.5 identity-multihash |
| format_agility | 10 | 0 | 0 | 0 | incl. AGILITY-UNKNOWN-1 (unsupported key_type → 400) |
| crypto_agility | 4 | 0 | 0 | 0 | ed448 / sha-384 via the daemon |
| negotiation | 4 | 0 | 0 | 0 | §4.5 hash-format / key-type negotiation |
| authz | 6 | 0 | 0 | 2 | §5.2a authz-class 403 surfaces (2 skips = ROLE-ext carve-outs) |

The `t1_1_concurrent_demux` WARN and the `resource_bounds` (c) WARN are the same
non-failing warnings the cohort carries; they do not gate.

## Origination-core (reference-peer-gated) — 3/3 PASS

`run-origination-core.sh` (Oz A-role vs Go `entity-peer` B-role @ cc1970f):

```
origination.reference_connect          PASS
origination.reference_ready            PASS
origination.dispatch_outbound_reentry  PASS   ← §6.11 reentry, cross-peer
```

`dispatch_outbound_reentry` is the substantive leg: the peer originates an outbound
EXECUTE back to the validator over the SAME inbound connection. On this substrate
that reentry is a **dataflow send + `{Wait Var}`** on the connection's writer,
correlated by the reader thread's dataflow-variable demux — no correlation pump.
The reader thread never blocks on dispatch (each frame dispatches in its own worker
thread), so the reentry cannot deadlock (the §6.11 concern the S1 watch-item flagged).

## Multisig ACCEPT-path unit test (the oracle can't cover accept)

`make multisig-accept` (`test/multisig_accept.oz`):

```
multisig 2-of-3 ACCEPT verdict = ALLOW
PASS: genuine K-of-N accept path verified
PASS: sub-threshold (1-of-3, need 2) correctly DENIED
```

A genuine 2-of-3 multi-signature ROOT capability, co-signed by 2 of the 3
constituent signers (one being the local peer, per §5.5 M6), verifies to `ALLOW`
through `Cap.verifyChain`; a sub-threshold (1 signature) variant correctly `DENY`s.
This exercises the accept direction the rejection-heavy `multisig` oracle category
never reaches (the "conformance-green can be vacuous" guard).

## S2 codec (lower bar) — 71/71

`make s2`: the pinned 71-vector ECF corpus (`conformance-vectors-v1.cbor`),
decode→re-encode byte-identity + content-hash equality, all PASS. Class B
(content_hash / signature) crosses the entity-codec-daemon live, so the S2 green
co-proves the co-process seam.

## Reproduce

```
# S2 codec
podman run … mozart-toolchain sh /work/protocol-generator/oz/run-s2.sh
# S4 core gate (writes CONFORMANCE-REPORT.json)
./run-s4.sh -profile core -timeout 10m -json-out .../status/CONFORMANCE-REPORT.json
# origination-core (needs the Go entity-peer reference)
./run-origination-core.sh
# multisig accept unit test
podman run … mozart-toolchain make -C protocol-generator/oz multisig-accept
```
