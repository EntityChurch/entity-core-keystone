# Crystal — Phase S4 (CONFORMANCE) summary

**Date:** 2026-07-12
**Oracle:** `entity-core-go` `validate-peer` @ **`cc1970f`**
(`cc1970f448e01b0eea8d8032e076f50b571359ed`, core_gate_fingerprint
`8261a033…f745`; the pinned local oracle in `output/s4-oracles/`).
**Spec-data:** v0.8.0 (V8). **Peer:** `bin/entity-core-peer --port 7777 --name
conformance --debug-open-grants --validate`, run in
`entity-core-keystone/crystal-toolchain:latest` (Crystal 1.20.2 / libsodium
1.0.18), sealed offline (`--network=none`) — oracle + peer share one loopback.

## Verdict

**292·0F @ `cc1970f` — P292 / W294 / F0 / S96** (`--profile core`).

```
Summary: 682 total, 292 passed, 294 warned, 0 failed, 96 skipped (elapsed ~21.5s)
         96 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL gate
Result: PASS (with warnings)
```

Every core-profile category is **0-FAIL**:

| Category | P | W | F | S |
|---|---|---|---|---|
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

The 294 WARN are almost all `type_system` "matched-if-present" probes for
NON-floor (extension) type vocabularies a core peer intentionally does not
publish, plus a `tree_operations.cleanup` and a `resource_bounds` connection-flood
WARN (§4.10(c) SHOULD, external-admission carve-out). The 96 SKIP are the §9.0
extension carve-outs (TREE/CONTENT/RELAY/… ops) auto-allowlisted under
`--profile core` — exempt from the FAIL gate.

## The single peer bug found + fixed at S4

`core_tree_path_flex_1` (§1.4 CORE-TREE-PATH-FLEX-1) failed one sub-pin:
`reject_null_byte` — the peer accepted a path segment containing a NUL byte with
200. `Peer.path_flex_ok?` checked for a space but not control characters. Fix:
reject any C0 control char (`c.ord < 0x20`) in a path segment. Re-run → PASS.
This was the only genuine FAIL across the whole core surface.

## Accept-path units (the direction the oracle can't cover)

The keystone "conformance-green can be vacuous" lesson: the `multisig` category is
mostly rejection probes. Added independent in-process accept-path spec units
(`spec/peer_spec.cr`):

- **§3.6/§5.5 multisig 2-of-3 ACCEPT** — a genuine K-of-N quorum root where the
  local peer is one of three signers, signed by two distinct members, MUST verify
  (`verify_capability_chain` → true). Paired with an M6 fail-closed reject (local
  NOT a signer → false). The oracle's own `valid_2of3_peer_signed_accepted` probe
  ALSO passed LIVE (not skipped) — the peer co-signs as the provisioned
  `conformance` identity — so multisig is not a vacuous pass.
- **§5.5 self-issued chain ALLOW**, **§7a.1 echo accept-shape** ({value:X}
  verbatim), **§4.10(b) in-bound chain not flagged**, and a full in-process
  handshake→404→8-way request_id demux loopback.

Spec suite: **97 examples, 0 failures** (89 S2 + 8 new S3/S4).

## Type registry drift (system/type/*)

Rendered natively (render-from-shapes): decode the vendored Go-dumped ECF `data`
with THIS S2 codec, re-materialize a `system/type`, assert content_hash ==
`CoreTypeFloor::CONTENT_HASH` (the byte-exact Go drift target). All 53 assert
clean at bootstrap; `type_system` 108-pass / 0-FAIL confirms the served bytes are
byte-identical to the oracle's floor.

## Honest framing (ADR-0012)

**Cohort-consistent, NOT independent convergence.** A green verdict corroborates
that the generator lands a conformant core peer on the compiled/typed/fixed-width/
CSP-fiber Crystal substrate; it passes one author's oracle at `cc1970f`. The
discovery well is dry on the current wire surface — the only net-new code was the
NUL-byte path check (a shared-with-cohort validation refinement, not a spec
finding). No new A-CRY blocking ambiguity surfaced.

## Reproduce

```
. tools/podman-caps.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/crystal-toolchain:latest \
  sh /work/protocol-generator/crystal/run-s4.sh -profile core \
     -json-out /tmp/report.json
```
