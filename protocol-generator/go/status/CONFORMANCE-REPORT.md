# entity-core-protocol-go — S4 Conformance Report

**Phase:** S4 (conformance — live oracle gate)
**Peer:** Go (clean-room; built from the spec + sibling lifecycle contracts, NOT
from `entity-core-go` source)
**Oracle:** `validate-peer` / `entity-peer` built from **entity-core-go commit `75c532e`**
(vendored via `git archive` into a temp dir OUTSIDE the oracle tree; binaries in
the gitignored `protocol-generator/go/output/s4-oracles/`)
**Peer host:** `cmd/host` bound to **127.0.0.1:7778** (Go's port; Ruby uses 7777)
**Run isolation:** `podman run --network=none` (netns-sealed, offline); oracle +
peer share one loopback inside the `entity-core-keystone/go:latest` container.

## Gate result — `validate-peer --profile core`

```
Summary: 653 total, 291 passed, 268 warned, 0 failed, 94 skipped (elapsed ~21s)
         93 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL gate
         1 skip(s) conditioned on local-test-env capability (multi-sig on-disk key) — exempt from the FAIL gate
Result: PASS (with warnings)
```

**Machine-verified:** `summary.failed == 0` (and 0 FAIL-severity check records in
the JSON). **GATE PASS.**

### Note on the total (653, not the docs' 576)

The phase prompt and S3 docs named a target of **576 · 0F · 89S**. The live
oracle at `75c532e` emits **653 total · 0 FAIL · 94 skip** for `--profile core`.
The delta is purely in the *non-failing* counts: this oracle commit carries newer
extension categories (`relay`, `encryption`-adjacent, `transport_family`,
`serving_mode`, …) that did not exist in the 576-era registry and that SKIP under
`--profile core` (auto-allowlisted carve-outs), plus a wider `type_system` probe
surface (374 checks: 53 floor + the matched-if-present extension vocabulary that
WARNs). **The binary gate is `failed == 0`, which holds.** The total is reported
honestly as the live `75c532e` value rather than forced to the stale 576 figure.

## The two iterations to green

1. **Initial run: 108 FAIL** — all concentrated in `type_system` (107) and
   `security` (1). Every `type_system` fail was `tree get status 404` for a
   `system/type/*` path: the peer had not published the **V7 §9.5 53-core-type
   registry** (an S3-deferred item, see PHASE-S3 "Not in this phase"). The single
   `security` fail (`captok_form_dispatch_minted_xpeer_presented_pl`, expected
   200/403, got 404) was the same root cause — the cross-peer capability-token
   path resolves through `system/type/system/capability/token`, absent until the
   registry was published.

2. **After publishing the registry: 0 FAIL.** `type_system` → 108 pass / 266 warn
   / 0 fail; `security` → 28 pass / 0 fail. No peer changes beyond the registry
   were needed.

## Supporting gates

| Gate | Result | How |
|---|---|---|
| **53-type §9.5 registry** | **53/53 byte-identical** | `TestCoreTypeRegistryByteIdentical` renders each type from the in-code model through the S2 codec and diffs `content_hash` against the canonical `type-registry-vectors-v1` (S8 golden-file). PASS on first run. |
| **origination-core** | **3/3 PASS** | `run-origination-core.sh`: Go target (A) :7778 + Go `entity-peer` reference (B) :7779, `--profile core -category origination`. `reference_connect` + `reference_ready` + `dispatch_outbound_reentry` (§6.11 reentry over real two-peer TCP) all PASS. |
| **S2 codec regression** | **69/69 + units** | `go test ./...` unbroken. |
| **S3 loopback smoke** | **11/11** | `go test ./peer/` unbroken. |
| **gofmt / go vet** | **clean** | hard Go gate. |

## The type-registry fix (clean-room)

`src/peer/typedefs.go` — the V7 §9.5 floor as an in-code model (`typeDef` +
`fspec` builders, omit-empty render through the peer's own codec), published at
`/{peer}/system/type/{name}` in `NewPeer` bootstrap. Per the cross-peer
render-from-model ruling: the peer expresses types in its own model and its own
encoder computes each `content_hash` — NOT ingest-the-oracle-bytes. The 53
content_hashes reproduce the canonical vectors **byte-for-byte**. Only the §9.5
core + operational + type-system-bootstrap floor is published; extension
vocabularies (`compute/*`, `content/*`, …) are NOT pre-published by a core peer
(refined G4 / F17) — the oracle WARNs (matched-if-present) on those, which does
not gate.

## Per-category status (core-profile, all non-skip categories green)

connectivity 22/0F · encoding 6/0F · **type_system 108P/266W/0F** · handlers
35/0F (32 ext-skip) · capability 12/0F · tree_operations 24P/1W/0F (31 ext-skip)
· **security 28/0F** · multisig 10/0F · concurrency 5/0F · resource_bounds
2P/1W/0F · universal_address_space 8/0F · peer_canonicalization 7/0F ·
format_agility 10/0F · crypto_agility 4/0F · negotiation 4/0F · authz 6/0F (2
ext-skip). All extension-only categories (subscriptions, continuations, role,
relay, registry, discovery, …) auto-skip under `--profile core`.

## go test -race (store-safety)

**Attempted twice (host + container-with-gcc); did not complete in-env** — the
cgo race-detector build stalled both times (host go is a 1.24.13 mise shim below
the go.mod 1.25 floor; the container cold race build exceeded a 540s timeout).
**Non-gating:** store safety is **structural** (`sync.RWMutex` over both store
maps; reads RLock, writes Lock; emit consumers fire outside the lock) AND
exercised live by the oracle's `concurrency` category (**5/5 PASS**, incl. the
§7b T2.1 sustained-load store-race probe) plus the S3 8-way demux. See PHASE-S4.md.

## Ambiguities

No new blocking ambiguities. A-GO-001..006 unchanged. The §9.5 registry render
matched the canonical vectors byte-for-byte, so no field-shape guesses were
needed. See SPEC-AMBIGUITY-LOG.md.

## Reproduce

```bash
# build the oracle (isolated temp dir, NEVER inside entity-core-go):
TMP=$(mktemp -d); git -C ~/projects/entity-systems/entity-core-go archive 75c532e | tar -x -C "$TMP"; rm -f "$TMP/mise.toml"
podman run --rm -v "$TMP":/oracle:Z -v <OUT>:/out:Z -e GOWORK=/oracle/go.work -e CGO_ENABLED=0 \
  -w /oracle/cmd entity-core-keystone/go:latest sh -c 'go build -o /out/validate-peer ./validate-peer && go build -o /out/entity-peer ./entity-peer'

# run the gate (sealed-offline):
podman run --rm --network=none -v "$PWD/protocol-generator":/work/protocol-generator:Z \
  -v "$PWD/protocol-generator/go/output/s4-oracles":/work/output/s4-oracles:Z \
  -e GOWORK=off entity-core-keystone/go:latest sh /work/protocol-generator/go/run-s4.sh

# origination-core:
./protocol-generator/go/run-origination-core.sh
```
