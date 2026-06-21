# entity-core-protocol-ruby — Conformance Report (S4)

**Peer #12 (Ruby)** — first dynamic / duck-typed /
scripting peer · **Status: GREEN — `validate-peer --profile core` = `Result:
PASS`, machine-verified `summary.failed == 0`.**

## The gate — `validate-peer --profile core` (V7 v7.72 §9.0)

```
Summary: 653 total, 291 passed, 268 warned, 0 failed, 94 skipped (elapsed ~31s)
         93 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL gate
         1 skip(s) conditioned on local-test-env capability (multi-sig accept path needs the peer's on-disk key) — exempt
Result: PASS
```

- **Oracle pin:** `entity-core-go @75c532e` (the clean snapshot named in the S4
  brief), vendored via `git archive` into a temp dir OUTSIDE the oracle tree and
  built `CGO_ENABLED=0 GOWORK=off` (offline, host modcache mounted read-only) —
  **no writes ever landed in `entity-core-go`** (verified clean after the build).
  Binaries: `output/s4-oracles/{validate-peer,entity-peer}` (gitignored ELFs).
- **Machine verdict:** `jq .summary.failed == 0` → **TRUE**. Severity tally of
  the 653 checks: **291 PASS / 268 WARN / 0 FAIL / 94 SKIP**.
- **Peer:** bound `127.0.0.1:7777` (Ruby's port; Go reference uses 7778), run
  `--debug-open-grants --validate`, container-sealed `--network=none`.

### Total reconciliation — why 653, not the brief's "576"

The brief flagged the total "has moved 568→573→576 … confirm live, don't
assume." Confirmed live: **653** on `75c532e`. `75c532e` is **28 commits after
`62044c5`** (the v7.75 8-peer-rerun oracle that read 576), adding whole new
**extension** categories — `relay` (R1-R7), `discovery`, `registry`,
`published_root` — plus the multisig accept-path check (`33f35fd`). Under
`--profile core` every one of those new categories **auto-skips** (1 SKIP each),
so they inflate the *total* and the *skip* count without touching the FAIL gate.
The gate (`failed == 0`) and every CORE category are unchanged. The 653 is the
correct `75c532e` figure; 576 was the earlier-commit figure.

## Per-category breakdown — all 16 core-profile categories GREEN (0 FAIL)

| Category | P | W | F | S | Notes |
|---|--:|--:|--:|--:|---|
| connectivity | 22 | 0 | 0 | 0 | §4.1 handshake + §6.11 request_id demux |
| encoding | 6 | 0 | 0 | 0 | ECF wire form, hash-format byte, key ordering |
| **type_system** | **108** | **266** | **0** | **0** | **53/53 §9.5 floor fetch+match PASS (content_hash byte-match)**; 266 WARN = the 133 non-floor `compute/*` types matched-if-present (fetch+match), never a core FAIL |
| handlers | 35 | 0 | 0 | 32 | core connect/tree/handler/capability checks; EXTENSION-TREE §9 ops + ext handlers auto-skip |
| tree_operations | 24 | 1 | 0 | 31 | core get/put/list/path; 1 WARN = harness cleanup (non-critical); ext tree-ops auto-skip |
| capability | 12 | 0 | 0 | 0 | §6.2 mint, attenuation, revocation, policy |
| authz | 6 | 0 | 0 | 2 | core verdicts; 2 skips route through EXTENSION-ROLE |
| security | 28 | 0 | 0 | 1 | §5.2 verify; 401/403 trichotomy; no hang on multisig granter caps |
| multisig | 10 | 0 | 0 | 1 | genuine §3.6 K-of-N reject; accept-path needs on-disk key → local-env skip |
| negotiation | 4 | 0 | 0 | 0 | §4.5 hash_formats/key_types advertise + disjoint reject |
| crypto_agility | 4 | 0 | 0 | 0 | Ed25519+Ed448, SHA-256/384 — native stdlib openssl, no FFI |
| format_agility | 10 | 0 | 0 | 0 | key_type/hash-format reject at the earliest boundary |
| peer_canonicalization | 7 | 0 | 0 | 0 | §3.6 PEER-PATTERN / §1.4 v7.65 |
| universal_address_space | 8 | 0 | 0 | 0 | §1.4 foreign-namespace addressing (open-grants advertises `*` + `/*/*`) |
| **concurrency** | **5** | 0 | 0 | 0 | **§7b/§4.8 floor: demux, reentry, no-head-of-line, sustained load, churn** |
| **resource_bounds** | **2** | **1** | 0 | 0 | **r1 payload→413 PASS · r2 chain-depth→400 chain_depth_exceeded PASS** · r3 conn-flood WARN (SHOULD / external admission carve-out) |

Every non-core category present in `75c532e` auto-skips under `--profile core`
(1 SKIP each): subscriptions, continuations, revision, auto_version, clock,
history, query, local_files, compute, entity_native, origination, attestation,
quorum, identity, role, behavioral_role, behavioral_v33, durability, type,
content, serving_mode, transport_family, session, published_root, registry,
discovery, relay.

## Supporting gates

### origination-core — 3/3 PASS (`./run-origination-core.sh`)

`-category origination` with the Go `entity-peer` as `-reference-peer` (B-role,
`-open-access`), Ruby target `--validate`:

```
[origination]
  PASS reference_connect
  PASS reference_ready
  PASS dispatch_outbound_reentry   GUIDE-CONFORMANCE §7a.1 + §7a.2a; PROPOSAL v7.74 §10.2
Result: PASS (3/3)
```

`dispatch_outbound_reentry` is the real wire proof of the §6.11 reentry seam: the
Ruby target originates an outbound EXECUTE back to the validator-as-B over the
**same inbound connection** (thread-per-connection reader-demux + per-inbound
Thread + the `Conn#outbound`→`Io#outbound` reentry primitive). Proven over real
two-peer loopback TCP, no fakes. origination is extension-only under
`--profile core` (auto-skipped there); this is the separate reference-peer-gated
leg the contract asks for.

### 53-type §9.5 registry — 53/53 (A-RUBY-008 resolved)

The full Core Type Floor is published render-from-shapes: each type's
`TypeDefinition` *shape* is vendored (`lib/entity_core/data/core_type_floor.rb`,
dumped byte-exact from the Go reference registry @75c532e — `RegisterCoreTypes`
plus the `typesystem.go` validator augmentation for Hello/Authenticate/tree
get/put/listing + the `OverrideField` corrections). THIS peer **decodes each
shape with its own S2-green ECF decoder** and re-materializes the `system/type`
entity via `Entity.make`, so the content_hash is recomputed by the Ruby codec —
`CoreTypes.floor_entities` asserts at boot that each recomputed hash equals the
Go reference's pinned hash (drift target). All 53 match byte-for-byte; the
oracle's `type_system` floor fetch+match is **53/53 PASS**, `types_all_present`
PASS, `types_listing_available` PASS. This is render-from-shapes / diff-against-
golden, not ingest-the-served-bytes.

### Regression — S2 codec + S3 machinery unbroken

`bundle exec rake test`: **32 runs / 66 assertions / 0 failures / 0 errors** —
ECF corpus **69/69**, crypto-agility **35/35** (Ed448 + SHA-384 native, no FFI),
two-peer loopback smoke **11/11**, the §4.10/§3.9/§7b unit checks. The full
53-type registry render runs inside `Peer.create`; nothing regressed.

## Reproduce

```bash
# the gate (writes status/CONFORMANCE-REPORT.json):
./run-s4.sh

# §10.2 origination-core (reference-peer-gated; Go entity-peer as B-role):
./run-origination-core.sh

# codec + machinery regression:
./run-s3.sh all
```

Oracle build (the isolation procedure — see PHASE-S4.md):
`git -C entity-core-go archive 75c532e | tar -x -C <TEMPDIR-outside-the-oracle>`,
then build `validate-peer` + `entity-peer` in the keystone `go:latest` container
(`CGO_ENABLED=0 GOWORK=off`, host modcache mounted read-only for offline), copy
the two ELFs into `output/s4-oracles/`. No build output ever lands in
`entity-core-go`.
