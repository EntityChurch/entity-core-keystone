# entity-core-protocol-ruby — Phase S4 (Conformance) Summary

**Peer #12 (Ruby)** — first dynamic / duck-typed /
scripting peer · **Status: COMPLETE — `validate-peer --profile core` =
`Result: PASS`, machine-verified `summary.failed == 0`. Iteration count: 1 fix
(seed the full 53-type §9.5 floor); first oracle run was already 0-FAIL on every
category except the deferred type registry.**

## Headline

| Gate | Result |
|---|---|
| **`validate-peer --profile core`** | **653 total · 291 P · 268 W · 0 F · 94 S → `Result: PASS`** (machine-verified `failed == 0`) |
| **origination-core** (`./run-origination-core.sh`, reference-peer-gated) | **3/3 PASS** incl `dispatch_outbound_reentry` over real 2-peer TCP |
| **53-type §9.5 registry** | **53/53** fetch+match PASS (content_hash byte-match vs Go reference) |
| Regression (`rake test`) | 32 runs / 66 assertions / 0 fail — ECF 69/69, agility 35/35, smoke 11/11 |

Oracle pin: **`entity-core-go @75c532e`**. See `CONFORMANCE-REPORT.{md,json}`
for the full per-category table.

## Iteration loop (what the oracle caught, what we fixed)

**Run 1** (S3 peer, minimal 5-type seed): `100 failed`, **all 100 in
`type_system`** — 48 floor types absent (`tree get → 404`) + 2 carried-over
(50 `_fetch` FAIL) and the dependent 50 `_match` blocked. Every OTHER core
category was already **0-FAIL on the first oracle contact** (connectivity 22,
encoding 6, capability 12, security 28, multisig 10, concurrency 5,
resource_bounds 2, universal_address_space 8, peer_canonicalization 7,
format_agility 10, crypto_agility 4, negotiation 4, authz 6, handlers/
tree_operations core subsets). The §4.1 reverse-leg handshake bug, the
401/403 trichotomy, the key_type-reject boundary, the §4.10 403→400 chain-depth
— all the cohort's historical S4 reds were already correct in the Ruby peer
(built spec-first against the complete v7.75 snapshot, corroborating rather than
rediscovering). The only gap was the deliberately-deferred full type registry
(A-RUBY-008).

**Fix** (the one S4 build item): seed the full **53-type §9.5 Core Type Floor**
(A-RUBY-008, below).

**Run 2** (full registry): **0 failed · `Result: PASS`**. type_system 1→108
PASS, 0 core FAIL.

## The 53-type registry — render-from-shapes (A-RUBY-008 resolved)

Design per the cross-peer ruling (single-source-of-truth-in-code, diff-against-
Go-golden, **not** ingest-the-served-bytes):

- **Shape source:** dumped byte-exact from the **Go reference registry @75c532e**
  via a throwaway `cmd/dump-floor` tool (built in the same vendored temp tree)
  that mirrors `cmd/internal/validate/typesystem.go` exactly:
  `types.RegisterCoreTypes(reg)` + the validator's augmentation
  (`ReflectType` Hello/Authenticate/tree get/put/listing + the `OverrideField`
  corrections for `peer_id`→`system/peer-id`, put `entity`→`core/entity?`,
  listing `entries`/`path`). For each of the 53 floor names it prints the type's
  ECF `data` payload (hex) and the oracle's `content_hash`. Vendored to
  `lib/entity_core/data/core_type_floor.rb` (`DATA_HEX` + `CONTENT_HASH` maps).
- **Render:** `CoreTypes.floor_entities` **decodes each shape with the Ruby
  peer's own S2-green ECF decoder** and re-materializes a `system/type` entity
  via `Entity.make` — so the content_hash is **recomputed by the Ruby codec**,
  not copied. It then asserts each recomputed hash equals the Go reference's
  pinned hash; a codec divergence would fail loudly at boot. All 53 match
  byte-for-byte (the S2 codec faithfulness, re-proven on the type surface).
- **Scope:** exactly the 53 §9.5 floor types. Non-floor vocabularies
  (`compute/*`, `content/*`, the type EXTENSION, …) are extension-owned and
  intentionally NOT published — the oracle matches them if-present (WARN), never
  FAILs on absence under `--profile core`. The 266 type_system WARNs are those
  non-floor `compute/*` fetch+match checks, all matched-if-present.

## Oracle build isolation (the hard-lesson procedure — followed exactly)

1. `git -C ~/projects/entity-systems/entity-core-go archive 75c532e | tar -x -C
   $TMP` into a `mktemp -d` **outside** the oracle tree.
2. Built `validate-peer` + `entity-peer` in the keystone `go:latest` container
   (`go1.25.10`, satisfies the `go.work` 1.25.0): `-w /src/cmd`,
   `CGO_ENABLED=0 GOWORK=off GOFLAGS=-mod=mod GOPROXY=off`, host
   `~/go/pkg/mod` mounted **read-only** for offline deps. Output to
   `$TMP/out-*`, then **copied** into the worktree's gitignored
   `output/s4-oracles/`.
3. **Verified `entity-core-go` stayed clean** (`git status --short` empty) after
   the build — no `.bin-out/` or any artifact leaked into the sacred oracle.
   The `git archive` snapshot is the committed `75c532e`, independent of the
   working tree.

## Harness (standing reproducers)

- `run-s4.sh` — boots the Ruby peer (`exe/entity-core-peer --port 7777
  --debug-open-grants --validate`, prints a `LISTENING …` readiness line),
  waits for it, runs `validate-peer -profile core -json-out
  status/CONFORMANCE-REPORT.json`. All inside one `--network=none`
  ruby-toolchain container (Go ELF + Ruby share the loopback, sealed-offline).
- `run-origination-core.sh` — Ruby target (A-role, port 7777) + Go `entity-peer`
  reference (B-role, port 7778, `-open-access`); runs `-category origination`.
- `exe/entity-core-peer` — the new standalone host. NB: its signal trap uses
  `exit!(0)` (not `listener.close`); closing the server socket from a trap while
  the accept-loop thread is blocked in the C `accept(2)` CFUNC segfaults MRI
  (`Thread#kill` racing a blocking CFUNC). The harness tears down the whole
  container, so a hard exit is the race-free shutdown.

## Two non-blocking WARNs (both expected; neither a core FAIL)

- `resource_bounds.r3_connection_flood` — peer served all 256 connections without
  refusal. §4.10(c) connection-admission is **SHOULD** / an external-layer
  carve-out (matches the whole cohort); not a core MUST.
- `tree_operations.cleanup` — the oracle's own test-entity teardown ("non-
  critical"), not a peer behavior.

## Ambiguities

No NEW spec-level ambiguity surfaced at S4. The peer reads the complete v7.75
snapshot and corroborated the inherited cohort findings (peer-id §1.5, 401/403
§5.2a, §4.10 resource_bounds, A-JAVA-010 data-shape, the §7a conformance-handler
framing) live against the oracle. A-RUBY-008 (the deferred 53-type seed) is
RESOLVED this phase. A-RUBY-009 Observation-2 (absent `spec-data/v7.75` vector
snapshot) is closed in practice: the live `--profile core` run is the version-
authoritative superset of the codec corpus.

## Exit criteria

`validate-peer --profile core` `Result: PASS`, `summary.failed == 0`
machine-verified · all 16 core categories 0-FAIL · 53/53 §9.5 floor byte-match ·
origination-core 3/3 · codec/agility/smoke regression unbroken · oracle built
under strict isolation (zero writes to `entity-core-go`) · report finalized.
**S4 PASS.** (Not committed — operator reviews + commits.)
