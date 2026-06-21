# PHASE-S4 — entity-core-protocol-kotlin conformance

**Status: COMPLETE — `validate-peer --profile core` PASS, 0 FAIL. Left UNCOMMITTED for
orchestrator gate.**

S4 stands up the S3 peer's standalone Host launcher and drives the Go `validate-peer`
oracle at it until the core-profile gate reports a clean `Result: PASS` with 0 FAIL,
plus the reference-peer-gated §10.2 `origination-core` probe. Iteration count: **0
peer-correctness fixes** — the S3 peer cleared every core gate on the first oracle run
(the reach-peer / corroboration-only expectation held; the JVM idiom was already
saturated by Java #7, and S3 built the §7a reentry surface, genuine §3.6 K-of-N, §10.1
register, and the v7.75 non-functional floor in anticipation of these gates).

## The oracle (mirror-stable)

Built via the committed `tools/oracle-bootstrap.sh` from the sibling **`entity-core-go`**
pinned at **v7.77 `e8524ed`** (`tools/oracle-pin.env`), `git archive`d into a temp dir
OUTSIDE the go repo and built in `entity-core-keystone/go:latest`:

- **`core_gate_sha256` MATCH: YES** — built oracle reproduces
  `e09a865ffea690ce207149eb68851f7afbc2fa3a9ba522a0ca9d9c72f9923308`
  (`sha256(cmd/internal/validate/profile.go)`), identical to `tools/oracle-pin.env`. The
  core surface == what the 17-peer cohort converged against. (Sibling go HEAD `71b6ba8`
  carries the byte-identical core gate; the commits since `e8524ed` are extension-only —
  the `encryption` category — so the pin and HEAD agree on the core fingerprint.)
- **Sibling go tree clean: YES** — `git status --porcelain` empty + HEAD unchanged
  (`71b6ba8`) before AND after the build; the clean-room `git archive` left no files in
  the SACRED `entity-core-go` tree.
- Binaries (gitignored) in `output/s4-oracles/{validate-peer,entity-peer}`; provenance in
  `output/s4-oracles/PROVENANCE.txt`.

## The gate — `validate-peer --profile core` → PASS, 0 FAIL

Run via `./run-s4.sh` (container-bound, `--network=none`; the Go validate-peer ELF runs
inside `kotlin-toolchain` alongside the peer over one sealed-offline loopback). The Host
launcher is the Gradle `installDist` artifact
(`build/install/entity-core-protocol-kotlin/bin/entity-core-protocol-kotlin`), started
`--name conformance --debug-open-grants --validate`.

```
Summary: 665 total, 292 passed, 278 warned, 0 failed, 95 skipped
Result: PASS (with warnings)
```

- **665 total · 0 FAIL** — exactly the cohort floor on `e8524ed`/v7.77.
- 278 WARN = type_system non-§9.5-floor type vocabulary (matched-if-present, non-blocking)
  + the r3 connection-flood SHOULD; 95 SKIP = §9.0 extension-category carve-outs
  (auto-allowlisted, exempt from the FAIL gate).
- Core categories GREEN: connectivity 22/22 · encoding 6/6 · type_system 108 pass (53-type
  §9.5 floor + core surface) / 276 warn · handlers 35 (core; 32 ext auto-skip) · capability
  12/12 · tree_operations 24 (core) · security 28/28 · multisig 11/11 · concurrency 5/5 ·
  resource_bounds 2 pass + 1 warn · universal_address_space 8/8 · peer_canonicalization 7/7
  · format_agility 10/10 · crypto_agility 4/4 · negotiation 4/4 · authz 6 (core).

### §10.1 core-register gate — 10/10 PASS

`core_register_{body_binding, op_status, op_result, manifest_at_path, handler_at_path,
grant_at_path, grant_signature_at_invariant_path, unregister_status,
unregister_signature_removed}` + `validate_echo_dispatch` — all PASS. The §3.4
invariant-pointer grant-signature is enforced (presence at `system/signature/{grant_hash}`),
unregister symmetry tested, and `validate_echo_dispatch` (the §7a EXECUTE replacing the old
compute/literal roundtrip) PASS.

### `resource_bounds` (v7.75 §4.10) + `concurrency` (§7b) — GREEN

- `r1_payload_over_limit` → **413 payload_too_large** PASS (declared max 16 MiB; a
  16778240-byte length prefix rejected before body buffer).
- `r2_chain_depth_over_limit` → **400 chain_depth_exceeded** PASS (declared max 64; a
  65-deep chain → `chainExceedsDepth` structural pre-check, distinct from the 403 authz
  path).
- `r3_connection_flood` → **WARN** (SHOULD / external-admission; non-blocking — peer kept
  serving under 256 simultaneous connections).
- `concurrency` 5/5 PASS: t1_1 concurrent demux (N=16), t1_2 concurrent reentry (M=8),
  t1_3 no head-of-line, t2_1 sustained load (16×10000, zero drops), t2_2 connection churn
  (100 cycles). Validates the §7b store-safety route (A-KT-011: ConcurrentHashMap +
  CopyOnWriteArrayList, atomic-per-key writes) structurally.

### `multisig` — 11/11 PASS, 0 SKIP — `valid_2of3_peer_signed_accepted` GENUINELY RUNS

"A skip is not a pass." The Host's `--name conformance` surface loads the on-disk Ed25519
identity (`~/.entity/peers/conformance/keypair`, entity-core PEM = base64 of the 32-byte
seed `0x11`×32 → peer_id `2KHoAk…`), so the validator's accept-path probe co-signs a valid
2-of-3 AS the peer (`crypto.LookupKeypairByPeerID`). The peer verifies the quorum
(§3.6 M3 structure + §5.5 M4 distinct-signer threshold + M6 local∈signers) → **200**:
`valid_2of3_peer_signed_accepted` PASS, NOT env-skipped. The 10 rejection checks (M3/M4/M6
deny flips + precedence) all PASS. Genuine cross-impl K-of-N proven against the oracle.

## §10.2 `origination-core` — 3/3 PASS (reference-peer-gated)

Run via `./run-origination-core.sh` (Kotlin target A-role, Go `entity-peer --open-access`
reference B-role, shared loopback `--network=none`):

```
[origination] reference_connect PASS · reference_ready PASS · dispatch_outbound_reentry PASS
Summary: 3 total, 3 passed, 0 failed
```

`dispatch_outbound_reentry` PASS over real two-peer TCP: the validator mints a reentry
capability, EXECUTEs `system/validate/dispatch-outbound` on the Kotlin peer, and the peer
originates an outbound EXECUTE back to the validator-as-B over the SAME inbound connection
(§6.11 reentry — the kotlinx.coroutines reader-coroutine demux + `Peer.outboundDispatch`
over the inbound `Conn`). Closes A-KT-012's inner-200 scope concretely (see the ambiguity
log). origination is extension-only under `--profile core`, so the single-peer `run-s4.sh`
honest-SKIPs it; this gate is the cross-impl wire proof of the seam.

## Ambiguities

No NEW spec defect surfaced (corroboration-only, as the reach-peer mandate predicted).
**A-KT-012 RESOLVED** at the gate (the §6.11 reentry inner-200 is the validator's
cross-peer cap, confirmed via origination-core). All other S1–S3 items unchanged; none
block. Ed448/SHA-384 agility higher-bar remains deferred (floor first).

## Exit criteria — met

- `validate-peer --profile core` → `Result: PASS`, **0 FAIL** (665 total).
- §10.1 register gate 10/10; §10.2 origination-core 3/3 incl `dispatch_outbound_reentry`;
  resource_bounds + concurrency GREEN; multisig 11/11 with the accept-path genuinely running.
- Oracle core_gate_sha256 matches the committed pin; SACRED sibling go tree clean.

## Invocations (orchestrator re-verifies)

```bash
# oracle (pinned ref e8524ed; needs network ONCE for go mod download)
GO_REPO=~/projects/[internal]/[internal]/entity-core-go tools/oracle-bootstrap.sh

# the core gate (sealed-offline, --network=none)
./protocol-generator/kotlin/run-s4.sh

# the §10.2 reference-peer-gated origination-core probe
./protocol-generator/kotlin/run-origination-core.sh
```

> NOTE: left UNCOMMITTED for orchestrator gate/review (per the worktree boundary).
