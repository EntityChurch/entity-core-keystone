# entity-core-protocol-rust — Phase S4 (Conformance) Summary

**Peer: Rust (clean-room)** · **Status: COMPLETE —
`validate-peer --profile core` = `Result: PASS`, machine-verified `summary.failed == 0`.**

## Gate

```
validate-peer --profile core   (oracle entity-core-go e8524ed, peer @ 127.0.0.1:7777, --name conformance)
→ 665 total · 292 pass · 268 warn · 0 FAIL · 93 skip · Result: PASS (with warnings)
```

Machine-verified `summary.failed == 0` (and 0 FAIL-severity records across all checks).
The 93 skips are the §9.0 profile extension-carve-out auto-allowlists (whole extension
categories: published_root / registry / discovery / relay / subscriptions / continuations /
role / quorum / attestation / local_files / …), all exempt from the FAIL gate. Live total
is **665 @ e8524ed** — record as `N·0F @ <commit>`; the count is oracle-version-specific
(both `failed==0` AND the total were verified). The +73 over the docs' 576 are
non-failing newer-category skips + the wider type_system warn probe.

## Iteration count: 0 peer-code changes

The peer compiled and reported `0 FAIL` on the **first** oracle run. S3 had already
published the V7 §9.5 53-type registry and wired the full peer surface (the four MUST
handlers + §6.6 routing, §5 capability core incl. §4.10(a)/(b) bounds, §6.13 register-live,
§6.11 reentry, §3.6 K-of-N multisig, §7a conformance handlers), so S4 was a pure
validation pass — no `system/type/*` 404 regression like the Go peer's iteration-1 (the
Rust peer never deferred the registry). **No peer source was touched this phase.**

## All 16 core-profile categories — 0 FAIL

connectivity 22 · encoding 6 · type_system 108P/262W · handlers 35 (incl. §10.1 **register
13/13**) · capability 12 · tree_operations 24 · security 28 · **multisig 11/11/0-skip** ·
negotiation 4 · crypto_agility 4 · format_agility 10 · peer_canonicalization 7 ·
universal_address_space 8 · authz 6 · **concurrency 5** · **resource_bounds 2P/1W** —
**every category 0 FAIL.** Detail + per-category table in `CONFORMANCE-REPORT.md`.

- **resource_bounds:** r1 payload→`413 payload_too_large` (MUST) PASS · r2 chain-depth→
  `400 chain_depth_exceeded` (MUST) PASS · r3 conn-flood→WARN (SHOULD, non-blocking).
- **concurrency:** 5/5 PASS — §7b store-safety (T2.1 sustained-load store-race probe) +
  resilience under load; the `RwLock<HashMap>` store + per-connection thread (N6) hold.
- **§10.1 register:** 13/13 PASS — register req/result type match, body-binding, op
  status/result, manifest/handler/grant at invariant paths, grant signature, unregister
  status + signature-removed.

## multisig — 11/11, 0 skip (accept-path is live, not skipped)

`valid_2of3_peer_signed_accepted` = **PASS** ("peer authorized a valid 2-of-3 multi-sig cap
it co-signed"). Provisioned the peer's persistent keypair at
`~/.entity/peers/conformance/keypair` (PEM = base64 of seed `0x11`×32) and started the host
`--name conformance` (deterministic peer_id `2KHoAk…`), so the oracle's
`LookupKeypairByPeerID` co-signs a genuine 2-of-3 quorum AS the peer. The §3.6 root verifies
M3 structure → M6 local-in-quorum → M4 distinct-signer threshold and ALLOWs. The other 10
rejection probes (threshold bounds, duplicate signers, n=1, below-threshold, M3-precedence)
also PASS. A skip would NOT have counted.

## origination-core — 3/3 over real two-peer TCP

`run-origination-core.sh`: Rust target (A-role, `--validate`) :7777 + Go `entity-peer
--open-access` reference (B-role) :7778, both in the rust-toolchain container,
`--network=none`. `reference_connect` + `reference_ready` + **`dispatch_outbound_reentry`**
all PASS (3/3, 0 skip). The reentry leg: the oracle EXECUTEs `system/validate/dispatch-
outbound` on the Rust target; the target originates an outbound EXECUTE back to the
validator-as-B over the SAME inbound connection (§6.11 reentry — transport.rs reader-demux
+ §6.13(b) OutboundFn seam, not a fresh dial). Cross-impl wire proof of the reentry seam
from the `std::thread`/no-async Rust idiom.

## Supporting gates (no regression)

- S2 codec: 69/69 byte-identical, unbroken.
- S3 loopback: 6/6 + 53-type registry 53/53 + 33 lib units, unbroken.
- Lint floor: `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` clean
  (held from S3; no source changed at S4).

## Oracle build isolation (hard rule, followed)

Vendored the committed `e8524ed` snapshot via `git archive e8524ed | tar -x -C <TEMP>` into
a temp dir OUTSIDE `entity-core-go`; removed the vendored `mise.toml`; built `validate-peer`
+ `entity-peer` from the temp multi-module tree (go.work over cmd/core/ext) with
`GOWORK=<temp>/go.work GOTOOLCHAIN=local CGO_ENABLED=0` and `GOCACHE`/`GOPATH`/`-o` on
temp/output mounts → static ELFs in the gitignored `output/s4-oracles/`. **Oracle tree
`git status -s` empty BEFORE and AFTER** — no leak. Built with the host mise go 1.25.9
(GOROOT pinned explicitly to avoid a stale 1.24.13 GOROOT env leaking the std). Required
symbols verified in the built `validate-peer` (`resource_bounds`, `concurrency`,
`valid_2of3_peer_signed_accepted`, `dispatch_outbound_reentry`, `reference_{connect,ready}`,
`payload_too_large`, `chain_depth_exceeded`).

## Sealed-offline build material

The `--network=none` peer build resolves against a gitignored `cargo vendor --locked`
mirror of the **unchanged** S2/S3 crate closure (`output/vendor/`, ed25519-dalek + sha2 +
transitive — no new dep). `run-s4.sh` injects a `replace-with = "vendored-sources"` config
at run time via a throwaway `$CARGO_HOME` — no `.cargo/config.toml` or vendor tree committed
(A-RUST-008). Both the vendor mirror and the oracle binaries live under the gitignored
`output/` — local tools, never committed.

## New ambiguity-log entries

- **A-RUST-008** — S4 sealed-offline build material via a gitignored `cargo vendor` mirror +
  run-time source-replacement (operator build-mechanism decision; not a spec issue). No NEW
  spec-semantic guess surfaced at S4 — the peer passed clean, consistent with the
  dry-discovery-well finding (the §9.5 floor + full surface were already correct at S3).

## Exit criteria

`validate-peer --profile core` = PASS (0 FAIL, JSON-verified) · all 16 core categories
0-FAIL (resource_bounds, concurrency, §10.1 register 13/13 incl.) · multisig 11/11/0-skip,
accept-path PASS · origination-core 3/3 incl. dispatch_outbound_reentry over real TCP · S2/S3
regression unbroken · oracle build isolated (tree clean before+after) · ambiguity log updated.
**S4 PASS. Nothing blocking S5 (publish).**

## Artifacts (under `protocol-generator/rust/`)

- `run-s4.sh` — single-peer `--profile core` conformance harness (provisions the
  `--name conformance` keypair, `--validate`, offline build).
- `run-origination-core.sh` — reference-peer-gated origination probe (Rust :7777 + Go
  entity-peer :7778).
- `status/CONFORMANCE-REPORT.{md,json}` — green report + raw oracle JSON (`summary.failed==0`).
- `status/PHASE-S4.md` — this summary.
- `status/SPEC-AMBIGUITY-LOG.md` — A-RUST-008 added.
- `output/s4-oracles/{validate-peer,entity-peer}` + `output/vendor/` — **gitignored** local
  tools (not committed).

## Not committed

The gitignored oracle binaries and the `output/vendor/` mirror are NOT committed (local
tools). The scripts + status reports ARE committed on `lang/rust` — LOCAL only, never pushed.
