# entity-core-protocol-python — Phase S4 (Conformance) Summary

**Peer: Python (CPython, clean-room)** · **Branch:**
`lang/python` (worktree). **Status: COMPLETE — `validate-peer --profile core` =
`Result: PASS`, machine-verified `summary.failed == 0` AND `total == 665`.**

## The gate

```
validate-peer --profile core  (oracle entity-core-go e8524ed, peer @ 127.0.0.1:7778)
→ 665 total · 292 pass · 268 warn · 0 FAIL · 93 skip · Result: PASS (with warnings)
   recorded as: 665 · 0F @ e8524ed
```

Counts are oracle-version-specific; the gate is **BOTH** `summary.failed == 0`
**AND** the pinned total. Verified via JSON: `summary = {total:665, passed:292,
warned:268, failed:0, skipped:93}`, and a full scan of `checks[]` confirms **zero
FAIL-severity records anywhere**. The 93 skips are §9.0 profile carve-out
auto-allowlists (whole extension-only categories — subscriptions, continuations,
revision, query, role, identity, attestation, quorum, …) + the handler/authz
extension-op subsets; all exempt from the FAIL gate. The 268 warns are
non-§9.5-floor type vocabulary (matched-if-present, WARN-not-FAIL) + the one
`resource_bounds` r3 SHOULD. (The prompt anticipated ~665; the live total at
`e8524ed` against this peer is 665 — recorded as the verified figure per the
"counts are oracle-version-specific" rule.)

## All 16 core-profile categories — 0-FAIL

| Category | Result | Note |
|---|---|---|
| connectivity | 22p · 0F | |
| encoding | 6p · 0F | |
| type_system | 108p · 262w · 0F | 53-type §9.5 floor PASS; non-floor vocab WARN |
| handlers | 35p · 32skip · 0F | **§10.1 register 10/10** (`core_register_*` all PASS); ext handler ops auto-skip |
| capability | 12p · 0F | |
| tree_operations | 24p · 1w · 0F | core get/put/list/connect; EXTENSION-TREE ops auto-skip |
| security | 28p · 1skip · 0F | |
| **multisig** | **11p · 0F · 0 skip** | incl. `valid_2of3_peer_signed_accepted` PASS (accept path) |
| universal_address_space | 8p · 0F | |
| peer_canonicalization | 7p · 0F | |
| format_agility | 10p · 0F | incl. `agility_unknown_1` (the iteration-2 fix) |
| crypto_agility | 4p · 0F | incl. Ed448 key_type |
| negotiation | 4p · 0F | |
| authz | 6p · 2skip · 0F | ROLE/SUBSCRIPTION ext checks auto-skip (F18/F19) |
| **concurrency** | **5p · 0F** | §7b store-safety + T2.1/T2.2 resilience |
| **resource_bounds** | **2p · 1w · 0F** | r1 payload→413 (MUST) PASS · r2 chain-depth→400 chain_depth_exceeded (MUST) PASS · r3 conn-flood (SHOULD) WARN |

## Iteration count: 2

1. **1 FAIL** — `format_agility.agility_unknown_1`: a handshake `authenticate`
   carrying a `peer_id` whose embedded `key_type` is the unknown `0xFD` returned
   **`401 identity_mismatch`** (the public-key/peer-id binding mismatched first)
   instead of the spec-required **`400 unsupported_key_type`** (§4.6 / §7.1
   crypto-agility: an unknown algorithm is an *unsupported key type*, not an
   identity mismatch). Everything else was already 0-FAIL.
2. **0 FAIL** — added a §4.6 hardening step to `handlers.py::_authenticate`: parse
   the claimed `peer_id` and, if its embedded `key_type != KEY_TYPE_ED25519`,
   return `400 unsupported_key_type` BEFORE the identity binding. This mirrors the
   Go peer's third agility check (arrived-at independently from the spec + the
   AGILITY-UNKNOWN-1 vector; clean-room — the Python sibling `entity-core-py` was
   not opened). One-line semantic fix; S3 regression (loopback 11/11,
   type-registry 53/53, multisig accept 7/7) stays green afterward.

## multisig accept-path (the headline)

`multisig` is **11/11 · 0 skip**, including `valid_2of3_peer_signed_accepted`
(PASS). The host is launched `--name conformance`; `run-s4.sh` provisions
`~/.entity/peers/conformance/keypair` (entity-core PEM = base64 of a 32-byte seed;
the cohort conformance seed `0x11`×32, base64 `ERER…ERE=`). The peer then boots
with peer_id **`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`**, so the oracle's
`crypto.LookupKeypairByPeerID` finds the peer's keypair and **co-signs AS the
peer**, exercising genuine K-of-N ACCEPT rather than env-skipping. A skip would
NOT be a pass; there is no skip here.

## origination-core: 3/3 (reference-peer-gated)

`./run-origination-core.sh` stands up the Python target (A-role, `--validate`) +
a Go `entity-peer -open-access` reference (B-role) inside one
`python-toolchain` container, sealed-offline. All three legs PASS:

```
[origination]  reference_connect PASS · reference_ready PASS · dispatch_outbound_reentry PASS
Summary: 3 total, 3 passed, 0 warned, 0 failed, 0 skipped · Result: PASS
```

`dispatch_outbound_reentry` is the substantive leg: the validator mints a reentry
capability, EXECUTEs `system/validate/dispatch-outbound` on the target, and the
target originates an outbound EXECUTE back to the **validator-as-B over the SAME
inbound connection** (§6.11 reentry — not a fresh dial). The Python §6.11 seam is
the thread-per-connection transport (reader-demux `request_id`→`Condition` pending
map + per-inbound-EXECUTE thread + the reentry primitive on the inbound
connection). This is the cross-impl wire proof of that seam against a Go reference.
The single-peer `run-s4.sh` honest-SKIPs `origination` under `--profile core`
(no `-reference-peer`); the probe runs only here, where `--validate` is on.

## Oracle-build isolation (hard rule — followed)

- Vendored the **committed** snapshot `e8524ed` via
  `git -C <entity-core-go> archive e8524ed | tar -x -C <TEMP>` into a temp dir
  **OUTSIDE** `entity-core-go` (`/tmp/oracle-vendor.*`). Removed the vendored
  `mise.toml` (the host go shim trips on it).
- Built `validate-peer` + `entity-peer` in that temp dir in the
  `entity-core-keystone/go:latest` container (go 1.25.10) with workspace mode
  (`GOWORK=<temp>/go.work`), `CGO_ENABLED=0`, `GOTOOLCHAIN=local`, and
  `GOCACHE`/`GOPATH`/`-o` all on the temp mount. (`GOFLAGS=` cleared the image's
  baked `-mod=mod`, which conflicts with workspace mode.)
- The `entity-core-go` tree was confirmed **clean (`git status -s` empty) BEFORE
  the vendor, AFTER the build, and AFTER all S4 runs** — never `cd`'d into the
  oracle tree, no binary/artifact leaked into it.
- Verified the target symbols compiled into `validate-peer`:
  `cmd/internal/validate/{resource_bounds.go,concurrency.go}`,
  `runConcurrency*`, `valid_2of3_peer_signed_accepted`,
  `dispatch_outbound_reentry`, §5.5 multisig M4/M6.
- Output copied to the **gitignored** `output/s4-oracles/{validate-peer,
  entity-peer}` (confirmed `git check-ignore` + not in `git status`). The temp
  build dir is disposable.

## Isolation / ports

This peer uses TCP **7778** (its own port + own `output/s4-oracles/` + own
`run-s4.sh`), so it does not collide with the concurrent Rust S4 on 7777. Each
run is `--network=none` (netns-isolated), oracle + peer share one loopback inside
the `python-toolchain` container (host podman; not a toolbox). The core image
carries only the runtime dep `cryptography` (no pytest), so the host is driven
with `PYTHONPATH=src python -m entity_core.host` (the S3 convention). The Go
oracle ELFs (fedora:43) run in the same fedora-based image.

## New ambiguity entries

None new this phase. The one peer fix (`400 unsupported_key_type` for an unknown
embedded `key_type`) is **not** an ambiguity — it is an unambiguous §4.6/§7.1
crypto-agility requirement the peer had under-implemented; the oracle's
AGILITY-UNKNOWN-1 vector named the exact expected code. SPEC-AMBIGUITY-LOG.md is
unchanged (the same-as-sibling adoption-peer discovery well stays dry).

## Exit criteria — met

`validate-peer --profile core` = `Result: PASS` (0 FAIL, machine-verified, 665·0F
@ e8524ed) · all 16 core categories 0-FAIL · multisig 11/11 · 0 skip (accept-path
PASS) · concurrency 5/5 · resource_bounds 2/1w/0F · §10.1 register 10/10 ·
origination-core 3/3 (incl. `dispatch_outbound_reentry`) · S3/S2 regression
unbroken · oracle build isolated (go tree clean before+after) · ambiguity log
reviewed (no change). **S4 PASS.**

## Anything blocking S5 (publish) — NONE

The peer is conformant at the higher S7 bar against the pinned oracle. S5 is the
publish/packaging increment (PyPI dist `entity-core-protocol-python`, import pkg
`entity_core`, PEP-440 `0.1.0` — A-PY-005/006; dev-deps pytest layer — A-PY-010;
name availability check — A-PY-006). No conformance debt carried forward.

## Not committed beyond the worktree

Per phase discipline: the changes under `protocol-generator/python` are committed
**LOCAL only on `lang/python`** (`handlers.py` fix, `run-s4.sh`,
`run-origination-core.sh`, the status reports + JSON) — **never pushed**. The
gitignored oracle binaries under `output/s4-oracles/` are NOT committed.

## Reproduce

```bash
# Core gate (sealed-offline; writes status/CONFORMANCE-REPORT.json):
cd protocol-generator/python && ./run-s4.sh

# origination-core 3/3 (reference-peer-gated):
cd protocol-generator/python && ./run-origination-core.sh

# (oracle binaries must be present at output/s4-oracles/ — vendor + build
#  validate-peer + entity-peer from entity-core-go @e8524ed into a temp dir
#  outside the go tree; see "Oracle-build isolation" above.)
```
