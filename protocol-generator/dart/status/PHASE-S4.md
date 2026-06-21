# entity-core-protocol-dart — Phase S4 (Conformance) Summary

**Release "reach" peer** (Dart 3) · **Status: COMPLETE — `validate-peer
--profile core` → 665 total · 0 FAIL · Result: PASS** on the v7.77 oracle (`e8524ed`, core_gate
`e09a865f…`). origination-core **3/3** (incl `dispatch_outbound_reentry`), multisig **11/11**
(incl `valid_2of3_peer_signed_accepted` genuinely running, **0 skip**), concurrency **5/5** (4
PASS + 1 informational WARN), resource_bounds r1/r2 PASS + r3 WARN.

## The gate (binary): `validate-peer --profile core` → 0 FAIL

| Metric | Value |
|---|---|
| Oracle | `validate-peer` from `entity-core-go @ e8524ed` (v7.77 line; pinned by `tools/oracle-pin.env`) |
| core_gate_sha256 | `e09a865ffea690ce207149eb68851f7afbc2fa3a9ba522a0ca9d9c72f9923308` — **matches the committed pin** (mirror-stable: core surface == the cohort's) |
| Peer | `127.0.0.1:7787`, peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` (the `--name conformance` 0x11×32 identity) |
| **Summary** | **665 total · 291 passed · 279 warned · 0 FAIL · 95 skipped** |
| **Result** | **PASS** (with warnings) |

665 total · 0 FAIL is exactly the current cohort floor on `e8524ed`/v7.77 (the total moved
568→573→576→653→665 across oracle versions; the gate is `failed==0`). The 279 warns are the
non-§9.5-floor type vocabulary (matched-if-present, non-blocking); the 95 skips are the §9.0
extension carve-outs (auto-allowlisted, exempt from the FAIL gate — 0 skip-counts-as-FAIL).

**The full 665 needs `-timeout 5m`.** The default 1m budget is consumed by the long real-time
categories (`security` ~20s + `concurrency` sustained-load/churn ~52s) before the later
categories surface; under 1m they get `budget_exhausted`-skipped (which DO count as FAIL).
`run-s4.sh` defaults to `-timeout 5m` so every core category runs to completion.

## The named gate checks (RELEASE-READINESS §4)

| Gate | Result |
|---|---|
| **origination-core** (reference-peer-gated, `run-origination-core.sh`) | **3/3** — `reference_connect` · `reference_ready` · **`dispatch_outbound_reentry`** PASS over real two-peer TCP (validator-as-B over the SAME inbound connection; Go `entity-peer --open-access` reference on :7788). |
| **multisig** | **11/11, 0 skip** — incl **`valid_2of3_peer_signed_accepted` PASS** (genuinely RUNS: the `--name conformance` persistent identity lets the validator co-sign AS the peer; the peer verifies the §3.6 M3 + §5.5 M4/M6 quorum → 200). The other 10 are the rejection battery (all PASS). |
| **concurrency** (§7b) | **5/5** — `t1_2_concurrent_reentry` · `t1_3_no_head_of_line` · `t2_1_sustained_load` · `t2_2_connection_churn` PASS; `t1_1_concurrent_demux` **WARN** (no parallel speedup on a single-threaded event loop — informational, NOT a §6.11 violation; the §6.11(a) no-serialization MUST is enforced by `t1_3`, which passes). |
| **resource_bounds** (§4.10) | r1 payload→`413` (MUST) **PASS** · r2 chain-depth→`400` (MUST) **PASS** · r3 connection-flood **WARN** (§4.10(c) SHOULD, admission delegated externally — not gated). |

## The genuine peer bugs S4 surfaced (and fixed) — A-DART-016

First full run had **2 FAIL**, both in `concurrency` robustness — exactly the corner the
two-peer S3 smoke (a handful of in-flight requests) cannot reach:

- `concurrency / t2_1_sustained_load` — **2263/10000 sustained requests dropped** (read
  deadline exceeded under C×K load).
- `concurrency / t2_2_connection_churn` — peer stopped accepting after cycle 0 (`dial …: i/o
  timeout`), a per-connection resource leak / accept-loop stall.

**Root cause (both, one fix-site — `lib/src/peer/transport.dart`):** the per-connection frame
reassembler was O(n²) per drain. `_drainFrames` called `BytesBuilder.toBytes()` (a full copy of
the *entire* accumulated buffer) on every loop iteration, and after each parsed frame rebuilt the
remainder via `Uint8List.fromList(sublistView(...))` then `clear()`+`add()`. When TCP coalesces
many frames into one chunk (the sustained-load case), this quadratic copy-per-frame starved the
single event loop — both the per-conn reader AND the shared accept callback live on that loop, so
responses missed the deadline (t2_1) and new connects timed out / were never accepted (t2_2).
Compounding t2_2: `Listener._conns` was a `List` that appended every accepted connection and
**never removed it on close** — an unbounded leak across churn cycles.

**Fix (peer-correctness only; oracle/test untouched):**
1. Replaced the `BytesBuilder` reassembly with a single growable `Uint8List` + a consumed-offset
   cursor (`_lo`/`_hi`). Frame parsing advances the cursor in **O(1)** (no whole-buffer rebuild);
   the buffer compacts (shift live tail to front) and grows geometrically only when needed, and
   resets/releases its backing store once fully drained — so an idle or long-lived connection
   pins no memory.
2. `Listener._conns` is now a `Set`; each `_Io.close()` fires an `onClose` callback that removes
   itself (no churn leak). Added `backlog: 1024` to `ServerSocket.bind` so a burst of churn
   connects is not refused while the loop drains. `close()` also frees the reassembly buffer.

No protocol-semantics change — the wire framing, demux, dispatch, and §6.11 reentry behavior are
byte-identical; this is purely the I/O-path complexity bug. After the fix: concurrency **5/5**
(0 FAIL), and **no regression** — `dart analyze --fatal-infos` clean, two-peer smoke **12/12**,
full `--profile core` **665 / 0 FAIL**.

The S2/S3 carry-forward watches all held: §1.5 peer_id re-verified green against the live
`entity-peer` handshake (connectivity 22/22); `dispatch_outbound_reentry` ran live (A-DART-015's
validator-supplied cross-peer reentry cap → inner-200); the multisig accept-path ran via `--name`
(A-DART-016 is the only new defect, an I/O-path bug, not a spec defect).

## What was built this phase (S4 scaffolding — no protocol logic except A-DART-016)

| File | Purpose |
|---|---|
| `run-s4.sh` | the Dart S4 harness: `dart pub get --offline` + AOT-compiles the host (`dart compile exe bin/peer.dart -o build-s4/peer`) offline in the `dart-toolchain` image, provisions `~/.entity/peers/conformance/keypair` (seed `0x11`×32 → peer_id `2KHoAk…`), starts `build-s4/peer --port 7787 --name conformance --debug-open-grants --validate`, waits for `LISTENING`, points `validate-peer -profile core -timeout 5m` at it. `--network=none` (sealed offline; oracle ELF + peer share one loopback). PORT default **7787**. |
| `run-origination-core.sh` | the §10.2 probe: Go `entity-peer --open-access` reference on :7788 (B-role input-shape) + the Dart `build-s4/peer --validate` (A-role) on :7787; `validate-peer -reference-peer … -category origination`. |
| `lib/src/peer/transport.dart` | **the one code change** — A-DART-016 (O(1)-cursor frame reassembly + connection-set lifecycle + backlog). |
| `.gitignore` | added `build-s4/` (the AOT output dir; the compiled exe is not committed). |

The peer source is otherwise the S3 build (the reentry transport + §7a conformance handlers were
already in place — no from-zero S4 transport rewrite, the trap OCaml/COBOL hit).

## Exact reproduction (orchestrator re-verify)

```bash
# from the worktree root (cd [internal]/projects/keystone-worktrees/dart):

# the gate (665 total, 0 FAIL):
podman run --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/dart-toolchain:latest \
  sh /work/protocol-generator/dart/run-s4.sh

# origination-core (3/3 incl dispatch_outbound_reentry):
podman run --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/dart-toolchain:latest \
  sh /work/protocol-generator/dart/run-origination-core.sh

# multisig in isolation (11/11, 0 skip; valid_2of3_peer_signed_accepted RUNS):
podman run --rm --network=none -v "$PWD":/work:Z -e PORT=7791 \
  entity-core-keystone/dart-toolchain:latest \
  sh /work/protocol-generator/dart/run-s4.sh -profile core -category multisig
```

`NOBUILD=1` reuses `build-s4/` across runs; `VALIDATE=0` exercises the §7a honest-SKIP path.

## Phase exit

`validate-peer --profile core` → **665 / 0 FAIL / PASS**; origination-core 3/3 incl
`dispatch_outbound_reentry`; multisig 11/11 (genuine accept, 0 skip); concurrency 5/5;
resource_bounds green. Oracle NOT rebuilt (sha unchanged) · `entity-core-go` NOT touched · only
`protocol-generator/dart/` written in the `lang/dart` worktree. One peer bug found + fixed
(A-DART-016, an I/O-path complexity bug); no new spec defect (the reach-peer prediction held).
Ed448/SHA-384 agility remains deferred (A-DART-003). **S4 PASS.**
