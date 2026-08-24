# Changelog — entity-core-protocol-io

## v0.1.0-pre (2026-07-15)

Initial full core peer — **tracks ENTITY-CORE-PROTOCOL v0.8.0 / V8** (Layers 0–4).
The cohort's **pure prototype-based OO paradigm probe** (peer target `io`).

### Codec (S2)
- `EntityCodec` Io C addon over `libentitycore_codec` (C-ABI 1.1): hand-rolled
  canonical ECF in the addon + Ed25519/SHA/peer-id via the C-ABI.
- Wire corpus **71/71 byte-identical** (incl. the uint64 tower via `EcBig`).
- §9.5 type floor **53/53 byte-identical** to the oracle (render-from-model).

### Peer (S3)
- Full core Layers 0–4 authored in Io: framing, envelopes, the §5 capability
  algebra (chain walk, attenuation, caveats, revocation, genuine §3.6 K-of-N
  multisig), §6.5 dispatch, store, §6.9/§6.9a bootstrap + seed policy.
- **§6.6 rendered as differential inheritance** — a `DispatchNode` proto network
  where longest-prefix resolution IS Io's delegation lookup (the probe payoff).
- Transport: single-coroutine non-blocking poll loop; §6.11 reentry a bounded
  synchronous send+wait on the same fd; **non-blocking buffered sends** (per-conn
  `wbuf` flushed at the poll boundary — A-IO-026) so one slow reader never stalls
  the loop.
- Dispatch path made **total (non-raising)** — `tryDecode`/`fromWire`→nil,
  `hashOk` flag for §5.2 step-1, reserved-path passthrough — removing every
  per-request `try` (Io's `try` clones a Coroutine per call → a retain-stack leak;
  A-IO-025).

### Conformance (S4)
- **`--profile core` → `Result: PASS` — 0 FAIL across every gated category,
  `concurrency` included** (682 total: 291 P / 295 W / 0 F / 96 S). connectivity
  22/22; origination-core 3/3; type_system 108/292/0, security 28/0, multisig
  11/0; genuine multisig accept-path unit test.
- **Concurrency:** t2_1 sustained-load (10 000 requests, **0 drops**) + t2_2 churn
  both PASS after the A-IO-025/A-IO-026 fixes. The earlier "single-threaded
  throughput ceiling" (A-IO-023) is **retracted** — it was a misdiagnosis of the
  two bugs above (the slower-crypto Oz/Mozart sibling passes the same checks).

### Toolchain
- Io pinned to the PERMANENTLY frozen native tag `2026.04.20-native-final`
  (+ Socket addon `e348c23`, parson submodule `4f3eaa68`), all SHA-256 pinned;
  gcc-15 dialect flags; build-time GO-gate self-test.
