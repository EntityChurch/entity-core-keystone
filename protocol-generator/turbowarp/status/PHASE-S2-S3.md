# Phases S2–S3 — TurboWarp/Scratch build

**Peer #32 · TurboWarp / Scratch (visual blocks) · Tier 5 · 2026-07-13**

Follows PHASE-S1 (visualization-first GO). Records the browser bundle (S2), the transport bridge +
architecture proof (S3), and the loadable custom extension + visualization (S3).

## Built + proven

**S2 — browser bundle (`src/extension/ec-core-browser.js` → `dist/ec-core-browser.js`).** esbuild
(0.28.1, S11) bundles the pure-JS surface of the TS peer (codec, model, identity, capability, store,
emit, types, dispatch — NOT transport/fs) into a self-contained 229KB browser IIFE, **zero `node:`
leakage**. Smoke: `createKernel` → peer_id `2KHoAk7A…` (identical to the Node-RED kernel), connect
resolves, 53-type registry seeded, codec round-trips. The delegated core runs in a browser context.

**S3 — transport + oracle reachability (the A-NR-transport resolution).**
- `src/bridge/ws-tcp-bridge.js`: a WS↔TCP multiplexing bridge — LISTENs on TCP (the oracle dials it),
  relays each TCP connection to the peer over one WebSocket, tagged by connId. The browser-Rust/WASM
  pattern (a sandbox can only WebSocket out).
- `src/harness/ec-peer-node.js`: headless stand-in for the extension (browser bundle + WS + §1.6
  framing + dispatch), used to prove the path.
- `src/extension/ec-turbowarp-extension.js` → `dist/entitycore.js` (234KB, self-contained): the
  **custom extension you load in TurboWarp**. 10 blocks (connect / reporters for peer id, open +
  established connections, dispatch count, last path, last status / a "when protocol event" hat /
  an "established?" boolean). Owns transport + delegated dispatch; exposes observable state for the
  stage. `src/BLOCK-DESIGN.md` narrates the stage visualization.

**Conformance @ `cc1970f` (via the bridge — the optional gate path):**
- `-category connectivity`: **22/22 PASS** — proven with BOTH the harness AND the **actual extension
  code** (`connect()` driven, oracle vs the bridge) → the sandboxed-peer-via-bridge architecture works.
- `--profile core`: **249 P / 293 W / 2 F / 101 S** (`status/CONFORMANCE-REPORT.json` when run with
  default args) — **identical to Node-RED**, all correctness categories green. The 2 FAILs are the
  §6.11 sustained-load/churn throughput boundary (**A-TW-throughput**, confirmed): the LEAN harness
  (no Node-RED overhead) hits the SAME boundary → it is the shared delegated-engine's full-suite
  sustained-load behavior, inherited by both visual peers, not a per-runtime artifact. Not a clean
  gate; not published.

## Visualization (the primary deliverable)

`run-viz.sh` serves the extension + runs the bridge (+ optional oracle traffic loop) so the peer
loads into the TurboWarp editor and the **stage becomes a live protocol monitor** (peer id, the
established/open connection counts ticking through the handshake, the dispatch heartbeat, per-request
path + status). See README + BLOCK-DESIGN.

## Honest framing (ADR-0012)

Cohort-consistent, not independent — the codec/engine are the TS peer's, bundled. Value is the
**watchable protocol** + generator-robustness on a visual-block substrate, and the confirmed
cross-substrate **A-TW-throughput** finding. The §6.11 throughput boundary is now characterized as
engine-level (both visual peers), not runtime-specific.

## Status

- **S2/S3: complete + proven** — browser bundle, bridge, extension all built; connectivity 22/22 and
  full core 249·2F via the bridge; extension loadable + visualization launcher ready.
- **S4: exercised via the bridge** (optional path) — 249·2F, same boundary as Node-RED.
- **Stage `.sb3`: BUILT** — `src/project/entity-core-peer.sb3` (committed, openable; rebuild via
  `npm run bundle:sb3`). A dependency-free builder (`src/project/build-sb3.mjs`) emits a valid
  Scratch 3.0 project: Stage + a Heartbeat sprite, a green-flag script (connect → forever mirror
  the reporters) + a "when protocol event → next costume" heartbeat, 5 variable monitors, all
  wired to the `entitycore` extension blocks. Validated: graph integrity (every next/parent/input/
  var-ref/asset resolves), all 7 opcodes match the extension, valid store-only zip. Load the
  extension URL first, then open the `.sb3`.
- **S5: docs done** (README/LICENSE); registry publish gate-blocked (2F), as Node-RED. Optional
  polish: richer stage art / a broadcast-style handler block — natural in-editor next steps.
