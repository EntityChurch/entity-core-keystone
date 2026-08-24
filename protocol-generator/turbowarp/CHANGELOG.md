# Changelog — entity-core-protocol-turbowarp

Versions track peer maturity, not the spec (spec surface: entity-core v0.8.0 / V8).

## [0.1.0-pre] — 2026-07-13

First cut of the TurboWarp/Scratch visual-blocks peer (#32). **Experimental
visualization-first probe** — runs + correctness-complete via the bridge, but not gate-green
(throughput boundary below); not published.

### Added
- **Browser bundle** (`extension/ec-core-browser.js` → esbuild IIFE): the pure-JS surface of the
  TS peer (codec, model, identity, capability, store, emit, types, dispatch), self-contained, zero
  `node:` deps. The delegated core, runnable in a sandbox.
- **WS↔TCP bridge** (`bridge/ws-tcp-bridge.js`): makes the sandboxed peer oracle-reachable
  (LISTENs on TCP for the oracle, relays to the peer over one multiplexed WebSocket).
- **Custom extension** (`extension/ec-turbowarp-extension.js` → `dist/entitycore.js`, self-contained):
  loadable in TurboWarp; 10 blocks (connect + reporters + a "when protocol event" hat). Owns the
  WebSocket transport + §1.6 framing + delegated §6.5 dispatch; exposes observable state.
- **Stage project** (`project/entity-core-peer.sb3`, committed + openable; builder
  `project/build-sb3.mjs`): a Scratch 3.0 project that visualizes the peer live on the stage
  (peer id, connection counts, last path/status, a dispatch heartbeat).
- **`run-viz.sh`** (serve extension + bridge for the editor) and **`run-s4.sh`** (oracle gate via
  the bridge). `BLOCK-DESIGN.md` narrates the stage.
- Conformance via the bridge @ `cc1970f`: connectivity **22/22** (proven with the real extension
  code); full `--profile core` **249 P / 293 W / 2 F / 101 S** — identical to Node-RED.

### Known limitations
- **A-TW-throughput** (documented): the 2 FAILs are §6.11 sustained-load/churn robustness; they
  pass standalone and fail only under the full-suite marathon. The lean harness hits the same wall
  as Node-RED → it's the shared delegated engine's sustained-load behavior (engine-level), not a
  per-runtime artifact. Not a correctness defect, not memory-bound.
- Vanilla Scratch (no unsandboxed JS extensions) would need a heavier delegation story — future #33.
- Rich stage art / broadcast-style handler blocks — natural in-editor polish.
