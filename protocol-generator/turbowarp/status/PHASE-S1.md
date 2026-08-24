# Phase S1 — TurboWarp/Scratch feasibility spike + profile

**Peer #32 · TurboWarp / Scratch (visual blocks) · Tier 5 · started 2026-07-12**

Second of the visual-paradigm cohort, informed by the Node-RED peer (#31, `../node-red/`). This is
the **operator's primary target** ("get a version working in Scratch"): TurboWarp is Scratch + JS
custom extensions, the stepping stone to vanilla Scratch. **Visualization is a first-class goal** —
loading the project in the TurboWarp editor and *seeing* the protocol run on the stage.

## Honest framing (ADR-0012)

Not wire-axis discovery (JS runtime, saturated by the TS peer). The axis is **paradigm + authoring
model + visualization**. A conformance pass would be cohort-consistent (shared JS substrate,
delegated codec/engine), not independent convergence — say so. The value is the **visual artifact**
+ generator-robustness on the most extreme substrate yet (imperative visual blocks, not text).

## The three unknowns (Node-RED answered #1/#2 favorably; TurboWarp is harder on #2)

### Unknown #1 — authored vs delegated: RESOLVED (same interop principle as Node-RED)

- **DELEGATED:** canonical CBOR, Ed25519, SHA-256, the §6.5 engine — but **browser-BUNDLED**, not
  `require()`'d. The TS peer's codec is already **browser-portable by design** (`@noble` pure-JS,
  `cborg` browser-ok — the TS profile's A-001 browser-portability choice), so `esbuild` bundles it
  into a single self-contained **TurboWarp custom-extension `.js`**. This is the Node-RED
  codec-bridge, re-expressed as a browser bundle. (The §6.5 engine is also pure-JS — no `node:net`;
  transport is authored separately.)
- **AUTHORED (Scratch blocks + stage):** dispatch routing (custom-block procedures /
  broadcast-by-path), the §4.1 handshake sequence, handlers (as **broadcast receivers** — "when I
  receive handler:echo" — so *adding a handler = adding a receiver*, the intuitive-handlers goal in
  block-native form), and the **stage visualization** (handshake legs, frames in/out, dispatch
  path, capability verdict, established state).

### Unknown #2 — transport + oracle reachability: THE CRUX (partially resolved)

**TurboWarp is sandboxed — no raw TCP.** A browser/VM can open a **WebSocket** but cannot `listen`
on TCP or dial raw TCP. The Go `validate-peer` oracle speaks **TCP** and **initiates** (dials the
peer). A browser peer can neither listen for the oracle nor be dialed. Resolution paths:

| Path | How | Verdict |
|---|---|---|
| **(a) WS↔TCP multiplexing bridge** | A small Node process LISTENs on TCP:7801 (the oracle dials it); the TurboWarp peer connects OUT to the bridge over WebSocket (browser can initiate WS); the bridge relays each oracle TCP connection ↔ a tagged WS stream (multiplexing the oracle's many connections to the one peer). | **Buildable** → oracle gate possible. The harder path; deferred to S3/S4 if pursued. |
| **(b) turbowarp/desktop (Electron) unsandboxed extension** | Desktop TurboWarp can load an unsandboxed extension with Node access → real TCP `net` in the extension. | Possible but couples to desktop; less faithful to "runs in the editor." |
| **(c) codec + smoke + visualization only** | No oracle. Two TurboWarp peers (or a scripted WS client) exercise handshake + dispatch; the stage visualizes. Honest documented scope boundary, NOT a failure. | **The default** — matches the visualize-first intent. |

**Decision:** default scope is **(c) visualization-first** (the operator's stated primary goal —
see it run in the editor). The oracle gate via **(a) the WS↔TCP bridge** is a documented, buildable
*optional* second path (pursue only if a gate score is wanted; expect A-NR-throughput to recur,
worsened by the sandbox + WS + VM-step overhead). This is the **transport-abstraction finding**
maturing (A-NR-transport, opened in the Node-RED log): the cohort/spec assumes **TCP + a dedicated
process**; a sandboxed visual peer cannot satisfy that without a bridge — a real datum about how
tightly the conformance apparatus is coupled to TCP.

### Unknown #3 — does S1→S5 / profile apply? PARTIALLY (bigger stretch than Node-RED)

- Source of truth is a **`.sb3` project** (a zip of `project.json` block-JSON + assets) — even less
  text-diffable than Node-RED's flow-JSON. Mitigation: author blocks in the editor + narrate in a
  **BLOCK-DESIGN.md**; keep the codec extension as reviewable TS→bundle. The `.sb3`'s `project.json`
  is the committed artifact; a screenshot/export documents the stage.
- The **generator model does not render visual blocks from templates** — S2/S3 produce a `.sb3`
  authored (largely by hand / editor) + a bundled extension. This is the sharpest
  "generator-model-doesn't-fit" datum yet (log it in the S-report): /entity-rosetta assumes
  textual source rendering; a block project has no textual template step.

## GO / NO-GO: **GO (visualization-first)**

Proceed to build: (S2) esbuild the TS codec → a TurboWarp custom extension exposing codec/crypto/
dispatch primitives to blocks; (S3) author the `.sb3` — the handshake + dispatch + a handler or two
as blocks, with the stage visualizing; run it in the TurboWarp editor (the deliverable the operator
wants to see). Oracle gate via the WS↔TCP bridge is an **optional** S4 stretch, honestly scoped.

## Decisions

- Codec **interop** via a **browser bundle** (esbuild) of the TS peer; blocks author the logic +
  visualization. Container **reuse node24** (esbuild + scratch-vm + bridge).
- Transport **WebSocket** (authored); oracle reachability **via WS↔TCP bridge (optional)**; default
  scope **visualization-first** (path c).
- Tier **5**; publish **deferred**.

## S1 exit

- [x] `profile.toml` complete (visual-blocks substrate; interop-browser-bundle; transport crux)
- [x] Three unknowns addressed; transport crux resolved with a default (visualization-first) + an
      optional buildable oracle path (WS↔TCP bridge)
- [x] Container: reuse node24
- [ ] S2: esbuild the TS codec → TurboWarp custom extension; smoke it in a headless scratch-vm
- [ ] S3: author the `.sb3` (handshake + dispatch + handler + stage visualization); run in editor
