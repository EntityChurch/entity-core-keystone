# TurboWarp/Scratch profile rationale

Peer #32, the second visual-paradigm probe and the operator's primary target (the path to Scratch).
One paragraph per major choice.

## Why TurboWarp/Scratch (the axis + the intent)

Not wire discovery — TurboWarp is a JS runtime (Scratch VM), saturated by the TS peer. The bet is
the **most extreme authoring substrate yet**: imperative *visual blocks* + a stage, where the
protocol is not just authored but **watched running**. The operator's explicit goal is to load the
project in the TurboWarp editor and *see* the handshake, frames, and dispatch happen on the stage —
visualization is the deliverable, generator-robustness (does the pipeline survive a non-textual,
block-based substrate?) is the finding.

## Why `interop` via a browser BUNDLE (not require)

Same principle as Node-RED — delegate the mechanical codec/crypto/§6.5 engine, author the logic —
but the substrate is a browser sandbox, so the delegated code must be **bundled for the browser**,
not `require()`'d. This is only feasible because the TS peer's codec was deliberately built
**browser-portable** (`@noble` pure-JS, `cborg` browser-ok — the TS profile's A-001 decision). That
choice, made for a different reason, is exactly what lets a Scratch custom extension carry the
canonical codec. `esbuild` produces one self-contained extension `.js`.

## Why WebSocket transport + the oracle-reachability crux

A sandboxed VM cannot do raw TCP — only WebSocket/fetch. The oracle speaks TCP and dials the peer.
So (unlike Node-RED, which was directly reachable) TurboWarp **cannot be oracle-gated without a
WebSocket↔TCP bridge**. Rather than contort the design, the honest resolution is: **visualization
is the primary scope** (no oracle needed — two peers or a scripted client over WS, stage shows the
protocol), and the **WS↔TCP bridge is a documented, buildable optional path** to a (cohort-consistent)
gate score. This makes A-NR-transport concrete: the conformance tooling assumes TCP + a dedicated
process, which a sandboxed visual peer structurally can't satisfy — a real observation, cleanly
documented rather than papered over.

## Why blocks author the logic + broadcasts carry dispatch

Scratch's native concurrency is **broadcasts** ("when I receive X"), which maps directly onto §6.6
dispatch (route by handler path → broadcast `handler:<path>`; a handler is a receiver). So authoring
a handler is *adding a receiver sprite/script* — the "adding handlers is intuitive" goal from the
Node-RED session, in block-native form. The §4.1 handshake is a block sequence; per-connection state
lives in lists/variables; the stage renders the live state (the visualization).

## Why Tier 5 / node24 / publish deferred

Experimental visualization probe (Tier 5). The esbuild bundle, the headless `scratch-vm` smoke, and
the optional WS↔TCP bridge all run on `containers/node24` — no new toolchain. Publish deferred
(cohort convention); the `.sb3` + extension `.js` are the artifacts.
