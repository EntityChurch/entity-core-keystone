# entity-core-protocol-turbowarp

An **entity-core core-protocol peer authored for TurboWarp/Scratch** — the second visual-paradigm
probe (peer #32), and the path toward vanilla Scratch. The protocol runs behind a **custom
extension** (the delegated codec/crypto/§6.5 engine, bundled for the browser) and is made
**watchable on the stage** via blocks. Visualization is the primary deliverable.

> **Honest status (ADR-0012).** Cohort-consistent, not independent — the codec + engine are the
> TypeScript peer's, bundled. Value: the *watchable* protocol + generator-robustness on a visual
> substrate + the confirmed cross-substrate throughput finding (A-TW-throughput).

## The transport crux (resolved)

TurboWarp is sandboxed — no raw TCP; it can only WebSocket **out** (the browser-Rust/WASM pattern).
The Go `validate-peer` oracle speaks TCP and dials the peer. So oracle-gating goes through a
**WS↔TCP bridge** (`src/bridge/ws-tcp-bridge.js`): it LISTENs on TCP (the oracle dials it) and
relays each connection to the peer over one WebSocket. Pure visualization needs no oracle at all.

## Authored vs delegated

The goal is the peer **authored in Scratch** — the §6.5 dispatch logic on the canvas — with only
the things Scratch physically can't do behind a small utility seam. See `src/BLOCK-DESIGN.md`.

- **DELEGATED — the utility seam only** (`src/extension/ec-utils-extension.js`, esbuild → the
  loadable `ecutils` extension): the socket + §1.6 framing, canonical CBOR, Ed25519/SHA-256 + the
  capability-chain verdict, and reading fields off / building entities. Exactly what Scratch has no
  type or capability for — nothing more. There is deliberately **no `dispatch` block**.
- **AUTHORED — the protocol, as Scratch blocks** (`src/project/entity-core-peer.sb3`): the §6.5
  dispatch is a `when execute arrives` **guard ladder** (connect-preauth → author/capability
  presence → signature → capability chain → resolve/404 → permission/403 → handler), a faithful
  block-for-line map of `dispatcher.ts#dispatchCore`. Every `if` and status code is visible.

> **Conformance (the Scratch-authored dispatch):** `validate-peer --profile core` @ `cc1970f` →
> **291 P / 294 W / 0 F / 97 S — Result: PASS** (all skips exempt). Zero failures — cleaner than the
> earlier wrapper (`249·2F`). Run headless by `src/harness/run-blocks.mjs`, which interprets the
> real `project.json` block graph against the oracle through the bridge. Caveat: that's the block
> interpreter, not the TurboWarp VM runtime — a manual editor run is the final confirmation. Handler
> *bodies* beyond echo (handshake, tree) are still delegated, to be pulled onto the canvas next.

## See it (the visualization)

```
podman run --rm -p 8601:8601 -p 7802:7802 -p 7801:7801 -v "$PWD":/work:Z -v kc-npm:/root/.npm \
  entity-core-keystone/node24:latest sh /work/protocol-generator/turbowarp/run-viz.sh
# add TRAFFIC=1 (as an -e env) to loop the oracle so the stage moves
```
> ⚠ **localhost is blocked from `https://turbowarp.org` by default** (Firefox Local Network Access /
> Chrome Private Network Access auto-deny). This gates the `ws://localhost:7802` bridge too, so
> loading the extension from a local file does **not** help. Two ways through:
> - **Recommended: [TurboWarp Desktop](https://desktop.turbowarp.org)** — not a public origin, so the
>   policy never applies; localhost + unsandboxed extensions just work (same steps below).
> - **Quick (browser): Firefox** `about:config` → set `network.lna.blocking = false` (revert when
>   done — it relaxes the feature for all sites). Chrome: allow the site's insecure private-network
>   requests, or use the desktop app.

Then: open the editor (**TurboWarp Desktop**, or **https://turbowarp.org** after the toggle) → Add
Extension → Custom → URL `http://localhost:8601/ecutils.js` (unsandboxed; the host must be the
literal `localhost` — `127.0.0.1`/`0.0.0.0` are rejected) → **File → Load from your computer →
`src/project/entity-core-peer.sb3`** → open the **peer** sprite → you'll see the `when execute
arrives` script: the full §6.5 dispatch guard ladder in blocks. Green flag to run it; the stage
monitors (peer id / last path / last status / dispatch count) move as requests flow.

The `.sb3` is a committed, self-contained deliverable (`src/project/entity-core-peer.sb3`, rebuildable
via `npm run bundle:sb3`). Load the `ecutils` extension **before** opening it so TurboWarp resolves
the blocks by id.

## Conformance (optional, via the bridge)

```
podman run --rm -v "$PWD":/work:Z -v kc-npm:/root/.npm \
  entity-core-keystone/node24:latest sh /work/protocol-generator/turbowarp/run-s4.sh -profile core
```
@ `cc1970f`: connectivity **22/22**; full `--profile core` **249 P / 293 W / 2 F / 101 S** — all
correctness green; the 2 FAILs are the §6.11 sustained-load/churn throughput boundary
(**A-TW-throughput**), an engine-level cross-substrate boundary, not a correctness defect. Not
gate-green; not published.

> ⚠ **This number is the earlier JS-wrapper shape** (the `run-s4.sh` harness drives the delegated
> engine directly). The **Scratch-authored dispatch** (`ecutils` + the `.sb3` guard ladder) is the
> current direction and is **not yet re-measured** — that needs a headless scratch-vm S4 harness (or
> a manual TurboWarp run) against the oracle. No number is claimed for it until it's run (ADR-0012).

## Layout

```
profile.toml                 interop-browser-bundle strategy + the transport crux
src/extension/ec-core-browser.js       delegated core codec/crypto (bundled → browser IIFE)
src/extension/ec-utils-extension.js    the `ecutils` UTILITY SEAM (socket/CBOR/crypto only) — CURRENT
src/extension/ec-turbowarp-extension.js legacy do-everything wrapper (drives run-s4.sh) — being retired
src/project/build-sb3.mjs      compiles the §6.5 dispatch guard ladder → entity-core-peer.sb3
src/bridge/ws-tcp-bridge.js   WS↔TCP multiplexing bridge (oracle reachability)
src/harness/run-blocks.mjs    headless S4: interprets the REAL project.json blocks vs the oracle
src/harness/ec-peer-node.js   legacy wrapper stand-in (drives run-s4.sh)
src/BLOCK-DESIGN.md           the stage visualization + block script
run-viz.sh                    serve extension + bridge (visualization)
run-s4.sh                     oracle gate via the bridge
status/                       PHASE-S*.md, SPEC-AMBIGUITY-LOG.md
```

## License

Apache-2.0 (repo `LICENSE`). DCO sign-off on contributions.
