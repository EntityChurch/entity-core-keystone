# entity-core-protocol-node-red

An **entity-core core-protocol peer authored as a Node-RED flow-graph** — the first of the
visual/dataflow-paradigm probe cohort (Node-RED → TurboWarp → Scratch). Peer #31.

The bet is not wire-axis discovery (Node-RED runs on Node.js, already covered by the native
TypeScript peer). It is a **new axis: paradigm + authoring model.** entity-core's §6.6 dispatch
("route by handler path") maps directly onto Node-RED's core semantic ("route messages over
wires") — so the peer's control flow is a *graph you can see and edit*, not textual source.

> **Honest status (ADR-0012).** A green result here is **cohort-consistent corroboration on a
> shared JS substrate**, not independent convergence — the codec and §6.5 engine ARE the
> TypeScript peer's. The value is visualization + generator-robustness.

## The authored-vs-delegated boundary (the whole design)

| | Where | What |
|---|---|---|
| **DELEGATED** (`interop`) | `lib/codec-bridge.js` + `lib/peer-kernel.js` — `require()` the compiled TS peer | canonical CBOR, Ed25519, SHA-256, the ECF model, and the §6.5 dispatch **engine** (verify → resolve → permission → handler). The mechanical/crypto "libraries." |
| **AUTHORED** (the graph) | `nodes/ec-listener.js` + `lib/session.js` + `flows.json` | TCP transport + §1.6 framing, the §6.11 demux, dispatch routing, reentry correlation, the response loop. **Wires ARE the routing.** |

Every wire carries **CBOR frame bytes** — exactly what the TCP wire carries. (Node-RED deep-clones
`msg` between nodes, which flattens class instances, so envelopes are reconstructed inside each
node, never carried across a wire. The faithful consequence, not a workaround.)

See `src/FLOW-DESIGN.md` for the node-by-node narration and `arch/PROFILE-RATIONALE.md` for the why.

## Run it

All commands run in the `node24` container (from the repo root). The delegated TS codec builds
first (`dist/`); Node-RED (4.1.11, S11-pinned) is in `src/package.json`.

**Conformance (headless):**
```
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none \
  -v "$PWD":/work:Z entity-core-keystone/node24:latest \
  sh /work/protocol-generator/node-red/run-s4.sh -profile core
```

**See it in the browser (the visual "pass-through"):**
```
podman run --rm --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 \
  -p 1880:1880 -p 7801:7801 -v "$PWD":/work:Z \
  entity-core-keystone/node24:latest sh /work/protocol-generator/node-red/run-editor.sh
```
Then open **http://localhost:1880** — the *entity-core peer* tab shows the graph
(transport → classify demux → dispatch / reentry). Double-click a function node to read/edit its
code; drop a **Debug** node on a wire + Deploy to watch live CBOR-byte messages. The peer is live
on `:7801` the whole time — run `run-s4.sh -category connectivity` against it and watch frames
flow through the nodes in real time.

## Conformance

`validate-peer --profile core` @ oracle `cc1970f`: **249 P / 293 W / 2 F / 101 S**
(`status/CONFORMANCE-REPORT.json`). **Not a clean gate.** All correctness categories are green
(connectivity 22/22, type_system 108 P, multisig 11 with a real 2-of-3 accept-path, security 28,
capability 12, agility/negotiation, and the §6.11 concurrency *correctness* tests). The two FAILs
are §6.11 **sustained-load / churn robustness** (`t2_1`/`t2_2`) — a documented **Node-RED-substrate
throughput boundary** (they pass standalone; see `status/SPEC-AMBIGUITY-LOG.md` → **A-NR-throughput**),
not a correctness defect. Per "no green → no publish," this peer is **not published**.

## Layout

```
profile.toml            interop codec strategy + the authored/delegated boundary
src/lib/codec-bridge.js  delegated codec/crypto/model (require the TS peer)
src/lib/peer-kernel.js   delegated §6.5 engine (mirrors Peer.#bootstrap)
src/lib/session.js       authored per-connection §6.11 ReentrantSender + granular steps
src/nodes/ec-listener.*  authored TCP transport + §1.6 framing (a Node-RED custom node)
src/flows.json           THE peer — the visible flow-graph
src/FLOW-DESIGN.md       node-by-node narration
run-s4.sh                headless conformance host
run-editor.sh            browser editor + live peer (visualization)
status/                  PHASE-S*.md, CONFORMANCE-REPORT.json, SPEC-AMBIGUITY-LOG.md
```

## License

Apache-2.0 (`LICENSE`). DCO sign-off required on contributions.
