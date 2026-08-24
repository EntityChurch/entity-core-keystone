# TurboWarp/Scratch — spec ambiguity / finding log

Peer #32. Log candidate findings here; route real spec findings to `research/stewardship/
SPEC-FINDINGS-LOG.md`.

## A-NR-transport (matured here) — the conformance apparatus assumes TCP + a dedicated process

Opened in the Node-RED log as the parked question. **TurboWarp answers it:** a sandboxed visual
peer can open a WebSocket but **cannot** `listen` on TCP or be dialed by the TCP oracle — so it
**cannot be oracle-gated without a WebSocket↔TCP bridge**. This is a concrete datum that the
`validate-peer` apparatus (and every `run-s4.sh`) is coupled to **TCP + a dedicated OS process**;
transports that are equally valid at the §1.6 framing layer (WebSocket) are not directly gate-able.
Not a wire-core defect — the §1.6 framing is transport-agnostic — but a real observation about the
*tooling's* TCP assumption. Mitigation (buildable): the WS↔TCP multiplexing bridge (profile
`[conformance].bridge`). Resolution: **documented scope** — TurboWarp is visualization-first;
oracle-gating is optional via the bridge.

**Status:** matured (was parked from Node-RED); documented as a tooling-coupling observation, not
routed to arch as a wire finding.

## A-TW-throughput (expected, carry from A-NR-throughput)

The Node-RED throughput boundary (event-loop saturation under §6.11 sustained load) is expected to
**recur and worsen** on TurboWarp: the Scratch VM steps blocks on a frame loop (30/60 fps by
default; TurboWarp can uncap), adding per-operation overhead well above Node-RED's. If the oracle
gate is pursued via the bridge, expect `t2_*` (and possibly more) to FAIL for the same
substrate-throughput reason. Pre-registered here so it's a confirmation, not a surprise.

**Status:** predicted; confirm/deny at S4 only if the bridge path is built.

## (S1 exits clean — visualization-first GO; transport crux resolved with a default + optional path)
