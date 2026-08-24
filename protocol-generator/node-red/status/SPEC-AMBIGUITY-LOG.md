# Node-RED — spec ambiguity / finding log

Peer #31. Entries are candidate spec findings surfaced while building this peer. Cohort policy:
log here, route real spec findings to `research/stewardship/SPEC-FINDINGS-LOG.md` (Fnn), never
paper over locally.

## A-NR-transport — TCP-loopback + dedicated-process assumption (PARKED, matures at TurboWarp S1)

**Severity:** low (generator/ecosystem observation, not a wire-core defect).

The entire conformance apparatus assumes a peer is reachable at `tcp://127.0.0.1:<port>` as a
dedicated OS process (`validate-peer` speaks TCP; every `run-s4.sh` LISTENs on loopback).
Node-RED satisfies this trivially (server-side Node, full sockets) — so it does not surface the
finding, it only *sets up* the contrast. The real question ("is the peer/transport layer cleanly
abstracted from TCP, or does the spec/cohort bake in TCP?") is answered by **TurboWarp**, whose
sandboxed VM has **no raw TCP** — WebSocket / message-ports only. Resolution options for
TurboWarp (decided at its S1): (a) a WebSocket↔TCP bridge in front of the sandbox; (b) a
socket-granting desktop/headless embedding; (c) accept codec+smoke+visualization-only scope
(honest documented boundary, not a failure). If the transport layer proves cleanly separable
(Node-RED's `frame-codec` is already the "one Node-coupled corner"), that is a mild positive
finding about §1.6 transport-independence; if the cohort/spec turns out to assume TCP in a way
that blocks a WebSocket peer from ever being gate-scored, that is a routable finding.

**Status:** open, owned by the TurboWarp peer's S1. Do not close from Node-RED.

## A-NR-throughput — Node-RED-substrate §6.11 sustained-load/churn boundary (S4 finding)

**Severity:** medium (a genuine paradigm/substrate characteristic; not a wire-core defect, not a
peer correctness bug).

`validate-peer --profile core` FAILs exactly two checks — `concurrency.t2_1_sustained_load` (~30%
of 10 000 pipelined requests dropped on i/o timeout) and `concurrency.t2_2_connection_churn`
("peer stopped accepting" at cycle 0). **Both PASS standalone** (`-category concurrency` → 4P/1W/0F;
`-category security -category concurrency` → 0F) and fail **only** under the full ~640-test
marathon. Root cause: a peer hosted inside the Node-RED runtime pays per-request overhead
(msg deep-clone + per-hop scheduling) on top of pure-JS Ed25519/CBOR, so under cumulative
sustained load the single event loop can't drain fast enough — request latency crosses the
oracle's drop threshold and the drained backlog starves the `accept` callback. A lean peer
(TS #2) avoids it; the visual-runtime host does not. This is the **throughput cost of the visual
paradigm as a peer host** — a finding the textual cohort cannot surface.

Not routed to arch as a spec finding (it is a host/runtime property, not a spec ambiguity). Two
honest resolutions, operator's call: (a) **accept + document** as the paradigm's boundary (this
peer is a visualization/generator-robustness probe, conformance is cohort-consistent-only per
ADR-0012); (b) **optimize** — bound in-flight dispatches / backpressure the socket while a
dispatch is in flight (risking the §6.11 no-head-of-line MUST that `t1_3` currently passes) or
collapse the hot path (tested: barely helps — overhead is crypto + event-loop, not hop count).
Carry to TurboWarp: its sandbox is even more constrained, so expect the boundary there too.

**Status:** open — documented S4 boundary; S5 publish blocked by the gate pending resolution.

## (S1 exited clean; A-NR-throughput is the sole S4 blocker — a documented substrate boundary)
