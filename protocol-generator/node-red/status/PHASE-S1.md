# Phase S1 — Node-RED feasibility spike + profile

**Peer #31 · Node-RED (visual flow-graph / dataflow) · Tier 5 · started 2026-07-12**

This is the FIRST of the visual-paradigm probe cohort (Node-RED → TurboWarp → Scratch).
Per the next-session handoff (`docs/status/HANDOFF-2026-07-12-visual-peers-next.md`), S1 is a
**heavier-than-usual feasibility spike**, not just profile authoring: answer the three real
unknowns and return an **honest go/no-go** before committing S2→S5.

## Honest framing (ADR-0012) — state up front

- **NOT wire-axis discovery.** Node-RED runs on the Node.js runtime, already saturated by the
  native **TypeScript** peer (#2, `@noble` codec). Same codec/crypto/numeric/string model → the
  productive wire-touching axes (crypto-availability, integer-model, float-model, string-model)
  are **saturated**. A passing peer is **cohort-consistent corroboration on a shared JS
  substrate**, not independent convergence — and even the corroboration is weak.
- **The value is a NEW axis: paradigm + authoring model.** The peer is authored as a
  *flow-graph* (nodes + wires), not textual source. The finding-bet is **generator-robustness
  at the extreme** (does S1→S5 / profile / templates survive a non-textual substrate?) plus a
  possible **transport-abstraction finding** (unknown #2).

## GO / NO-GO: **GO** (proceed S2→S5)

All three unknowns resolve favorably. Node-RED is the low-risk member of the visual cohort —
server-side Node, full sockets, oracle-reachable — exactly why the handoff sequenced it first.

---

## Unknown #1 — What is authored visually vs delegated to JS?

**Resolved: `codec_strategy = "interop"`.** Node-RED is a Node.js application, so this is the
textbook interop case (cf. "Clojure on JVM interops with the Java codec"). The boundary — *the
whole design* — is:

| Layer | Where | Why |
|---|---|---|
| Canonical CBOR (f16 shortest-float ladder, length-lex map sort, recursive mt6 tag-reject), Ed25519 sign/verify, SHA-256, base58, LEB128, the ECF value model + Entity/Envelope/Execute types | **DELEGATED** — `require()` the compiled TS peer (`protocol-generator/typescript/dist/src/**`) | Re-typing the TS codec into a function-node textarea is zero independent signal; the operator's explicit intent is to skip the crypto/hash/float-CBOR *libraries* and capture the LOGIC. The codec is proven byte-exact (71/71 wire-conformance @ `9695b1f1`). |
| TCP framing (4-byte BE len prefix, §1.6), the §4.1 handshake state machine, **§6.5 dispatch as a node pipeline**, **§6.6 handler resolution as a SWITCH node routing by handler-path**, §5.2 check_permission, §4.4 grant flow, §6.11 handler-outbound reentry, the 401/403/404 status logic | **AUTHORED** — the flow-graph (nodes + wires) | This is what makes it a **peer**, not a wrapper. Wires ARE the §6.6 routing. |

**The elegant mapping** (verified against `dispatch/dispatcher.ts` `#dispatchCore`): the §6.5
chain is a *linear pipeline with branch points*, which is precisely a Node-RED flow —

```
tcp-in → frame-decode → cbor-decode(delegated) → construct-Execute
  → [switch: connect-preauth & !established?] ── yes → connect-handler ─┐
  → author present?  ── no → 401 ──────────────────────────────────────┤
  → capability present? ── no → 403 ───────────────────────────────────┤
  → verify-request (sig + cap chain; crypto delegated to TS ChainVerifier)
  → [switch: resolve handler] ── no match → 404 ───────────────────────┤
  → check-permission ── deny → 403 ────────────────────────────────────┤
  → run-handler (a node/subflow per path) ─────────────────────────────┤
                                                                        ↓
                       cbor-encode(delegated) → frame-encode → tcp-out
```

**Wrapper guard:** if S2/S3 drifts into a single `function` node that calls
`tsPeer.dispatch(envelope)` end-to-end, we have a wrapper, not a visual peer — STOP and
re-decompose the dispatch chain into nodes. The switch-by-path node + per-handler nodes are the
minimum bar for "the flow-graph IS the peer."

## Unknown #2 — Transport, and can the oracle reach it?

**Resolved: REACHABLE.** Node-RED is server-side Node with full TCP. A `tcp in` core node (or a
small custom node wrapping `net.createServer`) LISTENs on `127.0.0.1:<port>`; the Go
`validate-peer` oracle (TCP) connects exactly as it does to every other peer. `run-s4.sh` will
launch Node-RED headless, wait for a `LISTENING` line, and point the oracle at the loopback port
— structurally identical to the TS `run-s4.sh`.

**Potential finding (parked for TurboWarp, unknown surfaced here):** the *reason* Node-RED is
easy and TurboWarp will be hard is that the whole cohort assumes **TCP loopback + a dedicated OS
process**. Node-RED satisfies both; TurboWarp (sandboxed VM, WebSocket-only, no raw TCP) breaks
the *transport substrate* assumption. That asymmetry is the transport-abstraction question:
**is the peer/transport layer cleanly separable from TCP?** Node-RED's framing (`frame-codec.ts`)
is already the "one Node-coupled corner"; the flow makes that seam a literal, movable node — good
evidence the layer *is* separable. Full answer lands at TurboWarp S1 (a WebSocket↔TCP bridge or a
documented codec+smoke-only scope boundary). Logged in SPEC-AMBIGUITY-LOG as **A-NR-transport**.

## Unknown #3 — Does S1→S5 / profile / templates apply?

**Partially — and the misfit IS the finding.** The lifecycle assumes text files, a compiler, a
package manager. For Node-RED:

- **Source of truth is a graph, not text modules.** `authoring_surface = "flow-json"`; the build
  artifact is `flows.json` (+ a `package.json` for the codec-bridge custom node). `templates/`,
  `layout`, `build`, `packaging` all needed reinterpretation — captured in the profile's new
  `[authored]` / `[build]` / `[packaging]` sections (documented in prose, not formalized, per
  `AGENTS.md`).
- **`src/` holds a graph + a thin bridge**, not idiomatic language modules. Reviewability of a
  JSON flow-graph is poor (it's machine-oriented); mitigation is an authored **FLOW-DESIGN.md**
  narrating node-by-node what the graph does — the human-readable companion the `.json` can't be.
- **Generator-model stretch (the generator-robustness finding, to be logged in the S-report):**
  the profile schema absorbed the visual substrate with three new sections rather than breaking —
  so the /entity-rosetta *profile* model is robust to a non-textual target. What does NOT map is
  the *templates → generated textual source* step (S2/S3 assume rendering source files); here S2
  produces a graph + a bridge. That's the concrete "where the generator model doesn't fit" datum.

---

## Decisions made

- Codec strategy **interop** (delegate byte-exact codec/crypto to TS peer #2; author protocol
  logic as the graph). Container **reuse node24** (no new Containerfile).
- Tier **5** (experimental niche, not a mainstream adoption peer). Publish **deferred** (cohort).
- Sequence confirmed: **Node-RED now (GO)**, TurboWarp next (transport gate at its S1), Scratch
  last (the operator's ultimate target).

## S1 exit

- [x] `profile.toml` complete (no TBD; new `[authored]`/`[build]`/`[container]`/`[conformance]`
      sections for the visual substrate)
- [x] `arch/PROFILE-RATIONALE.md` written
- [x] `status/SPEC-AMBIGUITY-LOG.md` initialized (A-NR-transport parked)
- [x] Container specified (reuse node24)
- [x] Three unknowns answered; **GO** recorded
- [ ] S2: author `flows.json` + the codec-bridge custom node + FLOW-DESIGN.md; stand it up
      headless; complete a handshake + one dispatch on loopback (the spike's runnable proof)
