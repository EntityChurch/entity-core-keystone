# FLOW-DESIGN — the entity-core peer as a Node-RED flow-graph

The human-readable companion to `flows.json` (a JSON graph is machine-oriented and near-unreadable
in review — this file is the node-by-node narration the `.json` can't be). It is the authored
protocol logic; the codec/crypto is delegated to the TS peer via `lib/codec-bridge.js`.

**Legend:** `[node]` = a Node-RED node; `──▶` = a wire (carries one `msg` per envelope, shape
`{ payload, conn, envelope, requestId, ... }`); `⟿` = a call into the delegated codec-bridge.

## Ingress / egress (transport — §1.6, AUTHORED)

```
[tcp-in :PORT loopback] ──▶ [frame-decode] ──▶ (per complete frame) ──▶ dispatch pipeline
                                    │ buffers partial reads; splits on the 4-byte BE length
                                    │ prefix; enforces the 16 MiB frame cap (§1.6 SHOULD)
dispatch pipeline ──▶ [frame-encode] ──▶ [tcp-out] (prepends the 4-byte BE length prefix)
```

`frame-decode` / `frame-encode` are the "one transport-coupled corner" (mirrors the TS
`frame-codec.ts`) — deliberately isolated as single nodes so TurboWarp can swap TCP for a
WebSocket by replacing exactly these two nodes (evidence for the A-NR-transport separability
question).

## The §6.5 dispatch chain (AUTHORED — this is what makes it a peer)

**Realized in `flows.json` (2026-07-13):** each stage below is a visible `function` node —
`n-dp-begin` (decode+target §1.4) → `n-dp-connect` (§4.2 connect-preauth, 3-way) → `n-dp-author`
(401) → `n-dp-cap` (403) → `n-dp-verify` (§5.2) → `n-dp-resolve` (§6.6, 404) → `n-dp-permission`
(§5.2/§6.8, 403) → `n-dp-handler` (§6.13). Each node's second output is the error wire → the
shared `n-dp-error` sink. The stages call the granular `session.dp*` steps, which delegate ONLY the
leaf crypto/verdict (`kernel.prim`: Ed25519 verify, `ChainVerifier`, `Permissions`); the §6.5/§5.2
*sequence* is the graph + `session.js` (ported from `dispatch/dispatcher.ts#dispatchCore`).

Each stage is a node; each branch is a `switch`; the error wire (dashed) runs straight to encode.

```
[ecf-decode] ⟿ decodeEnvelope        ── throw ┄┄▶ [err 400 invalid_request] ┄┄┐
     │                                                                        │
     ▼                                                                        │
[construct-Execute]                  ── throw ┄┄▶ [err 400 invalid_request] ┄┄┤
     │                                                                        │
     ▼                                                                        │
[switch: target == local peer?] ── no ┄┄▶ [err 400 invalid_request] ┄┄┄┄┄┄┄┄┄┤
     │ yes                                                                     │
     ▼                                                                        │
[switch: connect-preauth & !established?] ── yes ──▶ [connect-handler] ──▶ resp
     │ no                                                                      │
     ▼                                                                        │
[switch: author present?] ── no ┄┄▶ [err 401 missing_author] ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤
     │ yes                                                                     │
     ▼                                                                        │
[switch: capability present?] ── no ┄┄▶ [err 403 missing_authorization] ┄┄┄┄┄┄┤
     │ yes                                                                     │
     ▼                                                                        │
[ingest-signatures] ──▶ [verify-request] ⟿ capability.ChainVerifier + identity.verify
     │                        │                                                │
     │                        └── deny ┄┄▶ [err 401/403/400 per verdict] ┄┄┄┄┄┤
     ▼                                                                        │
[switch: resolve handler by tree walk (§6.6)] ── no match ┄┄▶ [err 404] ┄┄┄┄┄┤
     │  match → routes BY PATH to a handler node (wires = §6.6 routing)        │
     ▼                                                                        │
[check-permission] ⟿ capability.Permissions ── deny ┄┄▶ [err 403 capability_denied] ┄┤
     │ allow                                                                   │
     ▼                                                                        │
[handler node for the resolved path] ──────────────────────────▶ [build-response] ◀┘ (err path)
     (connect · capability · handlers · validate/echo · validate/dispatch-outbound)
                                                                       │
                                                             [ecf-encode] ⟿ encodeEnvelope
```

**Handler resolution as a switch node is the headline mapping:** entity-core §6.6 "route by
handler path" is *literally* a Node-RED switch routing a msg to an output wire by
`msg.envelope.uri`. The wires ARE the dispatch table.

## Handshake state machine (§4.1, AUTHORED)

The 3-EXECUTE / 3-EXECUTE_RESPONSE handshake (hello → authenticate, reverse authenticate) is
authored as the connect-handler node plus a **per-connection state store** (a `flow`-context map
keyed by the tcp connection id): `helloReceived`, `sentNonce`, `remotePeerId`, `established`,
plus the §4.1 leg-3 ordering latch (hold the reverse-authenticate until the leg-2 response is
written). The reverse-authenticate origination reuses the §6.11 outbound path below.

## §6.11 handler-outbound reentry (AUTHORED — the async-peer tax)

On an actor/CSP substrate this demux is ~free; on Node-RED (message-passing but single event
loop) it is a **correlation-map** function node: outbound EXECUTEs mint a requestId, park a
resolver in a map, and the ingress reader routes inbound EXECUTE_RESPONSE roots back to the parked
resolver (vs. EXECUTE roots → the dispatch pipeline). Same tax the TS peer's `reentrant-sender.ts`
pays. Drives `system/validate/dispatch-outbound` (the origination-core probe).

## Delegated surface (codec-bridge.js) — NOT authored, by design

`decodeEnvelope` / `encodeEnvelope` (canonical CBOR), `identity.sign/verify` (Ed25519 + SHA-256),
`capability.ChainVerifier` / `Permissions` (Layer-1 deterministic verdict math), the `Ecf` value
constructors + `Entity`/`Envelope`/`Execute`/`ExecuteResponse` types. Byte-exact via the TS peer
(71/71 wire @ 9695b1f1). Handler nodes *use* these to build LOGIC; they never touch bytes.

## Wrapper guard (ADR-0012 scope)

If this graph ever collapses to `[tcp-in] ▶ [function: tsPeer.dispatch(bytes)] ▶ [tcp-out]`, it is
a wrapper, not a visual peer — the switch-by-path node + the per-handler nodes + the authored
verify/permission/handshake stages are the minimum bar for "the flow-graph IS the peer."

**Guard satisfied (2026-07-13):** the earlier single-`n-dispatch`-node collapse (which called one
delegated `Dispatcher.dispatch()`) is retired — §6.5 is now the decomposed `n-dp-*` chain above,
delegating only leaf crypto. Re-verified 249·2F (no drift). Don't re-collapse it.
