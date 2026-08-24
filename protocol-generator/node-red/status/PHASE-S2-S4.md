# Phases S2–S4 — Node-RED peer build + conformance

**Peer #31 · Node-RED (visual flow-graph) · Tier 5 · 2026-07-12**

Follows PHASE-S1 (feasibility GO). This records the build (S2 codec-interop + transport,
S3 peer/dispatch, S4 conformance) and the **honest conformance result** (ADR-0012).

## What was built (the authored-vs-delegated boundary, realized)

**DELEGATED** (the mechanical/crypto "libraries" the operator chose to skip):
- `lib/codec-bridge.js` — `require()`s the compiled TS peer (`typescript/dist/src/**`): canonical
  CBOR (`Envelope.decode`/`.encode`), Ed25519, SHA-256, base58, the ECF value model. Interop
  seam, loaded once into Node-RED `functionGlobalContext` as `global.get('ec')`.
- `lib/peer-kernel.js` — the peer bootstrap (identity, tree/store, the 4 bootstrap handlers,
  `seedCoreTypes`, the §6.9a seed-authority bootstrap, the §7a conformance handlers) mirroring
  `Peer.#bootstrap`, plus the **`prim` bundle**: the DELEGATED leaf primitives the authored §6.5
  chain calls (Ed25519 verify, the `ChainVerifier` capability-chain verdict, the `Permissions`
  verdict, the model/path helpers). One shared kernel per peer. *(The TS `Dispatcher` is still
  constructed but the flow no longer calls `dispatch()` — the §6.5 sequence is authored below.)*

**AUTHORED** (the protocol logic, as the flow-graph + the per-connection session):
- `nodes/ec-listener.js` — the TCP server + §1.6 4-byte-BE framing + per-connection lifecycle.
  The single transport-coupled node (the TurboWarp WebSocket swap point).
- `lib/session.js` — the per-connection §6.11 `ReentrantSender` + the **granular §6.5 dispatch
  steps** the visible nodes call (`dpBegin` decode/target → `dpConnectPreauth` → `dpAuthorPresent`
  → `dpCapPresent` → `dpVerify` → `dpResolve` → `dpPermission` → `dpRunHandler`/`dpRunConnect`,
  with `dpBuildError` as the short-circuit sink), each advancing a per-dispatch scratch context
  keyed by `msg.did`. `#dispatchCore`/`#verifyRequest`/`#ingestSignatures`/`#runHandler` are
  faithfully ported here (delegating only the leaf crypto to `prim`). Also `classifyBytes` /
  `routeResponseBytes` + the reentry correlation map (the authored async-peer tax).
- `flows.json` — the visible graph (16 nodes): `ec-listener → classify (§6.11 demux switch) →
  {§6.5 dispatch chain | reentry | drop} → transport`, where the **§6.5 chain is DECOMPOSED into
  one visible node per stage** (begin → connect-preauth → author → capability → verify → resolve
  → permission → handler), each stage's error wire running to a shared build-error node. The wires
  ARE the §6.5 sequence. **Every wire carries CBOR frame BYTES** — exactly what the TCP wire
  carries (a faithful consequence of Node-RED cloning `msg`, which flattens class instances, so
  envelopes are reconstructed inside each node, never carried across a wire).

**Key implementation lessons** (durable, carry to TurboWarp):
1. **Node-RED deep-clones `msg` between nodes** → you cannot pass class instances (an `Envelope`'s
   private `#included` is lost) or functions (`_reply`) across wires. Carry only clone-safe
   primitives (Buffers, strings); look sessions up from a module-level registry by `conn` id.
2. **Conformance-host parity:** the kernel needs `--debug-open-grants` (default→* seed policy),
   mirroring the TS host — else capability checks 403 before handlers run (the earlier
   `unsupported_op_returns_501` / concurrent-reentry FAILs, and many core skips, were all this).
3. `session.dispose()` must unwind the delegated `respond()` driver (reject the handshake
   Deferreds) so half-open probe connections don't leak drivers + timers across a long run.

## S4 conformance — HONEST result (ADR-0012)

**`validate-peer --profile core` @ `cc1970f` (oracle `output/s4-oracles/validate-peer`):
249 P / 293 W / 2 F / 101 S** (`status/CONFORMANCE-REPORT.json`). **NOT a clean gate — 2 FAIL.**
Per "no green report → no publish", this peer is **not publishable**; reported as-is.

**All correctness categories are green:** connectivity **22/22**, encoding, type_system **108 P**,
multisig **11** (genuine 2-of-3 accept-path), security **28**, capability **12**, format_agility
**10**, crypto_agility **4**, negotiation **4**, peer_canonicalization **5**, and the §6.11
concurrency *correctness* tests — `t1_2_concurrent_reentry` **PASS**, `t1_3_no_head_of_line`
**PASS**, `t1_1_concurrent_demux` WARN (informational: single-threaded event loop shows no
parallel speedup — not a violation).

**The 2 FAILs are both §6.11 sustained-load/churn ROBUSTNESS** (`t2_1_sustained_load`: ~30% of
10 000 pipelined requests dropped on i/o timeout; `t2_2_connection_churn`: "peer stopped
accepting" at cycle 0, cascading from t2_1). **They are a documented Node-RED-substrate throughput
boundary, NOT a correctness defect** — see **A-NR-throughput** in SPEC-AMBIGUITY-LOG. Evidence it
is not a defect:
- **Standalone they PASS:** `run-s4.sh -category concurrency` → **4 P / 1 W / 0 F** (t2_1 PASS in
  ~52 s, t2_2 PASS); `-category security -category concurrency` → also **0 F**.
- They fail **only** under the full ~640-test marathon: cumulative event-loop pressure + the
  Node-RED per-request overhead (msg clone/scheduling per hop) on top of pure-JS Ed25519/CBOR
  push sustained-load latency past the oracle's per-request drop threshold, and the drained
  backlog starves the `accept` callback (the "stopped accepting" cascade). A lean peer (TS #2)
  avoids this by draining fast enough; the visual-runtime host has a real throughput cost.

The 7 skips that "count as FAIL" are the standard **reference-peer-gated** categories
(origination, authz, peer_canonicalization — single-peer runs honest-SKIP these; run via
`run-origination-core.sh` + allow-list, cohort convention) plus `security.handler_scope_denied`
— not gaps unique to this peer.

## Honest framing (ADR-0012)

A green result here would be **cohort-consistent corroboration on a shared JS substrate**, not
independent convergence — the codec/engine ARE the TS peer's. The peer's real value is
**demonstrated**: the protocol runs, authored as a visible/editable flow-graph, and the build
surfaced two durable findings — the Node-RED msg-clone constraint (→ bytes-on-every-wire) and the
**substrate throughput boundary** (A-NR-throughput), a genuine paradigm characteristic the
textual cohort could never surface.

## Update 2026-07-13 — §6.5 dispatch chain decomposed (the wrapper guard, satisfied)

The S2/S3 build had collapsed §6.5 into a single `n-dispatch` node calling one delegated
`session.dispatchBytes` → `Dispatcher.dispatch()` — the profile's `[authored] dispatch = "flow"`
claim (and FLOW-DESIGN's §6.5 chain) was the *design*, not yet the *implementation* (a §6.5
wrapper by FLOW-DESIGN's own wrapper-guard test). Now realized: the single node is replaced by the
**decomposed visible chain** (flows.json 7 → 16 nodes), each stage a node calling a granular
`session.dp*` step that delegates only the leaf crypto/verdict to `peer-kernel`'s new `prim`
bundle. The §6.5/§5.2 *sequence* (single-401 carve-out, chain-depth-before-authz, 401/403/404
ordering) is now authored, ported faithfully from `dispatch/dispatcher.ts`.
**Re-verified byte-identical: `validate-peer --profile core` @ `cc1970f` → 249 P / 293 W / 2 F /
101 S**, the 2 F still exactly `concurrency.{t2_1_sustained_load,t2_2_connection_churn}`
(A-NR-throughput, unchanged). No conformance drift; the change is purely make-it-visible.

## Status

- **S2/S3: complete** — peer runs headless in `containers/node24`; codec + leaf crypto/verdict
  delegated, transport/demux/**§6.5 dispatch chain (decomposed, visible)**/reentry authored.
- **S4: exercised, NOT gate-green** — 249·**2F** @ cc1970f; the 2F are the A-NR-throughput
  boundary (pass standalone). Correctness-complete.
- **S5: docs written** (README, LICENSE Apache-2.0, CHANGELOG `0.1.0-pre`) + `run-editor.sh` for
  the browser visualization; matrix row added (marked ‡, non-gate-green). **Registry publish
  blocked by the gate** (2F, no green → no publish) — accepted as the documented A-NR-throughput
  boundary per operator (2026-07-12): mostly-for-visualization, correctness at lower levels holds,
  peak throughput non-critical, may revisit. Proceeding to TurboWarp next.
