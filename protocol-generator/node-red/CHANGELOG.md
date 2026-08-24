# Changelog — entity-core-protocol-node-red

All notable changes to this peer. Format loosely follows Keep a Changelog; versions track the
peer's maturity, not the spec version (spec surface is entity-core v0.8.0 / V8).

## [Unreleased]

### Changed
- **§6.5 dispatch chain decomposed into visible nodes** (`flows.json` 7 → 16 nodes). The single
  `n-dispatch` node (one delegated `Dispatcher.dispatch()` call) is replaced by the visible chain
  `n-dp-begin` (decode+target §1.4) → `n-dp-connect` (§4.2) → `n-dp-author` (401) → `n-dp-cap`
  (403) → `n-dp-verify` (§5.2) → `n-dp-resolve` (§6.6, 404) → `n-dp-permission` (§5.2/§6.8, 403)
  → `n-dp-handler`, every stage's error wire converging on a shared `n-dp-error` sink. Now the
  profile's `[authored] dispatch = "flow"` claim (and FLOW-DESIGN's §6.5 chain) is the actual
  implementation, not just the design — the wrapper guard is satisfied.
- **`lib/session.js`** now authors the §6.5/§5.2 sequence as granular `dp*` steps (faithful port
  of `dispatcher.ts#dispatchCore`/`#verifyRequest`/`#ingestSignatures`/`#runHandler`), delegating
  only the leaf crypto/verdict to the new **`peer-kernel` `prim`** bundle (Ed25519 verify,
  `ChainVerifier`, `Permissions`). Per-dispatch scratch is keyed by `msg.did`.
- Re-verified byte-identical: `validate-peer --profile core` @ `cc1970f` → **249 P / 293 W / 2 F /
  101 S**, the 2 F still exactly the A-NR-throughput pair. No conformance drift.

## [0.1.0-pre] — 2026-07-12

First cut of the Node-RED visual/dataflow-paradigm peer (#31). **Experimental probe** — runs and
is correctness-complete, but not gate-green (see the throughput boundary below); not published.

### Added
- **Peer authored as a Node-RED flow-graph.** `flows.json` wires the protocol: `ec-listener`
  (authored TCP transport + §1.6 framing, a custom node) → classify (§6.11 demux switch) →
  {§6.5 dispatch | §6.11 reentry | drop} → transport. Wires carry CBOR frame bytes.
- **`interop` codec strategy** — `lib/codec-bridge.js` + `lib/peer-kernel.js` delegate the
  canonical CBOR, Ed25519, SHA-256, the ECF model, and the §6.5 dispatch engine to the compiled
  TypeScript peer (same Node.js runtime). No re-implementation.
- **`lib/session.js`** — per-connection §6.11 ReentrantSender + the granular byte-oriented steps
  the visible nodes call (classify / dispatch / routeResponse); the reentry correlation map.
- **`run-s4.sh`** (headless conformance host) and **`run-editor.sh`** (browser editor + live peer
  for visualization). Reuses `containers/node24`.
- Conformance: `validate-peer --profile core` @ `cc1970f` — **249 P / 293 W / 2 F / 101 S**. All
  correctness categories green (connectivity 22/22, type_system 108 P, multisig 11 with a real
  2-of-3 accept-path, security 28, capability 12, agility/negotiation, §6.11 concurrency
  correctness).

### Known limitations
- **A-NR-throughput** (documented, `status/SPEC-AMBIGUITY-LOG.md`): the 2 FAILs are §6.11
  sustained-load/churn robustness (`t2_1`/`t2_2`). They **pass standalone** and fail only under the
  full ~640-test marathon — a Node-RED-substrate throughput boundary (event-loop saturation +
  visual-runtime per-request overhead on pure-JS crypto), not a correctness defect. Not memory-bound
  (tested to 8g). Optimization deferred; may be revisited.
- Ed448 / SHA-384 agility deferred (would ride the same TS `@noble` seam).
- Registry publish deferred (cohort convention).
