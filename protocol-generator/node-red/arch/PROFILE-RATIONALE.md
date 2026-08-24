# Node-RED profile rationale

Peer #31, the first visual/dataflow-paradigm probe. One paragraph per major choice — the audit
trail for "why this way?".

## Why a Node-RED peer at all (the axis under test)

Not for wire discovery — Node-RED is Node.js, and the native TypeScript peer (#2) already
saturates every JS wire-touching axis (crypto, integer, float, string models). The bet is a
**new axis the cohort has never touched: paradigm + authoring model.** The peer is authored as a
*flow-graph* (nodes + wires), and the entity-core §6.6 dispatch (route by handler path) maps
astonishingly cleanly onto Node-RED's core semantic (route messages over wires). The value is
**generator-robustness**: does /entity-rosetta's profile+templates+S1→S5 model — which assumes
*textual* source — survive a non-textual substrate? (ADR-0012: a green peer here is
cohort-consistent corroboration on a shared JS substrate, not independent convergence — say so.)

## Why `codec_strategy = "interop"` (delegate the codec/crypto to the TS peer)

Node-RED runs on the same Node.js runtime as peer #2, so the compiled TS codec is `require()`-able
directly — the textbook interop strategy (the S1 phase prompt's "Clojure on JVM ↔ Java codec"
case). Re-implementing canonical ECF (the f16 shortest-float ladder, recursive major-type-6
tag-reject, length-then-lex map-key sort) and Ed25519 inside Node-RED `function` nodes would be
literally re-typing the TS peer's proven code into a textarea — **zero independent signal**, and
directly counter to the operator's stated intent (skip the crypto/hash/float-CBOR *libraries*;
capture the *logic*). The delegated codec is proven byte-exact: 71/71 wire-conformance @
`9695b1f1`. So the codec is a solved, trusted dependency and 100% of the *authoring* effort goes
where the signal is: the protocol logic as a graph.

## Why that still makes it a PEER, not a wrapper

The line between "visual-language peer" and "a Node-RED integration that wraps the TS peer" (the
scope flag in the handoff) is drawn at the dispatch chain. The §6.5 pipeline — connect-preauth
branch, author/capability presence (401/403), verify-request, **handler resolution as a switch
node**, check_permission, run-handler, the error-envelope routing — is authored as **nodes and
wires**, not as one `tsPeer.dispatch()` call. The delegated surface is exactly the byte-mechanical
codec/crypto; everything that decides *how the protocol behaves* lives in the graph. If a build
step collapses the chain into a single delegating node, that is the wrapper signal and we
re-decompose (guard recorded in PHASE-S1).

## Why `runtime = node24` / reuse the container

Node-RED is an npm package on Node.js; the existing `containers/node24` image (the TS peer's
toolchain, Node 24.15.0 LTS, SHA-pinned) hosts it with no new Containerfile — Node-RED and its
custom-node deps install via npm into that image. S11 cool-down applies to anything pulled from
the npm registry (node-red core + `node-red-node-test-helper`); pin exactly in the lockfile at S2.

## Why Tier 5 / publish deferred

Experimental paradigm probe, not a mainstream adoption target — Tier 5 (functional/niche) per
`research/LANDSCAPE.md`. Registry-publish is deferred like the rest of the recent cohort; S5 still
produces README/LICENSE/CHANGELOG/CI so it lifts out cleanly if a community wants it.

## Why the error model is "status-envelope", not exceptions

A dataflow graph has no call stack to throw across — a msg either continues down a wire or is
routed to a different wire. Protocol errors (401/403/404/400/500) are already
`EXECUTE_RESPONSE` **error envelopes** in entity-core, so the idiomatic mapping is a dedicated
"error" output wire that carries the error envelope straight to the encode→tcp-out path. This is
arguably a *cleaner* expression of §6.5's "faults become an error response, never hang the peer"
than the TS peer's try/catch — a small point in favor of the paradigm, to note at S4.
