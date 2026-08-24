# entity-core-protocol-io — Phase S3 summary (COMPLETE)

**Phase:** S3 (peer machinery)
**Date:** 2026-07-15
**Status:** ✅ COMPLETE — full core peer authored in Io; smoke via the real Go
`validate-peer` oracle (S3's higher-bar smoke): **connectivity 22/22, 0 fail**
and **origination-core 3/3** over real loopback TCP.

## What was built (all in Io — the paradigm surface)

| Layer | File | Notes |
|---|---|---|
| Value model | `Ec.io` + addon `A0_EntityCodec.io` | EcMap/EcBytes/EcBig/EcFloat/EcNull |
| Entity (§1.1/§3.4) | `Entity.io` | `{type,data,content_hash}`; fidelity recompute on `fromWire` |
| Envelope (§3.1) | `Envelope.io` | root + included; per-entity hash-vs-key verify |
| Identity (§1.5/§3.5/§7.3) | `Identity.io` | Ed25519 seed → identity-multihash peer_id; `--name` keypair load |
| Wire (§1.6/§3.2/§3.3) | `Wire.io` | framing + EXECUTE/EXECUTE_RESPONSE + Outcome seam |
| Store (§1.7/§6.10) | `Store.io` | content+tree, emit hooks, **§6.6 as a DispatchNode proto network** |
| Capability (§5) | `Capability.io` | verify_request, chain walk, attenuation, caveats, revocation, §3.6 K-of-N |
| Core types (§9.5) | `CoreTypes.io` | 53-type floor, render-from-model, 0 drift |
| Handlers (§6.2) | `Handlers.io` | Handler prototype + differential-inheritance clones |
| Peer (§6.5/§6.9/§6.9a) | `Peer.io` | dispatch chain, bootstrap, seed policy |
| Transport (§1.6/§4.8/§6.11) | `Transport.io` | single-coroutine non-blocking poll loop |

## The paradigm payoff — §6.6 as differential inheritance (the probe)

`Store.io` renders §6.6 handler resolution AS Io's own delegation mechanism: the
dispatch surface is a **network of `DispatchNode` prototypes mirroring the path
tree** — the node for `/a/b/c` is a `clone` of the node for `/a/b` (differential
inheritance). Binding a `system/handler` entity DEFINES `handlerPattern` on that
path's node; every descendant inherits it up the proto chain unless a deeper
handler shadows it. §6.6 longest-prefix resolution is therefore NOT a hand-written
backward loop — it is the peer asking `deepestNode(path) handlerPattern`, and Io's
delegation lookup returns the nearest (= deepest-prefix) definition, exactly as
the longest prefix wins in §6.6. Unbinding `removeSlot`s the definition and the
ancestor's shows through again. The protocol's dispatch IS the language's dispatch.

The handlers themselves (`Handlers.io`) are the paradigm rendering too: `Handler`
is the base prototype carrying the unknown-operation→501 default; each concrete
handler is a `clone` overriding only its `op_<name>` methods (it stores only its
diffs), and op dispatch is a guarded message send (`perform`, gated by the
declared-op set — A-IO-004/007).

## Transport (the substrate lesson — A-IO-020)

Io's Socket addon offers a coroutine+libevent model, but coroutine-per-connection
**deep-recurses `EventManager yield → handleEvent`** under the oracle's concurrent
connections → wedge. The correct model (the Pd/Scratch lesson) is a **single
coroutine non-blocking poll loop** over `asyncAccept`/`asyncStreamRead`/
`asyncStreamWrite`: one loop services every connection cooperatively; store-safety
is structural; §6.11 reentry is a bounded synchronous send+wait on the same fd
(non-response frames hand back to the assembler); the S1 half-close quirk is
honoured (a closed socket is dropped before any pending write).

## Smoke (the S3 gate — real oracle)

- `connectivity` **22/22 PASS** (handshake both legs, nonce/sig/identity-binding
  hardening, request_id echo, 404).
- `origination-core` **3/3 PASS** (`./run-origination-core.sh` — reference_connect
  + reference_ready + dispatch_outbound_reentry, the §6.11 reentry).
- `test/smoke-peer.io` — a two-Io-peer loopback (dialer `Session` + poll server).

## Findings (see SPEC-AMBIGUITY-LOG)

A-IO-002 (coroutine mid-frame write interleaving → per-connection FIFO — moot on
the poll loop), A-IO-013 (Io `try(...)` returns nil/exception NOT the value — a
recurring trap that surfaced real bugs: dropped dispatch result, discarded
peerid-parse), A-IO-020 (coroutine yield-recursion wedge → poll loop),
A-IO-021/022 (retain-stack + store-growth GC pressure under sustained load).

## Exit criteria — MET

Smoke green (connectivity 22/22 + origination 3/3); peer reads as idiomatic Io
(prototypes, message sends, differential inheritance); the §6.6 probe answered. → S4.
