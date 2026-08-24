# PHASE-S3 — peer machinery — entity-core-protocol-oz

**Date:** 2026-07-15. **Verdict: COMPLETE** (smoke = the S4 connectivity gate,
which passes 22/0).

## Built (all in `src/`, one functor per module)

| Layer | Module(s) | Notes |
|---|---|---|
| Value/path | `val.oz`, `hexpath.oz` | tagged-rep helpers; §5.4 canonicalize + pattern match + peer-id checks |
| L1 identity | `entity.oz`, `envelope.oz`, `identity.oz` | materialized entity + §1.8 fidelity; §3.1 envelope; §1.5 identity-multihash peer_id; §3.5 sign/verify |
| Foundation store | `store.oz` | §1.7 content store + tree index as a **PORT AGENT** (§4.8 store-safety by construction — one owning thread, no locks); §6.10 emit counters + consumer hook |
| L3 capability | `capability.oz` | §5.2 verify_request (3-way), §5.5 chain + M3 K-of-N multi-sig, §5.6 attenuation, §5.7 caveats, §5.1 revocation, §PR-8 granter-frame |
| Wire | `wire.oz` | §1.6 framing + EXECUTE/EXECUTE_RESPONSE builders |
| Peer | `peer.oz` | §6.9/§6.9a bootstrap + seed policy; §6.5 dispatch chain; §6.6 longest-prefix resolution; all MUST handlers (connect/tree/handler/type/capability) + §7a validate handlers; §6.13(a) register five-write; §6.13(b) outbound seam |
| Types | `typestore.oz` | §9.5 53-type floor, render-from-model |
| Conn | `conn.oz` | per-connection state (single-owner cells) + injected §6.11 outbound seam |
| Transport | `transport.oz` | native `Open.socket`; **dataflow-thread-per-connection** (reader routes, worker-per-frame dispatches, per-conn writer agent, per-conn pending-var demux) |
| Host | `host.oz` | `--port/--name/--seed/--daemon/--debug-open-grants/--validate` |

## Concurrency shape (the §7b fourth data point)

- Store, per-connection pending-map, and per-connection writer are each **port
  agents** (`{NewPort}` + one consumer thread). The daemon pipe is a port agent too
  (`crypto.oz`). No locks anywhere.
- The reader thread **never blocks on dispatch**: response frames bind pending
  dataflow vars; request frames each spawn a worker thread. §6.11 reentry is a
  `{Send Writer …}` + `{Wait Var}` — the demux IS the variable (A-OZ-006).

## Findings surfaced (see SPEC-AMBIGUITY-LOG)

- **A-OZ-005** — Oz `"" == nil`: two crash-class dispatch bugs (leading-slash drop
  in §6.6 resolution; a `List.last`-on-empty-target hang) + the durable fix
  (never `== nil` as a string sentinel; dispatcher catches ALL exceptions → 500).
- **A-OZ-006** — §6.11 reentry needs no correlation pump on this substrate (the
  S1 watch-item, resolved).
- **A-OZ-007** — AGILITY-UNKNOWN-1: decode the claimed peer_id's varint key_type.

## Exit

Compiles clean under `ozc`; connectivity gate (real handshake + request_id demux)
22/0; reads as native Oz (records, dataflow threads, port agents, no locks).
