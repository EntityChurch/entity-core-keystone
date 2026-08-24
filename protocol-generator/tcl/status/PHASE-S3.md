# entity-core-protocol-tcl — Phase S3 summary (COMPLETE)

**Phase:** S3 (peer machinery)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/tcl-toolchain:latest` (Tcl **9.0.2**)
**Status:** ✅ **COMPLETE — two-peer loopback smoke 12/12 (0 fail).**
Reproduce: `./run-s3.sh` (→ `make s3`: foundation self-test 26/26 + smoke 12/12).
Container-bound, sealed-offline (`--network=none`; loopback is intra-container
127.0.0.1). S2 codec gate unaffected: still **69/69**.

## What S3 built (Core Layers 1–4 + foundation, on the S2 codec)

The full peer, in idiomatic Tcl — namespaces as modules (`::entity::core::*`),
snake_case procs, dicts for values, arrays-keyed-by-handle for mutable objects
(the one-interp "object" idiom), and the `chan event` + `vwait` reactor for
concurrency. Every value rides the S2 tagged-value CBOR rep (the EIAS resolution);
`src/ecf.tcl` is the protocol-altitude map/field-access layer over it.

| Layer | Module(s) | Notes |
|---|---|---|
| Value model | `ecf.tcl` | map/list builders + typed field reads; `""`=absent sentinel (A-TCL-007) |
| Content hash | `hash.tcl` | varint(format_code) ‖ SHA over ECF{type,data}; SHA via the C-shim |
| L1 Identity | `identity.tcl`, `entity.tcl`, `peerid.tcl` | seed→pubkey→§1.5 peer_id; system/peer (v7.65, no peer_id in basis); sign/verify |
| Wire | `wire.tcl`, `envelope.tcl` | [4-byte BE len][CBOR]; EXECUTE / EXECUTE_RESPONSE; byte-keyed dedup `included` |
| L2 Interaction | `peer.tcl` (dispatch) | only EXECUTE/EXECUTE_RESPONSE are wire types; request_id demux; §6.12 error codes |
| L3 Capability | `capability.tcl` | §5.2 3-way verdict, §5.5 chain-walk + attenuation + caveats, §3.6 K-of-N multisig, §5.1 revocation |
| L4 Bootstrap | `transport.tcl` | TCP listener/dialer on the event loop; §4.8 inbound-concurrent-with-outbound; §6.11 reentry |
| Foundation | `store.tcl`, `conn.tcl` | content-addressed store + tree + §6.10/§6.13(c) emit seam; handler-interface contract |
| Handlers | `handlers.tcl` | connect (hello/authenticate), tree, handler(register/unregister), capability, type(validate) + §7a echo/dispatch-outbound |
| Core types | `coretypes.tcl` | the 53-type §9.5 floor, render-from-model |
| Umbrella | `entity_core.tcl` | one `source` loads the whole graph (every module self-guards re-sourcing) |

## Baked-in v7.75 substrate floor (built in, not rediscovered at S4)

- **§4.8 store-safety — STRUCTURAL.** Single event thread: one handler runs to
  completion before the next readable event → the store dicts are never accessed
  concurrently. No lock (profile [async] = event-loop).
- **§4.10(a) payload bound.** The 4-byte length prefix is checked against 16 MiB
  `wire::MAX_FRAME` BEFORE the body is buffered; an over-limit prefix ends the
  connection (body boundary unknowable), the peer keeps serving.
- **§4.10(b) chain-depth pre-check.** `capability::chain_exceeds_depth` walks parent
  pointers WITHOUT verifying sigs (structural), mapping over-depth → **400
  chain_depth_exceeded** BEFORE the per-link authz walk; an *unreachable* parent is
  not a depth problem (→ left for the 403 authz walk).
- **§7b TCP_NODELAY** set on every accepted/dialed socket (best-effort `chan
  configure -nodelay 1`); all sockets non-blocking, no blocking `[read]/[gets]` on
  the event path.
- **§6.11 reentry** is a nested `vwait` (the natural event-loop turn) — no
  correlation-map tax, no cross-thread demux.

## Smoke (the exit gate) — 12/12

Two Tcl peers over real loopback TCP on ONE event loop:

Scenario 1 (core): session established (cap minted) · remote peer_id matches ·
unregistered path → 404 · authority-gated tree get → 200 returning a
system/handler/interface · capability request → 200 · **8-way request_id demux**
(8 in-flight, correlated out of order, N7/§6.11).

Scenario 2 (v7.74 Core Extensibility Boundary, `--debug-open-grants` + `--validate`):
handler register → 200 (live §6.13(a), not 501) · emit hook fired on register's tree
writes (§6.13(c)) · §7a echo → 200 verbatim · **§6.11 dispatch-outbound reentry**
round-trips (B→A echo over the inbound conn; outer 200).

## Findings / decisions

- **No spec-precision finding.** The EIAS probe is clean corroboration end to end —
  every wire field's major-type kind was fixed by the spec's field definitions; EIAS
  forced no side-channel anywhere in the peer layer. See `SPEC-AMBIGUITY-LOG.md` S3
  resolutions (A-TCL-001/002/003 closed as corroboration; A-TCL-007 resolved at the
  ecf layer — the tag is the presence bit, no `{present 0}` dict needed; A-TCL-008
  corroborated — a fourth event-loop §6.11-reentry-free substrate).
- **`b` vs `$b` banked S2 lesson held.** Every recursive/handle-threading call site
  passes the value (`$x`), never the bareword — no regressions of the S2 trap.
- **Reentry target semantics.** `dispatch-outbound` passes the BARE `target` as the
  EXECUTE uri (the receiver canonicalizes it to itself); the §7a relay forwards the
  downstream `value` map VERBATIM (re-wrapping double-nests — the non-conformant
  shape the keystone matrix caught on another peer).

## Exit criteria — MET

Smoke green (12/12); peer loads cleanly; the code reads as Tcl (namespaces + procs +
dicts + the event-loop reactor), not transpiled. **Next: S4** — `validate-peer
--profile core` (oracle `cc1970f`) via `run-s4.sh`, to 0-FAIL, then a matrix row.
