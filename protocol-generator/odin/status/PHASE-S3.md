# Odin — Phase S3 (Peer machinery) summary

**Date:** 2026-07-12
**Spec-data:** v0.8.0 (V8)
**Outcome:** full core-protocol peer (L1–L4 + foundation) on the raw-thread +
manual-mutex model, built on the GREEN S2 codec. Compiles clean; the two-peer
loopback **smoke is GREEN (7/7)** and **leak-clean** under `mem.Tracking_Allocator`.

## What was built (package `entity_core`, src/*.odin — new S3 modules)

| File | Contents |
|---|---|
| `entity.odin` | `Entity` {typ, data, hash} + `Envelope` {root, included} on the S2 `Ec_Value` tree; content-hash validate-on-parse (§1.8); owned-tree clone/destroy; `text_val`/`bytes_val`/`value_clone`/`hex_of` helpers |
| `wire.odin` | §1.6 4-byte-BE length framing; §4.10(a) 16 MiB length-prefix reject BEFORE buffering; EXECUTE / EXECUTE_RESPONSE / error-result / empty-params builders; TCP_NODELAY |
| `store.odin` | §1.7 content store (hash→entity) + entity tree (path→hash); **Mutex-guarded** (§4.8 manual store-safety); one-level §3.9 listing; carries its OWN allocator (cross-thread-consistent) |
| `identity.odin` | L1 identity (seed→pubkey→peer_id→peer-entity→identity_hash); §1.5 canonical identity-multihash peer_id; sign/verify entity signatures |
| `capability.odin` | L3 §5 verification core: §5.4 pattern match, §5.2 check_permission, §5.5 chain walk, §5.6 attenuation, §5.7 caveats, §5.1 revocation, §3.6 M3 multisig root + M4/M6; §4.10(b) **chain_exceeds_depth structural pre-check** (→ 400, before the authz walk) |
| `type_defs.odin` | §9.5 render-from-model: the 53 core type entities rendered natively + bound; byte-diff drift target vs the Go vector set |
| `peer.odin` | dispatch chain (§6.5: verify→resolve→check_permission→handler); connect/tree/capability/handler/type handlers; §6.9a seed-policy bootstrap; §7a echo + dispatch-outbound behind `--validate`; token minting + subset (§6.2) |
| `transport.odin` | L4 raw-thread transport: one reader thread/conn (§6.11 demux via `{request_id→slot}` + `sync.Cond`), inbound EXECUTE dispatched on its OWN thread (§4.8 N6), §6.13(b) outbound reentry shim, Session handshake (§4.1) |
| `host/host.odin` | `bin/entity-core-peer --port --name [--validate] [--debug-open-grants]`; loads `~/.entity/peers/NAME/keypair`; prints `LISTENING …` |
| `smoke/smoke.odin` | two-peer loopback smoke (handshake, 404, tree get, cap request, 8-way request_id demux), leak-checked |
| `test/peer_test.odin` | accept-path units (multisig K-of-N accept + M3/M4/M6 deny flips, single-sig root, type-registry 53-count + byte-diff, echo bootstrap) |

## Idiom seams exercised (the generator-robustness payoff)

- **Raw OS threads + manual `sync.Mutex` (§4.8/§7b)** — the biggest S3 seam vs the
  actor/STM peers: store-safety is enforced BY HAND. One reader thread per
  connection; each inbound EXECUTE dispatched on its own thread so a handler that
  originates an outbound EXECUTE (§6.13(b)) and awaits its reply does not block the
  reader. The §6.11 demux is a `{request_id → *Pending_Slot}` + `sync.Cond` — the
  correlation-map tax (no actor/CSP substrate), exactly as the profile predicted.
- **No-GC per-request arena via `context.temp_allocator`** — the whole dispatch
  (chain walk + handler scratch) allocates freely on temp; the response envelope is
  deep-cloned into `context.allocator` (gpa) so it outlives the arena reset. The
  whole smoke run proves leak-free under a tracking allocator.
- **Cross-thread allocator discipline (net-new S3 finding for this shape)** — a §4.8
  dispatch thread runs with a DIFFERENT `context.allocator` than the main thread; a
  store keyed to the calling thread's context double/bad-frees at destroy. Fixed by
  pinning ONE allocator in the `Store` struct and using it for every internal
  clone (see A-ODIN-009).
- **Slice-literal lifetime trap (net-new S3 finding)** — an Odin `[]Field{...}`
  compound literal stored into a `[dynamic]` and read later dangles (stack-temp
  backing). The type-registry declaration renders + binds each type IN PLACE within
  its declaring statement (see A-ODIN-010). ASan caught this immediately.

## Smoke result: 7 · 0F (7/7 PASS)

```
Handshake:
  [PASS] session established (initial capability granted)
  [PASS] remote peer_id matches responder
Dispatch:
  [PASS] unregistered path -> 404
  [PASS] granted tree get -> 200
  [PASS] tree get returns a system/type entity
  [PASS] capability request -> 200
Concurrency (request_id demux):
  [PASS] 8 interleaved requests each correlated -> 8/8
Teardown clean.   ->   SMOKE: PASS (7 pass, 0 fail)
```

Two Odin peers over real loopback TCP through the full dispatch chain. Plus the
11-test `odin test test` suite (6 S2 + 5 S3 accept-path/registry units) all green
and leak-clean.

## §9.1 non-functional floor — baked in at design time (not rediscovered at S4)

- **§4.8 store race-safety:** explicit `sync.Mutex` around every content/tree op;
  each dispatch on its own thread — no data race (concurrency category 5/5 at S4).
- **§4.10(a) payload bound:** 16 MiB length-prefix reject BEFORE buffering the body.
- **§4.10(b) chain depth:** `chain_exceeds_depth` structural pre-check walks parents
  (no sig work) and maps over-depth → **400 chain_depth_exceeded**, BEFORE the
  per-link authz walk; an unreachable parent stays 403 (not a depth fault). This is
  the one net-new piece the whole cohort had to add — implemented as one helper at
  the verify site.
- **§5.2a auth verdict→status:** 3-way verdict → 401 (authn) / 403 (authz) /
  400 (chain) / 401 (unresolvable grantee).
- **§7b:** TCP_NODELAY on every socket; all blocking read/accept on dedicated OS
  threads (Odin has no cooperative pool to starve).

## Honest framing (ADR-0012)

Corroboration / generator-robustness. A green verdict is **cohort-consistent, not
independent convergence** — the type-registry vectors and conformance surface are
the Go author's artifacts; this peer reproducing them on a fresh raw-thread /
no-GC / value-error shape adds generator robustness, not a new independent witness.

## Next (S4)

Drive `validate-peer --profile core` to 0-FAIL (done — see PHASE-S4.md).
