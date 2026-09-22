# entity-core-protocol-julia — Phase S3 (Peer machinery) Summary

**Peer** (Julia, Tier-3 corroboration / generator-robustness — single-threaded Task scheduler,
multiple-dispatch codec) ·
**Status: COMPLETE — smoke runner 6/6 PASS, peer loads clean, S2 codec unbroken (71/71).**

## What was built (`src/`, module `EntityCore` — on top of the S2 codec)

| Module | Responsibility |
|---|---|
| `model.jl` | `Entity {type,data,content_hash}` (§1.1/§3.4) + `Envelope {root, included}` (§3.1) over the S2 `CborMap`; wire ⇄ entity with N4 validate-before-trust (recompute hash, reject mismatch) |
| `wire.jl` | Frame I/O `[4-byte BE len][CBOR envelope]` (§1.6) over a Sockets `TCPSocket`; §4.10 length-prefix check → 413 **before** buffering; EXECUTE (§3.2) + EXECUTE_RESPONSE (§3.3) builders |
| `identity.jl` | Peer identity seed→keypair→peer_id (§1.5 canonical identity-multihash) + `system/peer` (§3.5); `sign_entity`/`verify_signature` over the 33-byte content_hash |
| `store.jl` | Content-addressed store + tree-path index — plain `Dict`s, **structurally race-free** on the one scheduler (§4.8/§7b) |
| `handler.jl` | `HandlerContext` + the `(ctx)->(status,result,included)` handler contract; the §6.11 `reenter` outbound seam; the extension boundary (no domain handlers shipped) |
| `peer.jl` | The **§6.5 dispatch chain**: connect handler (§4.1/§4.6 hello+authenticate+grant), request-time `verify_request` (§5.2 **auth-before-resolve**), root-cap authz, handler resolution, seed-grant mint (§6.9a) |
| `transport.jl` | TCP listen/dial + per-connection reader Task + **§6.11 request_id demux** via `Channel`; `Session`/`initiate`/`session_execute`; serialized writes; TCP_NODELAY |
| `smoke.jl` | The S3 gate — two Julia peers over loopback |
| `bin/peer.jl` | The `validate-peer`-driven executable (`--name`/`--port`/`--validate`); loads the on-disk keypair, prints `LISTENING`, serves (S4 entry point) |

## Smoke gate — `./run-s3.sh` (was `run-smoke.sh`; renamed 2026-09-08 so the S3 axis sweep reaches it) (in-container, `--network=none`, capped)

```
Handshake (both directions):
  [PASS] hello + authenticate → session established (grant minted)
  [PASS] remote peer_id matches responder
Dispatch (§6.5 auth-before-resolve, F31):
  [PASS] UNAUTHENTICATED unknown-handler → 401 (not 404)
  [PASS]   └ 401 response correlates to its request_id
  [PASS] AUTHENTICATED unknown-handler → 404 (resolve reached post-auth)
Concurrency (§6.11 request_id demux — 8 out-of-order in-flight):
  [PASS] 8 interleaved authenticated requests each correlated → 8/8
→ SMOKE: PASS (6 pass, 0 fail)
```

- **Handshake both directions:** the initiator's `hello` and `authenticate` EXECUTEs each
  traverse a real frame through the responder's dispatch and return EXECUTE_RESPONSEs (200);
  authenticate mints a seed root capability and returns it in `included`.
- **§6.5 auth-before-resolve (F31) — the load-bearing check:** the SAME unregistered path returns
  **401** when the EXECUTE is unauthenticated (no author/signature) and **404** when it is
  authenticated. This proves the auth check (§5.2 → 401) runs BEFORE handler resolution (→ 404);
  reversing the order (resolve→404 first) would leak handler existence to unauthenticated probers,
  the F31 regression. Trichotomy realized: 401 (no auth) / 403 (auth, no valid cap) / 404 (auth +
  valid root cap, unknown handler).
- **§6.11 request_id demux:** 8 concurrently-issued authenticated requests, dispatched
  out-of-order on the responder's per-EXECUTE Tasks, each correlated back to its own `request_id`.

Also verified across a **real process boundary**: `bin/peer.jl` (identity from
`~/.entity/peers/NAME/keypair`) prints `LISTENING`, and a separate Julia client completes the
handshake (peer_id MATCH) and gets 401 (unauth) / 404 (auth) on an unknown path.

## §7b store-safety on Julia's single-threaded Task substrate (A-JULIA-005)

**Structural, no lock.** The core peer runs the single-threaded Task scheduler: cooperative Tasks
yield ONLY at I/O/await points, never mid-statement, so every store (`Dict`) mutation between yield
points is indivisible w.r.t. every other Task — there is no data race to guard, no lock, no atomics
(the actor/CSP/event-loop "free store-safety" result — PHP/Dart/Tcl class — on a fourth substrate).
The one place a lock IS taken is the **transport write path** (`ReentrantLock`): a frame's
`write`+`flush` yields at libuv, so writes are serialized to keep frames atomic on the shared
socket. Reads yield the Task (never block the thread); TCP_NODELAY is set on every socket. Even the
`s.req_counter` rid allocation under 8 concurrent `session_execute`s is safe by construction (the
read-modify-write completes before the first yield). The §6.11 reentry seam is a plain `Channel`
handoff — no cross-thread demux, no correlation-map tax, no deadlock.

## Idiom-level review

Reads as native Julia: multiple dispatch (codec + `mapget`), `nothing`-sentinel field access,
return-tuple outcomes `(status, result, included)` over out-params, custom `<: Exception` leaves for
faults, `@async`/`Channel`/`@sync` concurrency over the libuv reactor, `!`-suffixed mutators
(`store_put!`, `register_handler!`). No transpiled type-switch; connection state is a mutable
struct, entities are immutable structs.

## Ambiguity log

Two new non-blocking items: **A-JULIA-010** (S3 capability scope = single-link root cap;
multi-link attenuation + `checkPermission` scope + §4.10(b) chain-depth pre-check are S4) and
**A-JULIA-011** (§4.10 413-before-buffering vs `request_id` correlation tension on a length-prefixed
stream — flagged to arch for confirmation, not asserted as novel). No blocking items.

## Not in this phase (S4)

- The core handlers (`system/{tree,capability,type,handler}`) behind the resolved dispatch seam.
- Multi-link capability chain-walk / attenuation / TTL / §4.10(b) chain-depth → 400; §5.2
  `checkPermission` scope test against the resolved pattern.
- §7a `system/validate/*` conformance handlers behind `--validate` (accepted as a flag; handlers
  not yet installed).
- `run-s4.sh` + oracle bootstrap + the live `validate-peer --profile core` run.

## Exit criteria

Smoke runner 6/6 PASS · peer loads + precompiles clean under Julia 1.11.5 · reads as idiomatic
Julia · S2 codec regression-free (71/71) · ambiguity log has no blocking items · container
reproducible + offline (`--network=none`, capped). **S3 PASS.**
