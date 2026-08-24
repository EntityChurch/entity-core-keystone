# entity-core-protocol-fortran — Phase S3 summary (COMPLETE)

**Phase:** S3 (peer machinery)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/fortran-toolchain:latest` (gfortran 15.2)
**Status:** ✅ **COMPLETE — offline foundation self-test 18/18 + two-peer loopback smoke 5/5
(0 fail).** Reproduce: `./run-s3.sh` (→ `make s3`). Container-bound, sealed-offline
(`--network=none`; loopback is intra-container 127.0.0.1). S2 codec gate unaffected:
still **69/69** (`make conf`).

## What S3 built (Core Layers 1–4 + foundation, on the S2 codec)

The full peer, in idiomatic modern Fortran — modules as namespaces, `lower_snake_case`,
derived types (`entity_t`, `id_t`, `store_t`, `envelope_t`, `session_t`) as the record
analogue, and the `intent(out) stat` / integer-verdict status-code error model. Unlike
the Rexx peer (which packs every value into a self-delimiting byte string because classic
Rexx has no record type), Fortran works directly on the S2 `ecf_value_t` tagged-union
value tree + first-class derived types — a cleaner substrate.

| Layer | Module(s) | Notes |
|---|---|---|
| value helpers | `val.f90` | map/array builders + typed field reads over `ecf_value_t`; `str_t` string-list cell; hex/base bridges |
| **L1 identity** | `identity.f90` `keystore.f90` | §1.5 identity-multihash peer_id (base58 via C-ABI); §3.5 sign/verify; **keystore**: `~/.entity/peers/NAME/keypair` PEM (hand-rolled base64) |
| materialized entity | `ent.f90` | `entity_t {type,data,hash}`; §1.1 content_hash via C-ABI floor; §1.8 recompute-and-verify on decode |
| foundation | `store.f90` | content store (hash→entity) + tree (path→hash) + §3.9 listing; **§4.8 store-safety STRUCTURAL** (one image, one thread) |
| §9.5 floor | `coretypes.f90` | all 53 core types render-from-model |
| **L2/wire** | `wire.f90` | §3.1 envelope (byte-keyed `included`), §3.2/§3.3 EXECUTE/EXECUTE_RESPONSE builders+readers, `wire_peek` demux helper |
| **L3 capability** | `capability.f90` | §5 verify_request/chain-walk/attenuation/caveats/revocation + §3.6 M3 multisig K-of-N; ALLOW/DENY + unresolvable |
| **L4 transport** | `net.f90` `transport.f90` `src/ext/net_shim.c` | the C net-shim (below) + net wrappers + §6.11 request_id demux table |
| **L2/L4 peer** | `peer.f90` | §6.5 dispatch chain, §6.9/§6.9a bootstrap + seed policy, MUST handlers (connect/tree/handler/type/capability) + §7a echo/dispatch-outbound, initiator session + §4.1 handshake |
| host | `bin/peer.f90` | the S4-ready `--name/--port/--validate/--debug-open-grants` host (prints `LISTENING <port>`) |

## The transport — Fortran links C DIRECTLY (contrast Rexx)

The C net-shim (`src/ext/net_shim.c`) owns the real BSD sockets + the single `select()`
loop + §1.6 de-framing, and the Fortran peer drives it by symbol via `iso_c_binding`
(`ec_net_listen/connect/send/close/poll` + `ec_now_ms`/`ec_random`). This is the **ONLY**
C wrapper — crypto/base58/framing bind `libentitycore_codec` directly, no wrapper. Because
gfortran links C first-class (unlike Regina Rexx, which cannot `dlopen` a C extension and
so needed a co-process daemon over FIFOs), there are **no FIFOs, no co-process** — a
single compiled binary. `ec_net_poll` runs one `select()` pass and returns the next queued
event (ACCEPT / FRAME / CLOSED / OVERSIZE); the Fortran side pumps it in `peer_serve`.
**§7b/§4.8 store-safety is STRUCTURAL: one process, one thread, one select loop → the
store is never raced.** The §6.11 reentry is a manual pump on the same loop (the
correlation-map tax the non-actor peers pay).

## v7.75 §9.1 non-functional floor — baked in (not deferred to S4)

- **§4.8 store-safety = STRUCTURAL** (single-thread + single select-loop; stated in
  `store.f90` / `peer.f90`).
- **§4.10(a) 413**: the net-shim checks the length prefix and, on a frame > 16 MiB,
  signals `EC_EV_OVERSIZE` **before buffering the body** (it drains, keeps the connection);
  the peer answers **`413 payload_too_large`** and keeps serving (`send_413`). The 413's
  request_id is empty — the body was never read (A-FTN-014).
- **§4.10(b) chain depth**: `cap_chain_exceeds_depth(store, cap, inc)` is a STRUCTURAL
  pre-check run BEFORE the per-link authz walk in `cap_verify_request`; over-depth → **`400
  chain_depth_exceeded`** (NOT 403). An unreachable parent is not a depth error (stays 403).
  Informative bound 64. (Verified by the selftest chain-depth assertion.)
- **§4.10(c) admission**: `EC_MAXCONN` = 512 (above the 256-burst flood + follow-up), idle
  slots ~0 cost; keep serving after every rejection.
- **§7b**: `TCP_NODELAY` set on every accepted/dialed socket; blocking `read`/`accept` live
  ONLY in the C net-shim's own select loop (never on a Fortran cooperative pool — there
  isn't one).

## N5–N8 coverage

- **N5** envelope `included` preservation both sides: `env_to_cbor`/`env_of_cbor` carry the
  byte-keyed `included` map, dedup first-seen, and verify each content_hash == its key
  (§3.1); the authenticated-request path round-trips a 5-entity `included` (token, granter,
  author, cap-sig, exec-sig) through the responder and back.
- **N6** inbound-concurrent-with-outbound dispatch: the single pump dispatches an inbound
  EXECUTE to completion before polling the next event (§4.8 by construction).
- **N7** reentrant transport + request_id demux: the 8-way concurrent smoke leg fires 8
  EXECUTEs in flight and correlates every reply by request_id (`transport.f90` pending
  table + `wire_peek`). **PASS.**
- **N8** capability verdict determinism: `cap_verify_request` is a pure function of
  (local, store, envelope) — no clock-dependent branch except explicit TTL/temporal bounds.

## Smoke result (two OS processes over loopback TCP)

```
responder bound on 127.0.0.1:<port> (peer_id 2KHoAk7A5Jmh...)
  [PASS] session established both ways (capability minted)
  [PASS] remote peer_id is a base58 peer id
  [PASS] remote peer_id matches responder
  [PASS] unregistered path -> 404
  [PASS] 8 interleaved requests each correlated by request_id
SMOKE: PASS (5/5)
```

Handshake both directions (hello → authenticate → seed-policy grant mint), a real §5.2
chain-verify on the minted discovery-floor cap gating the 404 path, out-of-order demux,
clean teardown. The offline self-test (18/18) adds the accept-path coverage the network
gate can't isolate: store round-trip, entity content_hash + wire fidelity, sign/verify
(+ negative), base64 keystore round-trip, and the **full §5.2 verify-request chain**
(A grants to B; B's request ALLOWs; a mis-signed request → 401 AUTHN_FAIL) — the "direction
the oracle can't cover" discipline.

## Findings / decisions (S3)

- **A-FTN-013 (build-value heap leak → S4 arena).** Pointer-items (A-FTN-011) means built
  response trees leak per dispatch; fine within the cap for S3/bounded S4, needs a bump
  arena under a §4.9 sustained flood. Documented, deferred to S4.
- **A-FTN-014 (413 has empty request_id).** The body is never buffered, so the oversize
  reply cannot correlate by request_id. Arch to confirm the resource_bounds expectation.
- **A-FTN-015 (gfortran `.and.` does NOT short-circuit — durable lesson).** `-fcheck=bounds`
  evaluates both operands, so `i<=n .and. s(i:i)` aborts at `i=n+1`; every guarded
  substring must be a nested `if`. Surfaced at RUNTIME (compiler accepts it) — a real
  Fortran-family trap. Fixed across `val.f90`/`capability.f90`/`peer.f90`.
- No spec-precision finding at S3 — the peer machinery is a faithful port of the
  language-agnostic protocol layers onto Fortran's derived-type + `ecf_value_t` substrate
  (the probe's value was S2, the signed-carrier number model).

## What S4 must know

- **Launch:** `bin/peer --name NAME [--port N] [--validate] [--debug-open-grants]`. `--name`
  loads/creates the Ed25519 seed at `~/.entity/peers/NAME/keypair` (entity-core PEM =
  base64 of the 32-byte seed between BEGIN/END ENTITY PRIVATE KEY — verified against the
  run-s4 `ERER…` provision; peer_id `2KHoAk7A5Jmh…` for seed 0x11). Prints `LISTENING
  <port>` for the harness to scrape. `--validate` bootstraps the §7a `system/validate/{echo,
  dispatch-outbound}` handlers (OFF by default). `--debug-open-grants` selects the
  degenerate `default → *` seed policy through the real §6.9a mechanism.
- **Seed policy** is wired per the keystone convention: an owner cap at
  `system/capability/policy/{id_hash_hex}` (detached-signature shape) + a `default`
  policy-entry (discovery floor, or the open scope under `--debug-open-grants`);
  authenticate derives grants = UNION(discovery_floor, policy_entry.grants).
- **`run-s4.sh` is NOT yet authored** — author it rexx-shaped (build `make peer`, provision
  the keypair, launch `bin/peer --name conformance --port 0 --debug-open-grants --validate`,
  scrape `LISTENING`, run `validate-peer -profile core -addr 127.0.0.1:$PORT`). No
  co-process/FIFO cleanup needed (single binary). The go oracle is at
  `output/s4-oracles/{validate-peer,entity-peer}` (commit `cc1970f`).
- **Known S4 gaps to expect:** (1) `dispatch-outbound` returns `503 no_outbound_seam` —
  the full §6.13(b) reentry pump is stubbed (the manual reentry primitive exists in
  `sess_send`/`pump_until` but is not yet wired to the handler); (2) the build-value heap
  leak (A-FTN-013) may need the arena for `concurrency` T2.1's ~10k-request flood; (3)
  the 413 request_id question (A-FTN-014). Everything else (connect/tree/handler/type/
  capability, chain verify, multisig, revocation) is implemented and offline-verified.