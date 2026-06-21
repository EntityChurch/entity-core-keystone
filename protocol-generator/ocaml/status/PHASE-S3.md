# entity-core-protocol-ocaml — Phase S3 (Peer) Summary

**Status: COMPLETE — smoke surface green; S4 PASS (see PHASE-S4)**

## What was built (`src/`, on top of the S2 codec)

| Module | V7 layer | Responsibility |
|---|---|---|
| `model.ml`      | foundation | materialized entity `{type,data,content_hash}` + envelope (§3.1); fidelity-validating `of_cbor` (§1.8) |
| `store.ml`      | foundation | content store (hash→entity) + entity tree (path→hash) + one-level listing (§1.7, §3.9) |
| `identity.ml`   | L1 | keypair → peer_id (§1.5 **identity-multihash**, A-OC-007) / peer entity / signing (§3.5, §7.3) |
| `capability.ml` | L3 | §5.2 `verify_request` (3-way authn/authz verdict), `check_permission`, §5.4 patterns + `canonicalize` + §1.4 `normalize_uri`, §5.5 chain walk, §5.6 attenuation, §5.7 delegation caveats, §5.1 `is_revoked` |
| `type_defs.ml` + `type_defs_data.ml` | foundation | §9.5 53-core-type render-from-model (in-code override table) |
| `wire.ml`       | L2 | §1.6 framing; EXECUTE_RESPONSE / error builders |
| `peer.ml`       | L1–L4 | the four MUST handlers (connect/tree/handler/capability), §6.5 dispatch chain, §6.5 signature ingestion, §6.6 resolution, §6.9 bootstrap, per-connection state |
| `transport.ml`  | L4 | TCP listener + per-connection serve thread (stdlib `Unix`+`Thread`; A-OC-003 revised) |
| `bin/host.ml`   | — | standalone host for S4 (`--port`, `--debug-open-grants`, `LISTENING` line) |

## Idiom seams (deliberate, vs C#/TS)
`('a, …) result` / poly-variant verdicts (not exceptions) · `snake_case` / `Upper_snake`
modules · **stdlib threads** for concurrency (not eio — A-OC-003 revised; not Task/Promise).

## Concurrency decision (A-OC-003 revised)
eio was deferred: a `--profile core` peer has no handler-initiated outbound dispatch
(origination is extension-only, §9.0), so §4.8/§6.11 is met by one `Thread` per
connection — **zero new opam deps**, honoring the dependency-minimization stance.
eio/Lwt remain the path for when origination/subscription scope arrives; the swap is
localized to `transport.ml`. Flagged for operator review (overturns an S1 decision).

## Spec-first probes surfaced (the peer #3 payoff)
- **A-OC-007 ⚑** — §7.4 NORMATIVE peer-id pseudocode (`SHA256(pubkey)`, hash_type 0x01)
  **contradicts** the §1.5 v7.65 canonical-form table (identity-multihash, hash_type
  0x00, raw pubkey). A fresh §7.4 reader fails connectivity; peers #1/#2 inherited the
  correct §1.5 reading and never flagged §7.4's staleness. Routed to arch.
- **A-OC-008** — §5.2 flat "DENY → 403" under-specifies the §4.6 authn(401)/authz(403)
  boundary at request time; corroborates arch **F20** from a third, spec-first peer.
- **A-OC-006** — type-registry render-from-model: 53/53 byte-identical, first run.

## Smoke surface
The S3 lifecycle smoke scenario (boot peer, handshake both directions, 404 on
unregistered path, `request_id` correlation, teardown) is **subsumed by the
`validate-peer connectivity` category** (22/22 — TCP connect, hello→authenticate,
EXECUTE/EXECUTE_RESPONSE, request_id echo). No standalone smoke runner authored;
the live oracle is the stronger superset (see PHASE-S4).

## Exit criteria
Peer compiles clean (warnings-as-errors) · reads as OCaml, not transpiled · smoke
surface (connectivity) green · S2 codec regression unbroken (69/69 + selftest +
type-registry 53/53) · container reproducible. **S3 PASS.**
