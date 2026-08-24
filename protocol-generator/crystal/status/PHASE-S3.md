# Crystal — Phase S3 (PEER MACHINERY) summary

**Date:** 2026-07-12
**Spec-data:** v0.8.0 (V8), pinned snapshot
**Outcome:** full core-protocol peer (Layers 1–4 + foundation) on the S2-green
codec. Smoke runner GREEN; peer compiles clean; 97/0 spec suite (89 S2 + 8 new
S3 accept-path/loopback units). Exit criteria met.

## What was built (`src/entity_core/`)

- **`entity.cr`** — materialized `Entity {type, data, content_hash}` (§1.1/§3.4).
  A `class` (shared by reference, keyed by content_hash). `data` is the arbitrary
  `Cbor::EcValue` union (NOT assumed a Hash — A-JAVA-010). Typed nil-safe field
  reads (`text`/`bytes`/`uint`/`map_field`/`entity_field`) over the `data_map`
  view; §1.8 fidelity check on `from_cbor` (recompute + compare carried hash).
- **`envelope.cr`** — the §3.1 protocol envelope (`root` + insertion-ordered
  `included` list keyed by content_hash). §3.1 included-key == content_hash check;
  dedup on decode (N5 preservation is structural — the codec re-sorts keys, so
  wire order is canonical regardless of insertion order).
- **`identity.cr`** — L1 identity bundle over the S2 libsodium signature module:
  seed → pubkey → §1.5 peer_id → `system/peer` entity → identity_hash. `sign`
  produces a `system/signature` entity over the 33-byte content_hash (§3.5);
  `verify_signature` against a signer's `system/peer`.
- **`store.cr`** — in-memory content-addressed store + entity tree (§1.7). Content
  keyed by hex content_hash, tree by path. §3.9 `bind_cas`. §6.10 emit consumers
  (live with zero consumers — the §6.13(c) extensibility hook). **§4.8
  store-safety is STRUCTURAL** on Crystal's single-thread fiber scheduler: every
  mutating method is pure in-memory CPU with no suspension point, so a compound
  read-then-write is atomic w.r.t. other fibers by construction — no `Mutex` at
  core (documented; `-Dpreview_mt` would need one, A-CRY-005).
- **`wire.cr`** — §1.6 framing (`[4-byte BE len][CBOR envelope]`) + the two §3.3
  message builders (EXECUTE / EXECUTE_RESPONSE). `read_frame` checks the length
  prefix against `MAX_FRAME` (16 MiB, §4.10(a)) BEFORE buffering the body →
  `PayloadTooLargeError` → 413. Only these two are wire message types; any other
  root type yields no response.
- **`handler.cr`** — the handler seam: `Outcome` (status/result/included),
  `HandlerContext`, the `Conn` per-connection state (§4.2 handshake progress + the
  §6.13(b) `outbound` seam), and the abstract `Handler` (STATIC operation ladder —
  a compiler-checked `case operation` per subclass, the idiom divergence from the
  Ruby peer's reflective `send`).
- **`capability.cr`** — the L3 §5 verification core: pattern matching (§5.4),
  §5.2 `verify_request` (3-way `RequestVerdict` enum), §5.5 chain walk + §5.6
  attenuation + §5.7 caveats + §5.1 revocation, §PR-8 granter-frame
  canonicalization, §3.6/§5.5 K-of-N multi-sig root (M3/M4/M6), and the §4.10(b)
  `chain_exceeds_depth?` structural pre-check.
- **`core_types.cr` + `data/core_type_floor.cr`** — the 53-type floor
  (render-from-shapes): decode the vendored Go-dumped ECF `data` with THIS codec,
  re-materialize a `system/type`, ASSERT the recomputed content_hash equals the
  oracle's pinned hash. All 53 assert clean at bootstrap.
- **`peer.cr` + `handlers.cr`** — the §6.5 dispatch brain + the four MUST system
  handlers (connect/tree/capability/handler), §6.6 backward tree-walk resolution,
  §6.9/§6.9a bootstrap (self-owner cap + default seed policy), §6.13(a)
  entity-native dispatch, §6.13(b) outbound dispatch, and the §7a conformance
  handlers (echo, dispatch-outbound) behind `--validate`.
- **`transport.cr`** — L4: TCP listener + dialer, **fiber-per-connection** CSP
  model (A-CRY-005). One reader fiber per connection demuxes inbound frames
  (§6.11): EXECUTE_RESPONSE routes by request_id through a pending
  `{request_id => Channel}` map (a fiber parks on `channel.receive`, the reader
  `send`s); an inbound EXECUTE is dispatched on ITS OWN spawned fiber (§4.8) so a
  §6.13(b) reentry doesn't block the reader. Per-connection write `Mutex`;
  `TCP_NODELAY` on every socket (§7b). Plus the initiator dialer + §4.1 handshake.
- **`bin/entity-core-peer.cr`** — the host CLI (`--port/--name/--validate/
  --debug-open-grants`; PEM keypair load; `LISTENING` line).
- **`bin/smoke.cr`** — the S3 smoke runner (boot in-process, dial, handshake,
  404 on unregistered path, 200 on a real tree/get, 8-way request_id demux, clean
  teardown). GREEN.

## N5–N8 + §9.1 floor — baked in at design time

- **N5** envelope `included` preservation: structural — the codec re-sorts keys,
  `Envelope` carries the full list request+result side, `cap_included` /
  `outbound_dispatch` attach the authority chain on both surfaces.
- **N6** inbound-concurrent-with-outbound: each inbound EXECUTE dispatches on its
  own spawned fiber; the reader never blocks on a handler.
- **N7** reentrant transport + request_id demux: the `{request_id => Channel}`
  pending map; a handler issuing a sub-request parks on a Channel while the same
  reader fiber keeps serving.
- **N8** verdict determinism: the §5 Layer-1 verdict is a pure function of chain
  state (bare `RequestVerdict`), local policy separate.
- **§4.10 bounds:** 413 before buffering (length-prefix check); 400
  `chain_depth_exceeded` via the `chain_exceeds_depth?` structural pre-check
  BEFORE the per-link authz walk (an unreachable parent stays 403, not a depth
  fault) — the one net-new cohort primitive, implemented as one helper.
- **§5.2a verdict→status:** 401 authn / 403 authz / 400 chain-too-deep / 401
  unresolvable-grantee (carve-out via `UnresolvableGranteeError`).

## Naming-collision note (A-CRY-007 consequence)

`EntityCore::Hash` (the content-hash module) shadows stdlib `Hash` inside the
namespace once the whole peer is loaded together. Bare `Hash`/`when Hash` was
fixed to `::Hash`/`when ::Hash` in `cbor.cr` (`coerce`) and `base58.cr`; the
generic map type is written `::Hash(Cbor::EcValue, Cbor::EcValue)` throughout.
No spec matter — a Crystal-substrate consequence, logged under A-CRY-007.

## Honest framing (ADR-0012)

**Corroboration / generator-robustness — cohort-consistent, NOT independent
convergence.** The peer is modelled on the Ruby reference peer's module
boundaries but re-derived on the compiled/statically-typed/fixed-width-int/CSP-
fiber substrate; where it matches Ruby it is by independent arrival at the same
spec, and the concurrency seam (fibers + Channels vs GVL threads + ConditionVar)
deliberately differs. It does not add an independent producer.

## Next (S4)

Drive `validate-peer --profile core` to 0-FAIL (done — see PHASE-S4.md).
