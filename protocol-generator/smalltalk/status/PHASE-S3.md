# entity-core-protocol-smalltalk — Phase S3 summary (COMPLETE)

**Phase:** S3 (peer machinery)
**Date:** 2026-07-12
**Peer:** #26 — Pharo Smalltalk, the FIRST pure-object / live-image / message-passing peer.
**Status:** COMPLETE — GREEN. **SMOKE 6/6** + **SELFTEST 25/25** + S2 corpus still **69/69**.
No blocking items.

## The gate — MET

- **Smoke runner GREEN (6/6):** boots a Smalltalk responder on a loopback port; a
  distinct-identity initiator drives the §4.1 handshake both directions and the
  post-handshake checks:
  1. `connect:hello` → **200** (responder hello carries a peer_id + nonce)
  2. `connect:authenticate` → **200** (result is a `system/capability/grant` with a token)
  3. connection established (the grant proves it — a token content_hash is returned)
  4. EXECUTE an unregistered path (`local/does-not-exist`) → EXECUTE_RESPONSE **404**
     `handler_not_found` (a signed + capability-carrying request, so §6.6 resolution-first
     yields 404 before any deep authz)
  5. **§6.11 request_id demux:** two EXECUTEs PIPELINED (both sent before either reply is
     read); each reply correlates to its own `request_id` (out-of-order-safe)
  6. clean teardown
- **Peer-layer foundation self-test GREEN (25/25):** identity derivation + sign/verify,
  store bind/get round-trip, N5 envelope (byte-key + key==content_hash + first-seen dedup,
  both sides), the §4.10(b) chain-depth pre-check (deep-70 → exceeds; root → within;
  unreachable-parent → NOT depth), the §5.2 verdict trichotomy mapping, the §4.10(a) 16-MiB
  cap classifier, the wire builders round-trip, and the §6.11 demux table (distinct
  request_ids → distinct records, no cross-talk).
- **Peer compiles/loads cleanly into the image** (`make image` snapshots a peer image with
  the S3 packages added to `load.st` srcFiles). S2 corpus re-run **69/69·0F** after the one
  additive EcValue change (below) — no regression.
- **Idiom review:** reads as native Smalltalk (see the A-ST-000 verdict below).

All GREEN inside `containers/pharo-toolchain/`, sealed-offline (`--network=none`; loopback
127.0.0.1 works). No reference peer needed for S3 (Pharo owns the sockets + the
single-event-loop + crypto in-process via UFFI — no co-process daemon).

## What was built

Peer machinery in two new Tonel-ish packages on top of the S2 codec + UFFI crypto:

- **EntityCore-Peer** (12 classes):
  - `EcEntity` + `EcAbsent` — the materialized entity `{type, data, content_hash}` as a
    first-class OBJECT (memoized content_hash over `{type,data}`, format 0x00); field reads
    (`textAt:`/`bytesAt:`/`uintAt:`/`field:`) through the data-map view; `asWireMap` /
    `fromWireMap:` (recompute + verify the carried content_hash, §1.8). `EcAbsent` is the
    A-ST-007 sentinel (a singleton, NOT nil).
  - `EcVal` — a value-construction facade (`EcVal text:/bytes:/uint:/array:/map:`) so
    handlers build wire values idiomatically while the explicit-value-tagging discipline
    (A-ST-003) is preserved (the caller still chooses the class).
  - `EcEnvelope` — the §3.1 `{root, included}` builder; `included` is a byte-keyed
    content_hash→entity map with first-seen dedup on `include:` and key==content_hash
    verification on decode (N5 both sides).
  - `EcIdentity` — L1: seed → pubkey (UFFI) → `system/peer` entity → id_hash → §1.5 peer_id;
    `signatureEntityFor:` + `verifySignatureEntity:withPubkey:` (crypto via the C-ABI).
  - `EcWire` — the two §3.3 message builders (EXECUTE, EXECUTE_RESPONSE) + the
    `system/protocol/error` result + `emptyParams`.
  - `EcStore` — the content store + entity tree as Dictionaries (structurally race-free,
    §4.8 single-event-loop); bind/get/hashAt/unbind.
  - `EcNet` + `EcConnection` — native non-blocking BSD sockets: listen/dial/accept with
    TCP_NODELAY (§7b), 4-byte-BE-length framing, the §4.10(a) 16-MiB cap (drain-and-keep),
    every read gated by a bounded `waitForDataFor:`/`dataAvailable` readiness test (§7b: never
    block the single green process indefinitely).
  - `EcPending` + `EcPendingRecord` — the §6.11 request_id demux table (keyed by request_id
    String → a per-outbound record; the cohort's A-FT-025 cross-talk hazard is structurally
    absent — distinct ids are distinct Dictionary keys).
  - `EcHandlerContext` + `EcHandlerResult` — the §6.13 handler-interface contract (the
    extension boundary: a handler is a block receiving a context, answering a result +
    optional response-included entities).
  - `EcPeer` — the assembly: bootstrap (install identity + register the MUST handlers), the
    single-event-loop serve tick + loop, the §6.5 dispatch chain (connect pre-auth; else
    authn → resolve(404) → authz(403) → handler), the §3.3 frame router (EXECUTE dispatched,
    EXECUTE_RESPONSE correlated, any other root closes the conn), and the §6.11 reentry pump
    (`dispatchOutbound:` re-enters the serve tick, depth-capped). `EcPeerHandlers` compiles
    the built-in §4.1 connect (hello/authenticate + seed-grant mint) + §6.3 tree-get onto it.
- **EntityCore-Capability** (`EcCapability`) — the L3 S3 scaffold: verdict Symbols
  (#allow/#authn/#authz/#unresolvable/#depth), the §4.10(b) `exceedsDepth:in:` pre-check
  (the ONE net-new cohort bit — BEFORE the authz walk, unreachable-parent ≠ depth),
  `findSignatureFor:in:`, and the `verifyAuthn:`/`verifyAuthz:` legs.
- **EntityCore-Peer errors** (`EcPeerErrors`) — `EntityProtocolError`/`EntityTransportError`
  extending the S2 `EntityCoreError` tree (EcWireError etc.).
- Peer entry `bin/peer.st` (env-driven options: EC_PEER_PORT/SEED/NAME; prints
  `LISTENING <port>`, serves forever); drivers `tests/{s3-selftest.st, smoke.st, smoke.sh}`;
  `Makefile` targets (`s3`/`selftest`/`smoke`) + `run-s3.sh` (container-bound,
  `--network=none`).

## Bugs found + fixed in the generated peer (the keystone payoff)

All caught by the smoke / selftest / live edge probes and fixed in code (never the test):

1. **`EcValue>>isAbsent` was not polymorphic** (the headline). `EcEntity>>field:` returns the
   `EcAbsent` sentinel on a missing key or the raw value otherwise; `EcHandlerContext>>params`
   tested `v isAbsent`, but a plain value (`EcMap` etc.) did not understand `isAbsent` → a
   live DNU in `handleHello:` that dropped every handshake reply (SMOKE 0/6). Fixed by adding
   `isAbsent ^ false` to the `EcValue` base (a pure additive method — no wire change; S2 corpus
   re-verified 69/69). The generator's original design leaned on `isKindOf:` at each call site
   inconsistently; making the sentinel test polymorphic on the value base is the idiomatic
   Smalltalk fix and removes a whole class of latent DNUs. **This is a real generator-robustness
   finding for the pure-object substrate:** an in-band sentinel (A-ST-007) must answer the
   sentinel predicate polymorphically across the WHOLE value hierarchy, or a "distinguished
   object, not nil" discipline still faults at the first non-sentinel it meets.
2. **Live-image single-doit temp-decl constraint bit the DRIVERS** (A-ST-010, re-confirmed).
   `s3-selftest.st` / `smoke.st` originally interleaved `| x |` temp declarations after
   statements at the TOP level → an `OpalCompiler>>parse` failure (a doit compiles as one
   method). Fixed by hoisting ALL top-level temps to the leading declaration (block-local
   `| x |` inside a `[...]` stays legal). Banked for every future driver.
3. **The non-interactive transcript has no `#show:`/`#showln:`** (A-ST-006, re-confirmed on the
   driver side). The drivers first used `Transcript show:` → DNU. Fixed to the proven S2 idiom:
   build a result String in a `WriteStream` and emit via `Stdio stdout` + return the value.

No dispatch-logic, N5, depth-pre-check, or demux bug survived to the gate: those were correct
on the first green run once the DNU (#1) was fixed — a strong signal the value-object peer
model maps the §3/§5/§6 shapes cleanly.

## v7.75 non-functional substrate floor — CONFIRMED implemented + live-verified

- **§4.10(b) chain-depth pre-check → 400 `chain_depth_exceeded`** (NOT 403), BEFORE the
  per-link authz walk. `EcCapability>>exceedsDepth:in:` (structural parent-walk, no signature),
  default max 64; an *unreachable* parent stays 403 (returns false). Selftest: deep-70 →
  exceeds; root → within; unreachable-parent → NOT depth. The verdict maps to 400 at the
  boundary.
- **§4.10(a) payload bound → 413/drain-and-keep** on the length prefix BEFORE buffering the
  body. `EcConnection>>readFrame` checks `len > EcNet maxFrame` (16 MiB) and `drain:`s the
  body, keeping the connection. Live-verified: a 17-MiB prefix drains + the peer keeps serving.
- **§4.9 resilience — deliver-or-signal, never silently drop.** `handleExecute:` catches every
  `EntityCoreError` → a 500 coded response; `serveConn:` swallows a malformed-frame THROW and
  keeps serving. Live-verified: after a bad-root close AND after an oversize drain, a fresh
  handshake still returns 200.
- **§7b TCP_NODELAY** set on every accepted/dialed socket (`EcNet>>nodelay:`, verified
  `getOption: 'TCP_NODELAY'` → 1). **Non-blocking cooperative loop:** every read is gated by a
  bounded `waitForDataFor:`/`dataAvailable` readiness test; the serve tick's bounded
  `waitForAcceptFor:` is the cooperative-yield point — no indefinite block on the single green
  process (the §7b existential rule for a single-event-loop substrate).
- **N5–N8 enforced at design time:** N5 (envelope `included` byte-key + key==content_hash both
  sides — selftest + live), N6 (inbound-concurrent-with-outbound via the serve-tick reentry),
  N7 (reentrant transport + request_id demux — smoke pipeline + selftest table), N8 (verdict
  determinism — pure `EcCapability` class methods, no shared mutable state).

## The A-ST-000 verdict (the probe's payoff) — idiomatic, not translated

The peer reads as native Smalltalk. Dispatch is message-sends and polymorphism, NOT a
procedural type-switch: the §3.3 frame router is `root type = EcWire typeExecute ifTrue: […]`;
a handler is a **block** bound in a Dictionary and invoked `block value: ctx` (the §6.13
extension boundary as a first-class object); the §6.6 resolution is a `whileTrue:` prefix walk;
the value builders are `EcVal map: { 'k' -> value }` cascades; the entity is an OBJECT with
memoized state, not an (addr,len) byte span (contrast Forth's stack-machine rep). The demux is
a Dictionary keyed by request_id — the A-FT-025 stale-index cross-talk hazard is structurally
IMPOSSIBLE here (distinct ids are distinct keys), a genuine substrate win over the array-index
peers. No "Smalltalk-flavored C" giant case-method appeared in the peer layer.

## What S4 needs to know

- **The peer image** is `make image` (load `src/*.st` per `load.st` srcFiles + snapshot);
  the S3 peer packages are in the srcFiles list. S4 conformance loads ON the same image.
- **Boot:** `bin/peer.st` reads EC_PEER_PORT / EC_PEER_SEED / EC_PEER_NAME from the ENV (a
  headless `eval` appends argv to the source, so options travel via env — the S2 A-ST note).
  `EcPeer loadSeedForName:` reads `~/.entity/peers/NAME/keypair` (base64 of a 32-byte seed) for
  `--name` interop. Prints `LISTENING <port>`, then `serveForever`.
- **Capability interior is S3-SCAFFOLD only.** `EcCapability` has the depth pre-check + the
  authn/authz verdict scaffold + the trichotomy, but NOT the full §5.5 chain walk (per-link
  signature, attenuation subset, multisig M3/M4/M6, §5.7 caveats, §5.1 revocation) — that is
  S4 (study forth `src/capauthz.fs` for the converged logic to port as native Smalltalk).
  `verifyAuthz:` currently allows once the token resolves + grantee is resolvable; S4 adds the
  chain verification + grantee==author binding + scope matching.
- **Handlers are S3-minimal.** Only `system/protocol/connect` (full §4.1) + `system/tree`
  (get only) are registered. S4 adds tree put/listing, system/capability
  (request/configure/revoke/delegate), system/handler (register/unregister), system/type, the
  §6.2 handler-manifest publishing, and — under a `--validate` flag — the system/validate/*
  conformance handlers (study forth `src/handlers.fs` + `src/peer.fs` `peer-bootstrap`).
- **The §6.11 reentry pump** (`EcPeer>>dispatchOutbound:envelope:on:`) is built + depth-capped
  but NOT yet exercised by a handler (no dispatch-outbound handler at S3 — that's the §7a
  reference-peer-gated validate handler, S4). The plumbing (open a pending record, send, serve
  ticks until correlated, close) is ready.
- **Store safety is structural** (single-event-loop); the store is Dictionary-backed and
  touched only from the one serve process. If S4 introduces any true concurrency it must
  re-examine this (it should not — the profile is single-event-loop).

## Exit criteria — MET

Smoke 6/6 + selftest 25/25 + peer loads cleanly + S2 69/69 preserved + idiom review green.
The v7.75 floor (400 chain-depth, 413 payload, TCP_NODELAY, non-blocking loop, deliver-or-
signal) is implemented AND live-verified. Ready for S4 (conformance).
