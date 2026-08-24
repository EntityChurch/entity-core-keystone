# entity-core-protocol-nim — Phase S3 summary

**Phase:** S3 (peer machinery)
**Date:** 2026-07-12
**Spec surface:** v0.8.0 / V8 (`protocol-generator/shared/spec-data/v0.8.0/`)
**Exit status:** ✅ S3 complete — **smoke runner 7/7 PASS, 0 FAIL**; peer compiles
clean (`nim c --mm:orc --overflowChecks:on -d:release`); host binary builds; S2
codec still 71/71 (no regression). One spec finding surfaced (A-NIM-009).

## Smoke gate result (`src/smoke.nim`, `run-smoke.sh`)

Two Nim peers over real loopback TCP, full machinery (asyncdispatch event loop +
framing + dispatch + capability handshake):

| Leg | Result |
|---|---|
| Handshake A → B — hello + authenticate → session, capability granted (§4.1 legs 1-2) | **PASS** |
| Handshake A → B — remote peer_id matches responder | **PASS** |
| Unknown handler on an **authenticated** conn → **404** `handler_not_found` (resolved-then-missed) | **PASS** |
| `request_id` demux — **8/8** concurrent in-flight EXECUTEs each correlate by request_id (§6.11(b)) | **PASS** |
| Handshake **B → A** (symmetric/other direction) → session established | **PASS** |
| Handshake B → A — remote peer_id matches responder | **PASS** |
| **F31** — unknown handler on an **UNAUTHENTICATED** conn → **401** (auth-before-resolve; NOT 404) | **PASS** |

"Both directions" is literal: each peer both listens and dials the other; two
independent sessions establish. §4.1 leg 3 (reverse `authenticate`) is deferred per
the spec — a client-style initiator completes via legs 1-2 alone.

## Unknown-handler status — the two correct answers, both exercised

- **Authenticated → 404** `handler_not_found`. §6.5 verifies the request, resolves
  the handler via the §6.6 longest-prefix tree walk, misses → 404.
- **Unauthenticated → 401** `authentication_failed` (F31 / auth-before-resolve). §6.5
  runs `verify_request` (§5.2) BEFORE resolving the handler, so an unauthenticated
  request fails at auth and **never reaches the resolve step** — it MUST NOT leak 404.
  This is the F31 fix baked into dispatch ORDER, plus the §5.2a auth-class (401) row.

## §7b store-safety — realized structurally (no lock)

The peer runs a **single-threaded `asyncdispatch` cooperative event loop** (profile
`[async] style = event-loop`, A-NIM-006). §4.8/§7b store-safety is therefore **by
construction**: the store is a plain `std/tables Table` (`src/store.nim`) mutated only
by the one event thread — there is no concurrent writer, hence no data race, hence
**no mutex, no atomics** (the PHP/Tcl/Dart event-loop class, not the raw-thread
RW-lock/sharded class). §6.11 handler-outbound reentry is ~free: an outbound dispatch
is another loop turn; the reply arrives as a readable `Future` matched by request_id
from the one loop's pending `Table`. The reader dispatches each inbound EXECUTE via
`asyncCheck` and immediately loops (§4.8: inbound processing never blocks on a
handler's outbound). Writes are serialized by a small async mutex so two concurrent
`asyncCheck` responses cannot interleave bytes if a `send` yields.

## What was built (`src/`, peer machinery on the S2 codec)

| Module | Role |
|---|---|
| `model.nim` | `Entity {type,data,content_hash}` + `Envelope {root,included}` on the S2 `EcValue`; validate-before-trust (recompute + check `content_hash`, §1.8/§5.2); lowercase hex tree-path segments |
| `store.nim` | content store + tree index — plain `Table`s, structurally race-free under the single event thread (§4.8/§7b) |
| `identity.nim` | Ed25519 identity from seed; canonical §1.5 identity-multihash peer_id; `system/peer` entity; sign/verify over the 33-byte content_hash (§4.6) |
| `wire.nim` | the two L2 message builders (§3.2 EXECUTE, §3.3 EXECUTE_RESPONSE) + `system/protocol/error` result |
| `peer.nim` | §6.5 dispatch chain (auth-BEFORE-resolve), §4.1 connect responder (hello/authenticate PoP: nonce-echo + signature + identity-binding), §4.4 capability mint+sign, §4.10(b) chain-depth pre-check, §6.5 signature ingestion, §6.6 longest-prefix resolution, §6.9 bootstrap |
| `transport.nim` | asyncnet framing (4-byte BE length + ECF, §1.6), §4.10(a) 16 MiB inbound cap, §6.11 `request_id` pending-table demux, reader loop (§4.8), §4.1 initiator handshake + `Session.execute` (§5.8 chain in `included`), TCP_NODELAY (§7b) |
| `host.nim` | standalone peer host — `--port` / `--name NAME` (PEM keypair at `~/.entity/peers/NAME/keypair`) / `--validate` / `--debug-open-grants`; `LISTENING …` readiness line; `runForever` |
| `smoke.nim` | the S3 smoke gate (above) |

## §5.2a verdict-to-status split (baked in at design time, per the pinned N5–N8 + v7.75 floor)

`verify_request` (`peer.nim`) maps each DENY surface to the §5.2a tuple: auth-class
(author/signature absent or bad) → **401**; authz-class (capability absent / grantee ≠
author) → **403**; over-deep chain → **400** `chain_depth_exceeded` (structural, checked
BEFORE the per-link authz walk, §4.10(b)); the `unresolvable_grantee` carve-out → 401.
The §4.10(a) 16 MiB inbound frame bound and §4.10(b) depth pre-check are present in the
substrate (not rediscovered at S4).

## Spec finding — A-NIM-009 (§4.2 403 vs §5.2a 401)

§4.2 bullet 3 says a non-connect EXECUTE without auth fields is rejected with **403**;
the newer §5.2a (v7.73) "Author absent → **401** auth-class" row says 401. They
disagree on the number a fresh reader emits. Followed §5.2a (401) — the more specific,
authoritative-on-the-tuple section, and exactly the F31 invariant, confirmed live by the
smoke. Logged for arch to reconcile §4.2 with the §5.2a auth/authz split. Non-blocking.

## Scope boundary — what is S4, not S3

The extension-free **handler bodies** (`system/tree:get`, `system/capability:request`,
`system/handler:register`/`unregister`, `system/type`) return an honest `501
no_handler_body` once resolved — the §6.5 chain up to and including resolution is wired,
the bodies + `check_permission` scope-matching + the §7a `--validate` handlers + the
`run-s4.sh` oracle harness land at **S4**. The smoke gate (handshake / unknown-status /
demux) does not reach a resolved-handler body, so it is fully green now. The capability
verification is a faithful **1-link root-cap** check (author signature + grantee binding
+ depth pre-check); multi-link chain-walk hardening is S4.

## Boundaries honored

Wrote ONLY under `protocol-generator/nim/`. Did NOT touch `CONFORMANCE-MATRIX.md`,
`research/`, `docs/status/*`, spec-data, the corpus, or the oracles. No git writes —
tree left dirty for the overseer to DCO-sign-commit.
