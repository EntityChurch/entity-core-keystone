# entity-core-protocol-forth — Phase S3 summary (COMPLETE)

**Phase:** S3 (peer machinery — core Layers 1–4 + foundation)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/forth-toolchain:latest` (gforth 0.7.3, fedora:43)
**Status:** COMPLETE — the S3 gate is green, container-bound + sealed-offline
(`--network=none`):

- **Foundation self-test 20/20** (`test/s3-selftest.fs`) — identity, store, N5 envelope,
  the §4.10(a)/(b) floor, wire builders.
- **Two-peer loopback smoke 6/6** (`test/smoke.sh` → responder `bin/peer.fs` + initiator
  `test/smoke.fs`, two real processes over 127.0.0.1).
- S2 codec unaffected: **69/69** + int-boundary + crypto-accept still green.

**Reproduce:** `./run-s3.sh` (= `make s3`: selftest 20/20 + smoke 6/6). Sub-targets:
`./run-s3.sh selftest`, `./run-s3.sh smoke`.

## The transport verdict (A-FT-008/A-FT-015 — the headline)

gforth has GENUINE in-process BSD sockets (raw `socket`/`bind`/`listen`/`accept`/`recv`/`send`/
`select` bound via `libcc`) AND genuine in-process libffi crypto (A-FT-005). So — unlike the
Rexx precedent (#24), whose dead `rxfuncadd` + FIFO-corruption-under-subprocess forced an
`ecnet` C co-process daemon over two FIFOs — the Forth peer owns the sockets, the select()
loop, the §1.6 de-framing, the §4.10(a) 16-MiB cap, TCP_NODELAY, and the crypto ALL IN ONE
PROCESS. This is the COBOL/Tcl native-socket shape, not the Rexx daemon shape: no IPC, no FIFO,
no daemon. §4.8 store-safety is structural by construction (one interp, one frame dispatched to
completion per select wake — no lock, no race).

## Done — the peer modules (`src/`)

- **`net.fs`** — the transport: a `libcc c-library` binding the raw socket syscalls + a static
  `fd_set` shim (`FD_ZERO`/`FD_SET`/`FD_ISSET`) + `select()` (timeval passed as `(sec,usec)`);
  `net-listen`/`net-dial`/`net-accept`; framed I/O (`net-read-frame`/`frame-out`, 4-byte BE
  length prefix); the **§4.10(a) 16-MiB cap** enforced on the length prefix BEFORE buffering
  (over-limit → drain-and-keep the connection, a 413-class de-framer rejection, §4.9); TCP_NODELAY
  on every accepted/dialed socket; the `net-select` event primitive over listen + all conns.
- **`store.fs`** — the foundation store: a content-addressed Content Store (§1.1) + an Entity
  Tree (§6.3) in a DURABLE bump heap (the per-op arena reset can't clobber it). §4.8 structural.
- **`identity.fs`** — L1: seed→pubkey→peer_id (§1.5 identity-multihash), the `system/peer`
  entity {public_key, key_type} (§3.5 — no peer_id in the basis), id_hash, `system/signature`
  {target, signer, algorithm, signature} (§3.5), sign/verify.
- **`entity.fs`** — a materialized entity {type, data, content_hash} as a self-delimiting arena
  byte record; `ent->wire`/`ent<-wire` with §1.8 hash-fidelity re-validation.
- **`envelope.fs`** — the §3.1 envelope {root, included} with a BYTE-keyed included map,
  key==content_hash invariant, first-seen dedup (N5, both encode + decode sides).
- **`wire.fs`** — §3.2 EXECUTE / §3.3 EXECUTE_RESPONSE / `system/protocol/error` builders (the
  ONLY two wire roots; any other root closes the connection).
- **`capability.fs`** — L3: the `system/capability/token` shape, the trichotomy verdict split
  into `cap-verify-authn` (signature) + `cap-verify-authz` (chain/depth/grantee), and — the ONE
  net-new bit across the cohort — the **§4.10(b) chain-depth pre-check** `cap-exceeds-depth`
  (→ 400 chain_depth_exceeded, BEFORE the per-link authz walk; an unreachable parent is NOT a
  depth problem and stays 403).
- **`handlers.fs`** — the connect handshake (`hnd-connect` hello/authenticate, §4.1: nonce echo,
  proof-of-possession, identity binding, then a root seed grant), the handler registry
  (`register-handler`/`unregister-handler`/`resolve-handler` §6.6 longest-prefix tree-walk,
  §6.13(a) peer-owner-write), the seed-grant `mint-seed-token`.
- **`dispatch.fs`** — the §6.5 dispatch chain (AUTHN → resolve/404 → AUTHZ/403 → dispatch, the
  §6.6 resolution-first ordering, A-FT-016), the §6.11 **request_id demux** (pending-reply table)
  + the manual **reentry pump** (`dispatch-outbound` sends + `await-reply` re-enters the select
  pump keeping other frames served until the correlated reply arrives), the single-thread select
  serve loop.
- **`peer.fs`** — assembly: `peer-bootstrap` (install identity, register the MUST handlers),
  `peer-listen`, `peer-serve`.
- **`b64.fs`** — RFC-4648 base64 decode (the keypair PEM seed).
- **`bin/peer.fs`** — the CLI: `--name NAME` (loads `~/.entity/peers/NAME/keypair`), `--seed HH`,
  `--port N` (0=ephemeral), `--validate` (off by default), `--debug-open-grants` (no-op at S3);
  prints `LISTENING <port>` then serves. Matches the cohort convention.

## Smoke result — 6/6 (the gate)

Two Forth processes, 127.0.0.1 loopback, `--network=none`:

| # | Check | Result |
|---|---|---|
| 1 | connect:hello → 200, responder hello | ok |
| 2 | responder issued a nonce | ok |
| 3 | connect:authenticate → 200 (system/capability/grant) | ok |
| 4 | grant carries a capability token | ok |
| 5 | EXECUTE unregistered path → **404** handler_not_found (resolution-first) | ok |
| 6 | pipelined replies correlate by **request_id** (§6.11 demux, out-of-order) | ok |

3 EXECUTE + 3 EXECUTE_RESPONSE handshake completes both directions; the request_id demux is
proven by pipelining two EXECUTEs before reading either reply and matching each reply to its
sent request_id (order-independent).

## N5–N8 + the §4.10 floor — what was built in and how tested

- **N5 (envelope `included` preservation, request + result side):** byte-keyed included map,
  key==content_hash invariant, first-seen dedup — `env->wire`/`env<-wire` (`envelope.fs`).
  Tested: selftest `N5:` (dedup collapses a duplicate; round-trip preserves; key==content_hash),
  and live in the smoke (authenticate carries token+granter+signature in `included`).
- **N6 (inbound concurrent with outbound dispatch, §4.8):** structural — the select loop keeps
  serving inbound frames while `await-reply` awaits an outbound reply (the reentry pump never
  blocks the loop). §4.8 store-safety structural (single thread).
- **N7 (reentrant transport + request_id demux, §6.11/§6.12):** the pending-reply table +
  `dispatch-outbound`/`await-reply` reentry pump; demux by request_id. Tested: smoke check #6
  (pipelined out-of-order correlation).
- **N8 (capability verdict determinism, §5.10):** the verdict is a pure function of the chain +
  included set (`cap-verify-authn`/`cap-verify-authz`), no wall-clock/random in the verdict path.
- **§4.10(a) 16-MiB → 413/drain:** `net-read-frame` checks the length prefix BEFORE buffering;
  over-limit drains-and-keeps (never a silent close, §4.9). Tested: selftest `4.10(a):`
  (MAX-FRAME finite = 16 MiB; the oversize classifier predicate).
- **§4.10(b) chain-depth → 400 chain_depth_exceeded (BEFORE the authz walk):** `cap-exceeds-depth`
  at the dispatch site, mapped to 400 (structural, not 403); an unreachable parent stays 403.
  Tested: selftest `4.10(b):` (70-deep chain flagged; root within depth; unreachable parent NOT
  a depth problem).
- **A-RX-014 baked in:** the peer verifies request/authenticate signatures straight from
  `env.included`, and only caches signer PEER identities — it never persists the per-request
  `system/signature` entities (the unbounded-growth / §4.9 exhaustion vector Rexx surfaced).

## §6.11 reentry-pump mechanism + request_id demux (how verified)

`dispatch-outbound (conn exec arr lens nvar)` parks a pending request_id (`pend-new`), sends the
outbound EXECUTE, then `await-reply` RE-ENTERS a bounded `pump-once` select loop — keeping every
other inbound frame served — until `on-frame` correlates the reply (a `system/protocol/execute/
response` root) to the parked request_id and flips its done flag. No thread; the correlation-map
tax. **Verified** by the smoke's pipelined-reply check: two EXECUTEs sent before either reply is
read, each reply matched to its sent request_id order-independently (6/6). The `system/validate/
dispatch-outbound` conformance HANDLER that drives this from the Go oracle is S4 scope — see
`run-origination-core.sh` (honest-SKIP at S3, mechanism built + unit-proven).

## Compiles / loads cleanly under gforth

`gforth src/peer-all.fs` (the peer umbrella: S2 codec + every S3 module) loads clean;
`bin/peer.fs --port 0 --seed 11` boots and prints `LISTENING <port>`. No compile-gate (gforth is
incrementally compiled, no static types — the dynamic caveat, sharpest on this typeless
substrate; correctness rests on the corpus + selftest + smoke).

## The stack-machine idiom verdict (the peer layer)

**The select loop + reentry pump read as native Forth.** The single-thread select loop is a
plain `begin … pump-once … repeat` over a fd table; the reentry pump is `dispatch-outbound` +
`await-reply` composing on the data stack with `(addr,len)` spans and locals — no deep dup/roll
gymnastics. Connections/pending-replies/handlers are parallel arrays indexed by a small integer
(the Forth "struct" idiom), consistent with the codec's arena/TV model. The stack substrate cost
appears only where a word returns two values into a two-name local (`{ a b }` binds in STACK
order, A-FT-012) and where an append-and-return word is mistakenly re-`bytes,`'d (A-FT-014) — both
are idiom-discipline gotchas, not translated-code smells. **Verdict: the peer layer is idiomatic
Forth, corroborating the A-FT-000 generator-stress question down through the transport layer.**

## New ambiguities / escalation

Five S3 entries appended to `status/SPEC-AMBIGUITY-LOG.md`, all **operator-RESOLVED, no spec
bearing** (durable Forth-substrate lessons): A-FT-012 (locals bind in stack order), A-FT-013
(bump-heap pointer advance), A-FT-014 (append-word double-write), A-FT-015 (in-process
transport obviates the Rexx daemon), A-FT-016 (§6.6 resolution-first 404-beats-403 — confirms
the spec is precise; the finding is the ordering discipline, not an ambiguity). No fresh spec
DEFECT surfaced (corroboration, as expected on the saturated wire surface).

## S3 exit criteria

- [x] `src/` peer modules per the profile `[layout]` (identity, capability, store, dispatch,
      transport, reentry pump, handler registry, `bin/peer` entry).
- [x] smoke runner + `run-s3.sh` (container-bound) + `run-origination-core.sh` (split, honest-SKIP).
- [x] smoke green (6/6) + foundation self-test green (20/20); peer compiles/loads cleanly.
- [x] N5–N8 + the §4.10(a)/(b) floor built in AND tested (not deferred to S4).
- [x] idiom review done — the select loop + reentry pump read as native Forth.
- [x] `status/PHASE-S3.md` (this file) + `status/SPEC-AMBIGUITY-LOG.md` updated.
