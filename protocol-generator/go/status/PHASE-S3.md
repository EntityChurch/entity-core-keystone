# entity-core-protocol-go — Phase S3 (Peer machinery) Summary

**Peer: Go (clean-room)** · **Status: COMPLETE — two-peer
loopback smoke GREEN (11/11 checks), peer builds clean (go build + go vet + gofmt
all green), S2 codec regression unbroken (69/69 + all unit tests).**

Go is the reference oracle's language (`entity-core-go`); this peer's entire value
is being an INDEPENDENT reimplementation from the spec + the shared lifecycle
contracts + language-neutral sibling peers. **No source under `entity-core-go` was
opened, grepped, or referenced while building S3.** The cross-language blueprint
followed was the Common-Lisp peer (peer #5, native + spec-first), translated into
Go idiom — not the oracle.

## Gate result — the two-peer loopback (11/11 GREEN)

Two Go peers talk over real loopback TCP through the full §6.5 dispatch chain. Run
offline (`--network=none`, 127.0.0.1 loopback only) in the `go` toolchain container
via `go test ./peer/ -run TestSmokeLoopback`:

```
Scenario 1 — core ops (responder = default seed policy):
  [PASS] session established (capability minted)        (§4.1 handshake)
  [PASS] remote peer_id matches responder               (§4.6 identity binding)
  [PASS] unregistered path -> 404                        (§6.6 no handler resolved)
  [PASS] granted tree get -> 200                         (§4.4 discovery floor authority)
  [PASS] tree get returns a system/handler/interface entity
  [PASS] capability request -> 200                       (§6.2 mint-bounded)
  [PASS] 8 interleaved requests each correlated -> 8/8   (N7 / §6.11 request_id demux)

Scenario 2 — Core Extensibility Boundary (responder = --debug-open-grants + --validate):
  [PASS] handler register -> 200 (live, not 501)         (§6.13(a) register live-hook)
  [PASS] emit hook fired on register's tree writes        (§6.13(c) emit live-hook)
  [PASS] §7a echo -> 200                                  (§7a resolve→dispatch)
  [PASS] §7a echo returns params verbatim
SMOKE: PASS (11/11)
```

The full `validate-peer --profile core` conformance run is S4; this smoke proves the
wire-level peer surface (transport + handshake + register/dispatch/emit + capability
gating + request_id demux) is wired end-to-end, leaving the peer S4-ready.

The §4.8 store-safety floor is met **structurally** by the `sync.RWMutex`-guarded
store (the profile-mandated design — reads RLock, writes Lock, consumers fired outside
the lock), exercised live by the concurrent 8-way demux check. NOTE: `go test -race`
could NOT be run in the `go` toolchain container — the race detector needs cgo (a C
compiler) and the minimal stdlib-only image ships no `gcc`/`cc` (CGO has no compiler to
invoke; the build hangs rather than linking). Running `-race` is an S4 item on a host
with a C toolchain, or via adding `gcc` to the container; it is NOT the S3 gate (the
11/11 loopback is), and the store safety is structural, not race-detector-dependent.

## What was built (`src/peer/`, package `peer`, on top of the S2 codec)

The peer machinery lives in its OWN package (`peer`) layered above the S2 codec
(package `entitycore` + `internal/{cbor,base58,varint}`), so the codec stays a clean
unit and the peer surface is the new S3 namespace. Zero new third-party modules
(`net` + `sync` + `crypto/ed25519` ship with the toolchain; `go.sum` stays empty —
[idiom].stdlib_only holds through S3).

| File | V7 layer | Responsibility |
|---|---|---|
| `model.go`      | foundation | materialized `Entity {type,data,content_hash}` on `cbor.Value` + `Envelope` (§3.1); fidelity-validating `EntityOfCbor`/`EnvelopeOfCbor` (§1.8/§3.1). `data` is an ARBITRARY ECF value, not a map (A-JAVA-010) — the field accessors degrade gracefully when it is not a map. |
| `cborx.go`      | — | small `cbor.Value` constructors for peer call sites (str/val lists, empty map). |
| `identity.go`   | L1 | seed → **§1.5 canonical peer_id (hash_type=0x00 raw pubkey)** / `system/peer` entity (v7.65, no peer_id in basis) / sign-entity (§3.5, §7.3) / verify-signature. |
| `store.go`      | foundation | content store (hash→entity, dedup) + entity tree (path→hash) + one-level listing (§1.7/§3.9) + the §6.10/§6.13(c) **emit bus** (live with zero consumers). **`sync.RWMutex`-guarded** (§4.8); consumers fired OUTSIDE the lock (no I/O under lock). |
| `wire.go`       | L2 | §1.6 framing (4-byte BE length ‖ CBOR envelope) with the **§4.10(a) 413 payload guard** (length-prefix check BEFORE buffering the body); EXECUTE / EXECUTE_RESPONSE / error / empty-params builders. |
| `capability.go` | L3 | §5.2 `verifyRequest` (4-way verdict), `checkPermission`, §5.4 patterns + `canonicalize` + §1.4 `normalizeURI`, §5.5 chain walk + §5.5a per-link granter frames, §5.6 attenuation, §5.7 caveats, §5.1 revocation, the **§4.10(b) `chainExceedsDepth` structural pre-check (depth 64 → 400 chain_depth_exceeded, BEFORE the authz walk)**. |
| `peer.go`       | L1–L4 | the four MUST handlers as a `pattern → handler` map, the §6.5 dispatch chain, §6.5 signature ingestion, §6.6 backward resolution, §6.9/§6.9a bootstrap helpers, per-connection state, §6.13(b) outbound seam. |
| `handlers.go`   | L1–L4 | the handler bodies: connect (hello/authenticate), tree (get/put), capability (request/delegate/revoke/configure), handlers (register/unregister), §7a echo + dispatch-outbound. |
| `bootstrap.go`  | L4 | `NewPeer` + the §6.9 bootstrap write-set (MUST-handler tree entities) + §6.9a peer-authority bootstrap (owner cap at the hex policy path + detached self-signature at the §3.5 pointer + default scope-template entry; open-grants selects [default → *]) + §7a handlers under `--validate`. |
| `transport.go`  | L4 | TCP listener + per-connection reader goroutine (`net` + `sync`), §6.11 `request_id → channel` demux, §4.8 inbound-on-own-goroutine, §6.13(b) reentry seam, write-serializing mutex, **`SetNoDelay(true)` (TCP_NODELAY) on every accepted/dialed conn**; the client dialer + initiator handshake that drives the loopback. |
| `smoke_test.go` | — | the two-peer loopback gate (11 checks, two scenarios). |
| `cmd/host/main.go` | — | standalone S4-ready host (`-port`, `-seed`, `-debug-open-grants`, `-validate`, prints `LISTENING <port>`). |

## Concurrency — goroutines + channels (profile [concurrency].style)

- **one reader goroutine per connection** (`transportIO.readLoop`) demuxes inbound
  frames (§6.11): an EXECUTE_RESPONSE routes to its awaiting outbound caller by
  `request_id` through a `map[string]chan Envelope` guarded by a mutex; an inbound
  EXECUTE is dispatched on **its own goroutine** (§4.8 / N6) so a handler that
  originates an outbound EXECUTE (§6.13(b)) and awaits its response does NOT block
  the reader;
- **writes** (inbound responses + outbound requests share the stream) are serialized
  by a per-conn `sync.Mutex`;
- the §6.13(b) outbound primitive (`transportIO.outbound`) registers a response
  channel under the pending mutex, writes the request, and blocks on the channel;
  `closeIO` closes all pending channels so a waiter is woken on connection close
  (returns ok=false, never hangs);
- the **8-way request_id demux** check is the N7 proof: 8 EXECUTEs issued concurrently
  from 8 goroutines each correlate to their own response (the store is RWMutex-guarded,
  so the concurrent dispatch is data-race-safe by construction).

## Pre-resolved cohort traps — baked in from S3, not rediscovered

These are the v7.75 §9.1 floor items the 9-peer cohort each hit; the Go peer starts
with them wired (profile-mandated, recorded in PROFILE-RATIONALE + the ambiguity log
as settled readings, not open guesses):

- **§4.8 store data-race safety** — `sync.RWMutex` over both store maps; reads (resolve
  / listing) take RLock, writes (bind / put) take Lock; emit consumers fire OUTSIDE
  the lock; the concurrent 8-way demux exercises it live. (Zig + Common-Lisp shipped
  unsynchronized stores that fell over under the §7b T2.1 probe — Go has no race
  window from day one.)
- **§7b TCP_NODELAY** — `(*net.TCPConn).SetNoDelay(true)` on every accepted AND dialed
  connection (the Zig Nagle-killer: Nagle+delayed-ACK on small req/resp frames was the
  throughput killer). Set in `newTransportIO`.
- **§4.10(a) finite max inbound payload** — `ReadFrame` rejects a length prefix
  exceeding `MaxFrame` (16 MiB) **before** allocating the body buffer → 413
  payload_too_large; the peer keeps serving other connections after the rejection.
- **§4.10(b) finite max chain depth** — `chainExceedsDepth` is a structural pre-check
  that walks parent pointers counting depth (max 64), gated **BEFORE** the per-link
  authz walk in `verifyRequest`; over-depth → **400 chain_depth_exceeded** (structural
  excess), distinct from 403 capability_denied. An *unreachable* parent is NOT a depth
  problem — it returns false and is left for the chain walk to deny (403). This was the
  only net-new peer code across the whole v7.75 cohort; wired in S3 so S4 resource_bounds
  passes without rework.
- **peer_id §1.5 hash_type=0x00 raw pubkey** — `PeerIDFromPublicKey` (added to the S2
  `peerid.go`) derives Ed25519 peer_id as `(key_type=0x01, hash_type=0x00, raw 32-byte
  pubkey)` per the §1.5 canonical-form table + size-cutoff rule, NOT the stale §7.4
  SHA256(pubkey) skeleton (which fails the handshake).
- **§5.2 401/403/401-unresolvable trichotomy** — `verifyRequest` returns a 4-way
  Verdict (Allow / AuthnFail→401 / AuthzDeny→403 / UnresolvableGrantee→401 +
  ChainTooDeep→400). See A-GO-006 below — the Go peer independently lands on the same
  trichotomy the spec-first cohort flagged (A-ZIG-006 / A-OC-008 / A-SW-010 / A-CL).

## Idiom — reads as Go, not transpiled

- **Explicit `(T, error)` / `(T, bool)` returns** everywhere on the surface; no
  exceptions for protocol flow. The handler outcome is a value (`outcome{status,
  result, included}`), mapped to a status code at the dispatch boundary.
- **Method-table single dispatch** — each handler is a small struct implementing
  `handleOp(op string, ctx *dispatchCtx) outcome` with an internal `switch op` ladder;
  unknown op → 501. (The idiomatic Go shape; contrast the Common-Lisp peer's CLOS
  multiple dispatch over the same §6.6 surface — both land on byte/behaviour-identical
  dispatch, mild corroboration the §6.6 surface is idiom-neutral.)
- **goroutines + channels** for concurrency (not threads/Task/actor); `request_id →
  chan Envelope` is the §6.11 demux.
- **`recover()` at the goroutine boundary** so one adversarial request never crashes the
  peer (§4.9 no-crash); a panicking dispatch returns a 500 internal_error response.
- **gofmt + go vet clean** is a hard gate (the Go community floor) — both green.
- Go naming: `PascalCase` exported (PeerID, Entity, Envelope), `camelCase` unexported,
  initialisms all-caps (PeerID, ECF, TCP).

## Pinned conformance invariants (N5–N8) — enforced at design time

- **N5 (envelope `included` preservation)** — entities round-trip through
  `EntityOfCbor`/`ToCbor` with content_hash fidelity (§1.8); the §3.1 included-key ==
  content_hash check is enforced on parse (`EnvelopeOfCbor`).
- **N6 (inbound concurrent with outbound dispatch)** — each inbound EXECUTE dispatches
  on its own goroutine; the reader keeps reading (§4.8).
- **N7 (reentrant transport + request_id demux)** — the mutex-guarded `request_id → chan`
  table; verified by the 8-way demux check (RWMutex-guarded store, race-safe by design).
- **N8 (capability verdict determinism)** — `verifyRequest` is a pure function of
  (envelope, store); §5.10 Layer-1 bare verdict, no nondeterminism.

## Dev loop

```
# the two-peer loopback smoke gate + S2 regression (container-bound, offline):
podman run --rm --network=none -v $PWD:/work:Z -w /work/protocol-generator/go/src \
  entity-core-keystone/go:latest go test ./...

# (go test -race needs a C compiler for cgo; the minimal container ships none,
#  so race-check on a host with gcc — store safety is structural via sync.RWMutex)

# the standalone host (S4-ready):
... go run ./cmd/host -port 0 -validate
```

## Exit criteria

Two-peer loopback smoke GREEN (11/11) · peer builds clean (go build + go vet + gofmt
all green) · reads as Go (method-table dispatch + goroutines/channels + explicit
errors, not transpiled) · S2 codec regression unbroken (69/69 + all unit tests) ·
store data-race-safe by construction (sync.RWMutex) · container reproducible (`--network=none`, stdlib-only) · ambiguity log
updated (A-GO-006 §5.2 trichotomy convergence recorded). **S3 PASS.**

## Not in this phase (S4, next session)

- `validate-peer --profile core` conformance run against the Go oracle (commit
  `75c532e`, recorded in the profile) — the live superset of this smoke.
- The full §9.5 53-core-type registry publish (`system/type/*`) — S3 seeds only the
  MUST-handler tree entities; S4 needs the full type registry for the `type_system`
  oracle category.
- The full crypto-agility matrix wiring (Ed448 deferred per A-GO-002 — native gap).
