# entity-core-protocol-c — Phase S3 (Peer machinery) Summary

**Peer #10** (C / C11 / POSIX — procedural / manual-memory /
return-code idiom; the last untried memory axis) · **Status: COMPLETE — two-C-peer
loopback smoke GREEN (11/11), compiles `-Werror` clean, ASan/LSan/UBSan-clean through the
full smoke run, S2 codec regression unbroken (69/69 + selftests = 82/82).**

## Gate result — the two-peer loopback (the cohort baseline, 11/11)

Two C peers talk over real loopback TCP through the full §6.5 dispatch chain. Run offline
(`--network=none`, loopback only) via `./run-s3.sh`, built + run under ASan/LSan/UBSan:

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

Matches the Java + Common Lisp + Zig cohort precedent (11/11, the same two scenarios). The
full `validate-peer --profile core` conformance run is S4; this smoke proves the
wire-level peer surface (transport + handshake + register/dispatch/emit + capability
gating + request_id demux) is wired end to end, leaving the peer S4-ready.

The gate is `test/smoke.c`, container-bound and sealed-offline; `./run-s3.sh all` also
re-runs the S2 codec regression. `make` compiles every source `-std=c11 -pedantic -Wall
-Wextra -Werror` with **zero warnings**.

## peer_id byte-cross-check (the decisive S4-readiness signal)

The C responder derives peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` from
seed `0x11` — **byte-identical to the Java + Common Lisp cohort** (and the cohort peer_id
convergence). The Base58 prefix decodes to `(key_type=0x01 Ed25519, hash_type=0x00
identity-multihash, 32-byte digest)` — the **§1.5 canonical form** (A-C P1 / A-JAVA-004),
NOT the stale §7.4 SHA-256 form. The handshake's step-3 identity binding
(`peer_id == derive(public_key)`) is therefore correct now, so the S4 `authenticate` leg
is clean.

## Go reference peer / oracle provenance (the S2/S3 vendoring mandate)

- **The S3 gate is the two-C-peer loopback** (cohort baseline; same shape as Java/Zig/CL
  SmokeTest). It boots a RESPONDER and an INITIATOR — **both native C peers** — and does
  NOT require the Go reference peer at runtime; the Go `entity-peer`/`validate-peer`
  black-box interop is the **S4** `validate-peer --profile core` concern.
- **Go oracle state at S3 (read-only, vendor/read-only — NOT modified):** at S2 the oracle
  was clean at HEAD `7e5ab0428a63eb78b981a2000a90e5d4c85e7c79`. At S3 run-time its HEAD has
  advanced to `57dd0a09ec9371a6b1f04ed57832d46d875d8a35` (`57dd0a0`, "relay R1: entity
  types per EXTENSION-RELAY v1.0") and the working tree carries one uncommitted edit
  (`core/types/relay.go` — a RELAY *extension* file, NOT `core/ecf` / `validate-peer` /
  `entity-peer`). This is recorded honestly in `status/SPEC-AMBIGUITY-LOG.md` (A-C-008):
  the live `validate-peer` rebuild + run binds a clean oracle commit the orchestrator
  pins at S4; it does not affect the S3 two-C-peer gate (no doctoring — the C code is the
  thing under test here; the oracle is the S4 ground truth).

## What was built (`protocol-generator/c/src/`, on top of the S2 codec)

The peer machinery layers above the S2 codec (`ecf.c` / `content_hash.c` / `peer_id.c` /
`crypto.c` / `base58.c` / `varint.c`). One new public-ABI addition: `ec_value_clone`
(deep-copy, needed when an entity's `data` is reused across builders). ZERO new
third-party deps — libsodium (already pinned at S2) + POSIX pthreads/sockets are the whole
surface.

| File | V7 layer | Responsibility |
|---|---|---|
| `src/peer_internal.h`  | — | the internal peer types (refcounted `ec_entity`, `ec_envelope`, `ec_store`, `ec_identity`, `ec_conn`, `ec_peer`) + cross-module API |
| `src/entity.c`         | foundation | materialized `{type,data,content_hash}` (§1.1/§3.4) + the §1.8 fidelity-validating `ec_entity_of_cbor`; the value/field-read helpers (the Cbor.java analogue) + **lowercase hex** (`ec_hex`, A-CL-009); the §3.1 envelope (incl. the §3.1 included-key == content_hash check on parse, N5) |
| `src/store.c`          | foundation | content store (hash→entity) + entity tree (path→hash) + one-level §3.9 listing + the §6.13(c) emit bus (live with zero consumers); **`pthread_rwlock_t`-guarded** (§4.8 data-race safety, N6) |
| `src/identity.c`       | L1 | seed → §1.5 identity-multihash peer_id (A-C P1) / `system/peer` entity / sign (§3.5) / verify |
| `src/capability.c` (+`.h`) | L3 | §5.2 `verify_request` (3-way verdict + the §5.5 unresolvable→401 carve-out), `check_permission`, §5.4 patterns + `canonicalize` + §1.4 `normalize_uri`, §5.5 chain walk, §5.6 attenuation, §5.7 caveats, §5.1 revocation, the §PR-8 granter-frame; **the §4.10(b) `ec_cap_chain_exceeds_depth` structural pre-check** |
| `src/wire.c` (+`.h`)   | L2 | the §3.2 EXECUTE / §3.3 EXECUTE_RESPONSE builders + error result + empty-params (§3.2 `0xA0`) + resource-target; `EC_MAX_FRAME` (16 MiB) |
| `src/dispatch.c`       | L1–L4 | the peer brain: the four MUST handlers (connect/tree/handler/capability) as **operation-`switch` functions** (the procedural single-dispatch ladder), the §6.5 dispatch chain, §6.5 signature ingestion, §6.6 backward resolution, §6.9 bootstrap, §6.9a peer-authority bootstrap, the §7a conformance handlers, the §6.13(b) outbound seam |
| `src/transport.c` (+`.h`) | L4 | TCP listener/dialer + **one reader thread per connection** + the §6.11 `request_id` demux (a slot list + `pthread_cond_t`) + §4.8 inbound-on-its-own-dispatch-thread + the §6.13(b) reentry seam + a per-connection write mutex; the initiator dialer/handshake |
| `src/host.c`           | — | the standalone S4-ready host (`--port`, `--seed`, `--validate`, `--debug-open-grants`, the `LISTENING <port>` / `PEER_ID <id>` lines) |
| `test/smoke.c`         | — | the two-peer loopback gate (the two scenarios above) |

## Concurrency — POSIX pthreads (A-C-004 VALIDATED)

The axis S3 exercises that the codec (S2, pure/synchronous) did not. The peer is **one
reader thread per connection**, with each inbound EXECUTE dispatched on its **own thread**
(§4.8):

- the **accept loop** runs on its own thread; each accepted connection gets a **reader
  thread** (`reader_loop`) + a **reaper** thread that joins-then-frees the connection state
  (so every connection is deterministically reaped → **LSan-clean**, no detached leak);
- the reader demuxes inbound frames (§6.11): an `EXECUTE_RESPONSE` routes to its awaiting
  outbound caller by `request_id` through a slot list keyed on `request_id`, each slot a
  `pthread_cond_t` the outbound caller parks on; an inbound `EXECUTE` is dispatched on
  **its own thread** (§4.8) so a handler that originates an outbound (§6.13(b)) and awaits
  its response does NOT block the reader;
- writes (inbound responses + outbound requests share the stream) are serialized by a
  per-connection write mutex;
- **no blocking syscall on a cooperative pool**: each connection has its own thread, so a
  blocking `recv` only blocks that connection's own thread (the Swift §7b structured-pool
  starvation trap is sidestepped *structurally* — the profile's stated design).

The 8-way `request_id` demux check is the N7 proof. **A-C-004 confirmed** (the deliberate
pthreads decision the profile recorded; not re-litigated at S3).

## v7.75 non-functional substrate floor — baked in

- **§4.8 store data-race safety (N6).** The content store + tree are guarded by a
  **single `pthread_rwlock_t`** (many concurrent readers / one exclusive writer); reads
  dominate the dispatch path, so the rwlock beats a plain mutex (the profile decision).
  A data race here = a crash = FAIL; the rwlock makes the consistency structural. ASan's
  thread instrumentation through the 8-way concurrent run found no race.
- **§4.9 resilience under load.** A malformed frame is skipped (the reader keeps reading);
  a per-request dispatch fault returns 500 without tearing down the connection
  (deliver-or-signal, never silently drop). Resources are bounded (see §4.10).
- **§4.10 resource bounds.**
  - r1: the 4-byte length prefix is checked against `EC_MAX_FRAME` (16 MiB) **BEFORE the
    body is buffered** — an over-limit prefix ends the connection (the §4.10(a) clean
    close; the peer keeps serving other connections). `read_frame` in `transport.c`.
  - r2: **the §4.10(b) chain-depth pre-check — `ec_cap_chain_exceeds_depth(store, cap,
    env)` walks parent pointers counting depth with NO signature work, max=64, BEFORE the
    per-link authz walk**, mapping over-depth → **`400 chain_depth_exceeded`** (NOT 403).
    An *unreachable* parent returns false here (not a depth problem) and stays 403 in the
    authz walk. **This is the one net-new peer code across the whole v7.75 cohort, and it
    is implemented as the single structural helper the contract prescribes** — confirmed
    present in `src/capability.c` and gated at the §5.2 `ec_cap_verify_request` site
    BEFORE `verify_chain`.
  - r3: connection admission is a SHOULD; the C peer keeps serving after every rejection
    (no flood cap wired — honest WARN posture, the §4.10(c) external-layer carve-out).
- **§7b transport.** **TCP_NODELAY** is set on **every** connection socket (in `ec_io_new`
  + the dialer) — the Zig Nagle finding. One reader thread per connection sidesteps the
  cooperative-pool blocking-I/O trap structurally.

## §7a conformance handlers — the seam is built, OFF by default

`system/validate/echo` + `system/validate/dispatch-outbound` are bootstrapped **ONLY under
`--validate`** (off by default → unreachable, 404 — so a default peer honestly absents
them for the validator's SKIP). Echo is verified 200 + params-verbatim over the wire
(scenario 2). **dispatch-outbound is the standing-dialer seam**: in `--profile core` it is
wire-reachable ONLY via §6.11 reentry back to the caller over the inbound connection (the
reentry seam `conn->io` is wired by the transport on every served connection); with no live
reentry it returns an honest `503 no_outbound_seam`. Its full wire exercise (the
origination-core relay) is the S4 probe — the S3 seam is present, bootstrapped, and
reachable, matching the cohort `conformanceHandlers` opt-in contract exactly.

## Pinned conformance invariants (N5–N8) — enforced at design time

- **N5 (envelope `included` preservation).** Entities round-trip through
  `ec_entity_to_cbor`/`ec_entity_of_cbor` with content_hash fidelity (§1.8);
  `ec_env_of_wire` enforces the §3.1 included-key == content_hash check on parse (request
  + result side); the handshake + execute paths carry the full §5.8 authority chain in
  `included` and the dispatcher's `outcome` included survives to the response envelope.
- **N6 (inbound concurrent with outbound dispatch).** Each inbound EXECUTE dispatches on
  its own thread; the reader keeps reading (§4.8); per-request isolation (a fault → 500,
  never a connection teardown); the store is rwlock-guarded.
- **N7 (reentrant transport + request_id demux).** The slot-list + `pthread_cond_t`
  rendezvous; verified by the 8-way demux check; the reentry seam is reentrant (a handler
  issuing a sub-request runs on its own dispatch thread, so it cannot deadlock the reader).
- **N8 (capability verdict determinism).** `ec_cap_verify_request` is a pure function of
  (envelope, store); §5.10 Layer-1 ALLOW/DENY with no nondeterminism (the only clock read
  is the temporal-validity check, identical across peers given the same chain state).

## Idiom review — reads as C, not transpiled

- **return-code + out-param error model everywhere**: every fallible function returns an
  `ec_status` int and writes its result through an out-pointer; the caller checks before
  use. The §5.2 trichotomy is a verdict enum (`ec_req_verdict`) mapped to a wire status at
  the dispatch boundary — NO exceptions, NO setjmp/longjmp, NO unwinding.
- **manual memory, goto-cleanup**: the allocator-heavy builders (`entity.c`, `wire.c`,
  `identity.c`) use a single cleanup label + free-in-reverse on the error path. Entities
  are refcounted (`ec_entity_ref`/`ec_entity_unref`) because they are shared between the
  store, envelopes and outcomes; everything else is plain malloc/free with a documented
  owner. **ASan/LSan/UBSan clean through the whole smoke run** — the manual-memory bonus.
  (One real use-after-free was caught + fixed during the build: the connect handler's
  borrowed pubkey/peer_id were copied OUT of the auth entity before it was freed — exactly
  the class of bug the sanitizer pass exists to catch on a no-GC peer.)
- **opaque handles + `ec_` namespace**: `ec_peer` / `ec_store` / `ec_session` / `ec_io` are
  opaque to their consumers; the flat C symbol space is namespaced by the `ec_`/`EC_`
  prefix; the public ABI stays in `include/entity_core/protocol.h` behind `EC_API`.
- **single-dispatch via `switch(op)`**: each MUST handler is one
  `ec_handler_fn(... const char *op, ec_outcome *out)` that switches over the operation
  string, registered in a flat pattern→fn table (the table IS the §6.6 instance map). This
  is the procedural analogue of the Java single-dispatch ladder and the contrast with CL's
  CLOS multiple dispatch — the tenth independent arrival at byte/behavior-identical §6.6
  dispatch. **No new spec ambiguity from the dispatch shape.**
- **lowercase address-space hex** (`ec_hex`, `%02x` lowercase by construction): the
  §3.4/§3.5 convention; the signature-ingestion path, the §6.9a policy/owner-sig paths, and
  the revocation markers are all lowercase — dodging the A-CL-009 uppercase trap by default.

## Dev loop

```
# the two-peer loopback smoke gate (container-bound, sealed offline, ASan/LSan/UBSan):
./run-s3.sh

# smoke + S2 codec regression:
./run-s3.sh all
```

## Exit criteria

Two-peer loopback smoke GREEN (11/11) · compiles `-Werror` clean (zero warnings) ·
ASan/LSan/UBSan-clean through the full run · reads as idiomatic C (return codes + opaque
handles + goto-cleanup + pthreads + operation-`switch` dispatch, not transpiled) · S2
codec regression unbroken (69/69 + selftests = 82/82) · peer_id byte-equal to the cohort +
§1.5-canonical · the §4.10(b) chain-depth pre-check present as the one structural helper ·
ambiguity log updated (A-C-008 Go-oracle provenance; A-C-004 confirmed). **S3 PASS.**

## Not in this phase (S4, next session)

- `validate-peer --profile core` conformance run against the Go oracle (the live superset
  of this smoke); rebuild `validate-peer`/`entity-peer` from a clean Go HEAD the
  orchestrator pins (the live oracle, with the §7a wire-gate).
- The full §9.5 53-type registry (render-from-model + byte-diff vs the canonical
  type-registry vectors) for the `type_system` oracle category — S3 publishes the handler
  discovery floor only (no core-type entities pre-published; the §9.5 registry is the S4
  type_system surface). A real `system/type:validate` body is also S4 (the Java peer's
  TypeHandler analogue is not ported in the C core S3).
- The dispatch-outbound §7a handler's full wire exercise (the origination-core probe:
  reentry over real 2-peer TCP); the seam is built + bootstrapped under `--validate`, the
  reentry relay body lands at S4.
- The full crypto-agility matrix (Ed448/SHA-384) — deferred at the profile level (A-C-001);
  the Ed25519 + SHA-256 floor is fully native via libsodium and complete.
