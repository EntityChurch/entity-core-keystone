# entity-core-protocol-ruby — Phase S3 (Peer machinery) Summary

**Peer #12 (Ruby)** — first dynamic / duck-typed /
scripting peer · **Status: COMPLETE — two-peer loopback smoke GREEN (11/11),
peer loads + `ruby -w` clean, S2 codec regression unbroken (69/69), all 7
S2-deferred agility gates picked up (35/35, 0 deferred).**

## Gate result — the two-peer loopback (11/11)

Two Ruby peers talk over real loopback TCP through the full §6.5 dispatch chain.
Run offline (`--network=none`, loopback only) via `./run-s3.sh`:

```
Responder listening on 127.0.0.1:<port> (peer 2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg)
Handshake:
  [PASS] session established (capability minted)        (§4.1 handshake)
  [PASS] remote peer_id matches responder               (§4.6 identity binding)
Dispatch:
  [PASS] unregistered path -> 404                        (§6.6 no handler resolved)
  [PASS] granted tree get -> 200                         (§4.4 discovery floor authority)
  [PASS] tree get returns a system/handler/interface entity
  [PASS] capability request -> 200                       (§6.2 mint-bounded)
Concurrency (request_id demux):
  [PASS] 8 interleaved requests each correlated -> 8/8   (N7 / §6.11 request_id demux)
Extensibility (open-grants + --validate):
  [PASS] handler register -> 200 (live, not 501)         (§6.13(a) register live-hook)
  [PASS] emit hook fired on register's tree writes        (§6.13(c) emit live-hook)
  [PASS] §7a echo -> 200                                  (§7a resolve→dispatch)
  [PASS] §7a echo returns params verbatim
SMOKE: PASS (11/11)
```

Matches the Java / Common-Lisp cohort precedent (same two scenarios, same 11
checks). The full `validate-peer --profile core` run is S4; this smoke proves
the wire-level peer surface (transport + handshake + register/dispatch/emit +
capability gating + request_id demux) is wired end-to-end. Ran 8× back-to-back
with no flakiness — the §6.11 demux + Mutex-guarded store are concurrency-stable.

## peer_id byte-cross-check (the decisive S4-readiness signal)

The Ruby responder derives peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`
from seed `0x11` — **byte-identical to the Java and Common-Lisp peers' committed
reports** (the cohort peer_id convergence). The §1.5 canonical (identity-multihash)
form, NOT the stale §7.4 SHA-256 form. The handshake step-3 identity binding
(`peer_id == derive(public_key)`) is therefore correct, so the S4 `authenticate`
leg is clean.

## What was built (`lib/entity_core/`, on top of the S2 codec)

| Module | V7 layer | Responsibility |
|---|---|---|
| `entity.rb` | foundation | materialized `{type, data, content_hash}` (§1.1/§3.4); fidelity-validating `from_cbor` (§1.8); `data` = arbitrary ECF value (A-JAVA-010, `data_map` null-safe view) |
| `envelope.rb` | foundation | the §3.1 envelope (root + ordered included); §3.1 included-key == content_hash check on parse (N5) |
| `identity.rb` | L1 | seed → §1.5 identity-multihash peer_id / `system/peer` entity / sign (§3.5, §7.3) / verify |
| `store.rb` | foundation | content store (hash→entity) + entity tree (path→hash) + one-level listing (§1.7/§3.9) + the §6.10/§6.13(c) emit bus (live w/ zero consumers); **Mutex-guarded — atomic CAS (`bind_cas`) in one critical section (§4.8)** |
| `capability.rb` | L3 | §5.2 `verify_request` (3-way verdict), `check_permission`, §5.4 patterns + `canonicalize` + §1.4 `normalize_uri`, §5.5 chain walk + §PR-8 granter frame, §5.6 attenuation, §5.7 caveats, §5.1 revocation, **§4.10(b) `chain_exceeds_depth?` structural pre-check** |
| `wire.rb` | L2 | §1.6 framing (4-byte BE length ‖ CBOR); **§4.10(a) 16 MiB payload guard on the length prefix**; EXECUTE / EXECUTE_RESPONSE / error / empty-params / resource-target builders |
| `handler.rb` | — | the §6.6 handler interface contract (`Handler` base + `op`/`op_<name>` ladder), `HandlerContext`, `Outcome`, per-connection `Conn` (incl. the §6.13(b) reentry seam) |
| `core_types.rb` | foundation | §9.5 minimal core-type seed (S3 subset; full 53-type registry deferred to S4 — A-RUBY-008) |
| `peer.rb` | L1–L4 | the four MUST handlers (connect/tree/handler/capability) + §7a echo/dispatch-outbound, the §6.5 dispatch chain, §6.5 signature ingestion, §6.6 backward resolution, §6.9/§6.9a bootstrap, v7.74 register/outbound/emit/owner-cap, entity-native dispatch |
| `transport.rb` | L4 | TCP listener/dialer + per-connection reader **Thread** + §6.11 request_id demux (pending-map + ConditionVariable) + §4.8 inbound-on-own-thread + §6.13(b) reentry + write-serializing Mutex + **TCP_NODELAY**; the initiator dialer/handshake |
| `test/smoke_test.rb` | — | the two-peer loopback gate (the two scenarios above) |
| `test/peer_test.rb` | — | §4.10 chain-depth/payload guards + §3.9 CAS-store concurrency + §5.2a 401-not-403 unit checks |

The peer machinery layers cleanly above the S2 codec; **zero new runtime gem
deps** (`socket` / `thread` / `securerandom` / `openssl` are all stdlib).

## Concurrency — thread-per-connection under the honest GVL (A-RUBY-004 VALIDATED)

The axis S3 exercises that the codec didn't. The peer is one **reader `Thread`
per connection**, with each inbound EXECUTE dispatched on its **own `Thread`**
(§4.8):

- the **accept loop** runs on its own Thread; each accepted connection gets a
  reader Thread (`Transport.read_loop`);
- the reader demuxes inbound frames (§6.11): an EXECUTE_RESPONSE routes to its
  awaiting outbound caller by `request_id` through a `pending {request_id =>
  Waiter}` map, each Waiter a `Mutex` + `ConditionVariable` rendezvous; an
  inbound EXECUTE is dispatched on **its own Thread** (§4.8) so a handler that
  originates an outbound EXECUTE (§6.13(b)) and awaits its reply does NOT block
  the reader;
- writes (inbound responses + outbound requests share the stream) are serialized
  by a per-connection write `Mutex`;
- the §6.13(b) reentry seam (`Io#outbound`) sends + parks on the Waiter's condvar
  until the reader routes the correlated reply; a connection close wakes every
  parked waiter (`@closed` + `cond.signal`) so it returns nil instead of hanging.

**The honest GVL accounting (the point of this peer's concurrency axis).** MRI's
GVL serializes Ruby bytecode (no parallel Ruby execution) BUT is **released
during blocking IO** (socket read/write/accept, OpenSSL C calls), so
thread-per-connection is genuinely concurrent for this **IO-bound** peer —
adequate for the §7b gate without worker pools / fibers / Ractors. **The GVL does
NOT make a compound read-then-write atomic**, so the §3.9 CAS put and the §4.8
store mutations are each a single explicit-`Mutex` critical section — a real
correctness point, proven by `test/peer_test.rb`'s 64-thread CAS race
(exactly-one-winner). **Ractors declined** (share-nothing fights the shared store;
still experimental) — noted as the parallelism escape hatch.

## v7.75 non-functional substrate floor — built in at S3 (not rediscovered at S4)

- **§4.8 store data-race safety** — every store mutation (`put_entity`, `bind`,
  `bind_cas`, `unbind`) is a single `Mutex` critical section; emit consumers fire
  OUTSIDE the lock so a re-entrant store call from a consumer cannot deadlock.
  `test_cas_store_single_winner_under_concurrency` proves the RMW indivisibility.
- **§4.10(a) payload bound** — `Wire.read_frame` checks the 4-byte length prefix
  against `MAX_FRAME` (16 MiB) BEFORE buffering the body; over-limit →
  `PayloadTooLargeError` → the dispatcher answers **413 `payload_too_large`** and
  keeps serving.
- **§4.10(b) chain-depth bound** — `Capability.chain_exceeds_depth?` is a
  structural parent-walk (NO signature work) gated in `verify_request` **BEFORE**
  the per-link authz walk; over-depth (>64) → **400 `chain_depth_exceeded`** (NOT
  403 — structural excess ≠ authz denial). An **unreachable parent is NOT a depth
  fault** (stays the 403-class deny). All three cases unit-tested.
- **§7b TCP_NODELAY** — set on every socket (listener-accepted + dialed) via
  `setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)` from day one (the Zig small-frame
  lesson). Blocking reads run on dedicated OS Threads (the GVL releases on IO), so
  there is no cooperative-pool starvation hazard (the Swift trap does not apply).

## 7 S2-deferred agility gates — picked up (35/35, 0 deferred)

The 7 gates S2 deferred to the peer layer are now byte-green (`agility.rb`),
first attempt:

- **3 matrix `root_cap` cap-token §3.6 shapes** (`matrix.M2/M3/M6.root_cap`) —
  each produces a `system/capability/token` `{granter, grantee, grants[…],
  created_at:0, expires_at:0}`, content_hash under the ACTIVE format (SHA-256),
  Ed-signed by peer A over the 33-byte content_hash. **content_hash AND signature
  byte-identical** to the v7.67 pins across the Ed448-granter (M2), SHA-384-home
  (M3), and combined cross-key/cross-hash (M6) cases.
- **4 registry-interpretation `decode_reject` gates** (`varint-multibyte.1`,
  `varint-reserved-ff.1.key_type`, `varint-reserved-ff.2.hash_format`,
  `format-code-interpretation.1`) — an unallocated/reserved content-hash format
  code (`80 01`=128, `FF 01`=255, single `0x42`) MUST NOT resolve (→ the peer's
  400 `unsupported_content_hash_format`); a reserved `key_type` 255 MUST NOT
  resolve to a curve (the §1.5 key registry refusal). The multi-byte LEB128
  decoder fires before the registry check (N1).

> **Count note (logged, non-blocking):** the S3 brief said "4 root_cap + 3
> decode_rejects"; the actual v7.71 agility corpus has **3 root_cap + 4
> decode_reject** (7 total either way). The 7 deferred gates are the same set;
> only the per-kind split differs. Recorded in the ambiguity log.

## Pinned conformance invariants (N5–N8) — enforced at design time

- **N5 (envelope `included` preservation)** — `Entity#from_cbor` recomputes +
  validates content_hash (§1.8); `Envelope.from_cbor` enforces included-key ==
  content_hash on parse (request + result side).
- **N6 (inbound concurrent with outbound dispatch)** — each inbound EXECUTE runs
  on its own Thread; the reader keeps reading (§4.8); per-request isolation (a
  fault on one request → 500, never tears down the connection).
- **N7 (reentrant transport + request_id demux)** — the `pending` map + condvar
  rendezvous; verified by the 8-way demux check.
- **N8 (capability verdict determinism)** — `verify_request` is a pure function
  of (envelope, store); §5.10 ALLOW/DENY, no nondeterminism.

## Idiom seam — the duck-typed operation ladder (the dynamic-axis probe)

Where Java keeps the operation ladder a `switch` inside a method (router =
control flow) and Common Lisp externalizes it into a CLOS multiple-dispatch
method table (router = data), the Ruby peer uses **the object's own method table
reached by reflection**: each handler declares `op :name` and a method
`op_<name>(ctx)`; the base `Handler#handle` maps the wire operation string to the
method via `send`, with the "unknown operation → 501" arm as the
`respond_to?`/declared-op fallthrough. The router is metaprogramming, not an
explicit construct — the dynamic-language seam. Lands on byte/behaviour-identical
dispatch (the 12th independent arrival; no new spec ambiguity from the dispatch
shape). Other Ruby idiom decisions exercised: **exceptions** at the boundary
(`UnresolvableGranteeError`→401, `PayloadTooLargeError`→413, any other
StandardError→500; per-request isolation, N6); **`Data.define`** immutable value
objects (`Outcome`, `HandlerContext`, `Envelope::Included`, `Minted`,
`Store::TreeEvent`); **ASCII-8BIT byte strings** for all wire bytes (the codec
seam carried up); `::`-qualified core-class refs (the S2 `EntityCore::Hash`
shadow lesson).

## Dev loop

```
./run-s3.sh        # the two-peer loopback smoke gate (offline, container-bound)
./run-s3.sh all    # smoke + S2 codec (69/69) + agility (35/35) + peer-machinery checks
```

## Exit criteria

Two-peer loopback smoke GREEN (11/11) · peer loads + `ruby -w` clean (zero
warnings) · reads as Ruby (Handler `op`-ladder + Data.define value objects +
exceptions + threads + ASCII-8BIT, not transpiled) · S2 codec regression
unbroken (69/69) · agility 35/35 (the 7 S2-deferred gates picked up) · peer_id
byte-equal to the cohort + §1.5-canonical · §4.10 chain-depth/payload guards +
TCP_NODELAY + Mutex-guarded CAS store wired and unit-tested · zero runtime gem
deps · container reproducible (`--network=none`). **S3 PASS.**

## Not in this phase (S4, next session)

- `validate-peer --profile core` conformance run against the Go oracle (the live
  superset of this smoke).
- The full §9.5 53-type registry (render-from-model + byte-diff vs
  `type-registry-vectors-v1`) for the `type_system` oracle category — S3 seeds a
  minimal subset (A-RUBY-008).
- The dispatch-outbound §7a handler's full wire exercise (the origination-core
  probe over real 2-peer TCP); the seam is built + bootstrapped under
  `--validate`, the run lands at S4.
- The v7.75 test-vector snapshot (`shared/test-vectors/v7.75/`) is absent; the
  codec is wire-stable v7.73→v7.75 (SHA-verified in the profile), so the suite
  runs against the vendored v0.8.0 corpus. Flagged in the ambiguity log.
