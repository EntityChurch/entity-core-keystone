# entity-core-protocol-java — Phase S3 (Peer machinery) Summary

**Peer #7** (Java/JVM, mainstream OO/static idiom) · **Status:
COMPLETE — two-peer loopback smoke GREEN (11/11 checks), peer compiles clean, S2 codec
regression unbroken (69/69 + selftest + Ed448 KAT + BouncyCastle cross-check).**

## Gate result — the two-peer loopback

Two Java peers talk over real loopback TCP through the full §6.5 dispatch chain. Run
offline (`--network=none`, loopback only) via `./run-s3.sh`:

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

Matches the Common Lisp cohort precedent (11/11, same two scenarios). The full
`validate-peer --profile core` conformance run is S4; this smoke proves the wire-level
peer surface (transport + handshake + register/dispatch/emit + capability gating +
request_id demux) is wired end-to-end, leaving the peer S4-ready.

The gate is a JUnit 5 test (`SmokeTest`, run via surefire), container-bound and
sealed-offline; `run-s3.sh all` also re-runs the S2 codec regression (13 tests total,
all green). `mvn` compiles clean — 38 main + 5 test sources, no warnings.

## peer_id byte-cross-check (the decisive S4-readiness signal)

The Java responder derives peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`
from seed `0x11` — **byte-identical to the Common Lisp peer's committed
CONFORMANCE-REPORT** (and the cohort peer_id convergence). The Base58 prefix decodes to
`(key_type=0x01 Ed25519, hash_type=0x00 identity-multihash, 32-byte digest)` — the
**§1.5 canonical form** (A-JAVA-004), NOT the stale §7.4 SHA-256 form. The handshake's
step-3 identity binding (`peer_id == derive(public_key)`) is therefore correct now, so
the S4 `authenticate` leg is clean (this is the construction A-JAVA-004 catches before
S4).

## What was built (`src/main/java/org/entitycore/protocol/peer/`, on top of the S2 codec)

The peer machinery lives in its OWN package (`...protocol.peer`) layered above the S2
codec (`...protocol.codec`) + crypto (`...protocol.crypto`), so the codec stays a clean
unit. ZERO new third-party deps (`java.net` + `java.util.concurrent` + JDK 21 virtual
threads ship in the JDK; the S2 crypto is already zero-dep).

| File | V7 layer | Responsibility |
|---|---|---|
| `Cbor.java`            | — | constructor + typed-accessor helpers over the S2 `EcfValue` model + **lowercase hex** (A-CL-009 trap) |
| `Entity.java`          | foundation | materialized `{type,data,content_hash}` (§1.1/§3.4) + wire form; fidelity-validating `ofCbor` (§1.8); defensive-copy `byte[]` hash |
| `Envelope.java`        | foundation | the §3.1 envelope (root + included); §3.1 included-key == content_hash check on parse (N5) |
| `Identity.java`        | L1 | seed → §1.5 identity-multihash peer_id (A-JAVA-004) / `system/peer` entity / sign (§3.5, §7.3) / verify |
| `Store.java`           | foundation | content store (hash→entity) + entity tree (path→hash) + one-level listing (§1.7/§3.9) + the §6.10/§6.13(c) **emit bus** (live with zero consumers); thread-safe (`ConcurrentHashMap`) |
| `Capability.java`      | L3 | §5.2 `verifyRequest` (3-way verdict, A-JAVA-009), `checkPermission`, §5.4 patterns + `canonicalize` + §1.4 `normalizeUri`, §5.5 chain walk, §5.6 attenuation, §5.7 caveats, §5.1 revocation; §PR-8 granter-frame |
| `Wire.java`            | L2 | §1.6 framing (4-byte BE length ‖ CBOR via `DataInputStream`); EXECUTE / EXECUTE_RESPONSE / error / empty-params / resource-target builders |
| `Handler.java` / `HandlerContext.java` / `Outcome.java` | — | the §6.6 handler interface contract (single-dispatch + per-op `switch`), context, outcome |
| `Conn.java`            | — | per-connection state (§4.2) + the §6.13(b) reentry seam slot |
| `CoreTypes.java`       | foundation | §9.5 minimal core-type seed (S3 subset; full 53-type registry deferred to S4 — A-JAVA-008) |
| `Peer.java`            | L1–L4 | the four MUST handlers (connect/tree/handler/capability) **as nested `Handler` classes**, the §6.5 dispatch chain, §6.5 signature ingestion, §6.6 backward resolution, §6.9 bootstrap, §6.9a peer-authority bootstrap, §7a conformance handlers, §6.13(b) outbound seam, entity-native dispatch |
| `Transport.java`       | L4 | TCP listener/dialer + per-connection reader (platform accept + **virtual-thread** readers) + §6.11 request_id demux + §4.8 inbound-on-own-vthread + §6.13(b) reentry + write-serializing lock; the initiator dialer/handshake |
| `Host.java`            | — | standalone S4-ready host (`--port`, `--seed`, `--debug-open-grants`, `--validate`, `LISTENING <port>` line) |
| `SmokeTest.java` (test) | — | the two-peer loopback gate (two scenarios above) + a `main` for ad-hoc runs |

## Concurrency — JDK 21 virtual threads + platform threads (A-JAVA-003 VALIDATED)

**The axis S3 exercises that the codec didn't.** The peer is one **reader thread per
connection**, with each inbound EXECUTE dispatched on its **own virtual thread** (§4.8):

- the **accept loop** runs on a daemon **platform** thread; each accepted connection
  gets a **virtual-thread** reader (`Transport.readLoop`);
- the reader demuxes inbound frames (§6.11): an EXECUTE_RESPONSE routes to its awaiting
  outbound caller by `request_id` through a
  `ConcurrentHashMap<requestId, SynchronousQueue>` rendezvous table; an inbound EXECUTE
  is dispatched on **its own virtual thread** (§4.8) so a handler that originates an
  outbound EXECUTE (§6.13(b)) and awaits its response does NOT block the reader;
- writes (inbound responses + outbound requests share the stream) are serialized by a
  per-connection write lock;
- the §6.13(b) reentry seam (`Io.outbound`) sends + awaits-correlated-reply; a close
  wakes a parked waiter via a `closed` flag polled on the rendezvous timeout.

**Why virtual threads (the Java-21-specific decision for the arch ledger).** This is the
Java analogue of the C#-`Task` / TS-`Promise` / OCaml-stdlib-`Thread` / Elixir-process /
Zig-`std.Thread` / CL-`sb-thread` fork. For a `--profile core` peer the N6/N7 invariants
are met by one-thread-per-connection + one-thread-per-inbound-EXECUTE without
structured-concurrency machinery — the shape OCaml/Zig/CL arrived at with stdlib threads
(A-OC-003-revised). The Java-specific refinement: **JDK 21 virtual threads (Project Loom,
JEP 444 GA in 21) make thread-per-connection AND thread-per-request cheap** — the model
other peers justified *against* OS-thread cost is the *recommended* carrier on Loom, so
Java spends a thread per inbound EXECUTE (not just per connection) without the usual
cost concern. The accept loop stays a platform thread (a long-lived blocking accept does
not benefit from a carrier). Zero third-party dependency (`java.util.concurrent` is
stdlib). The 8-way request_id demux check is the N7 proof. **A-JAVA-003 RESOLVED** (logged
in the ambiguity log). `java.nio` async / `CompletableFuture`-everywhere remains the open
path if handler-initiated outbound origination enters the core (extension-only today);
the swap is localized to `Transport.java`.

## Idiom seam — single-dispatch OO ladder (the saturated-axis probe)

The headline Java idiom: **operation dispatch is a single-dispatch interface method per
handler, with a `switch` over the operation string inside each implementation** — the
mainstream static-OO `match op` ladder. Each MUST handler is a nested
`Handler`-implementing class (`ConnectHandler`, `TreeHandler`, `CapabilityHandler`,
`HandlersHandler`, …); the §6.6 backward tree-walk resolves a request URI to a
bootstrapped handler instance; `instance.handle(operation, ctx)` then `switch`es. The
"unknown operation → 501" arm is the `default` branch of that switch.

What the saturated idiom revealed vs the prior peers: this is the **DIRECT CONTRAST** to
the Common Lisp peer's CLOS MULTIPLE dispatch (A-CL-008). Where CL externalizes routing
into the metaobject method table (router = data), Java keeps it as control flow inside a
method (router = `switch`). **Both land on byte/behavior-identical dispatch** — the
seventh independent arrival, and the static-OO bookend to CL's distant-idiom probe:
five single-dispatch ladders (C#/TS/OCaml/Elixir/**Java**) + one multiple-dispatch (CL)
→ identical §6.6 behavior. Positive evidence the §6.6 surface is idiom-neutral, exactly
as the profile predicted (saturated axis → small refinement yield, but the convergence
itself is the data point). **No new spec ambiguity from the dispatch shape.**

Other Java idiom decisions, all exercised: **checked exceptions** at the boundary
(`AuthenticationException`/`AuthorizationException` → 401/403; `EntityTransportException`
for framing faults) — the dispatcher catches the §5.5 `UnresolvableGrantee` (an unchecked
carve-out signal) → 401 and any other runtime fault → 500 (per-request isolation, N6);
**records** for value-shaped types (`Outcome`, `HandlerContext`, `Envelope.Included`,
`Store.*Event`); **sealed `EcfValue` + pattern-matching** carried up from S2;
**defensive-copy `byte[]`** on every entity-hash / public-key boundary
(`no_byte_array_aliasing`).

## v7.74 resync (A-JAVA-001) — all four foundations reachable

Resynced the peer layer to the **v7.74 peer surface**, mirroring the
C#/TS/OCaml/Elixir/Zig/CL builds (the v7.73/v7.74 spec-data snapshot is still missing —
escalation re-stated in the ambiguity log):

- **register live-hook (§6.13(a))** — `system/handler:register` performs the five
  normative writes (handler manifest, associated types, self-issued signed grant,
  grant-signature at the §3.5 hex pointer, interface index); NOT a 501 stub. Verified
  200 over the wire (scenario 2). `unregister` reverses them.
- **outbound-dispatch seam (§6.13(b))** — `Peer.outboundDispatch` builds + signs an
  outbound EXECUTE and sends it through the §6.11 reentry seam on the serving connection
  (`Conn.outbound`, set by the transport). Present on every peer even with no core
  originator; reachable the moment a handler is registered.
- **emit live-hook (§6.10 / §6.13(c))** — the store's emit bus produces tree- and
  content-change events on every bind/put. **Live even with zero consumers**; verified
  by the scenario-2 check that the register's tree writes fire a registered consumer.
- **§7a conformance handlers** — `system/validate/echo` + `system/validate/dispatch-outbound`
  are bootstrapped ONLY under `--validate` (off by default → unreachable, 404). Echo
  verified 200 + params-verbatim over the wire; cap convention = in-band params (matches
  the signed-off cohort, zero rework). dispatch-outbound is wired (reentry seam +
  in-band reentry authority) but its full wire exercise is the S4 origination-core probe.
- **owner-cap bootstrap (§6.9a)** — the self-owner capability (root cap, full scope over
  `/{peer_id}/*`, grantee = own identity; §6.9a.0 detached-sig shape: cap token at the
  hex policy path + its self-signature at the §3.5 pointer) and the default scope-template
  entry are written at bootstrap and read back by authenticate via the dual-form lookup
  (hex → Base58 → default), UNION'd with the §4.4 discovery floor. `--debug-open-grants`
  selects the degenerate `[default → *]` (the cohort's non-conformant debug wildcard).

## lowercase-hex address-space paths (A-CL-009 trap) — exercised

`Cbor.hex` is lowercase `0123456789abcdef` everywhere — the §3.4/§3.5 convention. The
register scenario writes `system/signature/{token_hash}` and the bootstrap writes the
§6.9a policy path `system/capability/policy/{identity_hash}` + the owner-sig pointer; the
revoke handler writes `system/capability/revocations/{token_hash}`; signature ingestion
writes `/{pid}/system/signature/{target}`. All lowercase, dodging the CL uppercase
trap by construction (the codec was already lowercase; the peer layer matches).

## Pinned conformance invariants (N5–N8) — enforced at design time

- **N5 (envelope `included` preservation)** — entities round-trip through
  `Entity.toCbor`/`ofCbor` with content_hash fidelity (§1.8); `Envelope.ofCbor` enforces
  the §3.1 included-key == content_hash check on parse (request + result side).
- **N6 (inbound concurrent with outbound dispatch)** — each inbound EXECUTE dispatches
  on its own virtual thread; the reader keeps reading (§4.8); per-request isolation (a
  runtime fault on one request → 500, never tears down the connection).
- **N7 (reentrant transport + request_id demux)** — the `ConcurrentHashMap<requestId,
  SynchronousQueue>` rendezvous table; verified by the 8-way demux check.
- **N8 (capability verdict determinism)** — `verifyRequest` is a pure function of
  (envelope, store); §5.10 Layer-1 ALLOW/DENY, no nondeterminism.

## Dev loop

```
# the two-peer loopback smoke gate (container-bound, sealed offline):
./run-s3.sh

# smoke + S2 codec regression (full mvn test, 13 tests):
./run-s3.sh all
```

## Exit criteria

Two-peer loopback smoke GREEN (11/11) · peer compiles clean (no warnings) · reads as
Java (interfaces + nested handler classes + records + checked exceptions + virtual
threads, not transpiled) · S2 codec regression unbroken (69/69 + selftest + Ed448 KAT +
BC cross-check) · peer_id byte-equal to the cohort + §1.5-canonical · register/revocation
paths lowercase-hex · ambiguity log updated (A-JAVA-001 re-stated; A-JAVA-003 RESOLVED;
A-JAVA-008/009 new) · container reproducible (`--network=none`, zero-dep core). **S3 PASS.**

## Not in this phase (S4, next session)

- `validate-peer --profile core` conformance run against the Go oracle (the live
  superset of this smoke); rebuild the oracle from Go HEAD with the §7a wire-gate.
- The full §9.5 53-type registry (render-from-model + byte-diff vs the canonical
  type-registry vectors) for the `type_system` oracle category — S3 seeds a minimal
  subset (A-JAVA-008). The `system/type:validate` handler body is also a placeholder
  (currently an echo) and needs a real type-validate at S4.
- The dispatch-outbound §7a handler's full wire exercise (the origination-core probe:
  `dispatch_outbound_reentry` over real 2-peer TCP with the Go reference peer); the seam
  is built + bootstrapped under `--validate`, the run script lands at S4.
- The full crypto-agility matrix wiring (MATRIX-M2/M3/M6, cap-token content_hash,
  key_type registry refusals) — peer-layer; the Ed448+SHA-384 primitives are proven at S2.
- The v7.73/v7.74 spec-data snapshot remains missing (A-JAVA-001 escalation to arch).
