# entity-core-protocol-csharp — Phase S3 Summary

**Phase:** S3 — peer machinery (V7 Layers 1–4 + foundation)
**Outcome:** ✅ smoke green. Peer compiles clean (warnings-as-errors, 0 warnings) in
the `dotnet9` container; codec S2 gate still **69/69** (no regression). The
first generated peer talks to itself over real loopback TCP through the full
dispatch chain.

## What was built

The peer machinery on top of the S2 codec — the first time `/entity-rosetta`
produced a *running peer*. ~3.3k new lines of idiomatic C# across model,
identity, capability, store, handlers, dispatch, and transport layers.

```
src/EntityCore.Protocol/
├── Model/            Entity (fidelity), Envelope (N5), Execute, ExecuteResponse,
│                     ResourceTarget, Ecf helpers, Hashes, protocol constants
├── Identity/         PeerIdentity (peer-id §7.4), system/peer + system/signature,
│                     target-matching signing/verify (§3.5, §4.6)
├── Capability/       CapabilityToken, GrantEntry, Scope, Paths (canonicalize +
│                     matches_pattern §5.4), ChainVerifier (Layer-1 verdict §5.5/§5.10),
│                     Attenuation (§5.6/§5.7), Permissions (§5.2/§6.3)
├── Store/            ContentStore (hash→entity), EntityTree (path→hash, CAS, listing §1.7)
├── Handlers/         IHandler/HandlerContext, HandlerRegistry (tree-walk dispatch §6.6),
│                     ConnectHandler (§4), TreeHandler (§6.3), CapabilityHandler (§6.2)
├── Dispatch/         Dispatcher — the §6.5 chain (verify → resolve → permission → run)
├── Transport/        FrameCodec (§1.6), PeerConnection (reader-task demux, N6/N7),
│                     Handshake (§4.1 both directions), PeerSession (authenticated EXECUTE)
└── Peer.cs           assembled peer: bootstrap + TCP listen/dial + connection mgmt
```

Exception hierarchy fleshed out per the profile: `EntityProtocolException`
(+ `HelloFailed`, `Authentication`), `EntityTransportException`
(+ `RecvTimeout`, `ConnectionBroken`, `ProtocolError` carrying the §6.12 code/status).

Smoke runner at `samples/EntityCore.Protocol.Smoke/`.

## Smoke result (the S3 exit gate)

Two C# peers, real loopback TCP, run in `dotnet9`:

```
Handshake:
  [PASS] session established
  [PASS] remote peer_id matches responder
Dispatch:
  [PASS] unregistered path → 404
  [PASS] granted tree get → 200
  [PASS] capability request → 200
Concurrency (request_id demux):
  [PASS] 8 interleaved requests each correlated to its own response — 8/8
Teardown clean.   →   SMOKE: PASS
```

The `granted tree get → 200` is the load-bearing assertion: it drives the entire
authenticated path — `verify_request` (EXECUTE signature + author resolution),
Layer-1 `verify_capability_chain` (root-at-local, per-link signatures, grantee
resolution, temporal), `check_permission` (all four grant dimensions),
dispatch-time handler-grant validation (§6.8), and the tree handler's
defense-in-depth `check_path_permission`. The capability chain it verifies is the
one the responder minted at `authenticate` (§4.4) and the initiator re-bundled
into the request envelope (§5.8 chain inclusion).

## Conformance-invariant enforcement (designed in, not retrofitted)

- **N5** envelope `included` preservation — `Envelope` keeps the whole map; entities
  are spliced verbatim (`PreEncoded`) on encode, never re-serialized.
- **N6** inbound concurrent with outbound — `PeerConnection` dispatches inbound
  EXECUTEs on a separate task; the reader loop never blocks on a handler.
- **N7** reentrant transport + `request_id` demux — single reader routes
  EXECUTE_RESPONSEs to awaiting callers by `request_id`; the write lock guards only
  the byte-write, not the send+recv cycle; per-request deadline at the request layer
  (not a connection-wide deadline). Verified by the 8-way interleaved smoke.
- **N8** Layer-1 verdict determinism — `ChainVerifier` consults only the chain and
  the envelope `included`; no local policy hooks. (`supports_revocation=false` for
  now — A-005.)
- **N4** entity fidelity carries up from S2 — `Entity.WireBytes` forwards originals.

## Standards honored

- **S1** containers: all builds + the smoke run in `entity-core-keystone/dotnet9`; no
  host writes. Lockfiles committed; `bin/obj` gitignored.
- **S2** spec-data read verbatim, unmodified.
- **S5** no doctored oracles: the smoke is honest (it asserts real status codes; the
  one place behavior is incomplete returns a real error, not a faked pass).
- **S6** profile decided idiom: `async Task`, exceptions, records, file-scoped
  namespaces, PascalCase — all per `profile.toml`. No unauthorized library picks
  (transport is in-box `System.Net.Sockets`; no third-party deps added).
- **S8** convergence: the peer is correct against this S3 smoke surface; cross-impl
  proof is S4 (`validate-peer`).
- **S11** no new NuGet deps; existing pins unchanged.

## Deferred (logged, not silent) — see SPEC-AMBIGUITY-LOG A-004…A-008

- **A-007 (the headline gap):** the **handlers handler** (`system/handler`
  register/unregister) is MUST per §6.9 and is **not yet implemented**; the **types
  handler** (`validate`, SHOULD) likewise. Both need the §6.1 native-code↔manifest
  binding mechanism, which is implementation-defined and not yet designed. This is
  the top S3-completion item; `validate-peer` will flag it in S4.
- **A-004:** smoke is C#↔C# loopback; cross-impl validation against the Go reference
  peer is the S4 step (`validate-peer`).
- **A-005:** `supports_revocation = false` (conformant for a peer with no
  persistent-capability extensions, §5.2).
- **A-006:** `capability:delegate` / `:revoke` return 501 (deferred); `delegate`'s
  grantee target is underspecified in core (→ findings F13).
- **A-008:** authenticate nonce-echo is not validated against a stored sent-nonce
  (replay hardening); §4.6's algorithm verifies the signature but does not mandate
  the echo check (→ findings F12).

## Next move

**S4 — `/entity-rosetta csharp --phase verify`.** Build/borrow the Go `validate-peer`
oracle (present at `entity-core-go/cmd/validate-peer`) and the `entity-peer` binary,
launch the C# peer, and run the extension-free categories (`connectivity`,
`encoding`, `type_system`, `origination`). Expect `validate-peer` to surface the
A-007 handlers-handler gap and any cross-impl wire deltas first — then close them.
Implementing the handlers + types handlers (A-007) is the natural precursor so the
`type_system` / handler-discovery categories have something to exercise.
