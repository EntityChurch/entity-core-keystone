# entity-core-protocol-typescript — Phase S3 Summary

**Phase:** S3 — peer machinery (V7 Layers 1–4 + foundation)
**Outcome:** ✅ smoke green. The full peer compiles clean (strict +
`noUncheckedIndexedAccess` + `exactOptionalPropertyTypes` + `verbatimModuleSyntax`)
in the sealed `node24` container; the S2 codec gate still **54/54** (69/69 corpus +
F7 + units + cborg cross-check — no regression). TypeScript is the **second
generated peer** to run, and the first **registry-ecosystem** peer to do so.

## What was built

The peer machinery on top of the S2 codec — ~2.6k new lines of idiomatic TS across
model, identity, capability, store, handlers, dispatch, transport, and types. Ported
from the proven C# reference peer (peer #1, which reached the S4 `--profile core`
verdict at v7.72), translated to TS idiom: `bigint` integer surface (R1), `Uint8Array`
wire bytes, discriminated-union value model, `Promise`/`async` everywhere, `#`-private
fields, ESM `.js` specifiers.

```
src/
├── errors.ts            full hierarchy: EntityProtocolError (+ HelloFailed,
│                        Authentication), EntityTransportError (+ RecvTimeout,
│                        ConnectionBroken, WireProtocolError — A-003 resolved)
├── codec/               + hash-formats.ts, key-types.ts (the agility registries
│                        over the S2 crypto provider)
├── model/              Entity (3-field wire / 2-field hashable, N4), Envelope (N5),
│                        Execute, ExecuteResponse, ResourceTarget, Ecf, Hashes, consts
├── identity/           PeerIdentity (peer-id §1.5/§7.65), system/peer (v7.65
│                        projection), system/signature target-matching sign/verify
├── capability/         Scope, GrantEntry, CapabilityToken (+ multi-sig granter),
│                        Attenuation (§5.6/§5.7), Permissions (§5.2/§6.3), Paths
│                        (§5.4), the deterministic Layer-1 ChainVerifier (§5.5/§5.10)
├── store/              ContentStore (hash→entity), EntityTree (CAS, listing §3.9)
├── handlers/           Handler/HandlerContext, HandlerRegistry (tree-walk §6.6),
│                        ConnectHandler (§4), TreeHandler (§6.3), CapabilityHandler
│                        (§6.2), ConnectionState (Deferred handshake ordering)
├── dispatch/           Dispatcher — the §6.5 chain (verify → resolve → permission → run)
├── transport/          FrameCodec (§1.6), PeerConnection (reader-loop demux N6/N7),
│                        Handshake (§4.1 both directions), PeerSession
├── types/              FSpec/TypeDef builder + the 53-type core registry (§8–§10)
└── peer.ts             assembled peer: bootstrap + node:net listen/dial + conn mgmt
```

## Smoke result (the S3 exit gate)

Two TypeScript peers, real loopback TCP, run in `node24`:

```
Handshake:
  [PASS] session established
  [PASS] remote peer_id matches responder
Dispatch:
  [PASS] unregistered path -> 404
  [PASS] granted tree get -> 200
  [PASS] tree get returns a system/type entity
  [PASS] capability request -> 200
Concurrency (request_id demux):
  [PASS] 8 interleaved requests each correlated to its own response -> 8/8
Teardown clean.   ->   SMOKE: PASS
```

`granted tree get → 200` is the load-bearing assertion — it drives the entire
authenticated path: EXECUTE signature verification + author resolution, Layer-1
`verifyCapabilityChain` (root-at-local, per-link signature, grantee resolution,
temporal), `checkPermission` (all four grant dimensions + resource scope),
dispatch-time §6.8 handler-grant validation, and the tree handler's
defense-in-depth `checkPathPermission`. The capability it verifies is the one the
responder minted at `authenticate` (§4.4) and the initiator re-bundled into the
request envelope (§5.8 chain inclusion).

## Conformance-invariant enforcement (designed in, not retrofitted)

- **N4** entity fidelity — `Entity.wireBytes` forwards originals; the data region is
  spliced verbatim (`ecfPreEncoded`) on encode, never re-serialized.
- **N5** envelope `included` preservation — `Envelope` keeps the whole map; entities
  splice verbatim on encode + decode.
- **N6** inbound concurrent with outbound — `PeerConnection` dispatches inbound
  EXECUTEs via a floating `#dispatchInbound`; the reader loop never blocks on a handler.
- **N7** reentrant transport + `request_id` demux — one reader routes
  EXECUTE_RESPONSEs to awaiting callers by `request_id`; a promise-chain write mutex
  guards only the byte-write; per-request deadline at the request layer. Verified by
  the 8-way interleaved smoke.
- **N8** Layer-1 verdict determinism — `ChainVerifier` consults only the chain + the
  envelope `included`; no local-policy hook (`supports_revocation=false`, A-005).

## TS-idiom translation notes (the cross-language deltas)

- **`TaskCompletionSource` → `Deferred<T>`** (a promise + external resolve/reject).
  JS continuations are always async, so the §4.1 leg-ordering is automatic.
- **`SemaphoreSlim` write lock → promise-chain mutex**; **`ConcurrentDictionary` →
  `Map`** (single-threaded JS — no preemption between `await` points, so the C#
  locks collapse).
- **`Stream`/`ReadExactlyAsync` → an async generator over `node:net` `data` chunks**
  buffering partial frames. The one Node-coupled corner; the codec/crypto layers
  stay pure-JS (browser-portable).
- **`ulong` → `bigint`** end-to-end (R1); **`byte[]` → `Uint8Array`**.

## Standards honored

- **S1** containers: every build + the smoke run in `entity-core-keystone/node24`;
  pull-once then **`--network=none`** sealed-offline. No host installs; `dist`/
  `node_modules` gitignored; lockfile committed.
- **S2** spec-data read verbatim (v7.72), unmodified.
- **S5** no doctored oracles: the smoke asserts real status codes; the one place
  behavior is incomplete returns a real error, not a faked pass.
- **S6** profile decided idiom: `promise` async, `exceptions`, PascalCase types,
  camelCase members, kebab-case files, `@noble` crypto, `node:net` transport (in-box,
  no new deps).
- **S8** convergence: the peer is correct against the S3 smoke surface; cross-impl
  proof is S4 (`validate-peer`).
- **S11** no new runtime deps (transport is `node:net`); existing pins unchanged.

## Deferred (logged, not silent) — see SPEC-AMBIGUITY-LOG

- **A-006 (top S4 precursor):** the 53-type `CoreTypeRegistry` is rendered + seeded
  but **not yet byte-diffed** against the Go-rendered `type-registry-vectors-v1.cbor`.
  The C# reference proved this byte-identical; TS must too before the `type_system`
  category. Quick win: add a registry byte-check test.
- **A-007:** the handlers-handler (`system/handler` register/unregister, §6.9) and
  types handler (`validate`) are not implemented — extension-tier, out of the C#
  core-verdict scope (carried as the same A-007 there).
- **A-008:** `supports_revocation = false` (conformant for a core-only peer, §5.2);
  the revoke op + chain-revocation walk exist, but no persistent-cap extension.
- **delegate → 501** (closeout F1 / F13); same-peer-only in v1.

## Next move

**S4 — `/entity-rosetta typescript --phase verify`.** Build/borrow the Go
`validate-peer` oracle (+ `entity-peer`), launch the TS peer (`--debug-open-grants`
for the grant-gated categories), and run `--profile core`. Expect the type-registry
byte-diff (A-006) and any cross-impl wire deltas to surface first — then close them.
Carry peer #1's S4 scars: the `--profile core` machine verdict from day one, the F12
nonce-echo (already implemented), F18/F19 (core-vs-extension scoping), F20 (401 not
403 for request-time auth-class sig failure).
