# entity-core-protocol-swift — Phase S3 (Peer) Summary

**Status: COMPLETE — peer compiles clean + smoke-runs GREEN
(11/11) over real loopback TCP, in-container; S2 codec unregressed (69/69 corpus +
26 behavioral tests).**

Peer #7 (Swift, spec-first string/encoding + ARC-memory + actor-concurrency probe).
S3 builds V7 Layers 1–4 + foundation + the v7.74 extensibility foundations on top of
the byte-green S2 codec (69/69 wire-conformance), in Swift idiom: **async/await +
`actor` concurrency, value-type entities, typed `throws(CodecError)`, UTF-8-byte
wire discipline (A-SW-002)**. ~2.7k lines of new source. Derived **spec-first** from
`spec-data/v7.74/ENTITY-CORE-PROTOCOL-V7.md` (§3–§9) — the sibling peers (OCaml/Zig)
were consulted only for module layout + the §7a/§7b scaffolding *contract*, never for
protocol semantics.

## Modules built (`Sources/`, on top of the S2 codec)

| Module | V7 layer | Responsibility | LoC |
|---|---|---|---|
| `Model.swift`       | foundation | `BuiltEntity` (entity + computed content_hash + wire bytes); `Model.make`/`emptyParams` (§7.1/§3.2); CBORValue field-access ergonomics | 83 |
| `Store.swift`       | foundation | **`actor` content store + entity tree (§1.7) + emit pathway (§6.10/§6.13c)** — the §7b data-race-free advantage; listing (§3.9); `HashKey` | 162 |
| `Identity.swift`    | L1 | seed → **canonical identity-multihash peer_id (§1.5, NOT §7.4 SHA-256 — A-SW-008)** / `system/peer` (§3.5 v7.65) / sign (§7.3) / signature entity | 66 |
| `Wire.swift`        | L2 | §1.6 framing (4-byte BE length + CBOR envelope), the two message types (EXECUTE/EXECUTE_RESPONSE), envelope encode/decode (N5 `included`), error builder, §5.2 signature lookup | 186 |
| `Capability.swift`  | L3 | §5.4 patterns + §1.4 canonicalize, §5.2 verify/check_permission/matches_scope/check_resource_scope, §5.5 chain walk + §5.5a per-link granter frame, §5.6 attenuation, §5.7 caveats | 384 |
| `TypeRegistry.swift`| foundation | §9.5 render-from-model seam + minimal core-type seed (full 53 deferred — A-SW-009) | 116 |
| `SeedPolicy.swift`  | foundation | §6.9a keystone seed-policy convention (`standard`/`debugOpen`/`of`; dual-form derivation) | 89 |
| `Peer.swift`        | L1–L4 | the **`actor`** peer: §6.5 dispatch chain, §6.6 resolution, §5.2 verify_request, §6.9 bootstrap, **§6.9a peer-authority seed bootstrap**, §6.5 signature ingestion, the four MUST handlers' wiring | 458 |
| `PeerHandlers.swift`| L1–L2 | connect (§4.1 hello/authenticate + §4.6 proof-of-possession), tree (§6.3 get/put + listing), type (validate); §4.4/§6.9a.2 authenticate-grant mint | 187 |
| `PeerCapabilityHandler.swift` | L3 | handlers handler **register/unregister (§6.13a five writes — NOT a 501-stub)**; capability handler request/delegate/revoke/configure (§6.2); **§7a echo + dispatch-outbound** | 259 |
| `Socket.swift`      | L4 | zero-dep POSIX TCP (Glibc) loopback listener/dialer; framed read/write; **`TCP_NODELAY` (§7b)** | 152 |
| `Transport.swift`   | L4 | **`Connection` actor**: reader-demux (§6.11/N7), inbound-concurrent-with-outbound (§4.8), the **§6.13b outbound reentry seam**, per-request `request_id` correlation; `Server` accept loop | 196 |
| `PeerClient.swift`  | — | initiator side: §4.1 legs 1–2 handshake + authenticated `execute` (bundles author/cap/chain into `included`); B-role serve for the reentry self-check | 120 |
| `Sources/Host/main.swift`  | — | S4-ready host (`--port`/`--seed-policy`/`--owner-identity`/`--debug-open-grants`/`--validate`; unbuffered `LISTENING` line) | 77 |
| `Sources/Smoke/main.swift` | — | **the S3 smoke runner** — two Swift peers over real loopback TCP | 173 |

## 1. Does the peer compile + smoke-run green in-container?

**Yes.** Built and run inside `entity-core-keystone/swift-toolchain:latest` (Swift 6.2,
`--network=none` after the S2 resolve):
- `swift build` / `swift build -c release` — clean, no source warnings (the lone note
  is the A-SW-005 swift-asn1 transitive pin, expected).
- `swift test` — **26/26 pass** incl. the **69/69 ECF conformance corpus** (S2
  unregressed) + the 25 uncovered-range selftests.
- `swift run smoke` — **SMOKE: 11 pass, 0 fail**, EXIT 0.
- `entity-peer-swift --validate` host boots, emits `LISTENING …`, terminates clean
  (no hang) — S4-ready.

The smoke exercises, over two real loopback-TCP Swift peers:
1. **§4.1 handshake** — initiator `hello` → `authenticate` answered over real frames;
   session established with its §4.4 initial capability; remote peer_id == responder.
2. **404** — EXECUTE on an unregistered path → `404 handler_not_found`.
3. **authority-gated tree get → 200** — discovery-floor grant admits `system/type/*`.
4. **capability request → 200** — `system/capability:request` mints a bounded child cap.
5. **N7 request_id demux → 16/16** — 16 concurrent EXECUTEs each correlate to their
   own EXECUTE_RESPONSE.
6. **clean teardown** — close wakes the readers, resolves pending, drops sessions; no hang.
7. **§6.13a register → 200** + grant-write-landed — the five normative writes execute.
8. **§7a dispatch-outbound reentry → 200** + **value-passthrough (echo v=42)** — the
   responder originates back to the initiator (B-role) over the same connection; the
   value rides THROUGH (the cohort re-wrap bug avoided).

## 2. Concurrency model — the actor probe (genuinely distinct from all 6 prior peers)

`async/await` + **`actor`** isolation, distinct from C# Tasks, TS event loop, OCaml/Zig
threads+mutex, Elixir BEAM processes, CL conditions:

- **`Store` is an `actor`** — all mutable peer state (content map, tree map, emit
  consumers) is actor-isolated. There is *no path* to touch the maps except `await`-ing
  an actor method, which the runtime serializes onto the actor's executor. **No mutex,
  no lock — the type system is the proof.**
- **`Connection` is an `actor`** — owns the per-connection `pending` table (request_id →
  `CheckedThrowingContinuation`) and the outbound counter. One reader does blocking frame
  reads on a detached Task (so it doesn't pin the cooperative pool); EXECUTE_RESPONSE →
  resume the awaiting continuation by request_id (§6.11(b) out-of-order, **N7**); inbound
  EXECUTE → dispatch on a **child Task** so the reader keeps reading and the handler can
  originate outbound over the same connection (**§4.8** inbound-concurrent-with-outbound).
- **`Peer` is an `actor`** — identity, nonce/session table, `pendingIncluded` isolated.
- request_id↔continuation correlation via `withCheckedThrowingContinuation` (N7).

### §7b finding — the actor store makes data-races structurally impossible (compiler-enforced)

This is a **real finding on the memory/concurrency axis**, and it is the inverse of the
Zig/CL §7b failure. The §7b gate fired RED on Zig (HashMap double-free) and Common Lisp
(gethash 500s) because their stores were accessed from per-request dispatch threads with
no synchronization — PROPOSAL-V7-V7.75 then made store data-race-safety a §4.8 floor MUST.
**In Swift the store-race cannot compile:** the `Store` actor's state is `Sendable`-isolated;
a concurrent unsynchronized access is a *compile error* under Swift 6 strict concurrency,
not a runtime crash. The conformant fix the other peers had to *add* (serialize / RwLock /
mailbox) is the *default* here — an `actor` IS the cleanest §4.8/§7b-conformant shape, and
the compiler proves it. `TCP_NODELAY` is set on every socket (§7b — the Nagle/delayed-ACK
churn that bit Zig's raw sockets is pre-empted; managed runtimes dodged it, this raw-socket
peer sets it explicitly). **Generator guidance**: for any actor-model / structured-
concurrency target, model the store as an actor — §7b store-safety falls out for free and
is compiler-verified, not test-discovered.

### N5–N8 coverage

- **N5 (`included` preservation, request + result side):** request side — the EXECUTE
  envelope's `included` survives decode into `Envelope.included` and is passed to the
  handler context (caps/identities/signatures resolved from it). Result side — handlers
  attach minted token + granter peer + signature via `pendingIncluded`, returned in the
  `DispatchResult.included` and re-encoded into the response envelope (authenticate +
  capability:request both exercised, smoke steps 1 + 4).
- **N6 (inbound concurrent with outbound, §4.8):** the `Connection` reader dispatches each
  inbound EXECUTE on a child Task and keeps reading; the handler-outbound reentry
  (dispatch-outbound, smoke step 8) sends + awaits on the same connection without blocking
  the reader. Proven structurally (the reader never `await`s a handler) and behaviorally.
- **N7 (reentrant transport + request_id demux, §6.11/§6.12):** the `pending` table demuxes
  EXECUTE_RESPONSE by request_id, out-of-order tolerant; smoke **16/16 concurrent** + the
  reentry self-check. Teardown resolves all pending with connection-broken (§6.11 informative).
- **N8 (verdict determinism, §5.10):** `Capability.verifyChain` consumes only the chain +
  observable Layer-1 inputs (signatures, linkage, attenuation, TTL) — no local policy in
  the verdict; Layer-2 (seed policy) is a separate authenticate-time grant assembly. Full
  convergence-mode confirmation is an S4 multi-peer run.

## 3. §6.9a bootstrap + seed-policy wiring

- **§6.9a peer-authority bootstrap** at L0: the peer materializes a **self-owner
  capability** (root cap, full scope over `/{peer_id}/*`, grantee = self) in the
  **§6.9a.0 detached-signature shape** — the cap token at the hex policy path
  `…/policy/{self_identity_hash_hex}`, its self-signature at the §3.5 invariant pointer
  `…/system/signature/{cap_hash}`. The `default` (+ named) seed entries materialize as
  signed policy-entry caps at `…/policy/{key}`.
- **authenticate-time derivation (§6.9a.2 / §4.4)** UNIONs the matched seed-policy scope
  with the §4.4 discovery floor (v7.62 §8), via the v7.64 dual-form lookup (hex → Base58 →
  `default`). **No hardcoded initialGrants/openGrants fork** (§6.9a non-conformant).
- **Detached-signature uniformity** (the keystone S8 follow-on): the generator uses the
  detached-sig shape uniformly for ALL self-issued caps — bootstrap owner cap, per-handler
  grants (§6.2), register grants (§6.13a), minted child caps — so the generated cohort
  never splits across §6.9a.0's two shapes.
- **CLI**: `--owner-identity` / `--seed-policy` (the JSON parse lands at S4) /
  `--debug-open-grants` (the degenerate `default → *`, DEPRECATED v7.74; routed through
  the real §6.9a mechanism with a warning). **Builder API**: `Peer(seedPolicy:)` with
  `SeedPolicy.standard() | .debugOpen() | .of(...)`.

## 4. §7a/§7b implementation + the actor-store finding

- **§7a two conformance handlers** (`system/validate/{echo,dispatch-outbound}`) behind the
  **builder opt-in `conformanceHandlers: Bool`** surfaced as host **`--validate`**, **OFF
  by default** (dispatch-outbound is a standing dialer). `echo` returns the params entity
  **verbatim** (`result.value == params.value` — NOT re-wrapped). `dispatch-outbound`
  originates **one** outbound EXECUTE **back to the caller over the same inbound connection
  (§6.11 reentry, §7a.2a)** — proven over real two-peer TCP in the smoke — and relays the
  downstream result **verbatim** (no unwrap, value passed THROUGH; the §7b matrix re-wrap
  bug avoided). Cap-passing = **in-band params** (Go ruling (a)): the caller mints the
  reentry cap (granted to the responder, rooted at the caller) and passes it + the granter
  peer + cap sig nested in params.
- **§7b**: covered by the **actor store** finding in §2 — data-race-free is compiler-enforced.

## 5. ARC retain-cycle audit (the ARC probe)

The codec/entity data model is value types (struct/enum) — **cycle-free by construction**.
Reference types (`class`/`actor`) appear only for shared-mutable identity. Audited the
class/actor graph:

- **`Connection`** holds `peer` (strong, correct — the peer outlives the connection) and
  `socket`. Its reader `Task` captures **`[weak self]`**; the inbound-dispatch child Task
  captures **`[weak self, peer]`**; the §6.13b outbound closure captures **`[weak self]`**
  — so a long-lived continuation/closure does not retain the Connection past teardown.
- **`Server`** holds `connections` + `peer` (strong); its accept Task captures `[weak self]`.
- **`Session`/`HandlerContext`** are `@unchecked Sendable` value-ish holders, owned by the
  Peer actor / passed by reference into a single dispatch — no back-edge to the Peer.
- **`PeerClient`** holds `connection` + `socket` strongly (the client owns them); no
  back-edge from Connection to PeerClient. The smoke's clean-teardown step confirms no hang
  (a retain cycle on the connection graph would leave the reader Task alive and the process
  hanging — it exits 0).

**Result: no retain cycle found.** The watch surface (the connection/closure graph) uses
`[weak self]` at every Task/closure capture that could outlive its owner; the value-type
default keeps the codec/entity surface cycle-free.

## 6. New spec findings (this phase)

- **A-SW-008 ⚑** — §7.4 NORMATIVE peer-id derivation vs §1.5 canonical-form table; the
  §9.1 floor still cites "§7.4" though §1.5 is the canonical construction. **Fourth peer**
  to surface the §7.4/§1.5 peer-id tension (OCaml A-OC-007 headline, Zig A-ZIG-001, C#/TS
  ports) — strong convergence → recommend re-pointing §9.1 + demoting §7.4 to REFERENCE. → arch.
- **A-SW-010 ⚑** — §4.2/§5.1 "missing auth fields → 403" textually contradicts §5.2a's
  "Author absent → 401". Built to §5.2a (the v7.73 load-bearing enumeration). → arch (text
  consistency; recommend §4.2/§5.1 cross-reference §5.2a).
- **A-SW-009** — full §9.5 53-type registry render DEFERRED to S4 (seam wired, minimal seed
  published); mirrors Zig A-ZIG-008. Non-blocking. → operator/S4.

(No new *codec* ambiguity; A-SW-002 string discipline + A-SW-007 signature-preimage carried
from S2 and held through the peer surface.)

## 7. Idiom seams (deliberate, vs the 6 prior peers)

- **`actor` concurrency** — Store/Connection/Peer are actors; the §7b store-race is a
  compile error, not a runtime crash (the unique Swift property).
- **value-type entities** — struct/enum, copy semantics, no retain cycles on the data model.
- **typed `throws(CodecError)`** — checked, value-shaped control flow; not exceptions/panics.
- **UTF-8-byte wire discipline (A-SW-002)** — held through the peer (paths, hex, peer_id).
- **zero-dep transport** — raw Glibc POSIX sockets (no SwiftNIO; the profile's dep-minimization).
- Swift API naming: UpperCamelCase types, lowerCamelCase funcs, `PeerID`/`ECF` initialisms.

## Exit criteria

Peer compiles clean (no source warnings) · reads as Swift (actor/async, not transpiled) ·
smoke 11/11 green over real TCP · S2 codec regression unbroken (69/69 corpus + 26 tests) ·
container reproducible (`--network=none`, one networked resolve) · ARC audit clean.
**S3 PASS.**

## S4-entry checklist

1. **Full §9.5 53-type registry render** (A-SW-009) — complete the field-spec declarations
   (array_of/map_of/union_of/optional/omit-empty) + byte-diff against the Go reference
   type-registry vectors (the `type_system` category). The seam is in place; this is the
   top precursor.
2. **Rebuild the Go oracle + reference peer** from go HEAD in-container (`GOWORK=off`,
   `CGO_ENABLED=0`) into `output/s4-oracles/`; verify the §7a/§10 gate symbols compiled.
3. **Run `run-s4.sh`** (`-profile core`, `--validate` ON by default): drive `connectivity`
   first (the live superset of this smoke), then `encoding`/`type_system`/`handlers`/
   `capability`/`authz`/`security`; converge to GREEN (S5 — fix the code, never the oracle).
4. **§10.1 register gate** (10 checks incl. `validate_echo_dispatch`) + **§10.2
   origination-core** (`dispatch_outbound_reentry` via `run-origination-core.sh`, reference-
   peer-gated) — the smoke proves both pre-emptively; S4 runs them under the oracle.
5. **§7b concurrency category** (5 checks) — the actor store should pass unchanged (the
   point is it's gated before ship); confirm T1.1 demux + T1.2 reentry + T1.3 head-of-line +
   T2.1 sustained + T2.2 churn.
6. **A-SW-001 Ed448** stays deferred (hybrid-FFI agility higher bar; the Ed25519/SHA-256
   floor is native + complete) — not an S4-core gate.
7. **Carry A-SW-008/A-SW-010** to the architecture handoff as v7.74/v7.75 spec-text
   candidates (peer-id §7.4→§1.5 re-point; §4.2/§5.1→§5.2a status cross-reference).
