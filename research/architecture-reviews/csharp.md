# Architectural Review & Development Log — entity-core-protocol-csharp

Running, append-per-phase log of the **composition choices** in the C# peer and the
**reasoning** behind them, plus what worked, what fought back, and the known
deviations to watch under `validate-peer`. Companion to the pre-impl
`research/evaluations/csharp.md`. Descriptive, not normative.

**Profile:** `protocol-generator/csharp/profile.toml` · **Spec:** v7.56 ·
**Runtime:** `containers/dotnet9` (net9.0 / C# 13, warnings-as-errors).

## Phase index

| Phase | Date | Outcome | Detail |
|---|---|---|---|
| S1 profile | (arch-authored) | reference profile | `profile.toml` |
| S2 codec | — | ✅ 69/69 byte-identical | `status/PHASE-S2.md` |
| S3 peer | — | ✅ smoke green (L1–L4 + foundation) | `status/PHASE-S3.md` |
| S4 verify | — | 🔶 first run — handshake fixed (connectivity 15/15, encoding 6/6); core reds open | S4 section below |

---

## The composition (what we built) and why

The peer is a single assembly, `EntityCore.Protocol`, layered bottom-up. Each layer
depends only on those below it; the dependency direction is strictly acyclic except
where transport must know dispatch (it does, deliberately).

```
Transport (sockets, framing, reader-task)  ── Peer.cs (assembly + bootstrap)
   │ depends on
Dispatch (the §6.5 chain)
   │
Handlers (connect, tree, capability) + Registry
   │
Capability (chain verify, attenuation, permissions, pattern match)
   │
Store (content store + entity tree)        Identity (peer-id, sign/verify)
   │                                            │
Model (Entity, Envelope, Execute, Ecf helpers, Hashes)
   │
Codec (S2: EcfValue, CanonicalCbor, EntityCodec)   ← unchanged from S2
```

### 1. Native codec, reused whole (S2 carry-forward)
The peer builds on the S2 native codec (`System.Formats.Cbor` Ctap2 + hand-rolled
shortest-float + explicit tag-reject). **Choice:** the peer layer never re-touches
CBOR mechanics — it composes `EcfValue` trees through `Model/Ecf.cs` helpers and lets
the S2 engine encode/decode. **Why:** keeps the byte-identity guarantee (the thing
S2 proved) in exactly one place; the peer can't accidentally diverge the wire bytes.

### 2. Value model: head-form integers + a `PreEncoded` fidelity carrier
`EcfValue.Integer(bool Negative, ulong Argument)` stores the raw CBOR head argument,
not a signed int — so the full unsigned 64-bit range survives with no `Int128` hop
(the F7 bug class can't occur structurally). `EcfValue.PreEncoded` holds
already-canonical bytes spliced verbatim at encode time. **Why this matters at the
peer layer:** every place an entity is embedded in another (params in EXECUTE, result
in RESPONSE, entities in `included`) is a `PreEncoded` splice of the inner entity's
original `WireBytes`. Fidelity (N4) and `included` preservation (N5) fall out of the
encoder for free — there is no code path that re-serializes a decoded entity on the
forward direction.

### 3. Entity fidelity: store-original, re-encode-only-to-validate
`Entity` keeps `WireBytes` (the exact `{type,data,content_hash}` bytes) for
forwarding, and validates the hash on receipt by re-encoding `{type,data}` and
comparing. The one subtlety: when we decode a *whole envelope*, the per-entity byte
boundaries are flattened, so `Entity.FromDecoded` **re-encodes** the decoded sub-map
to recover its bytes. **Why this is safe:** the envelope is decoded in strict
`Ctap2Canonical` mode, so anything that decodes is canonical, and ECF canonical form
is unique — re-encode is byte-identical to the original. Non-canonical input is
rejected at the boundary, never re-encoded. **Watch:** this assumes our whole network
is canonical (true by construction); it is the one place "fidelity" is reconstructed
rather than literally preserved. Documented in `Entity.FromDecoded`.

### 4. Everything `internal` + `InternalsVisibleTo` — public API deferred to S5
The entire peer is `internal`; the smoke and tests reach it via `InternalsVisibleTo`.
**Why:** the public surface a consumer should call (a `Peer` facade, connection
options, a results shape that doesn't leak `EcfValue`) is a *packaging* design, not a
*correctness* one. Designing it now would be guessing before we know the consumer
ergonomics (Avalonia shared-data-library case, per the profile `[interop]`). S3's job
is "does the wire path work"; that's provable with internals + smoke. **Do not** read
the all-internal surface as an oversight — it's a deliberate deferral to S5.

### 5. Error model: profile-driven exception hierarchy
`EntityProtocolException` (+ `HelloFailed`, `Authentication`) and
`EntityTransportException` (+ `RecvTimeout`/`ConnectionBroken`/`ProtocolError`
carrying the §6.12 code+status) exactly mirror the profile's `exception_hierarchy`.
**Why:** the profile mandates exceptions (not `Result`); the §6.12 transport codes
want a typed home so a consumer can `catch (RecvTimeoutException)`. Protocol-level
*request* failures (404/403) are **not** exceptions — they are normal
EXECUTE_RESPONSE status codes built by handlers; exceptions are reserved for
genuinely exceptional conditions (malformed frame, broken connection). This split
keeps the dispatch happy-path allocation-light and matches how a .NET dev expects a
server to behave.

### 6. Capability: a pure Layer-1 verdict, separable from policy (N8 / §5.10)
`ChainVerifier.VerifyCapabilityChain` consults **only** the chain and the envelope
`included` — no peer state, no local policy. **Why:** §5.10 makes the Layer-1 verdict
the cross-peer determinism contract; keeping it a static function over (chain,
included, localPeerId, now) makes that determinism auditable by inspection and
impossible to leak local state into. Layer-2 (anything a peer adds on top) lives in
the dispatcher, above the call. `Attenuation` and `Permissions` are likewise pure
functions of their inputs. **Trade-off:** `now` (temporal validity) is a Layer-1
input that is wall-clock — acceptable per §5.10 (TTL is an observable input), noted.

### 7. Dispatch: in-memory registry that mirrors the tree (§6.6)
`HandlerRegistry` holds a `pattern → IHandler` map **and** installs the
`system/handler` / `interface` / grant entities in the tree, so the §6.6 tree-walk
resolves real entities and the registry supplies the executable code. **Why both:**
the spec's source of truth is the tree (entity-native handlers exist only there);
an in-memory-only registry would be non-conformant (§6.6 "an in-memory handler
registry … is not by itself a conforming cache"). We get the O(1) lookup *and* the
tree-walk semantics. The registry's `Resolve` does the actual backward walk so the
behavior is observably the tree-walk, not a shortcut.

### 8. Transport: one reader task, write-lock on the byte-write only (N6 + N7)
`PeerConnection` runs a single reader loop that routes EXECUTE_RESPONSEs to awaiting
callers by `request_id` (a `ConcurrentDictionary<string, TCS>`), and dispatches
inbound EXECUTEs on a **separate** `Task.Run` so the reader never blocks on a handler
(N6). The write lock guards only the frame write, never the send+recv cycle, so
multiple outbound requests proceed concurrently and a handler can reenter with its
own outbound request without deadlock (N7). Per-request deadline is a linked-CTS
timer at the request layer, not a connection-wide deadline (§6.11(c)). **Why this
exact shape:** it is the reader-task pattern §6.11 names as the conformant default —
the one all three reference impls converged on after the deadlock class. Building it
this way from the start means the N6/N7 deadlock can't appear. The 8-way interleaved
smoke is the proof.

### 9. Handshake: mutual, with a fire-and-forget reverse leg
The §4.1 flow is asymmetric (initiator sends hello+authenticate; responder sends only
authenticate, having returned its hello data in the response). **Composition:** the
initiator drives hello→authenticate inline (`Handshake.InitiateAsync`); the responder
starts a fire-and-forget `RespondAsync` on accept that awaits the inbound hello (via a
`TaskCompletionSource` the connect handler completes), then sends its reverse
authenticate (E3). The initiator marks `HelloReceived=true` at the *start* of its
driver — it has sent hello, so an inbound reverse-authenticate passes §4.2 ordering
without a race. **Why fire-and-forget:** the initiator's session is usable the moment
it has its own cap (after E2/R2); the reverse leg (responder getting *its* cap on the
initiator) is independent and shouldn't block the initiator. **Watch:** the reverse
leg's failure is swallowed (best-effort); validate-peer will exercise it properly.

### 10. Store: in-memory, minimal, concurrent
`ContentStore` (ConcurrentDictionary, idempotent put) + `EntityTree` (path→hash index
with a bind-lock for atomic CAS, plus a one-level listing). **Why minimal:** §1.10
makes storage backends implementation-defined; the core peer ships memory-only (a
conformant deployment). Persistence is a later, orthogonal concern (the §6.10 emit
pathway has no consumers in a core-only peer).

---

## What worked

- **Designing the invariants in, not testing them in.** N4/N5 (PreEncoded splice),
  N6/N7 (reader-task) and N8 (pure Layer-1) were architecture decisions made before
  the first run, so the smoke passed first try rather than after a deadlock hunt. The
  conformance-invariants doc (`research/diagnostics/conformance-invariants.md`) paid
  off exactly as intended — it's a design checklist, and it worked as one.
- **Reading the whole spec first.** §1–§8 read end-to-end before writing a line meant
  the type model (Entity/Envelope/Execute/cap shapes) was right the first time; almost
  no rework. The capability algorithms (§5.2–5.7) port near-literally from the
  pseudocode — they're CONFORMANCE-class, so following the pseudocode shape is the
  safe path.
- **Incremental container compiles.** Building each layer in `dotnet9` as it landed
  caught the three small errors (below) within seconds of introducing them, never
  letting them compound.
- **The S2 codec as a frozen foundation.** Zero codec changes in S3; the byte-identity
  guarantee held with no attention.

## What fought back (friction log)

- **`Array` name collision** — a helper `Ecf.Array(...)` shadowed `System.Array`
  inside the `Ecf` class (`System.Array.Empty` needed full qualification). Trivial,
  but a reminder that terse helper names collide with BCL types.
- **`Codec.` namespace prefix didn't resolve** from `Handlers` — `Codec.EcfValue`
  reads as `Handlers.Codec.EcfValue`, not `EntityCore.Protocol.Codec.EcfValue`. Fix
  was an explicit `using`. C# parent-namespace lookup is less forgiving than it looks.
- **Double-dispose** — `await using` + an explicit teardown disposed peers twice;
  `CancelAsync` on a disposed CTS throws. Resolved with try/finally and single
  disposal. Worth a guard if `Peer` becomes public.
- **Corpus fixture mount path (not a regression)** — the S2 conformance test resolves
  the fixture by walking up from the project dir; mounting only `csharp/` (the project
  is at `protocol-generator/csharp`, the fixture at `protocol-generator/shared`) puts
  it out of reach. S2 evidently ran with the repo root mounted / `ECF_VECTORS` set.
  **Process note:** S4 (and any test run touching the corpus) must mount the repo root
  and/or set `ECF_VECTORS=/repo/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`.
  Candidate fix: make the corpus locator honor `ECF_VECTORS` first (it already does) and
  document the mount in the test harness README.

## Known deviations & watch list (standing input to S4 validate-peer)

Ordered by how likely `validate-peer` is to hit them.

1. **Handlers handler + types handler missing (A-007).** `system/handler`
   (register/unregister, **MUST** §6.9) and `system/type:validate` (SHOULD) are not
   implemented. Expect `type_system` / handler-discovery to red first. Precursor work
   before S4 is meaningful. Needs the §6.1 native-code↔manifest binding (F11).
2. **Post-established connect → 403, not 409.** A connect EXECUTE on an
   already-established connection currently falls to the authed path (no author) and
   returns 403 `missing_authorization`, where §4.2 wants 409
   `connection_already_established`. The connect handler *has* the 409 branch but the
   dispatcher's pre-auth guard (`!Established`) makes it unreachable from the wire.
   Small dispatcher fix; left for S4 to confirm against the `connectivity` category.
3. **Bounds defaults not applied (§5.9).** `bounds` is parsed but ttl/budget defaults
   (64 / 100000) and decrement-on-dispatch aren't enforced (no sub-dispatch in the
   core peer yet). Surfaces only once handlers issue derived operations.
4. **Empty-params type rejection not enforced (§3.2).** Handlers accept the
   empty-params shape but don't reject a mismatched non-`primitive/any` payload with
   400 `unexpected_params`.
5. **Nonce-echo not validated (A-008 / F12).** Authenticate signature is verified;
   the echoed nonce is not checked against a stored sent-nonce (replay).
6. **`cap:delegate`/`revoke` → 501 (A-006 / F13).** `request` only.
7. **`supports_revocation=false` (A-005).** Conformant for a core-only peer.

## Idiom assessment (does it read as C#?)

Yes. `async Task` throughout, exceptions for exceptional control flow, `record` for
value shapes (Entity sub-types, GrantEntry, Scope, ResourceTarget), file-scoped
namespaces, `#nullable enable`, pattern matching in dispatch, `required` init
properties on `HandlerContext`, `ConcurrentDictionary`/`SemaphoreSlim`/`TaskCompletionSource`
for the concurrency. XML doc on every type. A .NET dev would recognize it as a normal
async socket server, not transpiled-from-Go. The one un-idiomatic spot by necessity:
the `Ecf` helper layer (terse `Map`/`Text`/`Uint` builders) exists to keep the rest of
the peer from touching the `EcfValue` records directly — a deliberate ergonomic seam,
not a smell.

## Open questions for the eventual cross-language analysis

- Will every native peer separate the Layer-1 verdict into a pure function the way
  §5.10 pushes? (C# did; worth checking the next language doesn't entangle it.)
- The `PreEncoded`-splice approach to N4/N5 is very clean in a language with a
  splice-bytes primitive (`CborWriter.WriteEncodedValue`). What do languages without
  one do — re-encode and trust canonical-uniqueness (our `FromDecoded` fallback), or
  carry byte slices through the decoder? This is the FFI crate's option-(a) question
  resurfacing at the native layer.
- Reader-task demux (N6/N7) is natural in `async`/Task languages. The shape for a
  callback or thread-per-connection language is the open design.

---

## S4 — validate-peer (first run)

First live cross-impl conformance run: the Go oracle `entity-core-go/cmd/validate-peer`
driving the C# peer over loopback TCP. This section doubles as the **how validate-peer
works / what it covers** reference the operator asked for.

### The harness we stood up

- **Host app** — `samples/EntityCore.Protocol.Host` (new). A standalone `Exe` that
  boots one `Peer` listener and blocks until signalled — the runnable target the
  validator points at (the S3 smoke was library-only; `Peer` stays `internal`, reached
  via `InternalsVisibleTo`). Flags: `--port N`, `--debug-open-grants`.
- **`--debug-open-grants`** — threads a flag through `Peer → ConnectHandler` so
  `authenticate` mints a wide-open admin cap (`*/*/*`, `ConnectHandler.OpenGrants()`)
  instead of the §4.4 restricted standard grant. Debug-only; default stays restricted.
  *Not needed for the core gate* (the restricted grant already covers `system/type/*` +
  `system/handler/*` get and `system/capability:request`, which is exactly what
  activates the core categories) — it exists to reach grant-gated extension paths.
- **Oracle build** — `validate-peer` built `CGO_ENABLED=0` (static) in `containers/go`
  from the sibling repo's `go.work`, extracted to `output/s4-oracles/`. Runs inside the
  `dotnet9` container alongside the host (both fedora:43; peer binds loopback, so
  validator + peer must share a netns → one container).
- **Run** (the reproducible core invocation):
  ```sh
  K=<keystone-abs-path>
  podman run --rm -v "$K":/work:z -v kc-nuget:/nuget entity-core-keystone/dotnet9:latest sh -c '
    cd /work/protocol-generator/csharp
    dotnet samples/EntityCore.Protocol.Host/bin/Release/net9.0/EntityCore.Protocol.Host.dll --port 7777 &
    # wait for the LISTENING line / port, then:
    /work/output/s4-oracles/validate-peer -addr 127.0.0.1:7777 -timeout 120s -json-out /work/output/s4-oracles/report-restricted.json'
  ```
  Use an **absolute** mount path (a stray persistent `cd` makes `$PWD` drift).
  Identity is optional — omitting `-identity` uses an ephemeral keypair, fine for a
  core-only peer (open-grants and §4.4 grants don't key on identity). `framework-admin`
  matters only for the grant-gated `session`/`universal_address_space` categories.

### The minimal-core-suite taxonomy (confirmed empirically)

validate-peer has ~35 categories; the vast majority are **extensions**. The JSON report
(`severity` per check) confirmed the three mechanically-distinct groups:

1. **Grant-gated extensions → SKIP cleanly** with the restricted §4.4 grant. Verified
   SKIP: `capability`*, `tree_operations`, `subscriptions`, `continuations`, `revision`,
   `auto_version`, `clock`, `history`, `query`, `local_files`, `compute`,
   `entity_native`, `origination` (no `-reference-peer`), `serving_mode` (no `-poll-url`),
   `session` (7S), `universal_address_space` (8S). No action — they gate themselves off.
   *(\*`capability` SKIPped unexpectedly — see Finding 5.)*
2. **Core gate → activates from the §4.4 minimum.** `connectivity`, `encoding`,
   `type_system`, `handlers`, plus the always-on negative suites `security` + `multisig`.
   This is the real bar (`origination` joins it once a reference peer is wired).
3. **Unconditional extension categories → spurious FAIL** (they `TreeGet
   system/handler/system/<ext>`, the grant authorizes it, the path 404s):
   `attestation` (15F), `quorum` (15F), `identity` (23F), `role` (25F),
   `behavioral_role` (27F), `behavioral_v33` (4F), `type` (18F), `content` (8F),
   `durability` (14F), `transport_family` (1F). **Exclude these from a core verdict**
   (`-exclude attestation,quorum,identity,role,behavioral_role,behavioral_v33,type,content,durability`)
   — note `-exclude` is report-level (they still execute), so prefer per-`-category`
   runs for a clean core read.

### First-run scoreboard (restricted grant, full suite)

```
connectivity   15P              ✅   (after the §4.1 fix below)
encoding        6P              ✅   S2 codec holds on the wire
type_system     1P / 295F       ❌   no type registry in the tree   (Finding 2)
handlers        8P / 5W / 34F   ❌   manifests mostly absent/shape  (Finding 3)
security       10P / 5F         🔶   enforces, but 401≠403          (Finding 4)
multisig        1P / 9F         ❌   HANGS 60s/check (9 min total)  (Finding 1)
capability        1S            ⚠️   grant-shape skip               (Finding 5)
<grant-gated>     SKIP          —    extensions, correctly skipped
<uncond. ext>   spurious F      —    excluded from core verdict
```

### Findings

**Finding 0 — §4.1 reverse-leg ordering (FIXED).** First red was `connectivity`
`authenticate_response_status: status 0`. §4.1 is a mutual 3+3 handshake; the responder
sends a reverse `authenticate` (leg 3) — but *after* writing the leg-2 response to the
initiator's authenticate. The C# peer fired the reverse leg on **accept** (gated only on
the inbound hello), so leg 3 raced ahead of leg 2's response, and the *sequential*
validator read the EXECUTE where it expected its EXECUTE_RESPONSE (an EXECUTE has no
status → 0). Invisible to the C#↔C# smoke because `PeerConnection` demuxes by
`request_id`. **Fix:** added `ConnectionState.AuthResponseSent`, raised in
`PeerConnection.DispatchInboundAsync` *after* the establishing authenticate's response
is written; `Handshake.RespondAsync` now awaits it before sending leg 3.
→ connectivity 6→15/15, smoke still green.

**Finding 1 — multi-sig caps HANG the peer (robustness; highest severity).**
`multisig` ate **9 minutes**: every check involving a multi-sig *granter* structure
(threshold/signers) → `i/o timeout` at 60s, connection left open, **no response**. The
peer doesn't support multi-sig (out of core scope, fine) but must **reject fast**, not
hang. Mechanism: a non-single-sig `Granter` almost certainly throws deep in
`CapabilityToken`/`ChainVerifier` on a path that yields no EXECUTE_RESPONSE yet doesn't
tear the connection down. A hang is worse than a wrong code (DoS surface). *Fix
direction:* make granter parsing total — unknown/multi-sig granter → `400`/`403`, never
an unhandled throw that swallows the response. The dispatcher should also guarantee
*some* response (or a clean close) for any inbound EXECUTE.

**Finding 2 — no type registry materialized in the tree (the headline build item).**
`type_system` 1P/295F: `types_listing_available` aside, every `system/type/<name>` fetch
404s. The peer installs handler/connect/capability entities but publishes **no
`system/type/*` TypeDefinition entities**. The validator builds a local registry of all
core + handler types and fetch-compares each. *Fix:* materialize a core type registry
into `system/type/` at bootstrap (definitions + the `system/type/` listing). This is the
single largest body of S4 work and pairs with the types handler (A-007).

**Finding 3 — handler manifests absent / wrong shape.** `handlers` 8P/5W/34F:
`system/handler/` listing 404s; installed-handler entities are the *wrong type/shape*
(e.g. `handler_tree_interface_type` got `system/tree/listing` not
`system/handler/interface`; `pattern=""`). The bootstrap installs handler entities but
not as the `system/handler/interface` manifests §6.9 specifies, and the handlers handler
(register/unregister, A-007) is absent. *Fix:* implement the §6.9 handlers handler +
emit conformant `system/handler/interface` manifests at bootstrap.

**Finding 4 — authorization failures return 401, validator expects 403 (status code).**
`security` 10P/5F — the peer **correctly rejects** all 15 forgeries (enforcement works),
but 5 signature-integrity cases return **401** where the oracle wants **403**:
`capability_not_in_included`, `signature_wrong_target`, `signer_author_mismatch`,
`tampered_signature`, `grantee_author_mismatch` (all V7 §5.2). The C# request-verify path
returns 401 for signature failures; §5.2 + the oracle treat request-time cap/signature
failures as **403** (authorization), reserving 401 for connection-time authentication.
*Fix:* return 403 for §5.2 request-verification failures. (Likely also a spec-clarity
item — the 401/403 boundary between §4.6 connect-auth and §5.2 request-auth is worth an
explicit statement → arch.)

**Finding 5 — `capability` category SKIPs (grant-shape nuance).** The restricted grant
*does* include `system/capability:request`, yet the category SKIPped
("does not advertise system/capability:request"). The C# capability grant sets
`Resources: Scope.Empty`; the oracle's `grantsAllow(…, "system/capability", "", "request")`
appears to read empty-resources as "covers nothing" rather than "resource-agnostic".
Minor (SHOULD-level handler) but a real grant-encoding question: does an operation with
no resource target want `Resources: ["*"]` or an explicit agnostic marker? → log + watch.

**Finding 6 — residual reverse-leg (leg 3) corrupts the first post-handshake read.**
The §4.1 fix orders leg 3 *after* leg 2's response, so the handshake passes — but the
peer *still proactively sends* leg 3 to the validator, which lands as the validator's
**first** post-handshake read (`type_system` `types_listing_available: status 0` — a lone
status-0 amid 404s). The validator's handshake never consumes leg 3 and its category
loop isn't a demuxer. Open question for arch: **does a responder proactively push the
reverse authenticate to a client-style initiator at all?** The reference peers pass the
full suite, which implies either the responder does *not* unilaterally send leg 3, or the
initiator must demux it — and validate-peer doesn't. *Fix direction (pending arch read):*
make the reverse/mutual leg initiator-driven (don't push leg 3 from `RespondAsync`), or
gate it on evidence the peer is a full peer. Costs exactly one check today; flagged
before it masks a real type-listing result.

### What this run proved about the loop

The oracle did exactly its job: a §4.1 ordering bug that *no self-test could surface*
(the C# demuxing client tolerates it) fell out on first contact with a sequential
reference client, traced cleanly to a spec MUST, fixed in three small edits. The
remaining reds are honest scope (type registry, handler manifests, handlers handler) +
two status/robustness items + two spec-interpretation questions for arch (401/403
boundary; responder-pushed leg 3). None are codec regressions — encoding held 6/6.

### Classified & handed to architecture

All six findings are classified (IMPL / AMBIGUITY / SPEC-ISSUE / ORACLE) in the
S4 request-to-architecture under `research/stewardship/`. Two corrections this run
made to the framing above, both vindicating "classify before conforming":

- **`type_system` 295F is mostly the *oracle*, not the peer.** `validate-peer`'s
  `RegisterCoreTypes` (`core/types/core.go`) registers ~250 **extension** type-defs as
  "core" (compute/subscription/continuation/clock/content/query/durability/type-ext/
  multi-granter). A core-only v7.56 peer must not publish those. The genuine IMPL gap is
  the ~40 core type-defs (peer publishes none). → arch ask A3.
- **`capability` SKIP is an oracle bug — the peer is correct.** §5.2 line 2006 explicitly
  blesses the empty-`resources` grant the peer uses for the capability handler;
  `validate-peer`'s gate treats empty-resources as "covers nothing" and skips. → arch ask
  A4. And **multi-sig (F1)** is "pending V7 absorption" (changelog L3345; granter is a
  single `system/hash` in v7.56 §3.6) — the `multisig` category runs ahead of the pinned
  spec (the peer-side hang is still our IMPL bug to fix). → arch ask A2.

Next session, after arch rules A1–A5: fix the IMPL set (multisig-hang robustness, core
type registry, handler manifests + §6.9 handler), rerun, drive the core gate green. Hold
the 401→403 (F4), empty-resources (F5), and leg-3-push (F6) changes pending the rulings.

*Append the next S4 iteration below when the reds are worked.*

---

## Packaging & publishing review (NuGet)

Reviewed ahead of S5 (we are **not** publishing yet — see the cross-language
publishing-seam review). NuGet specifics for this peer:

- **Consumable artifact ≠ this dir.** A published `.nupkg` is the `EntityCore.Protocol`
  assembly (`net9.0`) + README + LICENSE. **Cleaner default than npm:** `dotnet pack`
  packs only the library project; the `samples/` (Host/Smoke) and `test/` projects are
  separate and not packed — no allowlist surgery needed.
- **Publish path (S11-aligned):** **OIDC trusted publishing** on nuget.org — GitHub
  Actions with `id-token: write` calls `NuGet/login` to exchange the OIDC token for a
  **short-lived (~1h), single-use API key**, then `dotnet nuget push`. No stored API
  key. nuget.org applies **repository signing**; author signing optional.
- **Naming:** id `entity-core-protocol-csharp` (NuGet id may hyphenate; the C#
  assembly/namespace stays `EntityCore.Protocol`). Reserve the **`EntityCore.*` ID
  prefix** on nuget.org to block namespace squatting.
- **Consumer story:** `dotnet add package entity-core-protocol-csharp; using
  EntityCore.Protocol;`. The original consumer driver (Avalonia v1) wanted the
  *shared-data-library* lower bar (codec + types), which the S2 codec already satisfies
  byte-identically — a narrower `EntityCore.Protocol.Codec` package could ship ahead of
  the full peer if a consumer wants just that.
- **Account/signup:** nuget.org via a Microsoft account; 2FA; configure a trusted-
  publishing policy.

Same forcing function as TS: trusted publishing + provenance/signing wants a **public
CI repo** as the publish source — the S10 monorepo-vs-per-repo fork. Default stays S10
(no publish) until a trigger fires. See the seam review for the three options.
