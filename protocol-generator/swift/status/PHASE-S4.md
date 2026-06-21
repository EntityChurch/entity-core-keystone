# entity-core-protocol-swift — Phase S4 (Conformance) Summary

**Status: COMPLETE — `validate-peer --profile core` PASS, 0 FAIL
(573 · 288P · 196W · 0F · 89skip); §10.1 register 10/10; §10.2 reentry 3/3; §7b concurrency 5/5.**

Peer #7 (Swift). S4 drove the live Go oracle (`749e57e`) from the S3 baseline **573 · 177 fail**
to the core verdict **573 · 288 pass · 0 fail → PASS**, machine-verified (`summary.failed == 0`).
Same fixed point as the six prior peers, reached **spec-first** (peer behavior derived from
spec-data/v7.74 + cross-checked against the OCaml/Zig sibling sources only for the structural
type-floor enumeration + §7a/§7b contract, never for protocol semantics). Full scoreboard in
`CONFORMANCE-REPORT.md`; raw JSON in `CONFORMANCE-REPORT.json`.

## Iteration: the 177→0 fix set

**~8 iterations** (one rebuild+rerun per fix cluster). 9 load-bearing changes — split below into
**protocol-correctness** (the behavior was wrong/absent against the spec) vs **Swift-mechanics**
(a Swift-runtime/idiom defect, not a protocol error). The S2 byte-green codec held throughout
(zero codec changes); every fix was peer-machinery.

### Protocol-correctness fixes (7)

1. **`entity://` URI normalization (§1.4) — type_system 0→108, tree_operations −20, the headline.**
   The validator addresses every EXECUTE `uri` and resource target as `entity://{peer_id}/rest` (the
   universal-address-space scheme form). Swift's `canonicalize` didn't strip the scheme, producing a
   garbled `/{peer}/entity://{peer}/...` path → resolveHandler 404 on **all** tree/type ops. Added
   `Capability.normalizeURI` (mirrors OCaml `normalize_uri`); folded into `canonicalize`. This single
   fix unblocked type_system (108), tree_operations (24), uas (8), peer_canon (7) at once — the smoke
   had used bare `system/tree`, so the scheme gap was latent until the live oracle. **(peer bug)**

2. **Full §9.5 53-type registry render (A-SW-009) — type_system byte-correctness.** Replaced the S3
   minimal seed with the complete FSpec/TypeDef render-from-model builder (`TypeRegistry.swift`): the
   53 floor types declared in-code, rendered through the byte-green S2 codec, omit-empty. Byte-diffs
   **53/53 byte-identical** to the Go vectors (`TypeRegistryTests`, offline) AND passes live (108/108).
   First-run clean — the codec being byte-green meant the only risk was field-shape data. **(peer gap)**

3. **Tree put/get/listing shape (§6.3/§3.9) — tree_operations.** Put now reads the entity from
   `params.data.entity` (a `system/tree/put-request`), recomputes the content_hash, honors §3.9 CAS
   (`expected_hash` → 409 on mismatch, zero = create-only), and returns the bound `system/hash`. Get
   handles `mode=hash`, empty-resource → peer-root listing, and `pathFlexOK` (§1.4 / CORE-TREE-PATH-FLEX-1
   reject of null-byte / non-peer-id-leading-slash / `.`/`..`/`//`). Listing now builds `entries` as a
   **map** of `listing-entry` with `count`/`offset`/`path` (was a bare array) and omits deletion-marker
   leaves (CORE-TREE-DELETE-1). **(peer gaps)**

4. **Handler interface operation-sets (§6.2) — handlers `*_operations_match`.** The bootstrap handler
   interfaces now publish their `operations` map (connect={hello,authenticate}, tree={get,put},
   capability={request,delegate,revoke,configure}, …) as the §6.2 op-spec data map. **(peer gap)**

5. **author-from-included only (§5.2) — security `author_not_in_included`.** verify_request resolved
   the author entity with a store fallback; the §3.3 contract is that the author identity travels in
   `included` on the wire. Removed the fallback → author absent from included = 401, not 200. **(peer bug)**

6. **§5.5 verdict precedence + revocation + negotiation + agility (a cluster).**
   - `authz_grantee_1`: moved the §5.2 `grantee==author` check to AFTER `verifyChain` so the per-link
     **unresolvable-grantee 401** (PR-3 carve-out) takes precedence over the grantee-mismatch 403.
   - `authz_revoked_core_1`: added the §5.1 `is_revoked` marker check (leaf cap hash + chain-root hash
     at `system/capability/revocations/{hash}`) → 403 capability_denied (RULING-CLASS-C member).
   - `negotiation` (4): the hello response now advertises non-empty `hash_formats`/`key_types`
     accept-sets (NEGOTIATE-*-1 a), and a hello with disjoint advertised sets is rejected 400 up front
     (NEGOTIATE-*-1 b).
   - `format_agility agility_unknown_1`: an unsupported `key_type` at authenticate → 400
     `unsupported_key_type` — checked in all THREE carriers (the key_type field, a non-32-byte
     public_key, AND the claimed peer_id's leading key_type byte, the `0xfd` case where the field still
     reads "ed25519"). Mirrors OCaml's three-way reject. **(peer gaps)**

7. **capability revoke/configure validation (§6.2/v7.62) — capability.** revoke rejects an all-zero
   token (400), configure rejects a partial-prefix `peer_pattern` (only `default` / full 66-char hex /
   full Base58 peer_id accepted; `00abc*` → 400 invalid_peer_pattern). **(peer gaps)**

### Swift-mechanics fix (1, the most interesting)

8. **§7b `t2_2_connection_churn` — dedicated OS thread for blocking I/O (the actor-idiom trap).** The
   S3 transport ran every blocking `readFrame()`/`accept()` on a `Task.detached` — i.e. on Swift's
   **bounded cooperative thread pool** (≈ core count). A blocking `read()` *pins* one pool thread for
   its entire idle wait. Under connection churn, every pool thread ends up parked in a blocking syscall
   → new accepts/reads can't get a thread → `i/o timeout` (cycle 8). The Swift-idiomatic-looking
   `Task.detached { blockingRead() }` is exactly the wrong shape for blocking syscalls. Fix:
   `onBlockingThread` runs each blocking call on a fresh `Thread` (the raw-socket analogue of the
   cohort's thread-per-connection), keeping the cooperative pool free; + a churn-prune of finished
   connections. **Result: concurrency 60s-timeout → 3.0s, 5/5 PASS.** This is the Swift-specific §7b
   finding (distinct from Zig's store-race and TCP_NODELAY): *structured concurrency's bounded pool is
   hostile to blocking I/O; offload to dedicated OS threads*. **(Swift-mechanics — a runtime-model
   defect, the protocol logic was correct.)**

### The §7a dispatch-outbound contract (t1_2, both peer-correctness AND idiom)

9. **`dispatch_outbound_reentry` / `t1_2_concurrent_reentry` — value-passthrough + in-band entities.**
   The S3 handler double-wrapped the echo value as `{value: value}` (echo then returned a map; the
   validator's `result.value` decode wants a bare scalar — the §7b t1_2 cohort-contract pin), AND read
   the reentry authority as hash references. Rewrote to the cohort contract (verified against OCaml):
   the `value` field IS the outbound params data (passed THROUGH, no re-wrap), and the reentry cap /
   granter peer / cap signature ride **as full materialized entities nested in params** (Go ruling (a),
   in-band), which the handler bundles into the outbound EXECUTE's `included`. **(peer bug — same one
   all six prior peers hit; the value-blind §7a probe hid it until t1_2.)**

## §9.5 registry render — how it was built

`TypeRegistry.swift` declares the 53 floor types as value-type `TypeDef`s, each field an `FSpec`
(`type_ref` / `array_of` / `map_of` / `union_of` / `optional` / `byte_size`, exactly one structural
carrier set, omit-empty). `FSpec`/`TypeDef`/`FSpecBox` are `Sendable` (Swift 6 strict concurrency
requires it for the static `allTypes` table; `FSpecBox` is a `final class Sendable` with an immutable
`let value` for the value-type recursion). Each type renders through `Model.make` → the byte-green S2
codec; the resulting 32-byte SHA-256 digest is diffed per-type against `type-registry-vectors-v1.cbor`
in `TypeRegistryTests` (an offline `swift test` gate, run before the live type_system run de-risks it).
Structural enumeration ported from the cross-blessed Zig/OCaml registry (a fixed language-agnostic
floor); the rendered bytes verified independently. **53/53 byte-identical, first run.**

## §10.1 / §10.2 / §7b results

- **§10.1 core-register gate: 10/10 PASS** (incl. `validate_echo_dispatch` + the §3.4 grant-sig at
  the invariant pointer, enforced both ways; unregister symmetry). The §3.4 placement was already
  correct from S3 (`system/signature/{grant_hash}`); the gate exercised it live.
- **§10.2 origination-core: 3/3 PASS** over real two-peer TCP (`run-origination-core.sh`, Go
  `entity-peer --open-access` reference B-role) — `dispatch_outbound_reentry` proves the §6.11 reentry
  seam on the wire (validator-as-B over the same inbound connection, no third-peer dial).
- **§7b concurrency: 5/5 PASS** (3.0s) after the dedicated-thread fix.

## New spec findings (this phase)

**None new.** Every FAIL traced to peer machinery the S3 build hadn't yet implemented (the registry,
the `entity://` normalization, the tree/listing/put shapes, the negotiation surface, the §5.5 verdict
precedence, the §7a contract) or a Swift-runtime defect (the t2_2 blocking-I/O pool exhaustion) — not
spec contradictions. The S3 escalations carry forward unchanged:
- **A-SW-008** (§7.4-vs-§1.5 peer-id) — validated live: the §1.5 identity-multihash construction is
  correct against the oracle (connectivity 22/22 + peer_canon 7/7); the stale §7.4 SHA-256 form would
  fail handshake. **Fourth peer** to corroborate (OCaml A-OC-007 / Zig A-ZIG-001). → arch.
- **A-SW-010** (§4.2/§5.1 "403" vs §5.2a 401/403) — validated: built to §5.2a; security/authz all
  green against the oracle (401 author-absent, 401 unresolvable-grantee, 403 deny-default). → arch.
- **A-SW-009** (53-type registry) — **RESOLVED** this phase (byte-diff clean).
- **A-SW-001** (Ed448) — stays deferred (not a core gate; the Ed25519/SHA-256 floor is native + complete).

## Idiom seams exercised at S4

- **`actor` store** — §7b store-safety is a compile-time guarantee (no runtime race possible).
- **dedicated OS threads for blocking I/O** — the Swift-specific §7b lesson: structured concurrency's
  bounded cooperative pool must NOT carry blocking syscalls (generator guidance for any actor/async
  target that does raw blocking sockets).
- **`Sendable` static type tables** — the registry's value-type `TypeDef`/`FSpec` table needed explicit
  `Sendable` conformance under Swift 6 strict concurrency.
- **typed `throws(CodecError)`** + value-type entities held through the peer surface.

## Exit criteria

`--profile core` PASS, 0 FAIL · §10.1 10/10 · §10.2 3/3 · §7b 5/5 · 53-type byte-diff clean ·
warns/skips are the documented non-floor / §9.0-carve-out classes · in-container reproducible
(`run-s4.sh` / `run-origination-core.sh`, `--network=none`) · no codec/smoke regression · no new
spec ambiguity. **S4 PASS.** Next: S5 packaging.
