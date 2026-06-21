# entity-core-protocol-php — Phase S3 (Peer Machinery) Summary

**Release "reach" peer** · **2nd dynamic/scripting peer**
(after Ruby #12) · **Status: COMPLETE — two-peer loopback 12/12, 53/53 type
registry, genuine §3.6 K-of-N accept-path GREEN; full suite OK (28 tests, 327
assertions, 0 failures, 0 deprecations).**

## Result: the S3 gate is GREEN

| Gate | Result |
|---|---|
| **Two-peer loopback** (real TCP, full §6.5 chain, one event loop) | **12/12 PASS** (strict superset of the 11/11 cohort gate) |
| **53/53 core type-registry** (§9.5 render-from-model, bound + deterministic) | **53/53 PASS** |
| **Genuine §3.6 M3 K-of-N multisig — ACCEPT path** (2-of-3 → ALLOW + M3/M4/M6 deny flips + single-sig superset) | **PASS** (275 assertions) |
| **S2 wire-conformance corpus (v0.8.0)** — unregressed | **69/69 PASS** |
| **Full PHPUnit suite** | **OK (28 tests, 327 assertions), 0 deprecations** |

Run with `./run-s3.sh` (sealed-offline `--network=none`; loopback is
intra-container localhost, so the WHOLE gate stays dependency-sealed). Image
`entity-core-keystone/php-toolchain:latest`.

## The two "build it right the first time" mandates — GENUINELY built

### 1. Genuine §3.6 K-of-N multisig WITH a passing accept-path test

`Capability::verifyMultiSigRoot` implements the real union granter (single
`system/hash` ByteString | `{signers, threshold}` map, **root-only**): §3.6 M3
structure check (parent null, n≥2, 2≤threshold≤n, distinct signers) runs **BEFORE**
signature counting (precedence 25); then §5.5 M6 (local ∈ signers) + M4 (count of
**DISTINCT** signers with a valid sig over the cap content_hash ≥ threshold — the
K-of-N replay defense; a duplicate signature from one signer does NOT inflate).
Multi-sig is root-only (off-root → DENY); the single-sig path is a byte-identical
strict superset. `MultiSigCapabilityTest::testMultiSigKofN` exercises the **ACCEPT
path** (2-of-3 → ALLOW) plus every deny flip (below-threshold M4, dup-sig-no-inflate
M4, local-not-in-signers M6, threshold=1 M3, dup-signers M3, off-root M3) and the
single-sig superset — the direction the rejection-only validator can't cover.

### 2. §6.11 reentry-capable transport + §7a conformance handlers UP FRONT

The transport (`EventLoop` + `Io` + `Transport`) is reentry-capable from the start:
an inbound EXECUTE handler can originate an outbound EXECUTE back to the caller
**over the same inbound connection** (`$conn->outbound` pumps the loop until the
reply correlates by request_id). The two §7a handlers `system/validate/echo` +
`system/validate/dispatch-outbound` are built (opt-in via the `Peer::create`
`conformance` flag + host `--validate`, **OFF by default**); `dispatch-outbound`
originates back to the caller over the inbound connection (validator = B-role on
the same connection — NOT a third-peer dial). The smoke proves the full B→A reentry
round-trip over real two-peer TCP (outer 200; the inner 403 is expected — the smoke
passes the session cap, and S4's validator supplies the cross-peer reentry cap that
makes the inner verdict 200, exactly as the `dispatch_outbound_reentry` S4 gate
needs). This avoids the from-zero transport rewrite that bit OCaml/COBOL.

## `--name NAME` persistent identity — WORKING

`bin/peer --name NAME` loads the Ed25519 seed from
`~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed between
BEGIN/END ENTITY PRIVATE KEY lines). Verified end-to-end: a provisioned
`conformance` keypair (seed `0x11`×32) boots, prints `LISTENING <port>` + `PEER
2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`, and the peer_id has **parity** with
the seed-0x11 identity — the cohort conformance peer_id the S4 multisig accept-path
oracle co-signs as.

## Full §6 dispatch surface built (`protocol-generator/php/src/`)

- **Transport (L4):** `EventLoop` (single-thread `stream_select`), `Io` (framed
  non-blocking IO + §6.11 request_id demux + loop-driven outbound), `Transport`
  (listener + dialer), `Listener`, `Session` (initiator handshake + `executeAsync`
  /`awaitAll` for the 8-way demux), `Conn`, `Wire` (framing §1.6 + EXECUTE/RESPONSE
  builders, MAX_FRAME 16 MiB).
- **Dispatch (§6.5):** `Peer` — bootstrap (§6.9), §6.9a peer-authority seed policy
  (self-owner cap at L0 + detached-sig + default scope-template, dual-form lookup at
  authenticate), the §6.5 chain (ingest sigs → §5.2 verdict trichotomy + §4.10(b)
  chain-depth pre-check → resolve §6.6 → §5.2 checkPermission → handler), entity-
  native dispatch, §6.13(b) outbound seam.
- **Handlers:** `ConnectHandler` (§4.1/§4.6 hello+authenticate, 3-check PoP, §4.5
  negotiation, §4.6 key-type/pubkey hardening), `TreeHandler` (get/put + §3.9 CAS +
  listing w/ deletion-marker filter), `HandlersHandler` (register = 5 writes incl.
  grant-sig at `system/signature/{grant_hash}`, unregister), `CapabilityHandler`
  (request/delegate/revoke/configure + §5.6 attenuation-bounded mint), `TypeHandler`
  (extension), `EchoHandler` + `DispatchOutboundHandler` (§7a).
- **Capability (L3):** `Capability` (§5.4 patterns, §5.2 verifyRequest/
  checkPermission, §5.5 chain-walk + per-link §PR-8 granter-frame, §5.6 attenuation,
  §5.7 caveats, §5.1 revocation, §4.10(b) `chainExceedsDepth` structural pre-check,
  genuine §3.6 multisig), `Verdict`/`RequestVerdict` enums.
- **Foundation:** `Store` (content+tree, §6.10 emit hook live with 0 consumers,
  §4.8 race-safe by single-thread construction), `Entity`, `Envelope` (included
  dedup + key=content_hash invariant), `Identity`, `CoreTypes` (53-type §9.5 floor
  render-from-model), `Ecf`/`PeerHelpers` helpers.
- **Host:** `bin/peer` (`--port`/`--seed`/`--name`/`--validate`/`--debug-open-grants`).

## v7.75 substrate floor — baked in (not rediscovered)

- **§4.8 store-safety:** STRUCTURAL — the single-thread event loop has no
  concurrency to race (no lock; one handler runs to completion before the next is
  dispatched). The cleanest store-safety story in the cohort.
- **§4.10(a) max-payload → 413 / connection close:** the 4-byte length prefix is
  checked against MAX_FRAME (16 MiB) BEFORE the body is buffered (`Io::drainFrames`).
- **§4.10(b) chain-depth → 400 `chain_depth_exceeded`:** one structural
  `chainExceedsDepth` pre-check (walks parents, no sig work) BEFORE the per-link
  authz walk; an unreachable parent stays 403 (not a depth fault) — the one net-new
  cohort-wide v7.75 piece, inherited correctly.
- **§5.2 verdict trichotomy:** 401 (AuthnFail) / 403 (AuthzDeny) / 400 (ChainTooDeep)
  + the §5.5 unresolvable-grantee → 401 carve-out (`UnresolvableGranteeException`).
- **§7b:** TCP_NODELAY best-effort (ext-sockets-guarded; A-PHP-010); §4.9 resilience
  is structural (non-blocking multiplexed sockets — a slow/closed peer never blocks
  the others; a malformed frame closes only its own connection).

## Head-form (A-PHP-003) crossed into peer logic — handled

Every head-form value the peer compares (thresholds, temporal bounds, the §4.10
chain-depth/payload bounds) is normalized to `\GMP` via `Ecf::uint` and compared
with `gmp_cmp` — NEVER a blind `(int)` cast past PHP_INT_MAX. Content-hash map keys
are `ByteString` (the major-2 seam); `data` is read as an arbitrary ECF value
(`EcfMap`/scalar) through `Entity::data()`/`field()`, never assumed a map
(A-JAVA-010).

## Ambiguity log

3 new entries (A-PHP-009..011), all `operator`-scoped, **no new spec defect**: the
single-thread event-loop idiom (A-PHP-009), best-effort TCP_NODELAY (A-PHP-010),
PSR-4 per-file handler classes (A-PHP-011). S3 is corroboration-only — it matches
the freshest reference peers (cpp/kotlin/ruby) and the inherited cohort findings.

## What S4 must watch

1. **`ext-sockets` absent in the image** → TCP_NODELAY is a guarded no-op
   (A-PHP-010). Correctness is unaffected; if a §7b throughput gate ever needs
   NODELAY, add `ext-sockets` to the Containerfile (one line).
2. **The reentry inner verdict is cap-gated.** The smoke's inner echo verdict is
   403 because it passes the session cap, not a cross-peer reentry cap. S4's
   validator supplies the cross-peer cap that flips the inner to 200 — the
   `dispatch_outbound_reentry` gate. The transport seam (outer 200) is proven.
3. **`--name` keypair provisioning** for the multisig accept-path: the oracle
   co-signs AS the peer, so `run-s4` must provision `~/.entity/peers/conformance/
   keypair` (seed `0x11`×32 → peer_id `2KHoAk…`) and start `--name conformance`.
   The load path + peer_id parity are verified at S3.
4. **Single-thread parallelism caveat (A-PHP-009 / §7b T1.1):** the loop interleaves
   connections + correlates out-of-order replies (T1.3 head-of-line, the 8-way demux)
   but is NOT multi-core parallel — like TS, a §7b `t1_1_concurrent_demux` ratio
   ceiling that demands parallel speedup may not be met by a single-threaded peer
   (it passes head-of-line; it just gets no multi-core gain). Flag if S4 gates on it.
5. **Ed448 stays deferred** (A-PHP-002) — the §7a/§7b core gate is the Ed25519+
   SHA-256 floor; do not pull ext-ffi.
6. **The 53-type floor is render-from-model**, not byte-pinned vs the canonical
   type-registry vectors yet — the byte-exact `type_system` diff is the S4 item
   (S3 proves render+bind+determinism).

## No sacred-tree writes

All work is confined to `protocol-generator/php/` in the `lang/php` worktree. No
writes to the primary keystone, the meta-rooted clone, or `entity-core-go`. No
container build inside `entity-core-go` (S3 doesn't need the Go oracle — that's S4).

## Exit criteria

Two-peer loopback 12/12 GREEN · 53/53 type-registry GREEN · genuine §3.6 K-of-N
accept-path PASS · S2 codec 69/69 unregressed · all src lints clean (`php -l`) ·
full suite OK (0 failures, 0 deprecations) · `--name` identity-load + peer_id parity
verified · ambiguity log has no blocking items. **S3 PASS.**
