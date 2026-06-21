# PHASE-S3 — entity-core-protocol-kotlin peer machinery

**Status: COMPLETE (smoke GREEN, peer compiles clean, idiom reviewed). Left UNCOMMITTED
for orchestrator gate.**

S3 builds the V7 Layer 1–4 + foundation peer machinery on top of the S2 codec (still
69/69 byte-identical). Native Kotlin idiom per `profile.toml`: sealed/`enum`-class
verdicts matched by exhaustive `when`, `data class` value types, kotlinx.coroutines
`suspend` dispatch + reentry, JDK SunEC crypto. The Java peer (`protocol-generator/java/`)
was the JVM analog model; this is an INDEPENDENT Kotlin reading (coroutines vs Java
threads; sealed-result `Outcome` vs checked exceptions).

## What was built

Peer layer in `src/main/kotlin/org/entitycore/protocol/peer/` (12 files, ~2.7k LOC) +
`crypto/EdKeyDerivation.kt`:

| Surface | Files | Notes |
|---|---|---|
| **L1 Identity** | `Identity.kt`, `crypto/EdKeyDerivation.kt`, `Ed.rawPublicKeyFromSeed` | §1.5 identity-multihash peer_id from RAW pubkey; seed→pubkey net-new at S3 (A-KT-009) — pure-JDK RFC-8032 derivation, cross-checked vs SunEC + the handshake. system/peer + system/signature integrated with the codec. |
| **L2 Interaction** | `Wire.kt`, `Envelope.kt`, `Entity.kt`, `Dispatch.kt` | EXECUTE / EXECUTE_RESPONSE only (§3.3); typed builders/parsers; 4-byte-BE length-prefix framing; §6.11 request_id demux; §4.10(a) 16 MiB max-frame reject before body buffer. `included` content_hash-MAP dedup on emit (A-KT-010). |
| **L3 Capability** | `Capability.kt` | §5.2 verifyRequest (3-way verdict `enum`), §5.5 chain-walk + sig verify, §5.6 attenuation, §5.7 caveats, §5.1 revocation, §PR-8 granter-frame, §4.10(b) `chainExceedsDepth` pre-check (→ 400, distinct from 403). **Genuine §3.6 M3 multi-sig K-of-N** (granter union; M3 structure before sig counting; §5.5 M6 local∈signers + M4 distinct-signer quorum; root-only). |
| **L4 Bootstrap** | `Transport.kt` | TCP listener + dialer; **kotlinx.coroutines + dedicated reader OS threads** (§7b: blocking read off the cooperative pool; TCP_NODELAY); §4.8 inbound-concurrent-with-outbound (per-EXECUTE coroutine); §6.11 reentrant transport with `ConcurrentHashMap<requestId, CompletableDeferred>` demux. |
| **Foundation** | `Store.kt`, `Dispatch.kt`, `Peer.kt`, `CoreTypes.kt` | content store + entity tree (§1.7); §6.10 emit pathway (live with zero consumers); §6.6 handler resolution; `Handler` interface (`suspend`); the §6.5 dispatch chain; 53-type §9.5 core floor. |
| **Handlers** | `Peer.kt` inner classes | connect (hello/authenticate), tree (get/put), handler (register/unregister — §6.13(a) live), capability (request/delegate/revoke/configure), type (validate). |
| **§6.9a bootstrap** | `Peer.kt` | self-owner cap (detached-sig L0) + default scope-template; authenticate dual-form policy lookup ∪ §4.4 floor; `--debug-open-grants` = degenerate `default→*`. |
| **§7a conformance** | `Peer.kt` (`--validate` opt-in, OFF by default) | `system/validate/echo` + `system/validate/dispatch-outbound` (the §6.11 reentry originator). |
| **Host** | `Host.kt` (`application` plugin) | S4-ready: `--port`/`--seed`/`--name`/`--debug-open-grants`/`--validate`; prints `LISTENING <port>` + `PEER <id>`; `--name` loads the on-disk PEM keypair (multisig accept-path probe). |

## Gates (all GREEN, container-bound `entity-core-keystone/kotlin-toolchain:latest`)

Run via `./run-s3.sh` (smoke; loopback netns) / `./run-s3.sh units` (sealed-offline) /
`./run-s3.sh all`.

- **Two-peer loopback smoke — 12/12 PASS** (`SmokeTest`, real TCP between two Kotlin peers):
  handshake both legs; unregistered→404; granted tree-get→200; capability request→200;
  **8/8 request_id demux** (N7); register live-hook→200 (not 501); emit hook fires on
  register's tree writes (§6.13(c)); §7a echo→200 + verbatim; **§6.11 dispatch-outbound
  reentry round-trips over the inbound connection** (B→A echo, outer 200; inner verdict =
  A's §5.2 cap check — A-KT-012; S4's validator supplies the cross-peer cap for inner 200).
- **Type-registry — 53/53 PASS** (`TypeRegistryTest`): the full §9.5 core floor renders +
  binds at `system/type/{name}`, each a 33-byte ecfv1-sha256 hash, render deterministic.
- **Genuine multi-sig K-of-N accept-path — PASS** (`MultiSigCapabilityTest`): 2-of-3 →
  ALLOW (M3/M4/M6) + the deny flips the rejection-only oracle can't cover (below-threshold
  M4, duplicate-sig-no-inflate M4, local-not-in-signers M6, threshold=1 M3, duplicate-signers
  M3, off-root M3) + single-sig superset unregressed.
- **S2 codec regression — 69/69 byte-identical PASS** (`ConformanceTest`) + the spike tests
  — unchanged.
- Clean `gradle compileKotlin compileTestKotlin installDist` offline: **0 errors, 0
  warnings**. Host `installDist` launcher verified to bind + print LISTENING.

## Idiom notes (the Kotlin-native shapes; how it diverges from Java #7)

- **Verdicts/dispatch:** `enum class Verdict`/`RequestVerdict` matched by exhaustive `when`
  at the single dispatch site (compiler-checked); handler op-routing is a `when (operation)`
  ladder with `else → 501`. Failures are VALUES (`Outcome` with a status) on the recoverable
  path — the sealed-result error model, NOT Java's checked exceptions.
- **Async:** kotlinx.coroutines — `suspend` handlers + a `CompletableDeferred` request_id
  demux + per-EXECUTE coroutine dispatch (the §6.13(b)/§6.11 reentry awaits without blocking
  a thread). Blocking socket I/O runs on dedicated OS threads (§7b cooperative-pool rule),
  dispatched WORK on `Dispatchers.IO`. (Java peer = platform/virtual threads.)
- **Store-safety (§4.8/§7b):** `ConcurrentHashMap` + `CopyOnWriteArrayList`, atomic-per-key
  writes drive the §6.10 emit-on-change decision race-free — a third point in the §7b menu
  (A-KT-011); single-writer-dispatcher upgrade documented as the fallback if the S4
  `concurrency` gate demands stricter same-path atomicity.
- **Value types:** `data class` for `Outcome`/`HandlerContext`/`Store.*Event`/scope records;
  `Entity`/`Identity`/`Envelope` are hand-rolled (content_hash-based equality over a
  `ByteArray`, defensively copied — `no_byte_array_aliasing`). Nullability in the type system
  (`T?`), no `Optional`.

## Ambiguities logged (this phase)

`SPEC-AMBIGUITY-LOG.md` — all corroboration-only / local (no new spec defect; the reach-peer
expectation, JVM idiom saturated by Java #7):
- **A-KT-009** seed→Ed25519 raw-pubkey derivation net-new at S3 (SunEC gap; pure-JDK port,
  byte-verified by the cohort-canonical peer_id).
- **A-KT-010** `included` content_hash-MAP dedup mandatory on emit (§3.1) — the strict
  codec's duplicate-key rejection caught the reentry-path dup; generator-note candidate.
- **A-KT-011** §7b store-safety via concurrent collections (a within-menu choice;
  generator-menu candidate for concurrent-collection runtimes).
- **A-KT-012** §6.11 reentry inner-verdict at the smoke is a §5.2 cap check (S4 supplies the
  cross-peer cap) — scopes the smoke claim so S4 reads inner-403 as expected, not a defect.

**No spec defect surfaced** (corroboration-only, as the reach-peer mandate predicted).

## Carry-forward to S4 (`--phase verify`)

- Re-verify §1.5 peer_id construction against the live handshake oracle (A-KT-008 / A-KT-009
  — already exercised green in the loopback; S4 runs it vs `entity-peer`).
- The §6.11 `dispatch_outbound_reentry` origination-core gate: the transport seam is built +
  smoke-proven; S4's validator (B-role) supplies the cross-peer reentry cap for the inner-200
  round-trip (A-KT-012). The from-zero transport trap (OCaml/COBOL) is avoided.
- Multi-sig accept-path: the unit test proves genuine K-of-N; S4's
  `valid_2of3_peer_signed_accepted` runs via `--name` (Host loads the on-disk keypair).
- §7b `concurrency` + `resource_bounds` gates: store-safety (A-KT-011), max-payload 413,
  chain-depth 400 are built in; S4 scores them.
- Ed448/SHA-384 agility higher-bar remains deferred (floor first).

> NOTE: left UNCOMMITTED for orchestrator gate/review (per the worktree boundary).
