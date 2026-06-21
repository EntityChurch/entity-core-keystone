# Changelog — entity-core-protocol-kotlin

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note:** Gradle/Maven's version grammar accepts a SemVer-style qualifier directly,
> so the `0.1.0-pre` release line is carried in `build.gradle.kts` `version` + the
> `maven-publish` POM coordinates idiomatically (unlike Common Lisp, where ASDF's
> dotted-integer-only `:version` forced the `-pre` marker into the CHANGELOG/README only —
> A-CL-010). Kotlin needs no such split.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.75**, certified against the **v7.77** oracle
(`e8524ed`; the core floor is byte-unchanged v7.75 → v7.77 — the v7.77 delta is entirely
extension + the V8-naming kebab fold, which this peer already satisfies). Codec corpus v0.8.0
(ENTITY-CBOR-ENCODING byte-identical v7.71 → v7.75, no wire change).

First release line. The Kotlin / JVM **REACH peer** (Android / JVM-Kotlin ecosystem coverage),
derived **fresh** in S1 from the V7 spec as an **independent reader** (hand-rolled native Kotlin
codec, NOT interop into the Java peer's codec — A-KT-001) in Kotlin-native idiom: sealed-class
`Result` error model, `kotlinx.coroutines` structured concurrency, data classes, exhaustive
`when` dispatch. Not yet published — parked at `-pre` pending architecture v0.1 sign-off + first
external consumer (S5 promotion gate) AND the Maven Central namespace-verification operator step
(A-KT-005).

### Conformance
- `validate-peer --profile core`: **PASS** — 665 total / 292P / 278W / **0F** / 95skip
  (machine-verified `summary.failed == 0`), on the **v7.77** oracle `e8524ed` with
  **`core_gate_sha256` matched** (`e09a865f…`) to the committed pin — exactly the cohort floor.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, first run, **0 codec fixes**.
- §10.1 core-register gate: **10/10** PASS (incl `validate_echo_dispatch`; the §3.4
  invariant-pointer grant-signature at `system/signature/{grant_hash}` enforced; unregister
  symmetry tested).
- origination-core: **3/3** over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam cross-impl wire-proven).
- multisig: **11/11** PASS, **0 skip** — genuine §3.6 K-of-N incl
  `valid_2of3_peer_signed_accepted` (the accept-path genuinely runs via the `--name`
  persistent-identity surface, not a vacuous skip).
- `concurrency` (§7b): 5/5 PASS. `resource_bounds` (§4.10): r1 413 / r2 400 PASS, r3 WARN.
- `gradle --offline --no-daemon test`: codec corpus + Ed25519 KATs + 53-type byte-diff +
  two-peer loopback smoke — 0 failures.

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16⊂f32⊂f64 float minimization, length-then-lex
  map-key sort on encoded key bytes, recursive major-type-6 tag rejection, hand-rolled LEB128 +
  Base58 (neither in the JDK). **Native `UByte`/`ULong`** carry the full 0..2⁶⁴−1 head-form
  range — no `Long.compareUnsigned` / `ulong` / int63 trap (a Kotlin-native number-axis win;
  A-KT-007).
- **Ed25519 sign/verify native via the JDK SunEC provider** — zero-dependency core, no FFI, no
  BouncyCastle. SHA-256 via `MessageDigest`. Deterministic RFC-8032 signing → cross-impl
  signature byte-equality.
- **Pure-JDK RFC-8032 raw-pubkey derivation** (`crypto/EdKeyDerivation.kt`, A-KT-009) — SunEC
  exposes no seed→public-key API, so the §1.5 identity-multihash raw public key is derived by a
  hand-rolled scalar-mult routine, cross-checked against SunEC's own verifier and the
  cohort-canonical seed-`0x11` peer_id.
- §1.5 canonical-form peer_id construction (Ed25519 → `hash_type=0x00` raw-pubkey
  identity-multihash), following the §1.5 v7.65 table, NOT the stale §7.4 pseudocode (A-KT-004).
  Seed-`0x11` peer_id byte-identical to the Java / CL peers.
- §4.1 handshake, §6.5/§6.6 single-dispatch handler ladder, capability authorization with chain
  attenuation + §5.7 delegation caveats, type registry (render-from-model, 53/53), in-memory
  address-space store with CAS, §9.5a CORE-TREE get/put/CAS/delete + listing-omit deletion
  markers.
- v7.73/v7.74 peer surface: §6.13 register's five normative writes, §PR-8 granter frame (V2(a)),
  §6.9a owner-cap bootstrap, §7a conformance handlers (`--validate`, off by default).
- v7.75 non-functional floor: §4.10(a) max-payload → 413, §4.10(b) chain-depth structural
  pre-check → 400 (distinct from the 403 authz path; A-KT-011-adjacent), §7b store-safety via
  concurrent collections with atomic-per-key writes (A-KT-011).
- §5.2 request verification as a three-way verdict (ALLOW / AUTHN_FAIL→401 / AUTHZ_DENY→403).
- Error model: Kotlin **sealed-class `EcfResult` + `EntityError`** matched exhaustively by
  `when` (compiler-enforced; status carried as a value, never across an exception). The headline
  divergence from the Java peer's checked exceptions (A-KT-003 frames the idiom split).
- Concurrency: **kotlinx.coroutines** structured concurrency — one coroutine per connection on
  `Dispatchers.IO`, a reader coroutine demuxing `EXECUTE_RESPONSE` by `request_id` via
  `ConcurrentHashMap<requestId, CompletableDeferred<T>>`; both a `runBlocking` facade and native
  `suspend` surface. The second deliberate divergence from Java's threads (A-KT-003).
- Standard host CLI surface (cohort convention): `--name NAME` (load Ed25519 identity from
  `~/.entity/peers/NAME/keypair`), `--port N`, `--validate` (§7a handlers, off by default),
  `--debug-open-grants` (deprecated; degenerate `default→*` seed policy).
- Gradle `maven-publish` + `signing` config (`build.gradle.kts`) — POM coordinates
  `org.entitycore:entity-core-protocol-kotlin:0.1.0-pre`, Apache-2.0 license metadata,
  `Entity Core Protocol contributors` developer; publish credentials / repository URL left as
  explicit publish-time `TODO`s (A-KT-005).

### Known limitations
- **Maven Central publishing deferred** — requires a verified `org.entitycore` reverse-DNS
  namespace (DNS TXT / hosting proof) before the first `gradle publish` (A-KT-005). The artifact
  is publish-ready (`0.1.0-pre` coordinates, license metadata, near-zero-dep runtime); the deploy
  is an operator action.
- **Ed448 / SHA-384 crypto-agility is a deferred higher bar** for this reach peer (floor first).
  The JDK SunEC route + BouncyCastle opt-in cross-check are documented (A-KT-002); the v0.1
  target is the Ed25519 + SHA-256 §9.1 floor (69/69 byte-green). The full agility MATRIX harness
  is unwired.
- Public API surface is documented (README §Use, package tiers), not yet frozen with an explicit
  visibility / `@PublishedApi` lock — deferred to publish-prep / first external consumer.
- The v7.73/v7.74/v7.75 peer-surface behavior is oracle-sourced against the v7.75 spec-data
  snapshot (the v7.76/v7.77 deltas are extension-only; the core floor is byte-unchanged).

### Toolchain pins (S11)
- **Temurin JDK 21.0.10+7 LTS** (SHA-256-pinned; reviewed Adoptium channel, exact pin for repro;
  shared with the java-toolchain image).
- **Kotlin 1.9.25** (compiler + stdlib + kotlin-test; SHA-256-pinned). The conservative
  Android-default 1.9 line; 2.0/2.1 (K2) deliberately not picked (2.1.x under the ≥30-day floor
  at authoring).
- **kotlinx-coroutines-core 1.8.1** (≈13 mo aged; Maven-Central-pulled → ≥30-day floor met). The
  one non-stdlib runtime dep.
- **Gradle 8.10.2** (SHA-256-pinned via the wrapper distribution; reviewed Gradle Inc. channel).
- **JUnit 5 (Jupiter) 5.11.4** — kotlin-test backend, TEST-scope only (never shipped).
- **BouncyCastle `bcprov-jdk18on` 1.80** — OPT-IN agility cross-check ONLY; the core build is
  BouncyCastle-free. (BC 1.84 is under the ≥30-day floor — deliberately not picked.)

### Spec items surfaced (routed to architecture)
No NEW spec defect surfaced — corroboration-only, exactly as the reach-peer mandate predicted
(the JVM idiom was saturated by the Java peer). All `A-KT-*` items are recorded decisions,
corroborations, or local resolutions; full text in `status/SPEC-AMBIGUITY-LOG.md`:
- **A-KT-004** §7.4-vs-§1.5 peer-id form — **corroboration only** (already reconciled in the
  v7.75 body by v7.73 erratum E1; pinned proactively). Earlier surfaced by Zig/OCaml/CL/Java.
- **A-KT-009** SunEC has no seed→public-key API — resolved via a pure-JDK RFC-8032 derivation
  (corroborates the Java A-JAVA-002 seam; crypto-ledger data point).
- **A-KT-007** the hand-roll spike confirmed byte-correct on the load-bearing canonical risks
  (length-then-lex map ordering + the f16 shortest-float ladder) — first run.
- **A-KT-010** §3.1 `included` is a content_hash→entity MAP — duplicate-hash dedup is mandatory
  on emit (the strict-codec-catches-a-peer-bug payoff). Local fix; generator-note candidate.
- **A-KT-011** §7b store-safety via concurrent collections (atomic-per-key) — a profile-menu
  refinement candidate for concurrent-collection runtimes.
- **A-KT-005** Maven Central namespace verification — packaging note (operator).
- **A-KT-012** (RESOLVED at S4) §6.11 reentry inner-200 is the validator's cross-peer cap,
  confirmed via origination-core `dispatch_outbound_reentry`.
- **A-KT-001 / -002 / -003 / -006 / -008** recorded decisions (codec strategy / agility route /
  async idiom / toolchain checksums / S2 peer_id coverage gap) — local, no spec change.
