# Phase S5 — Publish (entity-core-protocol-kotlin)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` (in `build.gradle.kts version` + the `maven-publish`
POM coordinates directly). · **Spec basis:** V7 spec-data v7.75, certified against the v7.77
oracle `e8524ed` (core floor byte-unchanged v7.75 → v7.77); codec corpus v0.8.0.

S5 polishes the S4-conformant Kotlin / JVM **REACH peer** into a *ready-to-publish* artifact.
`/entity-rosetta` never publishes (lifecycle §Publishing) — this phase produces the artifacts +
the runbook; an operator publishes when arch signs off v0.1 AND the Maven Central namespace is
verified. This doc is the release-readiness record + the operator handoff.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | 665 / 292P / 278W / **0F** / 95skip, machine-verified `summary.failed == 0` (`status/CONFORMANCE-REPORT.{md,json}`), on the v7.77 oracle `e8524ed` with `core_gate_sha256` matched (`e09a865f…`) — exactly the cohort floor. |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`). |
| §10.1 core-register gate | ✅ | 10/10 (incl `validate_echo_dispatch`; §3.4 invariant-pointer grant-sig at `system/signature/{grant_hash}` enforced; unregister symmetry). |
| multisig genuine K-of-N | ✅ | 11/11, 0 skip — `valid_2of3_peer_signed_accepted` genuinely runs via the `--name` persistent-identity surface (not a vacuous skip). |
| concurrency (§7b) + resource_bounds (§4.10) | ✅ | concurrency 5/5; resource_bounds r1 413 / r2 400 PASS, r3 WARN (SHOULD). |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first run, **0 codec fixes**. |
| §9.5 53-type floor byte-identical | ✅ | 53/53 (peer-side dual + live oracle `type_system_match`). |
| Ed25519 RFC-8032 KAT | ✅ | SunEC sign/verify byte-equal; pure-JDK raw-pubkey derivation KAT-verified to the cohort-canonical seed-`0x11` peer_id (A-KT-009). |
| `gradle --offline --no-daemon test` clean | ✅ | codec 69/69 + Ed25519 KATs + 53/53 type-diff + two-peer loopback smoke, 0 failures. |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0; holder `Entity Core Protocol contributors` — cohort convention, matches the Java peer). `build.gradle.kts` POM `<licenses>` block. |
| README + conformance badge | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, verdict + reproduce + the byte-identity proof; conformance line links `status/CONFORMANCE-REPORT.md`). |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.75, certified @ v7.77 e8524ed`. |
| Package metadata (`build.gradle.kts`) | ✅ | `maven-publish` + `signing` authored: `org.entitycore:entity-core-protocol-kotlin:0.1.0-pre`, JDK 21, POM license/developer/url, sources + javadoc jars. Near-zero runtime deps (kotlinx-coroutines only; kotlin-test/JUnit test-scope; BouncyCastle opt-in). Publish repo + creds = explicit publish-time TODOs. |
| Version pin | ✅ | parked `0.1.0-pre` (cohort norm). Gradle carries the `-pre` qualifier directly (contrast A-CL-010). |
| Toolchain pin (S11) | ✅ | Temurin **JDK 21.0.10+7 LTS** + **Kotlin 1.9.25** + **Gradle 8.10.2** (all SHA-256-pinned); kotlinx-coroutines 1.8.1 / JUnit 5.11.4 / BouncyCastle 1.80 all ≥30-day-aged, test/opt-in scope where applicable. `gradle.lockfile` committed. |
| CI config (Podman, offline) | ✅ authored, not wired | `.github/workflows/kotlin.yml` — build + test + `--profile core` (assert `summary.failed == 0`) + origination-core, all in `kotlin-toolchain`, `--network=none`, read-only perms, **no deploy/publish**. Committed for reviewability; a runner is not attached (cohort norm — whether/where it runs is an operator/arch decision). |
| Public API surface | ◑ documented | package tiers in README §Use (`...codec`/`...crypto` Tier 1, `...peer` Tier 2); internal units may churn without a semver bump. Explicit visibility / `@PublishedApi` freeze deferred to publish-prep / first consumer (the Java `module-info` / OCaml `.mli` / Zig `root.zig` analogue). |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; all `A-KT-*` resolved-in-peer / corroboration / operator-owned. **No NEW spec defect** (reach-peer corroboration-only). |
| **Published to Maven Central / tagged** | ⛔ **deferred** | operator action — requires verified `org.entitycore` namespace (A-KT-005) AND arch v0.1 sign-off (§4). No auto-tag, no push, no deploy. |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and*
(b) ≥1 external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not
yet met** (no Kotlin consumer wired). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **Maven artifact** — `org.entitycore:entity-core-protocol-kotlin:0.1.0-pre`
  (`build.gradle.kts`), JDK-21 bytecode, `jar` packaging + sources + javadoc jars.
  **Near-zero runtime dependencies:** Ed25519 sign/verify + SHA-256 from the JDK (SunEC +
  `MessageDigest`); CBOR (canonical ECF), Base58, the multicodec LEB128 varint, and the
  RFC-8032 raw-pubkey derivation are hand-rolled in `src/main/kotlin`. The **one** non-stdlib
  runtime dep is `kotlinx-coroutines-core` (the Kotlin-native concurrency primitive — a
  deliberate idiom-over-minimalism trade vs Java's literal zero deps; A-KT-003). kotlin-test +
  JUnit 5 are test-scope; BouncyCastle is opt-in (agility cross-check, never shipped).
- **Crypto: JDK-native floor, no FFI.** SunEC supplies Ed25519 sign/verify natively; the
  raw-*public-key* half has a JDK gap (no seed→public API), closed by the pure-JDK RFC-8032
  derivation (A-KT-009, same gap the Java peer hit). Ed448 / SHA-384 **agility is a deferred
  higher bar** for this reach peer — the SunEC + BouncyCastle routes are documented (A-KT-002),
  the v0.1 target is the floor.
- **Host executable** (the S4 conformance driver, `--name`/`--port`/`--debug-open-grants`/
  `--validate`; emits `LISTENING …`). Test/conformance only — not part of the published library
  surface.

---

## 3. Packaging notes specific to Kotlin

- **Gradle Kotlin-DSL + `maven-publish` + `signing`, vanilla (no third-party publish plugin).**
  Kotlin's idiomatic build is Gradle with `build.gradle.kts` (kotlin-gradle-plugin is first-party
  JetBrains; the Android Studio / kotlinx-library norm) — Maven (the Java peer's choice) would
  read as un-idiomatic here. The publish path is the stock Gradle `maven-publish` + `signing`
  plugins, keeping the supply chain minimal (no nexus-publish / vanniktech plugin).
- **Gradle carries the `-pre` qualifier directly (contrast A-CL-010).** `version = "0.1.0-pre"`
  is the single source of the release line, flowing into the Maven coordinate idiomatically —
  no ASDF-style dotted-integer-only split that forced Common Lisp to carry `-pre` in docs only.
- **Maven Central is a real upload registry with a namespace gate (A-KT-005).** Publishing to
  Maven Central (Sonatype Central Portal) requires verifying ownership of the `org.entitycore`
  reverse-DNS namespace (DNS TXT / hosting proof) before the first `gradle publish` — a one-time
  operator action the pipeline cannot perform. The `publishing { repositories {} }` block is left
  empty (no default repo → no accidental deploy) with the staging-repo wiring + credentials as
  explicit publish-time TODOs; `signing` is gated to a real `publish` task (no-op for local
  build/test). This is *the* reason the Kotlin publish is deferred (plus the cohort-wide arch
  v0.1 gate).
- **Near-zero-runtime-dependency posture.** A consumer of the published artifact inherits only
  `kotlinx-coroutines-core` (+ the Kotlin stdlib) — no crypto provider graph (JDK SunEC),
  comparable to the Java peer minus the coroutine dep. The only other pin a consumer takes on is
  JDK 21.
- **Crypto-agility deferred (reach peer, floor first).** Does NOT affect the §9.1 floor
  (Ed25519 + SHA-256, 69/69 byte-green) nor the connect-path. The SunEC Ed448 / SHA-384 route +
  the BouncyCastle opt-in cross-check are documented for the higher bar; only the matrix harness
  is unwired (A-KT-002).

---

## 4. Ambiguity-log finalization (owner + escalation status)

All S1–S5 `A-KT-*` items are resolved-in-peer / recorded; **none block release**, and — exactly
as the reach-peer mandate predicted — **no NEW spec defect surfaced** (the JVM idiom was saturated
by the Java peer). Full text in `status/SPEC-AMBIGUITY-LOG.md`:

- **A-KT-004** §7.4-vs-§1.5 peer-id form — **corroboration only**, already reconciled in the
  v7.75 body (v7.73 erratum E1); pinned proactively. Earlier surfaced by Zig/OCaml/CL/Java —
  owner: research (cohort-ledger corroboration, no new arch escalation).
- **A-KT-009** SunEC has no seed→public-key API — resolved via a pure-JDK RFC-8032 derivation;
  corroborates the Java A-JAVA-002 seam (crypto-ledger data point). Owner: arch/research.
- **A-KT-010** §3.1 `included` is a content_hash→entity MAP (duplicate-hash dedup mandatory on
  emit) — local fix; a generator-note candidate (owner: research). The strict-codec-catches-a-
  peer-bug payoff.
- **A-KT-011** §7b store-safety via concurrent collections (atomic-per-key) — a profile-menu
  refinement candidate for concurrent-collection runtimes. Owner: research (generator menu).
- **A-KT-007** the hand-roll spike confirmed byte-correct on the load-bearing canonical risks
  (length-then-lex + f16 shortest-float) — recorded decision. Owner: operator.
- **A-KT-012** (RESOLVED at S4) §6.11 reentry inner-200 = the validator's cross-peer cap,
  confirmed via origination-core. Owner: operator.
- **A-KT-005** Maven Central namespace verification — owner: operator (S5 registry step).
- **A-KT-001 / -002 / -003 / -006 / -008** recorded decisions (codec strategy / agility route /
  async idiom / toolchain checksums / S2 peer_id coverage gap) — owner: operator; local, no spec
  change.

---

## 5. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar, an
external consumer confirms the peer, AND the `org.entitycore` namespace is verified:

1. **Decide in-repo vs standalone repo.** Per-language sibling repos are deferred keystone-wide
   (S10); current default is in-repo under `protocol-generator/kotlin/`.
2. **Verify the `org.entitycore` Maven Central namespace** (A-KT-005) — DNS TXT record on the
   owned domain or a hosting-provider proof via the Sonatype Central Portal. The gate that
   cannot be done before first deploy.
3. **Settle the public-surface freeze** (§1): lock the Tier-1/Tier-2 package visibility (mark
   internal units `internal` / `@PublishedApi`), build-verified in the `kotlin-toolchain` image.
4. **Promote version** `0.1.0-pre → 0.1.0` in `build.gradle.kts version` + `CHANGELOG.md` once
   the promotion gate (§1) is met. (Gradle carries the marker directly — no CL-style doc-only
   split.)
5. **Wire the publish repository + credentials + signing key** — fill the `publishing {
   repositories { … } }` Central Portal staging-repo TODO + the `signing` key TODO in
   `build.gradle.kts`; set the POM `url`/`scm` (currently the keystone repo) if Option 2 is
   taken. Also set `repository_url` in `profile.toml [publishing]`.
6. **Deploy** — `gradle publish` to the Central Portal staging repo (GPG-signed artifacts via
   the `signing` plugin), then release via the Portal. **Tag the release** at the reviewed
   commit at this point only (lifecycle §"no auto-tag").
7. **Wire CI** to the chosen repo's runner (`.github/workflows/kotlin.yml` already exists —
   build + test + `--profile core` + origination-core in `kotlin-toolchain`, `--network=none`,
   asserting `summary.failed == 0`), or fold into a keystone-wide CI home if arch defines one.
   No remote/CD is attached today by design.
8. **Pin discipline** (S11): JDK 21 + Kotlin 1.9.25 + Gradle 8.10.2 + kotlinx-coroutines 1.8.1 +
   JUnit 5.11.4 + BouncyCastle 1.80 pins stay exact; re-pinning is deliberate + reviewed.

---

## 6. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged to
Maven Central — gated on namespace verification A-KT-005 + arch v0.1; `0.1.0` promotion pending
external consumer; public-surface freeze pending; CI authored-offline but not wired to a remote
— by design). Regression GREEN (**S2 69/69 · S4 665 · 292P/278W/0F/95S @ e8524ed · origination
3/3 · §10.1 register 10/10 · multisig 11/11 incl accept-path · concurrency 5/5 · resource_bounds
GREEN · 53-type 53/53**). Ambiguity log finalized + owner-routed; **no NEW spec defect**
(corroboration-only, as the reach-peer mandate predicted). CONFORMANCE-MATRIX.md Kotlin row
appended (§1 + §2). Operator handoff (§5) prepared. **S5 objective met; the Kotlin / JVM REACH
peer is publish-ready and parked at `0.1.0-pre` pending arch v0.1 sign-off + the Maven Central
namespace step.**
