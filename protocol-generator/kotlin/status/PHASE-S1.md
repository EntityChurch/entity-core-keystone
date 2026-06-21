# entity-core-protocol-kotlin — Phase S1 (Profile) Status

**Phase:** S1 — profile research + authoring (NO build, NO podman, NO toolchain run).
**Peer:** Kotlin / JVM — a **"reach" peer** (Android-native / JVM-Kotlin ecosystem
coverage), **corroboration-only** on the spec-discovery axis (the JVM idiom was
already exercised by the Java peer #7; the language-axis discovery well is dry here).
**Spec surface:** `spec-data/v7.75` (latest stamped snapshot; core floor byte-stable
v7.75→v7.77, so the live oracle `entity-core-go @ e8524ed` / v7.77 applies unchanged
at the core floor). Codec corpus `test-vectors/v0.8.0` (ENTITY-CBOR-ENCODING
byte-identical v7.71→v7.75).
**Model peer:** `protocol-generator/java/` (the direct JVM analog) — studied closely,
but Kotlin authored as an **independent reader**, not ported.

---

## Decisions made

| Axis | Decision | Note |
|---|---|---|
| **Codec strategy (HEADLINE)** | **native, hand-rolled Kotlin ECF codec** — NOT interop into the Java codec | Independence/corroboration is this reach peer's entire mandate; interop = "Java in Kotlin syntax" (no-trench-coat, cf. C++ D1). Effort delta modest (no JVM CBOR lib gives ECF canonicality — A-005; Java hand-rolled too). A-KT-001. |
| **CBOR** | hand-rolled `CanonicalCbor`/`EcfCodec` (ByteArray + Kotlin unsigned types) | No JVM lib (incl. kotlinx-serialization-CBOR) gives ECF length-first ordering + f16 ladder + tag-reject. |
| **Crypto floor** | JDK SunEC (Ed25519) + SunMessageDigest (SHA-256) — **native, zero dep** | Via Kotlin/JVM interop. Same as Java by independent arrival. A-KT-002. |
| **Ed448 / SHA-384 agility** | JDK SunEC native (default) / BouncyCastle opt-in cross-check; **DEFERRED higher bar** (floor first) | Core build BouncyCastle-FREE. JVM closes agility natively (unlike OCaml/Zig gaps). A-KT-002. |
| **Error model** | **sealed-class `Result` / `EntityError`** + exhaustive `when` | The PRIMARY divergence from Java (Java = checked exceptions; Kotlin has none). A-KT-003 sibling. |
| **Async** | **kotlinx.coroutines** (structured concurrency) + `runBlocking` facade | The SECOND divergence from Java (threads → coroutines). The one non-stdlib runtime dep. A-KT-003. |
| **Number model** | Kotlin **unsigned types** (`UByte`/`ULong`) carry uint64 head-form natively | Softens the C#-`ulong`/OCaml-`int63` trap; a Kotlin-native ergonomic win. |
| **Naming** | Kotlin Coding Conventions (PascalCase / camelCase / UPPER_SNAKE / lowercase.dotted) | hex lowercase (`%02x`) — A-CL-009 lesson applied. |
| **Build** | **Gradle (Kotlin DSL, `build.gradle.kts`)** + wrapper | Deliberate divergence from Java's Maven — Gradle is the Kotlin/Android norm. |
| **Test** | **kotlin.test** on the JUnit 5 platform | The one test-path registry dep (test-scope, never shipped). |
| **Packaging** | **Maven Central** via vanilla Gradle `maven-publish` + `signing` | Namespace verification = S5 task. A-KT-005. |
| **License** | **Apache-2.0** (S9 default = Kotlin ecosystem norm — Kotlin/kotlinx/Android are Apache-2.0) | No override. |
| **Container** | new `containers/kotlin-toolchain/` (fedora:43 + Temurin 21 + Kotlin 1.9.25 + Gradle 8.10.2) | Authored, NOT built (S1). Checksum sentinels filled at S2 (A-KT-006). |

## peer_id construction (locked in profile)

Derive the Ed25519 peer_id from the **§1.5 v7.65 canonical-form table**
(`spec-data/v7.75` line 459: `hash_type=0x00` identity-multihash, digest = raw
public key), NOT the legacy SHA-256 form. On v7.75 this is **corroboration-only**:
the §7.4-vs-§1.5 contradiction the prior spec-first peers surfaced (A-OC-007 /
A-ZIG-001 / A-CL-002 / A-JAVA-004) is already reconciled in the v7.75 body by v7.73
erratum E1. Pinned proactively to dodge the `401 identity_mismatch` handshake cycle
that S2's opaque-digest corpus would not catch. A-KT-004.

## Supply-chain pins (S11) — all ≥30 days old at authoring

| Dep | Version | Age | Channel / floor |
|---|---|---|---|
| Temurin JDK | 21.0.10+7 | ~143d | reviewed vendor (Adoptium) — age relaxed, exact pin + sha256 |
| Kotlin | 1.9.25 | ~19mo | JetBrains; kotlin-test/stdlib registry-pulled → ≥30-day met |
| kotlinx-coroutines-core | 1.8.1 | ~13mo | Maven Central registry → ≥30-day met (the one non-stdlib runtime dep) |
| JUnit platform | 5.11.4 | ~18mo | Maven Central → ≥30-day met (test-scope only) |
| BouncyCastle bcprov-jdk18on | 1.80 | ~17mo | Maven Central → ≥30-day met (opt-in cross-check only) |
| Gradle | 8.10.2 | ~9mo | reviewed vendor (Gradle Inc.) — age relaxed, exact pin + sha256 |

Explicitly NOT picked (too-new / unnecessary): Kotlin 2.x K2 (2.1.x within cool-down),
BouncyCastle 1.84 (~33d, newer than needed), kotlinx-coroutines 1.9/1.10.

## Deliverables produced this phase

- `protocol-generator/kotlin/profile.toml` — complete, every field populated (no "TBD").
- `protocol-generator/kotlin/arch/PROFILE-RATIONALE.md` — written; codec-strategy decision front and center.
- `containers/kotlin-toolchain/Containerfile` — **authored, NOT built** (fedora:43 base; pinned JDK/Kotlin/Gradle; checksum sentinels for S2). `prefetch/` project referenced by COPY is an S2 deliverable (the offline-dep seed).
- `protocol-generator/kotlin/status/SPEC-AMBIGUITY-LOG.md` — initialized; 6 entries (A-KT-001..006), all informational/non-blocking, **zero blocking-severity**.
- `protocol-generator/kotlin/status/PHASE-S1.md` — this file.

## Phase exit criteria — MET

- [x] `profile.toml` has every field populated (none `"TBD"` — `repository_url=""` is a known S5 placeholder, logged A-KT-005).
- [x] `arch/PROFILE-RATIONALE.md` written, codec decision front and center.
- [x] Container authored (`containers/kotlin-toolchain/Containerfile`) — S2 builds it; S1 did not run podman.
- [x] Ambiguity log has **no blocking-severity items** (all informational / non-blocking S2/S5 tasks).

## Hand-off to S2 (codec)

1. **Build the container** (`containers/kotlin-toolchain/Containerfile`) — fill the
   `KOTLIN_SHA256` + `GRADLE_SHA256` sentinels from the published `.sha256` assets
   first (A-KT-006); author the `containers/kotlin-toolchain/prefetch/` Kotlin-DSL
   project that seeds the offline Gradle caches.
2. **Codec spike FIRST** (A-KT-001 mandate): push the `map_keys` + `float` v7.71
   vectors through the hand-rolled encoder before the full build — verify the
   length-then-lex map-key ordering + shortest-float (incl. f16) ladder. `ffi` is the
   documented fallback if the spike fails (not expected).
3. **Raw EdEC key extraction** (A-KT-002): verify the raw-32-byte-pubkey extraction /
   raw-seed key construction from the JDK EdEC point form.
4. Expect a **clean, low-friction port** (corroboration-only) — but log any
   divergence from the Java/cohort findings; a Kotlin-idiomatic reading landing
   anywhere other than the cohort's fixed point is the high-signal outcome.
