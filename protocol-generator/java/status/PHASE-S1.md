# entity-core-protocol-java — Phase S1 (Profile) Summary

**Peer #7** (Java, mainstream OO/static idiom — saturated-axes / high-signal-if-found probe) · **Status: COMPLETE (authoring) — container NOT built (S1 boundary)**

## Preconditions resolved at session start
- **Spec version.** Read `spec-data/v7.72` (latest available). Per the cohort
  finding, `ENTITY-CBOR-ENCODING.md` + `ENTITY-NATIVE-TYPE-SYSTEM.md` are
  byte-identical v7.71→v7.72 (no wire-format change), so the v7.71 codec corpus is
  valid at v7.72. Profile reads `spec-data/v7.72`; codec corpus `test-vectors/v0.8.0`.
- **peer_id verified directly in spec-data.** `ENTITY-CORE-PROTOCOL-V7.md`
  **line 448** (§1.5 canonical-form table) = Ed25519 → `0x00` identity-multihash,
  "the digest IS the public_key (v7.64)"; **lines 436/437–438/442/3561** (§1.5
  skeleton + §7.4 area) still show the stale `SHA256(public_key)` / `hash_type=0x01`
  form. Confirmed the §1.5 table is canonical; §7.4 is stale. (A-JAVA-004.)
- **No-peek discipline.** Derived from V7 + the Java/JVM ecosystem. Read the cohort
  `{csharp,zig,common-lisp,elixir}` `profile.toml` + rationale/status for the field
  *schema and exemplar shape* only (endorsed by PHASE-S1) — config structure, not
  spec interpretation. C# is the closest precedent (managed, static-OO, BouncyCastle
  agility); CL/Elixir are the native-Ed448 precedents.
- **S1 boundary honored.** No podman run, no container build, no toolchain install,
  no compile. Authoring only. (The JDK sha256 was read from the Adoptium release
  API — a metadata lookup, not a build/fetch of the toolchain.)

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| JDK | **Temurin 21.0.10+7** (pinned, sha256-verified) | LTS; ~143d old (≥30-day-clean even though Temurin is a reviewed vendor channel where the age floor relaxes). JDK 21 required for pattern-matching-switch GA (JEP 441) + virtual-threads GA (JEP 444) |
| Codec strategy | **native** | A-005 pattern; JDK crypto makes the CORE peer ZERO-runtime-dep (lightest tier, with Elixir/Zig) |
| CBOR | **hand-rolled** (CanonicalCbor/EcfCodec) | no JVM lib gives ECF (RFC-7049 length-first ≠ RFC-8949 bytewise); float ladder + tag-reject owned regardless |
| Ed25519 | **JDK SunEC** (`Signature("Ed25519")`) | in-JDK, RFC-8032 deterministic; zero dep |
| Ed448 | **JDK SunEC default**, BouncyCastle opt-in cross-check | JDK closes the agility bar natively (contrast OCaml C-ABI / Zig gap); BC stays opt-in, core build BC-FREE; A-JAVA-002 |
| SHA-256/384 | java.security.MessageDigest | in-JDK; SHA-384 for agility |
| base58 / varint | hand-rolled | dep-minimization |
| Error model | **checked exceptions** (`EntityCoreException`) | the static-OO RIGOR seam — compiler forces malformed-input handling (Java-distinct from C# unchecked, OCaml result, Zig error-union, CL conditions) |
| Async | **threaded** (platform + JDK 21 virtual threads) | not exercised by codec; validated at S3; Loom makes thread-per-conn cheap; A-JAVA-003 |
| Naming | PascalCase types / camelCase members / UPPER_SNAKE constants / reverse-DNS pkgs | Java-native |
| Idiom | records + sealed interfaces + pattern-matching switch (JDK 21) | exhaustive over closed type sets — the static analogue of OCaml/Zig exhaustiveness |
| Build / test / pkg | Maven + JUnit 5 + Maven Central | Maven over Gradle (simpler offline/repro); JUnit 5 is the one taken registry test-dep |
| License | Apache-2.0 | S9 default = JVM ecosystem norm |

## Container
`containers/java-toolchain/Containerfile` **authored, NOT built** (S1 boundary).
fedora:43 base → official Temurin 21.0.10+7 tarball, **sha256-verified** (digest
`ea3b9bd4…896a4` from the Adoptium release API; build fails closed on mismatch) →
pinned Apache Maven 3.9.9 (sha512 a **sentinel** — fill at S2 from the Apache dist
`.sha512`; fails closed until then, the zig-toolchain pattern) → pre-fetch the pinned
Maven deps (JUnit 5.11.4 test-scope, surefire 3.5.2, BouncyCastle 1.80 opt-in) into
`~/.m2` so the dev loop runs `mvn -o` fully offline under `--network=none`. Helper
fixture `containers/java-toolchain/prefetch-pom.xml` authored. Chosen over
`dnf install java` because Fedora 43 tracks the distro OpenJDK, not the pinned
Temurin 21.0.10+7.

## Ambiguity log
6 entries (A-JAVA-001..006), none blocking the codec floor:
- **A-JAVA-001** (corroborates A-CL-001): spec-data snapshot stops at v7.72 while
  HEAD is v7.74; peer-layer skew, escalate to arch (S2 ownership). Non-blocking S1/S2.
- **A-JAVA-002:** Ed448 — JDK SunEC native (default) vs BouncyCastle opt-in
  cross-check; raw-key-encoding spike at S2 decides the agility corpus path. Core
  build stays BC-free. NON-blocking for the §9.1 floor.
- **A-JAVA-003:** async = threaded (platform + JDK 21 virtual threads); S3 decision,
  recorded so S3 doesn't re-litigate silently.
- **A-JAVA-004 ⚑ (FOURTH spec-first corroboration, escalate to arch):** §7.4 NORMATIVE
  `derive_peer_id` (SHA-256-form, `hash_type=0x01`) contradicts the §1.5 v7.65
  canonical-form table (Ed25519 → `0x00` identity-multihash, raw pubkey). Verified in
  spec-data lines 448 vs 436/3561. After Zig/OCaml/CL = 4 spec-first peers → decisive.
- **A-JAVA-005:** Maven Central publish requires a verified reverse-DNS namespace
  (`org.entitycore`); deferred to S5 registry step. Operator.
- **A-JAVA-006:** Maven 3.9.9 sha512 is an S2-fill sentinel (S1 no-fetch boundary);
  build fails closed until filled. Operator.

## Exit criteria
profile.toml fully populated (no TBD-blocking) · rationale written · container
specified+authored (build deferred to S2 per the S1 boundary) · ambiguity log has no
blocking-severity items (A-JAVA-002 Ed448 is the agility higher bar, non-blocking for
the codec floor; both peer-id and the JDK sha256 are pre-resolved). **S1 PASS (authoring).**

## What S2 should tackle first
1. **Fill `MAVEN_SHA512`** in the Containerfile from the Apache dist `.sha512` file
   and build + smoke-test the toolchain image (the deferred S1 build). The JDK
   sha256 is already filled (verified at S1).
2. Run the **codec spike** before the full build: hand-roll `CanonicalCbor` enough
   to push the `map_keys` + `float` v7.71 vectors through the ECF encoder and assert
   byte-identity (the load-bearing canonical risk — shortest-float f16 +
   length-then-lex ordering). Watch the Java seams: `byte[]` mutability (defensive
   copy in/out, never alias), `long` has no native unsigned (use `Long.compareUnsigned`
   for the full uint64 head-form range, the C# `ulong` trap), and use `%02x`
   (lowercase) for all address-space hex (avoids the A-CL-009 uppercase trap by default).
3. Resolve the **Ed25519/Ed448 raw-key extraction** (A-JAVA-002): the JDK exposes
   EdEC keys as a point, not a raw byte string — build the raw 32-/57-byte pubkey for
   the identity-multihash peer_id, then KAT-verify Ed448 (and decide SunEC-vs-BC).
   Construct the peer_id per §1.5 (A-JAVA-004), NOT §7.4 — the corpus won't catch a
   wrong construction (opaque digests); it only blows up at the S4 handshake.
