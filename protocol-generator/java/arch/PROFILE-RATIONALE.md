# entity-core-protocol-java — Profile Rationale

Audit trail for every major S1 profile choice. Java is **peer #7** (canonical
order), and the **mainstream OO/static idiom** in the cohort: classes + interfaces,
checked exceptions, a managed GC, the JVM threading model, and a large
vendor-curated standard library (`java.security` / `java.util.concurrent`). Each
choice below was derived from the V7 spec + Java/JVM ecosystem research, **not**
ported from the prior peers. Where a value matches a prior peer it is by
independent arrival; the idiom seams (checked exceptions, records + sealed types +
pattern matching, JVM virtual threads) are the Java-native shapes.

## Why Java is a worthwhile probe — and the explicit caveat

The six prior peers spanned static-OO-unchecked (C#), gradual-structural (TS),
functional-static (OCaml), actor-dynamic-functional (Elixir), no-GC systems (Zig),
and program-model-distant (Common Lisp). On the **idiom-distance axes the cohort
tracks** (number model, dispatch shape, error model, concurrency, memory
discipline), Java is **mostly SATURATED**:

- **Dispatch** — single-dispatch OO `switch`/virtual methods, the same surface the
  C#/TS/OCaml/Elixir peers used; CL's multiple dispatch already probed the one
  divergent shape and confirmed §6.6 idiom-neutrality (A-CL-008).
- **Number model** — `long` is a 64-bit signed int with the same head-form/uint64
  trap C# (`ulong`) and OCaml (`int63`) hit; nothing new (Java has no native
  unsigned, so the full uint64 range needs the same careful handling C# applied).
- **Concurrency** — platform threads, the OCaml/Zig/CL stdlib-threads shape.
- **Memory** — managed GC, like every peer except Zig.

So the **expected spec-refinement yield is SMALL** — a deliberately low-friction
"it's just Java" port. The reason to build it anyway, recorded for the arch-review
ledger: **a mainstream stack rarely surfaces gaps, so any NEW finding it DOES
surface is HIGH-signal** — a defect that the single most-deployed enterprise
language hits is a defect almost every real deployment hits. Java is the
"does the spec survive contact with the boring mainstream?" probe. The build/
program-model axis it stresses for the ledger: **static OO + CHECKED exceptions +
the JVM threading model + a vendor-curated stdlib** (the last is itself notable —
Java is the first peer whose stdlib closes the full crypto-agility bar; see below).

## Codec strategy: native (JDK-native crypto, hand-rolled canonical CBOR)

`research/LANDSCAPE.md` placed the JVM in the saturated-axes backlog. Research lands
it as **native**, the same A-005 pattern every prior native peer hit, in two halves:

1. **Crypto is JDK-native — and the JDK closes the FULL agility bar with zero
   third-party deps.** This is the headline crypto-axis result. JDK 15+ ships
   Ed25519 (JEP 339) AND Ed448 in the SunEC provider (`Signature("Ed25519")` /
   `Signature("Ed448")`, `NamedParameterSpec.ED25519/ED448`), and
   `MessageDigest` covers SHA-256 AND SHA-384. So the §9.1 floor (Ed25519 +
   SHA-256) AND the v7.67 agility higher bar (Ed448 + SHA-384) are BOTH reachable
   from the default build with **no dependency at all**. This puts Java in the
   native-Ed448 camp alongside **Common Lisp (ironclad, pure-Lisp)** and **Elixir
   (OTP `:crypto`, OpenSSL NIF)** — and in **direct contrast with OCaml** (A-OC-002,
   which sourced Ed448 over the C-ABI because mirage-crypto-ec lacks it) and **Zig**
   (A-ZIG-002, a flat gap — no std Ed448, no BouncyCastle-equivalent). The Java
   mechanism is a third distinct one: a **vendor-curated stdlib provider**, not a
   pure-lang lib (CL) or an OS crypto binding (Elixir). See the Ed448 section.

2. **No JVM CBOR library gives ECF canonicality** — the A-005 pattern. The JVM CBOR
   options (`jackson-dataformat-cbor`, `com.upokecenter.cbor`, `co.nstant.in.cbor`)
   are general-CBOR; at best they offer RFC-8949 §4.2 deterministic mode, whose
   **bytewise** map-key ordering DIFFERS from ECF's RFC-7049 **length-FIRST then
   lexicographic** ordering. Add the shortest-float ladder (incl. f16), recursive
   major-type-6 tag rejection, and raw-byte fidelity — all yours to enforce on top
   of any library — and a library buys almost nothing while adding a Maven dep + pin.
   Hand-rolling `CanonicalCbor`/`EcfCodec` is the faithful AND simpler path.

Net: the **core peer has ZERO runtime dependencies** — JDK SunEC + SunMessageDigest
for crypto/hash, hand-rolled CBOR + base58 + varint. The only registry dep on the
TEST path is JUnit 5 (test-scope). This ties Elixir/Zig for the lightest
supply-chain in the cohort, achieved here via a mainstream vendor stdlib. `ffi`
stays the documented fallback but is not expected for any tier. **Codec spike at
S2** (PHASE-S1 mandate): push the `map_keys` + `float` v7.71 vectors through the
hand-rolled encoder before the full build — the load-bearing canonical risk
(length-then-lex ordering + shortest-float f16).

## CBOR: hand-rolled (no JVM library)

As above — the JVM CBOR libraries target general/RFC-8949 CBOR, and ECF's
length-first ordering + float ladder + tag rejection must be owned regardless.
**Java-specific footgun the codec must respect:** `byte[]` is **mutable and
aliasable** — the codec MUST defensive-copy bytes in and out of value types and
NEVER expose an internal `byte[]` by reference (a caller could mutate the backing
array of a `ContentHash`). The GC'd-but-immutable prior peers (C# `ReadOnlyMemory`,
OCaml `Bytes`/`string`, Elixir binaries are immutable) did not have this exact
seam; Java's array mutability makes raw-byte fidelity partly an aliasing-discipline
concern, recorded in `[idiom].no_byte_array_aliasing`. Also: Java has **no native
unsigned integer** — the full uint64 head-form range needs the C#-style careful
handling (`Long.compareUnsigned`, `Long.toUnsignedString`), the same trap C# noted
with `ulong`; no native bignum advantage (unlike CL/Elixir).

## Crypto: JDK SunEC (Ed25519, Ed448) + SunMessageDigest (SHA-256, SHA-384)

The JDK's SunEC provider supplies Ed25519 and Ed448 via the unified `Signature` /
`KeyPairGenerator` / `KeyFactory` API with `NamedParameterSpec.ED25519` /
`ED448` and the `EdECPrivateKeySpec`/`EdECPublicKeySpec` key specs;
`MessageDigest.getInstance("SHA-256" | "SHA-384")` covers both hash sizes. All
ship with the JDK — no Maven dependency, no libsodium/OpenSSL system dep. RFC-8032
deterministic by the algorithm. The one S2 wrinkle to verify: extracting / building
the **raw 32-byte (Ed25519) / 57-byte (Ed448) public key** for the wire form — the
JDK exposes EdEC keys as an (x-coordinate sign-bit, y-coordinate) point, not a raw
byte string, so the raw-pubkey extraction (for the identity-multihash peer_id) and
raw-seed key construction need explicit encoding handling. Logged as the S2 task in
A-JAVA-002.

## Ed448: JDK SunEC native (default), BouncyCastle opt-in cross-check (the OCaml/Zig gap does NOT recur)

The crypto-agility higher bar (v7.67: key_type Ed448 `0x02` validated; SHA-384
content_hash_format `0x01` validated) is reachable from the **default build via JDK
SunEC** — no FFI, no opt-in sub-library, no hybrid. This is the contrast with OCaml
(A-OC-002, C-ABI Ed448) and Zig (A-ZIG-002, flat gap). The §9.1 floor (Ed25519 +
SHA-256) is unaffected either way.

**BouncyCastle (`bcprov-jdk18on`) is the OPT-IN agility cross-check / fallback, NOT
the core.** Mirroring OCaml's opt-in `entitycore_agility` sub-lib stance and the C#
precedent (A-009, which used BouncyCastle BECAUSE NSec/libsodium lacked Ed448),
BouncyCastle is a **pure-managed independent crypto source** — a free byte-equality
cross-check against SunEC's Ed448/SHA-384, and the route to use if a SunEC Ed448
edge (raw-key encoding, a provider-availability quirk on a stripped JDK) bites at
S2. The **core build stays BouncyCastle-FREE**: the JDK covers the floor AND the
agility signature, so the conservative default keeps the dependency count at zero
and reserves BC for the cross-check. Decide SunEC-vs-BC for the agility corpus
(`KEY-TYPE-ED448-1`, 114-byte signature, `MATRIX-M2/M6`) at S2 after the raw-key
spike. Logged A-JAVA-002.

This is a genuinely interesting agility-axis data point for the ledger: Java is the
**first peer where the SAME ecosystem offers BOTH a native-stdlib agility path AND
an independent managed cross-check library** — CL had only pure-Lisp ironclad,
Elixir only the OTP NIF, C# had to reach for BC because libsodium lacked Ed448, and
OCaml/Zig had no managed option at all. The JVM's breadth is the finding.

## Base58 + varint: hand-rolled

Both are small and dependency-free. Base58 (Bitcoin alphabet, encode+decode,
~80 lines) for peer_id; multicodec-style LEB128 varints for the format-code /
key-type / hash-type framing (§7.3). Hand-rolling dodges two more Maven deps and
matches the dependency-minimization stance (the cohort precedent).

## Error model: checked exceptions (the static-OO rigor seam)

Java's idiom is the **exception hierarchy** — the nearest cousin to C#'s exceptions,
but with the distinctive Java seam that codec/protocol decode failures are
**CHECKED** (a subclass of a checked `EntityCoreException extends Exception`), so the
**compiler forces** every caller to handle the malformed-input path. This is the
static-OO analogue of Zig's compiler-checked error sets and OCaml's exhaustive
`result` matching — reached through Java's own checked-exception mechanism, a
different point in the design space from C#'s all-unchecked exceptions. Hierarchy:
`EntityCoreException` (checked) → `EntityCodecException` (`NonCanonicalEcf`,
`TruncatedInput`, `TagRejected`, `DuplicateKey`), `EntityCryptoException`
(`BadSeed`, `UnsupportedKeyType`, `UnsupportedContentHashFormat`),
`EntityProtocolException` (`Authentication`, `Authorization`),
`EntityTransportException`. Decode-path violations (N2/N3) are terminal (no
recovery). Truly unrecoverable programmer errors stay unchecked (`RuntimeException`/
`IllegalStateException`). Protocol-status failures map an exception subtype → status
code (400 non_canonical_ecf / 401 / 403) at the dispatcher boundary. The probe: the
checked-vs-unchecked split is the one error-model dimension no prior peer has
exercised (C#/TS unchecked, OCaml result, Elixir tuple, Zig error-union, CL
conditions).

## Async: JVM threads + virtual threads (deliberate S6 decision; validated at S3)

Java's concurrency primitive is the platform thread (`java.lang.Thread` +
`java.util.concurrent`). For a `--profile core` peer the N6/N7 reentrancy invariants
(inbound concurrent with outbound dispatch; reentrant request_id demux; §6.11
reentry) are satisfied by **one thread per connection** plus a
`ConcurrentHashMap<requestId, CompletableFuture>` correlation table — exactly the
shape OCaml/Zig/CL arrived at with stdlib threads (A-OC-003-revised). **JDK 21
virtual threads (Project Loom, JEP 444, GA in 21)** make one-thread-per-connection
cheap and are the recommended carrier — a Java-21-specific advantage worth noting:
the thread-per-connection model that other peers had to justify against thread cost
is the *recommended* model on Loom. The public surface is blocking + a
`CompletableFuture<T>` variant (the C#-`Task` / TS-`Promise` analogue). Not
exercised by the codec (pure/synchronous) — validated at S3. Logged A-JAVA-003.

## Naming: Java-native PascalCase / camelCase / UPPER_SNAKE

`PascalCase` for classes/interfaces/records/enums; `camelCase` for methods, fields,
locals, parameters; `UPPER_SNAKE_CASE` for `static final` constants and enum
constants (the Java idiom — unlike C#'s PascalCase constants or Zig's snake_case);
`lowercase.dotted` reverse-DNS packages (`org.entitycore.protocol`). Differs from
every prior peer's casing. **CASE-EXACT data caveat (the A-CL-009 lesson applied
proactively):** all external string/byte hex rendering must be kept **lowercase** to
match the Go oracle (`hex.EncodeToString`) and the cohort — Java's
`String.format("%02x", b)` defaults lowercase (good, unlike CL's `~x` uppercase), so
Java avoids the A-CL-009 trap by default; recorded here so the codec uses `%02x`
(lowercase) for all address-space tree-path hex and never `%02X`.

## Build / test / packaging: Maven + JUnit 5 + Maven Central

**Maven** (`mvn`) is the most-ubiquitous JVM build/dependency tool, with a simpler
offline/reproducible story than Gradle (no daemon, no build-script-as-code surface)
— the better fit for the dependency-minimization + reproducible-container stance.
Deps are pre-fetched into the image's local `~/.m2` at container build time, so the
dev loop runs `mvn -o` (offline) under `--network=none`. **JUnit 5 (Jupiter)** is
THE JVM test standard — and the one place Java deliberately diverges from the
OCaml/Zig/CL "hand-roll even the test framework" stance: JUnit 5 is so ubiquitous
and de-facto-reviewed that taking it (test-scope only, never shipped) is the
idiomatic, low-surprise choice. Still pinned exactly + ≥30-day. The conformance
harness is a JUnit test that loads the normative fixture and asserts byte-identity.
Distribution is **Maven Central** (the JVM registry); publishing requires a verified
reverse-DNS namespace (`org.entitycore`), the optional S5 registry step (A-JAVA-005).

## Java idiom: records + sealed types + pattern-matching switch (JDK 16/17/21)

The codec value types (`ContentHash`, `PeerId`, `Entity`) are Java **records**
(immutable, the Java analogue of C# records); the ECF value-node hierarchy and the
message types are **sealed interfaces** with `permits`, enabling **exhaustive
pattern-matching `switch`** (JEP 441, GA in JDK 21) over the closed set — the static
analogue of OCaml's exhaustive variant match and Zig's exhaustive error set, and the
reason JDK 21 (not an older LTS) is the pin: pattern matching for switch reached GA
in 21, giving the codec/dispatch ladders compile-checked exhaustiveness.

## License: Apache-2.0 (S9 default = ecosystem norm)

The JVM ecosystem is Apache-2.0-leaning (Apache Software Foundation projects, the
Maven Central default), so the repo's Apache-2.0 default IS the ecosystem norm — no
override (explicit patent grant retained).

## Toolchain pins (S11)

- **Temurin (Eclipse Adoptium) JDK 21.0.10+7** (~143 days old at authoring).
  JDK 21 is the current LTS, and 21 (not 17) is required
  for **pattern matching for switch GA (JEP 441)** + **virtual threads GA (JEP 444)**
  — both load-bearing for the idiom choices above. Temurin/Adoptium is a **reviewed
  vendor channel** (the .NET-feed analogue per the supply-chain scope clarification),
  so the ≥30-day AGE floor **relaxes for the JDK itself** — but the **exact version
  pin stands for reproducibility**. 21.0.10 is chosen over the newer 21.0.11+10
  (~51d) as the conservative, well-aged patch; both are LTS-clean. The
  JDK is the toolchain, NOT a registry-pulled package.
- **JUnit 5.11.4** (released 2024-12, ~18 months old) — **test-scope only**, never
  shipped in the artifact. Registry-pulled (Maven Central) with no human gate, so the
  ≥30-day floor applies with full force — comfortably met.
- **maven-surefire-plugin 3.5.2** (2024-11, ~19 months) — the test runner; build-
  plugin on the test path only.
- **BouncyCastle `bcprov-jdk18on` 1.80** (~17 months old) — the
  **OPT-IN agility cross-check / fallback only**; the core build is BouncyCastle-FREE.
  Registry-pulled → the ≥30-day floor applies → far exceeded. NOTE: BC **1.84**
  is only **~28 days old** — UNDER the floor — so it is **explicitly NOT
  picked**; 1.80 is the conservative aged pin (BC 1.81 is also clean
  but 1.80 is the longest-deployed choice).
- **Maven 3.9.9** — the build tool, bundled into the image (reviewed-channel: exact
  pin for repro, age floor relaxed).

## Spec version: read v7.72, codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.72` (latest snapshot). The codec
uses the `test-vectors/v0.8.0` corpus because `ENTITY-CBOR-ENCODING.md` and
`ENTITY-NATIVE-TYPE-SYSTEM.md` are byte-identical v7.71→v7.72 (SHA-verified upstream
per the cohort) — no wire-format change. The v7.73 nonce-echo (§4.6) and v7.74
(register/outbound/emit/owner-cap/§7a) folds are peer-layer (S3+), not codec, and
are resynced at S3. The spec-data snapshot stopping at v7.72 while HEAD is v7.74 is
logged A-JAVA-001 (corroborates A-CL-001 — escalate to arch; non-blocking for S1/S2).

## peer_id construction: §1.5 canonical-form table, NOT §7.4 (A-JAVA-004) — FOURTH spec-first peer

The profile **mandates** deriving the Ed25519 peer_id from the **§1.5 v7.65
canonical-form table** — `hash_type = 0x00` identity-multihash, digest = the **raw
public key bytes** (no hash) — and **ignoring the stale §7.4 pseudocode** and the
§1.5-line-436 skeleton, both of which still show the pre-v7.65 `SHA256(public_key)`
form (`hash_type = 0x01`). **Verified directly in `spec-data/v7.72`:**
`ENTITY-CORE-PROTOCOL-V7.md` **line 448** (the §1.5 canonical-form table) declares
`0x01 Ed25519 → 0x00 identity-multihash … The digest IS the public_key (v7.64)`;
**line 436** (the §1.5 path skeleton) and **lines 437–438, 442, 3561** (the §7.4
`derive_peer_id` area) still show `Base58(... || SHA256(public_key))` with
`hash_type = 0x01` and even claim "peer-IDs at the current spec are 34 bytes" — the
stale SHA-256 form. The §1.5 "Wire-acceptance carve-out" (Amendment 4, line 493)
confirms the SHA-256 form is at most a *decode* compat form, never the *construction*
form. Baking the §1.5 form into the profile **proactively** dodges the
handshake-failure debug cycle (`401 identity_mismatch`) that **Zig (A-ZIG-001),
OCaml (A-OC-007), and Common Lisp (A-CL-002)** each hit or pre-resolved — and which
S2's conformance corpus would NOT catch, because it uses opaque digests, so a wrong
construction passes S2 and only blows up at the S4 handshake. **This is the FOURTH
spec-first peer to corroborate the §7.4/§1.5 contradiction** — past decisive; logged
A-JAVA-004 as a corroboration with the arch escalation re-stated.
