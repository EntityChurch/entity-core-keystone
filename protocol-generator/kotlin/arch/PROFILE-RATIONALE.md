# entity-core-protocol-kotlin — Profile Rationale

Audit trail for every major S1 profile choice. Kotlin is a **"reach" peer**
(`research/RELEASE-READINESS.md` §2): an Android-native / JVM-Kotlin ecosystem
coverage build. On the **spec-discovery axis** it is **corroboration-only** — the
JVM idiom was already exercised by the **Java peer #7**, so the language-axis
discovery well is largely dry here; Kotlin is built for **ecosystem reach**, not
to surface new spec defects. The mandate still stands: **log anything that does**
surface, and (like any mainstream stack) treat a defect a "boring" widely-deployed
language hits as **high-signal**.

Each choice below was derived from the V7 spec (`spec-data/v7.75`) + Kotlin/JVM
ecosystem research, **not** ported from the Java peer. The Java peer
(`protocol-generator/java/`) is the direct JVM analog and the single most relevant
model — but Kotlin is authored as an **independent reader of V7**, and the headline
S1 decision (below) is precisely the choice to keep it independent rather than
collapse it into Java.

---

## Codec strategy decision (THE headline S1 call — operator deferred it to S1)

**RULING: NATIVE, HAND-ROLLED Kotlin ECF codec. NOT interop into the Java peer's
codec.**

The slate (`research/RELEASE-READINESS.md` §2) flagged Kotlin's codec as
**"interop into the Java peer's codec OR hand-roll (profile)"** and the operator
explicitly deferred the call to S1. The two options, weighed on
independence-value × reach-value × effort:

### Option A — interop into the Java peer's codec (REJECTED)
Kotlin runs on the JVM and has zero-overhead Java interop, so Kotlin could simply
call the Java peer's `EcfCodec` directly. Fast, idiomatic-for-Android (calling a
Java library from Kotlin is everyday Android practice), least effort.

**Why rejected — it proves nothing independent.** A peer exists to be an
**independent reader of V7**; that independence is the *entire* corroboration value
this reach peer contributes. Interop-into-Java is essentially **"Java in Kotlin
syntax"** — it collapses the Kotlin and Java peers to **one** reading of the spec.
This is exactly the keystone's **"no trench-coat" principle**, stated for the C++
peer as **decision D1**: an FFI/interop peer that just reuses another impl *"proves
nothing independent."* If Kotlin reuses Java's codec, then a latent Java-codec bug
is a *shared* bug, not a corroborated-clean result, and a Kotlin run can never
*disagree* with Java — so it can never corroborate. For a peer whose **only**
mandate is corroboration (discovery well dry), reusing the thing it is meant to
corroborate is self-defeating.

### Option B — hand-roll a native Kotlin ECF codec (CHOSEN)
A `CanonicalCbor` / `EcfCodec` written in Kotlin, owning the full canonical layer.

**Why chosen:**

1. **Independence / keystone thesis.** A hand-rolled Kotlin codec is a genuinely
   independent second JVM reading of ENTITY-CBOR-ENCODING. It *can* disagree with
   Java — which is what makes a clean cross-check meaningful and what gives this
   reach peer its corroboration value. This is the non-negotiable reason.

2. **The effort delta is real but modest — because the "easy library path" does
   not exist for EITHER language.** The **A-005 finding**, re-confirmed across the
   whole cohort (C#, TS, OCaml, Elixir, Zig, CL, Swift, Haskell, **Java**), is that
   **no CBOR library gives ECF's canonical guarantees**: ECF requires RFC-7049
   **length-FIRST then lexicographic** map-key ordering (≠ RFC-8949 §4.2 **bytewise**
   ordering, which is what `kotlinx.serialization`-CBOR, `jackson-dataformat-cbor`,
   `com.upokecenter.cbor`, and `co.nstant.in.cbor` implement at best), plus the
   shortest-float (incl. f16) ladder, recursive major-type-6 tag rejection, and
   raw-byte fidelity — all of which must be hand-enforced **on top of** any library.
   The **Java peer hand-rolled its codec for exactly this reason.** So hand-rolling
   in Kotlin is *not* "the hard path vs an easy library path" — there is no easy
   library path for ECF in any JVM language. The only marginal cost of Option B
   over Option A is "write a Kotlin codec" vs "call the Java codec," and that cost
   buys the independence the peer exists to provide.

3. **Idiom reach.** A hand-rolled Kotlin codec exercises Kotlin-native shapes that
   genuinely cover the Kotlin/Android ecosystem: `ByteArray` with Kotlin's
   **unsigned types** (`UByte`/`ULong`, stable since 1.5) carrying the uint64
   head-form range *natively* (no `Long.compareUnsigned` dance Java/C# needed),
   sealed-class ECF value nodes, and a `when`-exhaustive decode ladder. That is real
   Kotlin reach, not a syntax veneer over Java bytecode.

**Crypto considered too (S6 — the profile decides, not "the popular lib"):** the
JVM closes the **full** crypto bar natively via the JDK SunEC provider (Ed25519 +
Ed448) and SunMessageDigest (SHA-256 + SHA-384), callable from Kotlin with
zero-overhead interop and **no third-party dependency**. So Option B does not even
incur a crypto-library cost — crypto is native either way. This makes the only
meaningful axis of the decision the *codec*, and the ruling is unambiguous: own it.

`ffi` (consume `libentitycore_codec`) remains the **documented fallback** if a
codec spike ever fails — but it is not expected, because the JVM crypto is native
and the canonical layer is the same hand-roll every peer already does. **Codec
spike at S2 start** (PHASE-S1 mandate): push the `map_keys` + `float` v7.71 vectors
through the hand-rolled encoder before the full build — the load-bearing canonical
risk (length-then-lex ordering + shortest-float f16). Logged **A-KT-001**.

---

## Why Kotlin is a worthwhile peer despite the dry well — and the explicit caveat

The Java peer already covers the **JVM substrate** and the **mainstream static-OO**
idiom family. On the **idiom-distance axes the cohort tracks** (number model,
dispatch shape, error model, concurrency, memory discipline), Kotlin shares the JVM
substrate with Java and so is **mostly saturated on the substrate**, BUT it diverges
from Java on **three real idiom axes** that make it more than "Java again":

- **Error model** — Java chose **checked exceptions**; Kotlin has **no checked
  exceptions** and the idiomatic recoverable-error seam is a **sealed-class
  `Result`/`Either`** matched exhaustively by `when`. Different point in the
  error-model design space, reached via a different mechanism.
- **Concurrency** — Java uses **platform / virtual threads**; Kotlin's headline
  concurrency model is **coroutines** (structured concurrency, `suspend`). Different
  carrier for the same N6/N7 reentrancy + §7b store-safety requirements.
- **Number model** — Kotlin's **unsigned types** (`UByte`/`ULong`) carry the uint64
  ECF head-form range natively, removing the `Long.compareUnsigned` footgun Java/C#
  hit. A small but real ergonomic divergence on the number axis.

So the **expected spec-refinement yield is SMALL** (the JVM wire-and-crypto behavior
is identical to Java's; a clean re-derivation is the *expected* result). The reason
to build it anyway, for the arch-review ledger: **(1)** an independent second JVM
reading **corroborates** the Java findings (a clean Kotlin run strengthens
confidence that the JVM peers are right; a disagreement would be a high-signal
finding); **(2)** Kotlin is a **huge ecosystem** (Android-first, JetBrains tooling)
whose adopters want a *Kotlin-idiomatic* peer, not a Java jar — pure reach value;
**(3)** the three idiom-axis divergences (sealed-Result error model, coroutine
concurrency, unsigned number types) are genuine new data points on those axes even
though the substrate is shared. Kotlin is the **"does a Kotlin-idiomatic reading of
V7 land in the same place as the Java reading?"** probe.

---

## Crypto: JDK SunEC (Ed25519, Ed448) + SunMessageDigest (SHA-256, SHA-384) — native, no dep

Identical to the Java peer, by independent arrival from the shared JDK. The SunEC
provider supplies Ed25519 and Ed448 via the unified `Signature` /
`KeyPairGenerator` / `KeyFactory` API (`NamedParameterSpec.ED25519` / `ED448` +
`EdECPrivateKeySpec` / `EdECPublicKeySpec`); `MessageDigest.getInstance("SHA-256" |
"SHA-384")` covers both hash sizes. All ship with the JDK — no Gradle dependency,
no libsodium/OpenSSL system dep. Called from Kotlin via zero-overhead JVM interop
(`java.security.*` is just a Kotlin import). The S2 wrinkle to verify (shared with
Java): extracting / building the **raw 32-byte (Ed25519) / 57-byte (Ed448)** public
key for the wire form — the JDK exposes EdEC keys as an (x-sign-bit, y-coordinate)
point, not a raw byte string, so raw-pubkey extraction (for the identity-multihash
peer_id) and raw-seed key construction need explicit encoding handling. Logged the
S2 task in **A-KT-002**.

## Ed448 / SHA-384 agility: native-default (JDK SunEC), BouncyCastle opt-in cross-check, DEFERRED higher bar

The crypto-agility higher bar (v7.67: key_type Ed448 `0x02`; SHA-384
content_hash_format `0x01`) is reachable from the **default build via JDK SunEC** —
no FFI, no opt-in sub-library, no hybrid — exactly as the Java peer (and unlike
OCaml/Zig, which had ecosystem gaps). **BouncyCastle (`bcprov-jdk18on`)** stays the
**opt-in** pure-managed independent cross-check / fallback, the same stance as Java
(and OCaml's opt-in `entitycore_agility` sub-lib); the **core build is
BouncyCastle-FREE** (JDK covers floor + agility). **As a reach peer, Ed448 agility
is a DEFERRED higher bar** — the v0.1 target is the **floor** (Ed25519 + SHA-256);
the agility corpus is a later-cycle deliverable, taken via SunEC (or BC cross-check)
when the peer reaches that bar. Logged **A-KT-002**.

## CBOR: hand-rolled (no JVM library) — and the JVM byte[] aliasing seam

As argued in the codec decision: the JVM CBOR libraries target general/RFC-8949
CBOR; ECF's length-first ordering + float ladder + tag rejection must be owned
regardless. **JVM footgun the codec must respect (shared with Java):** `ByteArray`
is **mutable and aliasable** — the codec MUST defensive-copy bytes in and out of
value types and NEVER expose an internal `ByteArray` by reference (a caller could
mutate the backing array of a `ContentHash`; Kotlin's `val` makes the *reference*
immutable but **not the array contents**). Recorded in
`[idiom].no_byte_array_aliasing`. The immutable-data-structure peers (OCaml `Bytes`,
Elixir binaries, Haskell `ByteString`) do not have this exact seam. **Kotlin
mitigant the others lacked:** Kotlin's **unsigned types** (`UByte`/`ULong`) carry
the full uint64 head-form range natively, so the number-axis half of the seam (the
C#-`ulong` / OCaml-`int63` trap) is softer here — `ULong` comparison is unsigned by
construction (the canonical shortest head-form still gets hand-checked on emit; the
unsigned type only removes the signedness-comparison footgun).

## Error model: sealed-class Result (the Kotlin static-rigor seam — distinct from Java's checked exceptions)

Kotlin's idiomatic recoverable-error seam is a **sealed-class `Result`/`Either`**,
NOT exceptions (Kotlin has no checked exceptions, and throwing for recoverable
protocol errors is non-idiomatic). Codec/protocol decode failures return a sealed
`EcfResult<T>` (Ok/Err) or a sealed `EntityError` hierarchy matched **exhaustively
by `when`** — the compiler enforces exhaustiveness over a sealed type with no `else`
branch. This is the static-rigor analogue of OCaml's `result`, Zig's error union,
and Java's checked exceptions, reached via **Kotlin's own mechanism** — and it is
the **primary axis on which this peer diverges from Java** (which chose checked
exceptions). Exceptions stay reserved for truly unrecoverable programmer errors
(`IllegalStateException` / `IllegalArgumentException`), the Kotlin convention.
Hierarchy: `sealed class EntityError` → `CodecError` (`NonCanonicalEcf`,
`TruncatedInput`, `TagRejected`, `DuplicateKey`), `CryptoError` (`BadSeed`,
`UnsupportedKeyType`, `UnsupportedContentHashFormat`), `ProtocolError`
(`AuthenticationFailed`, `AuthorizationDenied`, `PayloadTooLarge` [413, §4.10a],
`ChainDepthExceeded` [400, §4.10b]), `TransportError`. Protocol-status failures map
a sealed variant → status code at the dispatcher boundary.

## Async: kotlinx.coroutines (structured concurrency — distinct from Java's threads)

Kotlin's headline concurrency model is **coroutines** (`kotlinx.coroutines`:
structured concurrency, `suspend` functions, `Dispatchers`). For a `--profile core`
peer the N6/N7 reentrancy invariants (inbound concurrent with outbound dispatch;
reentrant request_id demux; §6.11 reentry) are satisfied by **one coroutine per
connection** (on `Dispatchers.IO` / a `supervisorScope`), with a reader coroutine
demuxing `EXECUTE_RESPONSE` by request_id via a thread-safe
`ConcurrentHashMap<requestId, CompletableDeferred<T>>` — the coroutine analogue of
Java's `CompletableFuture` demux and the OCaml/Zig per-thread demux. **§7b
store-safety:** coroutine confinement (a single-threaded store dispatcher) or a
`Mutex`-guarded store gives the structured-concurrency store-race discipline (the
§7b taxonomy's manual-but-structured shape, distinct from Swift/Elixir
actor-isolation and Haskell STM). This is the **second axis where the peer diverges
from Java** (threads → coroutines). Public surface: **both** a blocking facade
(`runBlocking`-backed, for non-coroutine/Java callers) **and** native `suspend`
functions (the idiomatic Kotlin/Android surface). Not exercised by the codec
(pure/synchronous) — validated at S3. `kotlinx.coroutines` is the **one non-stdlib
runtime dependency** the peer takes (a deliberate S6 trade: idiom over absolute
minimalism — coroutines *are* how Kotlin does concurrency; a thread-only Kotlin peer
would read as un-idiomatic Java). Logged **A-KT-003**.

## Naming: Kotlin Coding Conventions (PascalCase / camelCase / UPPER_SNAKE)

`PascalCase` for classes/interfaces/data classes/objects/enums/sealed types;
`camelCase` for functions, properties, locals, parameters; `UPPER_SNAKE_CASE` for
`const val` / top-level `val` constants and enum constants; `lowercase.dotted`
reverse-DNS packages (`org.entitycore.protocol`). Largely overlaps Java but with
Kotlin specifics: **properties, not getter methods**; **file-level functions**
allowed; a file may hold **multiple types** (e.g. a whole sealed hierarchy in one
`.kt`). **CASE-EXACT data caveat (the A-CL-009 lesson applied proactively):** all
external string/byte hex rendering MUST be **lowercase** to match the Go oracle
(`hex.EncodeToString`) and the cohort — Kotlin `"%02x".format(b)` defaults lowercase
(good), so the codec uses `%02x` (never `%02X`) for all address-space tree-path hex.

## Build / test / packaging: Gradle (Kotlin DSL) + kotlin.test + Maven Central

**Gradle with the Kotlin DSL (`build.gradle.kts`)** is THE idiomatic Kotlin/Android
build tool — the `kotlin-gradle-plugin` is first-party JetBrains, and every kotlinx
library, Android Studio, and JetBrains toolchain assumes Gradle. This is a
**deliberate divergence from the Java peer's Maven** choice: Maven would read as
un-idiomatic in Kotlin, where Gradle+Kotlin-DSL is the ecosystem norm. Reproducible
/ offline via the **Gradle wrapper** (pins the exact Gradle distribution) +
pre-fetched deps + `gradle --offline --no-daemon` under `--network=none`.
**kotlin.test** (on the JUnit 5 platform) is the idiomatic Kotlin test surface — the
one test-path registry dependency; taking the de-facto standard (test-scope only,
never shipped) is the low-surprise idiomatic choice (the Java/JUnit-5 stance applied
to Kotlin), pinned exactly + ≥30-day. The conformance harness is a kotlin.test test
that loads the normative fixture and asserts byte-identity. Distribution is **Maven
Central** (the JVM registry) via the vanilla **Gradle `maven-publish` + `signing`**
plugins (no third-party publish plugin — keeps the supply chain minimal); publishing
requires a verified reverse-DNS namespace (`org.entitycore`), the optional S5 step
(A-KT-005).

## Kotlin idiom: data classes + sealed types + exhaustive `when` + unsigned types

The codec value types (`ContentHash`, `PeerId`, `Entity`) are Kotlin **data
classes** (immutable, auto `equals`/`hashCode`/`copy` — the Kotlin analogue of Java
records / C# records); the ECF value-node hierarchy, the message types, and the
`EntityError` hierarchy are **sealed classes/interfaces**, enabling **exhaustive
`when`** over the closed set (compiler-checked, no `else` needed) — the Kotlin static
analogue of OCaml's exhaustive variant match, Zig's exhaustive error set, and Java's
sealed-type switch. Null-safety lives in the **type system** (`T?` vs `T`) — no
`Optional` needed (the Kotlin idiom). **Unsigned types** (`UByte`/`ULong`) carry the
uint64 head-form range natively. **Extension functions** (`ByteArray.toBase58()`,
`ByteArray.toHexLower()`) and **companion-object factories** (`PeerId.fromPublicKey`,
`ContentHash.of`) keep value types clean and idiomatic.

## License: Apache-2.0 (S9 default = ecosystem norm)

The Kotlin/JVM ecosystem is Apache-2.0-leaning (Kotlin itself is Apache-2.0;
`kotlinx.*` are Apache-2.0; Android's core is Apache-2.0), so the repo's Apache-2.0
default IS the ecosystem norm — no override (explicit patent grant retained).

## Toolchain pins (S11)

- **Temurin (Eclipse Adoptium) JDK 21.0.10+7** (~143 days old at
  authoring). JDK 21 = current LTS; the JVM target Kotlin 1.9 supports.
  **Shared with the Java toolchain image** (same pinned Temurin). Reviewed vendor
  channel → age floor relaxes, exact pin + verified sha256 stand for repro/integrity.
- **Kotlin 1.9.25** (~19 months old) — compiler + stdlib +
  kotlin-test. The **1.9 line** is the conservative, stable, Android-default line;
  the **2.x K2 compiler** (2.0/2.1) is newer and 2.1.x is within the cool-down at
  authoring — **explicitly NOT picked**. JetBrains is a reviewed channel, but
  `kotlin-test` / `kotlin-stdlib` are Maven-Central-pulled → the ≥30-day floor
  applies (met by ~19 months). Exact pin for repro.
- **kotlinx-coroutines-core 1.8.1** (~13 months old) — the
  structured-concurrency runtime, the one non-stdlib **runtime** dep. Registry-pulled
  → ≥30-day applies → far exceeded. 1.9.0 / 1.10.x are newer; 1.8.1 is the
  conservative aged pin compatible with Kotlin 1.9.25.
- **JUnit platform 5.11.4** (2024-12, ~18 months) — the kotlin.test backend,
  **test-scope only**, never shipped. Registry-pulled → ≥30-day → met.
- **BouncyCastle `bcprov-jdk18on` 1.80** (~17 months) — the **opt-in**
  agility cross-check / fallback only; the core build is BouncyCastle-FREE.
  Registry-pulled → ≥30-day → far exceeded. BC **1.84** (~33d) — only
  marginally over the floor and newer than needed — is **not** picked; 1.80 matches
  the Java peer's aged pin.
- **Gradle 8.10.2** (~9 months) — the build tool, pinned via the wrapper
  distribution + a verified distribution sha256. Reviewed channel (Gradle Inc.) →
  exact pin for repro, age floor relaxed; a well-aged 8.x supporting JDK 21 + Kotlin
  1.9 (Gradle 8.5+ supports JDK 21; 8.10.2 is the conservative aged pick).

## Spec version: read v7.75 (snapshot), codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.75` (the latest stamped snapshot).
The codec uses the `test-vectors/v0.8.0` corpus because `ENTITY-CBOR-ENCODING.md` is
byte-identical v7.71→v7.75 (label 1.5, SHA-verified upstream per the cohort) — no
wire-format change. Live spec/oracle HEAD is **v7.77** with a **byte-unchanged core
floor v7.75→v7.77** (`profile.go` unchanged; the v7.77 delta is all
extension/relay/network/encryption + the V8-naming kebab fold, which every peer
already satisfies) — so this peer derives its protocol surface from the v7.75
snapshot and re-runs against the **current oracle** (`entity-core-go @ e8524ed`, the
17-peer-normalized reference), per the cohort convention. The peer-layer v7.73/v7.74
folds (peer-id reconciliation, register/outbound/emit/owner-cap §6.13/§6.9a, §7a
conformance handlers) are reflected in the v7.75 snapshot body and are S3+ work.

## peer_id construction: §1.5 canonical-form table, NOT the legacy SHA-256 form (A-KT-004)

The profile **mandates** deriving the Ed25519 peer_id from the **§1.5 v7.65
canonical-form table** (`spec-data/v7.75` **line 459**: `key_type=0x01` Ed25519 →
`hash_type=0x00` identity-multihash, digest = the **raw public key bytes**, "The
digest IS the public_key (v7.64)") — and **ignoring** the legacy SHA-256 form
(`hash_type=0x01`). The §1.5 Wire-acceptance carve-out (Amendment 4) makes the
SHA-256 form at most a *decode* compat form, never the *construction* form.
**On v7.75 this is corroboration-only, not a fresh finding:** v7.73 erratum E1
already reconciled the stale §7.4 pseudocode to defer to the §1.5 table, so the
§7.4-vs-§1.5 contradiction that **OCaml (A-OC-007)**, **Zig (A-ZIG-001)**, **Common
Lisp (A-CL-002)**, and **Java (A-JAVA-004)** surfaced is **already closed in the
v7.75 body**. Baking the §1.5 form into the profile proactively still matters: it
dodges the `401 identity_mismatch` handshake-failure debug cycle that S2's
opaque-digest conformance corpus would NOT catch (a wrong construction passes S2 and
only blows up at the S4 handshake). Logged **A-KT-004** as a corroboration.
