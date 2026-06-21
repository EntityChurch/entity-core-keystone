# entity-core-protocol-dart — Profile Rationale

Audit trail for every major S1 profile choice. Dart is a **"reach" peer**
(`research/RELEASE-READINESS.md` §2 row 4): a **Flutter cross-platform mobile / Dart
ecosystem** coverage build. On the **spec-discovery axis** it is **corroboration-only** —
the static-typed-with-null-safety + async/Future idiom space is already exercised by the
**Kotlin** (#18), **TypeScript** (#2), and **C#** (#1) peers, so the language-axis discovery
well is dry here; Dart is built for **ecosystem reach** (a Dart/Flutter developer can pull a
native, pure-Dart, pub.dev peer), not to surface new spec defects. The mandate still stands:
**log anything that does** surface, and treat a defect a "boring" widely-deployed language
hits as **high-signal**.

Each choice below was derived from the V7 spec (`spec-data/v7.75`) + Dart/Flutter ecosystem
research, **not** ported from Kotlin or TS. The closest analogs are **Kotlin** (sealed-class
Result error model, sound static null-safety, the hand-rolled-codec independence ruling) and
**TypeScript** (the uint64/web-number trap solved with a wide integer carrier; Promise/Future
async; the consumable-data-library browser-portability angle). Where a value matches them it
is by **independent arrival** from V7 + the shared static-typed/null-safe/async substrate, NOT
by inheritance.

---

## Codec strategy decision — NATIVE, HAND-ROLLED Dart ECF codec (the slate decision, affirmed)

**RULING: NATIVE, HAND-ROLLED Dart ECF codec. NOT the `cbor` pub package. NOT FFI for the codec.**

The slate (`research/RELEASE-READINESS.md` §2 row 4) already fixed the codec as **"hand-roll ECF
(cbor pkg not ECF)"**. S1 affirms it with the reasoning on record:

1. **No Dart CBOR library gives ECF canonicality.** The `cbor` pub package (and `cbor_codec`)
   implement general **RFC-8949** CBOR. ECF requires, on top of any library: RFC-7049
   **length-FIRST then bytewise** (CTAP2) map-key ordering (≠ RFC-8949 §4.2 **bytewise**
   ordering), the **shortest-float incl. f16** ladder, **recursive major-type-6 (tag) rejection**
   at any nesting depth → `400 non_canonical_ecf`, and **raw-byte fidelity** + the full
   `uint64`/`nint` head-form range. This is the **A-005 finding**, re-confirmed across the **entire
   cohort** (C#, TS, OCaml, Elixir, Zig, CL, Swift, Haskell, Java, Kotlin, C++) — **every** native
   peer hand-rolled the canonical layer regardless of any library underneath. So hand-rolling in
   Dart is **not** "the hard path vs an easy library path"; **there is no easy library path for
   ECF** in any language. A `cbor`-package peer would still have to hand-enforce the canonical
   layer on top, buying nothing but a dependency and a pin.

2. **Independence / keystone thesis.** A hand-rolled Dart codec is a genuinely independent reader
   of `ENTITY-CBOR-ENCODING` — it **can disagree** with the other peers, which is what makes a
   clean cross-check meaningful and is the *entire* corroboration value this reach peer
   contributes. This is the keystone's **"no trench-coat" principle** (stated for C++ as decision
   D1): an FFI-only peer that just calls `libentitycore_codec` proves nothing independent of the
   existing C/Rust codec. The codec MUST be native Dart.

3. **Idiom reach.** A hand-rolled Dart codec exercises Dart-native shapes — `Uint8List`/`ByteData`
   typed-data buffers, **sealed-class** ECF value nodes with **exhaustive switch-expression**
   pattern matching (Dart 3), a **sealed Result** error channel, and the **BigInt** head-form
   carrier — genuine Dart/Flutter ecosystem reach, not a syntax veneer.

`ffi` (consume `libentitycore_codec` via `dart:ffi`) remains the **documented fallback** only if a
codec spike ever fails — but it is not expected, and it would forfeit the pure-Dart
self-containment that is this peer's reach value (see Crypto). **Codec spike at S2 start**
(PHASE-S1 mandate): push the `map_keys` + `float` v7.71 vectors through the hand-rolled
encoder/decoder before the full build — the load-bearing canonical risk (length-then-lex ordering
+ shortest-float f16). Logged **A-DART-001**.

---

## THE integer / uint64 head-form carrier decision — BigInt (the single most important codec call)

**RULING: carry the FULL `uint64`/`nint` head-form range via Dart's arbitrary-precision `BigInt`
at the head-form boundary. Bare `int` only for values provably within the safe-integer range.**

This is the **single most important codec-correctness decision** for Dart, and it is a direct
application of the cohort's **A-OC-001 / F7** lesson and the **TypeScript bigint** precedent.

**The trap.** Dart `int` is **64-bit on the native VM** (63 value bits + sign — it represents the
full `uint64` head range as a possibly-negative signed 64-bit value, exactly like Java/Kotlin's
signed `Long`). **But** under `dart2js` / `dart compile js` / the **web platform**, a Dart `int`
is a **JavaScript number** with only **53 bits of integer precision** — values past `2^53` lose
precision (`2^53` and `2^53 + 1` collapse to the same value). A `uint64` head-form value near
`2^63` (the ECF `int.10/15/16/17` band, `[2^63, 2^64-1]`) would **silently truncate** on web.

**Why web matters here.** This is a **Flutter** reach peer, and Flutter **targets web** (and WASM).
A codec that is correct on the Dart VM but silently wrong under `dart2js` would be a latent
data-corruption bug exactly in the reach audience the peer exists to serve. The TS peer hit the
identical trap (JS `number` caps at `2^53`) and solved it with **`bigint` end-to-end** for the
integer surface (its `[codec].integer_model = "always-bigint"`, the R1/F7 rule).

**The ruling.** The Dart codec carries the head-form integer range via **`BigInt`** (first-party
`dart:core`, arbitrary-precision on **both** native and web). Specifically:
- `uint`/`nint` decode that **could exceed the safe range** decodes to `BigInt`; the canonical
  **shortest-head-form emit** is computed over `BigInt`. The `[2^63, 2^64-1]` band is `BigInt`.
- Small ints (provably within the safe `2^53` range) may stay `int` for ergonomics, but **any**
  value that could exceed it is `BigInt`-backed.
- This makes the codec **web-safe (dart2js/WASM)** *and* native-correct.

**Rejected alternative — the `fixnum` package (`Int64`).** `fixnum` gives strict 64-bit ints even
on web, but it is a **registry dependency**, and `BigInt` is **first-party, zero-dep**, and covers
the full `uint64` range exactly. Supply-chain minimalism (S11) + the zero-dep preference → `BigInt`.

**S2 must watch this.** The corpus exercises the head-form band; run the codec spike **and** at
least a smoke `dart2js`/`dart compile js` build of the integer round-trip to confirm no web-int
truncation. **NEVER carry a `uint64`-range head value in a bare `int`.** Logged **A-DART-006**.

---

## Crypto: cryptography_plus (Ed25519 floor, pure-Dart) + package:crypto (SHA-256 floor) — pure-Dart, self-contained; Ed448 deferred

**RULING (S1 evaluation of the slate's "`cryptography` pkg OR FFI" open question): pure-Dart
Ed25519 via `cryptography_plus`, with `package:crypto` for the SHA-256 floor. FFI is the
documented fallback, not the v0.1 path.**

The slate left the crypto floor as **"`cryptography` pkg / FFI — evaluate in S1 which is genuinely
conformant/maintained and idiomatic; pick one and justify."** The S1 evaluation:

- **The original `cryptography` package (terrier989 / `dint-dev/cryptography`) is effectively
  stalled.** The community moved the maintained line to **`cryptography_plus`** (originally
  gohilla.com, repo now `emz-hanauer/dart-cryptography`) **precisely because of lack of upstream
  maintenance**. Pinning the stalled original would violate the slate's "genuinely maintained"
  bar. So the choice within the package route is the **maintained fork**, `cryptography_plus`.

- **Pure-Dart Ed25519 keeps the peer self-contained across EVERY Flutter target.** `cryptography_plus`
  ships a **pure-Dart** Ed25519 (RFC-8032 deterministic). The deciding factor — the reach value of
  this peer — is **self-containment**: a pure-Dart crypto runs unchanged on **iOS / Android / web /
  WASM / desktop** with **no native `.so`/`.dylib` to bundle and no platform-channel to wire. The
  reach audience *is* Flutter mobile (and web). An FFI peer (to `libentitycore_codec`'s C-ABI
  crypto) would be byte-correct but would forfeit exactly that self-containment — a native library
  per Flutter ABI, the opposite of the reach goal. (The `cryptography_flutter_plus` companion can
  delegate to OS crypto APIs *as an optimization* on mobile, but the floor is pure-Dart so the peer
  is correct everywhere without it.)

- **SHA-256 floor via the first-party `package:crypto`.** The Dart-team `crypto` package
  (`sha256.convert(bytes).bytes`) is the ubiquitous, pure-Dart, browser+native ecosystem standard
  for the bare hash — lower-surface and lower-churn than reaching into `cryptography_plus` for the
  hash. (`cryptography_plus` *does* ship `Sha256`; `package:crypto` is the leaner choice for the
  floor hash.) NOTE: SHA-256 is for `content_hash` over the entity's ECF bytes — the **peer_id is
  NOT** a SHA-256 of the pubkey (§1.5 identity-multihash, raw pubkey; see peer_id section).

- **Ed448 (agility higher bar) — GAP → DEFER (FFI route documented).** `cryptography_plus` has **no
  Ed448** (Ed25519/X25519/ECDSA/RSA + the SHA-2 family, but no Ed448-Goldilocks), and there is no
  maintained pure-Dart Ed448. Same native gap **C (A-C-001), Zig (A-ZIG-002), OCaml (A-OC-002),
  Rust (A-RUST-002), C++ (A-CPP-002)** hit and Swift deferred (A-SW-001). The §9.1 **floor**
  (Ed25519 `key_type 0x01` + SHA-256 `content_hash_format 0x00`) is fully native pure-Dart and
  **unaffected**. Per the slate ("gap → FFI/defer"): **defer for v0.1**. When/if agility lands, the
  dependency-lightest Dart route is **`dart:ffi`** to the sibling **`entity-core-codec-ffi-c`**
  agility `.so` (C-ABI v1.1 already vendored a self-contained openssl curve448 for its Ed448
  family) — but that **breaks the pure-Dart self-containment**, so DEFER is the v0.1 default and FFI
  is the documented agility route, NOT a v0.1 path. The **SHA-384** agility *hash* **is** in
  `cryptography_plus` (`Sha384`), so only the Ed448 **signature** is the gap. Logged
  **A-DART-002** (maintenance/fork evaluation) + **A-DART-003** (Ed448 gap).

**base58 + varint hand-rolled** (dep-minimization; ~80-line base58 long-division, inline LEB128
varint) — the same call C/Rust/C#/Go/Kotlin/C++ made; a dep for something this small is pure
liability.

---

## Error model: Dart 3 sealed-class Result + exhaustive switch expressions (distinct from TS's exceptions)

Dart's recoverable-error seam, **as of Dart 3 (2023)**, is a **sealed class + exhaustive
switch-expression** Result — the Dart-3 analogue of Kotlin's sealed `when`, OCaml's `result` match,
Zig's error union, and C++'s `std::expected`. Codec/protocol decode failures return a sealed
`EcfResult<T>` (`Ok`/`Err`) or are modeled as a sealed `EntityError` hierarchy matched
**exhaustively by a `switch` EXPRESSION** — the Dart analyzer reports a non-exhaustive switch over a
sealed type, no `default` needed. **Exceptions** stay reserved for truly unrecoverable programmer
errors (`StateError` / `ArgumentError`, the Dart convention) and are caught at the per-connection
task boundary so one bad connection never crashes the peer (§4.9 no-crash floor) — **never** for
protocol flow.

This is a **deliberate idiom point distinct from the TypeScript peer**, which chose plain
exceptions (JS idiom). Dart *could* throw too, but **Dart 3 sealed classes make the Result idiom
first-class and statically-exhaustive**, which is the distinct, more-rigorous idiom point this peer
occupies (closer to Kotlin than to TS). Hierarchy: `sealed class EntityError` → `CodecError`
(`NonCanonicalEcf`, `TruncatedInput`, `TagRejected`, `DuplicateKey`, `NonMinimalInt`,
`NonCanonicalFloat`), `CryptoError` (`BadSeed`, `UnsupportedKeyType`,
`UnsupportedContentHashFormat`), `ProtocolError` (`AuthenticationFailed` [401], `AuthorizationDenied`
[403], `PayloadTooLarge` [413, §4.10a], `ChainDepthExceeded` [400, §4.10b]), `TransportError`.
Protocol-status failures map a sealed variant → wire status code at the dispatcher boundary. Logged
**A-DART-004**.

---

## Async + concurrency: Future/async-await on the per-isolate event loop; event-loop confinement for §7b store-safety

Dart's headline concurrency model is **async/await over `Future<T>`** + a **single-threaded event
loop per isolate**, with **isolates** (no shared memory; message-passing) for true parallelism.
`Future` is the close analogue of TypeScript's `Promise`; the distinct Dart point vs the cohort is
**isolates** (vs TS web-workers / Kotlin coroutines / Java threads) and, crucially for §7b,
**event-loop confinement**.

- **Codec is sync** (pure CPU; no `Future`), like the TS/C#/Kotlin codecs — isolates are not
  needed for the codec.
- **N6/N7 reentrancy** (§4.8/§6.11 inbound concurrent with outbound; reentrant `request_id` demux):
  one event-loop isolate drives dispatch; each connection is handled by async `Stream<List<int>>`
  socket reads; a reader future demuxes `EXECUTE_RESPONSE` by `request_id` via a
  **`Map<int, Completer<T>>`** — the `Future` analogue of Kotlin's `CompletableDeferred`, Java's
  `CompletableFuture`, and OCaml's per-thread demux.
- **§7b store-safety (the §7b taxonomy: actor-isolation OR transactional OR manual).** Dart's
  **single-threaded event loop per isolate** gives store-safety **structurally**: within one
  isolate there is **no preemption**, so a **synchronous critical section** over the store map is
  **atomic by construction** — no data race is possible without an `await` mid-section. This is the
  **event-loop-confinement** shape (akin to Node/TS's single-threaded loop) and the cleanest §4.8
  story in the cohort alongside the actor-isolation peers (Elixir/Swift). The **A-C-009**
  atomic-refcount finding (no-GC shared-entity race under concurrent threads) is **N/A** for Dart:
  it is **GC'd AND single-threaded per isolate**, so shared entities are never concurrently mutated
  across threads (the same reason the other GC'd peers never hit A-C-009).
- **TCP_NODELAY MUST still be set** on every connection socket
  (`Socket.setOption(SocketOption.tcpNoDelay, true)`) — the **Zig §7b throughput finding** applies
  regardless of the concurrency model (Nagle/delayed-ACK on small req/resp frames is the throughput
  killer). Logged **A-DART-005**.

---

## Naming: Effective Dart (PascalCase / lowerCamelCase / lowercase_with_underscores) — and the lowerCamelCase-constant divergence

`PascalCase` for types (classes/mixins/enums/extensions/typedefs); `lowerCamelCase` for members,
functions, parameters, locals; **`lowercase_with_underscores`** for libraries, **file names**, and
the **package name** (Dart files are NEVER PascalCase — the strict convention). The Dart-specific
divergence the generator must not get wrong: **constants are `lowerCamelCase`** in Effective Dart
(`const maxMessageSize = ...`), **NOT `UPPER_SNAKE`** as in Kotlin/Java/TS, and **enum members are
`lowerCamelCase`** (`KeyType.ed25519`, `HashFormat.sha256`). **CASE-EXACT data caveat (A-CL-009
applied proactively):** all external hex rendering MUST be **lowercase** to match the Go oracle
(`hex.EncodeToString`) — Dart `b.toRadixString(16).padLeft(2,'0')` is lowercase by default; the
codec NEVER calls `.toUpperCase()` on hex. Pinned in `[idiom].hex_lowercase`.

---

## Build / test / packaging: the first-party `dart` tool + pub + pub.dev (+ package:test)

The **`dart` SDK tool** (`dart pub` / `dart compile` / `dart test`) is THE idiomatic Dart toolchain
— a single first-party tool, the cargo/go analogue, with no Gradle/Make ceremony. **`pubspec.yaml`**
is the manifest, **`pubspec.lock`** is committed (authoritative for reproducible
`dart pub get --offline`). Reproducible/offline via a pre-populated **`PUB_CACHE`** in the image (deps
fetched in one network-on build layer; the dev loop then runs `--network=none` with
`dart pub get --offline` — the TS/npm offline-after-one-pull pattern, the user's hard supply-chain
requirement). **`package:test`** (first-party Dart-team) is the ecosystem-standard test runner —
the one dev-scope dependency, never shipped. The conformance host is **`bin/peer.dart`**,
**AOT-compiled** (`dart compile exe`) for the S4 `validate-peer` gate (fast startup, no JIT warmup).
Distribution is **pub.dev** (the slate row-4 packaging decision); publishing requires a verified
pub.dev **publisher** namespace (the optional S5 step, A-DART-007). Parked version **`0.1.0-pre`**
(the cohort convention). NOTE: the package name is **`entity_core_protocol`** —
`lowercase_with_underscores`, because pub.dev names **cannot hyphenate** (the keystone peer id
`entity-core-protocol-dart` maps to the pub name `entity_core_protocol`).

---

## License: Apache-2.0 (S9 default, compatible with the ecosystem norm)

The Dart/Flutter ecosystem is **BSD-3/Apache-2.0-leaning** (the Dart SDK is BSD-3-Clause; Flutter is
BSD-3; `package:crypto` + `package:test` are BSD-3; `cryptography_plus` is **Apache-2.0**). The
repo's **Apache-2.0** default (S9; explicit patent grant) is compatible with the ecosystem — no
override.

---

## Toolchain pin (S11)

- **Dart SDK 3.11.6** (**~45 days** old at authoring → clears
  the ≥30-day floor). The **3.11 line** is the conservative pick: **3.12.x** (~24 days)
  is **UNDER the floor** and explicitly **NOT** picked. The SDK is fetched as the **dart-lang
  official release tarball** (a reviewed vendor channel — Google/dart-lang's reviewed build pipeline
  + a verified sha256), so the age floor *relaxes* for the SDK — but it is met anyway, and the exact
  pin + verified checksum stand for reproducibility. (fedora dnf does NOT carry a current Dart SDK,
  so the pin-the-official-tarball pattern is used, like the kotlin/zig/java toolchains.)
- **`cryptography_plus` 2.7.0** — the maintained community fork; the **one non-first-party crypto
  runtime dep**. Registry-pulled (pub.dev) → **≥30-day applies with full force**. **PIN-DATE TO
  VERIFY AT S2:** confirm 2.7.0's pub.dev publish date is ≥30 days old at the S2 build; if too new,
  pin the latest ≥30-day-old 2.x and log it (sentinel discipline, A-DART-002).
- **`crypto` 3.0.6** — the first-party Dart-team SHA-256 package; a long-stable release, well over
  ≥30 days; BSD-3.
- **`package:test` 1.25.15** — the first-party test runner, **dev-scope only** (never shipped).
  Registry-pulled, first-party; ≥30-day applied + met. **PIN-DATE TO VERIFY AT S2** (sentinel).
- The codec / base58 / varint / conformance harness are all **hand-rolled in-repo** — no further
  registry deps; `cryptography_plus`'s transitive deps are locked in the **committed pubspec.lock**.

---

## Spec version: read v7.75 (snapshot), codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.75` (the latest stamped snapshot). The codec uses
the `test-vectors/v0.8.0` corpus because `ENTITY-CBOR-ENCODING.md` is byte-identical v7.71→v7.75
(label 1.5, SHA-verified upstream per the cohort) — no wire-format change. Live spec/oracle HEAD is
**v7.77** with a **byte-unchanged core floor v7.75→v7.77** (the v7.77 delta is all
extension/relay/network/encryption + the V8-naming kebab fold, which every peer already satisfies),
so this peer derives its protocol surface from the v7.75 snapshot and re-runs against the **current
oracle** (`entity-core-go @ e8524ed`, the 19-peer-normalized reference, uniform 665 / 0 FAIL), per
the cohort convention. The §7a/§7b **conformance scaffolding** (validate handlers + concurrency
gate) is **GUIDE-carried**, not in the spec-data snapshot (the v7.74/v7.75 MANIFEST flags this
split) — pulled from `GUIDE-CONFORMANCE.md` + the keystone generator menu at S3/S4 (A-DART-009). A
spec-first peer reading only spec-data would miss them and fail S4. Logged **A-DART-008** (spec
version/provenance) + **A-DART-009** (guide-carried scaffolding).

## peer_id construction: §1.5 canonical-form table, NOT the legacy SHA-256 form (A-DART-010)

The profile **mandates** deriving the Ed25519 peer_id from the **§1.5 v7.65 canonical-form table**
(`spec-data/v7.75`: `key_type=0x01` Ed25519 → `hash_type=0x00` identity-multihash, digest = the
**raw public-key bytes**, "The digest IS the public_key (v7.64)") — and **ignoring** the legacy
SHA-256 form (`hash_type=0x01`). `peer_id = Base58(varint(0x01) || varint(0x00) || public_key)`.
**On v7.75 this is corroboration-only:** v7.73 erratum E1 already reconciled the stale §7.4
pseudocode to defer to the §1.5 table, so the §7.4-vs-§1.5 contradiction that **OCaml (A-OC-007)**,
**Zig (A-ZIG-001)**, **Common Lisp (A-CL-002)**, **Java (A-JAVA-004)**, **Kotlin (A-KT-004)**, and
**C++ (A-CPP P1)** surfaced is **already closed** in the v7.75 body. Baking the §1.5 form into the
profile proactively still matters: it dodges the `401 identity_mismatch` handshake-failure debug
cycle that S2's opaque-digest conformance corpus would **NOT** catch (a wrong construction passes S2
and only blows up at the S4 handshake). Logged **A-DART-010** as a corroboration.
