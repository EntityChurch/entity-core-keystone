# entity-core-protocol-dart — Phase S1 (Profile) Summary

**Release "reach" peer** (Dart 3 — Flutter cross-platform mobile / Dart
ecosystem coverage; Dart-3 sealed-class Result + exhaustive switch-expression, sound null-safety,
Future/isolate async, the BigInt uint64 head-form carrier; `research/RELEASE-READINESS.md` §2 row 4;
**corroboration-only**, discovery well dry) · **Status: COMPLETE (authoring) — container AUTHORED
(not built), no toolchain run (S1 boundary).**

## Preconditions resolved at session start
- **Spec version.** Read `spec-data/v7.75` (the **latest stamped** snapshot; MANIFEST pins V7
  **7.75**). The core floor is stable **v7.75→v7.77** and the conformance oracle anchors at **v7.77**
  (`entity-core-go @ e8524ed`, the **19-peer** matrix uniform 665 / 0 FAIL — C++ + Kotlin reach peers
  landed). The wire/protocol surface is byte-stable across that window
  (ENTITY-CBOR-ENCODING + ENTITY-NATIVE-TYPE-SYSTEM unchanged since v7.73 E3 / v7.70), so deriving the
  peer from v7.75 + gating against the v7.77 oracle is the established cohort pattern. Codec corpus is
  **v7.71** (byte-stable v7.71→v7.75). (A-DART-008.)
- **Slate decisions (row 4), affirmed + made concrete.** Codec = **native hand-roll ECF** (the `cbor`
  pub package is general RFC-8949, not ECF — A-DART-001). Crypto floor = **the package route**, and
  the S1 maintenance evaluation chose **`cryptography_plus`** (the maintained fork) over the stalled
  original `cryptography` (A-DART-002). Ed448 = gap → **DEFER** (FFI route documented; no maintained
  pure-Dart Ed448 — A-DART-003). Packaging = **pub.dev** (A-DART-007). License = **Apache-2.0** (S9).
- **Closest analogs = Kotlin + TypeScript.** Kotlin: sealed-class Result error model, sound static
  null-safety, the hand-rolled-codec independence ruling. TypeScript: the uint64/web-number trap
  solved with a wide integer carrier (TS `bigint` → Dart `BigInt`), Promise/Future async, the
  consumable-data-library browser-portability angle. Authored as an INDEPENDENT reader of V7.
- **No-peek discipline.** Derived from V7 + Dart/Flutter ecosystem research (Dart SDK release dates,
  the cryptography/cryptography_plus maintenance split, the Dart native-vs-web int model). Read the
  cohort `{kotlin, cpp, csharp, typescript}` profiles for the field schema/exemplar shape — config
  structure, not spec interpretation.
- **S1 boundary honored.** No podman run, no container build, no toolchain install, no compile, no
  `dart pub get`. Authoring only. (Dart SDK / package versions + release dates were researched via web
  search — metadata, not a build/fetch.)

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** hand-roll ECF (NOT FFI, NOT the `cbor` pkg) | slate row-4 decision affirmed; `cbor` pub pkg is RFC-8949, not ECF (no length-first / f16 / tag-reject). `ffi` = documented fallback only if the S2 spike fails (A-DART-001) |
| **uint64 head-form carrier** | **BigInt** (the headline codec call) | Dart `int` is 64-bit on the VM but **53-bit on web/dart2js** — `BigInt` carries the full uint64 range web-safe AND native-correct. The TS-`bigint`/F7 lesson, Dart edition. Rejected `fixnum` (registry dep). **The single most important S2 watch.** (A-DART-006) |
| CBOR | **hand-rolled** (`lib/src/codec/ecf.dart`, Uint8List/ByteData) | A-005 pattern (no Dart CBOR lib gives ECF). Float-min (f16 ladder) = highest bug-density code |
| Ed25519 (floor) | **cryptography_plus 2.7.0** (pure-Dart) | the MAINTAINED fork (original `cryptography` is stalled — repo moved to emz-hanauer for lack of maintenance). Pure-Dart → **self-contained on every Flutter target** (no native lib) = the reach value. (A-DART-002) |
| SHA-256 (floor) | **package:crypto 3.0.6** (first-party Dart-team) | leaner floor-hash than cryptography_plus's Sha256; pure-Dart, browser+native |
| Ed448 / SHA-384 (agility) | **DEFERRED** (FFI route documented, NOT v0.1) | no maintained pure-Dart Ed448; same gap C/Zig/OCaml/Rust/C++. FFI to sibling entity-core-codec-ffi-c would break pure-Dart self-containment → defer. SHA-384 hash IS in cryptography_plus. (A-DART-003) |
| base58 / varint | **hand-rolled** | dep-minimization; ~80-line base58, LEB128 varint |
| Error model | **Dart-3 sealed-class Result** + exhaustive switch expression | distinct from the TS peer (which chose exceptions); Dart 3 makes sealed Result statically-exhaustive (the Kotlin-`when` analogue). Exceptions = programmer-error only, caught at the conn boundary (§4.9). (A-DART-004) |
| Async / concurrency | **Future/async-await** on the per-isolate **event loop**; **event-loop confinement** for §7b store-safety; TCP_NODELAY | Future == TS Promise; isolates = the Dart parallelism story (not needed for core). Single-threaded loop → §4.8 store-safety **structural** (no lock needed in-isolate). **A-C-009 is N/A** (GC'd + single-threaded). (A-DART-005) |
| Naming | PascalCase types / lowerCamelCase members / lowercase_with_underscores files+pkg; **lowerCamelCase constants** (Dart divergence); lowercase hex | Effective Dart. Constants are NOT UPPER_SNAKE in Dart. Hex lowercase by default but pinned (A-CL-009 / P2) |
| Build / test / pkg | **`dart` tool + pub** + **package:test** + **pub.dev** | first-party single tool (cargo/go analogue); package name `entity_core_protocol` (no hyphens in pub names); AOT-compiled `bin/peer.dart` for S4; parked `0.1.0-pre` (A-DART-007) |
| Container | **NEW `dart-toolchain`** (authored, NOT built) | fedora:43 + the pinned dart-lang SDK tarball (verified sha256, S2-filled sentinel) + a PUB_CACHE prefetch layer for offline builds. NOT fedora dnf (no current Dart SDK). (A-DART-011) |
| License | Apache-2.0 | S9 default; ecosystem is BSD-3/Apache-2.0-leaning; cryptography_plus is Apache-2.0 |
| Spec | read v7.75; gate v7.77 oracle | corroboration-only reach peer (A-DART-008) |

## Crypto + SDK pins (S11)
- **Dart SDK `3.11.6`** — ~45 days old at authoring → clears the
  ≥30-day floor. The **3.11 line** is the conservative pick; **3.12.x** (~24d) is
  **UNDER the floor** and explicitly **NOT** picked. Fetched as the dart-lang **official release
  tarball + verified sha256** (a reviewed vendor channel — age floor relaxes for the SDK, met anyway;
  exact pin + checksum for repro). fedora dnf does not carry a current Dart SDK → pin-the-tarball.
- **`cryptography_plus` 2.7.0** — the maintained community fork; pure-Dart Ed25519 floor (+ Sha384
  for agility). Apache-2.0. The ONE non-first-party crypto runtime dep. Registry-pulled (pub.dev) →
  ≥30-day applies **with full force**. **PIN-DATE SENTINEL:** verify 2.7.0's pub.dev publish date is
  ≥30d at the S2 build; if too new, pin the latest aged 2.x + re-log (A-DART-002).
- **`crypto` 3.0.6** — first-party Dart-team SHA-256 package; long-stable (well over ≥30d); BSD-3.
- **`package:test` 1.25.15** — first-party test runner, **dev-scope only** (never shipped);
  ≥30-day applied + met. **PIN-DATE SENTINEL** (verify at S2).
- Codec / base58 / varint / conformance harness = **hand-rolled in-repo** (no further registry deps);
  cryptography_plus transitive deps locked in the **committed pubspec.lock**.

## Container — AUTHORED, NOT built (S1 boundary)
`containers/dart-toolchain/Containerfile` is **NEW** (authored this phase; NOT a reuse — no existing
dart-toolchain). fedora:43 base. Fetches the pinned dart-lang SDK 3.11.6 x64-linux zip from
`storage.googleapis.com/dart-archive` and **verifies a sha256** (SENTINEL `DART_SHA256` at S1, filled
at S2 from the published `.sha256sum`; build FAILS CLOSED on the sentinel — the kotlin/gradle pattern).
A `containers/dart-toolchain/prefetch/pubspec.yaml` (the pinned deps) populates the image `PUB_CACHE`
in one network-on build layer, so the dev loop runs `--network=none` with `dart pub get --offline`
(the TS/npm offline-after-one-pull pattern). **Authored, NOT built; no podman/dart runs in S1.**

**"To verify-and-pin at S2" items (recorded, NOT done — S1 = no build/fetch):**
1. Fill the real **`DART_SHA256`** from the dart-archive `.sha256sum` for 3.11.6.
2. Confirm the **`cryptography_plus` 2.7.0** and **`package:test` 1.25.15** pub.dev publish dates are
   ≥30 days old at the S2 build; if too new, pin the latest aged 2.x / 1.25.x and re-log (A-DART-002).
3. Generate the **committed `pubspec.lock`** at the first `dart pub get` and pin the transitive set.
4. Smoke a **`dart compile js` / `dart2js`** integer round-trip alongside the codec spike to confirm
   the BigInt head-form carrier is web-safe (no 53-bit truncation) — the A-DART-006 watch.

## Ambiguity log
6 PRE-RESOLVED inheritances (P1–P6) + 11 entries (A-DART-001..011), **none blocking** the §9.1 floor:
- **P1** peer_id = §1.5 identity-multihash (raw pubkey); **P2** hex lowercase; **P3** §5.2a 401/403
  trichotomy; **P4** entity `data` = arbitrary ECF value (A-JAVA-010 silent-500); **P5**
  resource_bounds (413 / **400 chain_depth_exceeded** / 503); **P6** §7b CORE gate — **event-loop
  confinement** makes §4.8 structural, **A-C-009 N/A** (GC'd + single-threaded). All settled cohort
  convergence, built in.
- **A-DART-001:** codec = native hand-roll (NOT `cbor` pkg, NOT FFI) — slate row-4 affirmed.
- **A-DART-002:** crypto floor = **cryptography_plus** (the maintained fork) + package:crypto; the
  stalled original `cryptography` rejected. Pure-Dart = self-contained on every Flutter target.
- **A-DART-003:** Ed448 native gap (no maintained pure-Dart) — DEFERRED; FFI route documented, not
  v0.1 (breaks self-containment). Non-blocking for the floor.
- **A-DART-004:** error model = Dart-3 sealed-class Result + exhaustive switch (NOT exceptions —
  distinct from the TS peer).
- **A-DART-005:** concurrency = Future/event-loop; event-loop confinement for §7b; A-C-009 N/A.
- **A-DART-006:** **uint64 head-form carrier = BigInt** — the headline codec call (web 53-bit-int
  trap; TS-bigint lesson). The single most important S2 watch.
- **A-DART-007:** pub.dev publisher namespace + `entity_core_protocol` package name (no hyphens);
  parked `0.1.0-pre`.
- **A-DART-008:** read v7.75 (latest stamped); gate against the v7.77 oracle. Provenance.
- **A-DART-009:** §7a/§7b scaffolding is GUIDE-carried, not in spec-data (corroborates
  A-SW-006/A-C-003/A-CPP-006). Pull at S3/S4 from the guide.
- **A-DART-010:** peer_id = §1.5 (raw pubkey), NOT §7.4 SHA-256 — corroboration (see P1).
- **A-DART-011:** container = pin the official dart-lang SDK tarball + verified sha256 (NOT fedora
  dnf); S2 fills the sentinel digest.

## Exit criteria
profile.toml fully populated (**no TBD**) · rationale written · **container AUTHORED (new
`dart-toolchain` Containerfile + prefetch pubspec), NOT built** · ambiguity log initialized with **no
blocking-severity items** (A-DART-003 Ed448 is the agility higher bar, non-blocking for the codec
floor; native codec / cryptography_plus floor / BigInt int-carrier / sealed-Result error model /
pub.dev packaging / peer_id + hex + data-shape + resource_bounds + concurrency all pre-resolved or
profile-decided) · this summary complete. **S1 PASS (authoring).**

## Time spent
~1 session (single-pass authoring): read the PHASE-S1 contract + PROMPT-CONSTANTS + the
`{kotlin, cpp, csharp, typescript}` profile exemplars (esp. Kotlin = sealed-Result/null-safe/codec
ruling, TS = bigint int-carrier) + their rationale/status/container/ambiguity-log templates + the
seeded agent-memory (peer-id, hex-case, 401/403, A-JAVA-010, resource_bounds, §7b, A-C-009,
supply-chain-30day-pin, prerelease-slate) + the `research/RELEASE-READINESS.md` slate row 4; web
research on Dart SDK release dates, the cryptography/cryptography_plus maintenance split, and the
Dart native-vs-web int model; authored the five deliverables (profile, rationale, container [+
prefetch], PHASE-S1, ambiguity log). No build, no toolchain run, no `dart pub get` (S1 boundary).

## What S2 should tackle first
1. **Run the codec spike before the full build** (the load-bearing canonical risk): hand-roll
   `lib/src/codec/ecf.dart` enough to push the `map_keys` + `float` v7.71 vectors through the ECF
   encoder/decoder and assert byte-identity. **Float minimization is the highest bug-density code in
   the whole peer** — hardcode the four specials (F9 7E00 NaN / 7C00 +Inf / FC00 -Inf / 8000 -0.0),
   minimize by double→float→half re-decode-and-compare. ECF map-key ordering is **length-FIRST then
   bytewise** (CTAP2), NOT RFC-8949 §4.2 bytewise.
2. **THE int watch (A-DART-006):** carry the uint64/nint head-form via **`BigInt`**, and smoke a
   `dart compile js`/`dart2js` integer round-trip (the [2^63, 2^64-1] band) to confirm no web 53-bit
   truncation. NEVER carry a uint64-range head value in a bare `int`.
3. **Build the dart-toolchain image** (the deferred S1 build): fill the `DART_SHA256` from the
   dart-archive checksum; confirm `cryptography_plus` 2.7.0 + `package:test` 1.25.15 publish dates are
   ≥30d (re-pin + log if too new); `dart pub get` to generate the **committed pubspec.lock**, then
   seal the network (`--network=none` + `dart pub get --offline`).
4. **Wire crypto + verify raw-pubkey peer_id** (P1 / A-DART-010): Ed25519 via
   `Ed25519().newKeyPairFromSeed` / `.sign` / `.verify`, raw 32-byte pubkey via
   `SimplePublicKey.bytes`, SHA-256 via `package:crypto sha256.convert`; construct the peer_id per
   **§1.5** (identity-multihash, raw pubkey), NOT §7.4 — the corpus won't catch a wrong construction;
   it only blows up at the S4 handshake.
5. **Model entity `data` as a sealed `EcfValue`** (P4 / A-JAVA-010) — a general ECF value (any major
   type), never map-only, from the start; exhaustive switch over the sealed hierarchy.
