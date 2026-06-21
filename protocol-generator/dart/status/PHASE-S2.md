# entity-core-protocol-dart — Phase S2 (Codec) Summary

**Release "reach" peer** (Dart 3 — Flutter cross-platform / Dart ecosystem
reach; corroboration-only) · **Status: COMPLETE — 69/69 wire-conformance byte-identical, 0 FAIL;
all self-tests pass; dart2js web-int proof green.**

## Result headline

- **Wire-conformance: 69/69 PASS, 0 FAIL** (v0.8.0 corpus, byte-identical) on the **first full run**.
  18th+ independent impl to converge. Native, hand-rolled, no FFI, no `cbor` pub package.
- **dart analyze --fatal-infos: No issues found** (clean under the linter as a build gate).
- **17 package:test cases pass** (1 conformance group + 16 beyond-corpus self-tests).

## What was built (`protocol-generator/dart/`)

- `lib/src/errors.dart` — the Dart-3 **sealed-class** error model: `sealed EntityError`
  (Codec/Crypto/Protocol/Transport) + a `sealed EcfResult<T>` (Ok/Err), matched by exhaustive
  `switch`. Internal `EcfException` unwinds the recursive hot path; the public surface translates it
  to `Err` (the throw never escapes). (A-DART-004.)
- `lib/src/codec/ecf_value.dart` — the `sealed EcfValue` decoded-form model (Int via **BigInt**,
  Float, FloatSpecial sentinels, Bytes [defensive-copied Uint8List], Text, Array, Map, Bool, Null).
  `absent != null != false != 0`; bytes (major 2) vs text (major 3) never conflated; integral floats
  keep a float node.
- `lib/src/codec/ecf.dart` — the hand-rolled **canonical ECF encoder + decoder**: minimal int head
  (Rule 1, BigInt), length-first-then-byte-lex map-key sort (Rule 2), definite lengths (Rule 3),
  shortest-float f16/f32/f64 ladder + Rule-4a specials (Rule 4), recursive major-type-6 tag reject
  (N2), empty map = `0xA0` (N3), trailing-byte + depth + duplicate-key rejection.
- `lib/src/codec/varint.dart` — multicodec LEB128 (N1, BigInt-backed).
- `lib/src/codec/base58.dart` — Bitcoin-alphabet, leading-zero-preserving (BigInt long-division).
- `lib/src/crypto/ed.dart` — Ed25519 sign/verify/pubkey-from-seed via **cryptography_plus 2.7.1**
  (pure-Dart, async `Future` API). Ed448 throws (deferred; A-DART-003).
- `lib/src/crypto/content_hash.dart` — `varint(fc) ‖ SHA-256(ECF({type,data}))` via **package:crypto
  3.0.6**; SHA-384 reachable, construct-side fc verbatim / receive-side reject.
- `lib/src/crypto/peer_id.dart` — `Base58(varint(kt)‖varint(ht)‖digest)` + the §1.5 canonical-form
  `fromPublicKey` (raw pubkey for ≤32B keys — A-DART-010).
- `lib/entity_core_protocol.dart` — the public export barrel.
- `lib/src/conformance/harness.dart` — decodes the fixture with our own decoder, dispatches by
  kind+id, byte-compares against the embedded `canonical`.
- `test/conformance_test.dart` — the 69/69 gate. `test/codec_selftest_test.dart` — the beyond-corpus
  self-tests. `tool/web_int_smoke.dart` — the dart2js web round-trip smoke.
- `run-s2.sh` — sealed-offline podman gate (`all` = analyze+test; `test`; `web` = dart2js+node smoke).
- `pubspec.yaml` + **committed `pubspec.lock`** (transitive set pinned).
- `containers/dart-toolchain/` — image **built** (was authored-not-built at S1): SDK sha256 filled,
  nodejs added for the web smoke, prefetch repinned.

## The S1 watches, discharged

1. **BigInt uint64-band carrier (A-DART-006 — the #1 risk).** The head-form range
   [2^63, 2^64-1] + -2^64 carries via `BigInt` end-to-end. Self-tests prove the canonical hex
   (`2^64-1 -> 1bffffffffffffffff`, `2^63 -> 1b8000000000000000`, `-2^64 -> 3bffffffffffffffff`) +
   round-trip. **The corpus does NOT reach this band (int.10 = i64::MAX is the top), so this is
   author-it-yourself coverage** per the codec-review-heuristic.
2. **dart2js web-truncation proof.** `tool/web_int_smoke.dart` is `dart compile js`-compiled and
   **executed under node** (in-image, sealed offline): `WEB-INT SMOKE: PASS (4 band values, no
   truncation)`. Proving by EXECUTION (not just compilation) that the BigInt carrier survives
   JS-`number` 53-bit semantics. (Required node in the image — A-DART-013.)
3. **f16 shortest-float ladder** — highest bug-density code; ported carefully from the Kotlin
   reference (subnormal normalize, he>30 reject, low-bit-zero check, BigInt scaled-subnormal path).
   All 14 corpus float vectors + the f16-max/subnormal/f32-not-f16/f64 boundary self-tests pass.
4. **Image build + SDK sha256.** Built the dart-toolchain image: `DART_SHA256` filled from the
   dart-archive checksum (`ea0ff2396ea5af402ba3598a9139a0f4b1b3471d9d7e834882d1559622760add`),
   verified at build (fail-closed sentinel removed). Dart 3.11.6 confirmed. Crypto deps resolved.
5. **Crypto date sentinel (A-DART-002 → A-DART-012).** The sentinel FIRED: profile-pinned
   `cryptography_plus 2.7.0` **does not exist on pub.dev** (the 2.x line is 2.7.1; latest is 3.0.0).
   Re-pinned to **2.7.1** (~602d ≥ 30d). `crypto 3.0.6` (610d) and `test 1.25.15` (495d)
   both clear the floor. Logged A-DART-012; profile's 2.7.0 should be corrected at the next touch.
6. **peer_id §1.5 (A-DART-010 / P1)** — `fromPublicKey` builds (0x01, 0x00, raw pubkey); self-test
   asserts it. The corpus can't catch a wrong construction (opaque digests) — baked in proactively.
7. **N1/N2/N3** — each has a covering corpus vector AND a self-test.

## Ambiguities logged this phase

- **A-DART-012** — cryptography_plus 2.7.0 → 2.7.1 (the S1 pin sentinel resolution; 2.7.0 absent).
- **A-DART-013** — nodejs added to the image as a test-time JS runtime for the web-truncation proof.
- No NEW spec defect surfaced (corroboration-only reach peer, discovery well dry, as predicted at
  S1). All corpus behavior matched the cross-peer convergence.

## What S3 must watch

- **Crypto is async (`Future`).** cryptography_plus Ed25519 is `Future`-returning; the codec stays
  synchronous (`Ecf.encode/decode` are sync), but `Ed.sign/verify/rawPublicKeyFromSeed` and anything
  building on them (peer-id-from-seed, signature/envelope verify in the dispatcher) are `async`. The
  profile's async surface (Future/event-loop, `Map<int, Completer<T>>` demux, event-loop confinement
  for §7b) lines up — but S3 must thread `await` through the handshake/dispatch.
- **§4.10 chain-depth pre-check (P5)** — build the ~15-line §4.10(b) structural pre-check (walk
  parents, no signature work, max 64) BEFORE the per-link authz walk; over-depth self-chain → **400
  chain_depth_exceeded** (NOT 403). 16 MiB / 64 are informative defaults.
- **§5.2a trichotomy (P3)** — 401 authn / 403 authz / 401 unresolvable; the sealed `ProtocolError`
  variants are already declared (AuthenticationFailed/AuthorizationDenied/PayloadTooLarge/
  ChainDepthExceeded).
- **entity `data` is a general `EcfValue` (P4)** — the model is already general (not map-only);
  the dispatcher must accept scalar/bytes/array data, never 500.
- **§7a/§7b scaffolding is GUIDE-carried (A-DART-009)** — pull the `system/validate/*` handlers +
  the §7b concurrency gate from GUIDE-CONFORMANCE + the generator menu, not spec-data.
- **TCP_NODELAY on every socket (P6)** — `Socket.setOption(SocketOption.tcpNoDelay, true)`.
- **Profile pin correction** — the profile still says `cryptography_plus 2.7.0`; the working pin is
  2.7.1 (lockfile + pubspec + prefetch all corrected). Reconcile the profile text at the next touch.

## Exit criteria

69/69 wire-conformance byte-identical · conformance report green · `dart analyze --fatal-infos` clean
· image built (SDK sha256 verified, deps resolved offline) · BigInt uint64-band + dart2js web smoke
proven · crypto date sentinel resolved · no blocking ambiguities · no sacred-tree writes (only
`protocol-generator/dart/` + `containers/dart-toolchain/` in the `lang/dart` worktree). **S2 PASS.**
