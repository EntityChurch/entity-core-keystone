# entity-core-protocol-kotlin — Phase S2 (Codec) Status

**Phase:** S2 — codec layer (ECF encode/decode, content_hash, peer_id, Ed25519 sign).
**Strategy:** NATIVE, HAND-ROLLED Kotlin ECF codec (the A-KT-001 headline decision —
NOT interop into the Java peer's codec). `ffi` fallback NOT needed.
**Result:** **69/69 byte-identical**, in-build gate green AND byte-identical to a freshly
built Go `wire-conformance` oracle emission.

---

## What was built

- **Toolchain image** `containers/kotlin-toolchain/` — Temurin JDK 21.0.10+7 + Kotlin
  1.9.25 + Gradle 8.10.2. The S1 `REPLACE_…_AT_S2` checksum sentinels were filled with
  verified digests (A-KT-006) and the `prefetch/` Gradle Kotlin-DSL offline-dep seed was
  authored (mirroring the Java toolchain's `prefetch-pom.xml`, but Gradle). Image built
  with podman; all builds/tests run inside it `--offline --no-daemon --network=none`.
- **Codec** in `protocol-generator/kotlin/src/main/kotlin/org/entitycore/protocol/`:
  - `EntityError.kt` — sealed `EntityError` hierarchy + `EcfResult<T>` (Ok/Err). The
    Kotlin-native recoverable-error seam (the primary divergence from the Java peer's
    checked exceptions), matched exhaustively by `when`.
  - `codec/EcfValue.kt` — the decoded-form value model as a `sealed interface` (data
    classes + enum/object singletons); exhaustive `when` over a closed set. Explicit
    `Float64`/`FloatSpecial` nodes (integral floats never erase to int); `Bytes`
    defensively copies (no_byte_array_aliasing).
  - `codec/CanonicalCbor.kt` — the hand-rolled canonical encoder + decoder. Minimal int
    head-form (via a `ULong` argument-length switch — the profile unsigned-types idiom +
    a `BigInteger` value node for the -2^64..2^64-1 range), length-then-lex map-key sort,
    definite lengths only, the f16⊂f32⊂f64 shortest-float ladder + Rule-4a specials, and
    recursive major-type-6 tag rejection on decode.
  - `codec/Base58.kt`, `codec/Varint.kt` — hand-rolled Bitcoin-alphabet Base58 +
    multicodec LEB128 varint (N1).
  - `crypto/Ed.kt` — Ed25519/Ed448 sign/verify + raw-key extraction via JDK SunEC
    (zero dep, RFC-8032 deterministic; Kotlin/JVM interop). `crypto/ContentHash.kt`
    (SunMessageDigest SHA-256/384). `crypto/PeerId.kt` (§1.5-canonical construction).
- **Conformance harness** in `src/test/kotlin/.../conformance/` + the per-impl emission
  producer `EmitCanonical` (main) in `src/main`. `tools/oracle-diff.sh` drives the
  independent Go-oracle byte-diff.
- **Build:** `build.gradle.kts` + `settings.gradle.kts` (Gradle Kotlin DSL); dependency
  locking ON → `gradle.lockfile` committed (S11).

## Conformance — see `CONFORMANCE-REPORT.md`

- In-build `ConformanceTest`: **69/69 PASS** (64 encode + 5 decode-reject; 2 meta skipped).
- Independent Go-oracle emission diff (`tools/oracle-diff.sh`): **BYTE-IDENTICAL** —
  `emit-kotlin.cbor` ≡ `emit-go.cbor` (same SHA-256, 2132 bytes) under a shared impl
  identity. Go oracle built from `entity-core-go` HEAD `71b6ba8` in a temp dir OUTSIDE
  the go repo (`git archive | tar -x`); the go repo tree was verified CLEAN afterward.
- Spike (A-KT-001): float ladder + map-key ordering + beyond-corpus uint64 all byte-correct.

## Pinned digests (filled at S2)

| Artifact | Pin | sha256 |
|---|---|---|
| Kotlin compiler | 1.9.25 | `6ab72d6144e71cbbc380b770c2ad380972548c63ab6ed4c79f11c88f2967332e` |
| Gradle | 8.10.2 | `31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26` |
| Temurin JDK | 21.0.10+7 | `ea3b9bd464d6dd253e9a7accf59f7ccd2a36e4aa69640b7251e3370caef896a4` (reused from java-toolchain) |

## Ambiguities

No NEW spec defect surfaced — as expected for a reach/corroboration-only peer. New log
entries are all informational/non-blocking S2 closeouts:
- **A-KT-006** — RESOLVED (digests filled, image built).
- **A-KT-007** — spike outcome recorded (hand-roll byte-correct; `ffi` not needed).
- **A-KT-008** — documents the S2 peer_id coverage gap (corpus uses opaque digests; the
  §1.5 construction form is first exercised at S4). Non-blocking.

Zero blocking-severity items. The map-sort framing ("length-then-lex" in the profile vs
the Go oracle's `bytes.Compare`) was confirmed to COINCIDE for CBOR head-encoded keys —
not a divergence.

## Phase exit criteria — MET

- [x] All test vectors pass (69/69, byte-identical) — in-build gate + independent oracle diff.
- [x] Conformance report green (`CONFORMANCE-REPORT.md`).
- [x] Ambiguity log: no blocking items.
- [x] Codec compiles cleanly under the profile's compiler settings (Kotlin 1.9 / JVM 21),
      builds + tests fully offline in the toolchain container.
- [x] S11: all deps pinned ≥30 days; `gradle.lockfile` committed.

## Hand-off to S3 (peer machinery)

The pure/synchronous codec is done. S3 wires the dispatcher, handshake, auth, capability
and the kotlinx.coroutines concurrency surface (A-KT-003). Carry forward: A-KT-008
(re-verify peer_id §1.5 construction against the S4 handshake oracle); the Ed448/SHA-384
agility higher-bar remains deferred (floor first).

> NOTE: left UNCOMMITTED for orchestrator gate/review (per the S2 boundary). Do not advance to S3.
