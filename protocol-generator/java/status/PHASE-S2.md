# entity-core-protocol-java — Phase S2 (Codec) Summary

**Peer #7** (Java/JVM, mainstream OO/static idiom) · **Status: COMPLETE — 69/69 wire-conformance, 0 FAIL; container built clean**

## Result

- **ECF codec corpus 69/69 byte-identical** — **seventh** independent native codec to
  converge (C#/TS/OCaml/Elixir/Zig/Common-Lisp → S8). 0 fixes after the codec compiled.
- **Ed25519 + Ed448 RFC-8032 KAT byte-equality gates: PASS** — the native raw-pubkey
  derivation byte-equals the locked pins, SunEC signatures byte-equal the pins, and an
  **opt-in BouncyCastle cross-check** confirms both. Agility corpus trusted; no FFI.
- **Container built clean** — Temurin JDK 21.0.10+7 LTS (sha256-verified) + Apache
  Maven 3.9.9 (sha512-verified) + JUnit 5.11.4 (test-scope) + opt-in BouncyCastle 1.80,
  all pinned; deps pre-fetched into the image `~/.m2` so the dev loop runs `mvn -o`
  fully offline under `--network=none`.

Full detail: `CONFORMANCE-REPORT.md` / `CONFORMANCE-REPORT.json`.

## Container (carry-ins A-JAVA-006 resolved; two build defects fixed)

`containers/java-toolchain/Containerfile` BUILT (S1 authored it; S2 builds it). Image
`entity-core-keystone/java-toolchain:latest`, **746 MB**.

- **A-JAVA-006 RESOLVED** — Maven 3.9.9 sha512 filled:
  `a555254d…c4ac8b`, verified against the published `.sha512` on **both**
  downloads.apache.org and archive.apache.org/dist (byte-identical). Build fails closed
  on mismatch. The JDK sha256 (`ea3b9bd4…896a4`) was already filled at S1.

### Build defects hit + fixed (both in the Containerfile, S1 carry-ins)
1. **Maven URL rot.** `dlcdn.apache.org` only mirrors CURRENT releases — 3.9.9 has
   rolled off it (404). Switched the fetch to `archive.apache.org/dist` (the permanent,
   checksum-stable archive; the verified sha512 matches both).
2. **prefetch-pom.xml illegal XML comment.** The S1-authored comment contained `--`
   sequences (`--network=none`, list-dash bullets) which XML forbids inside comments —
   Maven's POM parser hard-failed. Rewrote the comment (no `--`).
3. **surefire JUnit-platform provider not offline-seeded.** `dependency:go-offline`
   does NOT pull surefire's lazily-resolved JUnit-platform provider + launcher, so
   `mvn -o test` failed offline. Fixed the prefetch step to run a real `mvn test` over
   a trivial JUnit 5 test at image-build time (network up), which seeds the provider
   into `~/.m2`.

## What was built (`src/main/java/org/entitycore/protocol/`)

| File | Responsibility |
|---|---|
| `EntityCoreException.java` | checked root of the error hierarchy (profile error_model = checked exceptions) |
| `codec/EntityCodecException.java` + `NonCanonicalEcf/TruncatedInput/TagRejected/DuplicateKey` | the checked codec exception subtypes (compiler-forced malformed-input handling — the Java static-OO rigor seam) |
| `codec/EcfValue.java` | **the value model** — a `sealed interface` + nested records (exhaustive pattern-matching switch, JDK 21): `Int`(BigInteger) / `Float64` / `FloatSpecial` / `Bytes`(defensive-copy) / `Text` / `Array` / `Map` / `Bool` / `Null` |
| `codec/CanonicalCbor.java` | **the heart** — canonical ECF encoder + index-walk decoder; length-then-lex map-key sort; shortest-float ladder (exact IEEE bits via `*BitsTo*`/`*To*Bits`, integer f16 test); recursive tag rejection (N2); full uint64/-2^64 via BigInteger |
| `codec/Varint.java` | multicodec LEB128 (N1) — encode/decode |
| `codec/Base58.java` | Bitcoin-alphabet encode/decode (leading-zero preserving, BigInteger) |
| `crypto/ContentHash.java` | `varint(fc) ‖ HASH(ECF({type,data}))`; SHA-256/384 via MessageDigest; construct-vs-receive format-code asymmetry (A-OC-004/A-CL-007 independently reached) |
| `crypto/PeerId.java` | `Base58(varint(kt) ‖ varint(ht) ‖ digest)` + parse + **§1.5 canonical-form derivation** (A-JAVA-004) |
| `crypto/Ed.java` | Ed25519/Ed448 sign/verify via SunEC; raw-pubkey extraction from `EdECPoint`; raw↔key round-trip |
| `crypto/EdKeyDerivation.java` | **native RFC-8032 seed→raw-pubkey** for both curves (the JDK seam — see A-JAVA-002/007) |
| `crypto/Shake256.java` | **hand-rolled FIPS-202 SHAKE256** (the JDK ships none; Ed448 expansion needs it) |
| `crypto/EntityCrypto*Exception.java` | crypto exception subtypes (BadSeed/UnsupportedKeyType/UnsupportedContentHashFormat) |

Tests (`src/test/java/.../conformance/`, JUnit 5):
`ConformanceHarness` (loads the normative fixture, byte-checks all 69) +
`ConformanceTest` (the gate) + `SelfTest` (uncovered-range probes + Ed25519/Ed448/
SHAKE256 KATs) + `BouncyCastleCrossCheckTest` (opt-in agility cross-check). 12 tests,
all green. `run-s2.sh` is the offline dev loop.

## Value representation (the Java idiom decisions)

- **Sealed-interface value model** (`EcfValue`) → exhaustive pattern-matching switch
  over a closed type set (JDK 21 JEP 441) — the static-OO analogue of the OCaml
  variant / Zig tagged-union / CL sentinel approach. The compiler proves the encode
  ladder is total.
- **Integers are `BigInteger`** (`EcfValue.Int`) — Java `long` has NO native unsigned,
  so the full uint64 head-form / -2^64 range is carried in BigInteger, sidestepping the
  C# `ulong` / OCaml int63 trap entirely (matches the CL/TS-bigint posture).
- **Byte strings are `EcfValue.Bytes`** (major 2), distinct from `Text` (major 3), and
  the `byte[]` is **defensively cloned in AND out** — Java arrays are mutable, so the
  codec never aliases an internal buffer (profile `no_byte_array_aliasing`, the
  Java-specific footgun the GC'd-but-immutable peers don't have).
- **bool/null/float-specials are explicit nodes** (`Bool`, `Null`, `FloatSpecial`) —
  never erased to Java `null`/`boolean`/`double`, so absent ≠ null ≠ false ≠ 0 on the
  wire (ECF §1.3) and a NaN/Inf/-0.0 never has to round-trip through a `double`.
- **Integral-valued floats** keep a `Float64` node, so `1.0` encodes via the float
  ladder, never as integer 1 (the value-erasure trap TS hit with cborg).

## Key implementation notes (the ECF traps, Java-specific)

- **Shortest-float ladder.** `Double.doubleToRawLongBits` / `Float.floatToRawIntBits`
  give exact IEEE bits; f16-representability is a pure-integer test (normalized: low-42
  mantissa bits zero AND half-exp ≤ 30; subnormal: significand divisible to an integer
  in [1,1023]); -0.0 is the Rule-4a `f98000`. Hit 65472/65503/65504 + 1.1→f64 exactly.
- **Map ordering.** Sort entries by ENCODED key bytes, length-first then bytewise-lex
  (ECF Rule 2 / §3.5) — text-key, byte-key, and mixed-key vectors all pass.
- **Recursive tag-6 reject (N2).** `dec` throws `TagRejectedException` on ANY
  major-type-6 item at any depth — no library default trusted (there is no library).
  Bare 55799 (`d9d9f7…`) and tags nested in `included` data both reject.
- **content_hash format_code (A-OC-004/A-CL-007).** Construct side serializes the
  caller-supplied `format_code` verbatim (content_hash.4 code 128 passes); receive-side
  `resolveFormat` rejects unallocated codes — independently reached the cohort fix.
- **peer_id = §1.5 canonical form (A-JAVA-004).** `PeerId.fromPublicKey` derives from
  the §1.5 size-cutoff table (Ed25519 ≤32 B → `hash_type=0x00` identity-multihash, raw
  pubkey; Ed448 >32 B → `hash_type=0x01`, SHA-256(pubkey)). The stale §7.4 SHA-256-form
  is NOT a construction path. Verified by the Ed448 KAT peer_id matching the locked pin.
- **lowercase `%02x` hex** everywhere (avoids the A-CL-009 uppercase address-space-path
  trap by default — exercised at S3).

## Crypto sourcing — the headline finding (A-JAVA-002 + new A-JAVA-007)

The S1 bet was "SunEC closes the FULL agility bar natively." S2 spike refines it:

- **SIGN/VERIFY (both curves): SunEC, native, zero-dep.** Confirmed deterministic
  (Ed25519 all-zero seed → RFC-8032 TEST-1 signature; Ed448 → agility KAT signature),
  and byte-equal to BouncyCastle. The JDK is the first peer whose vendor stdlib closes
  the agility *signature* bar with no third-party dependency.
- **RAW PUBLIC-KEY derivation: NOT available from SunEC — the seam.** SunEC exposes a
  public key only as an `EdECPoint` (y + x-sign-bit) and has **no seed→public-point
  API**; and the JDK `MessageDigest` registry has SHA3-{224,256,384,512} but **no
  SHAKE256**, which the RFC-8032 Ed448 seed-expansion requires. So the raw 32-/57-byte
  pubkey (needed for the §1.5 identity-multihash peer_id + the wire `system/peer`
  entity) is **hand-rolled**: SHA-512 / hand-rolled SHAKE256 + BigInteger Edwards
  scalar multiply — keeping the whole core **zero-runtime-dependency, BouncyCastle-free**.
  This is the same hand-roll-the-missing-primitive stance as the CBOR/base58/varint
  layer. Logged as **A-JAVA-007** (arch-bound data point for the cross-peer crypto
  ledger).

## Dev loop

```
# full gate (container-bound, sealed offline):
./run-s2.sh            # mvn -o -B clean test (ECF 69/69 + selftests + Ed448 KAT + BC cross-check)
./run-s2.sh package    # mvn -o -B clean package (also produces the jar)

# or directly:
podman run --rm --network=none -v $PWD:/work:Z \
  -w /work/protocol-generator/java \
  entity-core-keystone/java-toolchain:latest \
  mvn -o -B clean test
```

## Exit criteria

All 69 vectors PASS · Ed25519+Ed448+SHAKE256 KATs byte-equal · BouncyCastle
cross-check PASS · `mvn` compiles clean (no warnings) · ambiguity log has no blocking
codec items · container reproducible (JDK sha256 + Maven sha512 filled+verified, deps
pre-fetched offline). **S2 PASS.**

## Not in this phase (S3+, next session)

- Peer machinery (connection, dispatch, capability, store, processor, handlers) on
  JDK-21 virtual threads (A-JAVA-003) — resynced to the v7.74 peer surface
  (register/outbound/emit/owner-cap + §7a conformance handlers) per A-JAVA-001.
- The v7.73/v7.74 spec-data snapshot is still missing (A-JAVA-001 escalation to arch);
  S3 mirrors the cohort folded-proposal build.
- Full agility matrix (MATRIX-M2/M3/M6, cap-token content_hash, key_type registry
  refusals) — peer-layer, needs the §3.6 cap-token shape. The Ed448+SHA-384 primitives
  are proven at S2.
- The lowercase-hex address-space paths (A-CL-009 trap) are exercised at S3 (§3.4/§3.5).
