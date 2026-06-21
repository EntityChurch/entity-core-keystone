# entity-core-protocol-ada — Phase S2 (Codec) Summary

**Peer #10** (Ada / GNAT; safety-critical / strong-typing idiom) ·
**Status: COMPLETE — ECF wire-conformance 69/69 byte-identical, 0 FAIL; self-tests 37/37;
container built clean with corrected/exact pins**

## Result

- **ECF codec corpus 69/69 byte-identical** — the **tenth** independent native codec to
  converge, with **0 fixes** after the codec compiled and the float/map-key spike passed.
- **Self-tests 37/37** — N1–N4 covered, plus the uncovered-range probes (full uint64,
  2^63, -2^64), the float ladder boundaries (1.0/1.5/-0.0/65504→f16, 65503→f32, 1.1→f64),
  and the crypto KATs (Ed25519 RFC-8032 TEST-1 pubkey, SHA-256 empty/`abc`, deterministic
  sign+verify+tamper-reject), peer_id §1.5 form, base58 leading-zero round-trip.
- **Container built clean** — `entity-core-keystone/ada-toolchain:latest`, every package
  exact-NVR-pinned, the S1 libsodium/gcc-gnat draft pins corrected (see below).

Full detail: `CONFORMANCE-REPORT.md`.

## Float + map_keys spike (the PHASE-S1 mandate) — PASSED before the full build

The load-bearing canonical risk (length-then-lex map ordering + shortest-float incl. f16)
was validated FIRST via the self-test harness, then the full corpus confirmed it:

- **Float ladder.** Implemented with `Ada.Unchecked_Conversion` for exact IEEE bits
  (Long_Float↔U64, Float↔U32). f16-viability = does the candidate half round-trip
  **bit-exactly** through a direct-bit `Half_To_Double` (which expands normals,
  subnormals, ±0, ±Inf, and NaN straight in f64 bit space, so the specials round-trip and
  the encoder catches them without ad-hoc casing). NaN → `f9 7e00`, -0.0 → `f9 8000`,
  ±Inf → `f9 7c00`/`fc00`. All 14 float vectors PASS; 65503 correctly escapes f16 to f32.
- **Map ordering.** Each key is encoded to its own buffer, then slots are insertion-sorted
  by **encoded-key bytes, length-first then bytewise-lexicographic** (ECF Rule 2 / §3.5,
  which DIFFERS from pure RFC-8949 bytewise). Duplicate keys (adjacent after sort) raise
  `Duplicate_Key` (Rule 5). All `map_keys` + the mixed-key `content_hash`/`envelope`
  vectors PASS.

Native canonicality is **viable** — the documented `ffi` fallback was **not needed**, as
expected.

## The libsodium NVR correction + exact pins captured (the S2 fix-item)

The orchestrator-flagged fix-item is DONE. Captured by `rpm -q` inside the built image
(`/opt/ada-toolchain-versions.txt`):

| Package | S1 draft | S2 corrected (real NVR) |
|---|---|---|
| **libsodium / -devel** | `1.0.20` | **`1.0.22-1.fc43`** |
| **gcc-gnat** | `15.2.1-2.fc43` | **`15.2.1-7.fc43`** |
| **gcc** | (`-2.fc43`) | **`15.2.1-7.fc43`** |
| **gprbuild** | unpinned | **`25.0.0-5.fc43`** |
| **openssl-devel** | unpinned | **`3.5.4-3.fc43`** |
| **make** | unpinned | **`4.4.1-11.fc43`** |

- **libsodium 1.0.20 → 1.0.22-1.fc43.** fedora:43 ships ONLY `libsodium-1.0.22-1.fc43`
  (verified by `rpm -q`; matches the existing `containers/c-toolchain` pin). The high-
  level `crypto_sign_*` / `crypto_hash_sha256` APIs are **byte-identical** between 1.0.20
  and 1.0.22, so this is a **correctness/pin-hygiene fix, conformance-neutral** — the
  Ed25519/SHA-256/peer_id KATs all pass against 1.0.22.
- **gcc-gnat/gcc 15.2.1-2 → -7.fc43.** The S1 draft `-2.fc43` was a guess; the actual
  Fedora 43 release at the S2 build is `-7.fc43`. Corrected.
- **gprbuild / openssl-devel / make** were unpinned in the S1 RUN line — now exact-pinned.

Written back into: the `Containerfile` RUN line + the comment block + the `LABEL
…libsodium=` / `…gnat=`; `profile.toml [codec].ed25519_library.version` + the `[deps]`
block; and `arch/PROFILE-RATIONALE.md` "Toolchain pins". The `rpm -q` capture line in the
Containerfile now also records `gcc`/`make`.

## What was built (`src/`)

| File | Responsibility |
|---|---|
| `entity_core.ads` | root library unit |
| `entity_core-bytes.{ads,adb}` | wire-byte primitives: growable `Byte_Vector`, `Byte_Array`, **lowercase-hex helper via a custom nibble→char table** (A-ADA-003 — never `Integer'Image`/`Integer_IO Base=>16`) |
| `entity_core-errors.ads` | the exception set (Codec_Error / Tag_Rejected / Duplicate_Key / Crypto_Error / …) → 400 etc. at the S3 boundary |
| `entity_core-codec-value.{ads,adb}` | **the value model** — `Ecf_Value`, a **discriminated/variant `Controlled` record** over the full ECF value space (`K_Uint`/`K_Nint`/`K_Bytes`/`K_Text`/`K_Array`/`K_Map`/`K_Bool`/`K_Null`/`K_Float`). `data` is one such value, NOT a map (A-ADA-009/A-JAVA-010). Value-semantic (deep-copy on Adjust, deep-free on Finalize). |
| `entity_core-codec-cbor.{ads,adb}` | **the heart** — canonical ECF encode/decode; length-then-lex map sort; shortest-float ladder; recursive tag rejection (N2); definite lengths; full uint64/-2^64. **Design-by-contract aspects**: `Post` on `Encode` pins the N3 empty-map = 1-byte invariant. |
| `entity_core-codec-varint.{ads,adb}` | multicodec LEB128 (N1) encode/decode |
| `entity_core-codec-base58.{ads,adb}` | Bitcoin-alphabet encode/decode (leading-zero preserving) |
| `entity_core-codec-hash.{ads,adb}` | `varint(fc) ‖ SHA-256(ECF({type,data}))` |
| `entity_core-codec-peer_id.{ads,adb}` | `ECF-text(Base58(varint(kt) ‖ varint(ht) ‖ digest))` + parse + **§1.5 canonical-form derivation** (`From_Ed25519_Public`: kt=1, ht=0, raw pubkey; A-ADA-001) |
| `entity_core-crypto.{ads,adb}` | **libsodium binding** via `Interfaces.C`/`System.Address` (`crypto_sign_seed_keypair`/`_detached`/`_verify_detached`/`crypto_hash_sha256`); raw-pubkey directly |

Build/test: `entity_core_protocol.gpr` (gprbuild, Ada 2022, `-gnata` so the contract
aspects run); `tests/run_conformance.adb` (the ECF gate) + `tests/run_tests.adb` (the
hand-rolled self-test runner, no AUnit). `run-s2.sh` is the offline dev loop.

## Idiom seams exercised (the Ada-distinct axes)

- **Discriminated-record variant for the ECF value** (A-ADA-009 made pointed by strong
  typing): the compiler enforces the closed kind set; `data` is a general value, so the
  silent-500 trap (map-only `data`) is structurally avoided.
- **Design-by-contract aspects** (the profile's static-rigor seam): `Pre`/`Post`/
  `Type_Invariant` aspects throughout the codec specs, RUNTIME-CHECKED in the test build
  (`-gnata`). E.g. `Encode`'s `Post` pins N3 (empty map → 1 byte); the `Value`
  constructors' `Post` pin the resulting `Kind`; accessors carry `Pre => Kind (V) = …`.
- **Native modular unsigned** (`Interfaces.Unsigned_64`): the full uint64 head-form / -2^64
  range with NO BigInteger/`ulong` workaround — the Ada advantage over the C#/Java
  unsigned trap, proven by the uncovered-range self-tests.
- **`Interfaces.C` crypto binding**: raw 32-byte pubkey straight from
  `crypto_sign_seed_keypair` — no point-extraction (the Java EdEC wrinkle is absent).

## Deviations / engineering notes

- **`pragma Validity_Checks (Off)` in the codec + value bodies.** `-gnatVa` (and `-gnata`'s
  implicit float validity) treats IEEE specials (NaN / ±Inf, which the ECF float corpus
  legitimately carries) as "invalid data" the instant a value is produced via
  `Unchecked_Conversion` / returned — raising `Constraint_Error` on canonical wire bytes.
  Float specials are first-class in ECF, so blanket float-validity checking is wrong here;
  it is disabled in exactly the two bodies that traffic in raw float bits. This does NOT
  weaken the design-by-contract `Pre`/`Post`/`Type_Invariant` checks (those stay live under
  `-gnata`) — it only stops the compiler mis-flagging legitimate special floats.
- **`-gnatwJ` / `-gnatw.T`** in the `.gpr`: silence the obsolescent-`()`-aggregate note and
  the static `'Length`-postcondition note (the `Post` *does* reference `'Result`). All
  other `-gnatwa` warnings are on; the build is otherwise warning-clean.

## Ambiguity log

No NEW blocking-severity codec ambiguity surfaced — consistent with the dry well. The
inherited-settled items (A-ADA-001/003/007/008/009) held exactly as pre-resolved; A-ADA-002
(Ed448/SHA-384 defer) is confirmed as the libsodium gap (core floor unaffected). One small
NEW entry logged: **A-ADA-010** (float-validity-check suppression as an Ada-specific codec
note). See `SPEC-AMBIGUITY-LOG.md`.

## Not in this phase (S3+)

- Peer machinery (connection, dispatch, capability, store, processor, handlers) on Ada
  **tasks + protected objects + rendezvous** — the §4.8 store behind a protected object
  (A-ADA-006); the §4.10(b) 400-chain-depth structural pre-check (A-ADA-007); the §5.2
  401/403 trichotomy (A-ADA-008).
- The lowercase-hex address-space paths (§3.4/§3.5; A-ADA-003 helper exists, exercised at S3).
- The Ed448/SHA-384 agility overlay (A-ADA-002) — OpenSSL-curve448 / C-ABI route; the
  `openssl-devel` headers are already in the image for it.

## Exit criteria

ECF corpus byte-identical (69/69) · self-tests 37/37 · `gprbuild` clean (no warnings) ·
ambiguity log has no blocking codec items · container built clean with corrected
libsodium NVR + exact package pins. **S2 PASS.**
