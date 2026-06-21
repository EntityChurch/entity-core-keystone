> **v7.75 re-run (oracle `entity-core-go @ 62044c5`).**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **576 total · 292 pass · 195 warn · 0 FAIL · 89 skip.**
> New v7.75 categories scored GREEN: **`resource_bounds`** r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (SHOULD, external-admission carve-out); **`concurrency`** 5/5 PASS.
> The only net-new peer change this cycle: an explicit §4.10(b) max-chain-depth (64) pre-check that surfaces **400 `chain_depth_exceeded`** for an over-deep chain BEFORE the per-link authz walk — distinct from the prior 403 `capability_denied` (arch v7.75 ruling: structural excess ≠ authz denial). The numbers below this line predate the v7.75 re-vendor and are retained for history.

---

# entity-core-protocol-csharp — Conformance Report (S2 codec)

**Phase:** S2 (codec layer)
**Strategy:** native (`System.Formats.Cbor` 9.0.0 + `NSec.Cryptography` 25.4.0 + in-box SHA-256)
**Corpus:** `protocol-generator/shared/test-vectors/v7.56/conformance-vectors-v1.cbor`
(SHA `41d68d2d…`, the vendored arch-canonical fixture, ECF v1.5 / V7 7.56)
**Result:** ✅ **69/69 PASS — byte-identical** (S7 lower bar met)

```
category        pass total
--------------------------
float             14    14  ok
int               14    14  ok
map_keys           6     6  ok
length             8     8  ok
primitive          6     6  ok
nested             4     4  ok
tag_reject         5     5  ok
content_hash       4     4  ok
peer_id            3     3  ok
signature          3     3  ok
envelope           2     2  ok
--------------------------
TOTAL             69    69
# RESULT: PASS (69/69)
```

(The fixture array holds 69 vectors — 64 `encode_equal` + 5 `decode_reject`. The
"71" in the corpus MANIFEST additionally counts 2 non-vector metadata-agreement
checks from the arch lock report. All 69 wire vectors ran; complete coverage,
matching the rust-ffi / c-ffi 69/69 baseline exactly.)

## How to reproduce

```sh
podman run --rm -v "$PWD":/work:Z -v kc-nuget:/nuget \
  entity-core-keystone/dotnet9:latest sh -c '
    cd /work/protocol-generator/csharp
    dotnet test -c Release'                      # xUnit gate (24 tests, incl. the corpus fact)

# or the standalone harness (prints the table above, exit code = gate):
podman run --rm -v "$PWD":/work:Z -v kc-nuget:/nuget \
  entity-core-keystone/dotnet9:latest sh -c '
    cd /work/protocol-generator/csharp
    dotnet run -c Release --project test/EntityCore.Protocol.Conformance'
```

## What each category proves (and the load-bearing risks it closed)

- **float (14/14)** — the hand-rolled shortest-float pass (eval R1). f16/f32/f64
  boundary selection + Rule 4a specials (NaN `f97e00`, ±Inf, ±0). Closed the
  single biggest native-codec risk; the C#/`Half`-based selector matches the C
  impl's `encode_float` byte-for-byte, including the W2-battery large-f16 cases
  (32768.0 `f97800`, 65504.0 `f97bff`, 65503.0 → f32).
- **int (14/14)** — minimal-length argument encoding at every boundary incl. max
  i64; via `CborWriter` Ctap2 + `WriteUInt64`/`WriteCborNegativeIntegerRepresentation`
  (full u64 range, F7-safe).
- **map_keys (6/6)** — **F4 closed.** `Ctap2Canonical` reproduces length-then-lex
  ordering (RFC 8949 §4.2.1) byte-for-byte, incl. the length-boundary (23 vs 24)
  and mixed bytes/text-key cases. Verified empirically before the profile edit
  (`Strict` → `Ctap2Canonical`).
- **length (8/8)** — definite-length only, all container kinds, boundaries.
- **primitive (6/6)** — `f4`/`f5`/`f6` single-byte forms; null/bool in maps.
- **nested (4/4)** — deep nesting + the entity `{type,data}` + hash-keyed
  `included` shapes.
- **tag_reject (5/5)** — N2: explicit recursive tag rejection (eval R4), incl.
  tag-0/1/37/55799 and the deep tag nested inside an `included` entity.
- **content_hash (4/4)** — `LEB128(format_code) || SHA256(ECF({data,type}))`;
  N3 empty-data boundary (`content_hash.1`, the F5-superseding value
  `005f3139…`); N1 multi-byte varint prefix (`format_code=128`); N4 verbatim
  `data` splice.
- **peer_id (3/3)** — `Base58(LEB128(key_type)||LEB128(hash_type)||digest)`;
  N1 multi-byte varint (`key_type=128`). Hand-rolled Base58.
- **signature (3/3)** — deterministic Ed25519 (RFC 8032) over canonical-ECF
  entities; NSec/libsodium 1.0.20.1 produces signatures **byte-identical** to the
  Go/Rust/Py-blessed seeds. Cross-confirms the canonical encoder feeding the sign
  input.
- **envelope (2/2)** — `{root, included}` carrier; map-key sort under the envelope
  shape; hash-keyed included map.

## Cross-impl convergence (S8)

This is the **third** independent codec to hit 69/69 on this fixture — joining
`entity-core-codec-ffi-rust` and `entity-core-codec-ffi-c`. Three hand-independent
implementations (different language, CBOR engine, and crypto stack:
`System.Formats.Cbor`+NSec/libsodium vs ciborium+dalek vs hand-rolled+libsodium)
converging to the byte is exactly the convergence S8 promises. The native C# path
needs no FFI fallback for any primitive.

## Gate status

- **S7 lower bar (codec byte-identical to fixture):** ✅ met (69/69).
- **S7 higher bar (`validate-peer` live categories):** not in scope for S2 —
  belongs to S3 (peer) + S4 (conformance).
