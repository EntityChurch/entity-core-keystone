# Evaluation — C# / .NET

**Author:** operator (pre-FFI discipline pass)
**Purpose:** Ground the choices in `protocol-generator/csharp/profile.toml` with an audit trail, and de-risk the **native-first** codec decision against what the three reference impls (Go/Rust/Python) actually had to do. Per the research-arm discipline, evaluations are authored before the profile is trusted; the profile pre-exists as an arch draft, so this retroactively grounds + corrects it.

## Codec strategy decision: **native-first, FFI as fallback + cross-check**

C# stays **native** (`System.Formats.Cbor` + `NSec.Cryptography`). .NET has mature in-box canonical CBOR and audited Ed25519 — no reason to pay the FFI tax unless a native lib proves non-compliant. The FFI crate (`entity-core-codec-ffi`) is still built, but for C# it is **not on the critical path**:
- **(reference)** byte-identity cross-check target alongside the Go-generated test-vectors;
- **(fallback)** if `System.Formats.Cbor` can't be made ECF-compliant, C# drops to the FFI codec for the affected primitives;
- **(other ecosystems)** the FFI is primarily for languages without a credible native CBOR/crypto stack.

**Planning consequence:** C# native S2 validates against `test-vectors/v7.56/` (generated from `entity-core-go/core/ecf/ecf.go`). It does **not** block on the FFI crate. The two proceed in parallel.

## Library audit

| Concern | Choice (profile) | Reference-impl analogue | Notes |
|---|---|---|---|
| CBOR | `System.Formats.Cbor` 9.0.0 (in-box) | Go `fxamacker/cbor` 2.9; Py `cbor2`≥5.8; Rust `ciborium` 0.2 | In-box, no dependency. **Canonical-mode + float gaps below.** |
| Ed25519 | `NSec.Cryptography` 23.4.0 (libsodium) | Go stdlib `crypto/ed25519`; Py `cryptography`; Rust `ed25519-dalek` 2 | Signs the full 33-byte hash (V7 §7.3). Alt: BouncyCastle. |
| SHA-256 | `System.Security.Cryptography.SHA256` (in-box) | stdlib everywhere | Fine. |
| Base58 | (profile: TBD — not pinned) | Go `mr-tron/base58`; Py `base58`; Rust `bs58` | **Gap:** profile doesn't name a Base58 lib. Bitcoin alphabet (V7 §8.5). Pin one in S1, or hand-roll (small). |

## Load-bearing risks for C# native ECF (verify empirically in S1/S2 against test-vectors)

### R1 — Shortest-float (f16) minimization is NOT free *(HIGH — affects every hash over float-bearing data)*
RFC 8949 §4.2 Rule 4 + ECF Rule 4a (`ENTITY-CBOR-ENCODING` §4.1): floats encode to the shortest precision that round-trips, with exact f16 bytes for specials (NaN `F9 7E00`, −0 `F9 8000`, +Inf `F9 7C00`, −Inf `F9 FC00`). **`System.Formats.Cbor` does not minimize floats** — it writes the precision you ask for. Both **Rust** (`encoder.rs:145-193 try_encode_half`) and **Python** had to hand-roll this; Python's `cbor2` C-ext shipped the **exact W2 bug** (emitted float32 for f16-representable |x|≥2¹⁵ like 32768.0/65504.0) and was fixed by switching to the pure-Python encoder (commit `8890022`). → **C# must hand-roll a `TryEncodeHalf`/shortest-float pass.** Maps to conformance-invariant N3/float vectors. Lock with vectors at 1.0, 1.5, 32768.0 (`f97800`), 65504.0 (`f97bff`), NaN, ±Inf, ±0.

### R2 — Entity-data fidelity: hash over raw bytes, never re-encode *(HIGH — cross-impl hash agreement)* 
This is conformance-invariant **N4** (V7 §1.8), and **all three** reference impls converged on it: Go `cbor.RawMessage` passthrough (`ecf.go:40`), Rust `ecf_for_hash(type, &[u8] raw_data)` (`encoder.rs:56-72`), Python stores bytes + idempotency guard. The earlier Rust impl had a real cross-impl bug from decode→re-encode. → C# `ComputeContentHash(string type, ReadOnlySpan<byte> rawData)` must embed `rawData` verbatim into the `{data,type}` hashable, **not** parse-and-reserialize. Pairs with the proposed FFI `ec_entity_original_bytes()` (N4) for the FFI path.

### R3 — Canonical conformance mode: `Strict` is likely wrong → `Ctap2Canonical` *(see finding F4)*
Profile sets `canonical_mode = "Strict"`. .NET `CborConformanceMode.Strict` enforces well-formedness + minimal ints + no-dup-keys but **does not sort map keys**. ECF requires keys sorted by **encoded length then lexicographic** — which is exactly the **CTAP2** rule, i.e. `CborConformanceMode.Ctap2Canonical`. → Strongly suspect the profile must be `Ctap2Canonical` (then *still* hand-roll floats per R1, since no conformance mode does shortest-float). **Verify empirically against `map_keys` vectors in S1/S2 before trusting the profile.** Logged as **F4**.

### R4 — Tag rejection scanner *(MEDIUM — conformance-invariant N2)*
ECF rejects any CBOR major-type-6 in `data` (`ENTITY-CBOR-ENCODING` §6.3, `400 non_canonical_ecf`). `System.Formats.Cbor`'s reader surfaces tags via `CborReader.ReadTag()` rather than rejecting — so C# needs an **explicit recursive tag scan** on decode. None of the three reference impls rely on library defaults here.

### R5 — Zero-hash sentinels on decode *(MEDIUM — new ruling)*
Go carries the `RULING-Q-OMITZERO-HASH-FIELD` ruling (V7 §1.3): optional hash fields must accept CBOR null (`0xF6`), undefined (`0xF7`), and empty byte string as zero-hash. C# hash-field decode must accept these, reject other malformed lengths. (Confirm this ruling is reflected in the 7.56 spec text during S2.)

## Build / packaging (from profile, confirmed sane)
`dotnet9` container · `dotnet build/test/pack -c Release` · xUnit 2.9 · NuGet `entity-core-protocol-csharp` · Apache-2.0. The `dotnet9` Containerfile (bootstrap step 13) is **not yet written** — first S1 task.

## Open items feeding the profile / next session
1. **F4** — change `canonical_mode` `Strict` → `Ctap2Canonical` (verify first).
2. Pin a **Base58** library (or hand-roll) — profile gap.
3. Plan the **hand-rolled shortest-float** module (R1) — the single biggest native-codec risk.
4. Write `containers/dotnet9/Containerfile`.

## Reference files (for idiom, not copying)
Go `entity-core-go/core/ecf/ecf.go`, `core/hash/hash.go` · Python `entity-core-py/.../utils/ecf.py` (float fix lines 28-110) + `tests/unit/test_ecf_canonical.py` · Rust `entity-core-rust/core/ecf/src/encoder.rs`.
