# entity-core-protocol-fortran — Phase S1 summary

**Phase:** S1 (research + profile authoring)
**Date:** 2026-07-11
**Peer:** #25 — an alien-substrate probe in the FFI-hybrid COBOL/Rexx/Tcl family
(this machine's slot; a sibling machine builds Forth #26 in parallel).
**Status:** ✅ **COMPLETE** — profile + rationale + ambiguity log + container authored
(container build verification in progress at handoff — see below). No blocking items.

## The probe (why this peer exists)

Fortran is the **fixed-width SIGNED-ONLY numeric-model** probe. ECF's canonical wire
carries a binary UNSIGNED integer tower (CBOR mt0) reaching the full uint64 range
`[0, 2^64-1]`. Fortran's widest portable integer is the **signed** `integer(int64)`
(range `[-2^63, 2^63-1]`); there is **no portable unsigned type**. So the octet
`[2^63, 2^64-1]` is the sharp edge — carried as a 64-bit BIT PATTERN in a signed carrier,
byte-emitted via `ishft`/`iand` (never signed arithmetic). This is the durable "integer
head-form is a fixed-width artifact" lesson at its sharpest fixed-width case (sharper than
C# `ulong` / Zig `u64` / OCaml int63, none of which lack an unsigned/wide carrier). The
softer second axis: unlike Rexx (no binary float at all), Fortran has **native IEEE**
`real(real64/real32)` + a `transfer()` bits path, so the float tower is tractable — only
f16 + the shortest-float ladder are hand-rolled. See `arch/PROFILE-RATIONALE.md`.

## Decisions (all recorded in profile + ambiguity log)

- **Codec strategy = FFI-hybrid** (`codec_strategy = "ffi"`): hand-rolled canonical CBOR
  VALUE codec in pure Fortran (the numeric probe) + crypto / entity-framing / base58 over
  the C-ABI (`libentitycore_codec`). Crypto binds the `.so` **directly** via
  `iso_c_binding` interface blocks matching the verbatim `entitycore_codec.h` — NO C
  wrapper (cleaner than Rexx's SAA ext / Tcl's stubs shim). The ONLY C wrapper is the
  socket net-shim (Fortran has no native sockets).
- **uint64 boundary** (A-FTN-001/002): signed `integer(int64)` bit-carrier; octets via
  `iand(ishft(v,-8*k),255)`; unsigned compare via bias/top-byte, never bare `<`; mandatory
  head-form self-test on `{0, 2^63-1, 2^63, 2^64-2, 2^64-1}`. Fortran 2023 `UNSIGNED`
  (`-funsigned`, gfortran 15, `uint64` in `ISO_FORTRAN_ENV`) surveyed and **declined**
  (experimental/flag-gated/array-index-hostile) — a small finding that the framing is
  slightly outdated but the declined path is correct.
- **Floats** (A-FTN-005): native IEEE via `transfer()` for f32/f64 bits + `ieee_arithmetic`
  classification; f16 + shortest ladder (Rule 4) hand-rolled; `transfer` is native-endian
  → explicit big-endian byte-swap on every head.
- **Data model** (A-FTN-003): no native sum type → `ecf_value_t` derived type with an
  integer major-type discriminant carrying int-vs-float + byte-vs-text intent explicitly.
- **Byte buffers** (A-FTN-004): `integer(int8)` (SIGNED — 0xFF = -1); mask `iand(b,255)`.
- **Error model = status-code**: integer `intent(out) stat` + `error stop` (COBOL analogue,
  EC_*-aligned).
- **Async = single-thread select** via the C net-shim; §7b structural; §6.11 manual pump.
- **Naming = lower_snake_case** (fortran-lang/stdlib), `_t` derived types, `UPPER_SNAKE`
  parameters; modules are the namespace unit.
- **Build = gfortran + make** (A-FTN-008): fpm 0.12.0 is idiomatic but NOT in fedora dnf →
  make is the container build; `fpm.toml` shipped for fpm users.
- **Test = test-drive 0.6.1** vendored (A-FTN-009): the ecosystem standard, single-file
  redistributable; conformance corpus walk hand-rolled around it.

## Library picks (S11 pins, all >30d old at 2026-07-11)

| Surface | Pick | Version / date |
|---|---|---|
| Compiler | gfortran (GCC) | 15.2 (fedora:43 GNU Toolchain F43; GCC 15 = 2025 line) |
| CBOR | hand-rolled pure Fortran | in-repo |
| Crypto / framing / base58 | libentitycore_codec (FFI, iso_c_binding) | C-ABI 1.1 |
| Ed25519 / SHA-256/384 / Ed448 | libentitycore_codec | C-ABI 1.1 |
| Test framework | test-drive (vendored testdrive.F90) | 0.6.1 (2025-06-13) |
| Package manifest (idiomatic) | fpm.toml | fpm 0.12.0 (2025-05-18) — not container build |
| libsodium (transitive, in codec) | libsodium | 1.0.22 (image-provided) |

## Container

`containers/fortran-toolchain/Containerfile` authored on the fedora:43 base +
gcc-gfortran + gcc/gcc-c++ + cmake/make/pkgconfig + libsodium-static/devel. Includes
three in-build substrate probes (the S1 verification the rexx/cobol images do):
1. **signed-carrier uint64** — `2^64-1` (== `-1_int64`) big-endian octet extraction via
   `ishft`/`iand` yields `FFFFFFFFFFFFFFFF`; `2^63` top octet `0x80` (A-FTN-002).
2. **transfer() IEEE bits** — `1.0d0` → `0x3FF0000000000000`, `1.0` → `0x3F800000`;
   `ieee_arithmetic` NaN classification (A-FTN-005).
3. **iso_c_binding** — a live `bind(c)` call into libc `strlen` resolves + returns 11
   (the crypto/net FFI mechanism, end-to-end).

Build with the resource caps: `make fortran-toolchain` (= `podman build $PODMAN_BUILD_CAPS
-t entity-core-keystone/fortran-toolchain:latest -f containers/fortran-toolchain/Containerfile .`).

## Exit criteria — MET

Profile authored (PROMPT-CONSTANTS complete, no TBD blocking S2); rationale + ambiguity
log written; container authored with substrate probes. No blocking-severity ambiguity
(all 9 items are operator-level local decisions with resolved best-guesses).

## What S2 needs to know

- The whole numeric probe lives in `src/cbor.f90`: the signed-carrier uint tower (octet
  extraction + bias compare + the `{0,2^63-1,2^63,2^64-2,2^64-1}` self-test), the native
  f32/f64 `transfer` path with **explicit big-endian byte-swap**, and the hand-rolled f16
  + shortest-float ladder (Rule 4). The signed-byte mask (`iand(b,255)`, A-FTN-004) is
  pervasive.
- Crypto/framing/base58/peer-id are FFI: author `src/entity_core_ffi.f90` as
  `iso_c_binding` interface blocks matching `ffi-generator/c-abi/spec/entitycore_codec.h`
  verbatim (ec_* symbols). base58 rides `ec_peerid_{parse,format}` — do NOT hand-roll
  (no Fortran bignum, A-FTN-006). The socket net-shim (`src/ext/net_shim.c`) is S3, not S2.
- Confirm the three spec-data SHA-256 pins in `spec-data/v0.8.0/MANIFEST.md` unchanged at
  S2 entry. Codec corpus: `test-vectors/ecf-conformance/conformance-vectors.cbor`; target 69/69
  byte-identical (or the FFI differential). Oracle commit `cc1970f` for S4.
- **Next: S2** — the hand-rolled canonical CBOR codec + varint + the FFI interface module;
  target the full v0.8.0 corpus byte-identical.
