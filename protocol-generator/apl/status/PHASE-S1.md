# entity-core-protocol-apl — Phase S1 summary

**Phase:** S1 (research + profile authoring)
**Date:** 2026-07-12
**Peer:** the ARRAY / value-model alien-substrate probe, in the FFI-hybrid
COBOL/Rexx/Tcl/Fortran family.
**Status:** ✅ **COMPLETE** — profile + rationale + ambiguity log + container authored
**and the container BUILDS GREEN** (all in-build probes pass). No blocking items.

## The probe (why this peer exists)

APL is the **array-as-primitive-value** probe. Its whole paradigm is off-wire (every value
is an array; the codec is base-conversion `⊤`/`⊥` + grade `⍋` over vectors, in a language
whose pure functions have no statement control flow), and its ints/floats are conventional —
so the honest expectation is **corroboration + generator-stress**, NOT a fresh wire finding
(the durable lesson: the spec-discovery well is dry on the current wire surface). The one
wire-touching edge is the numeric ceiling, verified in-container:

- GNU APL's exact integer is signed **int64**, ceiling `2^63-1`.
- At/above `2^63` GNU APL **silently promotes to IEEE double** (lossy above `2^53`) with NO
  error — verified: `2*62` → `4611686018427387904` (exact), `(2*63)-1` → `9.223372037E18`
  (float form).
- So the ECF uint64 tower `[2^63, 2^64-1]` **cannot be a native APL scalar at all** —
  *sharper* than Fortran (whose signed int64 holds the 64-bit pattern in a controllable
  carrier; APL's overflow escapes to a lossy float). The carrier is the **array itself**: an
  8-octet big-endian int64-cell vector, never `256⊥`'d into a scalar (A-APL-002/003). This
  is the "integer head-form is a fixed-width artifact" lesson in the array model.

## Decisions (all recorded in profile + ambiguity log)

- **Interpreter = GNU APL 1.9** (A-APL-001/004), built from the SHA-256-pinned GNU source
  tarball. **No APL-family interpreter is in fedora:43 dnf** (verified — apl/gnu-apl/J/Dyalog
  all absent), so a source build is required (the GHC-bindist precedent). Declined: Dyalog
  (proprietary), J (external bindist / finicky build, ASCII dialect — though best FFI +
  bignum), dzaima/kap (JVM-heavy). GNU APL builds clean on GCC 15 and gives native ⎕FIO
  sockets. **apl-2.0** (2026-06-24) DECLINED — only ~18d old, violates the S11 30-day floor.
- **Codec strategy = FFI-hybrid** (`codec_strategy = "ffi"`): hand-rolled canonical CBOR
  VALUE codec in pure APL (the array probe) + crypto/entity-framing/base58 over the C-ABI
  (`libentitycore_codec`) via a GNU APL **native-function (⎕FX) C++ shim**. base58/peer-id
  ride `ec_peerid_*` (no APL exact bignum — A-APL-010).
- **uint64 tower** (A-APL-002/003): 8-octet big-endian int64-cell vector; `⊤`/`⊥` used only
  below `2^63`; mandatory self-test on `{0, 2^63-1, 2^63, 2^64-2, 2^64-1}`.
- **Floats** (A-APL-005): native IEEE binary64, but APL has **no bit-reinterpret primitive**
  (no `transfer`) → f64/f32 IEEE bits hand-rolled arithmetic (Rexx-family) or an ec_* helper;
  f16 + shortest ladder hand-rolled.
- **Data model** (A-APL-011): nested array (`⊂`/`⊃`) with an explicit integer major-type
  discriminant cell (int-vs-float + byte-vs-text intent explicit; never inferred from storage).
- **Error model = status-code + signal**: EC_*-aligned status scalar + `⎕SIGNAL`/`⎕ES` event
  system for faults (the COBOL/Fortran status family with APL's events on top).
- **Async = single-thread select** via **native ⎕FIO Berkeley sockets** — NO C net-shim
  (a difference from COBOL/Fortran; A-APL-006). §7b structural; §6.11 manual reentry pump.
- **Naming = PascalCase fns / camelCase vars / UPPERCASE consts** (A-APL-007); dfns for pure
  transforms, tradfns for the loop; the workspace is the namespace unit (no module system).
- **Build = make** (native-fn g++ compile + codec CMake); `.apl` is interpreted (no static
  gate — the harness + corpus are the gate).
- **Test = hand-rolled** corpus driver (no APL xUnit).
- **License = Apache-2.0** peer source, with the note (A-APL-008) that the native-fn shim
  #includes GPLv3 apl headers and combines into a GPLv3 binary (Apache-2.0 → GPLv3 one-way
  compatible; no relicense needed, flagged for awareness).

## Library picks (S11 pins, all ≥30d old at 2026-07-12)

| Surface | Pick | Version / date |
|---|---|---|
| Interpreter | GNU APL (source-built, sha256-pinned) | 1.9 (2024-06-29); sha256 `291867f1…` |
| Compiler | gcc/g++ | 15.2.1 (fedora:43) |
| CBOR | hand-rolled pure APL | in-repo |
| Crypto / framing / base58 | libentitycore_codec (FFI via ⎕FX native fn) | C-ABI 1.1 |
| Ed25519 / SHA-256/384 / Ed448 | libentitycore_codec | C-ABI 1.1 |
| Test framework | hand-rolled corpus driver | in-repo |
| libsodium (transitive, in codec) | libsodium | 1.0.22 (image-provided) |

## Container — BUILT + PROBES GREEN

`containers/apl-toolchain/Containerfile` on fedora:43 + gcc-c++/gcc + make/cmake/pkgconfig
+ readline-devel/ncurses-devel + libsodium-static/devel, building GNU APL 1.9 from the
sha256-pinned GNU source (fail-closed) and **RETAINING** the configured `/opt/apl-1.9` tree
(native-fn shims need apl's source-tree headers — A-APL-009). In-build probes, all passing:

1. **array/numeric probe** — `⊤`/`⊥` base-256 round-trip; the int64 exact-ceiling +
   silent-double-promotion demonstration (`(2*63)-1` shown as a float).
2. **native-function FFI mechanism** — a C++ native-fn shim compiled against the retained
   apl headers, loaded via `⎕FX`, calling a C symbol and returning to APL (gated on output).

Build (capped): `podman build $PODMAN_BUILD_CAPS -t entity-core-keystone/apl-toolchain:latest
-f containers/apl-toolchain/Containerfile .` → **exit 0, image built**.

## FFI spike — ec_* codec called from APL (out-of-band, VERIFIED)

Beyond the self-contained libc-strlen probe in the image, the **real ec_* spike** was run
(mount workspace → build `libentitycore_codec` fresh via CMake → build a native-fn shim
linking it → load in APL via ⎕FX). Result:

```
ECCODEC
ec_abi_version=1.1 ec_sha256_rc=0 sha256(empty)[0:2]=e3b0 impl=c 0.1.0 / ecf-c-abi 1.1 / ...
apl exit=0
```

`sha256(empty)` first bytes `e3b0` match the known SHA-256 empty-string vector
(`e3b0c442…`) — the GNU APL native function calls the **real** C-ABI codec symbols correctly.
The FFI path is **confirmed working, not blocked**.

## Exit criteria — MET

Profile authored (every field populated, no blocking TBD); rationale + ambiguity log written;
container authored **and built green**; no blocking-severity ambiguity (all 11 items are
operator/research-level local decisions with resolved best-guesses). FFI primitive proven
end-to-end against the real codec.

## What S2 needs to know

- The whole array codec lives in `src/cbor.apl`: `⊤`/`⊥` base-256 for values `< 2^63`, the
  **octet-array carrier** for the `[2^63, 2^64-1]` tower (never `256⊥` into a scalar,
  A-APL-002), `⍋` grade for length-then-lex map-key ordering, and the hand-rolled f64/f32
  bit path (no `transfer` — A-APL-005) + f16 + shortest ladder. Value model = nested array
  with an explicit major-type discriminant (A-APL-011).
- Crypto/framing/base58/peer-id are FFI: author `src/ext/ec_native.cc` as a GNU APL
  native-function shim wrapping the `ec_*` symbols from
  `ffi-generator/c-abi/spec/entitycore_codec.h`. Compile with `g++ -shared -fPIC -std=gnu++17
  -I/opt/apl-1.9 -I/opt/apl-1.9/src` (BOTH paths — build root for `config.h`, src for the
  headers); forward-declare `NativeFunction`; watch the most-vexing-parse on `UCS_string`.
  base58 rides `ec_peerid_{parse,format}` — do NOT hand-roll (A-APL-010).
- Sockets are native ⎕FIO (`[32/34/35/36/37/38/39/40]`) — no C net-shim (A-APL-006); confirm
  the `--safe` requirement + the TCP_NODELAY ⎕FIO sub-function code at S3.
- Confirm the three spec-data SHA-256 pins in `spec-data/v0.8.0/MANIFEST.md` unchanged at S2
  entry. Codec corpus: `test-vectors/v0.8.0/conformance-vectors-v1.cbor`. Oracle `cc1970f`
  for S4.
- **Next: S2** — the hand-rolled canonical CBOR array codec + varint + the native-fn FFI
  shim; target the full v0.8.0 corpus byte-identical (or the FFI differential).

## Time

~1 session. The bulk went to the load-bearing verifications: proving no APL interpreter is in
fedora dnf, that GNU APL 1.9 builds on GCC 15, the int64→double numeric ceiling, and the
native-function ⎕FX FFI mechanism end-to-end against the real `ec_*` codec.
