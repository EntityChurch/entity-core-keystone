# entity-core-protocol-fortran — Profile Rationale (S1)

For architecture review. Why the `profile.toml` decisions are what they are, and what
this peer is meant to surface. Peer #25, an alien-substrate probe in the FFI-hybrid
COBOL/Rexx/Tcl family, but on a distinct wire-touching axis.

## The axis: fixed-width SIGNED-ONLY integers (sharpest fixed-width uint64 case)

The peer-selection compass says spec-discovery yield is *substrate*-bound and lives on
the wire-touching axes (integer width / float model / crypto availability / string
model). ECF's canonical wire carries a binary UNSIGNED integer tower — CBOR mt0 reaches
the full uint64 range `[0, 2^64-1]` with a shortest-head ladder. Fortran's widest
portable-standard integer is the **signed** `integer(int64)` (two's-complement, range
`[-2^63, 2^63-1]`). There is **no portable unsigned integer type**. So the octet
`[2^63, 2^64-1]` of the uint64 tower has no natural signed carrier — the peer must hold
those values as a **64-bit bit pattern in a signed carrier** and emit/parse the octets
with bit intrinsics (`ishft`/`iand`), never signed arithmetic. This is the durable
"integer head-form is a fixed-width artifact, not a protocol property" lesson taken to
its sharpest fixed-width case: C# has `ulong`, Zig has `u64`, OCaml carries int63 — each
has *some* unsigned or wider carrier — whereas classic Fortran has neither. That is the
probe (A-FTN-002): does the spec's numeric determinism (uint boundary, minimal-int head)
survive a substrate whose only wide integer is signed?

## The Fortran 2023 UNSIGNED wrinkle (verified, declined)

Research turned up a genuine wrinkle worth recording: **Fortran 2023 adds an `UNSIGNED`
type**, and **gfortran 15 implements it** under `-funsigned` (per J3/24-116), exposing
`uint8/16/32/64` in `ISO_FORTRAN_ENV`. So the naive "Fortran has no unsigned integer at
all" framing is slightly outdated as of gfortran 15 / fedora:43. It is **declined**
anyway (A-FTN-001): `-funsigned` is experimental, flag-gated, and the unsigned type
cannot be a `DO` index or array subscript and needs explicit conversion for mixed
arithmetic — awkward for a codec, and non-portable across the older/other compilers a
Fortran peer should tolerate. The signed bit-carrier is portable, keeps the probe pure,
and is the honest representation of the substrate the compass wanted to stress. This is
itself a small finding: the spec forces even a substrate that *nominally* gained an
unsigned type to carry the uint tower as an explicit bit pattern.

## The softer axis: native IEEE floats (tractable, unlike Rexx)

Unlike Rexx (#24, no binary float type at all — every IEEE bit hand-computed in decimal),
Fortran has **native IEEE-754** `real(real64)`/`real(real32)` (binary64/binary32), the
`ieee_arithmetic` intrinsic module for classification (`ieee_is_nan`, `ieee_class`), and
`transfer(x, 0_int64)` to read a float's raw bits directly. So the float tower is
tractable: f32/f64 encode/decode is `transfer` + an explicit byte-swap to network order,
and only **f16 (binary16)** — which has no guaranteed native real kind — plus the
**shortest-float ladder** (Rule 4: does the value round-trip through f16/f32 exactly?)
are hand-rolled bit arithmetic. This makes Fortran a useful mid-point in the cohort:
harder than the platform-bignum peers, far easier than Rexx on floats, and the clean
place to corroborate that the shortest-float ladder is unambiguous.

## Codec: FFI-hybrid (native value CBOR + C-ABI crypto)

- **CBOR value codec hand-rolled in pure Fortran** — continuing the A-005 pattern (no
  Fortran package gives canonical ECF; the surveyed `fortran-cryptography` /
  `Fortran-Crypto` repos are exploratory and CBOR-less). Fortran's bit intrinsics
  (`ishft`/`iand`/`ibits`/`mvbits`/`transfer`) over `integer(int8)` byte arrays are a
  competent byte assembler; the integer tower is the signed-carrier probe, the float
  tower is native-with-hand-rolled-f16.
- **Crypto/entity-framing/base58 over the C-ABI** — no native audited Fortran crypto, so
  `libentitycore_codec` is bound from the start. Fortran's **first-class C interop**
  (`iso_c_binding`) binds the `ec_*` symbols **directly** via interface blocks matching
  the verbatim `entitycore_codec.h` — no C wrapper needed for crypto (cleaner than
  Rexx's SAA-API ext or Tcl's stubs shim). base58 rides `ec_peerid_{parse,format}`
  because Fortran has no bignum type (A-FTN-006, the COBOL choice).

## Sockets: single-thread select via a thin C net-shim

Fortran has no native sockets and no natural network-concurrency model (`do concurrent`
is data-parallel, coarrays are SPMD, OpenMP is loop parallelism). The peer is a
single-threaded `select` loop over a **thin C net-shim** (`ec_net_*`) bound via
`iso_c_binding` — the COBOL `netshim.c` / Rexx select-loop shape. This is the *only* C
wrapper (crypto binds the `.so` directly). §7b store-safety is structural (one image,
one thread, no lock); §6.11 outbound-dispatch reentry is a manual pump (the
correlation-map tax the non-actor/non-CSP peers pay).

## Error model, naming, build, test — following research, not preference

- **Error model = status-code** (integer `intent(out) stat` + `error stop`): Fortran has
  no exceptions/Result; the native `iostat=`/`stat=` convention maps directly onto the
  C-ABI `EC_*` codes and the protocol status codes — the COBOL analogue.
- **Naming = lower_snake_case** with `_t`-suffixed derived types and `UPPER_SNAKE`
  PARAMETER constants: the modern fortran-lang / stdlib convention (Fortran is
  case-insensitive; this is the community's chosen style, not a translation).
- **Build = gfortran + make** for the container: `fpm` (0.12.0, 2025-05-18) is the
  modern idiomatic tool but is **not in fedora:43 dnf** (snap/conda/pypi/binary only), so
  pulling it in adds supply-chain friction. `make` is self-contained and handles module
  dependency order; an `fpm.toml` is shipped for fpm users (A-FTN-008).
- **Test = test-drive** (0.6.1, 2025-06-13), vendored as the single redistributable
  `testdrive.F90`. Unlike COBOL/Rexx (no framework → hand-rolled), Fortran *has* a
  dominant community framework, so the profile follows research and uses it (the
  Tcl/tcltest reasoning), vendored so the make/gfortran container stays self-contained.
  The conformance corpus walk is a hand-rolled driver structured with test-drive asserts.

## Data model: tagged-union derived type

Fortran has no native sum type. An ECF value is a derived type (`ecf_value_t`) with an
integer major-type discriminant that carries **int-vs-float** and **byte-vs-text** intent
*explicitly* (A-FTN-003) — the peer never infers the CBOR major type from the Fortran
storage kind. Default-kind `character` is a byte string (`c_char`, 1 byte, `LEN` counts
bytes — no char-vs-byte trap for default kind, unlike Tcl); text is UTF-8 bytes. The one
byte-level trap is that `integer(int8)` buffers are **signed** (0xFF reads as -1), so the
codec masks `iand(b, 255)` when treating a byte as an unsigned octet (A-FTN-004).

## What we expect

Corroboration/robustness first — a fresh spec finding is the upside, not the expectation.
The most likely finding surface is the signed-carrier uint64 boundary (does any corpus
vector expose an ambiguity when the only wide integer is signed?) and the shortest-float
ladder under `transfer`-read IEEE bits. Most likely outcome: the spec is tight, the peer
carries the uint tower as an explicit bit pattern and computes f16/shortest exactly, and
the probe closes as corroboration — which is itself the answer (the spec is precise
enough to force even a signed-only substrate to carry the full unsigned numeric tower
with no side-channel).
