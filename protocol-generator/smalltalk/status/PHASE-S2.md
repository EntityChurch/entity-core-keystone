# entity-core-protocol-smalltalk — Phase S2 summary (COMPLETE)

**Phase:** S2 (codec layer)
**Date:** 2026-07-12
**Peer:** #26 — Pharo Smalltalk, the FIRST pure-object / live-image / message-passing peer.
**Status:** COMPLETE — GREEN. **69/69 byte-identical, 0 FAIL** + int-boundary OK + crypto
accept-path OK + SUnit 6/6. No blocking items.

## What was built

Pure-Smalltalk canonical CBOR codec + crypto over the C-ABI via in-process UFFI. Tonel-ish
`src/` packages (each `.st` a live-image doit that installs classes + compiles methods):

- **EntityCore-Codec**
  - `EcValue.st` — the tagged VALUE hierarchy (`EcInt`, `EcFloat`, `EcByteString`,
    `EcTextString`, `EcArray`, `EcMap`+`EcMapEntry`, `EcBool`, `EcNull`, `EcSimple`). THE
    A-ST-000 probe: the codec is a polymorphic `encodeOn:` **double-dispatch** — a value
    knows how to write itself onto an `EcCborWriter`. No procedural type-switch.
  - `EcCborEncoder.st` — `EcCborWriter` (byte sink; minimal-head arithmetic via
    bitShift:/bitAnd:/bitOr:), `EcKeyOrder` (§4.2.1 length-then-lex compare), `EcCborEncoder`
    facade.
  - `EcFloatBits.st` — the shortest-float ladder (f16 leg + f64↔f16/f32 predicates), all over
    NATIVE IEEE bits from `Float>>asIEEE64BitWord` (A-ST-002).
  - `EcCborDecoder.st` — canonical decoder with minimal-head enforcement, **N2 recursive mt6
    tag reject**, map-order re-validation, shortest-float ladder re-validation, full-consume.
  - `EcVarint.st` (LEB128, N1), `EcBase58.st` (bignum single-integer path, A-ST-001),
    `EcPeerId.st` (§1.5 canonical form), `EcContentHash.st` (varint(fmt)‖SHA(ECF{type,data})
    + Ed25519 sign), `EcConformance.st` (per-category production dispatch), `EcErrors.st`
    (the `EntityCoreError` exception tree).
- **EntityCore-Crypto** — `EcLibEntityCoreCodec.st`: the UFFI binding
  (`self ffiCall: #( int32 ec_ed25519_sign(...) ) module: 'libentitycore_codec.so'`), one
  method per `ec_*` symbol + a high-level surface (sha256/384, ed25519 sign/verify/pubkey).
- **EntityCore-Tests** — `EcCodecTest` (SUnit; the bundled xUnit) mirroring the drivers.
- Drivers: `tests/conformance.st` (69-vector), `tests/int-boundary.st`,
  `tests/crypto-accept.st`. `Makefile` (`ffi image test int-boundary crypto-accept sunit
  dist clean`) + `run-s2.sh` (container-bound, `--network=none`) + `load.st`.

## The A-ST-000 verdict (the probe's payoff)

**Idiomatic, not translated.** The recursive canonical encoder reads as native Smalltalk:
each value class has a two-line `encodeOn: aWriter`, container encode is `items do: [ :each |
each encodeOn: aWriter ]`, branching is message-sends (`ifTrue:`, `>=`, `whileTrue:`), the
map sort is `entries asSortedCollection: [ :a :b | (EcKeyOrder compareKey: …) <= 0 ]`. There
is NO giant `case`-on-type method — polymorphism over the value classes IS the dispatch. The
one place a category `if`-ladder appears (`EcConformance>>produceFor:`) is test-harness
plumbing, not the codec. The generator did not fall into "Smalltalk-flavored C."

## Bugs found + fixed in the generated codec (the keystone payoff)

All caught by the corpus / self-tests and fixed in code (never the test):

1. **`EcFloatBits>>f64ToF16:` — unbalanced paren** in the normal-f16 mantissa-fit predicate
   (`(m bitShift: -42) bitShift: 42)` had a stray closer). A parse error; fixed to
   `((m bitShift: -42) bitShift: 42) = m`. Without the fix the f16 leg wouldn't compile.
2. **Decode text-string UTF-8:** `(self take: arg) asString utf8Decoded` — `ByteString` has
   no `#utf8Decoded`; must call `utf8Decoded` on the **ByteArray** directly (A-ST-004 on the
   decode side: convert UTF-8 bytes → String via `ByteArray>>utf8Decoded`, never via
   `asString` first).

No codec-logic bugs surfaced in encode: the double-dispatch encoder was byte-correct on the
first full corpus run once it compiled — a strong signal that the value-class model maps the
spec cleanly.

## Generator-robustness lessons (live-image substrate — carry to S3 + the cohort)

These are the substrate seams the pure-object / live-image model imposes that no prior peer
hit; they are the real S2 discovery on this alien substrate (the wire well being dry):

- **A-ST-010 (NEW, the headline live-image constraint):** a single doit (one `eval` /
  `compiler evaluate:` unit) compiles ENTIRELY before it runs, so it **cannot both install a
  class and reference that class by its global name later in the same doit** ("Undeclared
  variable"). The idiom is to **capture every newly-installed class in a temp** and subclass
  / `compile:` off the temp; cross-*file* references by global name are fine (the class is
  globally registered once the doit completes). This shaped every `src/*.st`. It also means
  the test **driver must run against a SNAPSHOTTED peer image** (where classes are
  compile-time visible), not in the same `eval` that loads them. This is the Smalltalk
  analogue of a forward-declaration / two-pass-load discipline.
- **A-ST-011 (NEW, the Pharo 13 class-builder API):** `Object << #Name package: pkg
  slots: {…}` DNUs — `<<` (binary) yields a `ShiftClassBuilder`, then `package: pkg slots:
  {…}` parses as ONE keyword message `#package:slots:` (absent). The working form is the
  cascade `((Object << #Name) slots: {…}; package: pkg; install)` (separate fluent setters).
  A no-slots class is fine as `(Object << #Name package: pkg) install` (binary binds first).
- **Headless eval quirks (banked):** `--headless` before the image (A-ST-006, confirmed);
  the non-interactive transcript has no `#showln:` — a driver returns a result STRING (eval
  prints the doit's value); extra CLI tokens after the doit are appended to the SOURCE, not
  passed as args, so the corpus path is taken from the `EC_CORPUS` env var, not argv.

## What S3 needs to know

- The peer image is built by `make image` (load `src/*.st` + the SUnit test into a fresh base
  image, snapshot `entity-core.image`, gitignored). S3 peer machinery loads ON TOP of the
  same image; add S3 source files to `load.st`'s `srcFiles` list (the single load-order
  source of truth) and honor A-ST-010 (temp-capture within each doit).
- Crypto is live via UFFI: `EcLibEntityCoreCodec default` gives sha256/384 + ed25519
  sign/verify/pubkey; the `.so` must be on `LD_LIBRARY_PATH` (the `FFI_ENV` in the Makefile).
  Peer-id derivation for `--name` identity uses `ed25519PubkeyFromSeed:` + `EcPeerId format:…`
  with hash_type 0x00 identity-multihash over the raw pubkey (the §1.5 table, baked per the
  profile's `[spec]` note).
- The decoder returns an `EcValue` graph with `EcMap>>entryAt:` / `includesKey:` navigation —
  S3 request/response parsing can build on it. Absent is a distinguished object (A-ST-007),
  not `nil`.
- Error model is the `EntityCoreError` tree; a decode-canonical violation signals an
  `EntityCodecError` subclass caught at the dispatch boundary (S3 maps these to 400
  non_canonical_ecf etc.).

## Exit criteria — MET

69/69 byte-identical + 0 fail; int-boundary + crypto-accept + SUnit all green; codec loads
cleanly into the peer image; no blocking ambiguity items. Ready for S3 (peer machinery).
