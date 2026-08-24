# entity-core-protocol-smalltalk — Phase S1 summary (COMPLETE)

**Phase:** S1 (research + profile authoring)
**Date:** 2026-07-12
**Peer:** #26 — the fifth alien-substrate probe (after Tcl #23 EIAS, Rexx #24
native-decimal, Forth #25 stack-machine), and the FIRST pure-object / live-image /
message-passing peer (Pharo Smalltalk).
**Status:** COMPLETE — profile + rationale + ambiguity log + container authored AND
built; every S1 substrate assumption verified in-container. No blocking items.

## The probe (why this peer exists)

Smalltalk is the **pure-object / live-image / message-passing** generator-stress probe. It
is deliberately NOT a wire-axis probe (the wire-discovery well is dry after 25+ peers); its
value is **generator robustness on a maximally-unlike control/data model**. Prior peers
still had free functions and control-flow *keywords* to hang the recursive codec + the §5
chain-walk on. Smalltalk removes both: no free functions (every op is a method — a
message-send — on an object), no control keywords (`ifTrue:`, `whileTrue:`, `do:` are
messages to Boolean/Block/Collection), no primitive values (all objects). The program is a
persisted memory IMAGE, not an AOT source tree. The question: can the recursive codec +
chain-walk be expressed IDIOMATICALLY as double-dispatch over an object graph, or does it
force procedural "Smalltalk-flavored C"? Corroboration-first — a fresh spec finding is the
upside, not the expectation. See `arch/PROFILE-RATIONALE.md`.

## Done

- **`profile.toml`** — PROMPT-CONSTANTS authored fresh from the V8 spec-data + Pharo
  research. FFI-hybrid: hand-rolled pure-Smalltalk canonical CBOR (the pure-object probe) +
  crypto over the C-ABI via Pharo's in-process UFFI (`ffiCall:module:`). Pharo 13 (image
  build.732, SHA-256-pinned; the stable Linux x86_64 VM, SHA-256-pinned). Arbitrary-precision
  bignum integers → the bignum class (uint64 free). SUnit bundled (unlike the rest of the
  FFI-hybrid cohort). Exceptions error model. Single-event-loop concurrency.
- **`arch/PROFILE-RATIONALE.md`** — one paragraph per major choice (interpreter, number
  model, codec split, error model, concurrency/transport, idiom, expectations).
- **`status/SPEC-AMBIGUITY-LOG.md`** — 10 entries (A-ST-000..009); no blocking items.
- **`containers/pharo-toolchain/Containerfile`** — pinned recipe (SHA-256-verified VM +
  image download; fedora:43 does not package Pharo), BUILT this session
  (`entity-core-keystone/pharo-toolchain:latest`, exit 0). **All substrate probes passed at
  image-build time:**
  - **Headless boot** confirmed: `pharo --headless <image> eval "…"` boots + evaluates from
    argv (the `--headless`-before-image gotcha found + banked, A-ST-006). Image reports
    `Pharo13.1.0SNAPSHOT` (the 13.0/130 dir tracks the 13.x maintenance line; the SHA-256
    pins the exact bytes).
  - **Arbitrary-precision bignum** (A-ST-001): `(2 raisedTo: 64) - 1` exact + classes
    `LargePositiveInteger` → the bignum class, uint64 `[0,2^64-1]` carried FREE, NO
    fixed-width self-test tax (contrast the prior Forth probe's 64-bit cells).
  - **Native IEEE float bits** (A-ST-002): `1.0 asIEEE64BitWord = 16r3FF0000000000000`,
    `1.0 asIEEE32BitWord = 16r3F800000`, `Float fromIEEE64Bit:` inverse round-trips. f32/f64
    are native (like Forth); only the f16 leg + shortest-form ladder stay hand-rolled.
  - **Big-endian uint64 ByteArray assembly** (shift/mask loop: byte0=0xFF, byte7=0xFF).
  - **Block recursion** works (`fact 5 = 120`) — the CBOR encoder is a recursive message-send.
  - **In-process UFFI** (A-ST-005, the KEY differentiator): built an external
    `libecfake.so` exporting an `ec_*`-shaped symbol `(void*,uint64,void*)->int32`, bound it
    via the idiomatic `self ffiCall: #(...) module:` (class via `Object << #Name` → `install`
    → `compile:`), and CALLED it correctly in-process (status 0, xor-fold 0x0F). A genuine
    libffi binding — NOT Rexx's dead rxfuncadd. Crypto binds directly; no subprocess/FIFO/
    co-process daemon.

## Findings / decisions (resolved at S1)

- **A-ST-005 (in-process UFFI) is the KEY crypto-binding differentiator** — same clean
  in-process shape as Forth's libcc c-function. The `ffiCall:module:` surface was verified
  against an external `.so` with the exact `ec_*` `(ptr,len,out)->int32` shape. The entire
  Rexx S3 transport pain (dead rxfuncadd → co-process FIFO daemon → the A-RX-011
  FIFO-corruption finding) does NOT arise. **API gotchas banked for S2:** Pharo 13 creates
  classes via the fluent `Object << #Name` builder (the old
  `subclass:instanceVariableNames:…` is deprecated → DNU), and the builder returns a
  `ShiftClassBuilder` that needs `install` to yield the class; `compile:` then adds the
  method. In a single `eval` doit, all temporaries must be declared at the top and a
  runtime-created class must be captured from the builder result (not looked up by symbol
  mid-doit).
- **A-ST-001 (bignum uint64 free) is the concrete contrast with Forth (#25).** Same
  FFI-hybrid family, same native-float-bits codec, but Smalltalk is bignum (no boundary
  self-test) where Forth was fixed-width 64-bit cells (head-form + [2^63,2^64-1] discipline).
  The family now spans both integer classes.
- **A-ST-004 (char-vs-byte) needs care on the ENCODE path.** Unlike Forth/Tcl's
  byte-oriented strings, Pharo `String` is character-oriented → the peer MUST `utf8Encoded`
  text to a `ByteArray` before taking the wire byte length. Mechanism resolved; carried to S2.
- **A-ST-009 (crypto unified on the C-ABI).** SHA-256 could be native (the pure-Smalltalk
  `Cryptography` package), but the whole crypto surface is unified on the one audited C-ABI
  source (libsodium) for single provenance. S2 adds an accept-path SHA-256 unit test.
- **A-ST-000 (the pure-object generator-stress probe)** is framed, carried into S2/S3: the
  codec is a polymorphic `encodeOn:` double-dispatch over `Ec*Value` classes; the verdict
  (idiomatic vs procedural-translated) is a review judgment at S2/S3.

## Cohort context (FFI-hybrid single-event-loop family)

Smalltalk joins COBOL (#22) / Tcl (#23) / Rexx (#24) / Forth (#25) as an FFI-hybrid,
single-event-loop peer. On the wire-touching axes it corroborates Forth (bignum-vs-fixed is
the one integer-class difference; both have native float bits; both bind crypto in-process,
Forth via libcc, Smalltalk via UFFI). The NOVEL axis is off-wire (pure-object / live-image /
message-passing control+data model), so per the peer-selection compass this adds **generator
robustness**, not a fresh wire finding — the expected and intended payoff. One material EASE
over the rest of the family: SUnit (the original xUnit) is bundled in the base image, so the
conformance harness is first-class `TestCase` classes at zero dependency cost (COBOL/Rexx/
Tcl/Forth all hand-rolled a harness).

## Exit criteria — MET

Profile authored (PROMPT-CONSTANTS complete, no TBD blocking S2 — only publish URLs
TBD-on-first-publish, non-blocking as across the cohort); container built and every
substrate primitive the codec depends on verified in-container (headless boot, bignum
uint64, native IEEE float bits, BE ByteArray assembly, block recursion, in-process UFFI
ec_*-shape); rationale + ambiguity log written; no blocking-severity items. **Next: S2** —
the hand-rolled canonical CBOR codec (pure Smalltalk, native float bits, `encodeOn:`
double-dispatch over `Ec*Value` classes), base58/varint/peer_id, and the UFFI crypto binding
(`EcLibEntityCoreCodec`) to libentitycore_codec; target the full v0.8.0 corpus 69/69 (or the
FFI differential). Time spent: ~1 session.
