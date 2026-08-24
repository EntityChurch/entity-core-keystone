# entity-core-protocol-smalltalk — Profile Rationale (S1)

For architecture review. Why the `profile.toml` decisions are what they are, and what
this peer is meant to surface. Peer #26, the fifth alien-substrate probe (after Tcl #23
EIAS, Rexx #24 native-decimal, Forth #25 stack-machine), and the first PURE-OBJECT /
LIVE-IMAGE / MESSAGE-PASSING peer.

## The axis: pure-object / live-image / message-passing (generator stress)

The peer-selection compass (LANDSCAPE) says spec-discovery yield is *substrate*-bound and
lives on the wire-touching axes (integer width / float model / crypto availability /
string model). After 25+ peers those wire axes are saturated — the well is dry on the
current wire surface. Smalltalk is deliberately NOT a wire-axis probe; its value is
**generator robustness on a maximally-unlike control/data model**. Prior peers ranged
over procedural (COBOL/Rexx), stack (Forth), string (Tcl), typed and functional models —
but every one still had free functions and control-flow *keywords* to hang the recursive
codec and the §5 capability chain-walk on. Smalltalk removes both: there are no free
functions (every operation is a method — a message-send — on an object), no control-flow
keywords (`ifTrue:`, `whileTrue:`, `do:`, `ifNil:` are all messages to Boolean/Block/
Collection), and no primitive values (an Integer, a Character, a Boolean, a Class are all
first-class objects). The program is a persisted memory IMAGE — a live object graph — not
an AOT-compiled source tree. The question this peer answers: can the recursive codec + the
chain-walk be expressed *idiomatically* as message-sends over an object graph — a value as
a tagged `EcValue` object, the codec as a polymorphic `encodeOn:` / double-dispatch per
value class — or does the generator fall into procedural "Smalltalk-flavored C" (a giant
type-switch method, primitive obsession) that reads as translated rather than native?
Corroboration-first: a fresh spec finding is the upside, not the expectation.

## Interpreter: Pharo 13 (SHA-256-pinned VM + image, not a floating alias)

fedora:43 does NOT package Pharo, so — unlike the gforth/Regina cohort where the distro
pins the toolchain — the VM and image are downloaded from files.pharo.org and **verified by
SHA-256** in the Containerfile (a floating `stable`/`latest` alias is never trusted for the
pin). Pinned: the **Pharo 13.0 image build.732 (sha e84a2d15c7)** dated 2026-04-21 — well
over the S11 30-day supply-chain cool-down at authoring (2026-07-12) — and the **Pharo-13
stable Linux x86_64 VM** artifact (a fixed build, last-modified 2025-11-17, 8 months old;
not a rolling nightly). Pharo 13.0.0 released 2025-05-24; 13 is the current stable major.
(Note: the build.732 image self-reports `Pharo13.1.0SNAPSHOT` — the 13.0 directory tracks
the 13.x maintenance line; the SHA-256 pins the exact bytes regardless of the display
string.) Confirmed at the S1 container build: the VM boots HEADLESS via `pharo --headless
<image> eval "…"` and every substrate primitive the codec depends on was verified in-image.

**Headless gotcha (banked):** the `--headless` flag must precede the image path. Without it
the Pharo 13 launcher tries to open the Morphic World and FATALs with "Invalid window
handle" under a no-display container. This bit the first S1 build; the Containerfile now
launches `pharo --headless …` throughout and S2/S3/S4 must do the same.

## Number model: arbitrary-precision bignums (the bignum class — uint64 FREE)

Confirmed at S1: `(2 raisedTo: 64) - 1` is exact and its class is `LargePositiveInteger` —
`SmallInteger` promotes to `LargePositiveInteger` transparently. So the full uint64 range
`[0, 2^64-1]` is carried **FREE**. This places Smalltalk in the **bignum class**
(Rexx-decimal / Python / Common Lisp / Elixir / Haskell), NOT the fixed-width-int class
(Forth / Zig / C# / OCaml). The CBOR integer head form is still emitted explicitly
(minimal-argument encoding per the spec), but there is **no** `[2^63, 2^64-1]` signed/
unsigned boundary hazard and **no** fixed-width self-test tax (A-ST-001) — a concrete
contrast with Forth, the immediately-prior probe, whose 64-bit cells forced exactly that
boundary discipline.

## Codec: FFI-hybrid (native CBOR incl. native float bits + C-ABI crypto)

- **CBOR hand-rolled in pure Smalltalk** — the tenth peer to confirm no platform lib gives
  canonical ECF (A-005). The byte engine (`ByteArray` + `bitShift:` / `bitAnd:` / `bitOr:`
  / `bitXor:`) is native and clean; big-endian assembly is a shift/mask loop into a
  `ByteArray` (confirmed at S1: all-ones uint64 → byte0=0xFF, byte7=0xFF). The notable win
  (shared with Forth, unlike Rexx): the FLOAT tower is reachable NATIVELY. Pharo's `Float`
  has `asIEEE64BitWord` / `asIEEE32BitWord` (returning the raw IEEE-754 bits as an Integer)
  and the inverses `Float fromIEEE64Bit:` / `fromIEEE32Bit:` (confirmed at S1:
  `1.0 asIEEE64BitWord = 16r3FF0000000000000`, `1.0 asIEEE32BitWord = 16r3F800000`, inverse
  round-trips). So f32/f64 encode/decode read the true IEEE bits; only the f16 half-float
  leg and the shortest-float ladder stay hand-rolled bit arithmetic — from real float bits,
  not Rexx's all-decimal computation (A-ST-002). This makes Smalltalk's float codec as
  tractable as Forth's, materially easier than Rexx's (the deepest hand-roll in the cohort).
- **Crypto over the C-ABI** — the Pharo base image has **no native audited Ed25519**. The
  pure-Smalltalk `Cryptography` package ships SHA-256 / DSA / MD5, but no audited Ed25519;
  the community routes Ed25519 through libsodium via FFI (Crypto-Nacl). So `libentitycore_
  codec` is bound from the start via Pharo's **Unified FFI (UFFI)**. UFFI is a genuine
  in-process libffi binding — the VM dlopen's the `.so` and marshals call-outs; the
  idiomatic surface is a method `^ self ffiCall: #( int32 ec_ed25519_sign(void* priv,
  void* msg, uint64 msg_len, void* out) ) module: LibName`. Confirmed at S1: an external
  `libecfake.so` exporting an `ec_*`-shaped symbol `(void*, uint64, void*) -> int32` was
  bound with exactly this `ffiCall:module:` mechanism and called correctly in-process
  (status 0, correct xor-fold result). This is the FFI-hybrid shape of COBOL/Tcl/Rexx/Forth
  — and, like Forth's libcc, one of the **cleanest bindings in the family**: a direct
  in-process call, NO subprocess / FIFO / co-process daemon (Rexx's whole S3 transport pain
  around the dead `rxfuncadd` / the FIFO-corruption finding A-RX-011 does NOT arise). Even
  though SHA-256 could be native, the whole crypto surface (SHA-256/384, Ed25519, Ed448) is
  unified on the one audited C-ABI source (libsodium, statically linked into the `.so`).

## Error model: exceptions (Error subclasses + on:do:)

Smalltalk's idiomatic error path is exceptions: an `Error` subclass is raised with
`signal:` and caught with `[ … ] on: SomeError do: [ :ex | … ]` — a clean block-based
structured unwind that restores the stack. Reject-KINDs map to a namespaced `Error`
subclass hierarchy under a base `EntityCoreError`; unlike Forth's integer THROW code, a
Smalltalk exception is a first-class object carrying a class + message + arbitrary payload,
so the reject KIND is the exception's class (idiomatic class-per-kind). Absent / "not found"
is an in-band `EntityAbsent` singleton object — deliberately NOT `nil` and NOT the empty
`ByteArray`: the empty byte/text string is a legitimate wire value (A-ST-007), and `nil` is
itself an object that would collide with a legitimately-nil field, so absent must be a
distinguished object (the same discipline the whole cohort applies, expressed here in the
pure-object idiom).

## Concurrency + transport: single-event-loop on the VM's single native thread

The Pharo VM runs ALL green processes on ONE native OS thread (a cooperative scheduler with
priority preemption); there is no true shared-memory parallelism — only one green process
runs at a time. The peer is a single-event-loop over one green process (the COBOL/Rexx/Forth
pattern) → **structural §7b store-safety**: the store is touched from a single green process
on a single native thread, so there is no true concurrent access and no lock is needed. The
§6.11 outbound-dispatch reentry is a manual correlation pump (the correlation-map tax the
non-actor/non-CSP peers pay): the handler sends, then re-enters a bounded receive loop to
await the correlated reply by `request_id`, keyed in a `Dictionary` in the one image.
Sockets come from Pharo's native `Socket` class (non-blocking BSD sockets over the VM's
SocketPlugin, with readiness-testing) — a real in-process native socket path; NO co-process
daemon (contrast Rexx A-RX-008). Note the framing distinction from Forth: Forth's
store-safety was structural because the *OS process* was single-threaded; Pharo's is
structural because the *VM* schedules all green processes on one native thread — same
store-safety outcome, a different mechanism, worth stating precisely (ADR-0012 honesty).

## Idiom: Ec-prefixed classes, message-send control flow, class-polymorphic dispatch

Smalltalk naming is strongly conventional: classes PascalCase, method selectors camelCase
keyword messages (`encodeValue:on:`, `verifyRequest:against:`) that read as prose, ivars/
temps/args camelCase. There are no top-level constants (a "constant" is a class-side
accessor method — `EntityLimits maxChainDepth` returns 64) and no namespace keyword; code is
organized by class and by Tonel package. Class names are globally unique in a shared image,
so the profile prefixes classes `Ec` (`EcCborEncoder`, `EcEntity`, `EcCapability`) to keep
the global namespace clean — the Smalltalk analogue of Forth's word-prefix (A-ST-008).
Because dispatch is by object class, int-vs-float and bytes-vs-text intent lives in the
value object's CLASS (`EcInt` vs `EcFloat`, `EcByteString` vs `EcTextString`) and the codec
double-dispatches on it; the peer NEVER infers a CBOR major type from a raw Smalltalk value
(A-ST-003, the same explicit-intent discipline as Tcl/Rexx/Forth, expressed here as class
polymorphism). Strings: a `ByteArray` is the wire unit; text is a UTF-8-aware `String` whose
`utf8Encoded`/`asByteArray` gives the byte count — take the byte length, never the character
count (A-ST-004). One material EASE over the rest of the FFI-hybrid cohort: **SUnit** (the
original xUnit — Smalltalk is where the pattern was born) ships in the base image, so unlike
COBOL/Rexx/Tcl/Forth (all of which hand-rolled a test harness), the conformance harness is
first-class `TestCase` classes at zero dependency cost.

## What we expect

Corroboration/robustness first. The most likely finding surface is NOT a wire-spec
ambiguity (the well is dry) but a **generator-robustness** result: whether the pure-object /
message-passing substrate can express the recursive encoder + chain-walk as idiomatic
double-dispatch over an object graph, or whether it exposes a place where the
language-agnostic phase prompts assume free-function / control-keyword structure the
generator must work around. Most likely outcome: the codec is expressible cleanly as a
polymorphic `encodeOn:` visitor over `Ec*Value` classes, the crypto binds in-process via
UFFI, SUnit carries the conformance harness, and the probe closes as corroboration — which
is itself the answer (the generator is robust down to a pure-object, keyword-free, live-image
model). Smalltalk lands in the FFI-hybrid family alongside Forth on the number/float axes
(bignum ints, native float bits) but at the opposite end of the paradigm axis (pure-OO vs
stack-machine), which is the point: the family now spans stack-machine → pure-object with
the same wire and the same FFI crypto floor.
