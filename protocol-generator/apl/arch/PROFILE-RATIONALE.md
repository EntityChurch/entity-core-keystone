# entity-core-protocol-apl — Profile Rationale (S1)

For architecture review. Why the `profile.toml` decisions are what they are, and what
this peer is meant to surface. An alien-substrate probe in the FFI-hybrid COBOL / Rexx /
Tcl / Fortran family, on the **array / value-model** axis.

## The axis: the array as the primitive value (corroboration + generator-stress)

The peer-selection compass says spec-discovery yield is *substrate*-bound and lives on the
wire-touching axes (integer width / float model / crypto availability / string model). APL's
defining paradigm is off-wire: **every value is an array**, there is no scalar/collection
distinction, and the natural codec is base-conversion (`⊤` encode / `⊥` decode) + grade
(`⍋` for length-then-lex key ordering) over vectors, expressed in a language whose pure
functions (dfns) have **no statement-level control flow**. APL's ints and floats are
conventional (int64 + IEEE double), so — honestly — the bet is **corroboration + generator
stress**, not a fresh wire finding: the durable lesson is that "the spec-discovery well is
dry on the current wire surface," and with 15+ peers a novel-only-off-wire language adds
generator robustness, not new findings. The genuine value is (a) proving a from-spec
canonical-CBOR codec falls out of array primitives as cleanly as out of scalar bit-ops, and
(b) stressing the generator against a paradigm with no C-style control flow in its pure form.
A fresh finding is the upside, not the expectation — the profile states this plainly rather
than overclaiming novelty.

## The one wire-touching edge: signed int64 + SILENT double promotion

The single axis where APL does touch the wire is the numeric ceiling, and it is a real —
if corroborating — edge. GNU APL's exact integer is the signed `int64` (`APL_Integer`),
ceiling `2^63-1`. **At/above `2^63` GNU APL silently promotes to IEEE double** (precision
lost above `2^53`) with no error — verified in the toolchain probe: `2*62` prints
`4611686018427387904` (exact), `(2*63)-1` prints `9.223372037E18` (float form). So the ECF
uint64 tower `[2^63, 2^64-1]` **cannot be a native APL scalar at all**. This is *sharper*
than Fortran's signed-only int64: Fortran at least holds the full 64-bit pattern in a
carrier you control with `ishft`/`iand`; APL's overflow *escapes* to a lossy float, so the
native integer cannot even serve as a bit-carrier. The array-model answer is natural: the
high range lives as an **8-element big-endian octet vector** (int64 cells 0..255), built and
consumed by array operations that never form the `>2^63` scalar (`256⊤`/`256⊥` are used only
for values provably `< 2^63`; high-range values ride through as the bytes ⎕FIO recv already
hands back). This is the durable "integer head-form is a fixed-width artifact, not a
protocol property" lesson expressed in the array model — the corroboration is itself the
answer, and the mandatory `{0, 2^63-1, 2^63, 2^64-2, 2^64-1}` self-test is the guard.

## Interpreter: GNU APL 1.9, built from pinned GNU source (NOT dnf)

The key S1 decision. **No APL-family interpreter is in the fedora:43 dnf repos** (verified
2026-07-12 — `apl`, `apl*`, `gnu-apl`, `*/bin/apl`, and J/Dyalog searches all empty across
`fedora` + `updates`). So every candidate needs a source build or bindist. Runners-up
declined: **Dyalog APL** — proprietary, cannot ship in an Apache-2.0 keystone container
(licensing) → excluded outright. **J** — its `cd`/`15!:0` foreign is the *best* FFI (direct
C call, no shim) and it has native extended-precision integers, but it is not in dnf and
ships as an external binary bindist / finicky jsource build (more supply-chain friction than
a clean GNU autotools source build), and it is an ASCII APL-*family* dialect, not APL proper.
**dzaima/APL** and **kap** (both JVM) pull in a whole JVM and are less canonical. **GNU APL**
wins: it is the GNU-project free APL (ISO/IEC 13751 "Extended APL"), builds cleanly from a
SHA-256-pinned GNU source tarball with only dnf build deps (verified — `./configure && make
-j && make install` succeeds and runs on fedora:43 / GCC 15), has a native-function (`⎕FX`)
C++ FFI path (verified — see below), and — a bonus over COBOL/Fortran — provides **native
Berkeley sockets via `⎕FIO`**, so no C net-shim is needed. **S11:** `apl-2.0` exists
(2026-06-24) but is only ~18 days old at authoring → violates the ≥30-day cool-down and is
declined; `1.9` (2024-06-29, ~24 months) is the S11-clean pin and also the safer GCC-15
build (A-APL-004).

## Codec: FFI-hybrid (native array CBOR + C-ABI crypto via a native-fn shim)

- **CBOR value codec hand-rolled in pure APL** — continuing the A-005 pattern (no APL
  package gives canonical ECF). APL's array primitives are a natural codec substrate: `⊤`/`⊥`
  are base-256 encode/decode, `⍋` gives the length-then-lex map-key permutation directly,
  and `⍴ , ↑ ↓ ⊂ ⊃ ⌽` assemble/slice/nest the buffer. The integer tower is the octet-array
  carrier (A-APL-002); the float tower is the one soft spot — APL has native IEEE double but
  **no bit-reinterpret primitive** (no `transfer`), so f64/f32 IEEE bit access is hand-rolled
  arithmetic decomposition (the Rexx-family float path) or an `ec_*` native-fn helper, and
  f16 + the shortest-float ladder are hand-rolled regardless (A-APL-005).
- **Crypto / entity-framing / base58 over the C-ABI via a GNU APL native function** — no
  native audited APL crypto exists, so `libentitycore_codec` is bound from the start. GNU
  APL's native-function facility (`soname ⎕FX funname`) loads a C++ `.so` that calls the
  `ec_*` symbols; apl is linked `-export-dynamic`, so the `.so` resolves apl's own symbols at
  ⎕FX load. base58/peer-id ride `ec_peerid_{parse,format}` because APL has no exact integer
  past `2^63` (A-APL-010, the COBOL/Fortran choice). One wrinkle worth recording (A-APL-009):
  native-fn shims must compile against apl's **source-tree headers** (`Value.hh`/`Cell.hh`/…
  + the configure-generated `config.h`) — `make install` ships only `libapl.h` — so the
  toolchain image **retains** the configured `/opt/apl-1.9` tree as a build-time dependency.

## The value-model probe framing

The array/value-model framing is: APL arrays do **not** carry the CBOR major type, so the
peer's value model is a nested array (`⊂`/`⊃`) with an **explicit** integer major-type
discriminant cell (A-APL-011). int-vs-float (mt0/1 vs mt7) and byte-vs-text (mt2 vs mt3)
intent are represented explicitly and never inferred from APL storage — the same
storage-kind-≠-wire-intent trap Tcl (EIAS) and Fortran (no sum type) hit, seen from the
array end. The absent/"not present" sentinel is a tagged discriminant, not an empty vector
(the empty string is a real wire value). This is where the "does a from-spec codec fall out
of array primitives cleanly?" question actually gets answered in S2.

## Sockets: native ⎕FIO select loop (no C net-shim)

GNU APL provides the Berkeley-socket family natively through `⎕FIO` (`[32]` socket, `[34]`
listen, `[35]` accept, `[36]` connect, `[37]` recv, `[38/39]` send, `[40]` select —
confirmed in the apl-1.9 source `Quad_FIO.cc`). So unlike COBOL/Fortran (which hand-wrote a
C net-shim), the APL peer is a single-threaded `⎕FIO[40]` select loop with **no C net-shim
at all** — and `⎕FIO[37]`/`[38]` are byte-per-cell, matching the array byte model exactly.
§7b store-safety is structural (one image, one thread, no lock); §6.11 outbound-dispatch
reentry is a manual pump (the correlation-map tax the non-actor/non-CSP peers pay). The peer
runs without `--safe` (⎕FIO socket ops are gated behind that flag — A-APL-006).

## Error model, naming, build, test — following research, not preference

- **Error model = status-code + signal**: APL's native event system (`⎕SIGNAL`/`⎕ES` raise,
  `⎕EA`/`⎕EC`/dfn guards catch) is the exception analogue; the C-ABI's int32 `EC_*` codes are
  the protocol status codes. Fallible operations return an `EC_*`-aligned status the caller
  tests; unrecoverable faults `⎕SIGNAL` an event trapped by the dispatch loop — the
  COBOL/Fortran status family with APL's event system on top.
- **Naming = PascalCase functions / camelCase variables / UPPERCASE constants**, dfns for
  pure transforms and tradfns for the stateful loop, the workspace as namespace unit
  (A-APL-007): APL is case-sensitive with glyph primitives and has no single mandate, so the
  profile picks the modern APL-Wiki/Dyalog-influenced convention and records it.
- **Build = make** driving the native-fn g++ compile + the codec CMake build; the `.apl`
  source is interpreted (no compile step, so — unlike Fortran's gfortran static gate — there
  is no compile-time type gate; the hand-rolled harness + conformance corpus are the gate).
- **Test = hand-rolled** (the COBOL/Rexx choice): GNU APL has no dominant xUnit, so
  `test/conformance.apl` is a corpus driver asserting byte-identity, with unit `.apl` suites.
- **License** (A-APL-008): Apache-2.0 peer source per S9, with the honest note that the
  native-fn shim #includes GPLv3 apl headers and combines into a GPLv3 binary at build —
  Apache-2.0 is one-way compatible into GPLv3, so this is fine and needs no relicensing, but
  it is a stronger entanglement than gfortran's runtime-exception and is flagged for the
  operator's awareness.

## What we expect

Corroboration/robustness first — a fresh spec finding is the upside, not the expectation.
The most likely finding surface is the array-native uint64 octet carrier (does any corpus
vector expose an ambiguity when the substrate has *no* exact integer past `2^63`?) and the
hand-rolled float bit path under an array language with no `transfer`. Most likely outcome:
the spec is tight, the peer carries the uint tower as an explicit octet array and computes
the floats exactly, and the probe closes as corroboration — which is itself the answer (the
spec is precise enough to force even an array substrate with no wide exact integer to carry
the full unsigned numeric tower as an explicit byte pattern, with no side-channel).
