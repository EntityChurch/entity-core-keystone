# entity-core-protocol-forth — Profile Rationale (S1)

For architecture review. Why the `profile.toml` decisions are what they are, and what
this peer is meant to surface. Peer #25, the fourth alien-substrate probe (after Tcl
#23 EIAS and Rexx #24 native-decimal), and the first STACK-MACHINE peer.

## The axis: stack-machine / concatenative / typeless (generator stress)

The peer-selection compass (LANDSCAPE) says spec-discovery yield is *substrate*-bound
and lives on the wire-touching axes (integer width / float model / crypto availability
/ string model). After 15+ peers those wire axes are saturated — the well is dry on the
current wire surface. Forth is deliberately NOT a wire-axis probe; LANDSCAPE names it
"stack machine / no types — generator stress." Its value is **generator robustness on a
maximally-unlike control/data model**: every prior peer had named variables, typed
values, and structured records to hang a recursive canonical-CBOR encoder and the §5
capability chain-walk on. Forth removes all three — RPN with a single shared data stack,
no named locals by idiom, no value type, and a "struct" that is nothing but an offset
into an ALLOTed buffer. The question this peer answers: can the recursive codec + the
chain-walk be expressed *idiomatically* on a stack substrate, or does the generator fall
into awkward stack choreography (deep dup/roll/pick, an ad-hoc object convention) that
reads as translated rather than native? Corroboration-first: a fresh spec finding is the
upside, not the expectation.

## Interpreter: gforth 0.7.3 (the only Forth fedora packages)

fedora:43 packages exactly one Forth — **gforth 0.7.3-36.fc43** (GNU Forth). Confirmed
present + versioned at the S1 container build. 0.7.3 is the long-stable release line
(0.7.3 released 2014-09), far over the S11 30-day cool-down. gforth is the right choice
regardless: it bundles everything the peer needs — the ANS core + a floating-point
wordset with real IEEE floats, a libffi-based C interface (`libcc.fs`), and a BSD-socket
wordset (`unix/socket.fs`). No alternative Forth is packaged, so no ambiguity.

## Number model: fixed-width 64-bit cells (the fixed-width-int class)

Confirmed at S1: `1 cells` is 8 bytes — gforth cells are 64-bit on this image. So
uint64 fits ONE unsigned cell and int64 the same cell signed. This places Forth in the
**fixed-width-int class** (Zig u64 / C# ulong / OCaml int63 / C), NOT the bignum class
(Rexx decimal / Python / CL). The profile therefore carries the CBOR integer HEAD FORM
explicitly and a self-test on the `[2^63, 2^64-1]` boundary (A-FT-001) — the signed/
unsigned seam at the top of the u64 range is the classic fixed-width trap, and it must be
handled with unsigned comparisons (`U<`) not signed. ECF's integer tower tops out at
2^64-1 / -2^64, so a single unsigned cell with careful signed/unsigned handling covers
core; the CBOR bignum tags (2/3) are out of core scope.

## Codec: FFI-hybrid (native CBOR incl. native float bits + C-ABI crypto)

- **CBOR hand-rolled in pure Forth** — the ninth peer to confirm no platform lib gives
  canonical ECF (A-005). The byte engine (`C!`/`C@`/`RSHIFT`/`AND`) is native and clean.
  The notable win over Rexx: the FLOAT tower is reachable NATIVELY. gforth's FP wordset
  has a real IEEE f64 type with `DF!`/`SF!` memory words, so `f32`/`f64` encode reads
  the true IEEE-754 bits (confirmed at S1: `DF!` of `1.0e0` yields the `0x3F` MSB). Only
  the f16 half-float leg and the shortest-float ladder stay hand-rolled bit arithmetic —
  and they operate on real float bits, not Rexx's fully-decimal computation. This makes
  Forth's float codec materially easier than Rexx's (the deepest hand-roll in the cohort).
- **Crypto over the C-ABI** — gforth has no crypto, so `libentitycore_codec` is bound
  from the start via gforth's libffi-based C interface (`libcc.fs`: `c-library` /
  `c-function` / `add-lib`). This is the FFI-hybrid shape of COBOL/Tcl/Rexx — but the
  **cleanest binding in that family**. Confirmed at S1: an external `.so` exporting an
  `ec_*`-shaped symbol `(ptr, len, out) -> int32` was bound with `s" ecfake" add-lib`
  and called correctly, in-process. Crucially, unlike Rexx — whose `rxfuncadd` C-extension
  mechanism was non-functional and forced a subprocess co-process daemon with a FIFO
  transport (A-RX-005/011) — gforth's `c-function` is a genuine in-process libffi call
  (libtool+gcc compile a wrapper `.so`, dlopen it). So the crypto surface is a direct
  in-process call; Rexx's entire S3 transport pain (the FIFO-corruption finding A-RX-011,
  the co-process daemon) does NOT arise here.

## Error model: THROW / CATCH

Forth's idiomatic error path is ANS `THROW` / `CATCH`: `n THROW` unwinds to the nearest
`CATCH`, which returns the thrown integer code (0 = clean). gforth's `CATCH` restores the
data, return, and FP stack depths, so a codec reject unwinds cleanly to the public entry
— a proper structured unwind. This is notably better than Rexx, where `SIGNAL ON SYNTAX`
did NOT propagate across a `CALL` (A-RX-010) and the codec had to fall back to an RC flag.
A THROW code carries only an integer, so the reject KIND *is* the code: the profile
reserves a private range (base `-25000`) below the ANS/gforth system codes and maps each
leaf reject-kind to an offset.

## Concurrency + transport: single-thread select, native sockets

gforth is single-threaded for our purposes. The peer is a single-thread select loop (the
COBOL/Rexx pattern) → structural §7b store-safety (one interp, one thread, no lock); the
§6.11 outbound-dispatch reentry is a manual correlation pump (the correlation-map tax the
non-actor/non-CSP peers pay). Sockets come from gforth's `unix/socket.fs` BSD-socket
wordset (confirmed loadable at S1) — a real in-process native socket path. Again a win
over Rexx: NO co-process daemon is needed (Rexx had to fold sockets into a C co-process
because fedora Regina shipped no RxSock, A-RX-008); gforth links the socket syscalls
in-process.

## Idiom: word-prefix modules, offset-word structs, tagged values

There is no namespace/module system in ANS Forth core (gforth has wordlists, but a flat
dictionary loaded via `require` is the common library idiom). Public words are prefixed
with a module tag (`cbor-encode`, `cap-verify-request`) to keep the flat dictionary
readable. A "struct" is a set of named field-offset words over an ALLOTed buffer (`>type`
`>data` `>hash` return offsets) — the idiomatic Forth record. Because a stack cell is
typeless, the codec's value representation MUST tag int-vs-float and bytes-vs-text
EXPLICITLY (a type-tag cell + payload); the peer never infers a CBOR major type from a
cell (A-FT-003, the same explicit-intent discipline as Tcl/Rexx, sharper here since a cell
has literally no type). Strings are `(addr, len)` byte pairs throughout; the length is
already the wire byte count (no char-vs-byte trap — A-FT-004).

## What we expect

Corroboration/robustness first. The most likely finding surface is NOT a wire-spec
ambiguity (the well is dry) but a **generator-robustness** result: whether the stack
substrate can express the recursive encoder + chain-walk idiomatically, or whether it
exposes a place where the language-agnostic phase prompts assume named-variable /
typed-record structure the generator must work around. Most likely outcome: the codec is
expressible cleanly on the stack (offset-word structs + tagged values), the crypto binds
in-process, and the probe closes as corroboration — which is itself the answer (the
generator is robust down to a stack machine with no types). The float tower being native
here (vs Rexx's decimal hand-roll) is a concrete robustness data point: the FFI-hybrid
family spans decimal-only (Rexx, hardest) through native-float-bits (Forth) crypto-gap
substrates, all reaching the same wire.
