# entity-core-protocol-julia — Profile Rationale (S1)

For architecture review. Why the `profile.toml` decisions are what they are, and what
this peer is meant to surface.

## Honest framing (ADR-0012): what this peer is for

Julia is a **Tier-3 corroboration / generator-robustness** peer, **not** a spec-discovery
probe. The alien-substrate discovery well is dry on the current wire surface — the
wire-touching axes (integer width, float model, crypto availability, string model) are
saturated by the existing cohort. A Julia peer passing the author's vectors is
**cohort-consistent, not independent convergence** (it shares the generation lineage and
validates against one author's oracle). A fresh spec finding is **upside, not the
expectation.** Julia earns its slot by (a) corroborating the settled cohort results on a
fresh substrate and (b) stressing generator robustness on Julia's genuinely novel *idiom*
axes — none of which is wire-novel enough to expect a finding:

- **Multiple dispatch** as the codec-dispatch mechanism (a fresh dispatch shape).
- **Native `UInt64` + `BigInt`** — a hybrid numeric model (fixed-width wire carrier that
  is *exact* for the CBOR uint64 tower, plus arbitrary precision for values).
- **UTF-8-native `String`** — the char-vs-byte length trap, naturally avoided.
- **Task/coroutine concurrency** over libuv — a fourth event-loop-class §7b substrate.

## Codec: NATIVE (not the keystone C-ABI FFI-hybrid)

`codec_strategy = "native"`. The decision hinges on the crypto floor and the A-005 CBOR
pattern:

- **CBOR — hand-rolled, pure Julia.** No Julia CBOR library gives canonical ECF. `CBOR.jl`
  exists but is a round-trip serializer with none of the ECF guarantees (shortest-float
  incl. f16, length-then-lexicographic map-key order, recursive major-type-6 tag reject,
  raw byte-string fidelity, full uint64/nint range). This is the A-005 finding every
  native peer hit (OCaml/C#/TS/Zig, now 8+): a faithful codec must own the canonical layer
  regardless of any underlying library, so a library buys almost nothing. Hand-rolling is
  both the faithful and the simpler path. `CBOR.jl` is declined (A-JULIA-002).
- **SHA-256/384 — native.** Julia's `SHA` **stdlib** (ships with the language) provides
  `sha256`/`sha2_384`. No supply-chain cost, no external dep.
- **Ed25519 — system libsodium via `ccall`.** Julia has no native Ed25519, but libsodium
  (the audited reference crypto library) is present in the toolchain image and Julia's
  `ccall` is first-class C interop used throughout Base itself. Binding `crypto_sign_*`
  directly keeps the peer self-contained and **Pkg-fetch-free** (the container builds
  `--network=none`). This is the **native-audited-lib crypto tier** from the AGENTS.md
  spectrum (the Elixir OTP `:crypto` / Haskell `crypton` class — both are C under the
  hood) — explicitly **NOT** the keystone C-ABI FFI-hybrid that Tcl/COBOL/Fortran use for
  *all* crypto. Sodium.jl (the higher-level wrapper) is declined for the network-fetch +
  thin-need reasons (A-JULIA-003).
- **base58 + varint — hand-rolled.** `BigInt` (GMP) makes base-256↔base-58 long division
  trivial; the LEB128 multikey varint is inline bit ops.

Net: the shipped default (floor) peer is **native + self-contained** — Julia stdlib +
system libsodium, no `libentitycore_codec`, no registered packages. `ffi` remains the
documented fallback if the S2 canonical-CBOR spike (push the `map_keys` + `float`
vectors through the hand-rolled encoder) ever fails; it is not expected to.

## Crypto agility (Ed448): opt-in hybrid-FFI

libsodium provides **Ed25519 only** — it has **no Ed448**. So the crypto-agility higher
bar is an **opt-in hybrid-FFI sub-package** over the C-ABI (`libentitycore_codec`
`ec_ed448_*` + `ec_sha384`), scoped so the shipped Ed25519+SHA floor peer's crypto surface
stays native + self-contained. This is exactly the **Ed448-only-FFI** shape OCaml/Zig/Swift
reached (native floor + FFI-Ed448), reached here for the same reason (the audited native
library covers Ed25519+SHA but not the Ed448 family). Deferred until an adopter needs
agility; the floor ships first (A-JULIA-004).

## Numeric model: native UInt64 (exact) + BigInt (free) — a hybrid on the head-form axis

This is Julia's most interesting corroboration point. Julia has a **full native integer
tower** (`Int8..Int64`, `UInt8..UInt64`, `Int128`) **and** GMP-backed `BigInt`:

- The **wire head-form carrier is `UInt64`**, which *exactly* covers the CBOR mt0 argument
  range `[0, 2^64-1]`. Unlike Fortran (no unsigned type → a signed bit-carrier trap) or C#
  (`ulong` = the same UInt64), Julia has a native, natural, exact-width unsigned carrier
  for the whole uint64 tower with **no** representation gymnastics.
- Because that carrier is **fixed-width**, the durable lesson applies: the
  `[2^63, 2^64-1]` head-form self-test is **MANDATORY** (Julia is the C# `ulong` / Zig
  `u64` **fixed-width class** on the wire, not the free-range bignum class).
- Separately, `BigInt` carries any *reconstructed* application-level integer value
  overflow-free. The CBOR mt1 boundary value `-2^64` exceeds `Int64`; application
  reconstruction widens to `Int128`/`BigInt` as needed, but the **wire codec stays on
  `UInt64`** working with the raw argument — no widening, no precision risk on the wire.

So Julia is a **hybrid**: fixed-width on the wire (self-test required), bignum-capable for
values. It corroborates the C#/Zig fixed-width result rather than breaking new ground on
the numeric axis. Floats are native IEEE-754 (`Float64`/`Float32`, and `Float16` is a
*native* type — the f16 leg needs no hand-rolled half-float encode, only the shortest-float
ladder decision is hand-rolled per Rule 4).

## Multiple dispatch: a fresh codec-dispatch shape, the opposite of the Tcl EIAS problem

Julia's headline idiom is **multiple dispatch** (the CLOS/Smalltalk double-dispatch
family). `encode`/`decode` are generic functions dispatched on the Julia value *type*:
`Vector{UInt8}` → mt2 (byte string), `String` → mt3 (text string), `Integer` → mt0/mt1,
`AbstractFloat` → mt7. This makes CBOR major-type selection **natural and type-driven** —
the *opposite* of the Tcl EIAS probe (where an untyped value forced an explicit tag). The
corroboration is that the spec's type distinctions are carriable by a dispatch-typed value
model **with no side-channel**. The one thing to verify at S2 (A-JULIA-006): no value
satisfies two dispatch branches — `String` is not an `AbstractVector`, a `UInt8` vector is
not a `String`, so byte-vs-text does not shimmer.

## String model: UTF-8 native — the char-vs-byte trap, avoided by construction

Julia `String` is **UTF-8 internally** and immutable. CBOR text-string length is the
**byte** length of the UTF-8 encoding — so the codec uses `ncodeunits(s)` / `codeunits(s)`
/ `sizeof(s)` (all byte-oriented), **never** `length(s)`, which counts code points. This is
the Tcl A-TCL-002 char-vs-byte-length trap, naturally avoided here because UTF-8 *is* the
native storage (no `encoding convertto` step). Byte strings are `Vector{UInt8}`. Logged as
A-JULIA-007 so the generator carries the discipline explicitly rather than by luck.

## Concurrency: single-threaded Task scheduler → structural §7b safety

Julia's concurrency is **Tasks** (coroutines / green threads) multiplexed over a **libuv**
event loop — the same reactor Node/Dart use. The core peer runs the **single-threaded Task
scheduler** (default 1 OS thread): Tasks yield only at I/O/await points, so §7b store-safety
is **structural** — the store is a plain `Dict` mutated only between yields on one thread,
no lock, no race. This is the actor/CSP-class "free store-safety" reached via a cooperative
scheduler — the **PHP/Dart/Tcl event-loop result corroborated on a fourth substrate**. §6.11
handler-initiated outbound reentry is a plain `Channel`/`Condition` handoff keyed by
`request_id` (no cross-thread demux, no correlation-map tax). Julia's real multithreading
(`Threads.@spawn`, `JULIA_NUM_THREADS>1`) — a genuine shared-memory model needing locks — is
noted as the alternative substrate (A-JULIA-005), out of scope for `--profile core`.

## Error model, naming, build, test — following research, not preference

- **Error model = exceptions.** Julia's dominant idiom: custom `<: Exception` structs
  thrown and caught by `try/catch` + `isa` (the C#/TS/Java/Tcl family). The codec surface
  throws on canonicality violations; in-band absent/not-found returns **`nothing`** (the
  `Nothing` singleton) — a clean sentinel that cannot collide with an empty `String` or
  empty `Vector{UInt8}` (no Tcl empty-string trap).
- **Naming = Julia Base/community style:** `UpperCamelCase` modules + types, `lowercase`
  (run-together) functions, `!` suffix on in-place mutators, `UPPER_SNAKE` constants. Not a
  translation — the language's own convention.
- **Build = `Pkg` + `Project.toml`.** Julia is JIT-compiled (LLVM); "build" is precompile
  + load. The core peer pulls **zero registered packages** (SHA/Sockets/Test/Pkg are
  bundled stdlibs; Ed25519 is system libsodium via ccall), so the container builds
  `--network=none`.
- **Test = `Test` stdlib** (`@test`/`@testset`), bundled with Julia — the idiomatic,
  supply-chain-free choice (the Tcl tcltest / Zig zig-test reasoning). The conformance
  probe is a Test suite that walks the pinned v0.8.0 corpus and asserts byte-identity.

## Container

`containers/julia-toolchain/Containerfile` — `fedora:43` base, the **official julialang.org
tarball pinned by exact version + sha256** (the Zig-toolchain pattern: don't take whatever
`dnf` currently carries; pin and verify), plus system `libsodium` for the Ed25519 ccall.
The exact patch + tarball sha256 are confirmed at S2 against julialang.org checksums
(A-JULIA-001) — the S1 sentinel fails the build closed until filled, exactly as the Zig
image does.

## What we expect

Corroboration/robustness first — a fresh spec finding is the upside, not the expectation.
The most likely outcome: the multiple-dispatch codec carries every CBOR major-type
distinction with no side-channel, the `UInt64` head-form + `[2^63,2^64-1]` self-test
corroborate the C#/Zig fixed-width result, the UTF-8-native string model avoids the
char-vs-byte trap by construction, and the single-threaded Task scheduler corroborates the
event-loop §7b/§6.11 result — the peer closes as clean corroboration, which is itself the
answer (the spec is precise enough that a fresh, richly-typed substrate carries the wire
faithfully with no new ambiguity).
