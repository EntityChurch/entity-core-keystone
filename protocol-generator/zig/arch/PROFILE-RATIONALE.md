# entity-core-protocol-zig — Profile Rationale

Audit trail for every major S1 profile choice. Zig is **peer #4**, a *distant-idiom*
peer in the OCaml lineage (spec-first, derived from V7 — not ported from the
C#/TS/OCaml profiles) but carried into a **systems language**: no garbage collector,
explicit allocators, error-union error handling, and `comptime`. Where a value
matches a prior peer it is by independent arrival; the idiom seams deliberately
differ. Zig is pre-1.0; a specific settled release is pinned.

## Pinned Zig version: 0.15.1

Zig is pre-1.0 and the language still moves, so the version is pinned exactly and the
whole codec is designed against one release's standard library. **0.15.1**
(~10 months old at authoring) is chosen over the newer
**0.16.0** (a beta): 0.15.1 is a settled point release with a
stable `std.crypto`, comfortably clears the S11 ≥30-day cool-down, and its toolchain
is reproducible. 0.16.0 would also clear the 30-day floor numerically but is the
fresher beta line; the conservative settled release is the right pin for a
conformance-bearing peer. The one caveat to carry forward: **0.15.x is the
"Writergate" release** — `std.Io.Reader`/`std.Io.Writer` were reworked into
non-generic buffered interfaces, and `std.ArrayList` flipped to unmanaged-by-default.
Those are **transport / I/O (S3)** seams; the **codec (S2)** is pure in-memory byte
work and is unaffected. Re-pin deliberately if S3 wants a newer std.Io.

## Codec strategy: native (and lighter than any prior native peer)

The LANDSCAPE tiering would default a young language toward `ffi`, but the same
**A-005 pattern** every prior native peer hit overturns that on principle: a faithful
ECF codec must own the canonical layer — length-then-lex map ordering, shortest-float
including f16 minimization, recursive major-type-6 tag rejection on decode, full
uint64/nint range — regardless of any CBOR library underneath, so a library buys
almost nothing. For Zig the case for native is even stronger than for OCaml, because
**`std.crypto` ships audited Ed25519 + SHA-2 in-tree**: the entire core peer is
`std`-only with **zero third-party packages**. Native is therefore the strictly
lighter path (no package fetches, full `--network=none` builds). `ffi` remains the
documented fallback, and a **hybrid** (native Ed25519 + FFI Ed448) is the likely
shape if/when crypto-agility is in scope. A cheap spike — push the `map_keys` +
`float` vectors through the hand-rolled encoder — runs at S2 start before the full
build, per PHASE-S1-PROFILE.

## CBOR: hand-rolled (no Zig library)

Zig has **no `std` CBOR** and the third-party Zig CBOR packages are immature and
unaudited; none offers ECF's deterministic guarantees (the OCaml `cbor`/`cborl`
survey result, re-confirmed for the Zig ecosystem). ECF needs an explicit float node
(shortest-float f16/f32/f64), length-then-lex map-key ordering on encoded key bytes,
recursive major-type-6 tag rejection on decode (§6.3, the `tag_reject` corpus), and
full uint64/nint range — all of which a general CBOR library either omits or fights.
Hand-rolling (`src/cbor.zig`) is both the faithful and the simpler path. Zig's
**`comptime`** is a genuine asset here: the encoder can dispatch on the Zig value type
/ CBOR major type at compile time with zero runtime reflection, so the "encode any
value" surface stays fast and allocation-light without a reflection layer.

## Crypto: std.crypto.sign.Ed25519 (in std)

Zig's standard library provides **`std.crypto.sign.Ed25519`** with a clean API:
`Ed25519.KeyPair.generate()`, `key_pair.sign(message, null)` (RFC-8032 **deterministic**
by construction — no RNG needed for signing, matching the §7.3 deterministic-signature
expectation), and `Signature.verify(message, public_key)`. It is audited, maintained as
part of the compiler, and pulls **no external dependency**. Pinning is by **toolchain
version** (`zig-0.15.1-std`) — std ships with the compiler, so there is no separate
package version to age-check; the S11 discipline reduces to the single Zig pin.

## Ed448: deferred — native gap (A-ZIG-002)

`std.crypto` provides Ed25519 but **not Ed448**, and Zig has no mature audited pure-Zig
Ed448 nor a BouncyCastle-equivalent (the route C# took). This is the **same gap OCaml
hit** (A-OC-002): the agility-family strategy that worked for C# (a second managed-crypto
provider) does not generalize to Zig either. The ECF/Ed25519 conformance floor is
unaffected; only the higher-bar agility Ed448 vectors are blocked. Deferred with a
documented escalation rather than a silent gap or an unaudited hand-roll. The likely
shape when agility is required: **hybrid** native-Ed25519 + FFI-Ed448 (consume
`libentitycore_codec` for the Ed448 family only) — Zig's C-ABI FFI is first-class
(`@cImport` / `extern`), so this is a natural fit, arguably cleaner in Zig than in any
prior peer.

## Hash: std.crypto.hash.sha2 (in std)

`std.crypto.hash.sha2.Sha256` is the content_hash floor (`Sha256.hash(msg, &digest, {})`);
`Sha384`/`Sha512` are present in the same module for agility hashing. Like Ed25519, it
ships with the compiler — no dependency, pinned by the toolchain version.

## Base58 + varint: hand-rolled

Both are small and absent from `std`. Base58 (Bitcoin alphabet, encode + decode,
`src/base58.zig`) for peer-id; multicodec-style LEB128 varints (`src/varint.zig`) for
the §7.3 format-code / key-type / hash-type framing. Hand-rolling matches the
std-only / dependency-minimization stance.

## Error model: error unions (deliberate divergence from every prior peer)

Zig-native error handling is the **error union** (`!T` over an `error{...}` set),
propagated with `try` and handled with `catch`/`switch` — neither exceptions (C#/TS)
nor a result ADT (OCaml). The language has **no exceptions at all**, and error sets are
compiler-checked for exhaustiveness, which is a real correctness asset for the decode
path: every rejection condition is an enumerated, switch-exhaustive error tag. Codec
failures live in a `CodecError` error set; protocol-status failures map an error tag →
status code (400 `non_canonical_ecf` / 401 / 403) at the module boundary. This is
exactly the idiom seam that *should* differ from prior peers, and it differs from all
three. Critically, **allocation is fallible and explicit** — every alloc site is a
`try` and `error.OutOfMemory` is a first-class error-union member, never a panic.

## Memory: no GC, explicit allocators (the headline Zig seam)

This is the single biggest idiom seam versus C#/TS/OCaml, all of which are GC'd. Zig has
**no garbage collector**; memory is managed via an explicit `std.mem.Allocator` passed
by the caller. Every codec API that allocates takes an `allocator` parameter; the encoder
writes into a caller-provided buffer or an arena and owns no global state; decoded
structures follow a documented caller-frees ownership contract with `defer`/`errdefer`
for deterministic cleanup on every path. **Free-correctness becomes a first-class
conformance concern** that no GC'd peer has: `std.testing.allocator` runs under every
test and fails on any leak, so the conformance harness gets leak-checking for free. This
is where Zig will stress the spec/codec differently than the prior peers — see below.

## Async: threaded (deliberate; not exercised by the codec)

Zig's async story is **in flux**: the pre-0.15 colorless `async`/`await`/`suspend` was
removed and a new `std.Io`-based concurrency model is landing across 0.15/0.16. Rather
than bet the peer on an unsettled language feature, the core peer uses **OS threads**
(`std.Thread`, in std, zero deps): the §4.8/§6.11 inbound-concurrent-with-outbound
requirement is met by one reader thread per connection demuxing EXECUTE_RESPONSE by
`request_id`, with a `std.Thread.Mutex` serializing writes — mirroring the OCaml S3
decision (A-OC-003 revised: stdlib threads, not eio). The codec (S2) is pure and
synchronous, so this is **not exercised yet**; it is validated at S3. Revisit if
handler-initiated outbound (origination) enters scope, and if std.Io's concurrency
model has settled by then. Logged A-ZIG-003.

## Naming: Zig-native PascalCase types / camelCase fns / snake_case values

`PascalCase` for types (Zig types are values, and type-returning functions are
PascalCase too), `camelCase` for functions, `snake_case` for variables/fields/consts
(Zig does **not** use SCREAMING_SNAKE for constants), `PascalCase` for error-set members.
One logical unit per `snake_case.zig` file. Differs from C# PascalCase-members, TS
camelCase, and OCaml snake_case-everything — the correct Zig idiom.

## Build / test / packaging: zig build + in-language tests + build.zig.zon

`zig build` (driven by `build.zig` + `build.zig.zon`) is the universal Zig build system;
no external build tool. Tests are **in-language `test "..." {}` blocks** run by
`zig build test` — no test-framework dependency, honoring the minimization stance
natively (and Zig's runner gives leak-checking via `std.testing.allocator` for free).
Zig has **no central package registry**: packages are fetched by URL + content hash from
`build.zig.zon`, so "publishing" is a git tag that consumers pin by hash — decentralized
and hash-pinned by design, which is itself a supply-chain-friendly property. Identifiers
in `build.zig.zon` are snake_case (`entity_core_protocol_zig`).

## License: Apache-2.0 (S9 default)

Zig itself is MIT and the ecosystem leans MIT but does not mandate one, so the repo's
Apache-2.0 default (explicit patent grant) stands.

## Container: containers/zig-toolchain/Containerfile

fedora:43 base + the **official ziglang.org 0.15.1 tarball, SHA-256-pinned and minisign
signature-verified** against the Zig project's public key, installed to `/opt/zig`.
Authored, NOT built (S1 is research/authoring only; the toolchain comes in S2). Fedora 43
*does* ship a `zig` rpm, but it is **0.16.0 in updates-testing** — to lock the exact
0.15.1 the codec is designed against (and to verify the download cryptographically rather
than take whatever the distro channel currently carries), the Containerfile pins the
official tarball by hash. This is the OCaml pattern (pin the exact compiler version)
adapted to Zig's single-binary distribution. Per the supply-chain memo the toolchain pull
gets an exact pin for reproducibility; the ≥30-day age is satisfied anyway (0.15.1 is ~10
months old).

## Spec version: read v7.72, codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.72` (latest available). The codec uses
the `test-vectors/v0.8.0` corpus because `ENTITY-CBOR-ENCODING.md` and
`ENTITY-NATIVE-TYPE-SYSTEM.md` are byte-identical v7.71→v7.72 (the OCaml SHA-verified
finding; no wire-format change), so the v0.8.0 corpus is valid at v7.72.

## What Zig will likely surface that other peers didn't

Carried forward as S2/S3 watch-items (and the reason peer #4 is worth generating):

1. **Free-correctness as conformance.** GC'd peers (C#/TS/OCaml-with-GC) never have to
   prove they release memory. Zig's `std.testing.allocator` makes a leaked decode
   structure a **test failure**. Expect the decode-path ownership contract — who frees a
   decoded entity, its `included` map, its borrowed byte slices — to need explicit design
   the spec is silent on (it is an impl concern, but Zig forces the question where GC
   hides it). This is the highest-value new probe surface.
2. **Allocation-failure paths.** Every alloc is a `try`; the encoder/decoder must be
   correct under `error.OutOfMemory` at any point (e.g. via a failing test allocator).
   No prior peer exercised partial-allocation rollback. `errdefer` discipline matters.
3. **Integer width is explicit and checked.** Zig has real `u64`/`i64`/`u128` and traps
   on overflow in safe builds — so the §3.2 full `uint`/`nint` range (corpus `int.10` =
   2^63-1, and the [2^63, 2^64-1] band the codec-review-heuristic flags as untested)
   should be handled cleanly with `u64`, with the spec's documented 0..2^64-1 / -1..-2^64
   range mapping directly onto `u64` carriers. Unlike OCaml's 63-bit `int` trap (A-OC-001)
   or TS's BigInt (F7), Zig has native fixed-width ints — but builds in ReleaseSafe so an
   off-by-one in varint/length math traps loudly rather than wrapping silently.
4. **comptime encode dispatch.** The encoder dispatching on type at `comptime` is a
   different shape from runtime reflection (C#) or pattern-matching (OCaml); worth
   capturing as reusable Zig generator guidance.
5. **No-exceptions control flow.** The exhaustive error-set switch on the decode path is a
   stronger compile-time guarantee than any prior peer's error model — every rejection
   condition is enumerated and the compiler enforces the switch is total.
