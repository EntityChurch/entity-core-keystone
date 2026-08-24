# entity-core-protocol-crystal — Profile Rationale

The audit trail for `profile.toml`. One section per major choice. Authored at S1
(2026-07-12) from the pinned **v0.8.0 (V8)** spec-data + Crystal-ecosystem
research (with primary-source citations captured in the S1 research pass).

## Why build a Crystal peer at all (honest framing)

The deliberate alien-substrate spec-discovery sweep is **closed** — the
spec-discovery well is dry on the current wire surface (28-peer cohort; the
productive axes — crypto-availability, integer-model, memory-model,
string/encoding-model — are saturated). Crystal is therefore a **corroboration /
generator-robustness** peer, not a spec-discovery one. Its specific value:

- **Ruby-overfit check.** Crystal reads like Ruby (blocks, `PascalCase` types,
  `snake_case` methods, exceptions, a `spec`-style test framework) but is a
  **compiled, statically-typed, fixed-width-integer, LLVM-backed** language with
  **CSP fibers** instead of MRI threads+GVL. If `/entity-rosetta` were overfit to
  the Ruby peer's templates it would mis-model three wire/runtime-touching axes:
  the **integer model** (Ruby bignum → no head-form trap; Crystal fixed-width
  `UInt64` → the trap is real), the **crypto route** (Ruby stdlib `openssl` has
  Ed25519+Ed448; Crystal stdlib `openssl` has **no PKey at all**), and the
  **concurrency model** (GVL OS-threads vs single-thread CSP fibers). This peer
  proves the generator derives each from the profile, not from a Ruby template.

Per ADR-0012, a Crystal peer passing the author's vectors is **cohort-consistent,
not independent convergence** — stated plainly in the eventual CONFORMANCE-MATRIX
row and the S4 report.

## Toolchain — `crystallang/crystal:1.20.2`

Latest stable is 1.20.3 (2026-07-02) but that is ~10 days old — inside the S11
30-day cool-down. **1.20.2 (2026-05-15, ~58 days)** is the newest release that
clears the floor. The official vendor image `crystallang/crystal` (the core
team's Docker org) is a reviewed-vendor channel, so — as with the ruby-toolchain
image — the strict 30-day *registry* cool-down relaxes to "pin exactly," which a
patch-pinned tag does. `nightly`/`latest` are non-reproducible and rejected.
LLVM version-sensitivity is the known build gotcha; the vendor image already
carries a compatible LLVM, so we do not manage it ourselves.

## Codec strategy — NATIVE (hand-rolled canonical CBOR)

`strategy = "native"`. This is where the Ruby-overfit check pays off: the **same
ECF canonical codec Ruby hand-rolls, re-derived on a compiled + statically-typed
+ fixed-width substrate**. The A-005 "no platform CBOR lib suffices" pattern holds
a 29th time — no Crystal shard gives ECF's guarantees:

- `arestifo/crystal-cbor` (the de-facto pure-Crystal shard, v1.0.0, dormant ~3yr)
  targets **RFC 7049**: it gets the integer head-form right (the one free win) but
  emits floats by static type with **no shortest-float ladder and no float16
  (0xf9)**, iterates a `Hash` in **insertion order** (not length-then-lex), and on
  decode **silently *skips* major-type-6 tags** (`ignore_tag = true`) — the exact
  opposite of ECF's recursive tag-**reject**.
- `woodruffw/cbor.cr` (libcbor C binding) is abandoned (2020).

So the canonical layer (shortest-float incl. f16, recursive tag-6 reject,
length-then-lex map-key sort on **encoded** key bytes, full uint64/nint range,
raw-byte `data` fidelity) is hand-rolled regardless — faithful *and* simpler than
bending a library that fights length-first ordering. Per PHASE-S1, the
`map_keys` + `float` vectors get a spike at S2 start before the full build.

## Integer model — fixed-width `UInt64` (the overfit trap)

Crystal's integers are **fixed-width LLVM machine ints** (`Int8..128` /
`UInt8..128`), *not* Ruby's arbitrary-precision `Integer`. `UInt64` natively
covers the full `[0, 2^64-1]`, so the CBOR uint64 head-form carrier is a plain
`UInt64` — but arithmetic **overflow raises `OverflowError` by default** (wrapping
requires the explicit `&+`/`&*` operators). Consequence: Crystal is in the
**fixed-width int class** and MUST carry the CBOR integer head-form + the
`[2^63, 2^64-1]` self-test (like Zig/Forth/Fortran/OCaml/C#) — the Ruby peer's
`native_bignum = true` (no head-form trap) does **not** transfer. GMP-backed
`BigInt` is available via `require "big"` for any `>=2^64` arithmetic arm, but is
not needed for the head-form itself.

## Crypto — native SHA + direct libsodium Ed25519; Ed448 deferred

Crystal's stdlib `OpenSSL` exposes **no PKey/EVP surface** — no Ed25519 (verified
absent against the 1.20.x API index and `src/openssl.cr`; long-open
crystal-lang#3941; web snippets claiming `OpenSSL::PKey::Ed25519` are
hallucinations). SHA hashing *is* native: `Digest::SHA256`/`Digest::SHA512` are
pure-Crystal stdlib classes (zero dep) — used for the content-hash floor. There
is **no native `Digest::SHA384`**; the agility hash family's SHA-384 comes from
`OpenSSL::Digest.new("SHA384")` (OpenSSL-backed, by-name).

For **Ed25519** the audited, dependency-lean route is a **direct in-process
libsodium C binding** (`lib LibSodium` + `fun crypto_sign_seed_keypair /
crypto_sign_detached / crypto_sign_verify_detached`, under `@[Link("sodium")]`).
This is the Ada/C/C++/PHP **"native — libsodium (C binding)"** row reached through
Crystal's `lib`/`fun` FFI (in-process, no daemon). It is preferred over the
shard options — `didactic-drunk/sodium.cr` (stale 2021), `konovod/monocypher.cr`
(its default `crypto_eddsa_sign` is a BLAKE2b variant — non-RFC-8032; would need
its `crypto_ed25519_sign`), and pure-Crystal `spider-gazelle/ed25519` (small,
unaudited) — because a direct libsodium binding is audited, is a system lib (not a
shard dep to pin/track), and keeps the shipped peer self-contained.

**Ed448** (agility higher bar): **deferred**. libsodium has no Ed448 (same gap as
C/C++/Ada/PHP/Zig). The documented future path is **hybrid-FFI via
`libentitycore_codec`** (`ec_ed448_*`) as an opt-in sub-library; it does not
affect the Ed25519/ECF conformance floor.

## Error model — exceptions (with nilable-union `?` for ordinary absence)

Exceptions (`raise`/`rescue`/`ensure`) are the idiomatic Crystal fallible surface
— same idiom *family* as the Ruby peer, so the `EntityCore::Error` hierarchy
mirrors Ruby's **shape** while being compiled and statically type-checked.
Crystal's stdlib has **no `Result`/`Either`**; the non-exception convention is
nilable-union `?`-variant methods (`[]?` → `nil`), used for ordinary "not found"
rather than fabricating an error. Decode faults raise `CodecError` subclasses;
the dispatch boundary rescue-maps protocol faults to §5.2a/§6.12 status codes.

## Concurrency — CSP fibers (the divergence from Ruby's GVL threads)

Crystal's model is **CSP: fibers over channels**, scheduled by default on a
**single OS thread** (concurrency, not parallelism — no GIL construct; the
scheduler simply doesn't preempt between yield points). Blocking socket IO yields
the fiber via the event loop, so a **fiber-per-connection** peer is genuinely
concurrent for the IO-bound §4.8/§4.9 workload — adequate for the §7b gate.
Multithreading is still **opt-in/preview** as of 1.20 (`-Dpreview_mt`; the M:N
Execution Contexts model — `Fiber::ExecutionContext::{Concurrent,Parallel}` — is
"final preview" in 1.20 with default-on *targeted* for 1.21, not yet landed), so
it is **not used at core** and is noted only as the parallelism escape hatch.
Store-safety: fiber-safe between yield points under the single-thread default;
explicit `Mutex` is required under `-Dpreview_mt` (raw-thread class — manual §7b,
like Zig/CL). The §6.11 reentrant demux is a pending `{request_id => Channel}` map
(the CSP shape).

## Build / packaging / testing

- **Build/deps:** `shards` (Crystal's package+build tool), `shard.yml` manifest +
  committed `shard.lock`. The core peer has **zero shard runtime deps** (libsodium
  is a system lib, not a shard; CBOR/base58/varint/canonical-layer hand-rolled).
- **Testing:** stdlib `spec` (`crystal spec`) — zero added dependency (the
  Ruby/Minitest, Zig/zig-test, TS/node:test stance).
- **Publishing:** Crystal has **no central package host**; shards resolve from git
  repos by `v`-prefixed semver tags. "Publishing" = a git tag. The shards id drops
  the redundant `_crystal` suffix (snake_case `entity_core_protocol`), mirroring
  the Ruby/Elixir reasoning; the keystone peer id stays `entity-core-protocol-crystal`.
- **License:** Apache-2.0 (S9 default; Crystal itself is Apache-2.0, ecosystem is
  MIT-leaning with no mandate — keep the explicit patent grant).

## Container

Official `crystallang/crystal:1.20.2` (Ubuntu-based) + `libsodium-dev` +
`pkg-config` (resolve libsodium) + `ca-certificates`/`git` (the one network-on
`shards install`). The conformance **run** is sealed `--network=none`; the core
peer's zero shard deps make offline clean.
