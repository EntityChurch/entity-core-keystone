# entity-core-protocol-nim — Profile Rationale (S1)

Why each `profile.toml` choice was made. One section per major decision — the audit
trail when a future operator asks "why did Nim pick X?". Nim is a Tier-3
**corroboration / generator-robustness** peer (`research/LANDSCAPE.md`); it is not a
spec-discovery bet (the well is dry on the current wire surface — see
`status/PHASE-S1.md`). Its distinctive value is (a) a canonical ECF codec expressed
through Nim's **compile-time metaprogramming** (macro/template) and (b) a clean
**native-C-interop** crypto binding on a garbage-collected substrate. Where a choice
matches a prior peer it was reached independently from V8 + Nim, not inherited.

## Codec strategy: NATIVE (deviates from LANDSCAPE's "ffi" guess) — A-NIM-001

`LANDSCAPE.md` marks Nim `ffi` on a first pass (CBOR: the small `cbor` package;
Ed25519: libsodium via C interop). Per `PHASE-S1-PROFILE` **the profile decides**, and
the S1 reality-check is explicit: no surveyed CBOR library gives ECF's canonical
guarantees, so the canonical layer is hand-written on *every* substrate. Concretely the
codec must own, regardless of any library beneath it: shortest-float / float16
minimization with exact specials; **length-then-lexicographic** (CTAP2, RFC-7049)
map-key ordering — which differs from RFC-8949 §4.2 bytewise ordering; recursive
major-type-6 (tag) rejection anywhere (N2); byte-exact raw-slice round-trip; and the
full uint64/nint head-form range. The Nim `cbor` nimble package is a convenience DOM
codec and supplies none of these. So a library buys almost nothing and adds a nimble
pin.

Hand-rolling is therefore both the faithful and the simpler path — and it is the *only*
choice that (1) yields an **independent codec** to cross-check the oracle (consuming the
C-ABI would give zero independent codec signal — the C-ABI codec *is* the C impl) and
(2) exercises Nim's headline generator-stress axis: **compile-time metaprogramming**.
The encoder dispatches on CBOR major type / Nim value type at compile time via
`macro`/`template`/`static:` with zero runtime reflection — the Zig `comptime` result
carried onto a GC'd, C-backend substrate. `ffi` (consume `libentitycore_codec`) remains
the documented fallback if the S2 canonical spike fails, but it forfeits both the
independent codec and the metaprogramming probe, so it is a last resort. **Spike at S2
start** (PHASE-S1 mandate): push the `map_keys` + `float` v0.8.0 vectors through the
hand-rolled encoder before the full build — shortest-float f16 + length-then-lex are the
highest-bug-density legs.

## Crypto floor: libsodium via native `{.importc.}` C interop — A-NIM-003

Nim **compiles to C**, so binding libsodium through `{.importc.}` (+ static/`{.dynlib.}`
link) is idiomatic, in-process, zero-marshalling native interop — *not* a
foreign-language bridge. This is exactly the C peer's crypto decision (`strategy =
native` with libsodium), re-confirmed for Nim because Nim→C makes the two nearly
identical. libsodium is audited, statically linkable, and the single source of both
Ed25519 (RFC-8032 deterministic detached signing via `crypto_sign_detached` /
`crypto_sign_verify_detached`, seed→keypair via `crypto_sign_seed_keypair`) and SHA-256
(`crypto_hash_sha256`). A well-audited *pure-Nim* Ed25519 does not exist (nimcrypto
ships SHA-2/HMAC but no audited EdDSA), so libsodium is the crypto floor; nimcrypto
SHA-256 is noted only as an FFI-free SHA fallback if a libsodium-free build is ever
wanted. Because libsodium is a standard audited system crypto library (not the entity
C-ABI), the default peer stays **self-contained** — one system crypto dep, no dependence
on `libentitycore_codec`. Statically + privately linked so an embedder's own libsodium
does not collide.

This keeps the durable "Ed25519+SHA stay native" lesson: only Ed448 (which libsodium
lacks) would ever cross the entity C-ABI, and that is deferred to an opt-in sub-library.

## Ed448 / SHA-384 agility: DEFERRED, opt-in hybrid-FFI sub-library — A-NIM-004

libsodium has no Ed448-Goldilocks (it ships Ed25519 + SHA-2 + ML-KEM/SHA-3). This is the
same native gap C (A-C-001), Zig (A-ZIG-002), and OCaml (A-OC-002) hit. Ed448 + SHA-384
is the crypto-agility *higher bar*, not the §9.1 floor, so it is deferred from the v0.1
core. When agility lands, two honest routes: (a) bind the sibling
`libentitycore_codec` `ec_ed448_*` / `ec_sha384` via `{.importc.}` (the hybrid-FFI shape
used by OCaml/Zig/Swift/Tcl/COBOL), or (b) OpenSSL `EVP_PKEY_ED448` + SHA-384. Either is
scoped to an **opt-in agility sub-library** so the shipped default peer's crypto surface
stays one library (libsodium) and FFI-free of the entity C-ABI. Ed448 does not touch the
Ed25519 + SHA-256 conformance floor.

## Integer model: fixed-width uint64 + mandatory head-form self-test — A-NIM-002

Nim integers are **fixed-width** (`int8..64` / `uint8..64`), no native bignum. `uint64`
maps directly to the §1.5/§7.3 CBOR head form (like C `uint64_t`, Zig `u64`, C# `ulong`)
— cleaner than the bignum peers only in that there is no allocation, but with the
**fixed-width trap**: a signed `int64` carrier silently overflows in `[2^63, 2^64-1]`.
Per the `AGENTS.md` head-form lesson the carrier is `uint64` (magnitude for negatives,
tagged mt1), and a **round-trip self-test across `[2^63, 2^64-1]` is a mandatory S2 codec
gate**, not optional. The codec builds with `--overflowChecks:on`; unsigned arithmetic
wraps silently, so every decoder length read is explicitly bound-checked before use.

## String model: static byte-vs-text distinction (clean) — A-NIM-007

Unlike Tcl's EIAS substrate, Nim's byte-vs-text seam is a **static type** distinction and
is free: CBOR byte-string (mt2) is `seq[byte]`, text-string (mt3) is `string`, and a Nim
`string`'s `len` is already a **byte count** (not code points — no `encoding convertto`
dance, contrast A-TCL-002). The major type is sourced from the spec's field type
definitions and carried in the typed model (the type-registry "render from the model,
don't infer" lesson) — here it costs nothing because the types already carry it. mt3 text
is validated as UTF-8 on decode where the spec requires text; mt2 bytes are opaque.

## Error model: exceptions + `{.raises.}` effect tracking — A-NIM-008

Nim's idiom is exceptions (`raise`/`try`/`except`), with a distinguishing seam: the
`{.raises: [...].}` **effect system** lets the compiler statically enforce the exact
exception set a proc may raise — a lightweight checked-exceptions (the Java peer had this
heavyweight; the Zig peer had it as error-unions). Codec surfaces are `{.raises.}`-
annotated and throw hard on N2/N3 canonicality violations; protocol-status failures map
an exception type → wire status at the dispatcher boundary; in-band absent is `Option[T]`
(std/options), never a nil/empty collision. The `results` package (Result[T,E], the
Status/nim-libp2p idiom) was considered and rejected: it is a dependency, and stdlib
exceptions + `{.raises.}` are the dependency-minimal idiomatic choice.

## Memory: ARC/ORC deterministic GC — a third memory idiom

Nim 2.x defaults to `--mm:orc` (ref-counting + cycle collector): **deterministic
destructors** run at scope exit (like C++ RAII / Rust drop) with move-optimized value
semantics — no stop-the-world GC pause, yet no hand-written `free()`. This is genuinely a
third point versus both the tracing-GC peers (C#/Java/Go/Elixir) and the no-GC peers
(C/Zig): the programmer neither pays GC latency nor writes goto-cleanup. `seq[byte]`/
`string` are move-semantic value types; the decoder returns `openArray` borrows (zero
copy) where the input outlives the view, or copied slices otherwise, per a documented
per-proc contract.

## Async / concurrency: asyncdispatch single-threaded event loop — A-NIM-006

Nim's stdlib network-concurrency model is `asyncdispatch` — async/await on a
**single-threaded cooperative event loop** (the PHP `stream_select` / Tcl `chan event` /
Dart per-isolate class). This makes §7b store-safety **structural**: one event thread
serializes every store mutation, so the store is a plain `std/tables Table` with no mutex
or atomics, and §6.11 handler-initiated outbound-dispatch reentry is ~free — an outbound
dispatch is another event-loop turn, and the inbound `EXECUTE_RESPONSE` completes a
`Future` matched by `request_id` from the one loop's pending table (no cross-thread
demux, the correlation-map tax the raw-thread peers pay). Nim also has real OS threads
(`--threads:on` + channels) — a genuine alternative, but not used for the core peer
(asyncdispatch is more idiomatic and gives structural safety without a lock). `chronos`
(Status's async) was rejected as a dependency; stdlib `asyncdispatch` is dependency-
minimal. TCP_NODELAY is set on accepted sockets (the Zig Nagle throughput finding).

## Build / test / packaging: nimble + stdlib unittest + git-indexed registry

`nimble` is Nim's package manager and build tool and ships with the toolchain; a
`.nimble` file is the manifest (Cargo.toml/.asd analogue). `nim c` compiles Nim → C →
gcc. Tests use the **stdlib `unittest`** module (suite/test/check), the ecosystem
standard, discovered automatically by `nimble test` at `tests/t*.nim` — free, no
supply-chain cost, so unlike Zig/C/OCaml there is no dependency-minimization reason to
hand-roll a runner. The conformance harness (`tests/tconformance.nim`) loads the
normative v0.8.0 corpus and asserts byte-identity, and must include the `[2^63, 2^64-1]`
head-form self-test. Publishing is the `nimble` **git-indexed** model: tag a git release
with a working `.nimble` and PR the `nim-lang/packages` index (the SWI-pack / Quicklisp-
git model, not a binary registry). License is the S9 Apache-2.0 default (Nim itself is
MIT, ecosystem MIT-leaning but not mandating; libsodium is ISC, Apache-compatible).

## Toolchain pin: Nim 2.2.x, verified download (Zig install pattern) — A-NIM-005

Nim 2.x (ARC/ORC default, macros stable) is the target; the profile pins `2.2.2` with
`2.0.14` as the fallback line. The exact patch + tarball sha256 are confirmed at S2
against `nim-lang.org/install`, using a **fail-closed sentinel** in the Containerfile
(the Zig-toolchain install pattern) so an unverified image cannot build silently. The
codec logic is version-agnostic across 2.0/2.2. Nim needs gcc as its C backend at build
time (in the image) and links libsodium; there are **no third-party nimble packages** in
the core peer — the codec, base58, varint, crypto bindings, and test harness are all
hand-rolled or stdlib.

## Container: `containers/nim-toolchain/Containerfile` authored this phase

No existing `nim-toolchain` image, so one is authored (fedora:43 base, per the pattern):
the pinned Nim toolchain + gcc (C backend) + libsodium (runtime/static/devel for the
crypto floor) + download/verify tooling. S1 authors it only; the build is S2's job
(the S1 no-toolchain boundary).
