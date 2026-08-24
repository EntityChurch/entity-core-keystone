# entity-core-protocol-odin — Profile Rationale

The audit trail for `profile.toml`. One section per major choice. Authored at S1
(2026-07-12) from the pinned **v0.8.0 (V8)** spec-data + Odin-ecosystem research
(primary-source citations — pkg.odin-lang.org, GitHub source, official docs —
captured in the S1 research pass, with presence/absence proven by source
inspection + HTTP status rather than guessed).

## Why build an Odin peer at all (honest framing)

The alien-substrate spec-discovery sweep is **closed** — the well is dry on the
current wire surface (28-peer cohort; discovery axes saturated). Odin is a
**corroboration / generator-robustness** peer. Its value is generator robustness
on a fresh shape the cohort hasn't exercised together:

- **A no-exceptions, value-return error idiom** (`or_return`/`or_else`) distinct
  from Zig's language-level `!T` error union.
- **No package manager at all** — deps are vendored (git subtree); "publish" = a
  git tag. Exercises the generator's packaging path on a decentralized-by-absence
  ecosystem.
- **Manual memory via an implicit `context` allocator** (no GC) — the Zig class,
  re-derived on a different allocator model.
- **A native-crypto corroboration** — Odin ships pure-Odin `core:crypto`
  (Ed25519 + SHA-2), so the Ed25519/SHA floor is native + FFI-free, a fresh
  substrate re-deriving the same signatures/bytes.

Per ADR-0012, a green verdict here is **cohort-consistent, not independent
convergence** — stated in the CONFORMANCE-MATRIX row and the S4 report.

## Toolchain — Odin `dev-2026-06`, built from source

Odin uses monthly dated tags. `dev-2026-07`/`dev-2026-07a` (2026-07-06/-10) are
inside the S11 30-day cool-down; **`dev-2026-06` (2026-06-10, ~32 days)** is the
newest that clears it. There is **no official Odin Docker image** and Odin bundles
no LLVM, so the container layers onto the keystone fedora:43 base, installs stock
Fedora LLVM + clang (a reviewed distro channel — no third-party COPR), and builds
the compiler from source at the pinned git tag (`build_odin.sh release`).
Verified in-container: `odin version dev-2026-06:285f6d8`, LLVM from Fedora 43
(in the supported 17-22 window). `ODIN_ROOT=/opt/Odin` points the binary at its
`core/`+`vendor/` trees.

## Codec strategy — NATIVE (hand-rolled canonical CBOR)

`strategy = "native"`. Odin's stdlib `core:encoding/cbor` (author @laytan) is
**unusually canonical-aware** — an `Encoder_Flag` deterministic mode with
`Deterministic_Int_Size`, `Deterministic_Float_Size` (a real f16→f32→f64
round-trip-equality ladder), `Deterministic_Map_Sorting`, and
`ENCODE_FULLY_DETERMINISTIC` — but it is **not ECF-canonical**:

- map key sort is **pure bytewise** (RFC 8949 §4.2.1 CDE), **not** ECF's
  **length-then-lexicographic** (RFC 7049 §3.9) ordering — the wrong order for ECF;
- major-type-6 tag **rejection on decode is absent** (the generic `Value` decoder
  accepts any tag; only silently drops 55799) — the opposite of the required
  recursive tag-reject.

So the A-005 pattern holds again: the canonical layer (length-then-lex map order,
recursive tag-6 reject, shortest-float incl. f16, full uint64/nint range, raw-byte
`data` fidelity) is hand-rolled regardless. `core:encoding/cbor` is retained only
as a **float-ladder cross-check**, not the codec. (Confirmed present in the pinned
build: `core/encoding/cbor/{cbor,coding,tags,marshal,unmarshal}.odin`.) The
`map_keys` + `float` vectors get a spike at S2 start.

## Integer model — fixed-width `u64`

Odin ints are fixed-width (`u8..u128` / `i8..i128`; `int`/`uint` = 64-bit on
64-bit targets). `u64` natively covers `[0, 2^64-1]`, so the CBOR uint64 head-form
carrier is a plain `u64` — Odin is in the **fixed-width int class** and MUST carry
the head-form + the `[2^63, 2^64-1]` self-test (like Zig/Forth/Fortran). Bignum
(`core:math/big`, confirmed present) is opt-in for any `>=2^64` arithmetic arm, not
needed for the head-form.

## Crypto — native pure-Odin `core:crypto`; Ed448 deferred

`core:crypto/ed25519` (sign/verify/keygen, RFC 8032 / FIPS 186-5; in-tree since
2024-04, maintained) and `core:crypto/sha2` (SHA-256/384/512) are **pure Odin**
(source-verified: no `foreign import` in `ed25519.odin`/`sha2.odin`) — the whole
crypto **floor** is native + FFI-free, the native-pure-lang tier (Dart
cryptography_plus / Common Lisp ironclad precedent), and a genuine corroboration
signal (a fresh independent implementation re-deriving RFC-8032 signatures).

**Caveat (A-ODIN-004):** `core:crypto`'s README self-declares "not received
independent third-party review" and assumes 64-bit. This is an operator note, not
a floor blocker — the KAT accept-path unit + the `wire-conformance`/`validate-peer`
oracles gate the actual bytes, so any deviation from RFC-8032 would fail the gate
loudly rather than ship silently. (If an operator wants an audited floor, the
libsodium-via-`foreign import` fallback is a drop-in — but native is the
faithful, self-contained default and the more interesting corroboration.)

**Ed448** (agility higher bar): **deferred**. `core:crypto` has no Ed448 (only
`x448` ECDH, not the signature scheme — verified absent). Future path: hybrid-FFI
via `libentitycore_codec` (`ec_ed448_*`) bound with `foreign import` as an opt-in
sub-package; does not affect the Ed25519/ECF floor.

## Error model — no exceptions (value-return + `or_return`)

Odin has **no exceptions**. The idiomatic fallible surface is multi-return with a
trailing error value — an error `enum` (`Codec_Error`) or a tagged `union` for
richer payloads; `nil`/`.None`/`false` = success. `or_return` propagates,
`or_else` supplies a default. This is a deliberate idiom seam from the exception
peers and from Zig's language-level `!T` (here it is a plain value enum/union).
Protocol-status faults map an error value → §5.2a/§6.12 status code at the module
boundary; panic is reserved for true unreachable / programmer error.

## Memory — no GC, implicit `context` allocator

No garbage collector. Allocation flows through `context.allocator` (+
`context.temp_allocator` for scratch), overridable per-scope. The codec owns no
global state; encode writes into a caller buffer or a temp allocator; decode
returns owned data with a documented free contract (`defer` free on every path).
Tests wrap a `mem.Tracking_Allocator` so any un-freed alloc fails the test —
free-correctness is a first-class conformance concern here (unlike the GC'd peers).

## Concurrency — raw OS threads (manual §7b)

`core:thread` (Thread + Pool) with `core:sync` (Mutex, RW_Mutex, Sema, Cond,
Wait_Group, atomics). No async runtime, no green threads/fibers. The
§4.8/§6.11 inbound-concurrent-with-outbound requirement is met by one reader
thread per connection demuxing `EXECUTE_RESPONSE` by `request_id` — the Zig/CL
raw-thread shape. §7b store-safety is **manual** (explicit `sync.Mutex`; no
actor/STM structural guarantee), and the §6.11 handler-outbound demux is a
**correlation-map tax**, not free (no actor/CSP substrate). Factor into effort.

## Build / packaging / testing

- **Build/test:** the `odin` compiler *is* the build system (`odin build`/`test`/
  `check`); a package is a directory of `.odin` files. `core:testing`
  (`@(test) proc(t: ^testing.T)`) is the in-language runner — zero external
  framework (the Zig/Crystal dependency-minimization stance, native).
- **Publishing:** Odin has **no central package manager**; consumers vendor the
  package (Ginger Bill prefers git subtree). "Publish" = a git tag. Package ident
  is snake_case (`entity_core_protocol_odin`, no hyphens).
- **License:** Apache-2.0 (S9 default; Odin itself is BSD-3, no ecosystem mandate).

## Container

fedora:43 base + stock LLVM/clang + Odin built from source at `dev-2026-06`. The
core peer pulls **zero third-party packages** (core:crypto + core: covers
crypto/hash/threads/testing/cbor-survey), so the conformance **run** is fully
offline (`--network=none`) once the image exists.
