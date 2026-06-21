# entity-core-protocol-go — Profile Rationale

Audit trail for every major S1 profile choice for the **Go** peer. This is the
document a future operator reads to answer "why did we pick X for Go?".

## ⚠️ Clean-room constraint (the defining property of this peer)

**Go is the reference oracle's language.** The conformance oracle —
`entity-core-go` (`wire-conformance` + `validate-peer`, the cohort's ground truth)
— is written in Go. The *entire value* of this peer is that it is an **independent
clean-room reimplementation from the specification**, not a copy of the oracle.

How I honored it while authoring S1:

- I read **only**: `spec-data/v7.75` (the SHA-pinned verbatim V7 snapshot:
  `ENTITY-CORE-PROTOCOL-V7.md`, `ENTITY-CBOR-ENCODING.md`,
  `ENTITY-NATIVE-TYPE-SYSTEM.md`), the keystone `shared/lifecycle` contracts
  (`PROMPT-CONSTANTS.md`, `PHASE-S1-PROFILE.md`), the cohort's **language-neutral**
  sibling profiles (`csharp/`, `typescript/`, `zig/profile.toml` +
  `zig/arch/PROFILE-RATIONALE.md`), the existing `containers/go/Containerfile`, and
  the seeded cohort memory.
- I did **NOT** open, read, `cat`, `grep`, `find`, or otherwise reference any file
  under any `entity-core-go` checkout — not its codec, not its `validate-peer`, not
  its `wire-conformance`, not its `go.mod`. Every protocol-shaped decision below
  grounds in a **V7 §-pointer** from the spec snapshot, never in oracle source.
- The Go *language idioms* recorded here (stdlib `crypto/ed25519`, hand-rolled
  canonical CBOR, goroutines + channels, `sync.RWMutex` store, explicit `(T, error)`
  returns, gofmt naming) are derived from **general Go ecosystem knowledge** and the
  spec's requirements — they are what *any* competent Go engineer would reach for,
  not what I observed the oracle doing.

The clean-room rule is about **build-time source isolation**. It does **not**
forbid the S4 step of validating this peer's *output bytes* against the oracle —
that byte-comparison is exactly how conformance is proven and is allowed (the
oracle commit `75c532e`, target `--profile core` = 576 · 0F · 89skip, is recorded
in the profile `[spec]` block for that S4 leg).

### Honest limited-signal caveat (required by the brief)

Because **this peer's idiom necessarily equals the oracle's** (both are Go,
both reach for the same stdlib crypto, the same hand-rolled canonical CBOR shape,
the same goroutine concurrency), the **spec-refinement signal from this peer is
inherently bounded**. A *distant-idiom* peer (Zig's no-GC/error-union, Lean's proof
track, OCaml's 63-bit-int trap) stresses the spec along an axis the reference impl
never exercised, and so tends to *discover* latent spec ambiguities. A same-language
peer cannot do that as effectively: where the oracle and this peer would
independently arrive at the same reading of an ambiguous clause, the ambiguity stays
invisible — convergence here is weak evidence (it could be language-shared blindness,
not spec clarity). So the value proposition is deliberately narrower and honestly
stated:

1. **Independent cross-check** — a from-scratch Go impl that lands byte-identical to
   the oracle on the full corpus is genuine corroboration that the *spec*, not some
   oracle-private convention, determines the bytes (the same-language version of the
   six-peer independence accounting). It catches the failure mode "the oracle's
   behavior is under-specified and only the oracle knows the convention."
2. **Idiom completeness** — it fills the Go slot in the cohort's idiom matrix with a
   *generated-from-spec* peer, so the generator's Go output is exercised end-to-end
   rather than assumed.

What it is **NOT** expected to produce: a rich crop of net-new spec findings. If it
surfaces one, that is a bonus; the plan does not bank on it. (Cohort precedent: the
genuine discoveries came from OCaml/Zig/Lean/CL idiom seams, not from same-as-oracle
arrivals — see the six-peer-synthesis independence caveat.)

## Codec strategy: native

The LANDSCAPE default for a language with mature stdlib crypto + no canonical-CBOR
gap is `native`, and Go qualifies cleanly. The deciding reasoning is the **A-005
pattern** every prior native peer (C#/TS/OCaml/Elixir/Zig/CL) independently
re-confirmed: a faithful ECF codec must **own the canonical layer** regardless of
any CBOR library, because ECF's guarantees are stricter than any general library's
"deterministic" mode:

- **Rule 2** — map keys sorted by **encoded byte length, then lexicographically**
  (this is RFC-7049-style length-first ordering, which DIFFERS from RFC-8949 §4.2
  plain-bytewise ordering that many libs call "canonical" — a real trap).
- **Rule 3** — definite lengths only.
- **Rule 4 / 4a** — shortest-float including **float16**, with exact special-value
  bytes (NaN `F9 7E00`, -0.0 `F9 8000`, +Inf `F9 7C00`, -Inf `F9 FC00`), enforced
  on **decode** as well as encode (a received non-minimal float is non-canonical).
- **Rule 5** — no duplicate map keys (decode rejects).
- **§6.3** — recursive **major-type-6 (tag) rejection** anywhere inside a data field
  at any nesting depth → `400 non_canonical_ecf`. (Tagged ≠ untagged bytes ≠ same
  hash; tags are simply not part of ECF.)
- Full **uint64 / nint** range (the `int.10/15/16/17` corpus, the `[2^63, 2^64-1]`
  band).
- Raw-byte fidelity for the **arbitrary-ECF `data` field** (A-JAVA-010: `data` is an
  arbitrary ECF value, not necessarily a map — the codec encodes any ECF value, not
  a fixed struct).

A library either omits these or actively fights them, so it buys almost nothing. And
Go's stdlib ships audited `crypto/ed25519` + `crypto/sha256` + `crypto/sha512`, so
native is also the **lighter** path — the entire core peer is **stdlib-only, zero
third-party modules**. `ffi` (consume `libentitycore_codec`) remains the documented
fallback but is not expected to be needed. Per PHASE-S1-PROFILE, the S2 build opens
with a **spike**: push the `map_keys.*` + `float.*` vectors through the hand-rolled
encoder before the full build — cheap insurance; `ffi` is the fallback if it fails.

## CBOR: hand-rolled (fxamacker/cbor considered and rejected)

Go's stdlib has **no CBOR**. The credible third-party candidate is
**`fxamacker/cbor`**, which does offer a "Core Deterministic" / CTAP2 canonical
*encode* mode (length-first map keys, shortest int, smallest-float on encode) — the
nearest any Go library gets. It is **rejected for the core codec** for three reasons
(logged A-GO-001):

1. **It doesn't give ECF's guarantees for free regardless** — recursive tag
   rejection on **decode** (§6.3) returning the specific `400 non_canonical_ecf`,
   **decode-side** shortest-float minimality checking (Rule 4 on receive), the exact
   float16 special bytes (Rule 4a), and raw-byte fidelity for arbitrary `data`. These
   would have to be hand-written *on top of* the library anyway — at which point the
   library is doing what the hand-roll already does.
2. **Byte-exactness for a content-addressing substrate is a thing this peer must
   OWN and prove vector-by-vector**, not delegate to a dependency whose canonical
   mode targets a slightly different rule set.
3. **Dependency-minimization** (the repo's supply-chain stance) — a ~600-line
   hand-rolled canonical codec dodges a registry-module pin (and its `go.sum` entry)
   entirely; the core peer's `go.sum` stays empty.

The bar for a future maintainer to swap in the library is explicit in the profile:
prove it reproduces `map_keys.*` / `float.*` / `tag_reject.*` byte-for-byte AND
enforces decode-side rejection. Decode is implemented as explicit major-type
switching on the head byte — Go's idiomatic wire-parsing shape.

## Crypto: stdlib crypto/ed25519 + crypto/sha256/sha512

Go's standard library provides **`crypto/ed25519`** (FIPS-186-5 / RFC-8032):
`ed25519.GenerateKey(rand.Reader)`, `ed25519.Sign(priv, msg)` (deterministic by
construction — no RNG needed to sign, matching the §7.3 deterministic-signature
expectation), `ed25519.Verify(pub, msg, sig)`. It is maintained by the Go security
team, ships in-tree, and pulls **no module dependency**. `crypto/sha256` is the
`content_hash` floor; `crypto/sha512` provides **SHA-384** for agility hashing.
Pinning is by **toolchain version** (stdlib ships with the compiler) — there is no
separate module version to age-check, so the S11 discipline reduces to the single Go
toolchain pin (which comes through fedora dnf, a reviewed distro channel — pin
exactly for repro, age-floor relaxed).

## Ed448: deferred — native gap (A-GO-002)

`crypto/ed25519` exists but Go has **no Ed448** in the stdlib, and **`golang.org/x/crypto`
has no Ed448 either** — it carries ed25519-adjacent and NaCl-family primitives but
not the Ed448/Goldilocks curve. There is no reviewed-channel pure-Go audited Ed448
(no BouncyCastle-equivalent, the route C# took). This is the **same gap Zig
(A-ZIG-002) and OCaml (A-OC-002) hit** — the "second managed-crypto provider"
strategy that worked for C# does not generalize to Go either. The ECF/Ed25519
conformance floor (§9.1; the v7.75 `--profile core` target) is **unaffected** —
Ed448 is *validated*, not *required*. Deferred with a documented escalation rather
than a silent gap or an unaudited hand-roll. The likely shape when agility is in
scope: **hybrid** native-Ed25519 + FFI-Ed448 (consume `libentitycore_codec` for the
Ed448 family only via **cgo**) — Go's C-ABI FFI is first-class, so this is a natural
fit, mirroring the Zig/OCaml resolution. (SHA-384 agility hashing, by contrast, **is**
native via `crypto/sha512`.)

## Base58 + varint: hand-rolled

Both are small and absent from the stdlib. Base58 (Bitcoin alphabet, encode +
decode, `internal/base58`) for `peer_id`; multicodec-style LEB128 varints
(`internal/varint`) for the §1.5 / §7.3 `key_type` / `hash_type` framing. Note: Go's
`encoding/binary.Uvarint` is the *same* LEB128 shape, but the peer-id framing needs
explicit control over the multi-byte continuation for code allocations beyond `0x7F`
(future-proofing the §1.5 varint expansion) and over rejection of non-minimal
varints, so it is owned in-repo. Hand-rolling matches the stdlib-only stance.

## Error model: explicit (T, error) returns

Go-native error handling is the **explicit `(T, error)` return** checked with
`if err != nil` — the cohort taxonomy's `result` style, but spelled Go's way. The
language has **no exceptions**; `panic` is reserved for true programmer-error /
unreachable invariants and is recovered at goroutine boundaries so one bad
connection never crashes the peer (the §4.9 no-crash floor). Codec failures are
**sentinel/typed errors** wrapped with `%w`, so a caller discriminates via
`errors.Is(err, ErrNonCanonicalEcf)` / `errors.As` — **never string-matching** —
which is Go's analogue of an exhaustive error set or ADT verdict. At the dispatcher
boundary a typed error maps to a protocol status:

- `400 non_canonical_ecf` ← tag / canonical-rule violation (§6.3).
- **`400 chain_depth_exceeded`** ← over-deep capability chain (§4.10(b)) — **NOT
  403**. Pre-resolved cohort trap: a too-deep chain is a *structural excess*, not an
  authz denial; the fix shape (uniform across all 9 peers) is a `chainExceedsDepth`
  structural pre-check (walks parents, no signature work, max=64) **before** the
  authz walk; an *unreachable* parent stays 403.
- `401` ← `identity_mismatch` (§4.6 handshake binding) and the `unresolvable_grantee`
  carve-out on the authz path (§5.2). The **§5.2 trichotomy** is pre-resolved:
  `ALLOW` / `AUTH_DENY` (401) / `AUTHZ_DENY` (403 default), with the single
  `unresolvable_grantee → 401` authz carve-out (and the ROLE-extension
  `capability_revoked → 401` in-flight cascade, which is out of core).
- `403 capability_denied` ← `AUTHZ_DENY` default (§5.2 verdict-to-status table).
- `413 payload_too_large` ← inbound EXECUTE wire size over the configured max
  (§4.10(a); allocation-safety, the no-crash class).

## Concurrency: goroutines + channels, sync.RWMutex store

Go-native concurrency is **goroutines + channels**, and it is the cleanest fit in
the cohort for the §6.11 inbound-concurrent-with-outbound requirement: one goroutine
per connection, a reader goroutine demultiplexing `EXECUTE_RESPONSE` by `request_id`
over a per-conn response-channel map. The codec (S2) is pure synchronous; concurrency
enters at S3. Three pre-resolved §7b traps are baked into the profile so the peer
does **not** re-burn them:

1. **Store-safety (§4.8) from day one.** The shared content store MUST be
   data-race-safe under concurrent dispatch. **Zig and Common-Lisp shipped
   unsynchronized stores that fell over** under the §7b T2.1 sustained-load probe
   (Zig double-free PANIC, CL 500s). Go starts with a `sync.RWMutex`-guarded store
   (read-mostly: resolves are reads, binds are writes) — no race window. Discipline:
   copy-out under the read lock, do I/O outside it; never hold the lock across a
   syscall.
2. **TCP_NODELAY.** `net.TCPConn.SetNoDelay(true)` on **every** accepted/dialed
   connection. Nagle + delayed-ACK on small request/response frames was *the* §7b
   throughput killer for Zig (62s → 1.9s; 343ms/cycle churn was the Nagle signature).
   Set it from the start, not after a perf investigation.
3. **No blocking syscalls under the lock / cooperative-pool hygiene.** Go's runtime
   scheduler is non-blocking-aware and goroutines are cheap, so thread-exhaustion
   (the Zig T2.1 thread-per-request fall-over) is not a Go failure mode — but the
   discipline of not holding the store lock across I/O still applies.

`context.Context` threads cancellation/deadline through the transport for the §6.11
deadlines — the Go-native cancellation idiom.

## Integers: native uint64/int64 (the clean int story)

Go has native fixed-width `uint64`/`int64`, so the §3.2 full `uint`/`nint` range
(corpus `int.10/15/16/17`, the `[2^63, 2^64-1]` band the codec-review-heuristic
flags) maps **directly** onto `uint64`/`int64` carriers — **no BigInt ceremony**
(contrast TypeScript's F7 always-bigint rule) and **no 63-bit trap** (contrast
OCaml's A-OC-001 native-int loss). The one watch-item: CBOR `nint` encodes the value
`-1-n`, so the `[-2^64, -1]` band needs careful `uint64`-carrier arithmetic on the
decode path (the additional-info value is `|n|-1`); handled with explicit `uint64`
math, captured as an S2 vector check.

## Naming: gofmt-enforced MixedCaps

`PascalCase` for exported types/funcs, `camelCase` for unexported, **MixedCaps for
constants too** (Go does NOT use SCREAMING_SNAKE — a real divergence from C#/TS
constant conventions), `snake_case.go` file names, short lowercase single-word
package names, and **all-caps initialisms** (`PeerID`, `EncodeECF`, `CBOR`, `URL`,
`TCP` — a Go style-guide MUST, not `PeerId`/`Ecf`). All of it is `gofmt`-enforced, so
"clean gofmt + go vet" is the universal Go lint floor with no external linter.

## Build / test / packaging: go toolchain + stdlib testing + git-tag modules

`go build` / `go test` (the toolchain *is* the build system; `go.mod` is the
manifest, `go.sum` stays empty for a zero-dep peer). Tests use the built-in
**`testing`** package with **table-driven subtests** (`t.Run` per vector) — no
external test framework, the same dep-minimization win Zig/Elixir/Node got natively
(no `testify` in the core path). Go has **no central upload registry**: "publishing"
is a git tag that consumers pin via `go get module@vX.Y.Z`, checksum-recorded in
their `go.sum` + the `sum.golang.org` transparency log — decentralized and
checksum-pinned by design, itself a supply-chain-friendly property.

## License: Apache-2.0 (S9 default)

Go itself is BSD-3-Clause and the ecosystem is license-mixed without mandating one,
so the repo's Apache-2.0 default (explicit patent grant) stands.

## Container: REUSE containers/go/Containerfile (not re-authored)

Per the brief, I **inspected the existing `containers/go/Containerfile` and REUSE it
as-is** — it is adequate. It is `fedora:43` + `golang-1.25.10` (via `dnf`) + `git`,
with `GOTOOLCHAIN=local`, `GOFLAGS=-mod=mod`, `WORKDIR /work`. That is exactly the
toolchain a zero-dep stdlib-only core peer needs; **nothing is missing**, so no new
Containerfile was authored. Supply-chain note: the Go toolchain arrives through
**fedora dnf — a reviewed distro channel** — so per the supply-chain memo the S11
≥30-day age floor *relaxes* to "pin exactly for reproducibility" (the
`golang-1.25.10` NVR is the pin); 1.25.10 is a settled patch regardless and
satisfies `entity-core-go`'s declared `go 1.25.0` minimum. Forward note for S2+:
because the build is stdlib-only, the container can run `--network=none` after the
image exists (no module fetches); `GOFLAGS=-mod=mod` is harmless for a zero-dep
build.

## Spec version: read v7.75 (latest snapshot)

Profile + (future) peer derive from `spec-data/v7.75` (the latest available SHA-pinned
verbatim V7 snapshot), which folds the v7.75 non-functional substrate floor (§4.8
store-safety, §4.9 resilience, §4.10 resource bounds) — all three of which are
pre-resolved in the `[concurrency]` and `[error_model]` blocks. The codec corpus is
read at the same version. The S4 conformance target is `--profile core` = **576 ·
0 FAIL · 89 skip** against oracle `entity-core-go @ 75c532e` — recorded for the S4
byte-validation leg only (the clean-room rule permits validating *bytes* against the
oracle at S4; it forbids reading the oracle's *source* while building, which was
honored throughout S1).
