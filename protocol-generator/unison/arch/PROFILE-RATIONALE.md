# entity-core-protocol-unison — Profile Rationale

Audit trail for every major S1 profile choice. Unison is **peer #43**, operator-directed
(NOT on `research/LANDSCAPE.md`'s tier roster). Derived spec-first from the **v0.8.0 (V8)**
`spec-data/v0.8.0` snapshot + Unison ecosystem research + an in-container UCM spike (see
`status/PHASE-S1.md`). Unison is a **coverage / generator-robustness** peer, not a
wire-discovery bet: the wire-touching axes (integer width, float model, crypto availability,
string model) are saturated and the spec-discovery well is dry on the current surface. Where a
value matches a prior peer it is by independent arrival.

## What this peer probes (the reason it is worth generating)

1. **Generator robustness on a content-addressed codebase build model.** Unison source does
   NOT live in ordinary compiled text modules — code lives in a content-addressed **SQLite
   codebase** managed by **UCM**, which is interactive by design. Our pipeline is
   container-bound + non-interactive. The whole build hinges on driving `.u` source
   **headlessly** via `ucm transcript` — a build model no prior peer used (not a
   file→compile→link loop). This was THE de-risk, and it is **proven** (see the container
   spike below). *(Thematic aside, not a finding: Unison code is itself content-addressed —
   the hash of its typed AST — the same idea entity-core uses for entities.)*
2. **A no-C-FFI crypto-spectrum datum.** A managed runtime with **native** Ed25519 + SHA-256
   builtins but **no** Ed448 / **no** SHA-384, and **no general C FFI** — so the
   `libentitycore_codec` hybrid-FFI escape hatch is structurally unavailable. A distinct
   crypto-availability position (see below).
3. **An abilities/algebraic-effects concurrency taxonomy datum** for the §7b store-safety
   model (see below).

## Container: containers/unison-toolchain/Containerfile — BUILT + spike-verified at S1

`fedora:43` base + the official **UCM `release/1.3.0`** linux-x64 prebuilt tarball
(`ucm-linux-x64.tar.gz`), pinned to an **exact sha256**
(`0c52e223746ba36029993f38c6774675a2d61ff01dfc75c463a6e3df7d6d433b`), fail-closed on mismatch,
installed under `/opt/ucm` with the `ucm` wrapper symlinked onto PATH. This is the
zig/swift/ghc "official tarball + pinned sha256, fail-closed" discipline. The tarball contains
`./ucm` (a bash wrapper that sets `UCM_WEB_UI` and execs the real binary), `./unison/unison`
(the ELF binary — `ldd` → libm/libz/libgmp/libc, all from fedora:43's own repos), and `./ui/`
(the local web UI, unused headless). Fedora ships no `ucm`; UCM's own channels are the GitHub
release tarballs / Homebrew / an apt repo — none a Fedora pin we control — so the pinned
tarball is the route. The container was **built and proven NOW** (deliberate deviation from the
author-only S1 convention, per this peer's S1 task contract — the headless-codebase de-risk had
to be settled before S2):

- `podman build … containers/unison-toolchain/Containerfile` (under the resource caps) →
  **SUCCESS**; `ucm --version` → `release/1.3.0 (built on 2026-05-13)`.
- **Headless execution PROVEN** — `ucm transcript <file.md>` and `ucm run.file <file.u>
  <symbol>` both run `.u`/transcript source fully non-interactively in-container, emitting a
  diffable `<file>.output.md`. (The interactive-UCM concern is retired.)
- **Native crypto PROVEN** (one transcript, `builtins.mergeio` then watch-expressions):
  - `crypto.hashBytes crypto.HashAlgorithm.Sha2_256 (Bytes.fromList [104,101,108,108,111])`
    → `0xs2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` — **exact
    SHA-256("hello") KAT match**.
  - `crypto.Ed25519.sign.impl` of the empty message with the **RFC-8032 §7.1 Test-1**
    (seed, pubkey) → **matches the vector's 64-byte signature exactly**; and
    `crypto.Ed25519.verify.impl` of that signature → **true**.
- **Numeric model PROVEN** — `Nat.increment (2^64-1)` → `0` (64-bit unsigned wrap);
  `Int.increment (2^63-1)` → `-2^63` (64-bit signed two's-complement wrap);
  `Float.toRepresentation 1.0` → `4607182418800017408` (= `0x3FF0000000000000`, raw IEEE-754
  double bits — the shortest-float-ladder primitive).
- **Networking PROVEN present** — `builtin.io2.IO.serverSocket.impl`,
  `builtin.io2.IO.socketSend.impl` (and the io2.IO.* socket family) are **runtime builtins**
  (no base pull needed for TCP).

## Pinned UCM version: release/1.3.0

UCM releases on an irregular cadence; the version is pinned exactly and the whole peer is
designed against one release. **`release/1.3.0`** (published **2026-05-20**, ~60 days old at
authoring) is the **newest tagged, dated release before the 2026-06-19 ≥30-day cool-down
floor**. The rolling `trunk-build` (2026-06-28) is deliberately **not** used — it is not a
pinned release. The prebuilt binary carries the builtins we depend on (crypto, hashing, Bytes,
io2.IO sockets), so the pin fixes the whole runtime surface.

## Codec strategy: native, BUILTINS-ONLY floor (zero third-party dependency)

`native`. Two halves, and the outcome is a core peer whose only runtime is UCM itself:

- **Crypto is native via UCM runtime builtins** — no library, no pull. `crypto.hashBytes`
  with `crypto.HashAlgorithm.Sha2_256` (SHA-256); `crypto.Ed25519.sign.impl` /
  `verify.impl` (Ed25519). All build-proven at S1 (KATs above). This is the native-stdlib
  crypto tier.
- **CBOR is hand-rolled in pure Unison** — the **A-005 pattern** every native peer hits: no
  Unison CBOR library gives ECF's exact guarantees (length-then-lexicographic map-key
  ordering over the *encoded* key bytes §2.2 Rule 2, shortest-float incl. f16 §2.2 Rule 4 +
  the special-value table, recursive major-type-6 tag rejection on decode §6.3 Option B, full
  uint64/nint range, raw-byte fidelity), so a library buys nothing. AND — decisively — Unison
  has **no general C FFI**, so there is no `libentitycore_codec` fallback to weigh against
  hand-rolling regardless. `Float.toRepresentation : Float -> Nat` (build-proven) gives the
  raw IEEE double bits the float ladder needs.

The floor is therefore **builtins-only**: crypto/hash/Bytes/sockets are builtins; CBOR +
base58 + varint + the handful of list/text combinators the codec needs are hand-rolled
in-repo. `@unison/base` is **optional** convenience combinators, not required (A-UN-002). This
matches the cohort's dependency-minimization ethos (Zig std-only, CL one-dep) and yields a
fully-offline `--network=none` core build after the one-time toolchain pull. `ffi` is
structurally unavailable but is also not needed. The cheap codec spike (push the `map_keys` +
`float` ECF vectors through the hand-rolled encoder) runs at S2 start per PHASE-S1-PROFILE.

## Crypto: native Ed25519 + SHA-256 builtins; agility (Ed448 + SHA-384) DEFERRED — the no-FFI datum

UCM's `crypto.*` builtins provide **native Ed25519** (`sign.impl : secretKey → publicKey →
message → Either Failure Bytes`; `verify.impl : publicKey → message → signature → Either
Failure Boolean`) and **native SHA-256** (via `crypto.hashBytes … Sha2_256`), plus SHA-512,
SHA3-256/512, Blake2b/s. Both Ed25519 and SHA-256 are build-proven at S1 against known-answer
vectors. **Ed448 is NOT a builtin** (S1 `find crypto` enumerated Ed25519, P256, Rsa — no
Ed448) and **SHA-384 is NOT a builtin** (only Sha2_256/Sha2_512/Sha3_*/Blake2*/Md5/Sha1). The
crypto-agility higher bar (key_type 0x02 Ed448 + SHA-384 hashing) is therefore **DEFERRED**:
Unison is a **managed runtime with no general C FFI**, so the hybrid-FFI route OCaml
(A-OC-002), Zig, and Swift used to source Ed448 over the C-ABI is **structurally unavailable**,
and the only in-band route is a pure-Unison Ed448 + SHA-384 impl (large, ~zero discovery value
on a dry wire surface). Deferring agility is established cohort precedent (Swift A-SW-001, Zig
A-ZIG-002, OCaml) and is WARN not gating under `--profile core`; the agility corpus is out of
scope for this peer's gate. (A-UN-001.)

**This no-C-FFI fact is itself the crypto-spectrum datum this peer contributes.** The ledger
now has a distinct position: a managed-runtime peer with native Ed25519+SHA-256 but no agility
*and* no FFI fallback — distinct from native-full-agility (Haskell crypton, CL ironclad),
native-floor-plus-FFI-agility (OCaml/Zig/Swift), and gap→FFI-everything (COBOL). A managed
runtime's crypto reach is bounded by what its builtins expose, with no C escape hatch to widen
it.

## Numeric model: fixed-width 64-bit (Nat/Int) — carry the head form, self-test [2^63, 2^64-1]

Unison is a **fixed-width** peer, build-proven at S1: `Nat` is 64-bit **unsigned** (wraps mod
2^64) and `Int` is 64-bit **signed** two's-complement (wraps). There is **no
arbitrary-precision integer builtin**, so the full uint64 range cannot be carried free the way
the Elixir/CL/Python/Haskell bignum peers do. Per the durable head-form lesson the profile
branches fixed-width: carry the CBOR integer **head form** as an explicit artifact and run the
self-test over **[2^63, 2^64-1]** (the high-bit-set uint64s that need care when there is no
wider type to promote into). CBOR major-type-0 unsigned maps to `Nat` (full 0..2^64-1); CBOR
major-type-1 negative decodes as `-(n+1)` with the magnitude `n : Nat` — **not** `Int`, which
tops out at 2^63-1 and cannot hold the largest nint magnitudes. This puts Unison in the C#
ulong / Zig u64 / OCaml int63 / Fortran fixed-width class, distinct from the bignum peers.
(A-UN-003.)

## Concurrency: abilities (algebraic effects) over IO — a new §7b store-safety shape

Unison's concurrency is via **abilities** (algebraic effects) over the IO ability: `fork`
(lightweight green threads on the Unison runtime scheduler), `Promise`/`MVar` (synchronised
cells), `Ref` (mutable ref), and `scope`/structured-concurrency wrappers. The codec (S2) is
pure/synchronous, so concurrency enters at the peer (S3). The §4.8/§6.11
inbound-concurrent-with-outbound requirement, the §6.13b handler outbound closure, the §7a
dispatch-outbound reentry surface, and the §7b store-concurrency gate fit naturally: one
`fork`ed thread per connection; the live store an **MVar-guarded single-owner cell**
(take/modify/put serializes all store access — an **actor-like structural guarantee realized
through the effect system** rather than a language-level actor); request_id↔continuation
correlation via an MVar/Ref demux map or a per-request `Promise`. This is a **new shape** in
the §7b store-safety taxonomy — distinct from actor-isolation, STM, raw-thread,
single-thread-event-loop, and dataflow-variable: the serialization primitive is a library
value over an effect, not a language actor or a transaction. A taxonomy **datum**, not a spec
finding; final shape decided at S3. (A-UN-004.)

## Error model: pure `Either CodecError a` + Exception/Abort abilities at the IO edge

The pure codec is a total function returning `Either CodecError a` (Unison's builtin `Either`;
an error is a value — nothing to handle in the codec layer). IO-boundary failures use the
`Exception`/`Abort` abilities: the io2 builtins return `Either Failure a`, lifted/handled at
the S3 transport edge, never in the pure codec. Protocol-status failures (400
non_canonical_ecf / 401 / 403) map a `CodecError`/verdict constructor → status code at the
module boundary. The error *shape* converges with Haskell's Either / OCaml's result (the error
axis is low-yield and idiom-neutral across the cohort), arrived at independently as the Unison
idiom. (A-UN-005.)

## Naming: Unison conventions

`UpperCamelCase` for types, data constructors, and abilities (`Entity`, `ContentHash`,
`PeerId`, `CodecError`, `Exception`); `lowerCamelCase` for terms/functions, locals, record
fields, and top-level value bindings (`contentHash`, `signEntity`, `encodeEcf` — Unison uses
`lowerCamelCase` for value bindings, **not** SCREAMING_SNAKE). Hierarchical dotted namespaces
(`entityCore.codec.cbor`, `entityCore.peerId`). `.u` files are transient source (content lives
in the codebase); name them by feature (`Codec.u`, `PeerId.u`).

## Build / test / packaging: UCM transcripts + Unison Share

The build interface is **headless transcripts**: `ucm transcript transcripts/build.md` loads
`src/*.u` into the content-addressed codebase, typechecks (= builds), and `add`/`update`s;
`ucm transcript transcripts/conformance.md` runs the conformance harness (`>`/`test>`
watch-expressions asserting byte-identity against the v0.8.0 ECF corpus, results diffed in
`conformance.output.md`). No test-framework dependency (the OCaml/CL/Zig dependency-min
precedent). Single-definition runs via `ucm run.file`; the peer (S3/S4) compiles to a `.uc`
bytecode via `compile` and launches with `ucm run.compiled peer.uc` (fast, offline). The
content-addressed codebase (`.unison/`) is gitignored — regenerated from the committed
transcripts + source. **Packaging** targets **Unison Share** (`ucm push …/releases/<semver>`);
registry submission is the optional S5 step, deferred like the alien-substrate cohort.

## License: Apache-2.0 (S9 default)

Unison itself (UCM, base) is **MIT-leaning**, but the ecosystem does not mandate it. The
repo's Apache-2.0 default (explicit patent grant) stands — no S9-override case (MIT preference
is a lean, not a mandate; Apache-2.0 is a strictly broader grant).

## Spec version: v0.8.0 (V8), codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v0.8.0` (read directly, spec-first). The **core
wire contract is byte-unchanged across the V7→V8 cutover** (per `spec-data/v0.8.0/MANIFEST.md`
— the folded increments were verdict-timestamp determinism, extension type-path renames, and
release-prep, no core map-key/wire change). The **agility (Ed448/SHA-384) corpus is OUT OF
SCOPE** for this peer's gate (Ed448 deferred, A-UN-001). The §7a validate handlers + §7b
concurrency gate come from `GUIDE-CONFORMANCE.md` + the generator menu (not spec-data), picked
up at S3/S4. The Ed25519 **peer_id** derives from the **§1.5 canonical-form table** (key_type
0x01, hash_type 0x00 identity-multihash, digest = raw 32-byte pubkey) — corroborating the
reconciled form (A-OC-007 / A-ZIG-001 / A-CL-002), not the stale SHA256(pubkey) §7.4 skeleton
(A-UN-008).

## Spec-first observations (no NEW spec defects found at S1)

Reading v0.8.0 for profile-relevant facts surfaced no new spec contradiction. The peer-id
§7.4-vs-§1.5 tension is reconciled in-body; Unison corroborates it. The CBOR canonical rules
(§2.2 length-then-lex map ordering over encoded bytes, shortest-float incl. f16, §6.3 recursive
tag-reject) read unambiguously. The Unison-specific mapping judgments — fixed-width head form
(A-UN-003), `Text`-byte-vs-codepoint (use `Text.toUtf8` byte length), builtins-only floor
(A-UN-002), abilities concurrency (A-UN-004) — are generation-discipline calls, not spec
ambiguities. As expected for a coverage/generator-robustness peer on a dry wire surface, the
value is the headless content-addressed-codebase build proof + the no-C-FFI crypto-spectrum
datum + the abilities concurrency-taxonomy datum, not new wire findings.
