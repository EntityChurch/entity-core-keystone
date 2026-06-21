# entity-core-protocol-rust — Profile Rationale

Audit trail for every major S1 profile choice for the **Rust** peer. This is the
document a future operator reads to answer "why did we pick X for Rust?".

## ⚠️ Clean-room constraint (the defining property of this peer)

**Rust has a hand-written reference sibling.** Two of them, in fact:
`entity-core-rust` (a full hand-authored Rust peer) and `entity-core-codec-ffi-rust`
(the FFI codec that builds `libentitycore_codec`). This generated peer —
`entity-core-protocol-rust` — is **distinct from both**, and its *entire value* is
being an **independent clean-room reimplementation from the specification**, not a
copy of either sibling.

This is **exactly the go peer's situation**, which is why the brief named go as the
closest analog: Go also has a hand-written reference sibling (`entity-core-go`, which
is *additionally* the conformance oracle). The framing therefore mirrors go's:
**adoption value + an independence cross-check on the generator, NOT spec discovery.**
The 8-peer synthesis already established the spec-discovery well is dry and the v7.75
surface is tight; a peer in a language that already has a hand-written reference is the
*last* place to expect a novel spec finding (its idiom overlaps the sibling's).

How I honored the clean-room rule while authoring S1:

- I read **only**: `spec-data/v7.75` (the SHA-pinned verbatim V7 snapshot —
  `ENTITY-CORE-PROTOCOL-V7.md`, `ENTITY-CBOR-ENCODING.md`,
  `ENTITY-NATIVE-TYPE-SYSTEM.md` + `MANIFEST.md`), the keystone `shared/lifecycle`
  contracts (`PROMPT-CONSTANTS.md`, `PHASE-S1-PROFILE.md`), the cohort's
  **language-neutral** sibling profiles (`go/`, `csharp/`, `typescript/` +
  `go/arch/PROFILE-RATIONALE.md`), the `shared/seed-policy/` convention, the existing
  `containers/cargo/Containerfile` (the FFI codec's container, to confirm it is NOT the
  right base for the peer), the `containers/swift-toolchain` / `containers/ghc-toolchain`
  shape (for the native-peer Containerfile pattern), and the seeded cohort memory.
- I did **NOT** open, read, `cat`, `grep`, `find`, or otherwise reference any file
  under `entity-core-rust` or `entity-core-codec-ffi-rust` — not their codec, not their
  crypto, not their `Cargo.toml`. Every protocol-shaped decision below grounds in a
  **V7 §-pointer** from the spec snapshot, never in sibling source.
- The Rust *language idioms* recorded here (audited `ed25519-dalek` + `sha2`,
  hand-rolled canonical CBOR, `std::thread` + `Mutex` store, `Result<T, E>` + `?`,
  rustfmt/clippy naming) are derived from **general Rust ecosystem knowledge** and the
  spec's requirements — what *any* competent Rust engineer would reach for, not what I
  observed a sibling doing.

The clean-room rule is about **build-time source isolation**. It does **not** forbid
the S4 step of validating this peer's *output bytes* against the go oracle — that
byte-comparison is exactly how conformance is proven and is allowed (oracle commit
`e8524ed` recorded in the profile `[spec]` block for that S4 leg). One subtle point
for the future Ed448-FFI seam: the FFI codec building `libentitycore_codec` is *itself*
a Rust crate (`entity-core-codec-ffi-rust`), but consuming it here is **FFI over the
C-ABI** like any other peer — we link `libentitycore_codec` via `extern "C"` and read
provenance via `ec_impl_info()`; we do **not** in-process link the sibling's Rust
source. The clean-room boundary is preserved.

### Honest limited-signal caveat (required by the brief, go-peer pattern)

Because **this peer's idiom necessarily overlaps the hand-written sibling's** (both are
Rust, both reach for the same audited `ed25519-dalek`/`sha2`, the same hand-rolled
canonical CBOR shape, the same ownership-model concurrency), the **spec-refinement
signal from this peer is inherently bounded** — same accounting the go peer made. A
*distant-idiom* peer (OCaml's 63-bit-int trap, Zig's no-GC error-union, Lean's proof
track) stresses the spec along an axis the reference impl never exercised and tends to
*discover* latent ambiguities; a same-language-as-a-reference peer cannot do that as
effectively. So the value proposition is deliberately narrower and honestly stated:

1. **Independent cross-check** — a from-scratch Rust impl that lands byte-identical to
   the oracle on the full corpus is genuine corroboration that the *spec*, not some
   sibling-private convention, determines the bytes. It catches the failure mode "the
   behavior is under-specified and only the existing Rust impl knows the convention."
2. **Adoption / idiom completeness** — it fills the Rust slot in the cohort's idiom
   matrix with a *generated-from-spec* peer, so the generator's Rust output is exercised
   end-to-end rather than assumed. Rust is a high-adoption target for a content-addressed
   protocol substrate; a clean generated peer is directly adoption-valuable.

What it is **NOT** expected to produce: a rich crop of net-new spec findings. If it
surfaces one, that is a bonus; the plan does not bank on it. (Cohort precedent: the
genuine discoveries came from OCaml/Zig/Lean/CL distant-idiom seams, not from
same-as-a-reference arrivals.)

## Codec strategy: native

The LANDSCAPE default for a language with mature audited crypto + no canonical-CBOR gap
is `native`, and Rust qualifies as cleanly as any peer in the cohort — arguably the
cleanest. The deciding reasoning is the **A-005 pattern** every prior native peer
(C#/TS/OCaml/Elixir/Zig/CL/Swift/Haskell/Go) independently re-confirmed: a faithful ECF
codec must **own the canonical layer** regardless of any CBOR library, because ECF's
guarantees are stricter than any general library's "deterministic" mode:

- **Rule 2** — map keys sorted by **encoded byte length, then lexicographically**
  (RFC-7049-style length-first, which DIFFERS from RFC-8949 §4.2 plain-bytewise that
  many libs — including `ciborium`'s canonical mode — call "canonical": a real trap).
- **Rule 3** — definite lengths only.
- **Rule 4 / 4a** — shortest-float including **float16**, with exact special-value bytes
  (NaN `F9 7E00`, -0.0 `F9 8000`, +Inf `F9 7C00`, -Inf `F9 FC00`), enforced on **decode**
  as well as encode (a received non-minimal float is non-canonical).
- **Rule 5** — no duplicate map keys (decode rejects).
- **§6.3** — recursive **major-type-6 (tag) rejection** anywhere inside a `data` field at
  any nesting depth → `400 non_canonical_ecf`.
- Full **uint64 / nint** range (the `int.10/15/16/17` corpus, `[2^63, 2^64-1]`).
- Raw-byte fidelity for the **arbitrary-ECF `data` field**.

A library either omits these or actively fights them, so it buys almost nothing — and a
content-addressing substrate must **own + prove** byte-exactness vector-by-vector, not
delegate it. Rust *also* has the cohort's cleanest native crypto + integer story
(audited `ed25519-dalek` + `sha2`; native `u64`/`i64`/`u128`), so native is also the
**lighter** path. `ffi` (consume `libentitycore_codec`) remains the documented fallback
but is not expected. Per PHASE-S1-PROFILE, the S2 build opens with a **spike**: push the
`map_keys.*` + `float.*` + `tag_reject.*` vectors through the hand-rolled encoder/decoder
before the full build — cheap insurance; `ffi` is the fallback if it fails.

## CBOR: hand-rolled (`ciborium` et al. considered and rejected)

Rust's std has **no CBOR**. Surveyed third-party candidates, all **rejected for the core
codec** (logged A-RUST-001):

1. **`ciborium`** (CryptoCorrosion/enarx) — the most credible. It has a canonical mode,
   but it targets **RFC-8949 §4.2 bytewise** map ordering, **not** ECF's Rule-2
   length-then-lex; it does **not** enforce decode-side shortest-float minimality; it
   does **not** do recursive §6.3 tag rejection returning the specific
   `400 non_canonical_ecf`; raw-byte `data` fidelity is not its contract. Every ECF
   guarantee would have to be hand-written **on top of** it — at which point it is doing
   what the hand-roll already does, plus a registry pin.
2. **`serde_cbor`** — **deprecated / unmaintained**; a non-starter on supply-chain
   grounds (S11) regardless of capability.
3. **`minicbor` / `cbor4ii`** — lean and well-made, but same canonical-layer gaps.

Decision: **hand-roll** a ~600-line canonical encoder/decoder (a private `cbor` module),
**no `serde` dependency**, no registry pin for the codec core, byte-exactness owned +
proven vector-by-vector. Decode is explicit major-type switching on the head byte — the
idiomatic Rust wire-parse shape (a `match` on the initial byte). The bar for a future
maintainer to swap a library in is explicit in the profile: prove it reproduces
`map_keys.*` / `float.*` / `tag_reject.*` byte-for-byte **and** enforces decode-side
rejection.

## Crypto: ed25519-dalek 2.2.0 + sha2 0.10.9

**Ed25519 — `ed25519-dalek` 2.2.0** (dalek-cryptography; the de-facto audited pure-Rust
Ed25519, RFC-8032). Deterministic signing by construction (no RNG needed to sign,
matching §7.3); keygen via `OsRng`. ~11 months old — clears the S11 ≥30-day registry
cool-down comfortably. It pulls
`curve25519-dalek` (the field arithmetic), `signature`, and `ed25519` — the full
transitive closure is pinned exactly in the committed `Cargo.lock` at S2, each verified
≥30 days old. Note: `curve25519-dalek` **4.1.3** is the version to pin —
**4.2.0 was YANKED**, and **5.0.0 is pre-release only** (5.0.0-rc.0), so
4.1.3 is the correct stable pin (S2 lock will reflect this; the yank is the kind of
supply-chain event the 30-day floor exists to dodge, and here it argues for the older
stable line explicitly).

**SHA-256 + SHA-384 — `sha2` 0.10.9** (RustCrypto). SHA-256 is the `content_hash`
**floor**; the **same crate** provides SHA-384 (`sha2::Sha384`), so **agility hashing is
NATIVE** — no extra dependency for the hash-format agility seam. ~13 months old —
clears the floor. I chose the **0.10.x stable line** over the new
**0.11.0** major (~3 months old): 0.11.0 *would* clear the 30-day floor, but
it is a fresh major-version API break on a fresh release, and the 0.10.x line is the
settled, widely-depended-on series; re-pin to 0.11 deliberately if a phase wants it.

**No `ring`, no libsodium binding.** `ring` was considered (audited, fast) but rejected:
it is a larger, assembly-heavy dependency, its Ed25519 API is less ergonomic for the
keygen-from-seed path the §7.3 peer-id construction needs, and the pure-Rust dalek + sha2
stack is the cohort-idiomatic, dep-minimal, `#![forbid(unsafe_code)]`-compatible choice
for the *core* (Ed25519 + SHA-256) surface.

## Ed448: deferred — native-full-agility is NOT cleanly reachable (A-RUST-002)

This is the **headline crypto finding** and it answers the brief's explicit question.
**Native-full-agility including Ed448 is NOT reachable for Rust the way it was for
Haskell (crypton).** The survey:

- **RustCrypto `ed448-goldilocks`** — the "right" home for Ed448 in Rust. Its **Ed448
  signing/verification API exists ONLY in the `0.14.0-pre` PRERELEASE series**
  (`0.14.0-pre.13`, `-pre.12`, …). This fails S11 two ways:
  (a) it is a **pre-release** (no pinned-stable version), and (b) RustCrypto's own
  README states the code **"has NOT been audited — USE AT YOUR OWN RISK."** The latest
  **stable** `ed448-goldilocks` is **0.9.0 (2023)**, which predates the signing API
  entirely (curve group ops only).
- **`ed448-goldilocks-plus`** — a third-party fork (maintainer Michael Lodder, BSD-3).
  **0.16.0** **is** stable and **does** have Ed448 signing. But it is a
  **single-maintainer fork**, unaudited, outside the RustCrypto review channel — the
  same risk class as an unaudited hand-roll, just shaped as a registry crate.

So Rust matches the **Go (A-GO-002) / Zig (A-ZIG-002) / OCaml (A-OC-002) / Swift native
gap** — the "audited native Ed448 in a reviewed channel" route does **not** exist for
Rust today. **Haskell's crypton was the exception, not the rule;** the cohort's crypto-
availability spectrum places Rust in the **gap → hybrid-FFI** band, not the
native-full-agility band. **Ed448 is DEFERRED** (A-RUST-002) with a documented
escalation, not a silent gap or an unaudited pin. The decision does **not** affect the
Ed25519 + SHA-256 conformance floor (§9.1; the `--profile core` target is Ed25519 +
SHA-256 only — Ed448 is *validated*, not *required*).

The **likely shape when agility is in scope**: **hybrid** native-Ed25519 + **FFI-Ed448**
(consume `libentitycore_codec`'s `ec_ed448_{seed_to_pubkey,sign,verify}` over the C-ABI
v1.1, the route OCaml took with its opt-in `entitycore_agility` sub-library). Rust's
`extern "C"` FFI is first-class, so this is a natural fit, isolated to one opt-in module
(the only place `unsafe` is needed; the core stays `#![forbid(unsafe_code)]`). **SHA-384
agility hashing, by contrast, IS native** via `sha2::Sha384` — only the Ed448 *signature*
family is the FFI gap. A future revisit should re-check whether `ed448-goldilocks` has
reached a **stable, audited** release (the `0.14.0` line graduating out of `-pre` with an
audit would flip this to native-full-agility like Haskell).

## Base58 + varint: hand-rolled

Both are small and absent from std. Base58 (Bitcoin alphabet, encode + decode) for
`peer_id`; multicodec-style LEB128 varints for the §1.5 / §7.3 `key_type` / `hash_type`
framing (with explicit non-minimal-varint rejection + multi-byte continuation for code
allocations beyond `0x7F`). The `bs58` and `leb128` crates were considered and rejected
for **dep-minimization** — the same call C#/Go made. Hand-rolling matches the
crate-minimal stance and keeps the codec core registry-pin-free.

## Error model: `Result<T, E>` + `?`, hand-written error enums

Rust-native error handling is **`Result<T, E>` with the `?` operator** — the **canonical**
form of the cohort taxonomy's `result` style (Go spells it `(T, error)`; Rust spells it
`Result<T, E>` + ADT error enums). The language has **no exceptions**; `panic!` is
reserved for true programmer-error / unreachable invariants and is caught at the
connection-task boundary (`std::panic::catch_unwind` / task isolation) so one bad
connection never crashes the peer (the §4.9 no-crash floor). Codec failures are an **error
enum** with one variant per discriminable case; **exhaustive `match`** on the enum is
Rust's native form of an ADT verdict (the OCaml/Lean ADT shape, but a first-class language
feature here — the compiler enforces exhaustiveness). At the dispatcher boundary a typed
variant maps to a protocol status:

- `400 non_canonical_ecf` ← tag / canonical-rule violation (§6.3).
- **`400 chain_depth_exceeded`** ← over-deep capability chain (§4.10(b)) — **NOT 403**.
  Pre-resolved cohort trap: a too-deep chain is a *structural excess*, not an authz
  denial; a `chain_exceeds_depth` structural pre-check (walks parents, no signature work,
  max from the §4.10 recommended default 64) runs **before** the authz walk; an
  *unreachable* parent stays 403.
- `401` ← `identity_mismatch` (§4.6 handshake binding) and the `unresolvable_grantee`
  carve-out on the authz path (§5.2 / §5.2a trichotomy: `ALLOW` / `AUTH_DENY` 401 /
  `AUTHZ_DENY` 403 default).
- `403 capability_denied` ← `AUTHZ_DENY` default (§5.2a verdict-to-status table).
- `413 payload_too_large` ← inbound EXECUTE wire size over the configured max (§4.10(a)).

**No `thiserror`, no `anyhow`** in the core peer (dep-minimization) — the error surface is
small and fixed, so hand-written `Display`/`Error` impls are cheaper than a registry pin.

## Concurrency: std::thread + Mutex store (NOT async/tokio)

Rust offers both threaded and async concurrency. For the **core peer** the decision is
**`std::thread` + `std::sync` (blocking `std::net`, thread-per-connection)** — **not**
`tokio`/`async-std`. The reasoning is dep-minimization: `tokio` is a large transitive
closure (dozens of crates) against the repo's supply-chain stance, and the §6.11 /
§7b surface — one reader thread demultiplexing `EXECUTE_RESPONSE` by `request_id`,
inbound-concurrent-with-outbound, a data-race-safe store under load — is fully met by
threads + channels (`mpsc`) without it. The codec (S2) is pure synchronous. Async is a
**future opt-in**, logged as an idiom note (A-RUST-003), not a blocker.

The §7b traps are pre-resolved in the profile:

1. **Store-safety (§4.8) is enforced by the type system.** This is Rust's **strongest
   story in the cohort**: a shared-mutable store *without* a lock is a **compile error**
   (`Send`/`Sync` bounds), so the store-race that bit **Zig (double-free PANIC) and
   Common-Lisp (500s)** at the §7b T2.1 sustained-load probe is **structurally
   unrepresentable** — the borrow checker is the gate. `Mutex<HashMap>` is the
   simple-correct default; `RwLock` if read-mostly profiling ever shows it matters.
   Discipline: copy-out under the lock, do I/O outside it (never hold the lock across a
   syscall) — but even forgetting that is a deadlock at worst, never a data race.
2. **TCP_NODELAY.** `TcpStream::set_nodelay(true)` on **every** accepted/dialed
   connection. Nagle + delayed-ACK on small frames was *the* §7b throughput killer for
   Zig (62s → 1.9s). Set from the start.
3. **No bounded cooperative pool to starve.** Thread-per-conn means the Swift
   cooperative-pool / blocking-syscall trap doesn't apply; the OS scheduler handles
   blocking `recv`/`accept`.

## Integers: native u64 / i64 (the clean int story)

Rust has native fixed-width `u64`/`i64` (and `u128`/`i128` if ever needed), so the §3.2
full `uint`/`nint` range (corpus `int.10/15/16/17`, the `[2^63, 2^64-1]` band) maps
**directly** onto `u64`/`i64` carriers — **no BigInt ceremony** (contrast TypeScript's F7
always-bigint) and **no 63-bit trap** (contrast OCaml's A-OC-001 native-int loss). The
one watch-item is shared with Go: CBOR `nint` encodes `-1-n`, so the `[-2^64, -1]` band
needs careful `u64`-carrier arithmetic on decode (the additional-info value is `|n|-1`);
handled with explicit `u64` math, captured as an S2 vector check.

## Naming: rustfmt + clippy conventions

`PascalCase` for types/traits/enums/variants, `snake_case` for functions/methods/
variables/modules/files, `SCREAMING_SNAKE_CASE` for `const`/`static` (Rust **does** use
screaming-snake for constants — UNLIKE Go's MixedCaps). The case axis is **type-vs-value,
not exported-vs-unexported** (visibility is `pub`, orthogonal to case — a divergence from
Go/C#). **Initialisms are treated as words** (`PeerId`, `Ecf`, `Cbor`, `Url`, `Tcp` —
**not** `PeerID`/`ECF`/`CBOR`), enforced by `clippy::upper_case_acronyms`. A deliberate,
clippy-driven divergence from the Go/C# all-caps-initialism style. `cargo fmt --check` +
`cargo clippy -D warnings` is the universal Rust lint floor — no external linter.

## Build / test / packaging: cargo + std test + crates.io

`cargo build` / `cargo test` (cargo **is** the build system + package manager; `Cargo.toml`
is the manifest, **`Cargo.lock` is committed** — this is a binary-bearing peer, so the
full transitive closure is locked per S11). Tests use the built-in `#[test]` harness — no
external test framework (the dep-minimization win Zig/Elixir/Go got natively); unit tests
inline under `#[cfg(test)]`, integration/conformance tests in `tests/`, vector corpora as
table-style iterations. **Packaging** target is **crates.io** (`cargo publish`), but the
upload is **deferred** per S10 (all-source-in-repo-until-stabilization); the crate is
parked at **`0.1.0-pre`** (the cohort convention). Edition **2021** (settled), not 2024.

## License: Apache-2.0 (S9 default)

The Rust ecosystem norm is **dual MIT/Apache-2.0**. S9 says a profile MAY override the
Apache-2.0 default for a strong-MIT ecosystem — but Rust's norm is *dual* (Apache-2.0 is
half of it), so the repo's Apache-2.0 default (explicit patent grant) needs **no
override** and stands.

## Container: AUTHORED containers/rust-toolchain/Containerfile (NOT the existing cargo image)

Per the brief, the container is **AUTHORED, not built** (S1 is author-only for this peer —
no podman / build / toolchain execution). I authored a **peer-dedicated**
`containers/rust-toolchain/Containerfile` rather than reusing the existing
`containers/cargo/Containerfile`, because:

- `containers/cargo/` exists for the **FFI codec** (`entity-core-codec-ffi-rust`), a
  different build target with different concerns (cdylib/staticlib + glibc-floor notes).
  Reusing it would couple the protocol-peer build to the FFI codec's image and blur the
  clean-room separation.
- Every native-peer in the cohort has its **own `*-toolchain` image**
  (zig/swift/ocaml/haskell), matching the per-peer container convention.

It is `fedora:43` + the distro `rust`/`cargo` NVR + `gcc` (the linker; also needed for the
future Ed448-FFI `extern "C"` seam), with `CARGO_HOME` on a mountable path so the
conformance loop doesn't refetch crates. **Pin status:** the rust/cargo toolchain comes
through **fedora dnf — a reviewed distro channel** — so per the supply-chain memo the S11
≥30-day age floor **relaxes to "pin exactly for reproducibility"** (the NVR is the pin).
The registry crates (`ed25519-dalek` 2.2.0, `sha2` 0.10.9) **do**
get the ≥30-day discipline and both clear it. Forward note for S2+: after the one-time
`cargo fetch` (network on), the build runs `--offline` / `--network=none` (small closure:
2 direct crates).

## Spec version: read v7.75 (latest snapshot)

Profile + (future) peer derive from `spec-data/v7.75` (the latest SHA-pinned verbatim V7
snapshot — V7 `057dc8eb…`, CBOR 1.5, type-system 4.2.1), which folds the v7.75
non-functional substrate floor (§4.8 store-safety, §4.9 resilience, §4.10 resource
bounds) — all pre-resolved in the `[concurrency]` and `[error_model]` blocks. The S4
conformance target is `--profile core` against the **go oracle** (the brief's pinned
`e8524ed`, re-pin to S4-current if newer) — recorded for the S4 byte-validation leg only
(the clean-room rule permits validating *bytes* against the oracle at S4; it forbids
reading the oracle's *source*, and forbids reading the Rust *siblings'* source, while
building — both honored throughout S1).

## Planned S3 surface (cohort conventions baked in)

Recorded in the profile `[surface]` block so S3 inherits them, all derived from V7 + the
keystone seed-policy convention (NOT sibling source):

- **`--name NAME` persistent identity** — loads the Ed25519 identity from
  `~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed). The cohort
  standardization that makes the multisig accept-path run *genuinely* (not env-skipped).
- **Genuine §3.6 K-of-N multisig** — root-only M3 structure + M4 distinct-signer threshold
  + M6 local-∈-signers; single-sig path a byte-identical strict subset; an accept-path
  unit test (2-of-3 → ALLOW + M3/M4/M6 deny flips) covers the direction the rejection-only
  oracle can't.
- **§6.9a seed-policy bootstrap** — detached-signature self-owner cap at L0 + authenticate
  dual-form lookup ∪ §4.4 floor, via the keystone `shared/seed-policy` convention.
- **§7a conformance handlers** — `system/validate/{echo,dispatch-outbound}`, opt-in
  (`--validate`, OFF by default), dispatch-outbound reentry over the inbound connection
  (§6.11), not a third-peer dial.
