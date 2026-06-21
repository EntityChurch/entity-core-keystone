# entity-core-protocol-swift — Profile Rationale

Audit trail for every major S1 profile choice. Swift is **peer #7**, a
*genuinely-spec-first* peer derived from the freshly-stamped `spec-data/v7.74`
snapshot (read directly — protocol meaning was NOT cribbed from the C#/TS/OCaml/Zig/
Elixir/CL source; only sibling *profiles* were consulted for structure). Swift was
chosen to probe the two discovery axes the six-peer synthesis left unsaturated: the
**`String` grapheme/non-integer-indexable model** (highest fresh yield — the
A-CL-009 hex-case finding proved the encoding/string axis is live) and **ARC** (the
3rd memory discipline after GC and manual/no-GC). Where a value matches a prior peer
it is by independent arrival; the idiom seams deliberately differ.

## Pinned Swift version: 6.2-RELEASE

Swift moves fast (6.3.2 is the current head as of authoring), so the version is
pinned exactly and the whole peer is designed against one release. **6.2-RELEASE**
(~9 months old) is chosen over
the newer 6.3.x line: 6.2 is a settled `.0`-rooted release with a stable Linux
Foundation + swift-crypto stack, comfortably clears the S11 ≥30-day cool-down, and
ships native async/await + actors + Swift-6 strict concurrency. The newer 6.3.2 would
also clear the floor numerically but is the fresher line; the conservative settled
release is the right pin for a conformance-bearing peer. The toolchain is the
Swift.org **fedora39** tarball — verified by detached GPG signature (Swift 6.x
Release Signing Key, fingerprint `52BB 7E3D…EF80 A866 B47A 981F`) **and** an exact
sha256 pin (`4bcec3ee…4508`), fail-closed on either. The fedora39 build runs on
`fedora:43`'s newer glibc (Swift's Linux toolchain is built against an older glibc and
is forward-compatible) — this was **build-proven at S1**, not assumed.

## Codec strategy: native (lighter than ffi — crypto is the audited swift-crypto)

LANDSCAPE tiering had pencilled Swift toward `ffi` (the original "Apple ecosystem
(FFI codec)" note), but the same **A-005 pattern** every prior native peer hit (6-for-6)
overturns that: a faithful ECF codec must own the canonical layer — length-then-lex
map-key ordering on encoded key bytes, shortest-float incl. f16, recursive
major-type-6 tag rejection on decode, full uint64/nint range, raw-byte fidelity —
regardless of any CBOR library underneath, so a library buys almost nothing. With
**swift-crypto** supplying audited, BoringSSL-backed Ed25519 + SHA-2 natively on
Linux, `native` is the strictly lighter path (one audited crypto dependency, no FFI
boundary). `ffi` remains the documented fallback, and a **hybrid** (native Ed25519 +
FFI Ed448) is the likely shape if/when crypto-agility is in scope — exactly the
resolved OCaml A-OC-002 hybrid. The cheap codec spike (push `map_keys` + `float`
vectors through the hand-rolled encoder) runs at S2 start per PHASE-S1-PROFILE; the
crypto+toolchain spike already ran at S1 (below).

## CBOR: hand-rolled (no Swift library) — and the String trap

Swift has **no std CBOR**, and `SwiftCBOR` / other community libs do not offer ECF's
deterministic guarantees (the recurring survey result — cannot type-distinguish float
`1.0` from int `1`, no length-then-lexicographic key ordering, no recursive tag
rejection). Hand-rolling (`Sources/.../CBOR`) is both the faithful and the simpler
path. The **Swift-specific sharp edge** — the reason this peer exists — is the
`String` model: `String.count` is **grapheme clusters**, not bytes, and `String` is
not `Int`-indexable. The ECF text-string (major type 3) length is the **UTF-8 byte
count** (`ENTITY-CBOR-ENCODING §2.1`: "Length in bytes (UTF-8)"), so the encoder MUST
use `String.utf8.count`, never `String.count` — these differ for any non-ASCII text
(the S1 spike showed `"café".count == 4` but `.utf8.count == 5`). Likewise the
map-key sort (§2.2 Rule 2: "sorted by encoded length, then lexicographically") MUST
order over the **encoded UTF-8 key bytes** (`[UInt8]` comparison), never Swift's
`String` comparison (which is Unicode-canonical / locale-aware and would reorder keys
vs the wire). The whole codec works in `[UInt8]` / `String.utf8` on the wire path,
treating `String` purely as a UTF-8 carrier. This is the single highest-value probe
surface for peer #7. Logged as A-SW-002.

## Crypto: swift-crypto Curve25519.Signing (Ed25519) + SHA256/384/512

**`swift-crypto`** (github.com/apple/swift-crypto) is Apple's open-source, audited,
BoringSSL-backed implementation of the exact CryptoKit API, **supported on Linux** —
this is the correct choice because **CryptoKit itself is Apple-platforms-only and is
NOT available in the fedora:43 container** (A-SW-003). It provides
`Curve25519.Signing.PrivateKey`/`PublicKey` (= Ed25519, RFC-8032 deterministic:
`try sk.signature(for:)` needs no RNG), and `SHA256`/`SHA384`/`SHA512`. One audited
SwiftPM dependency (analogous to OCaml's mirage-crypto / TS's @noble). Pinned exactly
to **3.14.0** (~10 months old; clears S11). Crucially,
swift-crypto **vendors BoringSSL and compiles it from source** — there is no system
OpenSSL crypto dependency (good for supply-chain + reproducibility). **All of this was
build-proven at S1** (the spike below).

## Ed448: deferred — native gap (A-SW-001)

swift-crypto / BoringSSL does **not** expose Ed448 (BoringSSL omits it; CryptoKit has
no Ed448 surface), and there is no audited pure-Swift Ed448. This is the **same gap**
OCaml hit (A-OC-002, resolved via hybrid FFI) and Zig deferred (A-ZIG-002). The
ECF/Ed25519 conformance floor is unaffected — `key_type 0x02` is the crypto-agility
*higher bar*, not the §9.1 floor (`key_type 0x01` Ed25519 + `content_hash_format 0x00`
SHA-256). Deferred with a documented escalation rather than a silent gap or unaudited
hand-roll. The likely shape when agility is required: **hybrid** native-Ed25519 +
FFI-Ed448 — consume `libentitycore_codec` (the C-ABI v1.1 `ec_ed448_*` primitives)
for the Ed448 family only, exactly the resolved OCaml hybrid. Swift's C interop is
first-class (a C system-library SwiftPM target + module map over `entitycore_codec.h`),
so this is a natural — arguably clean — fit.

## Hash: swift-crypto SHA256 (+ SHA384/512 for agility)

`SHA256.hash(data:)` is the content_hash floor (`content_hash_format 0x00`);
`SHA384`/`SHA512` are present in the same library for agility hashing (validated at S1:
`SHA384.hash(data: Data())` returns a 48-byte digest). Same dependency as Ed25519 — no
separate pin. Foundation has no SHA-2, so swift-crypto is the idiomatic Linux source.

## Base58 + varint: hand-rolled

Both are small and absent from std/swift-crypto. Base58 (Bitcoin alphabet, encode +
decode) for `peer_id` (§7.4 `base58_encode(varint(key_type) || varint(hash_type) ||
digest)`); multicodec-style LEB128 varints for the §7.3 `key_type`/`hash_type`/
format-code framing (all current codes are single-byte ≤ 0x7F, but the varint shape is
implemented for forward-compat beyond 0x7F). Hand-rolling matches the
dependency-minimization stance.

## Error model: typed `throws` (Swift-native; distinct from prior peers)

Swift's primary error model is **`throws` + an `Error`-conforming enum + do/catch** —
NOT exceptions in the unwind-the-stack C#/Java sense (Swift `throws` is checked, typed,
value-shaped control flow the compiler tracks) and NOT panics. Codec/decode failures
throw a `CodecError` enum with one case per rejection condition (`.nonCanonicalECF`,
`.tagRejected`, `.duplicateKey`, …); protocol-status failures map a case → status code
(400/401/403) at the module boundary. `Result<Success, Failure>` is reserved for
**stored/async outcomes** per Swift idiom — not the primary synchronous codec return.
Swift 6's **typed throws** (`throws(CodecError)`) gives compiler-checked exhaustiveness
on the codec surface (closest Swift analog to Zig's exhaustive error-set switch); it is
*preferred if clean*, with untyped `throws` as the fallback if typed-throws ergonomics
fight the design (decided at S2). This idiom seam differs from C#/TS exceptions, OCaml's
`result` ADT, Zig's error union, Elixir's `{:ok,_}`/`{:error,_}`, and CL conditions.

## Memory: ARC + value-type-default (the headline Swift seam)

Swift uses **Automatic Reference Counting** — the 3rd distinct discipline after the
GC'd peers (C#/TS/OCaml/Elixir/CL) and Zig's manual/no-GC. ARC is deterministic and
non-tracing: a `class` instance's refcount hitting zero runs `deinit` immediately;
value types (`struct`/`enum`) are copied/moved with no refcount. The codec design
stance: **value types by default** (`Entity`, `ContentHash`, `PeerID`, `CBORValue`,
`CodecError` are all `struct`/`enum`) — copy semantics, no shared mutable state, no
possible retain cycles, and `Sendable`-clean for Swift 6 strict concurrency. This
matches the codec's pure/immutable data model and is the idiomatic Swift default.
`class` (ARC-managed reference type) is reserved for genuine shared-mutable identity
at S3 (the live `Peer`/connection object, the store). The ARC-specific watch surface —
**retain-cycle leaks** — therefore lives at S3 (the connection/handler graph + capturing
closures, where `weak`/`unowned` matter), not in the value-type codec, which is
cycle-free by construction. Unlike Zig, ARC means free-correctness is mostly automatic
(no explicit allocator threading), but unlike a tracing GC it is *deterministic* and
*cycle-vulnerable* — a genuinely new point on the memory axis. Logged as the ARC probe.

## Async: native async/await + actors (deliberate; not exercised by the codec)

Swift has first-class **async/await + structured concurrency + actors** (5.5+; Swift 6
adds compile-time data-race checking by default). The codec (S2) is pure + synchronous
+ `Sendable`, so async is **not exercised at S2**. At the peer (S3), the
§4.8/§6.11 inbound-concurrent-with-outbound requirement, the §6.13b handler outbound
closure, and the §7a `dispatch-outbound` **reentry** surface fit async/await + actors
naturally: an `actor` owns per-connection state and serializes mutation (the
data-race-free analog of OCaml's per-thread-dispatch + mutex and Zig's
`std.Thread.Mutex`), and request_id↔continuation correlation uses
`withCheckedThrowingContinuation` / an async demux. This is a cleaner concurrency story
than any prior peer (the compiler proves data-race freedom). Final shape decided at S3;
idiom recorded now.

## Naming: Swift API Design Guidelines

`UpperCamelCase` types/protocols/enums, `lowerCamelCase` funcs/properties/locals/
constants (Swift uses `lowerCamelCase` for `let` constants — **not** SCREAMING_SNAKE),
`lowerCamelCase` enum cases. **Acronyms/initialisms are cased as a unit** per the
Guidelines: `PeerID` (type), `peerID` (property — leading initialism lowercased),
`encodeECF` — never `PeerId`/`peerId`. Files named after the primary type
(`CBOR.swift`, `PeerID.swift`, `ContentHash.swift`). Differs from every prior peer's
convention; the correct Swift idiom.

## Build / test / packaging: SwiftPM + XCTest + git-tag publishing

**SwiftPM** (`Package.swift`, `swift build`/`swift test`) is the universal Swift build
system; no external tool. Tests use **XCTest** — the toolchain-bundled, zero-extra-
dependency framework — over the newer swift-testing (which IS toolchain-bundled in 6.2
and increasingly idiomatic, but XCTest is the longest-settled dependency-free default;
swift-testing is recorded as the documented alternative in A-SW-004, revisitable at S2
since it clears S11 via the toolchain pin). Swift has **no central binary registry**:
SwiftPM resolves from git URL + semver tag (Swift Package Index is discovery-only over
git), so "publishing" is a git tag consumers pin by URL + exact version —
decentralized + git-pinned by design, a supply-chain-friendly property shared with
crates/zig. The committed **`Package.resolved`** is the S11 lockfile (locks
swift-crypto + swift-asn1 by exact revision).

## Supply chain: the swift-asn1 transitive-pin finding (A-SW-005)

swift-crypto 3.14.0 transitively depends on **swift-asn1** via a version *range*, and
SwiftPM auto-resolves it to the newest matching tag — **1.7.1**,
which is only **6 days old** and **violates the S11 ≥30-day
cool-down**. This is exactly the supply-chain hazard S11 exists to catch. The profile
**pins swift-asn1 explicitly to 1.7.0** (~59 days old — clears
the floor), and S1 verified that the explicit 1.7.0 pin satisfies swift-crypto 3.14.0's
constraint and resolves cleanly. The committed `Package.resolved` then locks both. This
is the keystone payoff in miniature: a transitive range dependency is the easy place to
breach the cool-down, and an explicit older pin is the fix.

## License: Apache-2.0 (S9 default + ecosystem-norm)

Swift's own toolchain is **Apache-2.0** (with the Swift runtime-library exception), and
the package ecosystem is Apache/MIT-mixed without mandating either. The repo's
Apache-2.0 default (explicit patent grant) stands — and here it is *also* the
ecosystem-norm choice (it matches Swift's own license), so no S9-override case arises.

## Container: containers/swift-toolchain/Containerfile — BUILT + spike-verified at S1

`fedora:43` base + the Swift.org **6.2-RELEASE fedora39 tarball**, GPG-signature-verified
against the imported Swift project keys **and** sha256-pinned, fail-closed, installed to
`/opt/swift`. Fedora ships no `swift` rpm, so the official tarball is the only route;
pinning + cryptographic verification mirrors the zig-toolchain pattern adapted to
Swift's distro-tarball distribution. Per the S1 task contract for this peer (Swift-on-
Fedora is the long pole), the container was **built and proven NOW**, not just authored:
`swift --version` prints `Swift version 6.2` on the fedora:43 base, a trivial Swift
program compiles + runs, and a throwaway SwiftPM package depending on the pinned
swift-crypto 3.14.0 **builds and runs** `SHA256`/`SHA384`/`Curve25519.Signing` (Ed25519)
correctly (`sha256(hello)` matches the known digest; Ed25519 sign+verify returns true).
The offline-after-resolve claim is also proven: once `Package.resolved` is committed and
`.build` populated, `swift build` runs under `--network=none`. The network is needed only
for the toolchain pull + the one-time swift-crypto/swift-asn1 resolve.

## Spec version: read v7.74, codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.74` (the freshly-stamped snapshot
Swift was gated on — A-CL-001 — so it derives this surface independently). The codec
uses the `test-vectors/v0.8.0` ECF corpus: `ENTITY-CBOR-ENCODING.md` is byte-stable
across the v7.71→v7.74 line except the v7.73 **E3** construct-vs-decode erratum
paragraph (a decode-side clarification, **no wire change** — confirmed in the v7.74
MANIFEST), so the v0.8.0 corpus is valid at v7.74 (the same finding the OCaml/Zig peers
SHA-verified). The §7a conformance handlers + §7b concurrency gate come from
`GUIDE-CONFORMANCE.md` + the generator menu, **not** spec-data (per the v7.74 MANIFEST
note), and Swift picks them up at S3/S4.

## What Swift will likely surface that other peers didn't

Carried forward as S2/S3 watch-items (the reason peer #7 is worth generating):

1. **String byte-vs-grapheme boundary (the headline).** Every wire length and every
   map-key sort MUST run on `String.utf8` ([UInt8]), never `String.count` /
   `String` ordering. Non-ASCII keys/values and the lowercase-hex `peer_id`/digest
   display surfaces (§7.4, and the A-CL-009 hex-case neighborhood) are where a
   grapheme-vs-byte or `String`-comparison slip would diverge from the wire. Highest
   fresh-yield axis; the codec is designed to keep `String` strictly a UTF-8 carrier.
2. **ARC + value-vs-reference + retain cycles.** Value-type codec is cycle-free by
   construction (a genuinely different shape from GC and from Zig's allocator
   threading); the ARC watch surface (weak/unowned, capturing closures) lands at S3 on
   the Peer/connection/handler graph. Worth capturing whether the §6.11 reentry
   closure introduces a retain cycle the other peers' memory models hid.
3. **Swift-6 strict concurrency / Sendable.** The codec value types must be `Sendable`
   and the S3 actor model must pass compile-time data-race checking — a stronger
   static guarantee than any prior peer's concurrency model. Watch whether the §7a
   reentry / request_id correlation fits `withCheckedThrowingContinuation` cleanly.
4. **Typed throws exhaustiveness.** `throws(CodecError)` gives a compiler-checked,
   total set of rejection conditions on the decode path (Swift analog to Zig's
   exhaustive error-set switch) — worth capturing as reusable Swift generator guidance
   if it holds up ergonomically at S2.
5. **The swift-asn1 transitive cool-down breach (already surfaced).** A-SW-005 — a
   range-resolved transitive dep landed inside the 30-day window; the explicit older
   pin is the generator pattern to carry to any future SwiftPM peer.
