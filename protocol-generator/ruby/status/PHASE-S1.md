# entity-core-protocol-ruby — Phase S1 (Profile) Summary

**Peer #12** (Ruby — first DYNAMIC / DUCK-TYPED / SCRIPTING
peer) · **Status: COMPLETE (authoring-only; no build per S1 boundary)**

## Preconditions resolved at session start
- **Spec version.** `spec-data/v7.75` is a **complete** SHA-pinned snapshot (full
  `ENTITY-CORE-PROTOCOL-V7.md` body present). Profile + codec derive against it.
  The codec specs (`ENTITY-CBOR-ENCODING.md` label 1.5, `ENTITY-NATIVE-TYPE-SYSTEM.md`
  4.2.1) are byte-identical v7.73→v7.75 (MANIFEST SHA-verified), so the wire is
  stable. **Unlike peers #1–8** (which lagged HEAD and reconstructed the
  peer-surface from folded proposal text, A-ELX-001 et al.), Ruby derives the
  entire S1/S2/S3 surface — including the v7.75 §4.8/§4.9/§4.10 substrate floor —
  from ratified spec text. **No snapshot-lag caveat applies.**
- **Settled cohort traps pre-resolved in the profile** (NOT re-burned): §1.5
  peer-id canonical form (hash_type=0x00 identity-multihash, digest = raw pubkey
  for ≤32B keys; the stale §7.4 SHA256(pubkey) skeleton is superseded, per the
  A-SW-008 erratum that has §9.1 cite §1.5); lowercase `%02x` hex tree-paths
  (A-CL-009); §5.2/§5.2a 401/403/401 trichotomy; A-JAVA-010 `data` = arbitrary
  ECF value (NOT a map); §4.10 resource_bounds (chain-depth → **400**
  `chain_depth_exceeded` not 403, default depth 64; payload default 16 MiB → 413);
  §7b concurrency (data-race-safe store, TCP_NODELAY).

## Decisions (all in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** | A-005 pattern (12th): no gem does ECF → hand-roll canonical; crypto native via stdlib openssl |
| CBOR | **hand-rolled** (`lib/entity_core/cbor.rb`) | `cbor`/`cbor-canonical`/`cbor-deterministic` all fall short (see rationale); decoder = byte-cursor over ASCII-8BIT String |
| Ed25519 | **stdlib `openssl`** (OpenSSL 3.x) | native, audited, no gem; `generate_key/sign(nil,..)/verify(nil,..)/raw_*_key` |
| Ed448 | **NATIVE via stdlib `openssl`** | A-RUBY-002 — no FFI (Elixir/Haskell result on a 3rd native-crypto substrate; contrast OCaml hybrid-FFI) |
| SHA-256 / SHA-384/512 | stdlib `digest` + `openssl` | native, no gem |
| base58 / varint | hand-rolled | dep-minimization (zero runtime gem deps) |
| Error model | **exceptions** (`EntityCore::Error` < StandardError) | Ruby idiom; distinct from Elixir tagged-tuple / OCaml result / Zig error-union |
| Concurrency | **thread-per-connection under the GVL** + Mutex-guarded store + TCP_NODELAY | A-RUBY-004 — honest GVL accounting; Ractors declined |
| Naming | PascalCase classes / snake_case methods+vars / SCREAMING_SNAKE consts | Ruby-native; `?`/`!` suffixes |
| Build / test / pkg | Bundler + Rake + **Minitest (stdlib)** + RubyGems | Minitest = zero added dep |
| License | Apache-2.0 | S9 default |
| Container | **official `ruby:3.4.4-slim-bookworm`** | per prompt; ~13mo old (S11-clean); OpenSSL 3.x = Ed25519+Ed448 backend |

## The standout result: fully-native crypto agility, zero runtime gem deps
Ruby's stdlib `openssl` (OpenSSL 3.x backend) reaches Ed25519, **Ed448**, and the
SHA-2 family through one generic `OpenSSL::PKey` surface — so the crypto-agility
HIGHER BAR (KEY-TYPE-ED448-*, HASH-FORMAT-SHA-384-*) is reachable from the default
build with **no FFI, no opt-in sub-library, no second crypto source**. This is the
Elixir headline (vs OCaml's hybrid-FFI Ed448, A-OC-002) and the Haskell
native-full-agility result, **replicated on a 3rd native-crypto substrate**
(Ruby stdlib openssl). Combined with hand-rolled CBOR/base58/varint and stdlib
Minitest, the core peer ships with **zero runtime gem dependencies**.

## Idiom observations worth recording (not ambiguities — language facts)
- **No integer head-form trap.** Ruby `Integer` is arbitrary-precision, so the
  uint64/int64 head-form carrier that bit OCaml (int63→Int64), C# (`ulong`), TS
  (`bigint`) is **just an `Integer`** here — the BEAM result (Elixir #4),
  replicated. Carries the full range with no special-casing.
- **ASCII-8BIT byte discipline.** Wire bytes are ASCII-8BIT (BINARY) `String`s
  (`String#b` / `force_encoding`), never UTF-8 in the codec core — the Ruby
  analogue of TS's Uint8Array-not-Buffer and C#'s byte-span discipline.
- **The dynamic axis is real but well-trodden for the codec.** Duck typing makes
  A-JAVA-010 (`data` = arbitrary ECF value, not a map) natural; open classes /
  metaprogramming are powerful but the codec deliberately avoids depending on
  refinements/monkey-patches (self-contained + portable). `Data.define`
  (immutable value objects, Ruby 3.2+) for envelope/cap-token shapes.

## Container — AUTHORED, NOT BUILT (S1 boundary: no podman/build)
`containers/ruby-toolchain/Containerfile` authored. Pins **official
`ruby:3.4.4-slim-bookworm`** (Ruby 3.4.4, ~13mo old — S11-clean;
slim-bookworm = Debian 12 → OpenSSL 3.0.x, the Ed25519+Ed448+SHA-2 backend).
Includes a **build-time assertion** that round-trips sign/verify on BOTH Ed25519
and Ed448 + checks SHA-384 (fails the build loudly if the bundled OpenSSL lacks
Ed448 — closes the A-RUBY-002 risk at build time). Bundler offline posture set for
`--network=none` dev loops. Core peer has zero runtime gem deps, so no library
pins to mirror. **Build deferred to S2** (S1 is authoring-only); pin the image
*digest* at first pull.

## Ambiguity log
5 entries (A-RUBY-001..005), none blocking:
- **A-RUBY-001** — codec native / CBOR hand-rolled (no gem does ECF). Spike vectors at S2.
- **A-RUBY-002** — Ed448 native via stdlib openssl (overturns ffi default); byte-verify at S2 (container build-time assert is the first gate).
- **A-RUBY-003** — openssl EdDSA API spelling + raw-key method availability; confirm in-container at S2.
- **A-RUBY-004** — thread-per-connection under the GVL + Mutex-guarded store + TCP_NODELAY; Ractors declined. Honest GVL accounting.
- **A-RUBY-005** — RubyGems id `entity_core_protocol` (snake_case); availability checked at S5.

No **new spec-level** ambiguity surfaced — Ruby corroborates the inherited cohort
findings (peer-id §1.5, 401/403 §5.2a, §4.10 resource_bounds, A-JAVA-010
`data`-shape) against the complete v7.75 snapshot rather than re-litigating them.

## Exit criteria
profile.toml fully populated (no TBD-blocking) · rationale written · container
authored + specified (build verified at S2 per the S1 no-build boundary) ·
ambiguity log has no blocking-severity items (A-RUBY-002 Ed448 is native + asserted
at build time, not a gap). **S1 PASS.**

## Honest read: will Ruby hit the codec/crypto bars cleanly?
**Crypto: high confidence.** Ed25519 + Ed448 + SHA-2 are all native via stdlib
`openssl` (OpenSSL 3.x), deterministic by construction, audited via OpenSSL — the
same backend posture that gave Elixir/Haskell clean agility passes. The one
genuine risk is whether the *bundled* OpenSSL build enables Ed448; the container
build-time assertion catches that immediately, and Debian bookworm OpenSSL 3.x
ships it. The only impl wrinkle is API-spelling (`raw_private_key` etc., openssl
gem ≥3.0) — confirmed at S2, conformance-neutral.

**Codec: high confidence, with the usual hand-roll work.** The ECF canonical
layer is hand-rolled — same as all 11 prior peers — and Ruby is well-suited:
arbitrary-precision `Integer` removes the uint64 head-form trap entirely, and
ASCII-8BIT `String` gives clean byte-level cursor work. The one Ruby-specific
care point is the **shortest-float / f16 ladder** (Rule 4 is hand-rolled in every
peer regardless), where bit-exact pack/unpack and NaN/Inf/-0.0 handling via
`Array#pack`/`String#unpack` (`g`/`G`/`e`/`E` directives) need the same care the
BEAM peer flagged (guard f16 overflow → Inf, match NaN/Inf by raw bits). Spike
`map_keys` + `float` at S2 before the full build. **No reason to expect Ruby
misses the codec/crypto bars** — the dynamic axis differs in idiom (exceptions,
GVL threading, duck typing), not in wire capability.

## Next
S2 codec (`--phase codec`): build `EntityCore::Cbor` (hand-rolled canonical ECF,
byte-cursor decoder over ASCII-8BIT) + `EntityCore::Base58` + `EntityCore::Varint`
+ the stdlib-`openssl` crypto shim. **Build the container first** and confirm the
openssl EdDSA arity + raw-key methods (A-RUBY-003); the Ed448 build-time assert
already gates the image. Spike `map_keys` + `float` vectors, then run the full
v7.75 corpus to byte-identity. Because Ed448 is native, the agility slot runs from
the default build at S2 (not deferred).
