# entity-core-protocol-php — Phase S1 (Profile) Summary

**Release "reach" peer** (web-backend ubiquity; slate row 2,
`research/RELEASE-READINESS.md` §2) · **2nd dynamic/scripting peer** (after Ruby
#12) · **Status: COMPLETE (authoring-only; no build/podman/toolchain per S1
boundary)**

## Reach, not discovery — ratify the slate

PHP is **corroboration-only**: the 8-peer synthesis found the spec-discovery well
dry on language axes, and the dynamic/scripting axis was exercised by Ruby. PHP's
value is **REACH** (the enormous web-backend / WordPress / Laravel / Symfony reader
base) + exercising the generator against **PHP idiom**. The S1 job was to make the
already-fixed slate decisions (hand-roll ECF, libsodium/ext-sodium Ed25519, Ed448
gap → FFI/defer, Composer, Apache-2.0) **concrete and idiomatic** — not to reopen
them. No new spec defect is expected (logged honestly if any surfaces).

## Preconditions resolved at session start
- **Spec version.** `spec-data/v7.75` is a complete SHA-pinned snapshot (full
  `ENTITY-CORE-PROTOCOL-V7.md` body). Profile + codec derive against it; the codec
  specs are byte-stable v7.71→v7.75 (MANIFEST SHA-verified), and the core floor is
  byte-stable v7.75→v7.77, so deriving from v7.75 + gating against the current
  oracle is the established cohort convention. **No snapshot-lag caveat.**
- **Settled cohort traps pre-resolved in the profile** (NOT re-burned): §1.5
  peer-id canonical form (hash_type=0x00, raw pubkey for Ed25519; the §7.4 SHA-256
  skeleton is superseded); lowercase `bin2hex` hex tree-paths (A-CL-009);
  §5.2/§5.2a 401/403/401 trichotomy; A-JAVA-010 `data` = arbitrary ECF value (NOT
  an array); §4.10 resource_bounds (chain-depth → **400** chain_depth_exceeded not
  403, default 64; payload 16 MiB → 413); §7b concurrency.

## Decisions (all in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** | A-005 pattern: no PHP lib does ECF → hand-roll canonical; crypto native via ext-sodium |
| CBOR | **hand-rolled** (`src/Cbor.php`) | `spomky-labs/cbor-php` is general RFC-8949 (not ECF-exact, the slate note); decoder = byte-cursor over a binary `string` |
| **uint64 carrier** | **GMP (ext-gmp), uniform** | **THE headline codec decision** — PHP int is 64-bit SIGNED (overflows to lossy float past 2^63); GMP carries the [2^63,2^64-1] band. OCaml/C#/TS trap on a 3rd substrate |
| Ed25519 + SHA-256 | **ext-sodium** (bundled, zero dep) + stdlib `hash()` | native, audited, ships with PHP; the §9.1 floor in full |
| Ed448 | **GAP → DEFER** (v0.1 floor is Ed25519 only); hybrid-FFI when agility lands | ext-sodium has no Ed448; route = ext-ffi → `libentitycore_codec` (OCaml shape). SHA-384 itself is native via `hash()` |
| base58 / varint | hand-rolled (base58 reuses the GMP carrier) | dep-minimization (zero runtime Composer deps) |
| Error model | **exceptions** (`EntityCore\EntityCoreException` ← `\Exception`) | PHP idiom; same family as Ruby, distinct from tagged-tuple/result/error-union/std::expected |
| **Concurrency** | **single-thread `stream_select` event loop** | **a genuinely distinct cohort axis** — std PHP has NO native threads; store-safety is TRIVIAL (no races by construction, no lock); TCP_NODELAY |
| Naming | PascalCase classes / camelCase methods+props / SCREAMING_SNAKE consts (PSR-1/12) | PHP-native; `EntityCore\` namespace, PSR-4 |
| Build / test / pkg | Composer + **PHPUnit (dev-only)** + Packagist | zero runtime Composer deps |
| License | Apache-2.0 | S9 default |
| Container | **official `php:8.3.21-cli-bookworm`** + ext-gmp added | per prompt; ≥30-day (8.3.x line); ext-sodium built-in, ext-gmp installed; build-time crypto+carrier assertion |

## The PHP-specific headlines (where it earns its keep as a peer)

1. **The uint64 head-form carrier is a real trap here (GMP).** PHP's `int` is
   64-bit signed with silent overflow-to-float, so the [2^63, 2^64-1] band cannot
   be a native int (lossy past 2^53). Carried via GMP uniformly (one path). This
   is the OCaml A-OC-001/F7 trap re-derived on a **3rd signed-int substrate** —
   PHP is in the *has-a-trap* camp, NOT Ruby's arbitrary-precision free pass. This
   is the single most important codec-correctness decision for S2.
2. **Concurrency is a genuinely distinct cohort axis: single-thread event loop.**
   Standard PHP has no native threads, so concurrency is a non-blocking
   `stream_select` loop (what ReactPHP/Amp abstract over). The payoff is the
   **cleanest store-safety story in the cohort** — §4.8 is trivially satisfied (no
   data races by construction, no lock needed for the §3.9 CAS). §6.11 demux is a
   loop-driven request_id map; §4.9 resilience is structural (non-blocking
   multiplexed sockets). This is a new point in the §7b concurrency-runtime
   taxonomy: *single-threadedness* as the structural-safety mechanism (alongside
   actor-isolation, STM, and manual locking).
3. **Ed448 gap (not Ruby's native-full-agility).** ext-sodium has no Ed448;
   deferred for v0.1 (floor = Ed25519+SHA-256, self-contained), hybrid-FFI later —
   the OCaml posture. A deliberate divergence from the closest analog (Ruby gets
   Ed448 free from stdlib openssl).

## Idiom observations worth recording (not ambiguities — language facts)
- **Binary strings.** PHP `string` IS a binary-safe byte buffer (length in bytes);
  the codec works directly on it (`strlen`/`substr`/`ord`/`unpack`/`bin2hex`).
  Discipline: NEVER route wire bytes through `mb_*` functions — the PHP analogue of
  Ruby's ASCII-8BIT / TS's Uint8Array discipline. `declare(strict_types=1)` in
  every file prevents silent int↔string↔float coercion.
- **f16 has no pack code.** PHP `pack`/`unpack` offer only f32/f64 (`g`/`G`), no
  half-float — hand-assemble f16 from the binary64 bits (the Ruby A-RUBY-006 ladder
  shape). Highest-bug-density codec code; spike at S2.
- **SemVer-dash works natively.** Composer accepts `0.1.0-pre` (no RubyGems-style
  `0.1.0.pre.pre` mangling / no ASDF rejection) — PHP is in the suffix-accepting
  majority; `minimum-stability: dev` + `prefer-stable` gates the pre-release.
- **Modern PHP 8.x features used:** typed properties + constructor promotion +
  return types; `readonly` value objects (the records/data-class analogue); PHP
  8.1 backed enums for closed vocabularies.

## Container — AUTHORED, NOT BUILT (S1 boundary: no podman/build/toolchain)
`containers/php-toolchain/Containerfile` authored. Pins **official
`php:8.3.21-cli-bookworm`** (PHP 8.3.x line — far over the S11 30-day floor;
reviewed-vendor channel; `cli` SAPI for the long-lived peer;
bookworm/Debian 12). **ext-sodium** (Ed25519 + SHA-2 floor crypto) ships built-in;
**ext-gmp** (the uint64 carrier) is added via `docker-php-ext-install gmp`.
Composer copied from the pinned official `composer:2.7.9` layer. A **build-time
assertion** round-trips an Ed25519 sign/verify (ext-sodium live), a GMP arithmetic
check on a value > 2^63 (the carrier live), and SHA-256/384 presence — failing the
build loudly if any is missing. Ed448 deliberately NOT asserted (deferred agility
bar). PHPUnit (dev-only) vendored in one network-on step for `--network=none` dev
loops. **Build deferred to S2**; re-verify the exact 8.3.x patch NVR + pin the
image digest at first pull.

## Ambiguity log
6 entries (A-PHP-001..006), none blocking:
- **A-PHP-001** — codec native / CBOR hand-rolled (no PHP lib does ECF). Spike at S2.
- **A-PHP-002** — Ed448 GAP → defer for v0.1; hybrid-FFI (ext-ffi → libentitycore_codec) when agility lands. Floor (Ed25519+SHA-256) complete without it.
- **A-PHP-003** — uint64 carrier = GMP (PHP int is 64-bit signed, overflows to float). **The load-bearing codec decision.** Spike int.10/15/16/17 band at S2.
- **A-PHP-004** — f16 hand-rolled (PHP pack/unpack has no half-float code). Spike at S2.
- **A-PHP-005** — concurrency = single-thread stream_select event loop (no native threads); no-lock store-safety. Validate end-to-end at S3.
- **A-PHP-006** — Packagist coordinate `entity-core/protocol` (drop `-php`); SemVer-dash `0.1.0-pre` native. Availability checked at S5.

No **new spec-level** ambiguity surfaced — PHP corroborates the inherited cohort
findings against the complete v7.75 snapshot rather than re-litigating them.

## Exit criteria
profile.toml fully populated (no TBD-blocking) · rationale written · container
authored + specified (build verified at first build / S2 per the S1 no-build
boundary) · ambiguity log has no blocking-severity items (Ed448 deferred is a
scoped gap, not a blocker — the Ed25519+SHA-256 floor is complete). **S1 PASS.**

## Honest read: will PHP hit the codec/crypto/concurrency bars cleanly?
- **Crypto (floor): high confidence.** Ed25519 + SHA-256 are native via ext-sodium
  (bundled, audited libsodium, deterministic by construction). Zero dep, zero
  spelling risk (the `sodium_crypto_sign_*` API is stable). Ed448 is out of scope
  for v0.1 (deferred) — no risk to the floor.
- **Codec: high confidence, with the uint64-carrier care point.** The ECF
  canonical layer is hand-rolled (same as every prior peer). The one PHP-specific
  risk is the **uint64 head-form** — get the GMP carrier right (never touch a float
  for the high band) and the int.10/15/16/17 vectors pass; get it wrong and the
  [2^63, 2^64-1] band corrupts silently. The f16 ladder needs the usual care (no
  pack code → hand-assemble from bits). Both are spiked at S2 before the full build.
- **Concurrency: high confidence, distinct shape.** The single-thread event loop is
  the simplest store-safety story in the cohort (no races to begin with). The one
  care point is TCP_NODELAY plumbing through the stream context (fall back to a
  setsockopt via ext-sockets if the stream context is insufficient) — verified at S3.
- **No reason to expect PHP misses the bars** — the dynamic/reach axis differs in
  idiom (GMP carrier, event loop, exceptions, Ed448 gap), not in wire capability.

## Next
S2 codec (`--phase codec`): build `EntityCore\Cbor` (hand-rolled canonical ECF,
byte-cursor decoder over a binary string, **GMP uint64 carrier**) +
`EntityCore\Base58` + `EntityCore\Varint` + the ext-sodium crypto shim
(`EntityCore\Signature`). **Build the container first** and confirm ext-sodium +
ext-gmp are live (the build-time assertion gates this) and the
`sodium_crypto_sign_*` arity. **Spike `map_keys` + `float` + the uint64-band
(int.10/15/16/17) vectors** before the full corpus, then run the full v0.8.0 corpus
to byte-identity. Ed448/SHA-384 agility is **deferred** (out of the v0.1 codec run).

### What the next phase (S2) must watch
1. **The GMP uint64 carrier (A-PHP-003) is the #1 risk.** Verify NO uint64 value
   ever round-trips through a PHP float or a native-int cast for the [2^63,2^64-1]
   band — build the 8 wire bytes from the GMP value (`gmp_export`), and compute the
   shortest head-form via GMP. The int.10/15/16/17 vectors are the proof.
2. **f16 has no pack code (A-PHP-004)** — hand-assemble from binary64 bits with the
   exponent-range + mantissa-exactness guards + the four Rule 4a specials.
3. **Binary-string discipline** — never `mb_*` on wire bytes; `declare(strict_types=1)`
   everywhere; base58 reuses the GMP carrier (no native bignum).
4. **Ed448 stays deferred** — do not pull ext-ffi for the v0.1 floor codec/peer.
