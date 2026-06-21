# entity-core-protocol-php — Profile Rationale

Audit trail for every major S1 profile choice. PHP is a **release "reach" peer**
(web-backend ubiquity), built in the prerelease six-peer slate
(`research/RELEASE-READINESS.md` §2 row 2). It is **corroboration-only** by
design: the 8-peer synthesis found the spec-discovery well dry on language axes,
and the **dynamic/scripting** axis was already exercised by **Ruby (#12)**. PHP's
value is **REACH** (the vast web-backend / WordPress / Laravel / Symfony reader
base can pull a native peer) and exercising the generator against **PHP idiom**.
Anything genuinely new is logged honestly (`A-PHP-NNN`); it is gravy, not the goal.

Each choice below was derived from V7 (pinned `spec-data/v7.75`) + PHP-ecosystem
research, **not** ported from a sibling peer. The closest analog is the **Ruby
peer** (the other dynamic/scripting peer), but PHP is deliberately a **distinct
idiom point** on three load-bearing axes (see "Where PHP diverges from Ruby").

## Reach, not discovery; ratify the slate, don't re-litigate

The slate (`RELEASE-READINESS.md` §2 row 2) already fixes PHP's surface:
hand-roll ECF (cbor-php is not ECF-exact, the A-005 analogue), libsodium in-box
for Ed25519, Ed448 = gap → FFI/defer, Composer packaging, Apache-2.0 (S9). The S1
job is to make these **concrete and idiomatic** (error model, async style, naming,
PHP version pin, exact extensions, the uint64 carrier), not to reopen them. They
are ratified below with rationale.

## Spec version: full v7.75 snapshot (no snapshot-lag caveat)

`spec-data/v7.75` is a complete, SHA-pinned snapshot with the full
`ENTITY-CORE-PROTOCOL-V7.md` body. PHP derives the entire S1/S2/S3 surface — the
register/outbound/emit/owner-cap/§7a peer surface AND the v7.75 §4.8 store-safety
/ §4.9 resilience / §4.10 resource-bounds substrate floor — from ratified spec
text. The codec specs (`ENTITY-CBOR-ENCODING.md` label 1.5,
`ENTITY-NATIVE-TYPE-SYSTEM.md` 4.2.1) are byte-identical v7.71→v7.75 per the
MANIFEST, so the wire is stable and the v0.8.0 corpus is valid. The core floor is
byte-stable v7.75→v7.77 (the v7.77 delta is extension + V8-naming), so deriving
from v7.75 and gating against the current oracle is the established cohort
convention. No A-ELX-001-style escalation is needed.

## Codec strategy: native (hand-rolled ECF)

The A-005 pattern holds for an Nth language: **no PHP CBOR library gives ECF's
canonical guarantees out of the box**, so the canonical layer is hand-rolled
regardless of what sits underneath; meanwhile **crypto is native via ext-sodium**
(Ed25519 + SHA-256). So `native` is correct on both halves. `ffi` (ext-ffi →
`libentitycore_codec`) stays the documented fallback for the codec but is **not**
the chosen path — and is the **actual route for the Ed448 agility higher bar
only** (see below). This matches the slate's "hand-roll ECF / libsodium in-box /
gap → FFI/defer" row.

## CBOR: hand-rolled (no library)

Surveyed the PHP CBOR landscape:

- **`spomky-labs/cbor-php`** — the de-facto PHP CBOR library: a general
  **RFC-8949** implementation. It does **not** do ECF length-FIRST map-key
  ordering, does **no** shortest-float minimization, and **accepts tags**. Not
  ECF-exact (exactly the slate's "cbor-php not ECF-exact" note).
- **`2tvenom/CBOREncode`, `lukasoppermann/php-cbor`, and similar** — smaller,
  general, same gaps; none implements ECF determinism.

The full ECF contract — length-then-lex map order on **encoded key bytes**,
shortest-float incl. f16, recursive major-type-6 rejection on **decode**, full
uint64/nint range, and verbatim raw-byte `data` (N4) — is not delivered by any
single library. Hand-rolling `src/Cbor.php` is both faithful and *simpler* than
bending a general library that fights the length-first rule, and it keeps the
**zero-runtime-Composer-dependency** story intact. The decoder is a byte-cursor
over a binary `string` (PHP strings are binary-safe byte buffers — `strlen`,
`substr`, `ord`, `unpack` are the natural primitives). **Spike the `map_keys` +
`float` + the uint64-band (`int.10/15/16/17`) vectors at S2** before the full
build — the load-bearing codec risk.

## *** The uint64 head-form carrier: GMP (the single most important codec decision) ***

This is the PHP-specific codec-correctness headline (A-PHP-003). **PHP `int` is
64-bit SIGNED** on 64-bit builds (`PHP_INT_MAX = 2^63 − 1`), and PHP has **no
native arbitrary-precision integer** (unlike Ruby's bignum or the BEAM). A literal
beyond `PHP_INT_MAX` silently becomes a **float** — lossy past 2^53. So the CBOR
uint64 head-form in the **[2^63, 2^64−1]** band **cannot** be carried in a native
`int`, and must never round-trip through a float.

**Carrier ruling: use GMP (ext-gmp, bundled in the toolchain image) for CBOR
integer head-form values, uniformly across the whole range.** One uniform GMP path
(rather than int-below-2^63 / something-above) avoids an int↔carrier branching bug
surface, and GMP gives exact arbitrary-precision arithmetic for the encode-side
shortest-head-form computation and the decode-side range checks. The wire
primitive is `pack('J', …)`/`unpack('J', …)` (64-bit big-endian) for values that
fit a signed int; the **≥ 2^63 band assembles its 8 bytes from the GMP value**
(`gmp_export` / explicit byte extraction), **never** from an `int` cast. (The
lighter alternative — native `int` for the low band plus a decimal `string` for
the high band, the JSON-bigint shape — was considered and rejected for the
two-path bug surface; GMP is the one-path safe carrier and ext-gmp is in the
image.) This is the **OCaml A-OC-001 / F7 trap re-derived on a third signed-int
substrate** — after OCaml's int63→Int64, C#'s `ulong`, and TS's `bigint`. PHP is
firmly in the *has-an-int-trap* camp, **not** the Ruby/BEAM free-pass camp; that
divergence is the point of the peer's number axis.

## Crypto: ext-sodium — Ed25519 + SHA-256 (native, bundled, zero dep)

**ext-sodium** (libsodium) has been a **core PHP extension bundled since PHP
7.2** — it is NOT a PECL/Composer dependency. It provides the §9.1 floor crypto in
full:

```php
$kp  = sodium_crypto_sign_seed_keypair($seed32);      // seed -> keypair
$pk  = sodium_crypto_sign_publickey($kp);             // 32-byte pubkey
$sk  = sodium_crypto_sign_secretkey($kp);             // 64-byte expanded sk
$sig = sodium_crypto_sign_detached($msg, $sk);        // 64-byte detached sig
$ok  = sodium_crypto_sign_verify_detached($sig, $msg, $pk);
```

Ed25519 is **deterministic by construction** (RFC-8032; no RNG in the signing
path), so the crypto-library version is conformance-neutral (the C# F10 lesson).
It is audited (libsodium), ships with PHP (no Composer/PECL dep), and is the
self-contained v0.1 floor. **SHA-256** (the content_hash floor) is the stdlib
`hash('sha256', $bytes, true)` (binary output) — also bundled, no dep.
**Candidate considered and declined:** the `paragonie/sodium_compat` Composer
polyfill (only needed when ext-sodium is absent — it is bundled, so this is dead
weight) and any third-party Ed25519 Composer package (adds a dep for what the core
extension already does). ext-sodium dominates: native, audited, zero-dep.

## Ed448: GAP → DEFER for v0.1, hybrid-FFI when agility lands

The slate fixes "gap → FFI/defer", and the ruling is: **defer for v0.1**.
**ext-sodium has no Ed448** (libsodium ships Ed25519 + the SHA-2 family +
ML-KEM/SHA-3 but **no** Ed448/Ed448-Goldilocks — the same libsodium gap C, C++,
and Zig hit), and PHP's stdlib has no other EdDSA source (ext-openssl exposes no
Ed448 binding). So `key_type 0x02` is **not** reachable natively. The v0.1 core is
**Ed25519 + SHA-256 only** (the §9.1 floor), fully covered by ext-sodium, so the
gap does **not** touch the conformance floor — exactly the OCaml/C#/C++/Zig/Swift
deferred-higher-bar posture.

When/if agility enters scope, the dependency-lightest PHP route is the **hybrid
FFI** path (the slate's "FFI" half): **ext-ffi** (bundled in PHP since 7.4) binds
the sibling `libentitycore_codec` C-ABI v1.1 Ed448 family
(`ec_ed448_seed_to_pubkey` / `ec_ed448_sign` / `ec_ed448_verify`, with `ec_sha384`
available too) — the **OCaml hybrid-FFI shape** (A-OC-002), scoped to an **opt-in
agility surface** so the shipped floor peer stays FFI-free and self-contained.
Note that the agility **hashing** half (SHA-384) is **native** via stdlib
`hash('sha384', …)` — only the Ed448 **signature** primitive is the FFI piece. See
SPEC-AMBIGUITY-LOG A-PHP-002.

## Base58 + varint: hand-rolled

Both small and dependency-free. Base58 (Bitcoin alphabet, encode+decode,
`src/Base58.php`) for peer-id; LEB128 varints (`src/Varint.php`) for the N1
format-code / key-type / hash-type framing. Hand-rolling keeps the
**zero-runtime-Composer-dependency** story intact. Note: base58 does uint
arithmetic over arbitrary-size byte strings, so it uses the **same GMP carrier**
as the codec (PHP has no native bignum) — a small reuse, not a new dep (ext-gmp is
in the image).

## Error model: exceptions (the PHP idiom)

`throw`/`try`-`catch` with a hierarchy rooted at `EntityCore\EntityCoreException`
extending PHP's `\Exception` (which implements `\Throwable`) — the canonical PHP
fallible surface. The tree mirrors the C#/TS/Ruby exception hierarchies in *shape*
(Codec / Protocol / Transport families) but reads as PHP (namespaced PascalCase
classes, typed `catch`). Rooting at `\Exception` (not `\Error`) keeps faults
catchable by `catch (\Exception)` / `catch (\Throwable)` — `\Error` (e.g.
`\TypeError`) is reserved for engine/programmer faults, never protocol flow.
Decode-path violations throw `CodecException` subclasses; the peer catch-maps
protocol faults to the §5.2a / §6.12 status codes at the dispatch boundary
(400 non_canonical_ecf / 401 / 403 / 413 / 400 chain_depth_exceeded). This is the
dynamic-language exception seam — same family as Ruby's, distinct from Elixir's
tagged tuples, OCaml's `result`, Zig's error unions, and C++'s `std::expected`.

## Concurrency: a single-thread `stream_select` event loop (a genuinely distinct shape)

This is the PHP concurrency axis, and it diverges from **every** prior peer.
Standard PHP (the bundled `php-cli` SAPI) has **no native userland threads**:
ext-pthreads is dead, ext-parallel exists only on ZTS (thread-safe) builds and is
a non-core dependency, and the web-SAPI process-per-request model is irrelevant
for a long-lived peer. So the dependency-free, idiomatic PHP concurrency primitive
for a multi-connection socket server is a **single-thread non-blocking event
loop** over `stream_select()` with non-blocking stream sockets
(`stream_socket_server` / `stream_socket_accept` / `stream_set_blocking($s,
false)`) — the runtime that underlies dependency-free PHP socket servers (and that
ReactPHP/Amp abstract over). This maps the floor MUSTs cleanly:

- **§4.8 store-safety: trivially satisfied.** A single-thread event loop has **no
  data races by construction** — one handler runs at a time, cooperatively, so the
  §3.9 CAS put is just a sequential read-then-write needing **no lock**. This is
  the *structural-safety* route in the §7b taxonomy (the actor/STM peers reach
  store-safety structurally; PHP reaches it via single-threadedness) — and the
  **cleanest** store-safety story in the cohort: there is literally no concurrency
  to race. (Contrast Ruby's GVL, which serializes bytecode but still needs an
  explicit Mutex because a thread can be preempted mid-compound-op; the
  single-thread loop has no preemption, so even that subtlety is absent.)
- **§6.11 reentrant demux (N6/N7):** a `pending {request_id => waiter-state}` map
  in the loop; an outbound EXECUTE registers a waiter, the reader callback resolves
  it when the matching EXECUTE_RESPONSE frame arrives on the same connection — no
  thread/condvar, just loop-driven state (the event-loop analogue of OCaml's
  reader-thread + Hashtbl + condvar).
- **§4.9 resilience under load:** one slow/broken connection cannot block others
  *because* every socket is non-blocking and multiplexed by `stream_select` — a
  blocking `recv` is structurally impossible (the cooperative-pool blocking-syscall
  trap Swift hit is absent). A per-handler exception is caught at the loop boundary
  so one bad frame never tears down the loop (§4.9 no-crash floor).
- **§7b gate:** the loop interleaves connections; **TCP_NODELAY** MUST be set on
  every socket (the Zig Nagle/delayed-ACK small-frame lesson) — via
  `stream_context` `'socket' => ['tcp_nodelay' => true]`, or a `setsockopt` on the
  fd via ext-sockets if the stream context proves insufficient (verify at S3).

**Honest caveat:** a single-thread loop is **not parallel** — a burst of CPU-bound
signature verifies serializes. For an IO-bound protocol peer this is adequate (the
same honest accounting as Ruby's GVL note, but simpler — no GVL subtlety, just one
thread). True-parallelism escape hatches (`pcntl_fork` process-per-connection,
ext-parallel on a ZTS build, or an event extension like ext-ev/ext-event) are
**noted but not used at core**.

## Where PHP diverges from Ruby (the three load-bearing seams)

Ruby is the closest analog (the other dynamic/scripting peer, same exceptions
model, same hand-rolled-CBOR reality), but PHP is **not "Ruby in PHP syntax"** —
it diverges on exactly the three axes that matter:

1. **Integer carrier.** Ruby's `Integer` is arbitrary-precision (no head-form trap
   — the BEAM free pass). PHP's `int` is **64-bit signed with overflow-to-float**,
   so the uint64 [2^63, 2^64−1] band **is** a real trap → carried via **GMP**. PHP
   is in the OCaml/C#/TS *has-a-trap* camp, not Ruby's free-pass camp.
2. **Concurrency.** Ruby uses **thread-per-connection** under the GVL (native
   threads, GVL released on blocking IO, Mutex-guarded store). PHP has **no native
   threads** → a **single-thread `stream_select` event loop** (no store lock needed
   at all — structurally race-free).
3. **Ed448 agility.** Ruby gets **native full agility** via stdlib openssl (Ed448
   from the same surface, no FFI). PHP's ext-sodium **has no Ed448** → **gap,
   deferred**, hybrid-FFI when agility lands (the OCaml posture, not the Ruby one).

## Byte handling: binary strings

Wire bytes are plain PHP `string`s, which are **binary-safe byte buffers** (length
in *bytes* via `strlen()`); the codec works directly on them with
`strlen`/`substr`/`ord`/`chr`/`pack`/`unpack` and `bin2hex`/`hex2bin`. The
discipline is: **never** route wire bytes through the `mb_*` multibyte functions
(they are encoding-aware and will corrupt binary data) — the PHP analogue of
Ruby's ASCII-8BIT discipline and TS's Uint8Array-not-Buffer discipline.
`declare(strict_types=1)` at the top of every file prevents silent
int↔string↔float coercion (non-negotiable for a wire codec).

## §1.1 `data` is an arbitrary ECF value (A-JAVA-010)

The §1.1 entity `data` field is an **arbitrary ECF value, NOT necessarily a
map/array** (A-JAVA-010, the silent-500 trap). PHP's dynamic typing makes this
natural — `data` is modeled as a general decoded ECF value (a typed value union or
carried as pre-encoded bytes), **never** assumed to be a PHP `array`. Recorded now
so the S2 codec model is right from the start.

## Language features used: typed, immutable, modern PHP 8.x

- `declare(strict_types=1)` in every file (strict scalar typing — no coercion).
- Fully typed properties + constructor promotion + return types (PHP 7.4/8.0).
- `readonly` properties / `readonly class` (PHP 8.1/8.2) for immutable value
  objects (Envelope, CapToken, ContentHash, PeerId) — the records/data-class
  analogue.
- PHP 8.1 **backed enums** for closed vocabularies (`KeyType: int`,
  `HashFormat: int`, message-type tags) — the exhaustive-set seam.

## Build / test / packaging: Composer + PHPUnit + Packagist

**Composer** is the universal PHP dependency/build/autoload tool (the slate
decision); the "build" is PSR-4 autoload-dump (PHP is interpreted — no compile
step). The core peer has **zero runtime Composer dependencies** (crypto =
ext-sodium core extension; CBOR/base58/varint hand-rolled; SHA = stdlib `hash()`).
Tests use **PHPUnit**, the de-facto PHP test framework — a **dev-only** Composer
dependency (never shipped), so taking the ecosystem standard here is the
low-surprise idiomatic choice (the Java/JUnit + Kotlin/kotlin.test stance), pinned
exactly + ≥30-day. The conformance harness is a PHPUnit suite asserting
byte-identity against the normative fixtures; a thin `bin/entity-core-peer` script
is the standalone oracle driver for validate-peer / wire-conformance at S4.
**php-cs-fixer/phpcs (PSR-12)** and **phpstan/psalm** are the ecosystem
lint/static-analysis standards but dev-only — deferred to S5, not pulled silently.

## Naming the package: peer id vs Packagist coordinate

Peer id under keystone naming is `entity-core-protocol-php`. Composer coordinates
are `vendor/package` (lowercase, hyphen-separated); the Packagist coordinate is
**`entity-core/protocol`** — a package is implicitly PHP, so the redundant `-php`
suffix is dropped (mirrors the Ruby/Elixir registry-id reasoning). The PSR-4 root
namespace is `EntityCore` (mapped to `src/`). Availability/squatting on the
`entity-core` vendor namespace is checked at S5 before first publish.

## Pre-release version: SemVer-dash works natively (no grammar surprise)

Unlike RubyGems (which mangles `0.1.0-pre` → `0.1.0.pre.pre`, A-RUBY-010) and
Common Lisp's ASDF (dotted-integer-only, A-CL-010), **Composer/SemVer accepts the
SemVer-dash `0.1.0-pre` natively**. Packagist resolves it as a pre-release that
needs an explicit stability flag to install (`"minimum-stability": "dev"` +
`"prefer-stable": true` in composer.json, or a `@dev`/`@alpha` constraint) — the
correct behavior for an unpromoted peer. So the parked `0.1.0-pre` is the literal
gem coordinate too; no version-grammar rewrite needed. (A small positive note: PHP
is in the SemVer-suffix-accepting majority alongside Maven/opam/Cargo/npm.)

## License: Apache-2.0 (S9 default)

PHP itself is under the PHP License (a BSD-style permissive license) and the
Composer/Packagist ecosystem is MIT-heavy with no strong mandate, so the repo's
Apache-2.0 default (explicit patent grant) stands. ext-sodium/libsodium is ISC
(Apache-compatible).

## Container: official `php:8.3.x-cli-bookworm`

Per the S1 prompt, the toolchain image pins a **PHP 8.x release ≥30 days old**
(S11). **`php:8.3.21-cli-bookworm`** is the pin — the official Docker
`php:8.3` image (Docker Official Images, docker-library/php — a reviewed-vendor
channel, so the strict 30-day *registry* cool-down relaxes to "pin exactly for
reproducibility," which a patch-pinned tag does; the pin is comfortably ≥30 days
old regardless). Rationale for the version line:

- **PHP 8.3** is the conservative, well-aged, actively-supported 8.x line at
  authoring (the 8.3.x patch line has been issued
  monthly through 2024–2025). A patch in the 8.3.x line is far over the 30-day
  floor. (8.4 — released late 2024 — is the newer line; 8.3 is the conservative
  reach choice for the widest deployed-PHP compatibility, the reach goal. The exact
  patch NVR is verify-and-pinned at the first S2 build against what the official
  `php:8.3` tag currently ships, then the image **digest** is pinned.)
- The `cli` flavor (not `apache`/`fpm`) is the long-lived-CLI-peer SAPI we need.
  `bookworm` (Debian 12) is the base.
- **ext-sodium** (the floor crypto) and **ext-gmp** (the uint64 carrier) must both
  be enabled. The official `php:8.3` image ships **ext-sodium built-in**; **ext-gmp
  is NOT in the default image** and must be added via the official
  `docker-php-ext-install gmp` (which pulls `libgmp-dev` from Debian). The
  Containerfile does this and adds a **build-time assertion** that round-trips an
  Ed25519 sign/verify (ext-sodium live) AND a GMP arithmetic check on a value >
  2^63 (the uint64 carrier live) — so the image fails loudly if either is missing.
  Composer is installed from the official `composer:` image layer (pinned).
- The core peer has **zero runtime Composer dependencies**, so there are no library
  pins to mirror; PHPUnit (dev/test only) is vendored in one network-on build step
  for `--network=none` dev loops.

(The image is **authored, not built** in S1 — the S1 boundary forbids
podman/build/toolchain execution. The build-time assertions are verified at the
first build, S2; the tag is pinned now, the digest at first pull.)
