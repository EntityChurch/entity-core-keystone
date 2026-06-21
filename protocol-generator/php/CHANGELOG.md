# Changelog — entity-core-protocol-php

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version-spelling note (the PHP analogue of RubyGems A-RUBY-010 / CL A-CL-010).** The cohort
> release line is written `0.1.0-pre` in prose. **Composer's version grammar does not accept the
> literal `0.1.0-pre`** — `pre` is not one of Composer's recognized stability keywords
> (`alpha`/`beta`/`RC`/`dev`/…), so `composer validate` rejects it (`Invalid version string
> "0.1.0-pre"`; verified in-container, Composer 2.7 / PHP 8.3). This contradicts the S1 A-PHP-006
> prediction. The idiomatic Composer resolution is to **omit the `version` field** and let Packagist
> infer the version from the VCS git tag at publish time (`composer validate --strict` reports the
> tag-less manifest valid). So `composer.json` carries no `version`; this CHANGELOG/README carry the
> cohort `0.1.0-pre` label, and the publish-time git tag is the registry coordinate. See
> `status/SPEC-AMBIGUITY-LOG.md` A-PHP-012.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.75** (a complete SHA-pinned snapshot — the
register/§6.13 peer surface, §6.9a owner-cap, §7a conformance handlers AND the §4.8/§4.9/§4.10
substrate floor are all present as ratified text, so this peer carries no snapshot-lag caveat). Codec
corpus v0.8.0, byte-stable v7.71→v7.75 (SHA-verified in the spec-data MANIFEST); the core category set
is wire byte-stable v7.75→v7.77, so this peer derives against v7.75 and **certifies against the v7.77
oracle `e8524ed`** (the established cohort pattern).

First release line. The **2nd dynamic / scripting peer** (after Ruby #12) and a release **"reach"**
peer (web-backend ubiquity), derived **spec-first** (no sibling-language source). Not yet published —
parked at `0.1.0-pre` pending architecture v0.1 sign-off + a first external PHP consumer (S5 promotion
gate).

### Conformance
- `validate-peer --profile core`: **PASS** — **665** total / 292P / 278W / **0F** / 95S
  (machine-verified `summary.failed == 0`) @ the v7.77 cohort oracle `e8524ed` (`core_gate_sha256`
  `e09a865f…`, matches `tools/oracle-pin.env`). No peer-correctness fixes were required at S4 — the S3
  peer converged on the oracle first-try.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, 0 codec fixes.
- origination-core: 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 same-connection reentry seam cross-impl wire-proven).
- multisig: **11/11, 0 skip** — incl. `valid_2of3_peer_signed_accepted` genuinely co-signed AS the
  peer via the on-disk `--name conformance` keypair (RUN→PASS, not env-skipped).
- §9.5 53-type registry: 53/53 byte-identical (content_hash recomputed by the PHP codec and asserted
  equal to the Go reference, not ingested).
- S3 two-peer loopback smoke: 12/12 (handshake + dispatch + capability + multi-request_id demux).

### Added
- Hand-rolled canonical-CBOR (ECF) codec (`src/Cbor.php`): f16⊂f32⊂f64 float minimization (PHP
  `pack`/`unpack` has no half-float code, so f16 is hand-assembled from the binary64 bits —
  A-PHP-004/008), length-first-then-bytewise map-key sort on encoded key bytes, recursive
  major-type-6 tag rejection at any depth, full uint64/−2⁶⁴ head-form range. Hand-rolled Base58
  (Bitcoin alphabet) + multicodec LEB128 varint. Wire bytes are a binary PHP `string` throughout —
  never routed through `mb_*`; `declare(strict_types=1)` in every file.
- **uint64 head-form carried uniformly through GMP** (ext-gmp; A-PHP-003): PHP's `int` is 64-bit
  *signed* (`PHP_INT_MAX = 2^63 − 1`, silent overflow-to-float past it), so the `[2^63, 2^64 − 1]`
  band cannot ride a native int and never round-trips through a float — the OCaml int63 / C# `ulong` /
  TS `bigint` trap re-derived on a **3rd signed-int substrate** (PHP is in the *has-a-trap* camp, the
  opposite of Ruby's arbitrary-precision free pass). `int.10/15/16/17` are the proof.
- **Ed25519 sign/verify via ext-sodium** (libsodium `sodium_crypto_sign_*`) + SHA-256/384 via the
  stdlib `hash()` — both bundled with PHP, **zero Composer/PECL dep, no FFI**. Deterministic RFC-8032
  signing → cross-impl signature byte-equality.
- §1.5 canonical-form peer_id construction (`hash_type=0x00` identity-multihash, digest = raw pubkey),
  per the §1.5 v7.65 table — **not** the stale §7.4 SHA-256 pseudocode. Lowercase `bin2hex` hex
  everywhere (dodges the A-CL-009 uppercase address-space-path trap).
- §1.1 entity `data` modeled as an **arbitrary ECF value** (`ByteString` / `EcfMap` wrappers —
  A-PHP-007 — since a PHP `string` carries no encoding tag and PHP arrays coerce numeric-string keys
  to int), not a native associative array; corroborates A-JAVA-010 on a 2nd dynamically-typed peer.
- §4.1 handshake (three-check PoP), §6.5/§6.6 dispatch ladder, capability authorization with chain
  attenuation + §5.7 delegation caveats + the §4.10 max-chain-depth (64) pre-check returning **400
  `chain_depth_exceeded`**, the §9.5 53-type registry, an in-memory address-space store with §3.9 CAS,
  the §9.5a CORE-TREE get/put/CAS/delete surface, the §6.13 register / §6.9a owner-cap / §7a
  conformance surface.
- §4.10 resource_bounds: 413 `payload_too_large` (16 MiB) + 400 `chain_depth_exceeded`;
  connection-admission is the §4.10(c) SHOULD / external-layer carve-out (WARN, not a core MUST).
- §5.2 / §5.2a request verification as a three-way verdict
  (ALLOW / unauthenticated→401 / authenticated-but-unauthorized→403 / unresolvable-identity→401).
- Error model: a `\Exception`-rooted `EntityCore\EntityCoreException` lattice (`CodecException`, …) —
  the PHP exception idiom. Protocol status is carried as a **value, never across an exception** (the
  cohort's status-as-value invariant).
- Concurrency (the §7b seam, A-PHP-005/009): a **single-thread non-blocking event loop** over
  `stream_select()` — php-cli has no userland threads, so this is the dependency-free idiomatic
  primitive AND the cleanest store-safety story in the cohort: one handler runs to completion before
  the next, so §4.8 is satisfied **structurally** (no data races, the §3.9 CAS needs no lock). §6.11
  reentry is cooperative loop-pumping (no thread/condvar). A new point in the §7b taxonomy:
  *single-threadedness as the structural-safety mechanism*. `TCP_NODELAY` is best-effort via
  ext-sockets when present (A-PHP-010).

### Known limitations
- **Packagist publishing deferred** — operator action after arch v0.1 sign-off. The package id
  `entity-core/protocol` (A-PHP-006) must be confirmed non-squatted at first publish; fall back to a
  different vendor namespace if the `entity-core` vendor is taken.
- **Ed448 / SHA-384-agility deferred** (A-PHP-002) — ext-sodium has no Ed448 and PHP's stdlib exposes
  no other EdDSA source. The §9.1 floor (Ed25519 + SHA-256) is fully native and is the only path the
  corpus exercises (69/69 byte-green). When agility lands: hybrid ext-ffi to the sibling C-ABI
  `ec_ed448_*` (the OCaml shape), opt-in so the floor peer stays FFI-free; SHA-384 itself is already
  native via `hash()`.
- Public API surface is documented (README §Install/consume), not yet frozen with an explicit semver
  lock — PHP has no module-private keyword, so freezing is a documentation + test-relocation pass
  deferred to publish-prep / first external consumer (the Ruby / OCaml `.mli` / Zig `root.zig`
  analogue). `bin/peer` is the conformance/oracle driver, not part of the published library surface.
- The vendored codec corpus is `v7.71` (no `v7.75` test-vector snapshot ships); the ECF encodings are
  byte-identical v7.71→v7.75 (SHA-verified in the MANIFEST), and the live `--profile core` run @
  e8524ed is the version-authoritative superset, so the codec axis is wire-stable. `repository_url` is
  TBD until first publish.

### Toolchain pins (S11)
- **PHP 8.3** (official `php:8.3-cli-bookworm`) with **ext-sodium** (libsodium; Ed25519 + SHA-2,
  bundled) + **ext-gmp** (the uint64 carrier, added via `docker-php-ext-install gmp`). Composer 2.7
  (from the pinned official `composer:2.7` layer). Floor is PHP `>= 8.3`. The container build-time
  assertion round-trips an Ed25519 sign/verify (ext-sodium live), a GMP value > 2^63 (the carrier
  live), and SHA-256/384 presence — failing the build loudly if any is missing.
- **PHPUnit 11.2.0** — dev-only Composer dependency (never shipped on the runtime path). The core peer
  has **ZERO runtime Composer dependencies** (crypto/hashing from ext-sodium + stdlib `hash()`;
  CBOR/base58/varint hand-rolled).

### Spec items surfaced (routed to architecture / operator)
- **No NEW spec-level defect.** PHP is a **corroboration-only reach peer** (the discovery well was
  drained by the spec-first cohort, and the dynamic/scripting axis by Ruby #12): it read the complete
  v7.75 snapshot and **corroborated** the inherited cohort findings (peer-id §1.5, 401/403 §5.2a,
  §4.10 resource_bounds, A-JAVA-010 `data`-shape, lowercase address-space hex) **live against the
  oracle** rather than re-litigating them. The contribution is **idiom breadth + convergence
  evidence** (2nd scripting peer; the signed-int uint64 trap on a 3rd substrate via GMP; the
  single-thread-event-loop concurrency axis with no-lock store-safety; ext-sodium native floor with an
  Ed448 gap), not a new finding.
- **A-PHP-012** (NEW, packaging) — Composer rejects the literal `0.1.0-pre` (`pre` is not a Composer
  stability keyword); the idiomatic fix is to omit `version` and let Packagist infer it from the VCS
  git tag. The PHP analogue of RubyGems A-RUBY-010 / CL A-CL-010 — and the *inverse* of the S1
  A-PHP-006 "SemVer-dash works natively" prediction. **Owner: operator.**
- **A-PHP-006** Packagist coordinate `entity-core/protocol` confirm-non-squatted — **owner: operator**
  (S5 registry step).
- **A-PHP-001/-003/-004/-005/-007/-008/-009/-010/-011** (RESOLVED) — native hand-rolled codec / GMP
  uint64 carrier / f16-from-bits / single-thread event loop / ByteString+EcfMap wrappers / PHP-runtime
  float seams / TCP_NODELAY best-effort / PSR-4 handler files.
- **A-PHP-002** Ed448 native gap → defer — **owner: research/agility**. Does not affect the floor.
