# Changelog — entity-core-protocol-cpp

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note (the `-pre` / numeric-CMake split, A-CPP-015).** CMake's `project(... VERSION ...)`
> field is dotted-numeric-only, so `CMakeLists.txt` carries the numeric `0.1.0` (and the conan recipe
> ref `entity-core-protocol/0.1.0`); the `-pre` pre-release marker is carried here, in the README, and
> in `status/PHASE-S5.md`. Same split the C peer hit with `pkg-config` and Common Lisp with ASDF
> (A-CL-010). The release line is `0.1.0-pre`.

## [0.1.0-pre]

**Tracks ENTITY-CORE-PROTOCOL-V7 v7.75** (spec-data v7.75; codec corpus v0.8.0, byte-identical
v7.71→v7.75 — no wire change across the window). Conformance certified @ the **v7.77** cohort oracle
**`e8524ed`** (go HEAD; the core category set is byte-unchanged v7.75→v7.77, the v7.77 delta being
entirely extension + the V8-naming kebab fold every peer already satisfies — `core_gate_sha256`
`e09a865f…`).

First release line. A release **"reach"** peer (C++ / C++23), corroboration-only by design (the
spec-discovery well is dry — the 8-peer synthesis saturated the language axes), derived **fresh in
S1** from the V7 spec in the cohort's **RAII / `std::expected` / template** idiom — native
hand-rolled canonical codec, libsodium Ed25519 + SHA-256, RAII smart-pointer ownership (no manual
`new`/`delete`/`free`), value-based `std::expected` error channel. Its closest analog is the C peer,
but a deliberately distinct idiom point (RAII vs raw malloc/free, `std::expected` vs return-code/
out-param). Not yet published — parked at `-pre` pending architecture v0.1 sign-off + a first
external C++ consumer (the S5 promotion gate). C++ has no central registry; "packaging" is a CMake
`find_package` package + a vcpkg port + a conan recipe (none pushed).

### Conformance
- `validate-peer --profile core`: **PASS** — 665 / 292P / 278W / **0F** / 95skip
  (machine-verified `summary.failed == 0`) @ oracle `e8524ed`. `resource_bounds` ACTIVE
  (r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN);
  `concurrency` 5/5 PASS.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, **ASan/LSan/UBSan-clean on g++ AND
  clang++** (cross-compiler hygiene: clang caught A-CPP-010, a g++-only recursive-variant slip).
- §9.5 53-type registry: 53/53 byte-identical (`typereg` + live oracle `type_system_match`).
- origination-core: 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam wire-proven).
- multisig: 11/11, 0 skip — genuine §3.6 K-of-N incl. `valid_2of3_peer_signed_accepted` PASS
  (`--name conformance` persistent identity → the validator co-signs as the peer → 200).
- §10.1 core-register gate: 10/10 (incl. `validate_echo_dispatch`).
- S3 two-peer loopback smoke: 11/11; peer_id byte-identical to the cohort (seed `0x11` →
  `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`).

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16⊂f32⊂f64 float minimization + the four exact specials,
  length-first-then-bytewise (CTAP2) map-key sort (`std::sort` over encoded key bytes), recursive
  major-type-6 tag rejection at any depth, definite-length only, zero-copy `std::span`/`string_view`
  decode (bounds-checked), hand-rolled LEB128 + Base58. **Full uint64 / −2⁶⁴ head-form via native
  `std::uint64_t`** (cleanest int story alongside C/Zig/Rust — no `ulong`/int63 special-casing).
- Ed25519 sign/verify + SHA-256 via **libsodium** (the one runtime dep); RFC-8032 TEST-1 pubkey KAT.
- §1.5 canonical-form peer_id construction (Ed25519 → `hash_type=0x00` raw-pubkey
  identity-multihash), per the §1.5 v7.65 table, NOT the stale §7.4 SHA-256 pseudocode. peer_id
  byte-identical to the cohort. Lowercase `std::format("{:02x}")` hex everywhere (dodges A-CL-009).
- §1.1 entity `data` modeled as an arbitrary ECF value (`EcfValue`, a `std::variant` over all ECF
  major types), never map-typed (the A-JAVA-010 silent-500 trap) — scalar-data entities round-trip.
- §4.1 handshake, §6.5/§6.6 single-dispatch handler ladder, capability authorization with chain
  attenuation + §5.7 delegation caveats, type registry (render-from-model, 53/53), in-memory
  address-space store with CAS, §9.5a CORE-TREE get/put/CAS/delete + listing-omit deletion markers,
  §10.1 core-register gate (10/10).
- §4.10 resource bounds: r1 `413 payload_too_large` (16 MiB default), r2 the §4.10(b) ~15-line
  structural max-chain-depth (64) pre-check returning **`400 chain_depth_exceeded`** (MUST be 400,
  NOT 403) BEFORE the per-link authz walk, r3 connection-flood WARN.
- §5.2 request verification as a three-way verdict (ALLOW / AUTHN_FAIL→401 / AUTHZ_DENY→403) +
  the §5.5 unresolvable-grantee→401 carve-out, carried over a `std::expected<Verdict, Error>` channel.
- Genuine §3.6 K-of-N multisig built at S3 (not a retrofit, A-CPP-012): §3.6 M3 structure +
  M4 distinct-signer threshold + M6 (local ∈ signers), with a positive 2-of-3 accept-path test.
- §7a `system/validate/{echo,dispatch-outbound}` conformance handlers behind a `--validate` opt-in
  (off by default); dispatch-outbound is a generic verbatim relay over the §6.11 reentry seam.
- Concurrency (§7b): one reader thread per connection (request_id demux), one thread per inbound
  EXECUTE; `std::shared_mutex` content store; per-connection write mutex; `TCP_NODELAY`. All 5 §7b
  checks PASS. **Shared entity lifetime is `std::shared_ptr<const Entity>`** (atomic refcount) — the
  A-C-009 race the C peer surfaced is structurally pre-resolved (A-CPP-011).
- The §1.4 R1 path-flex embedded-NUL/control-byte guard, fixed at S4 (A-CPP-014): the wire target is
  length-prefixed text so a NUL survives into `std::string` and a length-comparison guard was a no-op;
  rewritten to scan bytes directly and reject any control byte (`< 0x20`, `0x7f`) → `400 invalid_path`.
- Public API: the single umbrella header `include/entity_core/protocol.hpp` + the `entity_core::` API;
  `-fvisibility=hidden` + an `ENTITY_CORE_API` export macro; libsodium symbols localized (no embedder
  collision). Static + shared `libentity_core_protocol` + a CMake `find_package` package config.
- **Packaging:** an installable CMake package (`find_package(EntityCoreProtocol)` → `entity_core::protocol`,
  `EntityCoreProtocolConfig.cmake` via install + CPack) + a **vcpkg port** (`packaging/vcpkg/`) + a
  **conan recipe** (`packaging/conan/conanfile.py`), all pinned at `0.1.0`. None pushed to a registry.

### Known limitations
- **No central-registry publish** — C++ has none. "Packaging" is the CMake `find_package` package +
  the vcpkg port + the conan recipe; uploading them is an operator action. Publish-ready at
  `0.1.0-pre`.
- **Ed448 / SHA-384 agility deferred** (A-CPP-002) — libsodium has no Ed448. The §9.1 floor (Ed25519
  + SHA-256) is fully native and is the only path the corpus exercises. When agility lands, the
  dependency-lightest route is the OCaml FFI-hybrid pattern (the sibling C-ABI `ec_ed448_*`) or
  OpenSSL `EVP_PKEY_ED448`. Does not affect the §9.1 floor (69/69 byte-green).
- **Tier-2 peer/transport surface not frozen** — the public header freezes the Tier-1 codec/crypto
  island; the peer-layer (`Peer`/`Transport`/store) is driven via the `host` binary and not yet
  exposed as a stable ABI (the profile's `opaque_pimpl` boundary). Freeze deferred to publish-prep /
  first external consumer (the C `entity-peer-c` / OCaml `.mli` / Zig `root.zig` analogue).
- **ThreadSanitizer pass not runnable in-container** (A-CPP-013) — `libtsan` is absent from the
  `cpp-toolchain` image. The §7b live concurrency gate (5/5) + the structural `shared_ptr` /
  `shared_mutex` design carry the data-race coverage; a TSan pass is a release-prep nicety.

### Toolchain pins (S11)
- **gcc-c++ 15.2.1-7.fc43** (`-std=c++23 -pedantic -Wall -Wextra -Werror`; pulls libasan/libubsan
  for the sanitizer test pass). Reviewed distro channel (fedora dnf) — exact pin for repro, age floor
  relaxed (but met).
- **clang 21.1.8-4.fc43** — the second compiler for the ASan/UBSan cross-check pass (cross-compiler
  hygiene; libc++ has `<expected>` too).
- **CMake 3.31.11-1.fc43** + **Ninja 1.13.1-4.fc43** — the build system (the slate decision,
  A-CPP-003) + its generator backend.
- **binutils 2.45.1-4.fc43** (objcopy for libsodium symbol localization), **libstdc++-devel
  15.2.1-7.fc43** (the C++20/23 standard library headers `<expected>`/`<span>`/`<format>`).
- **libsodium 1.0.22-1.fc43** — the ONE crypto runtime dep (Ed25519 + SHA-256). Linked via
  pkg-config; the shared `.so` carries a normal `libsodium.so` runtime dependency. CVE-2025-69277 is
  in the low-level `crypto_core_ed25519_is_valid_point` validator this peer does NOT call.
- **No registry-pulled (vcpkg/conan/crates.io/npm-style) ecosystem deps** — the codec, base58,
  varint, and test harness are all hand-rolled in-repo; vcpkg/conan are S5 recipe-authoring only
  (and even then declare libsodium as the single dep). The simplest supply chain in the cohort
  alongside C — one audited C lib + the toolchain, both via the reviewed distro channel.

### Spec items surfaced (routed to architecture)
- **A-CPP-014** §1.4 R1 path-flex embedded-NUL guard was a no-op — peer bug, FIXED at S4 (found by
  validate-peer). Spec-clear; **owner: peer**, RESOLVED.
- **A-CPP-015** copyright-holder convention (`Entity Core Protocol contributors`, matching the C peer
  + 13 other peers) vs the brief's `the entitychurch contributors` — **owner: research/operator**,
  bookkeeping; matched the dominant cohort convention for consistency.
- **A-CPP-009** `<expected>` forces `-std=c++23` (GCC/Clang gate it behind `__cplusplus > 202002L`)
  vs the profile's C++20 target — **owner: operator**, RESOLVED (bumped to C++23, zero new deps).
- **A-CPP-002** Ed448 native gap — **owner: research/agility**, DEFERRED. Does not affect the floor.
- **A-CPP-001 / -003 / -004 / -005 / -006 / -010 / -013** native-codec / CMake-build / test-harness /
  spec-snapshot header / scaffolding source / clang portability / no-libtsan — **owner: operator**,
  RESOLVED or documented; non-blocking.
- **A-CPP-011** §4.8 shared-entity lifetime via `std::shared_ptr` (atomic refcount) — the A-C-009
  race **structurally pre-resolved** in C++ (RAII owns lifetime). Corroboration, no new ask.
- The §1.5-canonical-vs-§7.4 peer-id contradiction is the **6th+ spec-first corroboration**
  (A-OC-007 / A-ZIG-001 / A-CL-002 / A-SW-008 / A-JAVA-004 / A-C P1) — built to §1.5 from the start
  (PRE-RESOLVED P1), no new ask; corroboration only.
