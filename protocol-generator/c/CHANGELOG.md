# Changelog — entity-core-protocol-c

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note:** C has no package-manifest version field (no `Cargo.toml`/`pom.xml`/`.cabal`).
> The `0.1.0-pre` release line lives in the `Makefile` `VERSION`, the `pkg-config` `.pc` `Version:`,
> the `make dist` tarball name, and here. The `.pc` `Version:` field is dotted-numeric-only by
> convention, so the `-pre` marker is carried in the tarball name + this CHANGELOG + the README
> (mirrors the Common Lisp ASDF split, A-CL-010).

## [0.1.0-pre]

**Tracks ENTITY-CORE-PROTOCOL-V7 v7.75** (spec-data v7.75; codec corpus v0.8.0, byte-identical
v7.71→v7.75 — no wire change across the window). Conformance certified @ the v7.75 cohort oracle
**`b30a589`**.

First release line. Peer **#10** (C / C11 / POSIX), the **10th byte-compatible core impl**, derived
**spec-first** in the cohort's procedural / **manual-memory** / **return-code** idiom — native
hand-rolled canonical codec, libsodium Ed25519 + SHA-256, POSIX pthreads, raw `malloc`/`free` with
documented caller-frees ownership. The cohort's **last untried memory axis** (every prior peer
delegates lifetime to GC / actor / STM / ARC; C owns every allocation by hand). Not yet published —
parked at `-pre` pending architecture v0.1 sign-off + a first external C consumer (the S5 promotion
gate). C has no central registry; "publishing" is a source tarball + `pkg-config`.

### Conformance
- `validate-peer --profile core`: **PASS** — 576 / 291P / 196W / **0F** / 89skip
  (machine-verified `summary.failed == 0`) @ oracle `b30a589`. `resource_bounds` ACTIVE
  (r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN);
  `concurrency` 5/5 PASS. 0 FAIL also at the `62044c5` subset (574·0F·90S) and the `7e5ab04`
  superset (631·0F·92S) → conformance-safe.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, **ASan/LSan/UBSan-clean**.
- §9.5 53-type registry: 53/53 byte-identical (`make typereg` + live oracle `type_system_match`).
- origination-core: 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam wire-proven).
- S3 two-peer loopback smoke: 11/11; peer_id byte-identical to the cohort (seed `0x11` →
  `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`).

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16⊂f32⊂f64 float minimization, length-then-lex map-key
  sort on encoded key bytes (`qsort` + length-then-`memcmp`), recursive major-type-6 tag rejection,
  definite-length only, hand-rolled LEB128 + Base58. **Full uint64 / −2⁶⁴ head-form via native
  `uint64_t`** (the cleanest int story in the cohort alongside Zig — no `ulong`/int63 special-casing).
- Ed25519 sign/verify + SHA-256 via **libsodium** (the one runtime dep); RFC-8032 TEST-1 pubkey KAT.
  Nonces from the libsodium CSPRNG (`ec_random_bytes`).
- §1.5 canonical-form peer_id construction (Ed25519 → `hash_type=0x00` raw-pubkey
  identity-multihash), per the §1.5 v7.65 table, NOT the stale §7.4 SHA-256 pseudocode. peer_id
  byte-identical to the cohort. Lowercase `%02x` hex everywhere (dodges the A-CL-009 trap).
- §1.1 entity `data` modeled as an arbitrary ECF value (`ec_value` tagged union over all ECF major
  types), never map-typed (the A-JAVA-010 silent-500 trap) — scalar-data entities round-trip.
- §4.1 handshake, §6.5/§6.6 single-dispatch handler ladder, capability authorization with chain
  attenuation + §5.7 delegation caveats, type registry (render-from-model, 53/53), in-memory
  address-space store with CAS, §9.5a CORE-TREE get/put/CAS/delete + listing-omit deletion markers,
  §10.1 core-register gate (10/10).
- §4.10 resource bounds: r1 `413 payload_too_large` (16 MiB default), r2 the §4.10(b) ~15-line
  structural max-chain-depth (64) pre-check returning **`400 chain_depth_exceeded`** (MUST be 400,
  NOT 403) BEFORE the per-link authz walk, r3 connection-flood WARN.
- §5.2 request verification as a three-way verdict (ALLOW / AUTHN_FAIL→401 / AUTHZ_DENY→403) +
  the §5.5 unresolvable-grantee→401 carve-out.
- §7a `system/validate/{echo,dispatch-outbound}` conformance handlers behind a `--validate` opt-in
  (off by default); dispatch-outbound is a generic verbatim relay (forwards `{value: X}`, returns
  the downstream result entity verbatim).
- Concurrency: POSIX **pthreads** — one reader thread per connection (request_id demux), one thread
  per inbound EXECUTE; `pthread_rwlock_t` content store; per-connection write mutex; `TCP_NODELAY`
  on every connection socket. All 5 §7b concurrency checks PASS.
- **Shared entity refcounts are `atomic_int`** (A-C-009) — a plain-`int` refcount raced under the
  live §7b load and freed a still-referenced entity (heap-use-after-free); `atomic_fetch_add`
  (relaxed) / `atomic_fetch_sub` (acq/rel) fixes it. The C peer's net-new §4.8 datapoint.
- Public ABI: the single umbrella header `include/entity_core/protocol.h` + `ec_*` symbols;
  `-fvisibility=hidden` + an `EC_API` export macro; libsodium symbols localized (no embedder
  collision). Static `.a` (self-contained) + shared `.so` + a `pkg-config` `.pc` template.

### Known limitations
- **No central-registry publish** — C has none. "Publishing" is the `make dist` source tarball +
  the `entity-core-protocol.pc` consumed by distro packagers / vendoring; the deploy (tag + tarball
  hosting) is an operator action. The artifact is publish-ready at `0.1.0-pre`.
- **Self-contained `.so` deferred** (A-C-006) — Fedora's `libsodium.a` is not `-fPIC`, so the `.so`
  links shared `-lsodium` (a normal `libsodium.so` `NEEDED`); a private static libsodium in the
  `.so` needs a `-fPIC` libsodium built from source (release-prep, not conformance). The `.a` path
  is already self-contained.
- **Ed448 / SHA-384 agility deferred** (A-C-001) — libsodium has no Ed448. The §9.1 floor (Ed25519
  + SHA-256) is fully native and is the only path the corpus exercises. When agility lands, the
  dependency-lightest route is the sibling FFI codec's vendored Ed448 `.a` (C-to-C static link, not
  a foreign bridge) or OpenSSL `EVP_PKEY_ED448`. Does not affect the §9.1 floor (69/69 byte-green).
- **Tier-2 peer/transport surface not frozen** — the public header freezes the Tier-1 codec/crypto
  island; the peer-layer (`Peer`/`Transport`/store) is driven via the `entity-peer-c` host and not
  yet exposed as a stable ABI. Freeze deferred to publish-prep / first external consumer (the OCaml
  `.mli` / Zig `root.zig` analogue).

### Toolchain pins (S11)
- **gcc 15.2.1-7.fc43** (`-std=c11 -pedantic -Wall -Wextra -Werror`; pulls libasan/libubsan for the
  sanitizer test pass). Reviewed distro channel (fedora dnf) — exact pin for repro, age floor relaxed.
- **make 4.4.1-11.fc43**, **binutils 2.45.1-4.fc43** (objcopy for libsodium symbol localization).
- **libsodium 1.0.22-1.fc43** — the ONE crypto runtime dep (Ed25519 + SHA-256). Statically +
  privately linked into the `.a`/binaries; dynamically into the `.so` (A-C-006). CVE-2025-69277 is
  in the low-level `crypto_core_ed25519_is_valid_point` validator this peer does NOT call.
- **No registry-pulled (crates.io/npm/PyPI-style) ecosystem deps** — the codec, base58, varint, and
  test harness are all hand-rolled in-repo. The simplest supply chain in the cohort by construction
  (one audited C lib + the toolchain, both via the reviewed distro channel).

### Spec items surfaced (routed to architecture)
- **A-C-009 ⚑** §4.8 shared-entity refcounts MUST be atomic/lock-guarded on a multi-threaded peer —
  a no-GC manual-memory peer is the one that surfaces it (the GC'd/actor/STM/ARC cohort's runtimes
  own object lifetime and never hit it). Sibling to A-JAVA-010 (the "passes smoke green, breaks
  under the live §7b/concurrency gate" latent-bug class). Recommend a §4.8 conformance note.
- **A-C-008 ⚑** the 9-peer scorecard's v7.75 oracle label `62044c5` is **off-by-one-commit** —
  `b30a589` is the commit that folds `catResourceBounds: true` into core and yields the recorded
  576·0F·89S figure. Surface to mainline/arch so the scorecard's oracle commit is fixed.
- **A-C-006** Fedora `libsodium.a` not `-fPIC` → self-contained-`.so` is an S5/publish concern —
  owner: research/packaging.
- **A-C-010** clock-derived nonce → cross-connection replay (F12) — RESOLVED via CSPRNG nonce.
- **A-C-011** §4.5 disjoint negotiation reject / §1.4 path validation (`//` + embedded-NUL) /
  §2.6 delegate-501-ordering / §6 operations-match — RESOLVED (peer bugs, spec-clear).
- **A-C-001** Ed448 native gap — DEFERRED (3rd+ peer to hit it; sibling-FFI-`.a` route novel for C).
- **A-C-002 / -003 / -007** spec-snapshot / conformance-scaffolding / oracle-provenance notes
  (non-blocking; research/operator).
- **A-C-004 / -005** pthreads / native-codec — RESOLVED local decisions (S3/S2 sign-off).
- The §1.5-canonical-vs-§7.4 peer-id contradiction is the **5th+ spec-first corroboration**
  (A-OC-007 / A-ZIG-001 / A-CL-002 / A-SW-008 / A-JAVA-004) — built to §1.5 from the start
  (PRE-RESOLVED P1), no new ask; corroboration only.
