# entity-core-protocol-cpp — Profile Rationale

Audit trail for every major S1 profile choice. **C++** is a release **"reach" peer**
(systems / games / embedded ecosystem coverage; `research/RELEASE-READINESS.md` §2 row 3)
— **corroboration-only**: the 8-peer synthesis found the spec-discovery well dry on
language axes, so C++ is built for **reach** (a systems/games/embedded reader can pull a
native peer) and to **exercise the generator against C++ idiom** (RAII / `std::expected`
vs exceptions / templates / move semantics), **not** to surface new spec defects. Each
choice below derives from the V7 spec (`spec-data/v7.75`) + C++ ecosystem research, **not**
ported from the prior peers. The closest analog is the **C peer** (same libsodium crypto,
same hand-rolled canonical ECF codec, same systems-language footguns) — but C++ is
**deliberately a distinct idiom point** from C: it does **not** inherit C's raw return-code
error model or its unguarded `malloc`/`free`.

## D1 is binding — native hand-roll, NOT FFI (affirmed explicitly)

**Decision D1** (`research/RELEASE-READINESS.md` §3-D1) is already made and **binding**, and
this profile **affirms it**: the C++ codec is a **native hand-roll in idiomatic C++**, **not**
an FFI to `libentitycore_codec`. The recorded rationale, restated:

> "An FFI C++ peer is the C peer in a trench coat and proves nothing independent; native
> exercises the generator against C++ idiom (RAII / `std::expected` vs exceptions /
> templates), which is the actual reach value. Crypto stays libsodium."

So `codec_strategy = "native"`, and the peer **must** write `ecf.{hpp,cpp}` in idiomatic
C++ — it must **not** link the sibling C/Rust FFI codec for the codec layer (even though
C++-to-C `extern "C"` would compile trivially). The sibling FFI `.so`
(`entity-core-codec-ffi-c`/`-rust`) is kept only as a **free byte-for-byte cross-check
oracle** at S2/S4. `ffi` is the documented S2-spike fallback **only if the spike fails** —
but D1 explicitly rules it out as the chosen path: the whole point is to *write* the
canonical C++ codec. (`A-CPP-001`.)

## Codec strategy: native (hand-rolled canonical CBOR + base58 + varint, libsodium crypto)

The same A-005 pattern every prior native peer hit — **and** the codec must OWN the
canonical layer regardless of any CBOR library underneath:

1. **No C++ CBOR library gives ECF canonicality.** `tinycbor` (Intel/AOSP) is the closest
   (streaming/low-level) but float-min / tag-rejection / CTAP2 ordering are still the
   caller's job, it has 0.5→0.6 pin churn, **and it is a C library** (re-introducing the
   C idiom C++ is paid to replace). `cppcodec` is base64/base32/hex only — **not a CBOR
   library** (a LANDSCAPE mis-association). `jsoncons`'s CBOR sub-library is a DOM-tree,
   broad-surface, header-only library not focused on ECF determinism (no length-then-lex,
   no decode-side shortest-float minimality), obscuring raw-byte fidelity. `QCBOR` targets
   dCBOR determinism but **only in its 2.x alpha** (no stable release → fails the S11
   ≥30-day-stable pin) and is a C library. The four hard ECF requirements —
   shortest-float/float16 with the four exact specials, RFC-7049 **length-FIRST then
   bytewise** (CTAP2) map-key ordering (which **differs** from RFC-8949 §4.2 bytewise),
   recursive major-type-6 tag rejection, byte-exact raw-slice round-trip + full
   uint64/nint head-form range — are exactly what a general library does differently or
   leaves to the caller. So a library buys almost nothing and adds a build/pin dependency.

2. **Hand-rolling is the faithful AND the idiom-exercising path.** `ecf.{hpp,cpp}` is a
   `std::span<const std::byte>`-based **zero-copy** decoder returning
   `std::expected<EcfValue, EcfError>`, and a `std::vector<std::byte>` encoder — a few
   hundred lines of straight-line modern C++, no allocation in the decode hot path
   (the decoder index-walks the input span and returns views/spans **into** it). The
   `std::span` carries its own size, so the C peer's "C will not bounds-check an overread"
   footgun becomes a checked `.at()`/explicit-length-guard in C++ — bounds-checking is
   structural here, but still **explicitly enforced** (`defensive_bounds = true`).

3. **Crypto is one pinned external dep (libsodium), per D1.** C++ has no stdlib crypto. The
   §9.1 floor (Ed25519 + SHA-256) is met by **libsodium** — audited, statically-linkable,
   the single source of both SHA-256 and RFC-8032 Ed25519 (`crypto_sign_*` +
   `crypto_hash_sha256`), wrapped in a small **RAII C++ facade** so the C handles are owned
   with C++ ownership semantics (no raw resource leaks). This is the one runtime
   dependency, profile-**authorized** (S6, per D1) and S11-pinned.

**Codec spike at S2** (PHASE-S1 mandate): push the `map_keys` + `float` v7.71 vectors
through the hand-rolled encoder/decoder before the full build — the load-bearing canonical
risk; **float minimization is the highest bug-density code in the whole peer** (hardcode
the four specials F9 7E00 / 7C00 / FC00 / 8000; minimize by double→float→half
re-decode-and-compare).

## Error model: `std::expected<T, E>` (the C++-modern Result — NOT exceptions, NOT C's return-codes)

The **headline C++-idiom choice** the slate's D1 names. C++ here is the **`std::expected`
point** in the cohort, deliberately distinct from **both** neighbors:

- It is **not** the C peer's raw **return-code / out-param** model (status `int` + out-pointer,
  no compiler enforcement). C++ has value-based `std::expected`, which carries the result
  OR the error in the type — the modern idiomatic shape.
- It is **not** the C# peer's **exceptions** model. C++ *has* exceptions, and the generator
  must **not** reflexively reach for `throw`/`try`/`catch` on the hot path. Exercising
  `std::expected` in a language that *also* has exceptions is precisely the C++ idiom axis
  no prior peer covers.

Every fallible codec/dispatch function returns `std::expected<T, ProtocolError>` (or
`EcfError` in the codec layer); the dispatcher maps a `ProtocolError` → wire status code at
the boundary (400 non_canonical_ecf / 401 / 403 / 413 / **400 chain_depth_exceeded**).
**Exceptions are reserved for true programmer-error only** — `std::bad_alloc` on OOM,
`std::logic_error` for can't-happen invariants — caught at the **per-connection task
boundary** so one bad connection never crashes the peer (the §4.9 no-crash floor), and
**never** for protocol flow. No exception escapes the public ABI (the public surface returns
`std::expected`, it does not throw). `<expected>` is C++23 but ships usable in libstdc++
(GCC 12+) and libc++ (Clang 16+) under `-std=c++20`; `tl::expected` is the documented
header-only fallback shim. (`A-CPP-007`.)

## Memory / ownership: RAII + smart pointers + move semantics (the C++ answer to C's manual memory)

**THE idiom seam that makes C++ a distinct reach point from C.** C++ has GC-free
**deterministic destruction** (RAII), so ownership lives in the **type system**
(`std::unique_ptr` sole ownership / `std::shared_ptr` shared / value containers / move
semantics) and is enforced by the compiler + destructors — **not** by convention + manual
`free()`. There is **no raw `new`/`delete` and no manual `free()`** in idiomatic peer code:
allocation is owned by a smart pointer or a value container (`std::vector<std::byte>` /
`std::string`) whose destructor frees deterministically. Zero-copy decode returns
`std::span`/`string_view` **into** the caller's input buffer (a documented borrow contract;
the input must outlive the view). Despite RAII making leaks far rarer than in C, tests still
run under **ASan + LSan + UBSan** so a leak / use-after-free / UB is a **test failure** —
the C++ analogue of the C peer's manual-memory conformance bonus.

**The A-C-009 lesson, pre-resolved in the type system.** The C peer's single net-new §4.8
finding (A-C-009) was a **plain-`int` refcount race** on shared entities under sustained
concurrent load → heap use-after-free → host crash → fixed with `atomic_int`. In C++ this is
**free**: materialized entities shared across per-EXECUTE dispatch threads (§4.8) are held by
`std::shared_ptr<Entity>`, whose control-block refcount **is atomic by the C++ standard**
(thread-safe ref/unref). So the C peer's hand-rolled atomic fix is the *default* here — the
design holds the shared store entities by `shared_ptr` from the start. **The standard
caveat is built in:** `shared_ptr`'s *refcount* is atomic, but concurrent mutation of the
*pointee* still needs the store lock (`store_safety` below) — `shared_ptr` buys
lifetime-safety, not data-race-safety of the contents.

## Concurrency: C++ standard thread library (deliberate; inherits the §7b CORE gate)

C++'s portable concurrency primitive is the **C++ standard thread library** (`std::thread` /
`std::mutex` / `std::shared_mutex` / `std::condition_variable` / `std::atomic`) — the
standard-library, **type-safe, RAII-locked** analogue of the C peer's raw pthreads (locks via
`std::scoped_lock`/`unique_lock`/`shared_lock`, no manual unlock). For a `--profile core`
peer the §4.8/§4.9/§6.11 reentrancy invariants AND the CORE-gating **§7b concurrency gate
(5/5)** are satisfied by **one reader thread per connection** demuxing `EXECUTE_RESPONSE` by
`request_id` (an `unordered_map<request_id, condvar-slot>`; N7), plus a **data-race-safe
content store**. Store-safety is a **`std::shared_mutex`** (many concurrent readers via
`shared_lock`, exclusive writer via `unique_lock` — reads dominate the dispatch path, so a
shared_mutex beats a plain mutex; `std::mutex` is the simpler fallback). The two §7b findings
are built in structurally:

- **TCP_NODELAY on every connection socket** is mandatory — Nagle/delayed-ACK on small
  req/resp frames was THE throughput killer (Zig §7b: 343 ms/cycle churn is the Nagle
  signature).
- **No blocking syscalls on a cooperative path** — one `std::thread` per connection means a
  blocking `recv` only blocks that connection's thread (the Swift §7b "dedicated thread for
  blocking I/O" finding applied structurally; no shared cooperative pool to stall).
- **Entity lifetime via `std::shared_ptr`** (atomic refcount) pre-resolves A-C-009.

Shared connection sockets are write-serialized with a per-connection `std::mutex`. Not
exercised by the codec (pure/synchronous); validated at S3. C++20 **coroutines are NOT used**
for the core peer — blocking-thread-per-connection is the simpler, portable, §7b-clean shape.
(`A-CPP-008`.)

## Build system: CMake + vcpkg/conan (the slate decision — diverges from the repo make convention BY PROFILE)

**Build system = CMake** (`research/RELEASE-READINESS.md` row 3: "vcpkg/conan + CMake"). This
is the **explicit slate decision** and the C++ ecosystem standard — **unlike** the C peer's
plain GNU `make`. C++ has no single universal build tool, but CMake is the de-facto standard
that **both vcpkg and conan** integrate with and what a systems/games/embedded C++ developer
expects. The repo's "build via make" convention **bends here BY PROFILE (S6)** because CMake
is the idiomatic C++ build system and the slate names it; a thin meta-`Makefile` may still
wrap `cmake --build` as orchestration per repo convention, but **CMake owns the build graph**.
`-std=c++20 -pedantic -Wall -Wextra -Werror`. **C++20** (not C++23-required) is chosen for the
widest reach across embedding toolchains (the reach goal) while still giving `std::span`
(zero-copy decode), `std::format` (hex), and concepts; `<expected>` (technically C++23) ships
usable under `-std=c++20` in GCC 12+/Clang 16+, with the `tl::expected` shim as fallback.
(`A-CPP-003`.) **Test framework: hand-rolled + CTest** — an in-repo assert/count harness
registered with CTest, no GoogleTest/Catch2 dependency (the dep-minimization stance; a corpus
byte-identity test does not need a framework). (`A-CPP-004`.)

## Packaging: CMake package + vcpkg + conan (decentralized, the C++ ecosystem shape)

C++ has **no single central registry**; the two dominant package managers are **vcpkg**
(Microsoft) and **conan** (JFrog), **both named in the slate**. "Publishing" = (a) an
installable CMake package (`find_package(EntityCoreProtocol)` → target
`entity_core::protocol`) consumable via FetchContent / `add_subdirectory` / system install,
plus (b) a **vcpkg port** and a **conan recipe**, each declaring libsodium as the single
dependency. This mirrors the C peer's decentralized stance but uses the C++ package-manager
ecosystem instead of pkg-config-only. The conformance **build** needs none of this — the
codec/peer have no third-party C++ deps to fetch (everything but libsodium is in-repo), so
vcpkg/conan are an S5/publish-recipe concern only.

## Naming: C++-native — namespace `entity_core` + PascalCase types / snake_case functions

C++ **has namespaces** (unlike C's flat global symbol space), so types live in
`namespace entity_core { ... }` rather than carrying an `ec_` symbol prefix — the namespace
**is** the module boundary. Modern-C++ house style: **PascalCase** user types
(`Entity`, `ContentHash`, `PeerId`, `EcfValue`, `ProtocolError`), **snake_case** functions
and variables (`content_hash()`, `sign_detached()`, `ecf_encode()`), private members with a
trailing underscore (`content_hash_`), **scoped `enum class`** members in PascalCase
(`ProtocolError::CapabilityDenied`, `KeyType::Ed25519` — never C-style bare `UPPER_SNAKE`
enums). Headers `.hpp`, impl `.cpp`. **Case-exact hex caveat (A-CL-009 applied proactively):**
all external string/byte hex rendering MUST be **lowercase** to match the Go oracle
(`hex.EncodeToString`) and the cohort. C++'s `std::format("{:02x}")` / `std::hex` is
**naturally lowercase** (good — avoids the A-CL-009 trap by default, like C), but it is
**pinned explicitly**: never `{:02X}`/`std::uppercase` for any address-space tree-path hex
(§3.4/§3.5).

## License: Apache-2.0 (S9 default; libsodium is ISC, compatible)

The C++ ecosystem has no dominant license norm. Keep the repo's **Apache-2.0** default
(explicit patent grant). libsodium is **ISC** (permissive, Apache-compatible — statically
linkable into an Apache-2.0 artifact); no conflict.

## Container: NEW `containers/cpp-toolchain/` (authored, NOT built — S1 boundary)

`containers/cpp-toolchain/Containerfile` is **authored this phase** (NOT reused from
`c-toolchain`, NOT built — S1 = no podman). The C peer's `c-toolchain` has `gcc` + libsodium
but the C++ **peer** needs the C++ toolchain (**g++ / clang++** + the **C++20 standard
library** incl. `<expected>` / `<span>` / `<format>` via `libstdc++-devel`), **CMake as the
build system** + **Ninja** (the slate's build system, vs the C peer's make), and libsodium
static+devel. `fedora:43` base (S1). All packages come through fedora's **reviewed dnf
channel** (exact-pin for repro; the ≥30-day age floor relaxes for the reviewed distro channel
per the S11 clarification — but the pins are ≥30-day-old anyway). The build is fully offline
(`--network=none`): libsodium is pre-installed; everything else is hand-rolled in-repo.
**S2 "verify-and-pin" note** (NOT done now — S1 = no build): the exact clang/ninja fedora:43
NVRs are pinned to the current fedora:43 builds at author time and should be re-verified at
the first container build; the ASan/UBSan pass needs `libasan`/`libubsan`, which on fedora:43
ship **with** gcc — verify at S2.

## Toolchain pins (S11)

All pins come through fedora:43's **reviewed dnf channel** → **exact version pin for
reproducibility**, ≥30-day **age floor relaxes** (the distro has its own security review).
There are **no registry-pulled (vcpkg/conan/crates.io/npm/PyPI-style) ecosystem C++ deps** in
the conformance build at all — the codec, base58, varint, and test harness are hand-rolled
in-repo, and the one crypto dep (libsodium) comes via dnf. This gives C++ **a supply chain as
simple as the C peer's by construction** (one audited C lib + the toolchain, both
reviewed-channel).

- **libsodium 1.0.22-1.fc43** — the one crypto dep; meets the ≥30-day
  floor; statically + privately linked (symbol localization).
- **gcc-c++ 15.2.1-7.fc43** (C++20 compiler; ships libstdc++ `<expected>`/`<span>`/`<format>`;
  pulls libasan/libubsan), **clang 21.1.x** (second compiler for the sanitizer cross-check),
  **cmake 3.31.11-1.fc43** (the slate build system), **ninja 1.13.x** (CMake generator
  backend), **binutils 2.45.1-4.fc43** (objcopy for libsodium symbol localization),
  **libstdc++-devel 15.2.1-7.fc43** (the C++20 stdlib headers) — reviewed distro channel,
  exact pins for repro (clang/ninja exact NVRs verified-and-pinned at the first S2 build).

## Spec version: read v7.75, codec corpus v0.8.0, gate against the v7.77 oracle

Profile + (future) peer derive from `spec-data/v7.75` (the latest **stamped** snapshot;
MANIFEST pins V7 **7.75**). The brief notes the **core floor is stable v7.75→v7.77** and the
conformance oracle anchors at **v7.77** (`entity-core-go @ e8524ed`, the 17-peer matrix
uniform 665 / 0 FAIL). The wire/protocol surface is byte-stable across that window
(`ENTITY-CBOR-ENCODING.md` + `ENTITY-NATIVE-TYPE-SYSTEM.md` unchanged since v7.73 E3 / v7.70
per the v7.75 MANIFEST), so **deriving the peer from v7.75 + gating against the v7.77 oracle**
is the established cohort pattern (no `spec-data/v7.77` stamp is required for a
corroboration-only reach peer; the re-run vendors the oracle, not the snapshot). The codec
uses the **v7.71** corpus (byte-stable v7.71→v7.75; the v7.75 MANIFEST SHA-confirms CBOR +
type-system unchanged from v7.74). (`A-CPP-005`.)

## Inherited current-state floor (pre-resolved so S3 does not re-burn them)

The keystone-menu / cohort-convergence items below are **settled** and folded into the
profile + ambiguity log as **pre-resolved**, NOT open questions:

- **peer_id (§1.5 canonical-form):** `hash_type = 0x00`, **raw pubkey** for Ed25519. IGNORE
  the stale §7.4 `SHA256(pubkey)` skeleton. (6th+ spec-first arrival —
  A-OC-007/A-ZIG-001/A-CL-002/A-SW-008/A-JAVA-004/A-C P1; past decisive.) Model the peer_id
  `data` as `bytes([0x01, 0x00]) || public_key`, Base58-encoded. **Why it matters:** the S2
  corpus uses opaque digests, so a wrong construction passes S2 green and only fails at the
  S4 handshake (401 identity_mismatch).
- **Tree-path hex: lowercase `{:02x}`** (§3.4/§3.5; A-CL-009). C++ lowercase by default;
  pinned.
- **§5.2 trichotomy:** 401 (authn) / 403 (authz) / 401-unresolvable (§5.2a verdict table).
- **§1.1 entity `data` is an ARBITRARY ECF value, NOT necessarily a map** (the A-JAVA-010
  silent-500 trap): model `data` as a general `EcfValue` (`std::variant` over the ECF major
  types) from the start; a map-only model passes S2/S3 green then 500s on the first
  scalar-`data` entity at the live S4 gate.
- **resource_bounds (§4.10, CORE-gating):** r1 oversize-payload → `413 payload_too_large` or
  clean close (default 16 MiB); r2 over-deep delegation chain → **`400 chain_depth_exceeded`
  (MUST be 400, NOT 403)** (default 64) — S3 builds the ~15-line §4.10(b) structural
  pre-check (walk parents, **no sig work**, max=64, **BEFORE** the authz walk; all prior peers
  needed it; over-depth → 400, an *unreachable* parent stays 403); r3 connection flood →
  `503`/close or honest WARN.
- **concurrency (§7b, CORE-gating):** 5/5; data-race-safe store (§4.8 → `std::shared_mutex`),
  shared entity lifetime via `std::shared_ptr` (atomic refcount → **A-C-009 pre-resolved**),
  resilience under load (§4.9), no blocking syscalls on a cooperative pool (one thread per
  connection sidesteps it), TCP_NODELAY.
