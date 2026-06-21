# entity-core-protocol-cpp — Phase S1 (Profile) Summary

**Release "reach" peer** (C++ — RAII / `std::expected` / templates /
move-semantics idiom; systems/games/embedded coverage; `research/RELEASE-READINESS.md` §2 row 3;
**corroboration-only**, discovery well dry) · **Status: COMPLETE (authoring) — container
AUTHORED (not built), no toolchain run (S1 boundary).**

## Preconditions resolved at session start
- **Spec version.** Read `spec-data/v7.75` (the **latest stamped** snapshot; MANIFEST pins V7
  **7.75**). The brief notes the core floor is stable **v7.75→v7.77** and the conformance oracle
  anchors at **v7.77** (`entity-core-go @ e8524ed`, the 17-peer matrix uniform 665 / 0 FAIL). The
  wire/protocol surface is byte-stable across that window (`ENTITY-CBOR-ENCODING.md` +
  `ENTITY-NATIVE-TYPE-SYSTEM.md` unchanged since v7.73 E3 / v7.70 per the v7.75 MANIFEST), so
  deriving the peer from v7.75 + gating against the v7.77 oracle is the established cohort pattern
  (no `spec-data/v7.77` stamp needed for a corroboration-only reach peer). The codec corpus is
  **v7.71** (byte-stable v7.71→v7.75). (A-CPP-005.)
- **D1 binding (the slate decision).** C++ codec = **native hand-roll, NOT FFI**
  (`research/RELEASE-READINESS.md` §3-D1). Affirmed explicitly in the profile + rationale: an FFI
  C++ peer is "the C peer in a trench coat"; native exercises the generator against C++ idiom.
  Crypto stays libsodium; Ed448 deferred (libsodium gap). (A-CPP-001 / A-CPP-002.)
- **Closest analog = the C peer** (`protocol-generator/c/`): same libsodium crypto, same
  hand-rolled canonical ECF codec, same systems-language footguns, and — crucially — the
  **A-C-009** §4.8 atomic-refcount finding (no-GC heap use-after-free in a plain-int refcount
  under live concurrency, fixed with `atomic_int`). C++ pre-resolves A-C-009 **in the type
  system** via `std::shared_ptr` (atomic control-block refcount by the standard). But C++ is a
  DELIBERATELY distinct idiom point: it does NOT inherit C's raw return-code error model
  (→ `std::expected`) or its unguarded malloc/free (→ RAII / smart pointers / move).
- **No-peek discipline.** Derived from V7 + the C++ ecosystem. Read the cohort `{c, csharp, rust,
  zig, swift}` profiles for the field schema/exemplar shape + the proven libsodium/canonical-CBOR
  stack — config structure + the already-decided systems-language library survey, not spec
  interpretation. The C peer + `ffi-c.md` are the closest precedent (same hand-roll-CBOR +
  libsodium decision); the C# peer is the error-model contrast (exceptions, vs C++'s
  std::expected); rust/zig the native-int-trap + §7b approaches.
- **S1 boundary honored.** No podman run, no container build, no toolchain install, no compile.
  Authoring only. (libsodium / fedora NVRs were read from the existing c-toolchain Containerfile +
  the cohort — metadata, not a build/fetch.)

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** hand-roll (NOT FFI) | **D1 binding** — affirmed. Sibling C/Rust FFI codec kept as a free cross-check oracle, NOT the codec. `ffi` = documented fallback only if the S2 spike fails (A-CPP-001) |
| CBOR | **hand-rolled** (`ecf.{hpp,cpp}`, std::span/std::byte zero-copy decode, std::expected) | no C++ CBOR lib gives ECF (tinycbor leaves float-min/tag-reject/CTAP2 to caller + is a C lib + churn; cppcodec is base64/hex only; jsoncons DOM/non-determinism; QCBOR alpha-only). Float-min = highest bug-density code |
| Ed25519 + SHA-256 | **libsodium** (`crypto_sign_*` / `crypto_hash_sha256`), RAII C++ facade | the ONE runtime dep; profile-authorized (S6, per D1) + S11-pinned; statically + privately linked w/ symbol localization |
| Ed448 / SHA-384 (agility) | **DEFERRED** (do NOT FFI around it for v0.1) | libsodium has no Ed448; same gap as C/Zig/OCaml/Rust/Swift. Core = Ed25519+SHA-256 only. When agility lands: sibling FFI agility `.a` (extern "C") preferred over heavy OpenSSL (A-CPP-002) |
| base58 / varint | **hand-rolled** | dep-minimization; ~80-line base58, LEB128 varint |
| Error model | **`std::expected<T, E>`** (Result-style) | the C++-modern idiom — NOT exceptions (that's C#'s point), NOT C's return-code/out-param. Exceptions reserved for programmer-error only, caught at the conn-task boundary (§4.9). The headline C++-idiom choice (A-CPP-007) |
| Memory / ownership | **RAII + smart pointers + move semantics** (no raw new/delete/free) | the headline idiom seam vs C: ownership in the type system, deterministic destruction. ASan+LSan+UBSan make memory bugs TEST FAILURES |
| Concurrency | **C++ standard threads** (std::thread / std::shared_mutex store / shared_ptr entities / TCP_NODELAY) | type-safe RAII-locked analogue of C's pthreads; **A-C-009 pre-resolved** via shared_ptr atomic refcount; coroutines NOT used; inherits §7b CORE gate (A-CPP-008) |
| Naming | namespace `entity_core` + PascalCase types / snake_case fns; lowercase `{:02x}` hex | C++-native (namespace = module boundary, no C-style ec_ prefix); hex lowercase by default but pinned (A-CL-009) |
| Build / test / pkg | **CMake + Ninja** + **hand-rolled + CTest** harness + **CMake package + vcpkg + conan** | the SLATE decision (vs C's make); S6 profile-decides bends the repo make convention for C++ idiom (A-CPP-003); no GoogleTest/Catch2 dep (A-CPP-004); C++ has no single central registry |
| Container | **NEW `cpp-toolchain`** (authored, NOT built) | g++/clang++ + C++20 stdlib (`<expected>`/`<span>`/`<format>`) + CMake-build-system + ninja + libsodium static+devel. NOT a reuse of c-toolchain |
| License | Apache-2.0 | S9 default; libsodium ISC (compatible) |
| Int model | native `std::uint64_t` (head-form maps directly) | cleanest int story with C/Zig/Rust; no ulong/int63 special-casing; UBSan watches signed overflow |

## Crypto pin + release date
- **libsodium `1.0.22-1.fc43`** — fedora's build, ~2 months old at authoring → clears
  the ≥30-day floor even though, as a **reviewed distro channel**,
  the age floor relaxes; exact pin stands for reproducibility). The high-level `crypto_sign_*` /
  `crypto_hash_sha256` calls are stable + byte-identical across the 1.0.2x line →
  conformance-neutral. CVE-2025-69277 is in the low-level `crypto_core_ed25519_is_valid_point`
  validator we do **not** call. **There are NO registry-pulled (vcpkg/conan/crates.io/npm/PyPI)
  ecosystem C++ deps** in the conformance build — the codec/base58/varint/test-harness are all
  hand-rolled in-repo; vcpkg/conan are an S5/publish-recipe concern only. The C++ peer's supply
  chain is as simple as the C peer's by construction.

## Container — AUTHORED, NOT built (S1 boundary)
`containers/cpp-toolchain/Containerfile` is **NEW** (authored this phase; NOT a reuse of
`c-toolchain` — C++ needs the C++ toolchain + the CMake build system + ninja). fedora:43 base.
Pinned packages (reviewed dnf channel; exact-pin for repro, age floor relaxed but met):
- **gcc-c++ 15.2.1-7.fc43** (g++; ships libstdc++ `<expected>`/`<span>`/`<format>`; pulls
  libasan/libubsan), **libstdc++-devel/-static 15.2.1-7.fc43** (the C++20 stdlib headers),
  **clang + clang-tools-extra + libcxx/-abi** (the second compiler for the ASan/UBSan
  cross-check), **cmake 3.31.11-1.fc43** (the slate build system), **ninja-build** (CMake
  generator backend), **make 4.4.1-11.fc43** (thin meta-orchestration shim), **binutils
  2.45.1-4.fc43** (objcopy for libsodium symbol localization), **libsodium 1.0.22 +
  -static + -devel**. **Authored, NOT built; no podman runs in S1.**

**"To verify-and-pin at S2" items (recorded, NOT done — S1 = no build):**
1. The exact **clang / ninja** fedora:43 NVRs are pinned to the current fedora:43 build at author
   time (un-suffixed in the Containerfile where the exact NVR was not read offline); re-verify +
   re-pin the exact NVR at the first S2 build.
2. ASan/UBSan test pass needs `libasan`/`libubsan` — on fedora:43 these ship **with** gcc-15.2.1
   (pinned explicitly anyway); confirm at S2.
3. Ed448 agility (deferred) would need `openssl-devel` OR the sibling FFI agility `.a` — an "add
   at S2/agility" item, **not** in the core image.

## Ambiguity log
6 PRE-RESOLVED inheritances (P1–P6) + 8 entries (A-CPP-001..008), **none blocking** the §9.1 floor:
- **P1** peer_id = §1.5 identity-multihash (raw pubkey); **P2** hex lowercase; **P3** §5.2a
  401/403 trichotomy; **P4** entity `data` = arbitrary ECF value (A-JAVA-010 silent-500); **P5**
  resource_bounds (413 / **400 chain_depth_exceeded** / 503); **P6** §7b CORE gate (shared_mutex
  store + TCP_NODELAY) **+ A-C-009 atomic-refcount pre-resolved via `std::shared_ptr`**. All
  settled cohort convergence, built in.
- **A-CPP-001:** codec = native hand-roll, NOT FFI — **D1 binding** affirmed; sibling FFI kept as
  cross-check oracle.
- **A-CPP-002:** Ed448 native gap (libsodium has none) — DEFERRED; do NOT FFI around it for v0.1;
  sibling-FFI-`.a` route preferred when agility lands. Non-blocking for the floor.
- **A-CPP-003:** build = CMake + vcpkg/conan (slate decision; S6 bends the repo make convention).
- **A-CPP-004:** test = hand-rolled + CTest (no GoogleTest/Catch2; dep-minimization).
- **A-CPP-005:** read v7.75 (latest stamped); gate against the v7.77 oracle. Provenance note.
- **A-CPP-006:** §7a/§7b scaffolding is GUIDE-carried, not in spec-data (corroborates
  A-SW-006/A-C-003). Pull at S3/S4 from the guide.
- **A-CPP-007:** error model = `std::expected` (NOT exceptions, NOT C's return-codes) — the
  headline C++-idiom choice.
- **A-CPP-008:** concurrency = C++ standard threads + std::shared_mutex (S3 decision; coroutines
  not used; A-C-009 pre-resolved via shared_ptr).

## Exit criteria
profile.toml fully populated (**no TBD**) · rationale written · **container AUTHORED (new
`cpp-toolchain` Containerfile), NOT built** · ambiguity log initialized with **no blocking-severity
items** (A-CPP-002 Ed448 is the agility higher bar, non-blocking for the codec floor; D1 native
codec / std::expected error model / CMake build / peer_id + hex + data-shape + resource_bounds +
concurrency all pre-resolved or profile-decided) · this summary complete. **S1 PASS (authoring).**

## Time spent
~1 session (single-pass authoring): read the PHASE-S1 contract + PROMPT-CONSTANTS + the
`{c, csharp, rust, zig, swift}` profile exemplars + the seeded agent-memory (peer-id, hex-case,
401/403, A-JAVA-010, resource_bounds, §7b, A-C-009, supply-chain-30day-pin) + the C peer's full
profile/rationale/ambiguity-log (the closest analog, incl. A-C-009) + the `research/RELEASE-
READINESS.md` slate context (D1) + the v7.75 MANIFEST; authored the five deliverables (profile,
rationale, container, PHASE-S1, ambiguity log). No build, no toolchain run (S1 boundary).

## What S2 should tackle first
1. **Run the codec spike before the full build** (the load-bearing canonical risk): hand-roll
   `ecf.{hpp,cpp}` enough to push the `map_keys` + `float` v7.71 vectors through the ECF
   encoder/decoder and assert byte-identity. **Float minimization is the highest bug-density code
   in the whole peer** — hardcode the four specials (F9 7E00 NaN / 7C00 +Inf / FC00 -Inf / 8000
   -0.0), minimize by double→float→half re-decode-and-compare. Watch the C++ seams: bounds-check
   every decoder read via `std::span` (size-carrying — checked, never UB), zero-copy decode is a
   borrow contract (input outlives the span/view), native `std::uint64_t` maps the head-form
   directly (UBSan on for signed-overflow UB), `{:02x}` (lowercase) for all address-space hex
   (A-CL-009 avoided by default but pinned), and the error channel is `std::expected` (NOT
   exceptions on the hot path).
2. **Build the cpp-toolchain image + smoke-test** (the deferred S1 build): confirm `<expected>` /
   `<span>` / `<format>` are usable under `-std=c++20` in the pinned libstdc++ (and libc++ for the
   clang pass); confirm libasan/libubsan come with gcc-15.2.1; verify + re-pin the exact clang +
   ninja NVRs.
3. **Wire libsodium crypto + verify raw-pubkey peer_id** (P1 / A-CPP-002): `crypto_sign_*` for
   Ed25519, `crypto_hash_sha256` for SHA-256, behind a RAII facade; construct the peer_id per
   **§1.5** (identity-multihash, raw pubkey), NOT §7.4 — the corpus won't catch a wrong
   construction (opaque digests); it only blows up at the S4 handshake. Link libsodium statically +
   privately (-fvisibility=hidden + symbol localization).
4. **Run tests under ASan/LSan/UBSan from the start** (via CTest) — memory correctness as a
   conformance bonus (RAII makes leaks rare, but the sanitizers catch any zero-copy borrow-lifetime
   slip).
5. **Hold the shared store entities by `std::shared_ptr` from the start** (A-C-009 pre-resolved) —
   so the §7b concurrency gate's sustained-load fan-out never hits the C peer's plain-int refcount
   race; the store mutation still takes the `std::shared_mutex`.
