# entity-core-protocol-cpp — Phase S2 (Codec) Summary

**Release "reach" peer** (C++20/23 — RAII / `std::expected` / `std::span` /
templates / move-semantics idiom; systems/games/embedded coverage; corroboration-only) · **Status:
COMPLETE — 69/69 wire-conformance, 0 FAIL; ASan/LSan/UBSan-clean on BOTH g++ AND clang++;
cpp-toolchain image BUILT with exact NVR pins; Go oracle + FFI codec cross-checks both GREEN.**

## Result

- **ECF codec corpus 69/69 byte-identical** — the **11th** independent native codec to converge
  (C# / TS / OCaml / Elixir / Zig / Common-Lisp / Swift / Haskell / Java / C → S8/S9). 15/15
  self-tests pass (full uint64/-2^64 range, float ladder, N1/N2, base58 round-trip, peer_id §1.5,
  Ed25519 RFC-8032 TEST-1 + sign/verify/tamper). Total harness: **84 PASS / 0 FAIL**.
- **Spike PASSED FIRST** (profile mandate) — 20/20 (14 float + 6 map_keys), byte-identical, first
  run. See below.
- **ASan/LSan/UBSan-clean** — the C++ memory-correctness conformance bonus: a leak / UAF / overflow
  / strict-aliasing-UB would be a test failure; the full run is clean (RAII makes leaks rare; the
  sanitizers confirm the zero-copy decode borrow + the recursive value tree are sound).
- **Cross-compiler hygiene** — the same codec builds + passes **69/69 under clang++** (libstdc++)
  too, not just g++. The clang pass earned its keep: it caught A-CPP-010 (a g++-only portability
  slip in the recursive variant).
- **Container BUILT** — `containers/cpp-toolchain/Containerfile` built with podman; the S1
  "verify-and-pin at S2" NVRs resolved + pinned (below). Added `pkgconf-pkg-config` (CMake's
  `pkg_check_modules(libsodium)`).

Full detail: `CONFORMANCE-REPORT.md`.

## The spike (PHASE-S1 mandate) — DONE FIRST, PASSED

Before the full build, the **float + map_keys v7.71 vectors** were pushed through the hand-rolled
encoder/decoder (`conformance --spike`). Float minimization (double→f16 re-decode-and-compare) is
the highest bug-density code in the whole peer; length-then-lex (CTAP2) map ordering is the other
load-bearing canonical risk.

**Spike result: 20/20 byte-identical (14 float + 6 map_keys), ASan/UBSan-clean, zero `-Werror
-pedantic` warnings — on the first run.** The native canonical layer is confirmed: the pure-integer
f16-representability test reproduces the whole float ladder (incl. the f32-not-f16 boundary
`65503.0 → fa477fdf00` and `1.1 → fb3ff199999999999a`), the four specials emit their pinned bytes
(NaN f97e00 / +Inf f97c00 / -Inf f9fc00 / -0.0 f98000), and the length-first `std::sort` comparator
reproduces all six map-ordering vectors incl. the mixed text/byte `map_keys.5`. **No `ffi` fallback
needed** — D1's native hand-roll bet stands; the documented fallback was not triggered.

## Resolved container NVR pins (the S1 "verify-and-pin at S2" items)

Built on fedora:43 (`registry.fedoraproject.org/fedora:43`, cache `aa03ca9219a8`). The un-suffixed
S1 placeholders are now exact (reviewed distro channel → exact-pin for repro, ≥30-day age relaxed):

| Package | Resolved NVR |
|---|---|
| **clang / clang++** | **21.1.8-4.fc43** |
| clang-tools-extra | 21.1.8-4.fc43 |
| libcxx / libcxx-devel / libcxxabi(-devel) | 21.1.8-4.fc43 |
| **ninja-build** | **1.13.1-4.fc43** |
| gcc-c++ / gcc / libstdc++(-devel/-static) | 15.2.1-7.fc43 |
| libasan / libubsan | 15.2.1-7.fc43 (ship with gcc-15.2.1 — S1 item 2 confirmed) |
| cmake | 3.31.11-1.fc43 |
| binutils | 2.45.1-4.fc43 |
| libsodium(-static/-devel) | 1.0.22-1.fc43 |

`<expected>` / `<span>` / `<format>` confirmed usable — but `<expected>` ONLY under `-std=c++23`,
not c++20 (A-CPP-009). `libasan`/`libubsan` ship with gcc-15.2.1 (S1 item 2 confirmed). No
openssl-devel / FFI-agility `.a` in the core image (Ed448 deferred, S1 item 3 holds).

## Conformance + cross-checks (the codec gate)

1. **The vendored fixture IS the Go oracle output.** `conformance-vectors-v1.cbor` (v7.71, sha
   `41d68d2d…`) embeds the 3-way Go×Rust×Python byte-locked `canonical` field per vector. The
   harness decodes the fixture with THIS peer's OWN decoder (a decoder bug = a conformance failure
   per §E.3), runs each vector through the codec, and byte-compares. **69/69 byte-identical.**
2. **Go `wire-conformance` rebuilt + fixture regenerated (the ground-truth provenance check).** Per
   the runbook isolation rule, `git archive <go HEAD 71b6ba8> | tar -x` into a temp dir **OUTSIDE**
   the go repo, built `wire-conformance` there (`GOWORK=off`, `CGO_ENABLED=0`, go-toolchain image),
   ran `build-fixture` on the vendored `.diag` → **regenerated `.cbor` is BYTE-IDENTICAL** to the
   vendored one (sha `41d68d2d…` match). So our 69/69 is against the live Go oracle's own canonical
   emission. The go repo was untouched (clean, same HEAD — read-only confinement honored).
3. **Sibling C-ABI FFI codec cross-check.** Built `libentitycore_codec.so` (entity-core-codec-ffi-c)
   and ran a differential probe (`test/ffi_xcheck.cpp`): **28/28 PASS** (14 entity-encode + 14
   content_hash) across a battery incl. the uncovered u64/-2^64 band + float-ladder edges (the
   corpus tops out at i64max — codec-review-heuristic.md). Two independent codecs agree byte-for-byte.

## Codec architecture (the C++-native shapes)

- **Value model = `std::variant`** over the ECF major types (`Int / double / FloatSpecial / bool /
  Null / Bytes / Text / Array / Map`), `EcfValue` in `include/entity_core/ecf.hpp`. **P4 honored
  from the start:** the entity `data` field is a GENERAL `EcfValue` (any major type), never
  map-typed — the A-JAVA-010 silent-500 trap cannot fire at S4. Recursive alternatives boxed for
  libc++/clang portability (A-CPP-010).
- **Error channel = `std::expected<T, EcfError>`** (A-CPP-007) — value-based, no exceptions on the
  hot path. `EcfError { Truncated, NonCanonicalEcf, TagRejected, DuplicateKey, NonTextByteKey,
  DepthExceeded, BadInput }`. Forces the build to **C++23** (A-CPP-009) — zero new deps.
- **Integers in native `std::uint64_t`** — `Int { bool negative; std::uint64_t arg; }` maps the
  CBOR major-0/1 head argument directly (no ulong/int63 special-casing; cleanest int story with
  C/Zig/Rust). uint64-max and -2^64 both round-trip. `std::bit_cast` for the float bit-twiddling
  (no strict-aliasing UB; UBSan-clean).
- **Zero-copy-capable decode via `std::span`** — the decoder bounds-checks every read through the
  size-carrying `std::span` (the C++ answer to C's "won't bounds-check"); it COPIES byte/text into
  owned nodes for the codec gate (so the input span need not outlive the tree — RAII frees the
  whole tree deterministically). The lifetime-borrowing variant is a peer-layer refinement.
- **RAII everywhere** — no raw `new`/`delete`/`free`; value containers (`std::vector` / `std::u8string`)
  + `Box` (`std::unique_ptr` value holder) own all memory; destructors free deterministically.
  libsodium secret-key material zeroed via a small RAII guard.
- **Hand-rolled everything but crypto** — ECF (`ecf.cpp`), base58 (`base58.cpp`), varint
  (`varint.cpp`), content_hash/peer_id (`identity.cpp`), and the CTest harness all in-repo;
  libsodium the one runtime dep (Ed25519 + SHA-256), RAII-facaded in `crypto.cpp`.
- **Lowercase hex pinned** (`identity::hex_lower`, P2 / A-CL-009) — `0123456789abcdef`, never upper.
- **CMake + Ninja** build (A-CPP-003); static + shared lib targets (`entity_core::protocol`); the
  hand-rolled CTest harness (A-CPP-004; no GoogleTest/Catch2).

## The two net-new S2 findings (both fixed; vectors/oracle never doctored — S5)

1. **A-CPP-009** — `<expected>` is C++23-only on the pinned libstdc++ (NOT usable under
   `-std=c++20`, contra A-CPP-007). Fixed by building to `-std=c++23` (keeps the std::expected
   idiom, zero new deps; the `tl::expected` shim fallback NOT needed). Profile-field correction.
2. **A-CPP-010** — the recursive `EcfValue` variant relied on `std::vector<incomplete>` which g++
   tolerates but clang++ (same libstdc++) rejects eagerly. Fixed with a value-semantic `Box`
   indirection; builds identically on both compilers. Caught by the clang cross-pass.

Neither is a spec defect — both are C++ toolchain / engineering findings. The discovery well stays
dry (corroboration-only reach peer, as the profile predicted).

## Files created/changed (S2)

- `include/entity_core/{ecf,varint,base58,crypto,identity,protocol}.hpp` — the public codec headers
- `src/{ecf,varint,base58,crypto,identity}.cpp` — the hand-rolled codec impl
- `test/conformance.cpp` — the CTest wire-conformance harness + spike mode + selftests
- `test/ffi_xcheck.cpp` — the optional FFI byte-for-byte cross-check
- `CMakeLists.txt` — CMake/Ninja build (C++23, ASan/UBSan tests, lib targets, optional FFI xcheck)
- `run-s2.sh` — container-bound S2 runner (test / spike / clang / xcheck)
- `containers/cpp-toolchain/Containerfile` — NVRs resolved + pinned; built
- `status/{PHASE-S2,CONFORMANCE-REPORT}.md` + `SPEC-AMBIGUITY-LOG.md` (A-CPP-009/010)

## Exit criteria

All 69 vectors PASS byte-identical · spike PASSED first · conformance report GREEN · ambiguity log
no blocking items (A-CPP-009/010 non-blocking) · codec compiles clean under `-Wall -Wextra -Werror
-pedantic` on g++ AND clang++ · ASan/LSan/UBSan-clean · container built. **S2 PASS.**

## What S3 should tackle

1. **Peer machinery** on top of the codec — store (`std::shared_mutex` + `std::shared_ptr<Entity>`,
   A-C-009 pre-resolved), dispatch, transport (one `std::thread`/connection, TCP_NODELAY), the
   §5.2a trichotomy, §4.10 resource bounds (413 / **400 chain_depth_exceeded** / 503), the §7a/§7b
   scaffolding from GUIDE-CONFORMANCE (A-CPP-006).
2. **The zero-copy-borrow decode variant** (`std::span`/`string_view` into the input) if a hot path
   wants it — the codec gate did not need it.
3. Carry the **C++23** standard forward (A-CPP-009); keep the clang cross-pass in the S3/S4 loop.
