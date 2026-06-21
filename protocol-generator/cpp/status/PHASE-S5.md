# Phase S5 — Publish (entity-core-protocol-cpp)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` (the `-pre` marker in CHANGELOG/README; the CMake
`project(VERSION)` / vcpkg `version` / conan `version` fields carry the dotted-numeric `0.1.0` per
convention — A-CPP-015/A-CL-010-style split). · **Spec basis:** V7 spec-data **v7.75**; codec corpus
v7.71 (byte-stable v7.71→v7.75). · **Oracle:** the **v7.77** cohort baseline **`e8524ed`** (go HEAD;
core category set byte-unchanged v7.75→v7.77; `core_gate_sha256` `e09a865f…`, pinned in
`tools/oracle-pin.env`).

S5 polishes the S4-conformant C++ peer — a release **"reach"** peer (systems / games / embedded
ecosystem coverage), corroboration-only by design (the spec-discovery well is dry; its value is
REACH + exercising the generator against C++ idiom: RAII / `std::expected` / templates / move
semantics) — into a *ready-to-publish* artifact. `/entity-rosetta` never publishes (lifecycle
§Publishing); this phase produces the artifacts + the runbook; an operator publishes when arch signs
off v0.1 AND a first external C++ consumer confirms it. C++ has **no central registry**, so
"packaging" is a CMake `find_package` package + a vcpkg port + a conan recipe (none pushed). This doc
is the release-readiness record + the operator handoff.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | **665** / 292P / 278W / **0F** / 95skip, machine-verified `summary.failed == 0` @ the v7.77 oracle `e8524ed` (core_gate `e09a865f…` matches the committed pin). `resource_bounds` 2P+1W active; `concurrency` 5/5. (`status/CONFORMANCE-REPORT.{md,json}`.) |
| §10.1 core-register gate | ✅ | 10/10 (9 `core_register_*` + `validate_echo_dispatch`). |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`). |
| multisig (genuine K-of-N) | ✅ | 11/11, 0 skip — incl `valid_2of3_peer_signed_accepted` PASS (`--name conformance` persistent identity; validator co-signs as the peer → 200). |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, **ASan/LSan/UBSan-clean on g++ AND clang++**. |
| §9.5 53-type floor byte-identical | ✅ | 53/53 (`typereg` peer-side dual + live oracle `type_system_match`). |
| S3 two-peer loopback smoke | ✅ | 11/11; peer_id byte-identical to the cohort (seed `0x11` → `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`). |
| Ed25519 RFC-8032 KAT | ✅ | libsodium sign/verify; all-zero-seed → RFC-8032 TEST-1 pubkey KAT; sign→verify→tamper-reject. |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0 + libsodium ISC third-party notice). Holder `Entity Core Protocol contributors` (cohort convention; A-CPP-015). |
| README + conformance status | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, consume/CMake-package, distribution, verdict). |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre`, literally **"tracks ENTITY-CORE-PROTOCOL-V7 v7.75"** (certified @ v7.77 oracle `e8524ed`). |
| Package metadata (CMake + vcpkg + conan) | ✅ | CMake `install(EXPORT)` + `EntityCoreProtocolConfig.cmake` (template `packaging/cmake/*.in`) + CPack; `packaging/vcpkg/{vcpkg.json,portfile.cmake}`; `packaging/conan/conanfile.py`. All pinned `0.1.0`. **No registry push** (§4). |
| Toolchain pin (S11) | ✅ | gcc-c++ 15.2.1-7.fc43 + clang 21.1.8-4.fc43 + cmake 3.31.11-1.fc43 + ninja 1.13.1-4.fc43 + binutils 2.45.1-4.fc43 + **libsodium 1.0.22-1.fc43** — all via the reviewed fedora dnf channel (exact pin for repro; age floor relaxed but met). Zero registry-pulled ecosystem deps. |
| CI config (Podman, offline) | ✅ authored | `.github/workflows/cpp.yml` — `run-s2.sh` (codec 69/69 + sanitizers) + `run-s4.sh` (assert `summary.failed == 0`) + `run-origination-core.sh` (3/3) in the `cpp-toolchain` image, `--network=none`. Matches the cohort peers that ship a workflow (c/zig/swift/haskell). Committed for reviewability; not wired to a remote/CD by design. |
| Public API surface (Tier-1 frozen) | ◑ documented | the public header `include/entity_core/protocol.hpp` freezes the Tier-1 codec/crypto island (`entity_core::` API, `-fvisibility=hidden` + `ENTITY_CORE_API`); the Tier-2 peer/transport surface (driven via the `host` binary) is documented in README §Consume but not yet exposed as a stable ABI — freeze deferred to publish-prep / first consumer (the profile's `opaque_pimpl` boundary; the C `entity-peer-c` / OCaml `.mli` / Zig `root.zig` analogue). |
| Ed448 / SHA-384 agility | ◑ deferred | A-CPP-002 — libsodium has no Ed448. The §9.1 floor (Ed25519 + SHA-256) is fully native + the only path the corpus exercises. When agility lands: the OCaml FFI-hybrid pattern (sibling C-ABI `ec_ed448_*`) or OpenSSL `EVP_PKEY_ED448`. Non-v0.1; does not affect the floor (69/69 byte-green). |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; A-CPP-014 (peer bug, resolved), A-CPP-015/016 (S5 bookkeeping), A-CPP-002 (deferred, owner research/agility), A-CPP-011 (A-C-009 pre-resolved) — all named-owner-routed. |
| **Published / tagged** | ⛔ **deferred** | operator action — gated on arch v0.1 sign-off + a first external C++ consumer (§7). No auto-tag, no push, no deploy. |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) ≥1
external C++ consumer confirms it works — **not yet met** (no C++ consumer wired). Stays
`0.1.0-pre` until then.

---

## 2. What this peer ships

- **Static + shared `libentity_core_protocol`** — the codec library; `-fvisibility=hidden` +
  `ENTITY_CORE_API`, libsodium symbols localized so an embedder's own libsodium does not collide.
- **Public header** `include/entity_core/protocol.hpp` — the single umbrella header; the frozen
  Tier-1 codec/crypto API (`EcfValue`, `ecf_encode`/`ecf_decode`, base58/varint/content_hash/peer_id,
  Ed25519 + SHA-256), carried over a `std::expected<T, Error>` channel.
- **CMake package** — `find_package(EntityCoreProtocol 0.1.0)` → `entity_core::protocol`
  (`EntityCoreProtocolConfig.cmake`, generated by the install + CPack); `find_dependency(libsodium)`.
- **vcpkg port** `packaging/vcpkg/` + **conan recipe** `packaging/conan/conanfile.py` — the two
  decentralized C++ package managers (the slate row-3 decision).
- **Host executable** `host` (`test/host.cpp` — the S4 conformance driver: `--port` / `--name` /
  `--debug-open-grants` / `--validate`, emits `LISTENING …`). Test/conformance only — not part of
  the published library surface.
- **Crypto:** Ed25519 + SHA-256 via libsodium — the one runtime dep, distro-channel. Ed448/SHA-384
  agility deferred (A-CPP-002).

---

## 3. Public API surface (the S5 "settle the surface" decision)

The stable contract is the **public header `include/entity_core/protocol.hpp`** — the Tier-1
codec/crypto island. `-fvisibility=hidden` + the `ENTITY_CORE_API` export macro hide everything else;
libsodium's symbols are localized so an embedder's own libsodium does not collide. The **Tier-2 full
peer/transport** (`Peer`/`Transport`, the store + capability surface) is driven via the `host` binary
— **not** part of the frozen public header at `0.1.0-pre`. Exposing it as a stable Tier-2 ABI (via
the profile's `opaque_pimpl` boundary — a `std::unique_ptr<Impl>` Pimpl + a second public header) is
a mechanical publish-prep step, deferred until the surface is frozen against a first external
consumer — the honest `-pre` state (mirrors the C `entity-peer-c` / OCaml `.mli` / Zig `root.zig`
deferral). Internal units may churn without a semver bump.

---

## 4. Packaging notes specific to C++

- **C++ has no central package registry** (no crates.io/npm/Maven/Hex/opam). The slate (row 3) names
  **CMake + vcpkg + conan** — three parallel decentralized surfaces, all authored here:
  (a) an installable CMake `find_package` package (`EntityCoreProtocolConfig.cmake` via
  `install(EXPORT)` + `configure_package_config_file`; CPack emits the source/binary tarball);
  (b) a vcpkg port (`packaging/vcpkg/`); (c) a conan recipe (`packaging/conan/conanfile.py`). This
  mirrors the C peer's decentralized stance but uses the C++ package-manager ecosystem instead of
  pkg-config-only.
- **The `-pre` / numeric split (A-CPP-015).** CMake's `project(... VERSION ...)`, vcpkg's `version`,
  and conan's `version` are all dotted-numeric-only — they carry `0.1.0`; the `-pre` marker lives in
  CHANGELOG/README/this doc. Same split the C peer hit with `pkg-config` and CL with ASDF (A-CL-010).
- **CMake-as-build-system is a deliberate profile divergence from the repo's `make` convention**
  (A-CPP-003, S6) — CMake is the idiomatic C++ build system and is what vcpkg AND conan integrate
  with. A meta-Makefile may wrap `cmake --build` as a thin shim, but CMake owns the build graph.
- **C++23, not C++20 (A-CPP-009).** GCC/Clang gate `<expected>` behind `__cplusplus > 202002L`, so
  the build is `-std=c++23` to keep the headline `std::expected` idiom with **zero** new deps (vs
  vendoring `tl::expected`). The conan recipe and CMake both pin C++23. Widest-reach is slightly
  narrowed (C++23 compilers), but the dep-minimization win is the right call (recorded decision).
- **Simplest supply chain in the cohort alongside C.** One audited C lib (libsodium, reviewed distro
  channel) + the toolchain; **zero** registry-pulled ecosystem deps (CBOR/base58/varint/test-harness
  all hand-rolled in-repo). vcpkg/conan are S5 recipe-authoring only, and even then declare libsodium
  as the single dep.
- **Crypto-agility — Ed25519 + SHA-256 NATIVE, Ed448 deferred (A-CPP-002).** libsodium closes the
  §9.1 floor (69/69 byte-green) but has no Ed448. When agility lands, the dependency-lightest route
  is the OCaml FFI-hybrid pattern (the sibling C-ABI `ec_ed448_*`) or OpenSSL `EVP_PKEY_ED448`. An
  explicit non-v0.1 item; does not affect the floor.
- **ThreadSanitizer pass not runnable in-container (A-CPP-013).** `libtsan` is absent from the
  `cpp-toolchain` image. The §7b live concurrency gate (5/5) + the structural `std::shared_ptr` /
  `std::shared_mutex` design carry the data-race coverage; a TSan pass is a release-prep nicety, not
  a conformance gate.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-CPP-* items are resolved-in-peer or owner-routed; none block release. Full text in
`status/SPEC-AMBIGUITY-LOG.md`:

- **A-CPP-014** §1.4 R1 path-flex embedded-NUL guard was a no-op — **owner: peer**, FIXED at S4
  (found by validate-peer; `src/dispatch.cpp` `path_flex_ok` now scans bytes + rejects control
  bytes). Not a spec defect.
- **A-CPP-015** copyright-holder convention — **owner: research/operator**, bookkeeping; matched the
  dominant cohort convention (`Entity Core Protocol contributors`, what the C peer + 13 others use)
  over the brief's `entitychurch` form, for cohort LICENSE uniformity + profile authority (S6).
- **A-CPP-016** packaging surface (CMake + vcpkg + conan, none pushed) — **owner: operator**; the
  publish action + registry-submission decision. The publish-time TODOs (repository_url, tag,
  tarball hash) are explicit in each recipe. Non-blocking.
- **A-CPP-009** `<expected>` forces `-std=c++23` — **owner: operator**, RESOLVED (bumped, zero deps).
- **A-CPP-002** Ed448 native gap — **owner: research/agility**, DEFERRED. Does not affect the floor.
- **A-CPP-011** §4.8 shared-entity lifetime via `std::shared_ptr` (atomic refcount) — the A-C-009
  race **structurally pre-resolved** in C++ (RAII owns lifetime). Corroboration, no new ask.
- **A-CPP-013** `libtsan` absent — **owner: operator/container**, documented; §7b live gate carries
  coverage.
- **A-CPP-001 / -003 / -004 / -005 / -006 / -010** native-codec / CMake-build / test-harness /
  spec-snapshot header / scaffolding source / clang portability — **owner: operator**, RESOLVED or
  documented; non-blocking.
- The §1.5-vs-§7.4 peer-id contradiction is built-to-§1.5 (PRE-RESOLVED P1) — the **6th+ spec-first
  corroboration** (A-OC-007 / A-ZIG-001 / A-CL-002 / A-SW-008 / A-JAVA-004 / A-C P1); no new ask.

**Net S5 findings: 0 new spec items** — A-CPP-015/016 are packaging/licensing bookkeeping. The
discovery well stays dry, as the corroboration-only reach-peer slate predicted.

---

## 6. CONFORMANCE-MATRIX row (added this phase)

Appended to the repo-root `CONFORMANCE-MATRIX.md` §1 primary table (Tier-3, alongside C/Zig/Ada),
format-identical to the existing rows:

```
| **C++** | 3 | v7.77 | `e8524ed` | 665 · **0F** | native hand-rolled | native — libsodium | deferred (libsodium has no Ed448) | CMake pkg + vcpkg + conan, `0.1.0-pre` |
```

---

## 7. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar AND an
external C++ consumer confirms the peer:

1. **Decide in-repo vs standalone repo** — per-language sibling repos are deferred keystone-wide
   (S10); current default is in-repo under `protocol-generator/cpp/`.
2. **Settle the Tier-2 public-surface freeze** (§3): expose the locked `Peer`/`Transport`/store
   surface behind the `opaque_pimpl` boundary (a second public header), build-verified in the
   `cpp-toolchain` image.
3. **Promote version** `0.1.0-pre → 0.1.0` once the promotion gate (§1) is met — the CMake/vcpkg/
   conan `version` fields are already numeric `0.1.0`; drop the `-pre` from CHANGELOG/README.
4. **Set `repository_url`** in `profile.toml [publishing]`, the vcpkg `portfile.cmake`
   (`vcpkg_from_github(... REF v0.1.0 SHA512 ...)`), and the conan `conanfile.py` (a tagged-release
   `source()` instead of `exports_sources`). All three currently point at the in-repo tree.
5. **Publish** — push the vcpkg port to a registry/overlay, the conan recipe to conancenter or a
   private remote, and/or host the CPack tarball at a **tagged release**. **Tag the release** at the
   reviewed commit at this point only (lifecycle §"no auto-tag"). There is no single registry to
   submit to.
6. **Wire CI** (`.github/workflows/cpp.yml`: `run-s2.sh` + `run-s4.sh` assert `summary.failed == 0`
   + `run-origination-core.sh` in `cpp-toolchain`, `--network=none`) to the chosen repo's runner, or
   fold into the keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
7. **Pin discipline** (S11): gcc-c++ 15.2.1 + clang 21.1.8 + cmake 3.31.11 + ninja 1.13.1 + binutils
   2.45.1 + libsodium 1.0.22 stay exact (reviewed distro channel); re-pinning is deliberate +
   reviewed. **Re-confirm 665·0F against a clean `e8524ed` oracle** (`tools/oracle-pin.env`,
   `core_gate_sha256` `e09a865f…`) if the oracle is rebuilt.

---

## 8. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged — gated on
arch v0.1 + a first external C++ consumer; `0.1.0` promotion pending that consumer; Tier-2 surface
freeze pending; Ed448 agility deferred; ThreadSanitizer documented as release-prep; CI authored-
offline but not wired to a remote — by design). Regression GREEN (**S2 69/69 ASan/LSan/UBSan-clean
on g++ + clang++ · S3 11/11 · S4 665 · 292P/278W/0F/95S @ e8524ed · origination 3/3 · multisig 11/11
· 53-type 53/53**). Ambiguity log finalized + owner-routed (A-CPP-014 resolved, A-CPP-015/016 S5
bookkeeping, A-CPP-002 deferred). The CONFORMANCE-MATRIX C++ row added (§6). Operator handoff (§7)
prepared. **S5 objective met; the C++ reach peer is publish-ready and parked at `0.1.0-pre` pending
arch v0.1 sign-off + a first external C++ consumer. Nothing published.**
