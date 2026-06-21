# entity-core-protocol-c — Phase S1 (Profile) Summary

**Peer #10** (C — procedural / manual-memory / return-code idiom;
the last untried memory axis; breadth probe, low-yield-discovery) · **Status: COMPLETE
(authoring) — container REUSED (not built), no toolchain run (S1 boundary)**

## Preconditions resolved at session start
- **Spec version.** Read `spec-data/v7.75` (the current snapshot; MANIFEST pins V7
  **7.75**, the input version). The codec corpus is **v7.71**: `ENTITY-CBOR-ENCODING.md`
  + `ENTITY-NATIVE-TYPE-SYSTEM.md` are byte-stable v7.71->v7.75 (cohort SHA-verified;
  the only deltas — the v7.73 §4.7 construct-vs-decode erratum + the v7.67 large-uint
  `int.15/16/17` additions — are already reflected in the v0.8.0 corpus the 9-peer matrix
  runs). Noted: the verbatim body file's internal changelog header reads "Version: 7.73"
  while MANIFEST pins 7.75 — copy artifact, MANIFEST authoritative (A-C-002).
- **peer_id verified directly in spec-data.** `ENTITY-CORE-PROTOCOL-V7.md` **line 459**
  (§1.5 canonical-form table) = Ed25519 `0x01` -> `0x00` identity-multihash, "The digest
  IS the public_key (v7.64)"; **line 3905** = `data` is `bytes([0x01, 0x00]) ||
  public_key`. §7.4 reconciled to defer to §1.5 (E1, v7.73). Confirmed identity-multihash
  is the construction form; the SHA-256 form is decode-only (§1.5 Amendment 4). (P1.)
- **No-peek discipline.** Derived from V7 + the C/POSIX ecosystem. Read the cohort
  `{csharp, java, zig}` + the `ffi-c.md` evaluation for the field *schema/exemplar shape
  and the proven C codec/crypto stack* — config structure + the already-decided C
  library survey, not spec interpretation. The C FFI codec eval (`ffi-c.md`) is the
  closest precedent (it made the same hand-roll-CBOR + libsodium decision for the same
  reasons); Zig is the closest idiom (no-GC memory axis); Java is the error-model inverse
  (checked exceptions vs C return codes).
- **S1 boundary honored.** No podman run, no container build, no toolchain install, no
  compile. Authoring only. (libsodium / fedora NVRs were read from the existing
  Containerfile + the ffi-c.md eval — metadata, not a build/fetch.)

## Decisions (all logged in profile.toml + arch/PROFILE-RATIONALE.md)
| Surface | Decision | Note |
|---|---|---|
| Codec strategy | **native** (hand-rolled canonical CBOR) | A-005 pattern; the same decision ffi-c.md made for C. Sibling FFI `.a` kept as a free cross-check oracle, NOT the codec (A-C-005) |
| CBOR | **hand-rolled** (`ecf.c`, encode+decode one TU) | no C CBOR lib gives ECF (libcbor DOM/alloc; tinycbor leaves float-min/tag-reject/CTAP2 to caller + churn; QCBOR determinism alpha-only -> fails S11 pin). Float-min is highest bug-density code |
| Ed25519 + SHA-256 | **libsodium** (`crypto_sign_*` / `crypto_hash_sha256`) | the ONE runtime dep; profile-authorized (S6) + S11-pinned; statically + privately linked w/ symbol localization |
| Ed448 / SHA-384 (agility) | **DEFERRED** | libsodium has no Ed448; same gap as Zig/OCaml/Swift. When agility lands: sibling FFI agility `.a` (vendored curve448) preferred over heavy OpenSSL. Core = Ed25519+SHA-256 only (A-C-001) |
| base58 / varint | **hand-rolled** | dep-minimization (ffi-c.md); ~40-line base58, LEB128 varint |
| Error model | **return codes + out-params** (`ec_status` int + out-pointer) | the rawest error model in the cohort — the INVERSE of Java's checked exceptions; no compiler enforcement; no setjmp/longjmp; `EC_ERR_OOM` on malloc==NULL |
| Memory | **manual malloc/free, UNGUARDED** (caller-frees, goto-cleanup, zero-copy decode) | the headline idiom seam — the ONLY peer with no safety rails (no Zig allocator-param/ReleaseSafe/defer). ASan+LSan+UBSan make memory bugs TEST FAILURES |
| Concurrency | **pthreads** (one reader thread/conn; `pthread_rwlock_t` store; TCP_NODELAY) | manual analogue of OCaml/Zig/CL/Java stdlib-threads; inherits the §7b CORE gate (A-C-004) |
| Naming | snake_case + `ec_`/`EC_` namespace prefix; lowercase `%02x` hex | C-native; prefix = the module boundary (flat global namespace); hex lowercase by default but pinned (A-CL-009) |
| Build / test / pkg | **GNU make** + **hand-rolled** test harness + **source tarball + pkg-config** | repo make convention; no Unity/Check/CMocka dep; C has no central registry |
| Container | **REUSE `c-toolchain`** (no new Containerfile) | already has gcc/make/cmake/binutils + libsodium static+devel — covers the whole core floor |
| License | Apache-2.0 | S9 default; libsodium ISC (compatible) |
| Int model | native `uint64_t` (head-form maps directly) | cleanest int story with Zig; no ulong/int63 special-casing; UBSan watches signed overflow |

## Crypto pin + release date
- **libsodium `1.0.22-1.fc43`** — fedora's build, ChangeLog ~2 months old
  at authoring -> clears the >=30-day floor even though, as a **reviewed
  distro channel**, the age floor relaxes; exact pin stands for reproducibility). Strict
  superset of ffi-c.md's interim 1.0.21 (adds ML-KEM/SHA-3; the `crypto_sign_*` /
  `crypto_hash_sha256` calls are byte-identical -> conformance-neutral). CVE-2025-69277 is
  in the low-level `crypto_core_ed25519_is_valid_point` we do **not** call. Already in the
  c-toolchain image. **There are NO registry-pulled (crates.io/npm/PyPI-style) deps** in
  this peer at all — the simplest supply chain in the cohort.

## Container — REUSED, NOT authored, NOT built (S1 boundary)
`containers/c-toolchain/Containerfile` **already exists** (built for the ffi-generator C
codec) and is **reused as-is** for the C peer's core floor. It provides everything
needed: **gcc-15.2.1-7.fc43**, **make-4.4.1-11.fc43**, **cmake-3.31.11-1.fc43**,
**binutils-2.45.1-4.fc43**, **libsodium-1.0.22-1.fc43** (runtime + static + devel). **No
new Containerfile authored; the existing one is NOT edited or built here.**

**"To add at S2" items (recorded, NOT done — S1 = no build):**
1. ASan/UBSan test pass needs `libasan`/`libubsan` — on fedora:43 these ship **with**
   gcc-15.2.1, so **no Containerfile edit is expected**; verify at S2 and add the NVRs
   only if a separate package turns out to be required.
2. Ed448 agility (deferred) would need `openssl-devel` OR the sibling FFI agility `.a` —
   an "add at S2/agility" item, **not** in the core image.

## Ambiguity log
6 PRE-RESOLVED inheritances (P1-P6) + 5 entries (A-C-001..005), **none blocking** the
§9.1 floor:
- **P1** peer_id = §1.5 identity-multihash (verified spec-data line 459/3905); **P2** hex
  lowercase; **P3** §5.2a 401/403 trichotomy; **P4** entity `data` = arbitrary ECF value
  (A-JAVA-010 silent-500); **P5** resource_bounds (413 / **400 chain_depth_exceeded** /
  503); **P6** §7b CORE gate (rwlock store + TCP_NODELAY). All settled cohort
  convergence, built in.
- **A-C-001:** Ed448 native gap (libsodium has none) — DEFERRED; sibling-FFI-`.a` route
  preferred when agility lands. Non-blocking for the floor.
- **A-C-002:** spec-data/v7.75 body header reads "7.73" while MANIFEST pins 7.75 — copy
  artifact; MANIFEST authoritative. Snapshot-hygiene note to research. Non-blocking.
- **A-C-003:** §7a/§7b scaffolding is GUIDE-carried, not in spec-data (corroborates
  A-SW-006). Pull at S3/S4 from the guide. Non-blocking.
- **A-C-004:** concurrency = pthreads (S3 decision, recorded so S3 doesn't re-litigate).
- **A-C-005:** codec = native hand-roll, NOT the sibling C FFI codec (kept as a
  cross-check oracle); `ffi` is the documented fallback if the S2 spike fails.

## Exit criteria
profile.toml fully populated (**no TBD**) · rationale written · **container decision
recorded = REUSE `c-toolchain`, no new file** · ambiguity log initialized with **no
blocking-severity items** (A-C-001 Ed448 is the agility higher bar, non-blocking for the
codec floor; peer_id + hex + data-shape + resource_bounds + concurrency all pre-resolved)
· this summary complete. **S1 PASS (authoring).**

## Time spent
~1 session (single-pass authoring): read the PHASE-S1 contract + PROMPT-CONSTANTS + the
csharp/java/zig profile exemplars + the seeded agent-memory (peer-id, hex-case, 401/403,
A-JAVA-010, resource_bounds, §7b) + the `ffi-c.md` C-stack evaluation + the existing
`c-toolchain/Containerfile`; verified peer_id directly in `spec-data/v7.75`; authored the
four deliverables. No build, no toolchain run (S1 boundary).

## What S2 should tackle first
1. **Run the codec spike before the full build** (the load-bearing canonical risk): hand-
   roll `ecf.c` enough to push the `map_keys` + `float` v7.71 vectors through the ECF
   encoder and assert byte-identity. **Float minimization is the highest bug-density code
   in the whole peer** (ffi-c.md) — hardcode the four specials (F9 7E00 NaN / 7C00 +Inf /
   FC00 -Inf / 8000 -0.0), minimize by double->float->half re-decode-and-compare. Watch
   the C seams: bounds-check every decoder read (C will not trap an overread), zero-copy
   decode is a borrow contract (input outlives the view), native `uint64_t` maps the
   head-form directly (UBSan on for signed-overflow UB), and `%02x` (lowercase) for all
   address-space hex (A-CL-009 avoided by default but pinned).
2. **Build the c-toolchain image + smoke-test** (the deferred S1 build): confirm
   libasan/libubsan come with gcc-15.2.1 (expected — no Containerfile edit); if not, add
   the NVRs (the only anticipated container delta).
3. **Wire libsodium crypto + verify raw-pubkey peer_id** (P1 / A-C-001): `crypto_sign_*`
   for Ed25519, `crypto_hash_sha256` for SHA-256; construct the peer_id per **§1.5**
   (identity-multihash, raw pubkey), NOT §7.4 — the corpus won't catch a wrong
   construction (opaque digests); it only blows up at the S4 handshake. Link libsodium
   statically + privately (-fvisibility=hidden + symbol localization).
4. **Run tests under ASan/LSan/UBSan from the start** — memory correctness is first-class
   conformance here (the manual-memory analogue of Zig's leak-checking allocator).
