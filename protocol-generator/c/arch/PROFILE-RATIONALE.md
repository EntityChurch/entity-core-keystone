# entity-core-protocol-c — Profile Rationale

Audit trail for every major S1 profile choice. C is **peer #10** (canonical order)
and the **procedural / manual-memory / FFI-lingua-franca idiom** in the cohort: no
GC, no language runtime, explicit `malloc`/`free` with **zero safety rails**, a
**return-code error model**, and POSIX **pthreads** concurrency. Each choice below
was derived from the V7 spec (`spec-data/v7.75`) + C/POSIX ecosystem research, **not**
ported from the nine prior peers. Where a value matches a prior peer it is by
independent arrival from V7 + POSIX; the idiom seams (raw manual memory, status-int
errors, a mandatory single crypto dep) are the C-native shapes.

## Why C is a worthwhile probe — and the explicit caveat

The nine prior peers spanned static-OO-unchecked (C#), gradual-structural (TS),
functional-static (OCaml), actor-dynamic (Elixir), no-GC-systems (Zig),
program-model-distant (Common Lisp), grapheme-string (Swift), pure-functional-lazy
(Haskell), and mainstream-OO-checked (Java). On the idiom-distance axes the cohort
tracks, C contributes the **last untried memory axis**:

- **Memory** — fully manual, **unguarded** `malloc`/`free`. Zig already probed
  no-GC, but Zig has allocator-as-parameter discipline, `defer`/`errdefer`, and a
  `ReleaseSafe` mode that **traps** overflow and bounds violations. C has **none of
  that** — an off-by-one is silent undefined behavior, a leak is invisible without
  tooling, a double-free corrupts the heap. C is the only peer where memory
  correctness is enforced purely by convention + sanitizers, not by the language.
- **Error model** — the **return-code / out-parameter** model (status int + result
  via out-pointer), the functional **inverse** of Java's checked exceptions and a
  distinct point from Zig's compiler-checked error union. C status codes are plain
  `int`s with **no compiler enforcement** that a caller checks them — the rawest
  error model in the cohort.
- **Crypto / dependency tension** — C has **no stdlib crypto and no stdlib CBOR**, so
  the "minimize dependencies" stance is most strained here: crypto MUST be a pinned
  external library. This is the cohort's clearest single-mandatory-crypto-dep case.
- **Concurrency** — POSIX pthreads, the manual analogue of the stdlib-threads shape
  OCaml/Zig/CL/Java arrived at.

**Expected spec-refinement yield is essentially zero.** The discovery well is dry —
nine independent prior peers found no new defect on the v7.75 surface
(memory `v775-rerun-pending`). C's value is **idiom breadth** (no prior peer
exercises raw manual memory + return-code errors + a mandatory single crypto dep) and
**exercising the parallel S1->S5 process**, not new findings. The bar is a clean,
complete, correct S1 profile that lets S2-S5 reach **576 · 0 FAIL** GREEN. Any
genuinely-new ambiguity is logged honestly if real, but it is gravy, not the goal.

## Codec strategy: native (hand-rolled canonical CBOR + base58 + varint, libsodium crypto)

`research/LANDSCAPE.md` places C in the systems backlog. Research lands it as
**native**, the same A-005 pattern every prior native peer hit — and, notably, the
**exact same decision the existing C FFI codec impl already made**
(`research/evaluations/ffi-c.md`, `entity-core-codec-ffi-c`). A faithful ECF codec
must OWN the canonical layer regardless of any CBOR library underneath:

1. **No C CBOR library gives ECF canonicality.** `libcbor` (0.13.0) is a DOM-tree
   allocator that obscures raw-byte fidelity and is not determinism-focused;
   `tinycbor` is the closest (streaming, low-level) but float-min / tag-rejection /
   CTAP2 ordering are still the caller's job and its 0.5->0.6->7.0 churn is a pin
   risk; `QCBOR` targets dCBOR determinism but **only in its 2.x alpha** (no stable
   release -> fails the S11 >=30-day-stable pin). The four hard ECF requirements —
   shortest-float/float16 with exact specials, RFC-7049 **length-FIRST then bytewise**
   (CTAP2) map-key ordering (which **differs** from RFC-8949 §4.2 bytewise ordering),
   recursive major-type-6 tag rejection, and byte-exact raw-slice round-trip — are
   exactly what a general library does differently or leaves to the caller. So a
   library buys almost nothing and adds a build/pin dependency. Hand-rolling
   `ecf.c` (encode + decode in one translation unit) is the faithful **and** simpler
   path — a few hundred lines of straight-line C, no allocation in the decode hot path
   (the decoder index-walks the input buffer and returns exact slices).

2. **Crypto is one pinned external dep (libsodium).** C has no stdlib crypto. The §9.1
   floor (Ed25519 + SHA-256) is met by **libsodium** — audited, statically-linkable,
   and the **single source of both SHA-256 and RFC-8032 Ed25519** (`crypto_sign_*` +
   `crypto_hash_sha256`). This is the one runtime dependency, profile-**authorized**
   here (S6) and S11-pinned. Monocypher was explicitly **disqualified**: it has **no
   SHA-256** (BLAKE2b + SHA-512 only), and bolting an unaudited `sha256.c` reintroduces
   the trust problem crypto is paid to avoid (ffi-c.md).

**`ffi` is the documented fallback** if a codec spike ever fails — but for C it is a
peculiar fallback: the FFI codec **is C**, so "consume `libentitycore_codec`" would be
a plain static link of a sibling C archive, not a foreign-language bridge. We choose
**native hand-roll for the peer** because the whole point of the C peer is to *write*
the canonical C codec (idiom breadth), not to relink a pre-built one — and we keep the
sibling FFI `.a` as a **free byte-for-byte cross-check oracle** at S2/S4. **Codec spike
at S2** (PHASE-S1 mandate): push the `map_keys` + `float` v7.71 vectors through the
hand-rolled encoder before the full build — the load-bearing canonical risk, and per
ffi-c.md the **float minimization is the highest bug-density code in the whole peer**
(hardcode the four specials F9 7E00 / 7C00 / FC00 / 8000; minimize by
double->float->half re-decode-and-compare).

## CBOR: hand-rolled (no C library) — the manual-memory seams the codec must respect

As above. The C-specific codec footguns, recorded so S2 builds them in from the start:

- **The decoder must bounds-check every read.** C will not — reading past the input
  buffer is undefined behavior / a buffer overread, not a trap. The decoder validates
  the remaining length **before** every read; `defensive_bounds = true`.
- **Zero-copy decode is a borrow contract.** The decoder returns exact slices **into**
  the caller's input buffer (no copy in the hot path); the input buffer MUST outlive
  the decoded view. Documented in the header; the manual-memory analogue of Zig's
  caller-frees ownership but with no allocator-as-param scaffolding.
- **No VLAs.** Attacker-controlled sizes must never size a stack buffer (stack
  overflow); fixed buffers or heap with explicit size checks. `c11_no_vla = true`.
- **Native `uint64_t` is the cleanest int story** (with Zig). The §1.5/§7.3 head-form
  maps **directly** to `uint64_t` — no `ulong`/`int63` special-casing like C# or OCaml.
  The one watch-item: signed-integer overflow is UB in C, so UBSan runs in the test
  pass to catch it.

## Crypto: libsodium (Ed25519 + SHA-256), the one authorized runtime dependency

libsodium supplies RFC-8032 Ed25519 (`crypto_sign_seed_keypair` for seed->keypair,
`crypto_sign_detached` / `crypto_sign_verify_detached` for sign/verify) and SHA-256
(`crypto_hash_sha256`) from one audited library. **Pin: `1.0.22-1.fc43`** (fedora's
build; ChangeLog ~2 months old at authoring — clears the
>=30-day floor even though, as a **reviewed distro channel**, the age floor relaxes
for it; the exact pin stands for reproducibility). `1.0.22` is a strict superset of
the eval's interim `1.0.21` (adds ML-KEM / SHA-3; the high-level `crypto_sign_*` /
`crypto_hash_sha256` we call are byte-identical -> conformance-neutral).
**CVE-2025-69277** is in the low-level `crypto_core_ed25519_is_valid_point` validator
we do **not** call. libsodium is linked **statically + privately** (`-fvisibility=hidden`
+ libsodium symbol localization via `objcopy`/version-script) so the artifact is
self-contained and an embedder linking *their* libsodium does not collide. Already
present in the c-toolchain image (runtime + static + devel) — no Containerfile change.

## Ed448 (crypto-agility higher bar): DEFERRED — libsodium has no Ed448 (the recurring native gap)

The v7.67 crypto-agility higher bar (key_type Ed448 `0x02`; SHA-384 content_hash
`0x01`) is **not** reachable from libsodium — it ships Ed25519 + the SHA-2 family but
**no Ed448 / Ed448-Goldilocks**. This is the **same native gap Zig (A-ZIG-002) and
OCaml (A-OC-002) hit and Swift deferred (A-SW-001)** — no minimal native C crypto lib
covers Ed448. The v0.1 **core is Ed25519 + SHA-256 ONLY** (the §9.1 floor), which
libsodium covers completely, so the gap does **not** touch the conformance floor. Two
honest routes when agility enters scope, both deferred (A-C-001):

- **(a) OpenSSL / libcrypto** — `EVP_PKEY_ED448` + SHA-384 exist there, but OpenSSL is
  a heavy, broad-surface dependency that fights the minimize-dependencies stance.
- **(b) The sibling FFI agility path** — `entity-core-codec-ffi-c` (C-ABI v1.1) already
  **vendored a self-contained openssl curve448** for its Ed448 family
  (`v770-resync-crypto-agility-core`). Linking that sibling C `.a` for the Ed448
  family **only** is the OCaml hybrid-FFI shape — but C-to-C, so a plain static link,
  not a foreign bridge, and the **dependency-lightest** fit.

Default position: defer; route (b) is the preferred path if/when agility lands.

## Base58 + varint: hand-rolled

Both are small and dependency-free. Base58 (Bitcoin alphabet, ~40 lines of
long-division encode/decode, `base58.c`) for peer_id; multicodec-style LEB128 varints
(`varint.c`) for the format-code / key_type / hash_type framing (§7.3). All
currently-allocated codes are 0-127 (single-byte), so a 1-byte fast path plus a general
continuation loop. A dependency for something this small is pure liability (ffi-c.md);
`wire-conformance` confirms both.

## Error model: return codes + out-params (the rawest error model in the cohort)

C's idiom is the **status-int return + result-via-out-pointer** convention: every
fallible function returns an `ec_status` (`0 == EC_OK`, negative == a specific failure
enum) and writes its result through an out-pointer; the caller checks the return before
using the out-param. This is the functional **inverse** of Java's checked exceptions
(which the compiler forces you to handle) and distinct from Zig's error union (which
the compiler checks for exhaustiveness): C status codes are plain `int`s with **no
compiler enforcement** at all — discipline is convention + review + sanitizers. **No
`setjmp`/`longjmp`** for control flow; **no errno-smuggling** for protocol errors
(`errno` is reserved for libc syscall failures). Codec/decode failures are `EC_ERR_*`
members of the enum (`NON_CANONICAL_ECF`, `TRUNCATED`, `TAG_REJECTED`, `DUPLICATE_KEY`,
`BAD_SEED`, `UNSUPPORTED_KEY_TYPE`, `UNSUPPORTED_HASH_FORMAT`, `OOM`,
`CHAIN_DEPTH_EXCEEDED`, `PAYLOAD_TOO_LARGE`, `AUTHN`, `AUTHZ`); protocol-status
failures map an enum value -> wire status code at the dispatcher boundary (400
non_canonical_ecf / 401 / 403 / 413 / **400 chain_depth_exceeded**). Allocation is
fallible and explicit: `malloc` -> NULL propagates `EC_ERR_OOM` up the chain; every
alloc site checks (the Zig `error.OutOfMemory` discipline, but unenforced by the
compiler). Error-path cleanup uses the idiomatic **single goto-cleanup label** per
function (free in reverse-alloc order — the C analogue of `defer`/`errdefer`).

## Memory: manual malloc/free, unguarded — the headline idiom seam, a first-class conformance concern

C has no GC and **no safety rails**: no allocator-as-parameter discipline enforced by
the language, no `ReleaseSafe` bounds/overflow trap, no `defer`. This is the single
biggest idiom seam vs every prior peer and the reason the C peer is worth building — it
is the **only** peer with fully manual, unguarded memory. Discipline: documented
**caller-frees** ownership in every allocating function's header comment (matching
`ec_*_free()`); **goto-cleanup** error paths; **zero-copy decode** with a documented
borrow contract (input outlives the view). Memory-correctness is **first-class
conformance** here: tests run under **AddressSanitizer + LeakSanitizer** (and/or
valgrind) so an un-freed alloc, a use-after-free, or an overflow is a **test failure**
— the manual-memory analogue of Zig's `std.testing.allocator` leak check, the stronger
guarantee a GC'd peer cannot make. Release builds add `-D_FORTIFY_SOURCE=2
-fstack-protector-strong`; the test pass adds `-fsanitize=address,undefined` so UBSan
catches the overflow/UB C will not trap by default.

## Concurrency: POSIX pthreads (deliberate; validated at S3 — inherits the §7b CORE gate)

C's portable concurrency primitive is **pthreads** — the manual analogue of the
OCaml/Zig/CL/Java stdlib-threads decision (A-OC-003-revised). For a `--profile core`
peer the §4.8/§4.9/§6.11 reentrancy invariants AND the now-CORE-gating **§7b
concurrency gate (5/5)** are satisfied by **one reader thread per connection** demuxing
`EXECUTE_RESPONSE` by `request_id` (via a hashtable of `request_id` -> condvar slot;
N7), plus a **data-race-safe content store**. The store-safety mechanism is a
**`pthread_rwlock_t`** (many concurrent readers, one exclusive writer — reads dominate
the dispatch path; a `pthread_mutex_t` is the simpler fallback). Two §7b findings
inherited from the gate runs are built in structurally:

- **TCP_NODELAY on every connection socket** is mandatory — Nagle/delayed-ACK on small
  req/resp frames was THE throughput killer (Zig §7b finding: 343 ms/cycle churn is
  the Nagle signature; `concurrency-gate-7b-results`).
- **No blocking syscalls on a cooperative path** — one thread per connection means a
  blocking `recv` only blocks that connection's thread (the Swift §7b "dedicated thread
  for blocking I/O" finding applied structurally; no shared cooperative pool to stall).

Shared connection sockets are write-serialized with a per-connection `pthread_mutex_t`.
Not exercised by the codec (pure/synchronous); validated at S3 (A-C-004).

## Naming: C-native snake_case + `ec_` namespace prefix

`snake_case_t` for typedef'd structs/enums (`ec_entity`, `ec_content_hash`,
`ec_peer_id`); `snake_case` functions (`ec_ecf_encode`, `ec_sign_detached`);
`UPPER_SNAKE_CASE` for `#define`/enum constants (`EC_OK`, `EC_MAX_MESSAGE_SIZE`).
Every exported symbol carries the **`ec_` / `EC_` prefix** — C has a flat global symbol
namespace, so the prefix **is** the module boundary, exported via `-fvisibility=hidden`
+ an explicit `EC_API` export macro. Differs from every prior peer's casing (no
PascalCase types). **CASE-EXACT hex caveat (the A-CL-009 lesson applied proactively):**
all external string/byte hex rendering MUST be **lowercase** to match the Go oracle
(`hex.EncodeToString`) and the cohort. C's `printf("%02x")` is **naturally lowercase**
(good — avoids the A-CL-009 trap by default, unlike CL's uppercase `~x`), but it is
**pinned explicitly**: the codec uses `%02x` (never `%02X`) for all address-space
tree-path hex (§3.4/§3.5).

## Build / test / packaging: GNU make + hand-rolled harness + source tarball

**GNU `make`** drives the build (the repo's stated build/orchestration convention;
avoid heavier meta-toolchains where make suffices). A hand-written `Makefile` produces
`libentity_core_protocol.{a,so}` + the conformance harness binary. The existing
c-toolchain image drives the *FFI codec* via CMake, but for the **peer** a plain
Makefile is the lighter, dependency-minimal fit; CMake stays available in the image if
a later generator step wants it. `-std=c11 -pedantic -Wall -Wextra -Werror` (widest
reach across embedding toolchains, ffi-c.md). **Test framework: hand-rolled** — an
in-repo assert/count harness, no Unity/Check/CMocka dependency (the Zig/OCaml/CL
"hand-roll even the test runner" stance); the conformance harness loads the normative
fixture and asserts byte-identity, run under ASan/LSan. **Packaging:** C has no central
registry, so "publishing" is a versioned **source tarball** carrying the static + shared
lib and a **pkg-config** (`.pc`) file (`pkg-config --cflags --libs
entity-core-protocol`), consumed by distro packagers / vendoring — the decentralized
stance, mirroring Zig.

## License: Apache-2.0 (S9 default; libsodium is ISC, compatible)

The C ecosystem has no dominant license norm. Keep the repo's **Apache-2.0** default
(explicit patent grant). libsodium is **ISC** (permissive, Apache-compatible —
statically linkable into an Apache-2.0 artifact); no conflict.

## Container: REUSE `containers/c-toolchain/` — no new Containerfile

`containers/c-toolchain/Containerfile` **already exists** (built for the ffi-generator
C codec work) and provides everything the C peer's Ed25519 + SHA-256 core needs:
`gcc-15.2.1`, `make-4.4.1`, `cmake-3.31.11`, `binutils-2.45.1`, and
`libsodium-1.0.22-1.fc43` (runtime + static + devel). It is **REUSED as-is** — **no new
Containerfile is authored** (per the S1 mandate). The build is fully offline
(`--network=none`): libsodium is pre-installed; everything else is hand-rolled in-repo.
**S2+ "to add" notes** (NOT edited now — S1 = no build): the ASan/UBSan test pass needs
`libasan`/`libubsan`, which on fedora:43 ship **with** gcc-15.2.1 (so no edit expected;
verify at S2 and add the NVRs only if a separate package turns out to be needed); Ed448
agility (deferred) would need `openssl-devel` OR the sibling FFI agility `.a` — also an
"add at S2/agility" item, not in the core image.

## Toolchain pins (S11)

All pins come through fedora:43's **reviewed dnf channel**, so they get the **exact
version pin for reproducibility** but the >=30-day **age floor relaxes** (the distro
has its own security review; supply-chain scope clarification). There are **no
registry-pulled (crates.io/npm/PyPI-style) ecosystem deps** in this peer at all — the
codec, base58, varint, and test harness are all hand-rolled in-repo, and the one crypto
dep (libsodium) comes via dnf. This gives C **the simplest supply chain in the cohort
by construction** (one audited C lib + the toolchain, both reviewed-channel).

- **libsodium 1.0.22-1.fc43** (ChangeLog ~2 months old) — the one crypto
  dep; meets the >=30-day floor anyway; already in the image.
- **gcc 15.2.1-7.fc43** (C11 compiler; pulls libasan/libubsan), **make 4.4.1-11.fc43**,
  **cmake 3.31.11-1.fc43**, **binutils 2.45.1-4.fc43** — reviewed distro channel,
  exact pins for repro.

## Spec version: read v7.75, codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.75` (the current snapshot; MANIFEST
pins V7 **7.75**). The codec uses the **v7.71** corpus because `ENTITY-CBOR-ENCODING.md`
+ `ENTITY-NATIVE-TYPE-SYSTEM.md` are byte-stable across v7.71->v7.75 (the cohort
SHA-verified this window; the v7.73 §4.7 construct-vs-decode erratum and the v7.67
large-uint `int.15/16/17` additions are the only deltas, both already reflected in the
v0.8.0 corpus the 9-peer matrix runs). **One snapshot oddity** worth flagging for S2:
the verbatim `ENTITY-CORE-PROTOCOL-V7.md` body's own changelog header still reads
"Version: 7.73" even though MANIFEST.md pins the snapshot at 7.75 — the snapshot is a
byte-for-byte copy whose internal top changelog entry is dated; **MANIFEST.md is
authoritative** for the snapshot version. Recorded (A-C-002) so S2/S3 are not confused
by the in-file header.

## Inherited current-state floor (pre-resolved so S3 does not re-burn them)

The keystone menu items below are **settled** convergence (4+-peer) and folded into the
profile + ambiguity log as **pre-resolved**, NOT open questions:

- **peer_id (§1.5 canonical-form):** `hash_type = 0x00`, **raw pubkey** for Ed25519
  (keys <=32 B). IGNORE the stale §7.4 `SHA256(pubkey)` skeleton. **Verified directly
  in `spec-data/v7.75`:** line **459** (§1.5 canonical-form table) = Ed25519 `0x01` ->
  `0x00` identity-multihash, "The digest IS the public_key (v7.64)"; line **3905** =
  `data` is byte-for-byte `bytes([0x01, 0x00]) || public_key`. §7.4 (E1, v7.73) is now
  reconciled to defer to the §1.5 table. The corpus uses opaque digests, so a wrong
  construction passes S2 and only blows up at the S4 handshake (401 identity_mismatch)
  — hence pre-resolving it. (Corroborates A-OC-007 / A-ZIG-001 / A-CL-002 / A-SW-008 /
  A-JAVA-004; this is the 5th+ spec-first arrival — past decisive.)
- **Tree-path hex: lowercase `%02x`** (§3.4/§3.5; A-CL-009). C is lowercase by default;
  pinned in `[idiom].hex_lowercase`.
- **§5.2 trichotomy:** 401 (authn) / 403 (authz) / 401-unresolvable (§5.2a verdict
  table; 5-peer convergence).
- **§1.1 entity `data` is an ARBITRARY ECF value, NOT necessarily a map** (the
  A-JAVA-010 silent-500 trap): model `data` as a general ECF value from the start; a
  map-only model passes S2/S3 green then 500s on the first scalar-data entity at the
  live gate.
- **resource_bounds (§4.10, CORE-gating):** r1 oversize-payload -> `413
  payload_too_large` or clean close (default 16 MiB); r2 over-deep delegation chain ->
  **`400 chain_depth_exceeded` (MUST be 400, NOT 403)** (default 64) — S3 builds the
  ~15-line §4.10(b) structural pre-check (walk parents, **no sig work**, max=64,
  **BEFORE** the authz walk; all 9 peers needed it); r3 connection flood -> `503`/close
  or honest WARN.
- **concurrency (§7b, CORE-gating):** 5/5; data-race-safe store (§4.8 -> rwlock),
  resilience under load (§4.9), no blocking syscalls on a cooperative path (one thread
  per connection sidesteps it), TCP_NODELAY.
