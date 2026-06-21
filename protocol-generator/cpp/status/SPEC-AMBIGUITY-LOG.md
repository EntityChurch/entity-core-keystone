# entity-core-protocol-cpp — Spec Ambiguity Log

Every guess / judgment call made while generating the C++ peer (a release "reach" peer;
`research/RELEASE-READINESS.md` §2 row 3). Format per PROMPT-CONSTANTS.md S3. Items escalate
to architecture as proposal candidates via `research/stewardship/`. **No silent guesses.**

`A-CPP-NNN` convention. Severity: a **blocking** item halts the dependent phase; the rest are
recorded decisions / escalations / pre-resolved inheritances. **No blocking items at S1 exit.**

The discovery well is **dry** — the 8-peer synthesis saturated the language axes, and C is
corroboration-only (`research/RELEASE-READINESS.md` §2 honesty note: the reach peers
Kotlin/C++/PHP/Dart are corroboration-only, built for ecosystem coverage, not to surface spec
findings). C++ is a **reach** peer — its value is ecosystem coverage + exercising the
generator against C++ idiom (RAII / `std::expected` / templates / move semantics), NOT new
findings. No new spec ambiguity was strained for or invented at S1. The inherited-settled items
(peer_id, hex-case, 401/403, A-JAVA-010 data-shape, 400-chain-depth, §7b, and notably the
A-C-009 atomic-refcount finding) are recorded below as **PRE-RESOLVED** so S2/S3 do not
re-burn them.

---

## PRE-RESOLVED inheritances (settled cohort convergence — NOT open questions)

These are folded into `profile.toml` + `arch/PROFILE-RATIONALE.md`. Recorded here so S3
inherits them as decided, with the §-pointers, not as fresh guesses.

### P1: peer_id construction — §1.5 canonical-form (hash_type=0x00, raw pubkey), NOT §7.4 SHA-256
**V7 section:** §1.5 canonical-form table + §1.5 `data` construction; §7.4 reconciled via E1
(v7.73) to defer to §1.5; §9.1 floor (A-SW-008 erratum: §9.1 peer-id citation now points at
§1.5, per the v7.75 MANIFEST).
**Status:** PRE-RESOLVED (**6th+ spec-first arrival** — A-OC-007 / A-ZIG-001 / A-CL-002 /
A-SW-008 / A-JAVA-004 / A-C P1; past decisive). Construct the Ed25519 peer_id as
`Base58(varint(0x01) || varint(0x00) || public_key)` — `hash_type = 0x00` identity-multihash,
the digest **IS** the raw 32-byte public key. IGNORE the stale SHA-256 / `hash_type=0x01` form
(decode-time wire-acceptance carve-out only, never a construction form for v7.65+).
**Why it matters:** the S2 corpus uses opaque digests, so a wrong construction passes S2 green
and only fails at the S4 handshake (`401 identity_mismatch`). Built in now.
**Escalation:** arch — already escalated by 6 peers; corroboration, no new ask.

### P2: address-space tree-path hex MUST be lowercase ({:02x})
**V7 section:** §3.4 / §3.5 (tree-path keys rendered from content_hash hex).
**Status:** PRE-RESOLVED (A-CL-009 — the headline second-cohort defect). Tree paths are
case-sensitive string keys; the Go oracle uses `hex.EncodeToString` (lowercase). C++'s
`std::format("{:02x}")` / `std::hex` is **naturally lowercase**, so C++ avoids the A-CL-009
uppercase trap by default — but it is **pinned explicitly** (`[idiom].hex_lowercase = true`;
never `{:02X}` / `std::uppercase`) so no codec site can regress.
**Escalation:** arch already asked to pin lowercase normatively (A-CL-009); corroboration only.

### P3: §5.2 trichotomy — 401 (authn) / 403 (authz) / 401-unresolvable
**V7 section:** §5.2 + the §5.2a verdict-to-status enumeration (v7.73 E2).
**Status:** PRE-RESOLVED (5+-peer convergence; F20 / A-OC-008 / A-SW-010 / A-C P3). Request-time
EXECUTE on a non-connect path: author absent → **401** authentication_failed; capability absent
(author present + signed) → **403** capability_denied; unresolvable author → 401. §5.2a is the
single source of truth for the (status, code) tuple; build to it.
**Escalation:** arch — §5.2a already absorbed the ruling; no new ask.

### P4: §1.1 entity `data` is an ARBITRARY ECF value, NOT necessarily a map
**V7 section:** §1.1 entity model.
**Status:** PRE-RESOLVED (the A-JAVA-010 silent-500 trap). Model `data` as a **general ECF
value** (any major type — scalar, bytes, array, map) from the start. In C++ this means the
entity's `data` field is a general `EcfValue` (a `std::variant` tagged union over the ECF major
types), never a map-typed field. A map-only model passes S2/S3 green then returns **500** on the
first scalar-`data` entity at the live S4 gate.
**Escalation:** none — spec is clear; a generation-discipline pre-resolution.

### P5: resource_bounds (§4.10) — 413 oversize / 400 chain_depth_exceeded / 503 flood
**V7 section:** §4.10 (a/b/c); CORE-gating since the v7.75 cycle.
**Status:** PRE-RESOLVED (all prior peers needed the chain-depth pre-check). r1: oversize
payload → `413 payload_too_large` or clean close (default **16 MiB**). r2: over-deep delegation
chain → **`400 chain_depth_exceeded`** — **MUST be 400, NOT 403** (default depth **64**). S3
builds the ~15-line §4.10(b) **structural pre-check**: `chain_exceeds_depth(cap, resolve)` walks
parents with **NO signature work**, max=64, **BEFORE** the per-link authz walk; an over-depth
self-chain → 400, an *unreachable* parent stays 403 (not a depth problem). r3: connection flood
→ `503`/close or honest WARN (SHOULD / external-admission). The §4.10 defaults (16 MiB / 64) are
INFORMATIVE recommended defaults, NOT normative constants (v7.75 MANIFEST) — the contract is
"enforce a finite declared bound + reject over-limit cleanly."
**Escalation:** none — settled cohort fix.

### P6: §7b concurrency gate is CORE-gating (5/5) — AND the A-C-009 atomic-refcount lesson is pre-resolved IN THE TYPE SYSTEM
**V7 section:** §4.8 (data-race safety) / §4.9 (resilience) / §6.11 + GUIDE-CONFORMANCE §7b.
**Status:** PRE-RESOLVED (concurrency-gate-7b: all prior peers green; **A-C-009** is the only
net-new §4.8 finding to date). Data-race-safe store (§4.8) → the C++ peer uses a
**`std::shared_mutex`** guarding the content store (RAII-locked); resilience under load (§4.9);
**no blocking syscalls on a cooperative path** (one `std::thread` per connection sidesteps it);
**TCP_NODELAY** mandatory on every connection socket (the Zig Nagle finding). **A-C-009
pre-resolved structurally:** the C peer hit a plain-`int` refcount race on shared entities under
sustained concurrent load (heap use-after-free → host crash → fixed with `atomic_int`). In C++
this is **free** — shared entities are held by `std::shared_ptr<Entity>`, whose control-block
refcount **is atomic by the C++ standard** (thread-safe ref/unref). The standard caveat is built
in: `shared_ptr`'s refcount is atomic, but concurrent mutation of the *pointee* still needs the
store lock — `shared_ptr` buys lifetime-safety, not data-race-safety of the contents.
**Escalation:** none — settled gate; A-C-009 is arch-bound from the C peer (recommended §4.8
conformance note "refcounted shared entities MUST use atomic/lock-guarded refcounts"); C++
corroborates that a GC-free shared_ptr language gets it for free.

---

## A-CPP-001: codec strategy = native hand-roll (D1 binding; NOT FFI, even though C++-to-C would link trivially)

**V7 section:** absent (codec-strategy / library choice; PHASE-S1 codec-strategy matrix + the
slate decision D1).
**Profile field:** `[codec].strategy = "native"`, `cbor_library = "hand-rolled"`.
**Your guess:** Hand-roll the canonical CBOR codec **natively in idiomatic C++** (`ecf.{hpp,cpp}`)
rather than consuming the sibling C/Rust FFI codec `libentitycore_codec` — affirming **Decision
D1** (`research/RELEASE-READINESS.md` §3-D1), which is already made and binding.
**Rationale:** D1 on record: "An FFI C++ peer is the C peer in a trench coat and proves nothing
independent; native exercises the generator against C++ idiom (RAII / std::expected vs
exceptions / templates), which is the actual reach value. Crypto stays libsodium." No C++ CBOR
library gives ECF canonicality regardless (tinycbor leaves float-min/tag-reject/CTAP2 to the
caller + is a C lib + churn; cppcodec is base64/hex only, not CBOR; jsoncons is DOM/broad-surface
non-determinism-focused; QCBOR determinism is alpha-only → fails the S11 stable pin), so a
library buys nothing. The sibling FFI codec is kept as a **free byte-for-byte cross-check oracle**
at S2/S4, NOT as the codec. `ffi` remains the documented fallback **only** if the S2 codec spike
fails (not expected) — but D1 explicitly rules it out as the chosen path.
**Escalation:** operator — local decision within the profile's authority + an already-recorded
slate decision (D1); non-blocking. The S2 spike (map_keys + float v7.71 vectors) is the cheap
insurance.

---

## A-CPP-002: Ed448 (key_type 0x02) native gap — DEFERRED (do NOT FFI around it for v0.1)

**V7 section:** §1.5 key_type table (0x02 Ed448); §7.3 (Ed448 validated v7.67); §8.1.
Crypto-agility *higher bar*, NOT the §9.1 floor.
**Profile field:** `[codec].ed448_library = { name = "DEFERRED", version = "none" }`.
**Your guess:** Defer Ed448 at the profile level, per the slate ("gap → defer"). The Ed25519
(`key_type 0x01`) + SHA-256 (`content_hash_format 0x00`) §9.1 floor is fully native via
**libsodium** and is **unaffected**. libsodium has **no Ed448** (ships Ed25519 + the SHA-2 family
+ ML-KEM/SHA-3 as of 1.0.22, but no Ed448 / Ed448-Goldilocks). The slate is explicit: **defer,
do NOT FFI around it for v0.1**.
**Rationale:** Same native gap C (A-C-001), Zig (A-ZIG-002), OCaml (A-OC-002), Rust (A-RUST-002)
hit and Swift deferred (A-SW-001) — no minimal audited native crypto stack covers Ed448. When
agility enters scope (NOT v0.1), the dependency-lightest C++ route is the **sibling FFI agility
path** — `entity-core-codec-ffi-c` (C-ABI v1.1) already vendored a self-contained openssl
curve448 for its Ed448 family; linking that sibling C `.a` for the Ed448 family **only** via
`extern "C"` is the OCaml hybrid shape, and C++-to-C is a plain link, not a foreign bridge.
Route (b) OpenSSL/libcrypto (`EVP_PKEY_ED448` + SHA-384) is the heavier alternative. Deferring
with a documented escalation beats a silent gap or an unaudited hand-roll. Does not block the
floor.
**Escalation:** research — profile/agility (5th+ peer to hit the same Ed448 native gap;
reinforces the cross-peer finding that no minimal native crypto stack covers Ed448. The
sibling-FFI-`.a` route is the dependency-lightest agility path for a systems-C++ peer when it
lands).

---

## A-CPP-003: build system = CMake + vcpkg/conan (slate decision; diverges from the repo "build via make" convention BY PROFILE)

**V7 section:** absent (build/orchestration choice; the slate row 3 "vcpkg/conan + CMake").
**Profile field:** `[build].build_tool = "cmake"`, `[publishing].registry = "cmake-package +
vcpkg + conan"`.
**Your guess:** Use **CMake** as the build system + **vcpkg/conan** as the package managers,
per the slate (row 3), even though the repo's stated convention is "build/orchestration via
make."
**Rationale:** C++ has no single universal build tool, but **CMake is the de-facto standard**
that both vcpkg AND conan integrate with and what a systems/games/embedded C++ developer
expects — and the slate **names** it. S6 (profile decides) authorizes this divergence for
C++-idiomatic correctness. The repo's make convention can still be honored as a thin
meta-`Makefile` wrapping `cmake --build` (orchestration shim), but CMake owns the build graph.
The C peer used plain make (its codec is a few hand-rolled files); the C++ peer's idiom + the
explicit slate decision both point to CMake.
**Escalation:** operator — local/profile decision (S6); non-blocking. Recorded so S2/S3 do not
re-litigate make-vs-CMake.

---

## A-CPP-004: test framework = hand-rolled + CTest (NOT GoogleTest/Catch2 — dep-minimization)

**V7 section:** absent (test-framework choice).
**Profile field:** `[testing].framework = "hand-rolled + CTest"`.
**Your guess:** Hand-roll the conformance harness (in-repo assert/expect macros + a counting
main()) registered with **CTest**, rather than depending on GoogleTest or Catch2.
**Rationale:** The dependency-minimization stance (matching the C/Zig/OCaml/CL "hand-roll even
the test runner" call). A corpus byte-identity test does not need a framework — a counting
harness + CTest suffices, and CTest comes with CMake (no extra registry dep). Adding a
test-framework dep buys little for this peer.
**Escalation:** operator — local/profile decision; non-blocking.

---

## A-CPP-005: spec version — read v7.75 (latest stamped), gate against the v7.77 oracle

**V7 section:** absent (spec-version / oracle provenance).
**Profile field:** `[spec].v7_version_pinned = "7.75"`, `[spec].target_oracle` (v7.77 head).
**Your guess:** Derive the profile + peer from `spec-data/v7.75` (the **latest stamped**
snapshot; MANIFEST pins V7 7.75), and gate the peer against the **v7.77** validate-peer oracle
(`entity-core-go @ e8524ed`, the 17-peer matrix uniform 665 / 0 FAIL) per the brief.
**Rationale:** The brief states the core floor is **stable v7.75→v7.77** and the conformance
oracle anchors at v7.77. The wire/protocol surface is byte-stable across that window
(`ENTITY-CBOR-ENCODING.md` + `ENTITY-NATIVE-TYPE-SYSTEM.md` unchanged since v7.73 E3 / v7.70 per
the v7.75 MANIFEST). For a **corroboration-only reach peer**, deriving from v7.75 + gating
against the v7.77 oracle is the established cohort pattern (the re-run vendors the oracle, not
the snapshot; no `spec-data/v7.77` stamp is required unless a spec-first peer is queued against
it). The orchestrator pins the exact clean go commit at S4.
**Escalation:** operator — provenance bookkeeping (non-blocking). Re-confirm the oracle HEAD /
clean pin at S4 when the live `validate-peer` binary is built and run.

---

## A-CPP-006: §7a/§7b conformance scaffolding is GUIDE-carried, not in v7.75 spec-data

**V7 section:** GUIDE-CONFORMANCE.md §7a (validate handlers) + §7b (concurrency gate) — NOT in
the three normative spec-data files (per the v7.74/v7.75 MANIFEST note).
**Profile field:** `[spec].conformance_scaffolding = "guide-conformance-7a-7b"`.
**Your guess:** The C++ peer derives its **protocol surface** (including the §4.10 floor MUSTs,
which ARE in the v7.75 snapshot) from `spec-data/v7.75`, but picks up the **conformance
scaffolding** (the `system/validate/{echo,dispatch-outbound}` handlers behind a `--validate`
opt-in, off by default; the §7b store concurrency-safety gate; the generator-menu defaults —
16 MiB/64, TCP_NODELAY, blocking-syscalls-off-the-cooperative-pool) from `GUIDE-CONFORMANCE.md`
+ the keystone generator menu at S3/S4 — not from spec-data.
**Rationale:** The MANIFEST explicitly flags this split (§7a/§7b live in the non-normative guide
+ the generator menu, not the snapshot; the §4.10 *contract* is in the snapshot but its *gate*
is menu-carried). A spec-first peer reading only spec-data would otherwise MISS the conformance
handlers and fail S4. Recorded now so S3/S4 pulls them from the right source.
**Escalation:** research — operator-carried convention; track the standing arch open-item on
whether GUIDE-CONFORMANCE joins the snapshot set (corroborates A-SW-006 / A-C-003).

---

## A-CPP-007: error model = std::expected (NOT exceptions, NOT C's return-codes) — the headline C++-idiom choice

**V7 section:** absent (error-model choice; S6 profile-decides).
**Profile field:** `[error_model].style = "result"`, `result_type = "std::expected<T,
ProtocolError>"`.
**Your guess:** Use a value-based **`std::expected<T, E>`** error channel for all fallible
codec/dispatch functions; reserve exceptions for **programmer-error only** (`std::bad_alloc`,
`std::logic_error`), caught at the per-connection task boundary; never throw for protocol flow;
never let an exception escape the public ABI.
**Rationale:** This is C++'s modern idiomatic Result shape and exercises the generator against a
C++ idiom axis no prior peer covers: value-based error propagation **in a language that also has
exceptions** — the generator must NOT reflexively reach for `throw`/`try` (the C# peer is the
exceptions point in the cohort; C++ is the `std::expected` point). It is also DISTINCT from the
C peer's raw return-code/out-param model (no compiler enforcement; out-pointers). `<expected>` is
technically C++23 but ships usable under `-std=c++20` in libstdc++ (GCC 12+) and libc++
(Clang 16+); `tl::expected` is the documented header-only fallback shim if a target toolchain
lacks it.
**Escalation:** operator — local/profile decision (S6); non-blocking. Recorded so S2/S3 do not
re-pick exceptions-on-the-hot-path.

---

## A-CPP-008: concurrency = C++ standard threads + std::shared_mutex (deliberate S3 decision; coroutines NOT used)

**V7 section:** §4.8 / §4.9 / §6.11 / §7b (the concurrency surface); NOT exercised by the codec
(S2 is pure/synchronous).
**Profile field:** `[concurrency].style = "threaded"`, `primitive = "std::thread / ..."`,
`store_safety = "std::shared_mutex"`, `entity_refcount = "std::shared_ptr (atomic control
block)"`.
**Your guess:** Use the **C++ standard thread library** — one `std::thread` reader per connection
demuxing `EXECUTE_RESPONSE` by `request_id` (an `unordered_map` → condvar slot; N7), a
**`std::shared_mutex`** guarding the content store (§4.8 data-race safety, RAII-locked), shared
entity lifetime via **`std::shared_ptr`** (atomic refcount — A-C-009 pre-resolved), a
per-connection `std::mutex` write-serializing each shared socket, and `TCP_NODELAY` on every
connection socket. C++20 **coroutines are NOT used** for the core peer.
**Rationale:** The C++ standard thread library is the portable, type-safe, RAII-locked analogue
of the C peer's pthreads (and the OCaml/Zig/CL/Java stdlib-threads decision). One-thread-per-
connection satisfies §4.8/§6.11 with no handler-initiated outbound in `--profile core` and
sidesteps the §7b cooperative-pool blocking-syscall trap structurally. The `shared_mutex` (vs a
plain mutex) reflects read-dominated dispatch. Blocking-thread-per-connection is the simpler,
portable, §7b-clean shape; coroutines add complexity with no conformance benefit for a blocking
core peer. A decision, not a spec gap; recorded so S3 does not silently re-pick the threading
model.
**Escalation:** operator — local/profile decision (S3 validates; non-blocking). Mirrors the prior
peers' stdlib-threads sign-off.

---

**S1 finalization verdict:** 6 PRE-RESOLVED inheritances (P1–P6, incl. the A-C-009 atomic-refcount
lesson pre-resolved in the type system via `std::shared_ptr`) + 8 entries (A-CPP-001..008), all
local/profile decisions or non-blocking notes/deferrals with named owners. **No blocking item at
S1 exit** (A-CPP-002 Ed448 is the agility higher bar, non-blocking for the §9.1 floor; D1 native
codec, std::expected error model, CMake build, peer_id/hex/data-shape/resource_bounds/concurrency
all pre-resolved or profile-decided). No new spec defect surfaced or invented (corroboration-only
reach peer, discovery well dry). S1 ambiguity log initialized.

---

## A-CPP-009: `<expected>` is NOT usable under `-std=c++20` on GCC 15.2.1 / Clang 21 (libstdc++) — bumped the build to C++23 (NOT a new dep)

**V7 section:** absent (toolchain / language-standard reality; S6 profile-decides).
**Profile field:** `[build].std = "c++20"`, `[error_model].result_type = "std::expected<T,
ProtocolError>"`; A-CPP-007 (the std::expected error-model decision).
**Your guess:** Build the peer to **`-std=c++23`** (not the profile's `c++20`), keeping the
headline `std::expected` value-based error channel with **ZERO new dependencies**.
**What forced it (an S2 toolchain finding):** the profile (A-CPP-007) asserted `<expected>` "ships
usable under `-std=c++20` in libstdc++ (GCC 12+)". On the pinned **GCC 15.2.1** *and* **Clang 21**
(both over libstdc++ 15.2.1), `<expected>` is gated behind `__cplusplus > 202002L` and is **NOT
available under `-std=c++20`** (nor `-std=gnu++20`) — `std::expected is only available from C++23
onwards`. Verified at the first S2 build: `-std=c++23` exposes `std::expected` cleanly on **both**
compilers under `-Wall -Wextra -Werror -pedantic`; `<span>` and `<format>` work under c++20 (only
`<expected>` forces the bump). The two options were (a) `-std=c++23` (keeps std::expected, zero
deps) or (b) vendor the `tl::expected` header-only shim (the A-CPP-007 documented fallback — but a
registry dep, against the zero-dep / supply-chain-minimal stance). **(a) is strictly better:** it
preserves the headline idiom AND the zero-dep supply chain. The reach cost is minimal — every
toolchain that ships `<expected>` (GCC 12+ / Clang 16+) also speaks C++23. CMake set to
`CMAKE_CXX_STANDARD 23`.
**Rationale:** zero-dep beats a vendored shim (S11 supply-chain stance); the std::expected idiom is
the whole point of A-CPP-007 and survives intact. The profile's "c++20-with-`<expected>`" premise
was simply wrong for the pinned libstdc++; C++23 is the faithful realization of the same intent.
**Escalation:** research — profile field correction (`[build].std` → `c++23`; A-CPP-007's "usable
under -std=c++20" note is libstdc++-version-dependent and false for GCC 15 / libstdc++ 15). Non-
blocking; the codec is GREEN under c++23 on both compilers. A note for the next libstdc++-based C++
peer: do not assume `<expected>` under `-std=c++20`.

---

## A-CPP-010: recursive `EcfValue` variant needs explicit indirection for libc++/clang portability (a `Box` heap-holder) — NOT a spec issue, a C++ value-model engineering call

**V7 section:** absent (C++ value-model implementation detail).
**Profile field:** `[codec].cbor_library` (the hand-rolled `EcfValue` model); `[idiom]` (RAII /
value semantics).
**Your guess:** Store the recursive variant alternatives (Array elements + Map keys/values) behind
a small value-semantic heap holder **`Box`** (`std::unique_ptr<EcfValue>` with deep copy), rather
than `std::vector<EcfValue>` / `std::vector<MapEntry>` directly.
**What forced it (a cross-compiler hygiene finding):** the natural model — a `std::variant` whose
alternatives include `std::vector<EcfValue>` (Array) and `std::vector<MapEntry>` (Map) where
`MapEntry` holds two `EcfValue` by value — relies on `std::vector` tolerating an **incomplete**
element type at the variant-instantiation point. **GCC's libstdc++ tolerates this (lazy
completeness); Clang over the SAME libstdc++ does NOT** — it eagerly instantiates
`std::__is_complete_or_unbounded` and hard-errors (`incomplete type 'MapEntry' used in type
trait`). The g++-only build passed; the clang cross-compiler pass (profile-mandated for ASan/UBSan
hygiene) caught it. The `Box` indirection makes the variant hold a complete pointer-holding type,
so it compiles **identically on g++ AND clang++**; `EcfValue` stays a regular value type (deep
copy / move), and ergonomic `push()` / `put()` keep call sites clean. Both compilers now build the
codec GREEN (69/69 + 84 selftests + 20/20 spike, ASan/LSan/UBSan-clean) under `-Werror -pedantic`.
**Rationale:** a portable recursive-variant is a known C++ pattern; the `Box` is the minimal,
idiomatic (value-semantic, RAII, no raw new/delete) realization. The clang pass earned its keep —
it surfaced a latent non-portability the g++-only path would have shipped.
**Escalation:** operator — local C++ engineering decision; non-blocking. Recorded as a reusable
ruling for the next libstdc++/libc++ C++ peer: box recursive variant alternatives, don't rely on
`std::vector<incomplete>`.

---

**S2 verdict:** 2 net-new entries (A-CPP-009 std-version, A-CPP-010 recursive-variant) — both C++
toolchain / engineering findings, **neither a spec defect** (corroboration-only reach peer; the
discovery well stays dry — no V7 ambiguity surfaced). Both non-blocking; the codec is GREEN. The
S1 pre-resolved inheritances (P1–P6) and A-CPP-001..008 all held as authored.

---

## S3 (peer machinery)

### A-CPP-011 — entity sharing across dispatch threads: `std::shared_ptr<const Entity>` (A-C-009 pre-resolved structurally)

**V7 section:** §4.8 (store data-race safety under concurrent dispatch).
**Profile field:** `[memory].shared_entity_lifetime`, `[concurrency].entity_refcount` (both pin
`std::shared_ptr` with the standard's atomic control block as the A-C-009 fix).
**Your guess:** Model the materialized entity as an **immutable** `Entity` held by
`std::shared_ptr<const Entity>` everywhere it is shared (store / envelope / outcome / dispatch
threads). It is computed-once (type, data, content_hash) and never mutated, so the only thread-
shared mutation is the refcount — which `shared_ptr`'s control block makes atomic by the C++
standard. This is exactly the profile's pre-resolution of the C peer's A-C-009 hand-rolled
`atomic_int`: the C++ type system gives the same guarantee for free, and immutability removes the
pointee-mutation hazard entirely (no entity is ever written after construction).
**What confirmed it:** the 8-way concurrent `request_id`-demux scenario + the per-connection-thread
inbound dispatch run repeatedly (10×) ASan/LSan/UBSan-clean with no use-after-free. The store's
`std::shared_mutex` (below) guards the *maps*; `shared_ptr` guards entity *lifetime*; together they
make §4.8 structural. (TSan would be the ideal additional witness, but `libtsan` is **not installed
in the `cpp-toolchain` image** — see A-CPP-013; ASan + the immutability argument cover it.)
**Escalation:** operator — local C++ engineering decision, non-blocking, no spec ambiguity.

### A-CPP-012 — genuine §3.6 multi-sig K-of-N built at S3 (not deferred to a retrofit)

**V7 section:** §3.6 (M3 multi-granter structure), §5.5 (M4 distinct-signer quorum, M6 root-at-local).
**Profile field:** n/a — keystone S3 mandate (the cohort multi-sig closeout direction).
**Your guess / decision:** the closest analog (the native C peer, #10) ships **no** genuine
multi-sig — its `verify_chain` is single-sig only (the multi-sig cohort closeout post-dates the C
peer's build). Per the S3 brief, C++ builds **genuine K-of-N the first time**, porting the canonical
C# `ChainVerifier.VerifyMultiSigRoot` contract: the `granter` is a union (single `system/hash` |
`{signers, threshold}` map, **root-only**); at the chain root, `verify_multi_sig_root` runs §3.6 M3
structure (parent-null, n≥2, 2≤threshold≤n, distinct signers) **before** signature counting, then
§5.5 M6 (local ∈ signers) + M4 (**distinct**-signer valid-sig count over the cap's content_hash ≥
threshold). Multi-sig is root-only (an off-root multi-granter denies); single-sig is a strict
superset (unchanged path). An **accept-path unit test** (`test/multisig_accept.cpp`, 9/9) covers the
direction the rejection-only `multisig` oracle category cannot: a real 2-of-3 → ALLOW, plus M3/M4/M6
deny-flips and the single-sig superset.
**Escalation:** operator — implementation completeness (genuine vs rejection-only), non-blocking; no
spec ambiguity (the C# contract is the settled cohort reading).

### A-CPP-013 — `libtsan` absent from the `cpp-toolchain` image (ThreadSanitizer pass not runnable in-container)

**V7 section:** n/a (toolchain / container content).
**Profile field:** `[memory].leak_tooling` / `[memory].hardening` name ASan/LSan/UBSan (all present
and used); TSan is not named, but a TSan pass would be the strongest witness for the §4.8/§7b
store-safety claim.
**Observation:** the `containers/cpp-toolchain` image installs `libasan`/`libubsan` (the named
sanitizers — all tests build + run under `-fsanitize=address,undefined`, clean) but **not**
`libtsan` (`ld: cannot find libtsan.so.2.0.0`). A `-fsanitize=thread` build of the smoke runner
therefore cannot link in-container. Store-safety is argued structurally instead (immutable
`shared_ptr` entities + a `std::shared_mutex` store; A-CPP-011) and witnessed by repeated ASan-clean
concurrent runs. **Recommendation (operator, non-blocking):** add `libtsan` to the Containerfile's
dnf line so a `-fsanitize=thread` concurrency pass can run alongside ASan before S4's `concurrency`
gate — cheap insurance and a natural fit for a systems-language reach peer.
**Escalation:** operator — container content gap; non-blocking for S3.

---

**S3 verdict:** 3 net-new entries (A-CPP-011 shared-entity model, A-CPP-012 genuine multi-sig,
A-CPP-013 libtsan gap) — all C++ engineering / container findings, **none a spec defect**
(corroboration-only reach peer; the discovery well stays dry — no new V7 ambiguity surfaced). The
peer compiles GREEN on **both** g++ 15.2.1 and clang++ 21.1.8 under `-Wall -Wextra -Werror
-pedantic`, ASan/LSan/UBSan-clean; smoke 13/13 (incl. the §6.11 reentry loop), type-registry 53/53
byte-identical, multi-sig accept-path 9/9. The A-CPP-010 `Box` recursive-variant discipline held
across the peer layer on both compilers.

---

## A-CPP-014: §1.4 R1 path-flex — embedded-NUL detection via length-comparison was a no-op (peer bug, FIXED at S4)

**V7 section:** §1.4 R1 (path validation flex set; CORE-TREE-PATH-FLEX-1 in §9.5a).
**Profile field:** absent (a code-correctness bug, not a profile decision).
**Observation:** validate-peer's `core_tree_path_flex_1` sent a `tree:get` whose resource target
was `system/validate/core-tree/path-flex/with\x00null` (a NUL embedded mid-segment) and the peer
**accepted it → 200** (should be `400 invalid_path`). Root cause: `path_flex_ok()` tried to detect
an embedded NUL with `raw_len != target.size()`, but `exec_resource_target()` builds the target as
`std::string(ptr, size)` from the length-prefixed wire text — the NUL is preserved into the
`std::string` and `target.size()` already counts it, so the comparison was **never true** (the
"embedded NUL" guard never fired). This is the one genuine peer correctness bug S4 surfaced; it was
masked at S3 because the smoke harness never sends a control-byte path. **Fix:** `path_flex_ok()`
now scans the target bytes directly and rejects any control byte (`< 0x20`, incl. NUL, plus `0x7f`)
in any segment — the §1.4 R1 reading the C# pathfinder also took. After the fix
`core_tree_path_flex_1` → PASS; no other check regressed (the full `tree_operations` category +
codec/smoke/typereg/multisig regression all stayed green on g++ and clang++).
**Escalation:** operator — peer code bug, fixed in-tree (`src/dispatch.cpp` `path_flex_ok`). Not a
spec defect (§1.4 R1 is unambiguous). No arch action.

---

**S4 verdict:** 1 net-new entry (**A-CPP-014**, the §1.4 path-flex NUL bug — found by validate-peer,
fixed in `path_flex_ok`). `validate-peer --profile core` → **665 total · 0 FAIL · Result: PASS** on
the v7.77 oracle (`e8524ed`, core_gate `e09a865f…`). §10.1 register 10/10, §10.2 origination-core
3/3 (incl `dispatch_outbound_reentry`), multisig 11/11 (incl `valid_2of3_peer_signed_accepted`
genuinely running), concurrency 5/5, resource_bounds r1/r2 PASS + r3 WARN. **No new V7 ambiguity —
the discovery well stays dry, as the corroboration-only reach-peer slate predicted.**

---

## A-CPP-015: copyright-holder convention — `Entity Core Protocol contributors` vs `the entitychurch contributors` (S5)

**V7 section:** n/a (a packaging/licensing convention, not a spec item).
**Profile field:** `[publishing].authors = "Entity Core Protocol contributors"`; `[license]`.
**Observation:** the S5 brief named the LICENSE holder as `© the entitychurch contributors` while
*also* instructing "match how the C peer does it." These conflict: the C peer's `LICENSE` (and 13
other cohort peers' — 14/15 total) reads **`Copyright 2026 Entity Core Protocol contributors`**;
only one peer uses an `entitychurch` form. **Decision:** matched the dominant cohort convention
(`Entity Core Protocol contributors`) — it is what the named model peer (C) actually uses, what the
profile's `[publishing].authors` already declares, and what keeps the cohort's LICENSE files
uniform. Logged here per S3 (no silent guess); a deliberate divergence from the brief's literal
holder string in favor of cohort consistency + the profile authority (S6).
**Escalation:** research/operator — bookkeeping; if the ecosystem standardizes on the
`entitychurch` holder, it is a one-line sweep across all peers, not a C++-specific fix. Non-blocking.

---

## A-CPP-016: packaging surface — CMake `find_package` package + vcpkg port + conan recipe, none pushed (S5)

**V7 section:** n/a (S5 packaging, lifecycle §Publishing / §Version-pin).
**Profile field:** `[publishing]` (`registry = "cmake-package + vcpkg + conan"`, `vcpkg_port`,
`conan_recipe`, `cmake_config`, `repository_url = ""`), `[build].pack_command` (CPack).
**Observation:** C++ has **no single central package registry** — the profile names three parallel
decentralized surfaces (the slate row-3 decision: "vcpkg/conan + CMake"). Authored all three,
version-pinned at the numeric `0.1.0` (the `-pre` marker carried in CHANGELOG/README/PHASE-S5 — the
CMake `project(VERSION)` / vcpkg `version` / conan `version` fields are dotted-numeric-only, the same
`-pre`/numeric split the C peer hit with `pkg-config` and CL with ASDF, A-CL-010):
- **CMake package** — `install(EXPORT)` + `configure_package_config_file` →
  `EntityCoreProtocolConfig.cmake` (template `packaging/cmake/*.in`), consumed via `find_package` /
  `FetchContent` / `add_subdirectory`; CPack (`--target package`) emits the source/binary tarball.
- **vcpkg port** — `packaging/vcpkg/{vcpkg.json,portfile.cmake}` (overlay-port consumable today; on
  publish the in-repo `SOURCE_PATH` becomes a `vcpkg_from_github(... REF v0.1.0 SHA512 ...)`).
- **conan recipe** — `packaging/conan/conanfile.py` (`entity-core-protocol/0.1.0`; `conan create`
  locally; on publish, switch `exports_sources` to a tagged-release fetch).
**Decision:** **none is pushed to any registry** — that is an operator action after arch v0.1 sign-off
+ a first external C++ consumer (the `-pre` promotion gate); `/entity-rosetta` never publishes
(lifecycle §Publishing). The publish-time TODOs are explicit in each recipe: set
`[publishing].repository_url`, the release tag, and the tarball SHA512/SHA256 (currently empty/in-repo).
**Escalation:** operator — the publish action + the registry-submission decision. Non-blocking;
the artifacts are authored + build-consumable in-repo today.

---

**S5 verdict:** 2 net-new bookkeeping entries (**A-CPP-015** holder-convention, **A-CPP-016**
packaging surface) — neither a spec item. README / LICENSE / CHANGELOG / CMake-package +
vcpkg-port + conan-recipe / CI (`.github/workflows/cpp.yml`) / `tools/oracle-pin.env` authored;
version parked at `0.1.0-pre`; license Apache-2.0 (S9). **Nothing published** (lifecycle §Publishing).
The discovery well stays dry, as the corroboration-only reach-peer slate predicted.
