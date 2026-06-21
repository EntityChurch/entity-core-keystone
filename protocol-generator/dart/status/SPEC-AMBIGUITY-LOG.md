# entity-core-protocol-dart — Spec Ambiguity Log

Every guess / judgment call made while generating the Dart peer (a release "reach" peer;
`research/RELEASE-READINESS.md` §2 row 4). Format per PROMPT-CONSTANTS.md §"Ambiguity-log
discipline". Items escalate to architecture as proposal candidates via `research/stewardship/`.
**No silent guesses.**

`A-DART-NNN` convention. Severity: a **blocking** item halts the dependent phase; the rest are
recorded decisions / escalations / pre-resolved inheritances. **No blocking items at S1 exit.**

The discovery well is **dry** — the 8-peer synthesis saturated the language axes, and the
static-typed-null-safe-async idiom space is already covered by Kotlin/TypeScript/C#. Dart is a
**reach** peer (`research/RELEASE-READINESS.md` §2 honesty note: the reach peers
Kotlin/C++/PHP/Dart are corroboration-only, built for ecosystem coverage, not to surface spec
findings). Its value is ecosystem coverage (a Dart/Flutter dev can pull a native pure-Dart pub.dev
peer) + exercising the generator against Dart idiom (Dart-3 sealed-class Result + exhaustive
switch-expression, sound null-safety, Future/isolate async, the **BigInt uint64 head-form
carrier**). No new spec ambiguity was strained for or invented at S1. The inherited-settled items
(peer_id, hex-case, 401/403, A-JAVA-010 data-shape, 400-chain-depth, §7b) are recorded below as
**PRE-RESOLVED** so S2/S3 do not re-burn them.

---

## PRE-RESOLVED inheritances (settled cohort convergence — NOT open questions)

These are folded into `profile.toml` + `arch/PROFILE-RATIONALE.md`. Recorded here so S3 inherits
them as decided, with the §-pointers, not as fresh guesses.

### P1: peer_id construction — §1.5 canonical-form (hash_type=0x00, raw pubkey), NOT §7.4 SHA-256
**V7 section:** §1.5 canonical-form table + §1.5 `data` construction; §7.4 reconciled via E1
(v7.73) to defer to §1.5; §9.1 floor.
**Profile field:** `[spec]` peer_id note; `[codec].ed25519_library` (raw 32-byte pubkey extraction).
**Your guess:** Construct the Ed25519 peer_id as `Base58(varint(0x01) || varint(0x00) ||
public_key)` — `hash_type = 0x00` identity-multihash, the digest **IS** the raw 32-byte public key.
IGNORE the stale SHA-256 / `hash_type=0x01` form (decode-time wire-acceptance carve-out only).
**Rationale:** PRE-RESOLVED — **7th+ spec-first arrival** (A-OC-007 / A-ZIG-001 / A-CL-002 /
A-JAVA-004 / A-KT-004 / A-CPP P1; already reconciled in the v7.75 body via v7.73 E1). The S2 corpus
uses opaque digests, so a wrong construction passes S2 green and only fails at the S4 handshake
(`401 identity_mismatch`). Built in now. (Also: in Dart extract the raw pubkey via
`SimplePublicKey.bytes` from cryptography_plus — verify at S2.)
**Escalation:** arch — already escalated by 6+ peers; corroboration, no new ask.

### P2: address-space tree-path hex MUST be lowercase
**V7 section:** §3.4 / §3.5 (tree-path keys rendered from content_hash hex).
**Profile field:** `[idiom].hex_lowercase = true`, `[naming].hex_case = "lowercase"`.
**Your guess:** All external hex rendering is lowercase — Dart `b.toRadixString(16).padLeft(2,'0')`
is lowercase by default; NEVER `.toUpperCase()`.
**Rationale:** PRE-RESOLVED (A-CL-009 — the headline second-cohort defect). Tree paths are
case-sensitive string keys; the Go oracle uses `hex.EncodeToString` (lowercase). Dart avoids the
A-CL-009 uppercase trap by default but it is **pinned explicitly** so no codec site can regress.
**Escalation:** arch already asked to pin lowercase normatively (A-CL-009); corroboration only.

### P3: §5.2 trichotomy — 401 (authn) / 403 (authz) / 401-unresolvable
**V7 section:** §5.2 + the §5.2a verdict-to-status enumeration (v7.73 E2).
**Profile field:** `[error_model].error_hierarchy` (ProtocolError: AuthenticationFailed=401,
AuthorizationDenied=403).
**Your guess:** Request-time EXECUTE on a non-connect path: author absent → **401**
authentication_failed; capability absent (author present + signed) → **403** capability_denied;
unresolvable author → 401. §5.2a is the single source of truth for the (status, code) tuple.
**Rationale:** PRE-RESOLVED (5+-peer convergence; F20 / A-OC-008 / A-SW-010 / A-C P3). §5.2a
absorbed the ruling; build to it.
**Escalation:** arch — §5.2a already absorbed it; no new ask.

### P4: §1.1 entity `data` is an ARBITRARY ECF value, NOT necessarily a map
**V7 section:** §1.1 entity model.
**Profile field:** `[codec]` (the hand-rolled `EcfValue` sealed hierarchy over all ECF major types).
**Your guess:** Model `data` as a **general ECF value** (any major type — scalar, bytes, array,
map) from the start. In Dart this is a **sealed `EcfValue`** hierarchy (the closed set of ECF major
types), never a map-typed field.
**Rationale:** PRE-RESOLVED (the A-JAVA-010 silent-500 trap). A map-only model passes S2/S3 green
then returns **500** on the first scalar-`data` entity at the live S4 gate. The Dart sealed-class +
exhaustive-switch idiom makes the general value model natural.
**Escalation:** none — spec is clear; a generation-discipline pre-resolution.

### P5: resource_bounds (§4.10) — 413 oversize / 400 chain_depth_exceeded / 503 flood
**V7 section:** §4.10 (a/b/c); CORE-gating since the v7.75 cycle.
**Profile field:** `[error_model].error_hierarchy` (PayloadTooLarge=413, ChainDepthExceeded=400).
**Your guess:** r1: oversize payload → `413 payload_too_large` or clean close (default **16 MiB**).
r2: over-deep delegation chain → **`400 chain_depth_exceeded`** — **MUST be 400, NOT 403** (default
depth **64**). S3 builds the ~15-line §4.10(b) **structural pre-check**: walk parents with **NO
signature work**, max=64, **BEFORE** the per-link authz walk; an over-depth self-chain → 400, an
*unreachable* parent stays 403. r3: connection flood → `503`/close or honest WARN.
**Rationale:** PRE-RESOLVED (all prior peers needed the chain-depth pre-check). The §4.10 defaults
(16 MiB / 64) are INFORMATIVE recommended defaults, NOT normative constants (v7.75 MANIFEST) — the
contract is "enforce a finite declared bound + reject over-limit cleanly."
**Escalation:** none — settled cohort fix.

### P6: §7b concurrency gate is CORE-gating (5/5) — and Dart's event-loop confinement makes §4.8 structural; A-C-009 is N/A
**V7 section:** §4.8 (data-race safety) / §4.9 (resilience) / §6.11 + GUIDE-CONFORMANCE §7b.
**Profile field:** `[async].store_safety`, `[async].tcp_nodelay = true`.
**Your guess:** Data-race-safe store (§4.8) → **event-loop confinement**: Dart's single-threaded
event loop per isolate means a **synchronous** critical section over the store map is **atomic by
construction** (no preemption without an `await`), so no lock is needed within one isolate.
Resilience under load (§4.9) → exceptions caught at the per-connection task boundary.
**TCP_NODELAY** mandatory on every connection socket
(`Socket.setOption(SocketOption.tcpNoDelay, true)`) — the Zig §7b finding. Reentrant `request_id`
demux (N7) via `Map<int, Completer<T>>`.
**Rationale:** PRE-RESOLVED (concurrency-gate-7b: all prior peers green). The **A-C-009**
atomic-refcount finding (no-GC shared-entity race across threads) is **N/A** for Dart: it is GC'd
AND single-threaded per isolate, so shared entities are never concurrently mutated across threads
(the same reason the other GC'd peers never hit A-C-009). Event-loop confinement is the cleanest
§4.8 story alongside the actor-isolation peers (Elixir/Swift).
**Escalation:** none — settled gate; Dart corroborates that a single-threaded-event-loop language
gets §4.8 store-safety structurally.

---

## A-DART-001: codec strategy = native hand-roll (slate decision; NOT the `cbor` pub package, NOT FFI)

**V7 section:** absent (codec-strategy / library choice; PHASE-S1 codec-strategy matrix + the slate
decision row 4).
**Profile field:** `[codec].strategy = "native"`, `cbor_library = "hand-rolled"`.
**Your guess:** Hand-roll the canonical CBOR codec **natively in idiomatic Dart**
(`lib/src/codec/ecf.dart`) rather than using the `cbor` pub package or consuming the sibling C/Rust
FFI codec `libentitycore_codec`.
**Rationale:** The slate fixed it ("hand-roll ECF — cbor pkg not ECF"). The `cbor` pub package
implements general RFC-8949 CBOR and does NOT give ECF canonicality: length-FIRST-then-bytewise
(CTAP2) map-key ordering (≠ RFC-8949 §4.2 bytewise), the shortest-float incl. f16 ladder, recursive
major-type-6 tag rejection, raw-byte fidelity. This is the **A-005 pattern** every native peer hit
(C#, TS, OCaml, Elixir, Zig, CL, Swift, Haskell, Java, Kotlin, C++ all hand-rolled) — there is no
easy library path for ECF. A `cbor`-package peer would still hand-enforce the canonical layer, so a
library buys nothing but a dep + pin. Native independence is the corroboration value ("no
trench-coat" — C++ D1). `ffi` is the documented fallback only if the S2 spike fails (NOT expected;
also forfeits pure-Dart self-containment). Spike at S2 start: map_keys + float v7.71 vectors.
**Escalation:** operator — local decision within the profile's authority + an already-recorded
slate decision; non-blocking.

---

## A-DART-002: crypto floor = cryptography_plus (the MAINTAINED fork), NOT the stalled `cryptography` — pure-Dart Ed25519

**V7 section:** absent (crypto-library choice; the slate's S1-open "`cryptography` pkg / FFI —
evaluate which is maintained/idiomatic").
**Profile field:** `[codec].ed25519_library = { name = "cryptography_plus", version = "2.7.0" }`,
`sha256_library = { name = "crypto", version = "3.0.6" }`.
**Your guess:** Ed25519 floor via **`cryptography_plus` 2.7.0** (pure-Dart), SHA-256 floor via the
first-party **`package:crypto` 3.0.6**. NOT the original `cryptography` package; NOT FFI for v0.1.
**Rationale (the S1 maintenance evaluation the slate asked for):** the original `cryptography`
package (terrier989 / dint-dev) is **effectively stalled** — the community moved the maintained line
to **`cryptography_plus`** (repo now `emz-hanauer/dart-cryptography`) precisely because of lack of
upstream maintenance, so the stalled original fails the slate's "genuinely maintained" bar. The
maintained fork is the package-route choice. **Pure-Dart Ed25519 keeps the peer self-contained on
EVERY Flutter target** (iOS / Android / web / WASM / desktop) with no native `.so`/`.dylib` to
bundle — which IS the reach value. An FFI peer would be byte-correct but forfeit self-containment (a
native lib per ABI), the opposite of the reach goal. SHA-256 via first-party `package:crypto` is the
leaner floor-hash choice (lower surface/churn than reaching into cryptography_plus for the hash).
**PIN-DATE SENTINEL (S11):** verify `cryptography_plus` 2.7.0's pub.dev publish date is ≥30 days old
at the S2 build; if too new, pin the latest ≥30-day-old 2.x and re-log. cryptography_plus is
Apache-2.0; crypto is BSD-3.
**Escalation:** research — profile/crypto: records the cohort finding that the canonical Dart
crypto package is the *fork*, not the original; non-blocking for the floor.

---

## A-DART-003: Ed448 (key_type 0x02) — no maintained pure-Dart impl → DEFER (FFI route documented, not v0.1)

**V7 section:** §1.5 key_type table (0x02 Ed448); §7.3 (Ed448 validated v7.67); §8.1. Crypto-agility
*higher bar*, NOT the §9.1 floor.
**Profile field:** `[codec].ed448_library = { name = "DEFERRED (FFI route documented)", version =
"none" }`.
**Your guess:** Defer Ed448 at the profile level, per the slate ("gap → FFI/defer"). The Ed25519
(`key_type 0x01`) + SHA-256 (`content_hash_format 0x00`) §9.1 floor is fully native pure-Dart
(cryptography_plus + crypto) and **unaffected**. cryptography_plus has **no Ed448** (Ed25519/X25519/
ECDSA/RSA + SHA-2, no Ed448-Goldilocks), and there is no maintained pure-Dart Ed448.
**Rationale:** Same native gap C (A-C-001), Zig (A-ZIG-002), OCaml (A-OC-002), Rust (A-RUST-002),
C++ (A-CPP-002) hit and Swift deferred (A-SW-001). When agility enters scope (NOT v0.1), the
dependency-lightest Dart route is **`dart:ffi`** to the sibling `entity-core-codec-ffi-c` agility
`.so` (C-ABI v1.1 already vendored a self-contained openssl curve448 for its Ed448 family) — but
FFI **breaks the pure-Dart self-containment** (a native lib per Flutter target), so DEFER is the
v0.1 default and FFI is the documented agility route, NOT a v0.1 path. The **SHA-384** agility
*hash* **IS** in cryptography_plus (`Sha384`), so only the Ed448 **signature** is the gap. Does not
block the floor.
**Escalation:** research — profile/agility (6th+ peer to hit the same Ed448 native gap; reinforces
the cross-peer finding that no minimal native crypto stack covers Ed448, and for Dart specifically
that pure-Dart Ed448 does not exist maintained).

---

## A-DART-004: error model = Dart-3 sealed-class Result + exhaustive switch expression (NOT exceptions — distinct from the TS peer)

**V7 section:** absent (error-model choice; S6 profile-decides).
**Profile field:** `[error_model].style = "result"`, `result_type = "sealed-class"`,
`checked = false`.
**Your guess:** Use a **Dart-3 sealed-class Result** (`sealed class EcfResult<T> { Ok ; Err }` + a
sealed `EntityError` hierarchy) matched **exhaustively by a `switch` EXPRESSION**; reserve
exceptions for programmer-error only (`StateError`/`ArgumentError`), caught at the per-connection
task boundary; never throw for protocol flow.
**Rationale:** Dart 3 (2023) made sealed classes + exhaustive switch-expressions first-class, so the
Result idiom is statically-exhaustive (the analyzer reports a non-exhaustive switch over a sealed
type) — the Dart-3 analogue of Kotlin's sealed `when`, OCaml's `result`, Zig's error union, C++'s
`std::expected`. This is a **deliberate idiom point distinct from the TypeScript peer**, which chose
plain exceptions (JS idiom). Dart *could* throw too, but the sealed-Result is the more-rigorous,
distinctly-Dart-3 point (closer to Kotlin than TS) and exercises the generator on the
static-exhaustiveness axis.
**Escalation:** operator — local/profile decision (S6); non-blocking. Recorded so S2/S3 do not
silently re-pick exceptions-on-the-hot-path.

---

## A-DART-005: concurrency = Future/async-await on the per-isolate event loop; event-loop confinement for §7b store-safety

**V7 section:** §4.8 / §4.9 / §6.11 / §7b (the concurrency surface); NOT exercised by the codec (S2
is pure/synchronous).
**Profile field:** `[async].style = "future"`, `store_safety = "event-loop-confinement"`,
`request_demux = "Map<int, Completer<T>>"`, `tcp_nodelay = true`.
**Your guess:** One event-loop isolate drives dispatch; each connection is async
`Stream<List<int>>` socket reads; a reader future demuxes `EXECUTE_RESPONSE` by `request_id` via a
`Map<int, Completer<T>>` (N7). §7b store-safety is **structural** via event-loop confinement (a
synchronous critical section over the store is atomic — no preemption without `await`). TCP_NODELAY
on every connection socket. Isolates are available for parallelism but NOT needed for `--profile
core`. Codec stays sync.
**Rationale:** Dart's headline concurrency is Future/async-await + single-threaded event loop per
isolate (Future == TS Promise; isolates are the distinct Dart parallelism story). Single-threaded
confinement is the cleanest §4.8 story alongside the actor-isolation peers (Elixir/Swift), and the
**A-C-009** atomic-refcount finding is **N/A** (GC'd + single-threaded). TCP_NODELAY is mandatory
regardless of concurrency model (the Zig Nagle finding). A decision, not a spec gap; recorded so S3
does not re-pick the model.
**Escalation:** operator — local/profile decision (S3 validates; non-blocking).

---

## A-DART-006: uint64 head-form carrier = BigInt (the headline codec call — web/dart2js 53-bit-int truncation trap)

**V7 section:** §1.5 / §7.3 (the multikey + integer head-form); ENTITY-CBOR-ENCODING (int.10/15/16/17
head-forms, the [2^63, 2^64-1] band).
**Profile field:** `[idiom].integer_carrier = "BigInt"`, `bigint_for_64bit = true`.
**Your guess:** Carry the **full `uint64`/`nint` head-form range via Dart `BigInt`** at the
head-form boundary; bare `int` only for values provably within the safe range; the canonical
shortest-head-form emit is computed over `BigInt`.
**Rationale (THE single most important codec-correctness decision for Dart):** Dart `int` is 64-bit
on the **native VM** but maps to a **JS number (53-bit integer precision)** under `dart2js` /
`dart compile js` / **web** — a `uint64` head value near `2^63` **silently truncates** on web. This
is the cohort **A-OC-001 / F7** trap; **TypeScript hit the identical JS-`number`-caps-at-2^53 trap
and solved it with `bigint` end-to-end** (its `integer_model = "always-bigint"`). Because this is a
**Flutter** peer and Flutter **targets web/WASM**, a VM-correct-but-web-wrong codec would be a latent
data-corruption bug in the reach audience. `BigInt` (first-party `dart:core`, arbitrary-precision on
both native and web) carries the full range exactly. **Rejected:** the `fixnum` package (`Int64`) —
it works but is a registry dep; `BigInt` is first-party + zero-dep + exact. **S2 MUST watch:** run
the codec spike AND a smoke `dart compile js`/`dart2js` integer round-trip to confirm no web-int
truncation; NEVER carry a `uint64`-range head value in a bare `int`.
**Escalation:** operator/research — local codec-engineering decision corroborating the cross-peer
F7 integer-width finding; non-blocking. The headline thing S2 must get explicit.

---

## A-DART-007: pub.dev publisher namespace + package name `entity_core_protocol` (hyphens not allowed)

**V7 section:** n/a (S5 packaging).
**Profile field:** `[publishing].package_id = "entity_core_protocol"`, `publisher = ""`,
`repository_url = ""`, `parked_version = "0.1.0-pre"`.
**Your guess:** pub.dev package name is **`entity_core_protocol`** (`lowercase_with_underscores`,
since pub names cannot hyphenate — the keystone peer id `entity-core-protocol-dart` maps to it);
publish to pub.dev under a **verified publisher** namespace (TBD, claimed at first publish); parked
at `0.1.0-pre`.
**Rationale:** pub.dev names are `lowercase_with_underscores` only (no hyphens). Publishing requires
a verified pub.dev publisher (the optional S5 step); the namespace is a placeholder until claimed.
The `-pre` marker rides the pubspec `version:` field (pub supports semver pre-release suffixes
directly, unlike CMake/conan's dotted-numeric-only fields — no `-pre`/numeric split needed here).
**Escalation:** operator — the publish action + the publisher-namespace decision. Non-blocking.

---

## A-DART-008: spec version — read v7.75 (latest stamped), gate against the v7.77 oracle

**V7 section:** absent (spec-version / oracle provenance).
**Profile field:** `[spec].v7_version_pinned = "7.75"`, `[spec].target_oracle` (v7.77 head).
**Your guess:** Derive the profile + peer from `spec-data/v7.75` (the latest stamped snapshot), and
gate against the **v7.77** validate-peer oracle (`entity-core-go @ e8524ed`, the 19-peer matrix
uniform 665 / 0 FAIL).
**Rationale:** The core floor is **stable v7.75→v7.77** (the v7.77 delta is all extension/
relay/network/encryption + the V8-naming kebab fold); the wire/protocol surface is byte-stable
(ENTITY-CBOR-ENCODING + ENTITY-NATIVE-TYPE-SYSTEM unchanged since v7.73 E3 / v7.70). For a
corroboration-only reach peer, deriving from v7.75 + gating against the v7.77 oracle is the
established cohort pattern (re-run vendors the oracle, not the snapshot). The orchestrator pins the
exact clean go commit at S4.
**Escalation:** operator — provenance bookkeeping (non-blocking). Re-confirm the oracle HEAD / clean
pin at S4.

---

## A-DART-009: §7a/§7b conformance scaffolding is GUIDE-carried, not in v7.75 spec-data

**V7 section:** GUIDE-CONFORMANCE.md §7a (validate handlers) + §7b (concurrency gate) — NOT in the
three normative spec-data files (per the v7.74/v7.75 MANIFEST note).
**Profile field:** `[spec].conformance_scaffolding = "guide-conformance-7a-7b"`.
**Your guess:** Derive the **protocol surface** (including the §4.10 floor MUSTs, which ARE in the
v7.75 snapshot) from `spec-data/v7.75`, but pick up the **conformance scaffolding** (the
`system/validate/{echo,dispatch-outbound}` handlers behind a `--validate` opt-in, off by default;
the §7b store concurrency-safety gate; the generator-menu defaults — 16 MiB/64, TCP_NODELAY) from
`GUIDE-CONFORMANCE.md` + the keystone generator menu at S3/S4 — not from spec-data.
**Rationale:** The MANIFEST explicitly flags this split (§7a/§7b live in the non-normative guide +
the generator menu, not the snapshot). A spec-first peer reading only spec-data would MISS the
conformance handlers and fail S4. Recorded now so S3/S4 pull them from the right source
(corroborates A-SW-006 / A-C-003 / A-CPP-006).
**Escalation:** research — operator-carried convention; track the standing arch open-item on whether
GUIDE-CONFORMANCE joins the snapshot set.

---

## A-DART-010: peer_id construction is §1.5 (raw pubkey), NOT §7.4 SHA-256 (corroboration — see P1)

**V7 section:** §1.5 canonical-form table; §7.4 (reconciled via v7.73 E1 to defer to §1.5).
**Profile field:** `[spec]` peer_id note.
**Your guess:** `peer_id = Base58(varint(0x01) || varint(0x00) || public_key)` — `hash_type=0x00`
identity-multihash, digest IS the raw 32-byte pubkey. (Same as P1; logged separately as the
cohort-corroboration entry.)
**Rationale:** Corroboration-only on v7.75 (the §7.4-vs-§1.5 contradiction is already closed in the
v7.75 body). Baking the §1.5 form in proactively dodges the `401 identity_mismatch` handshake
failure the S2 opaque-digest corpus would NOT catch. 7th+ spec-first arrival.
**Escalation:** arch — corroboration of an already-closed reconciliation; no new ask.

---

## A-DART-011: container — Dart SDK fetched as the official tarball + verified sha256 (NOT fedora dnf); S2 fills the sentinel digest

**V7 section:** n/a (toolchain / container provenance; S11).
**Profile field:** `[container]` (NEW dart-toolchain Containerfile; pin-the-official-tarball).
**Your guess:** Author a NEW `containers/dart-toolchain/Containerfile` (fedora:43 base) that fetches
the **dart-lang official SDK release zip** (Dart 3.11.6, x64-linux) from
`storage.googleapis.com/dart-archive` and verifies it against the published sha256 — NOT `dnf
install` (fedora:43 does not carry a current Dart SDK). The `DART_SHA256` is a **SENTINEL** at S1
(authoring does not fetch/build — S1 boundary); the real digest is filled at the S2 build from the
published `.sha256sum`, and the build FAILS CLOSED on the sentinel. A `prefetch/pubspec.yaml`
(pinned deps) populates the image `PUB_CACHE` in one network-on layer so the dev loop runs
`--network=none` with `dart pub get --offline`.
**Rationale:** The kotlin/zig/java-toolchain pin-the-exact-compiler-and-verify pattern. The Dart SDK
is a reviewed vendor channel (Google/dart-lang reviewed build pipeline), so the ≥30-day age floor
relaxes for the SDK (and 3.11.6 at ~45d meets it anyway); the exact pin + verified sha256 stand for
reproducibility. The pub deps get the ≥30-day discipline with full force (registry-pulled).
**Escalation:** operator — toolchain provenance bookkeeping; non-blocking. Fill the DART_SHA256 (and
re-confirm the cryptography_plus / test publish dates) at the first S2 build.

---

## A-DART-012: cryptography_plus re-pinned 2.7.0 -> 2.7.1 at S2 (the S1 sentinel fired — 2.7.0 does not exist on pub.dev)

**V7 section:** absent (crypto-library pin; the S1 PIN-DATE SENTINEL on A-DART-002).
**Profile field:** `[codec].ed25519_library = { version = "2.7.0" }`, `[deps].cryptography_plus = "2.7.0"`.
**Your guess:** Re-pin `cryptography_plus` from the profile's **2.7.0** to **2.7.1**. The S1
sentinel asked S2 to "confirm 2.7.0's pub.dev publish date is ≥30 days old; if too new, pin the
latest aged 2.x and log it." The sentinel fired for a different reason than anticipated: **2.7.0
does not exist on pub.dev at all** — the 2.x line publishes **2.7.1** (~602
days old, far clears the ≥30-day floor), and the latest overall is 3.0.0. 2.7.1 is
the aged 2.x release the sentinel directs toward. Verified its constraints are compatible: `sdk
>=3.1.0 <4.0.0` (our SDK 3.11.6 fine), `crypto ^3.0.3` (our 3.0.6 fine). Updated profile-mirrored
pins in `pubspec.yaml`, `containers/dart-toolchain/prefetch/pubspec.yaml`, and the committed
`pubspec.lock`. The image built, deps resolved, Ed25519 RFC-8032 KAT + sign/verify pass.
**Rationale:** The profile is the authority on the *package*; the exact patch is an S2-build-time
fact (the S1 boundary forbade fetching/resolving). 2.7.0 was an S1 best-guess version that did not
materialize; 2.7.1 is the same maintained fork, same major.minor line, aged well past the floor,
API-identical for the Ed25519 floor (`Ed25519().newKeyPairFromSeed / .sign / .verify`;
`SimplePublicKey.bytes`). No behavior change vs the S1 intent — a pin correction, not a re-decision.
**Escalation:** research — profile/crypto pin maintenance (the recorded sentinel resolution; the
profile's 2.7.0 should be corrected to 2.7.1 at the next profile touch). Non-blocking; the floor
passes.

---

## A-DART-013: nodejs added to the dart-toolchain image as a TEST-TIME JS runtime (the dart2js web-truncation proof)

**V7 section:** n/a (toolchain; the A-DART-006 web-safety proof obligation).
**Profile field:** `[container]` (the dart-toolchain image).
**Your guess:** Add `nodejs` (fedora dnf, at the network-on image-build layer) to the
dart-toolchain image. It is used ONLY to **execute** the `dart compile js` output of
`tool/web_int_smoke.dart` (`run-s2.sh web`), proving the BigInt uint64 head-form carrier does not
53-bit-truncate under dart2js/web across the [2^63, 2^64-1] band (A-DART-006). It is NOT a build or
runtime dependency of the peer (the peer is pure Dart; node never ships).
**Rationale:** The S1 mandate explicitly asked to "smoke a `dart compile js` integer round-trip over
the [2^63, 2^64-1] band to prove no web truncation." A compile-only check proves it *compiles*; only
EXECUTING the emitted JS under a JS-`number`-semantics runtime proves the band survives. The host
(atomic Fedora) and the original image had no JS runtime, so the proof needed one. node is the
standard dart2js test runtime. Added at build time (network-on), sealed `--network=none` thereafter.
**Escalation:** operator — toolchain/test provenance; non-blocking. The smoke is green
(`WEB-INT SMOKE: PASS (4 band values, no truncation)`).

---

## A-DART-014: profile-text crypto pin reconciled 2.7.0 → 2.7.1 (the S2 carry-forward, discharged at S3)

**V7 section:** absent (crypto-library pin maintenance; A-DART-012 follow-through).
**Profile field:** `[codec].ed25519_library.version`, `[deps].cryptography_plus`.
**Your guess:** At S3 (the next profile touch), update the profile TEXT from `2.7.0` to `2.7.1` at
both pin sites (`[codec].ed25519_library` line + `[deps].cryptography_plus` line), with an inline
note pointing to A-DART-012. The lockfile / pubspec / prefetch were already 2.7.1 at S2; only the
profile text lagged.
**Rationale:** A-DART-012 resolved the sentinel (2.7.0 absent on pub.dev; 2.7.1 is the aged 2.x
release) and corrected the lock/pubspec/prefetch, but explicitly left the profile text for "the next
profile touch." S3 is that touch. Bookkeeping only — no behavior change, no re-decision.
**Escalation:** research — pin maintenance, now fully reconciled (profile text == lock == pubspec ==
prefetch == 2.7.1). Closed.

---

## A-DART-015: §6.11 dispatch-outbound smoke inner-verdict is a §5.2 cap check (S4 supplies the cross-peer cap)

**V7 section:** §6.11 reentry / §6.13(b) outbound; §5.2 authz (the inner EXECUTE's verdict).
**Profile field:** `[spec].conformance_scaffolding` (the §7a dispatch-outbound handler).
**Your guess:** At the S3 two-peer loopback smoke, the §6.11 dispatch-outbound reentry asserts the
OUTER status (200 = the transport seam round-tripped B→A→B over the same inbound connection). The
INNER echo verdict carried in the result is A's §5.2 cap check on the reentrant EXECUTE — at the
smoke it is **403** (A authorizes by the session cap B passed, which does not grant
`system/validate/echo`). Scope the smoke claim to the transport seam; S4's validator (B-role)
supplies the cross-peer reentry cap that flips the inner verdict to 200.
**Rationale:** Identical scoping to the Kotlin reference (A-KT-012) and the cohort: the smoke proves
the reentry TRANSPORT path end-to-end (the from-zero-transport trap that bit OCaml/COBOL is avoided)
without minting a cross-peer cap inline; that cap is the validator's job at S4's
`dispatch_outbound_reentry` gate. The handler, the §6.13(b) outbound primitive, and the reader-demux
reentry are all built + smoke-proven now. Outer 200 + inner 403 is the EXPECTED smoke shape, not a
defect.
**Escalation:** none — corroboration of the cohort reentry-smoke convention; S4 reads inner-403 as
expected.

---

**S3 finalization verdict (peer machinery):** corroboration-only as the reach-peer mandate predicted
— **no new spec defect surfaced.** The S2 carry-forwards are discharged: §4.10(b) chain-depth
pre-check (P5) built as a ~15-line structural `chainExceedsDepth` BEFORE the authz walk (over-depth →
**400**, unreachable parent → 403); §5.2a trichotomy (P3) wired (401/403/400 + the §5.5
unresolvable-grantee → 401 carve-out); entity `data` general (P4); TCP_NODELAY on every socket (P6);
event-loop confinement gives §4.8 store-safety structurally (the store is sync-only; no `await`
inside a critical section). The two mandates are GENUINELY built: real §3.6 K-of-N
`verifyMultiSigRoot` with a PASSING accept-path unit test (2-of-3 → ALLOW + M3/M4/M6 deny flips +
single-sig superset), and a §6.11 reentry-capable transport + §7a `system/validate/{echo,
dispatch-outbound}` handlers, the dispatch-outbound reentry round-tripping over the inbound
connection at the smoke (A-DART-015). The `--name` on-disk PEM keypair load works (the S4 multisig
accept-path prerequisite). Two new non-blocking notes (A-DART-014 pin-text reconciliation,
A-DART-015 reentry-smoke scoping). Loopback **12/12**, units (multisig + type-registry 53/53 +
codec 69/69 + selftests) all green.

---

**S1 finalization verdict:** 6 PRE-RESOLVED inheritances (P1–P6; incl. A-C-009 being N/A for a GC'd
single-threaded-event-loop language) + 11 entries (A-DART-001..011), all local/profile decisions or
non-blocking notes/deferrals with named owners. **No blocking item at S1 exit** (A-DART-003 Ed448 is
the agility higher bar, non-blocking for the §9.1 floor; native hand-roll codec / cryptography_plus
floor / BigInt int-carrier / sealed-Result error model / pub.dev packaging / peer_id + hex +
data-shape + resource_bounds + concurrency all pre-resolved or profile-decided). No new spec defect
surfaced or invented (corroboration-only reach peer, discovery well dry). S1 ambiguity log
initialized.

---

## S4 (Conformance)

**A-DART-016 (peer-correctness defect, NOT a spec ambiguity; FIXED).** The first full
`validate-peer --profile core` run had 2 FAIL, both `concurrency` robustness
(`t2_1_sustained_load`: 2263/10000 requests dropped; `t2_2_connection_churn`: peer stopped
accepting after cycle 0). Root cause: the per-connection frame reassembler in
`lib/src/peer/transport.dart` was O(n²) per drain — `BytesBuilder.toBytes()` copied the entire
accumulated buffer on every loop iteration, and each parsed frame rebuilt the remainder. Under
TCP-coalesced sustained load this starved the single event loop (which also hosts the shared
accept callback) → dropped responses + stalled accept. Compounded by `Listener._conns` being a
`List` that never removed connections on close (unbounded churn leak). Fix (peer-code only;
oracle/test untouched): O(1)-cursor reassembly (growable `Uint8List` + `_lo`/`_hi` offsets,
geometric grow + compact-on-demand + release-when-drained), a `Set` of live connections with an
`onClose` removal callback, and `backlog: 1024` on the listener bind. Pure I/O-path complexity
fix — wire framing/demux/dispatch/§6.11 reentry semantics byte-identical. After: concurrency 5/5,
no regression (analyze clean, smoke 12/12, full core 665/0 FAIL). **The reach-peer prediction held
— no new spec defect; the one S4 finding was an implementation bug validate-peer exists to
surface.**

**S4 verdict:** `validate-peer --profile core` 665/0 FAIL/PASS; origination-core 3/3 (incl
`dispatch_outbound_reentry`); multisig 11/11, 0 skip (incl `valid_2of3_peer_signed_accepted`
genuinely running via `--name conformance`); concurrency 5/5; resource_bounds green. §1.5 peer_id
re-verified against the live `entity-peer` handshake (connectivity 22/22). One defect found+fixed
(A-DART-016), no blocking ambiguity, Ed448/SHA-384 deferred (A-DART-003). **S4 PASS.**
