# entity-core-protocol-c — Spec Ambiguity Log

Every guess / judgment call made while generating the C peer (peer #10). Format per
PROMPT-CONSTANTS.md S3. Items escalate to architecture as proposal candidates via
`research/stewardship/`. **No silent guesses.**

`A-C-NNN` convention. Severity: a **blocking** item halts the dependent phase; the rest
are recorded decisions / escalations / pre-resolved inheritances. **No blocking items
at S1 exit.**

The discovery well is **dry** — nine independent prior peers found no new defect on the
v7.75 surface (`v775-rerun-pending`). C is the breadth probe (the last untried memory
axis); no new spec ambiguity was strained for or invented at S1. The inherited-settled
items (peer_id, hex-case, 401/403, A-JAVA-010 data-shape, 400-chain-depth) are recorded
below as **PRE-RESOLVED** so S2/S3 do not re-burn them.

---

## PRE-RESOLVED inheritances (settled cohort convergence — NOT open questions)

These are folded into `profile.toml` + `arch/PROFILE-RATIONALE.md`. Recorded here so S3
inherits them as decided, with the §-pointers, not as fresh guesses.

### P1: peer_id construction — §1.5 canonical-form (hash_type=0x00, raw pubkey), NOT §7.4 SHA-256
**V7 section:** §1.5 canonical-form table (line 459 in `spec-data/v7.75`) + §1.5 `data`
construction (line 3905); §7.4 reconciled via E1 (v7.73) to defer to §1.5; §9.1 floor.
**Status:** PRE-RESOLVED (5th+ spec-first arrival — A-OC-007 / A-ZIG-001 / A-CL-002 /
A-SW-008 / A-JAVA-004; past decisive). Construct Ed25519 peer_id as
`Base58(varint(0x01) || varint(0x00) || public_key)` — `hash_type = 0x00`
identity-multihash, the digest **IS** the raw 32-byte public key. **Verified directly in
`spec-data/v7.75`:** line 459 ("Ed25519 | 0x00 identity-multihash | The digest IS the
public_key (v7.64)") and line 3905 ("`data` is byte-for-byte `bytes([0x01, 0x00]) ||
public_key`"). IGNORE the stale SHA-256 / `hash_type=0x01` form (now only a decode-time
wire-acceptance carve-out, §1.5 Amendment 4 — never a construction form for v7.65+).
**Why it matters:** the S2 corpus uses opaque digests, so a wrong construction passes
S2 green and only fails at the S4 handshake (`401 identity_mismatch`). Built in now.
**Escalation:** arch — already escalated by 5 peers; this is corroboration, no new ask.

### P2: address-space tree-path hex MUST be lowercase (%02x)
**V7 section:** §3.4 / §3.5 (tree-path keys rendered from content_hash hex).
**Status:** PRE-RESOLVED (A-CL-009 — the headline second-cohort defect). Tree paths are
case-sensitive string keys; the Go oracle uses `hex.EncodeToString` (lowercase). C's
`printf("%02x")` is **naturally lowercase**, so C avoids the A-CL-009 uppercase trap by
default — but it is **pinned explicitly** (`[idiom].hex_lowercase = true`; never `%02X`)
so no codec site can regress. **Escalation:** arch already asked to pin lowercase
normatively (A-CL-009); corroboration only.

### P3: §5.2 trichotomy — 401 (authn) / 403 (authz) / 401-unresolvable
**V7 section:** §5.2 + the §5.2a verdict-to-status enumeration (v7.73 E2).
**Status:** PRE-RESOLVED (5-peer convergence; F20 / A-OC-008 / A-SW-010). Request-time
EXECUTE on a non-connect path: author absent -> **401** authentication_failed; capability
absent (author present + signed) -> **403** capability_denied; unresolvable author ->
401. §5.2a is the single source of truth for the (status, code) tuple; build to it.
**Escalation:** arch — §5.2a already absorbed the ruling; no new ask.

### P4: §1.1 entity `data` is an ARBITRARY ECF value, NOT necessarily a map
**V7 section:** §1.1 entity model.
**Status:** PRE-RESOLVED (the A-JAVA-010 silent-500 trap). Model `data` as a **general
ECF value** (any major type — scalar, bytes, array, map) from the start. A map-only model
passes S2/S3 green then returns **500** on the first scalar-`data` entity at the live S4
gate. In C this means the entity struct's `data` field is a generic `ec_ecf_value`
(tagged union over the ECF major types), never a map-typed field. **Escalation:** none —
spec is clear; this is a generation-discipline pre-resolution.

### P5: resource_bounds (§4.10) — 413 oversize / 400 chain_depth_exceeded / 503 flood
**V7 section:** §4.10 (a/b/c); CORE-gating since the v7.75 cycle.
**Status:** PRE-RESOLVED (all 9 peers needed the chain-depth pre-check). r1: oversize
payload -> `413 payload_too_large` or clean close (default **16 MiB**). r2: over-deep
delegation chain -> **`400 chain_depth_exceeded`** — **MUST be 400, NOT 403** (default
depth **64**). S3 builds the ~15-line §4.10(b) **structural pre-check**:
`chain_exceeds_depth(cap, resolve)` walks parents with **NO signature work**, max=64,
**BEFORE** the per-link authz walk; an over-depth self-chain -> 400, an *unreachable*
parent stays 403 (not a depth problem). r3: connection flood -> `503`/close or honest
WARN (SHOULD / external-admission). **Escalation:** none — settled cohort fix.

### P6: §7b concurrency gate is CORE-gating (5/5)
**V7 section:** §4.8 / §4.9 / §6.11 + GUIDE-CONFORMANCE §7b.
**Status:** PRE-RESOLVED (concurrency-gate-7b: all peers green). Data-race-safe store
(§4.8) -> the C peer uses a **`pthread_rwlock_t`** guarding the content store; resilience
under load (§4.9); **no blocking syscalls on a cooperative path** (one thread per
connection sidesteps it); **TCP_NODELAY** mandatory on every connection socket (the Zig
Nagle finding). **Escalation:** none — settled gate.

---

## A-C-001: Ed448 (key_type 0x02) native gap — DEFERRED

**V7 section:** §1.5 key_type table (0x02 Ed448); §7.3 (Ed448 validated v7.67); §8.1.
Crypto-agility *higher bar*, NOT the §9.1 floor.
**Profile field:** `[codec].ed448_library = { name = "DEFERRED", version = "none" }`.
**Your guess:** Defer Ed448 at the profile level. The Ed25519 (`key_type 0x01`) +
SHA-256 (`content_hash_format 0x00`) §9.1 floor is fully native via **libsodium** and is
**unaffected**. libsodium has **no Ed448** (ships Ed25519 + the SHA-2 family + ML-KEM/
SHA-3 as of 1.0.22, but no Ed448 / Ed448-Goldilocks), and there is no minimal audited C
crypto lib that adds it without a heavy dep.
**Rationale:** Same native gap Zig (A-ZIG-002), OCaml (A-OC-002), and Swift (A-SW-001)
hit. Two honest C routes when agility is in scope: (a) **OpenSSL/libcrypto**
(`EVP_PKEY_ED448` + SHA-384) — heavy, broad-surface, fights the minimize-deps stance; or
(b) the **sibling FFI agility path** — `entity-core-codec-ffi-c` (C-ABI v1.1) already
vendored a self-contained openssl curve448 for its Ed448 family, so the peer could link
that sibling C `.a` for the Ed448 family **only** (the OCaml hybrid shape, but C-to-C =
a plain static link, not a foreign bridge). **Default: route (b)** when agility lands —
dependency-lightest. Deferring with a documented escalation beats a silent gap or an
unaudited hand-roll. Does not block the floor.
**Escalation:** research — profile/agility (third+ peer to hit the same Ed448 native
gap; reinforces the cross-peer finding that no minimal native crypto stack covers Ed448.
For C the sibling-FFI-`.a` route is novel — C-to-C static link, not a foreign bridge —
worth recording as the dependency-lightest agility path for a systems-C peer).

---

## A-C-002: spec-data/v7.75 in-file changelog header reads "Version: 7.73" while MANIFEST pins 7.75

**V7 section:** `spec-data/v7.75/ENTITY-CORE-PROTOCOL-V7.md` line 9 (`**Version**: 7.73`)
vs `spec-data/v7.75/MANIFEST.md` (`Spec version: V7 protocol 7.75`).
**Profile field:** `[spec].v7_version_pinned = "7.75"`.
**Your guess:** Treat **MANIFEST.md as authoritative** for the snapshot version (7.75).
The body file is a verbatim byte-for-byte copy whose internal changelog's TOP dated entry
happens to be the 7.73 closeout; the snapshot directory + MANIFEST stamp it 7.75 (the
input version). Profile + peer target **7.75**.
**Rationale:** The snapshot is, by S2 mandate, a verbatim copy — so its in-file header
reflecting an earlier changelog top-entry is a copy artifact, not version skew of the
snapshot. MANIFEST.md is the snapshot's own version declaration. No behavioral
consequence (the codec corpus is byte-stable v7.71->v7.75 either way), but recorded so a
later phase reading the in-file "7.73" header does not think it is on the wrong snapshot.
**Escalation:** research — snapshot-hygiene note (the verbatim body's internal header
could be re-stamped or annotated to match the MANIFEST version on the next snapshot, to
avoid the in-file-vs-MANIFEST mismatch confusing a spec-first reader). Non-blocking,
documentation-only.

---

## A-C-003: §7a/§7b conformance scaffolding is GUIDE-carried, not in v7.75 spec-data

**V7 section:** GUIDE-CONFORMANCE.md §7a (validate handlers) + §7b (concurrency gate) —
NOT in the three normative spec-data files (per the v7.74/v7.75 MANIFEST note).
**Profile field:** `[spec].conformance_scaffolding = "guide-conformance-7a-7b"`.
**Your guess:** The C peer derives its **protocol surface** from `spec-data/v7.75`, but
picks up the **conformance scaffolding** (the `system/validate/{echo,dispatch-outbound}`
handlers behind a `--validate` opt-in, off by default; the §7b store concurrency-safety
gate) from `GUIDE-CONFORMANCE.md` + the keystone generator menu at S3/S4 — not from
spec-data.
**Rationale:** The MANIFEST explicitly flags this split (§7a/§7b live in the
non-normative guide, not the snapshot). A spec-first peer reading only spec-data would
otherwise MISS the conformance handlers and fail S4. Recorded now so S3/S4 pulls them
from the right source.
**Escalation:** research — operator-carried convention; track the standing arch
open-item on whether GUIDE-CONFORMANCE joins the snapshot set (corroborates A-SW-006).

---

## A-C-004: concurrency = pthreads (deliberate S3 decision, recorded so S3 does not re-litigate)

**V7 section:** §4.8 / §4.9 / §6.11 / §7b (the concurrency surface); NOT exercised by the
codec (S2 is pure/synchronous).
**Profile field:** `[concurrency].style = "threaded"`, `primitive = "pthreads"`,
`store_safety = "pthread_rwlock_t"`.
**Your guess:** Use **POSIX pthreads** — one reader thread per connection demuxing
`EXECUTE_RESPONSE` by `request_id` (hashtable -> condvar slot; N7), a `pthread_rwlock_t`
guarding the content store (§4.8 data-race safety), a per-connection `pthread_mutex_t`
write-serializing each shared socket, and `TCP_NODELAY` on every connection socket.
**Rationale:** pthreads is C's portable concurrency primitive — the manual analogue of
the OCaml/Zig/CL/Java stdlib-threads decision (A-OC-003-revised). One-thread-per-
connection satisfies §4.8/§6.11 with no handler-initiated outbound in `--profile core`.
The rwlock (vs a plain mutex) reflects read-dominated dispatch; TCP_NODELAY + no-blocking-
syscall-on-cooperative-path are the inherited §7b findings (P6). A decision, not a spec
gap; recorded so S3 does not silently re-pick the threading model.
**Escalation:** operator — local decision (S3 validates; non-blocking). Mirrors the
prior peers' stdlib-threads sign-off.

---

## A-C-005: codec strategy = native hand-roll (NOT the sibling C FFI codec, though it IS C)

**V7 section:** absent (codec-strategy / library choice; PHASE-S1 codec-strategy matrix).
**Profile field:** `[codec].strategy = "native"`, `cbor_library = "hand-rolled"`.
**Your guess:** Hand-roll the canonical CBOR codec **natively** in the peer (`ecf.c`)
rather than consuming the existing C FFI codec `libentitycore_codec.a` — even though that
FFI codec is itself C and a plain static link would be trivial.
**Rationale:** The C peer's idiom value is **writing** the canonical C codec (breadth: no
prior peer exercises raw manual-memory CBOR), not relinking a pre-built sibling. No C
CBOR library gives ECF canonicality regardless (libcbor DOM/alloc; tinycbor leaves
float-min/tag-reject/CTAP2 to the caller + has version churn; QCBOR determinism is
alpha-only -> fails the S11 stable pin), so a library buys nothing. The sibling FFI `.a`
is kept as a **free byte-for-byte cross-check oracle** at S2/S4, not as the codec. `ffi`
remains the documented fallback if the S2 codec spike fails (not expected).
**Escalation:** operator — local decision (codec-strategy choice within the profile's
authority; non-blocking; the spike at S2 is the cheap insurance).
**S2 outcome:** spike PASSED 20/20 first run (14 float + 6 map_keys),
full corpus 69/69 byte-identical; `ffi` fallback NOT triggered. Native hand-roll stands.

---

## A-C-006: distro `libsodium.a` is not `-fPIC` — the `.so` links shared libsodium, not the static archive

**V7 section:** absent (packaging / linkage; S2 build mechanics).
**Profile field:** `[codec].ed25519_library` (libsodium), `[idiom].no_symbol_leak`
(static + private link goal), `[publishing]` (static + shared lib artifacts).
**Surfaced at:** S2 `make all` — linking the static `libentitycore_*` objects against
`/usr/lib64/libsodium.a` into a shared object fails with
`relocation R_X86_64_PC32 … can not be used when making a shared object; recompile
with -fPIC`. Fedora's `libsodium-static` archive is built WITHOUT `-fPIC`.
**Your guess:** Split the linkage by artifact: the **`.a`** (and the conformance
harness) link the **static** `libsodium.a` (fully self-contained — the profile's
preferred "static + private" shape); the **`.so`** links the **shared** `-lsodium`
(so the peer `.so` carries a runtime dependency on the system `libsodium.so`). Both
build clean; the corpus is byte-identical either way (the same `crypto_sign_*` /
`crypto_hash_sha256`). Documented in the Makefile (`SODIUM_LINK` vs `SODIUM_SO_LINK`).
**Rationale:** The profile's "static + private libsodium, `-fvisibility=hidden` +
symbol localization" goal is fully achievable for the `.a` consumer path (the primary
C artifact) with the distro archive. For a self-contained **`.so`**, the distro
`libsodium.a` is unusable (no `-fPIC`); the honest options are (a) link the shared
libsodium (chosen — simplest, the `.so` declares a normal `libsodium.so` NEEDED), or
(b) build a `-fPIC` libsodium from source to bundle privately (heavier; an S5/release
concern, not a conformance one). The codec gate (the `.a`/harness path) is unaffected.
**Escalation:** research — packaging note for the C peer's S5/publish phase: a release
`.so` that wants a private static libsodium needs a `-fPIC` libsodium build (the
manylinux-style rebuild already flagged for old-glibc portability in the Containerfile
R5 note). Non-blocking for S2/S4; the static-`.a` path meets the self-contained goal.

---

## A-C-007: Go oracle HEAD advanced past the handoff-cited `0d48de6` (provenance note)

**V7 section:** absent (oracle provenance / S2 vendoring mandate).
**Profile field:** `[spec].target_oracle` (`entity-core-go validate-peer`); the S2
prompt's "record the exact go commit" mandate.
**Surfaced at:** S2 conformance vendoring — the handoff cited the read-only Go oracle
as clean at HEAD `0d48de6`. At S2 run time the oracle is clean (0 uncommitted) but HEAD
is **`7e5ab0428a63eb78b981a2000a90e5d4c85e7c79`** (`7e5ab04`, "RELAY cohort handoff"),
with `0d48de6` now its **direct parent**.
**Your guess:** Record BOTH commits in CONFORMANCE-REPORT and proceed. The fixture
producer lineage is the arch byte-lock `23db2546` (per the v7.71 MANIFEST), NOT the live
Go HEAD — `wire-conformance` is a fixture producer, not a runtime checker, and the codec
corpus is byte-stable across the whole v7.56→v7.71→v7.75 window. `7e5ab04` is an
EXTENSION-RELAY handoff that does not touch `core/ecf` or `wire-conformance`. The Go
binary was NOT rebuilt (the self-contained fixture IS the oracle output); the fixture
sha256 was verified against the MANIFEST pin (`41d68d2d…6a052`).
**Rationale:** The vendoring mandate's intent is traceability — pin the exact oracle
state used. The fixture is byte-locked upstream and version-stable, so the live HEAD
delta is provenance-only with zero behavioral consequence at S2. Both commits are
recorded so a later phase is not confused by the moved HEAD.
**Escalation:** operator — provenance bookkeeping (non-blocking; the byte-pinned fixture
is the actual conformance contract). Re-confirm the oracle HEAD at S4 when the live
`validate-peer` binary IS built and run.

---

## A-C-008: Go oracle moved again at S3 (HEAD `57dd0a0`, working tree dirty) — S4-deferred

**V7 section:** absent (oracle provenance / the S2+S3 vendoring mandate).
**Profile field:** `[spec].target_oracle` (`entity-core-go validate-peer`); the S3 prompt's
"vendor the go reference peer, confirm the oracle clean, record the commit" mandate.
**Surfaced at:** S3 — the prompt cited the Go oracle as clean at HEAD `7e5ab04` (the S2
state, A-C-007). At S3 run-time the **read-only** oracle HEAD has advanced to
`57dd0a09ec9371a6b1f04ed57832d46d875d8a35` (`57dd0a0`, "relay R1: entity types per
EXTENSION-RELAY v1.0 post Go pre-impl review"), AND its working tree carries one
uncommitted edit: `core/types/relay.go` (a RELAY *extension* type file).
**Your guess:** Record the moved HEAD + the dirty file, and proceed — the **S3 gate is the
two-C-peer loopback** (the cohort baseline; Java/Zig/CL all run it), which boots a RESPONDER
+ INITIATOR that are **both native C peers** and does NOT need the Go `entity-peer` /
`validate-peer` at runtime. The Go black-box interop (live `validate-peer --profile core`)
is the **S4** concern, and it binds whatever clean Go commit the orchestrator pins at S4 —
NOT the dirty working tree seen here. The oracle was NOT modified (read/vendor-only, per the
confinement rules); the uncommitted `relay.go` is upstream's in-flight RELAY work, off the
`core/ecf` / `validate-peer` / `entity-peer` surface this peer is gated against, so it is
behaviorally irrelevant to both S3 (two-C-peer) and the S4 core gate (`--profile core` skips
RELAY).
**Rationale:** The vendoring mandate's intent is traceability + no-doctoring. At S3 the
thing under test is the C peer talking to *itself* over real TCP; recording the oracle's
exact (moved, dirty) state is the honest provenance entry, and deferring the live-oracle
rebuild to S4 (against a clean pin) is the correct sequencing — building `validate-peer`
off a dirty oracle tree would taint the S4 ground truth, which the no-doctoring rule
forbids. Non-blocking for S3.
**Escalation:** operator — provenance bookkeeping + an S4 pre-condition: **pin a CLEAN Go
oracle commit before the S4 `validate-peer` rebuild** (do not build off the dirty tree).
Corroborates A-C-007 (the oracle HEAD is a moving target across phases; the conformance
contract must pin a specific clean commit, not "HEAD").

**RESOLVED at S4.** The orchestrator pinned the CLEAN commit
**`7e5ab0428a63eb78b981a2000a90e5d4c85e7c79`** ("RELAY cohort handoff") — the
last clean commit on the core surface (≥ the v7.75 re-run baseline `62044c5`; everything
since is RELAY *extension* discovery work off the core gate). The oracle `validate-peer` +
`entity-peer` were built `CGO_ENABLED=0 / GOWORK=off` from a **read-only `git archive`
extract** (NOT a checkout/stash/clean of the oracle tree — the confinement rule honored).
Verified the v7.75 symbols compiled in: `resource_bounds`, `concurrency`,
`validate_echo_dispatch`, `dispatch_outbound_reentry`, `chain_depth_exceeded`,
`payload_too_large`; the stale `core_register_dispatch_roundtrip`/`register_dispatch` symbol
is GONE (replaced by the §7a wire-gate). NOTE for the record: by S4 run-time the oracle HEAD
had advanced to `cbaa64e` and its working tree was CLEAN again (the `relay.go` edit had been
committed upstream) — but the brief's clean pin `7e5ab04` was used regardless for traceable
ground truth. **CLOSED.**

**RE-CERTIFIED at the cohort baseline.** A-C-008's resolution now **pins the
stamped v7.75 cohort baseline `62044c5`** ("v7.75 resource_bounds: cohort 3-way GREEN; arch
fold routing") as the certification oracle — the commit all 9 cohort peers +
`spec-data/v7.75` are certified against, making this peer's number apples-to-apples with the
9-peer matrix. The **oracle was swapped only** (the C peer was NOT rebuilt or modified — same
`entity-peer-c`, same Peer ID `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`): the
`62044c5` `validate-peer` + `entity-peer` were re-built `CGO_ENABLED=0 / GOWORK=off` from a
**read-only `git archive` extract** of `62044c5` (oracle tree never checked-out/stashed/
cleaned; `entity-core-go` HEAD left at `a053670`, untouched), all six v7.75 symbols verified
present, stale symbol gone. **Gate @ `62044c5`: 574 total · 289P/195W/0F/90S → PASS**
(machine-verified `summary.failed == 0`; live count 574·90, NOT the brief's expected 576·89 —
the 2/1 delta is in the oracle's check inventory, not C-peer behavior). origination-core
**3/3** against the `62044c5` `entity-peer` reference. The unchanged peer is **0 FAIL at both
the 574 cohort baseline AND the 631 `7e5ab04` superset → conformance-safe** (Java-peer
precedent). The earlier `7e5ab04` oracle binaries are retained as
`output/s4-oracles/{validate-peer,entity-peer}.7e5ab04` (additional evidence). **CLOSED — now
pinned to cohort baseline `62044c5`.**

**PROVENANCE CORRECTION + RE-CERTIFIED at the TRUE cohort baseline `b30a589` —
⚑ surface to mainline/arch.** The cohort scorecard's "`62044c5`, 576·0F·89S, resource_bounds
PASS" label is **off-by-one-commit**. Verified READ-ONLY from the oracle source:

- `62044c5:cmd/internal/validate/profile.go` `coreProfileCategories` has
  `catConcurrency: true` but **NOT** `catResourceBounds` → `resource_bounds` SKIPs under
  `--profile core` at `62044c5` (→ 574·0F·90S, exactly what this peer scored there).
- The **next commit `b30a589`** ("v7.75: pair §9.0 drift gate post-arch-fold; resource_bounds
  enumerated") adds the line `catResourceBounds: true` → `resource_bounds` becomes an ACTIVE
  core category → **576·0F·89S** (the real recorded cohort number). `b30a589` is clean and an
  ancestor of `7e5ab04`/the later clean commits.

So **`b30a589` is the actual v7.75 cohort oracle** that yields the scorecard's figure; the
recorded "62044c5" is a label off by one commit. **This provenance correction is worth
surfacing to the mainline/arch so the 9-peer scorecard's oracle commit is fixed.**

Re-certification (oracle swap only — C peer NOT rebuilt or modified; same `entity-peer-c`,
same Peer ID `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`): the `b30a589` `validate-peer`
+ `entity-peer` were built `CGO_ENABLED=0 / GOWORK=off` from a **read-only `git archive`
extract** of `b30a589` (oracle tree never checked-out/stashed/cleaned; `entity-core-go` HEAD
untouched). Verified at the binary's **live behavior** that `resource_bounds` is now ACTIVE
under `--profile core` (2 PASS + 1 WARN, 0 SKIP — the `catResourceBounds: true` fold), not a
SKIP. **Gate @ `b30a589`: 576 total · 291P/196W/0F/89S → PASS** (machine-verified
`summary.failed == 0`; live count 576·89 — matching the recorded cohort figure exactly), with
`resource_bounds` **r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3
connection-flood WARN** and `concurrency` 5/5 PASS. origination-core **3/3** (incl.
`dispatch_outbound_reentry`) against the `b30a589` `entity-peer` reference. The same unchanged
peer is **0 FAIL at the 574 subset (`62044c5`), the 576 cohort baseline (`b30a589`), AND the
631 superset (`7e5ab04`) → conformance-safe**. The earlier oracle binaries are retained as
`output/s4-oracles/{validate-peer,entity-peer}.62044c5` (574 subset) and `*.7e5ab04` (631
superset). **CLOSED — now pinned to the TRUE cohort baseline `b30a589`; "62044c5" scorecard
label flagged as off-by-one.**

---

## A-C-009: refcount race under sustained concurrent load — peer crash (S4 fix; ⚑ ARCH-BOUND)

**V7 section:** §4.8 (data-race safety) / §6.11 (concurrent dispatch robustness).
**Surfaced at:** S4 — `validate-peer --profile core` run 1, the `concurrency` category
(`t2_1_sustained_load` / `t2_2_connection_churn`). Under the oracle's sustained C×K load the
peer **crashed** (ASan: `heap-use-after-free in ec_entity_ref`, entity.c). The crash
cascaded: once the host died, every later category that re-dialed got "connection refused" /
"broken pipe" — **22 of the 31 run-1 FAILs were this single crash**, not independent bugs.
**Root cause:** `ec_entity`'s reference count was a plain `int`. Materialized entities are
shared across the per-EXECUTE dispatch threads (one thread per inbound EXECUTE, §4.8); a
plain `refcount++/--` from two threads races → a lost decrement frees a still-referenced
entity → use-after-free. The S3 design note ("refcounted; guarded where shared") was true
for the single-threaded smoke but **not** for the live oracle's concurrent fan-out — the
smoke's 8-way demux exercises one connection's reader, not C×K independent connections
ref'ing the SAME shared store/identity entities.
**Fix (C11-idiomatic, no new dep):** `refcount` → `atomic_int`; `ec_entity_ref` is a relaxed
`atomic_fetch_add`, `ec_entity_unref` an acq/rel `atomic_fetch_sub` (so the last-drop thread
sees all prior writes before it frees). Re-run: `concurrency` 5/5, churn PASS, host stays
ALIVE, ASan-clean. This is the C peer's net-new contribution to the §4.8 conformance picture.
**Escalation:** ⚑ ARCH-BOUND — recommend a §4.8 conformance note that "refcounted shared
entities MUST use atomic (or lock-guarded) refcounts on a multi-threaded peer"; a no-GC
manual-memory peer is the one that surfaces it (the GC'd cohort peers — Java/CL/etc. — never
hit it because the runtime's GC owns object lifetime). Sibling to A-JAVA-010 (a class of
"passes smoke green, breaks under the live §7b/concurrency gate" latent peer bugs).

## A-C-010: nonce was clock-derived (collision → cross-connection replay) — F12 fix

**V7 section:** §4.6 / §6.1 (handshake nonce binding; finding F12).
**Surfaced at:** S4 — `connectivity/handshake_replay_cross_connection`: a valid authenticate
captured on one connection, replayed on another, was ACCEPTED (200). **Root cause:** the
S3 hello issued the challenge nonce from `ec_now_ms()` (a millisecond clock) XOR an index
constant — two connections opened within the same millisecond got the **same** nonce, so
the authenticate check (`echoed == conn->issued_nonce`) passed for a replayed authenticate.
The S3 code even carried a comment admitting the CSPRNG mix was never wired. **Fix:** issue
the 32-byte nonce from the libsodium CSPRNG (`randombytes_buf` via a new `ec_random_bytes`),
making each connection's challenge unique — the replay's echoed nonce now fails the per-
connection check. PASS. **Escalation:** none (a peer bug, spec is clear); recorded as the
F12 surface a clock-nonce peer trips.

## A-C-011: §4.5 negotiation + §1.4 path-validation + §2.6 delegate-501 — S4 gate fixes

**V7 section:** §4.5 (NEGOTIATE-FORMAT/KEYTYPE-1b) / §1.4 R1 (path validation) / §2.6
closeout F1 (delegate same-peer-only) / §6 (handler operations-match).
**Surfaced at:** S4 — five independent core-gate FAILs the S3 peer left, each fixed
spec-first (no oracle doctoring):
- **negotiation (2):** the hello handler never inspected the initiator's advertised
  `hash_formats`/`key_types` — a disjoint accept-set was accepted (200) instead of rejected.
  Fix: reject a non-empty advertisement that excludes our floor → 400
  `incompatible_hash_format` / `unsupported_key_type` (absent/empty = no constraint).
- **handlers (3):** the bootstrap interface entities carried an EMPTY `operations` map; the
  §6 operations-match check wants the op-name keys present (connect→hello/authenticate,
  tree→get/put, capability→request/revoke/configure/delegate). Fix: populate the operations
  map per handler.
- **tree_operations (2):** `path_flex_ok` used `strtok_r`, which collapses consecutive `//`
  so empty segments were never caught; and the embedded-NUL check was a no-op on a C-string
  view. Fix: detect literal `//` before tokenizing, and pass the value-node byte length so an
  embedded-NUL target (raw_len ≠ strlen) is rejected → 400 invalid_path (§1.4 R1).
- **capability (1):** delegate validated `parent` BEFORE the same-peer check, so a remote
  caller got 400 (parent shape) instead of 501. Fix: the §2.6-F1 same-peer-only check moves
  FIRST → 501 unsupported_operation, shape-independent.
**Escalation:** none (peer bugs; spec/closeout-clear). Recorded as the precise S4 grind.

---

## S5 finalization — every item tagged with owner + escalation status

Per the lifecycle S5 §"Spec-ambiguity-log finalization": all S1–S5 A-C-* items are resolved-in-peer
and routed; **none block release**. The arch escalation bundle (consolidated table also in
`ARCHITECTURE-REVIEW.md` Part D):

| Item | Severity | Owner | Escalation status |
|---|---|---|---|
| **A-C-009** §4.8 shared-entity refcount MUST be atomic/lock-guarded under concurrency | **⚑ ARCH-BOUND** | **arch** | **OPEN ⚑** — NEW (behavioral; the cohort's only §4.8 finding). Resolved in-peer (`atomic_int`); recommend a §4.8 conformance note. Sibling to A-JAVA-010. Only a no-GC manual-memory peer surfaces it. |
| **A-C-008** cohort scorecard oracle label `62044c5` is off-by-one; `b30a589` is the true v7.75 oracle | **⚑ provenance** | **mainline/arch** | **OPEN ⚑** — verified read-only; 0-FAIL at the 574 subset / 576 baseline / 631 superset → conformance-safe. Correct the recorded cohort oracle commit to `b30a589`. THE handoff item (PHASE-S5 §6). |
| **A-C-006** Fedora `libsodium.a` not `-fPIC` → self-contained `.so` needs a `-fPIC` libsodium build | packaging | **research/packaging** | OPEN (non-blocking) — the one C-specific S5/publish work item; the `.a` path is already self-contained. |
| **A-C-010** clock-derived nonce → cross-connection replay (F12) | resolved | peer | **RESOLVED** (CSPRNG nonce via `ec_random_bytes`). Recorded as the F12 surface a clock-nonce peer trips. |
| **A-C-011** §4.5 negotiation / §1.4 path validation / §2.6 delegate-501 / §6 ops-match | resolved | peer | **RESOLVED** (peer bugs, spec/closeout-clear) — the precise S4 grind. |
| **A-C-001** Ed448 (key_type 0x02) native gap | deferred | **research/agility** | **DEFERRED** — 3rd+ peer to hit it; sibling-FFI-`.a` route (C-to-C static link) novel for C. Does NOT affect the §9.1 floor (Ed25519 + SHA-256, 69/69 byte-green). |
| **A-C-002** spec-data/v7.75 in-file header reads "7.73" while MANIFEST pins 7.75 | note | research | OPEN (documentation-only, non-blocking) — MANIFEST authoritative; snapshot-hygiene note. |
| **A-C-003** §7a/§7b conformance scaffolding is GUIDE-carried, not in v7.75 spec-data | note | research | OPEN (operator-carried convention) — tracks the standing arch open-item (corroborates A-SW-006). |
| **A-C-007** Go oracle HEAD advanced past the handoff-cited commit (provenance) | note | operator | RESOLVED-at-S4 sequencing (a clean commit pinned for the S4 rebuild); provenance bookkeeping, non-blocking. |
| **A-C-004** concurrency = pthreads | local decision | operator | **RESOLVED** (S3 validated; mirrors the cohort's stdlib-threads sign-off). |
| **A-C-005** codec strategy = native hand-roll (not the sibling C FFI codec) | local decision | operator | **RESOLVED** (S2 spike passed 20/20; full corpus 69/69; `ffi` fallback not triggered). |
| **PRE-RESOLVED P1** peer-id §1.5-canonical-vs-§7.4-SHA-256 | corroboration | arch | Built to §1.5 from the start; **5th+ spec-first corroboration** (A-OC-007/A-ZIG-001/A-CL-002/A-SW-008/A-JAVA-004) — no new ask, corroboration from the most-distant memory idiom. |
| **PRE-RESOLVED P2–P6** hex-case / §5.2 401-403 / A-JAVA-010 data-shape / §4.10 resource_bounds / §7b concurrency | corroboration | arch | Inherited-settled cohort convergence; built in from the start so S2/S3 did not re-burn them. Corroboration only. |

**Finalization verdict:** two ⚑ arch-routed items (A-C-009 §4.8 atomic-refcount + A-C-008 oracle
off-by-one), one packaging item (A-C-006), the rest resolved/deferred/notes with named owners.
**No blocking item at any phase exit.** S5 ambiguity log finalized.
