# entity-core-protocol-python — Spec Ambiguity Log

Every guess made while authoring the Python peer goes here (S3 discipline: **no
silent guesses**). Most entries below are **S1 profile-level** decisions (library /
pin / packaging guesses), not spec-semantics findings — Python is a same-as-sibling
adoption peer (clean-room clone of `entity-core-py`) and the spec-discovery well is
dry per the 8-peer synthesis, so no net-new spec ambiguity surfaced at S1. Spec-
semantics entries (if any) would arise at S2/S3 against `spec-data/v7.75`.

Format per `PROMPT-CONSTANTS.md` §"Ambiguity-log discipline".

---

## A-PY-001: No Python CBOR library delivers the ECF canonical contract

**V7 section:** ENTITY-CBOR-ENCODING Rules 1–5, §6.3 (tag rejection); N1–N4
**Profile field:** `[codec].cbor_library`
**Your guess:** Hand-roll the canonical CBOR encoder/decoder (`entity_core/_cbor.py`);
do NOT use `cbor2` (or any Python CBOR lib) for the core codec.
**Rationale:** `cbor2` is the de-facto Python CBOR library and offers
`dumps(obj, canonical=True)`, but that mode targets **RFC-8949 §4.2 bytewise** map-key
ordering — the WRONG order for ECF, which requires **length-then-lexicographic on the
ENCODED key bytes** (RFC-7049 length-first). cbor2 also does not minimize floats on
DECODE (Rule 4 on receive), does not recursively reject major-type-6 tags on decode
(§6.3 → `400 non_canonical_ecf`; it decodes tags into objects), and does not guarantee
raw-byte `data` fidelity (N4). Every prior native peer (C#/TS/OCaml/Elixir/Zig/CL/
Swift/Haskell/Java/Go/Ruby + the 2 spec-first) independently hit this same A-005
pattern — the canonical layer must be owned regardless. **NOT a spec ambiguity** — the
spec is unambiguous; this is a library-survey guess. **Resolution gate:** prove cbor2
reproduces the `map_keys.*` / `float.*` / `tag_reject.*` corpus byte-for-byte AND
enforces decode-side rejection before any future swap — at which point it equals the
hand-roll. Spike at S2 start.
**Escalation:** operator — local decision (profile authorizes hand-rolled; no arch
action). Recorded for the S2 codec spike.

---

## A-PY-002: cryptography's bundled OpenSSL must enable Ed448 (native-full-agility)

**V7 section:** §1.5 `key_type 0x02` (Ed448); §7.x crypto-agility; KEY-TYPE-ED448-*
agility corpus
**Profile field:** `[codec].ed448_library`
**Your guess:** Source Ed448 NATIVELY from the same `cryptography` library
(`ed448.Ed448PrivateKey`), placing Python in the native-full-agility class (Haskell/
Ruby), NOT the hybrid-FFI class (OCaml/Zig/Go).
**Rationale:** `cryptography` exposes Ed448 (57-byte seed, 114-byte sig, PureEdDSA)
through the identical raw-key surface as Ed25519, and its manylinux wheels (+ fedora
system OpenSSL 3.x) bundle OpenSSL 3.5.x which builds Ed448. So no FFI / no second
crypto source is needed — strictly better than PyNaCl (Ed25519-only, would force
hybrid-FFI). **Risk:** a bundled OpenSSL build *could* omit Ed448 (FIPS-restricted or
trimmed builds). **Mitigation:** the `containers/python-toolchain/Containerfile` build
asserts an Ed448 sign/verify/tamper-reject round-trip and FAILS the image build if
absent; the agility corpus is byte-verified at S2. If a target OpenSSL lacks Ed448,
fall back to hybrid-FFI Ed448 via `libentitycore_codec` (the OCaml A-OC-002 shape) —
documented escalation, not a silent gap.
**Escalation:** operator — local decision; verified at container-build + S2.

---

## A-PY-003: Exact `cryptography` raw-key API spelling (confirm in-container)

**V7 section:** §7.3 (Ed25519 keygen/sign/verify); §3.x (peer identity from raw key)
**Profile field:** `[codec].ed25519_library`
**Your guess:** Use `Ed25519PrivateKey.from_private_bytes(seed32)` /
`.sign(msg)` / `.public_key().verify(sig, msg)` / `.private_bytes_raw()` /
`.public_key().public_bytes_raw()`; entity-core PEM = base64 of a 32-byte seed.
**Rationale:** these are the documented `cryptography` APIs since v35 (raw-key
methods) and v2.6 (EdDSA); we pin 48.0.0. Ed25519 is deterministic (RFC-8032) so the
version is conformance-neutral. **Risk:** minor API spelling drift / a
`serialization`-encoding-flag requirement on `private_bytes_raw`. **Mitigation:**
confirm the exact spelling + raw-key availability in-container at S2 (a one-line
round-trip), as the Ruby peer did (A-RUBY-003).
**Escalation:** operator — local decision; verified at S2.

---

## A-PY-004: CPython 3.13.14 pin is < 30 days old (distro-channel relaxation)

**V7 section:** absent (toolchain pin, not spec)
**Profile field:** `[deps].python`, `[container]`
**Your guess:** Pin CPython **3.13.14** (fedora:43 `python3`),
accepting any 3.13.x stable patch fedora:43 ships.
**Rationale:** 3.13.14 as a *patch* is < 30 days old,
which the strict S11 ≥30-day cool-down would flag. BUT (a) the **3.13.x series** is
long-stable (3.13.0 = 2024-10, ~20 months), so the patch is a settled maintenance
release in a mature line, and (b) the toolchain arrives via the **fedora:43 distro
channel — a reviewed channel**, for which the supply-chain memo relaxes the age floor
to "pin exactly for reproducibility" (exactly the Go `golang-1.25.10` precedent).
Contrast the one PyPI **library** dep `cryptography==48.0.0`, which is held to the
strict ≥30-day rule (and pinned at the newest version that clears it). The container
asserts the resolved Python is 3.13.x.
**Escalation:** operator — local decision (distro-channel relaxation, logged for
transparency per S11 "CVE-forced/age exceptions are explicit and logged").

---

## A-PY-005: PEP 440 version = final `0.1.0` (not a pre-release suffix)

**V7 section:** absent (packaging, not spec)
**Profile field:** `[publishing].version`
**Your guess:** Publish at PEP-440 **`0.1.0`** (a final 0.x release), NOT a pre-release
tag like `0.1.0rc1` / `0.1.0-pre`.
**Rationale:** The cohort parks first publishes at "0.1.0-pre"-style markers (OCaml/
Elixir). But PEP 440 pre-releases (`rc`/`a`/`b`/`.dev`) are **excluded by default** by
`pip install` — so a `0.1.0rc1` would not install without `--pre`, undercutting the
ADOPTION goal that is this peer's headline value. A bare `0.1.0` already signals "early,
pre-1.0, no API-stability promise" via the SemVer 0-major, WITHOUT the installer-
resolution surprise. So the PEP-440-correct spelling of "0.x early peer, installable by
default" is the final `0.1.0`.
**Escalation:** operator — local decision (packaging convention; revisit if a true RC
gate is wanted before 0.1.0).

---

## A-PY-006: Dist name kept as `entity-core-protocol-python` (full keystone id)

**V7 section:** absent (packaging, not spec)
**Profile field:** `[publishing].package_id`
**Your guess:** Keep the PyPI dist name = `entity-core-protocol-python` (the full
keystone peer id), with the import package `entity_core`.
**Rationale:** PyPI normalizes dist names (PEP 503), and unlike Ruby/Elixir — which
dropped the redundant `-ruby`/`_elixir` because a gem/hex package is language-implicit
— here the *import package* `entity_core` already carries the language-implicitness, so
keeping the full keystone id on the dist name is unambiguous and useful (and matches
the keystone naming directly). **Risk:** name squatting on PyPI.
**Mitigation:** check availability at S5 before first publish; fall back to a variant
if taken.
**Escalation:** operator — local decision; availability checked at S5.

---

## A-PY-007: Threading (not asyncio) for the §7b concurrency floor

**V7 section:** §4.8 store-safety, §4.9 resilience, §6.11 reentrancy (v7.75 floor,
gated under §7b)
**Profile field:** `[async].style`, `[async].store_safety`
**Your guess:** Thread-per-connection (`threading`) with a `Lock`/`RLock`-guarded
shared store + `Condition`-based §6.11 reentrant demux; NOT asyncio.
**Rationale:** the peer is IO-bound; CPython releases the GIL during blocking socket IO
and inside the `cryptography`/`hashlib` C extensions, so thread-per-connection is
genuinely concurrent for this workload and clears §7b without asyncio's async-coloring
of the sync codec/crypto APIs (and matches the cohort reader-thread + condvar shape:
OCaml/Ruby). The GIL does NOT make compound read-then-write atomic (and the free-
threaded build has no GIL), so explicit `Lock`-guarding of the §4.8 store is mandatory
(the Ruby GVL trap). TCP_NODELAY set on every socket (Zig §7b lesson).
**Escalation:** operator — local decision (profile authorizes the concurrency idiom).
Recorded for S3.

---

## A-PY-008: fedora:43 ships CPython 3.14.5 at S2 build (not the 3.13.x S1 assumed)

**V7 section:** absent (toolchain pin, not spec)
**Profile field:** `[deps].python`, `[container]`
**Your guess (S2 resolution):** Accept CPython **3.14.5** as the in-container
interpreter (the fedora:43 distro channel resolved to 3.14.5 at S2 build time, not
the 3.13.14 the S1 profile assumed), and widen the Containerfile version assert to
accept `3.13.x OR 3.14.x`.
**Rationale:** 3.14 is a stable CPython release. The codec is deterministic and the
only behavioural surfaces it touches — `cryptography` raw-key APIs, `hashlib`,
`struct`, arbitrary-precision `int` — are stable across 3.13→3.14, so the minor
version is **conformance-neutral** (verified: 69/69 wire-conformance + the Ed448
agility byte-pin all PASS under 3.14.5). Distro-channel relaxation (S11 supply-chain
memo) applies as for A-PY-004: pin exactly for reproducibility, accept whatever the
reviewed fedora:43 channel ships. The profile's `[deps].python = 3.13.14` is now a
stale *intent*; the realized pin is 3.14.5 (fedora:43 digest-pinned in the
Containerfile). Non-blocking — a transparency log entry, no behaviour change.
**Escalation:** operator — local decision (distro-channel version drift, logged).

---

## A-PY-002 (RESOLVED at S2): Ed448 native via cryptography — byte-verified

**Resolution:** CONFIRMED native-full-agility. The `cryptography` 48.0.0 bundled
OpenSSL exposes Ed448 through `Ed448PrivateKey.from_private_bytes / sign /
public_key().verify / private_bytes_raw / public_bytes_raw`. Byte-verified against
the v7.71 agility corpus pin `KEY-TYPE-ED448-1` (seed `0x42`×57): 57-byte pubkey,
114-byte signature, and the Base58 `peer_id` all byte-match; verify + tamper-reject
OK. No FFI, no second crypto source (the Haskell/Ruby result). The container build
also hard-asserts Ed25519+Ed448 at image-build time. Risk retired.

---

## A-PY-003 (RESOLVED at S2): cryptography raw-key API spelling confirmed

**Resolution:** CONFIRMED in-container. `Ed25519PrivateKey.from_private_bytes(seed32)`
/ `.sign(msg)` / `.public_key().verify(sig, msg)` / `.private_bytes_raw()` (32 B) /
`.public_key().public_bytes_raw()` (32 B) all work as the profile declared, no
serialization-flag detour. Identical shape for `Ed448PrivateKey` (57-byte seed,
114-byte sig). Ed25519 deterministic (RFC 8032) → version-neutral; the 3
`signature.*` conformance vectors reproduce byte-exactly. Risk retired.

---

## A-PY-009: `host.py --name` keypair file format (S3)

**V7 section:** absent (host CLI / operator convention, not spec)
**Profile field:** `[bootstrap].persistent_identity` (`--name NAME`)
**Your guess:** Load the Ed25519 identity for `--name NAME` from
`~/.entity/peers/NAME/keypair`, where the file content is **base64 of a 32-byte
seed** (the entity-core PEM convention named in the profile + prompt); tolerate
PEM armor (`-----BEGIN/END-----` lines stripped) if present.
**Rationale:** the profile `[bootstrap]` block and the prompt both pin "PEM =
base64 of a 32-byte seed" and the `~/.entity/peers/NAME/keypair` path (the Go
entity-peer / peer-manager + cohort `--name` standardization). The
exact on-disk wrapping (bare base64 vs PEM armor) is not spec'd, so the loader
accepts both and validates the decoded seed is exactly 32 bytes (errors loudly
otherwise). Enables the multisig accept-path + a stable cross-run identity for
S4 without env-skip.
**Escalation:** operator — local decision (host CLI convention).

---

## A-PY-010: S3 test runner is a stdlib zero-dep runner (offline core image)

**V7 section:** absent (test-harness mechanics, not spec)
**Profile field:** `[testing].framework = pytest` (dev-only) /
`standalone_runner`
**Your guess:** Drive the S3 peer suites (`tests/peer/test_*.py`) with a stdlib
zero-dep runner (`tests/peer/_run.py`) under `PYTHONPATH=src`, because the
offline `python-toolchain` core image ships **no pytest / no hatchling** (they
are dev-only deps; the core image carries only the one runtime dep
`cryptography`, per `[container].network_policy = pull-once-then-offline`).
**Rationale:** the test files are written as plain-`assert` pytest functions, so
they run unmodified under either pytest (a dev layer with network on) OR the
stdlib runner (offline). This honors the profile's named fallback ("stdlib
`unittest` is the zero-dep fallback if pytest is ever disallowed") AND keeps the
S3 gate reproducible inside the `--network=none` dev-loop without adding a
network step or a second dep to the core image. The S2 wire-conformance harness
is already structured the same way (a runnable `harness.py`, no pytest needed).
**Escalation:** operator — local decision (harness mechanics; a dev-deps layer
that installs pytest is the S5 increment).

---

_No NEW spec-semantics ambiguities surfaced at S2 (expected: same-as-sibling adoption
peer, dry discovery well). The codec is byte-identical to the cross-blessed corpus AND
the Go oracle (e8524ed); every encoding/hash/sign/peer-id decision was already pinned
by the unambiguous spec + the conformance fixture. A-PY-008 is the only new entry and
is a toolchain-pin transparency note, not a spec gap. Add `A-PY-NNN` entries here if
the peer machinery (S3) surfaces a genuine spec gap against the v7.75 snapshot — those
are the high-signal class that escalate to arch as proposal candidates
(research/stewardship/), though the well is expected dry for a same-as-sibling peer._
