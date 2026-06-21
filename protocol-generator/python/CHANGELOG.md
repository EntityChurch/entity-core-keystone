# Changelog — entity-core-protocol-python

All notable changes to this peer. Spec-version tracked literally per the keystone
lifecycle (S5 §Version-pin). Format loosely follows Keep a Changelog; versions follow
[PEP 440](https://peps.python.org/pep-0440/) / SemVer-0.x.

> **Version-spelling note (A-PY-005).** The cohort writes its first release line as
> `0.1.0-pre` in prose. Python's installer, however, **excludes PEP 440 pre-releases
> (`rc`/`a`/`b`/`.dev`) by default** — a `0.1.0rc1` would not install via
> `pip install entity-core-protocol-python` without `--pre`, undercutting the adoption
> goal that is this peer's headline value. A bare **`0.1.0`** already signals "early,
> pre-1.0, no API-stability promise" via the SemVer 0-major *without* the installer-
> resolution surprise, so the PyPI coordinate is the final **`0.1.0`**. See
> `status/SPEC-AMBIGUITY-LOG.md` A-PY-005. (The Ruby/CL `.pre`/dotted-version wrinkle
> does not apply: PEP 440 accepts the bare `0.1.0` cleanly.)

## [0.1.0]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.75** (the COMPLETE ratified snapshot —
the §6.13 register / §6.9a owner-cap / §7a peer surface AND the §4.8 store-safety /
§4.9 resilience / §4.10 resource_bounds substrate floor are all present as ratified
text, so this peer carries no snapshot-lag caveat). Codec corpus pinned at the
`conformance-vectors-v1` fixture; encodings byte-identical across the snapshot window.

First release line. The Python (CPython) core-protocol peer, derived **clean-room** from
the V7 specification (the hand-written sibling `entity-core-py` was **not** opened, read,
or referenced while authoring it). Not yet published — parked at `0.1.0` pending
architecture v0.1 sign-off + the PyPI-name availability check (A-PY-006). PyPI dist name
`entity-core-protocol-python`; import package `entity_core`.

### Conformance
- `validate-peer --profile core`: **PASS** — 665 total / 292P / 268W / **0F** / 93S
  (machine-verified `summary.failed == 0` AND `total == 665`), oracle
  `entity-core-go @e8524ed`. All 16 core categories 0-FAIL. Recorded as **665·0F @ e8524ed**.
- Codec (S2): **69/69** byte-identical to `conformance-vectors-v1`, first full run,
  0 codec fixes. Re-ran GREEN at S5 via the stdlib zero-dep runner.
- multisig: **11/11 · 0 skip**, including `valid_2of3_peer_signed_accepted` (genuine
  K-of-N ACCEPT path, not env-skipped — host launched `--name conformance`).
- origination-core: **3/3** over real two-peer TCP (`reference_connect` ·
  `reference_ready` · `dispatch_outbound_reentry` — the §6.11 reentry seam wire-proven
  against a Go reference peer).
- §9.5 53-type registry: **53/53** byte-identical (content_hash recomputed by the
  Python codec, asserted equal to the Go reference @e8524ed — not ingested).

### Added
- Hand-rolled canonical-CBOR (Entity Canonical Form, ECF) codec (`_cbor.py`): shortest-
  float minimization (f16 ⊂ f32 ⊂ f64), length-then-lexicographic map-key sort on the
  ENCODED key bytes (RFC-7049 length-first — **not** `cbor2 canonical=True`, which is
  RFC-8949 bytewise and wrong for ECF; A-PY-001), recursive major-type-6 tag rejection
  on decode (§6.3 → `400 non_canonical_ecf`), full 0..2⁶⁴−1 head-form integer range.
  CPython's **arbitrary-precision `int`** carries the full u64 range with **no native-int
  trap** (the BEAM/Ruby result, replicated — the head form is selected explicitly per the
  major-type head, never delegated to Python's unbounded int). Wire bytes are `bytes`/
  `bytearray`/`memoryview` throughout — never `str` in the codec core.
- Hand-rolled Base58 (Bitcoin alphabet, `_base58.py`) + multicodec LEB128 varint
  (`_varint.py`) — neither warranted a third-party package.
- **Ed25519 AND Ed448 sign/verify + SHA-256/384 native via `cryptography`** (one runtime
  dep; bundled OpenSSL 3.5.x). The generic raw-key EdDSA surface
  (`Ed{25519,448}PrivateKey.from_private_bytes / sign / public_key().verify /
  private_bytes_raw / public_bytes_raw`) reaches BOTH curve families — **native-full-
  agility, no FFI, no second crypto source** (the Haskell/Ruby class; A-PY-002 confirmed,
  byte-verified vs the v7.71 `KEY-TYPE-ED448-1` pin: 57-byte pubkey, 114-byte signature,
  Base58 peer_id all byte-match; tamper-reject OK). The container build hard-asserts both
  curves at image-build time.
- §1.5 canonical-form peer_id construction (Base58 of `varint(key_type) ||
  varint(hash_type) || digest`), lowercase hex everywhere (dodges the A-CL-009 trap).
- §1.1 entity `data` modeled as an **arbitrary ECF value, not necessarily a `dict`**
  (A-JAVA-010 — duck-typed: `data` is "whatever ECF value decodes").
- §4.1 handshake (three-check PoP), §6.5/§6.6 dispatch ladder, capability authorization
  with chain attenuation + §5.7 delegation caveats + the §4.10(b) max-chain-depth (64)
  pre-check returning **400 `chain_depth_exceeded`**, type registry (53/53), in-memory
  address-space store with §3.9 CAS, the §6.13 register / §6.9a owner-cap / §7a
  conformance surface, CORE-TREE get/put/CAS/delete.
- §4.6 / §7.1 crypto-agility hardening: an `authenticate` carrying a `peer_id` whose
  embedded `key_type` is not Ed25519 returns **400 `unsupported_key_type`** BEFORE the
  identity binding (the AGILITY-UNKNOWN-1 vector; arrived at clean-room from the spec —
  a clean §4.6 requirement, not a guess; see PHASE-S4 §iteration-2).
- §4.10 resource_bounds: 413 `payload_too_large` (16 MiB) MUST + 400
  `chain_depth_exceeded` MUST; the connection-flood SHOULD is a WARN, not a core MUST.
- §5.2 / §5.2a request verification as a three-way verdict (ALLOW / unauthenticated→401 /
  authenticated-but-unauthorized→403 / unresolvable-identity→401).
- Error model: an `EntityCoreError`-rooted exception lattice (`CodecError`,
  `ProtocolError`, `TransportError`, …) — the Python exception idiom; protocol status is
  carried as a **value, never across an exception** (the cohort status-as-value invariant).
- Concurrency (A-PY-007, the GIL seam): **thread-per-connection** (`threading`) — a reader
  thread per socket, a thread per inbound EXECUTE, a `pending {request_id => Condition}`
  map for the §6.11 reentrant demux, a `Lock`/`RLock`-guarded §4.8 store, `TCP_NODELAY` on
  every socket. CPython releases the GIL on blocking IO + inside the `cryptography`/
  `hashlib` C extensions, so the IO-bound peer is genuinely concurrent; the GIL does NOT
  make compound read-then-write atomic (and the free-threaded build has no GIL), so the
  store lock is load-bearing. NOT asyncio (avoids async-coloring the sync codec/crypto).
- Standalone host / oracle driver (`entity_core.host`, console-script `entity-core-peer`):
  `--name` / `--port` / `--seed` / `--validate`; emits `LISTENING <port>`.

### Known limitations
- **PyPI publishing deferred** — operator action after arch v0.1 sign-off. The dist name
  `entity-core-protocol-python` (A-PY-006) must be confirmed non-squatted at first publish;
  fall back to a variant if taken. No auto-tag, no `twine upload`.
- Crypto-agility **full MATRIX** (the M2/M3/M6 key-type × hash-format cross-product
  end-to-end harness) is a cohort-wide deferral; the primitives (Ed448 + SHA-384) AND the
  cap-token shapes are S2-byte-proven, but the full agility matrix harness is not wired.
  Does NOT affect the §9.1 floor (Ed25519 + SHA-256, 69/69 byte-green) nor the connect-path
  agility slice (`crypto_agility` 4/4 · 0F, incl. the Ed448 key_type).
- Public API surface is documented (README §Use, the `entity_core` `__all__` Tier 1 +
  `entity_core.peer` Tier 2), not yet frozen with an explicit semver lock — leading-
  underscore modules (`_cbor`/`_base58`/`_varint`) signal "internal, may churn"; a hard
  freeze is a publish-prep / first-consumer pass (the cohort `.mli`/`internal/` analogue).
- `repository_url` (`[project.urls]`) is unset until first publish (A-PY-006).

### Toolchain pins (S11)
- **CPython 3.14.5** in-container (fedora:43 distro channel — a reviewed channel; the
  S11 ≥30-day age floor relaxes to "pin exactly for reproducibility"; A-PY-004/008). The
  S1 profile assumed 3.13.x; fedora:43 resolved to 3.14.5 at S2 build — conformance-neutral
  (codec deterministic; raw-key / hashlib / struct / arbitrary-int APIs stable 3.13→3.14;
  verified 69/69 + Ed448 byte-pin under 3.14.5). Floor `requires-python >= 3.9`.
- **cryptography 48.0.0** — the ONLY runtime dependency; clears the
  S11 ≥30-day cool-down (48.0.1/49.0.0 were too new to pin), wheel HASH-pinned in
  `requirements.txt` (`--require-hashes`). Bundled OpenSSL 3.5.x → Ed25519 + Ed448 + SHA-2.
- **pytest / ruff / mypy** — dev-only (the `[dev]` extra), NOT runtime deps. The offline
  core image carries only `cryptography`; the S2/S3 gates run under a stdlib zero-dep
  runner (A-PY-010), so the codec 69/69 gate needs no third-party test framework.

### Spec items surfaced (routed to architecture / operator)
- **No NEW spec-level defect. The well is dry** (expected for a same-as-sibling adoption
  peer per the 8-peer synthesis): Python read the COMPLETE v7.75 snapshot and the §4.6
  crypto-agility requirement straight from the spec + the AGILITY-UNKNOWN-1 vector, and
  **corroborated** the inherited cohort findings (peer-id §1.5, 401/403 §5.2a, §4.10
  resource_bounds, A-JAVA-010 data-shape) **live against the oracle** rather than
  re-litigating them. The contribution is an **independent adoption cross-check +
  generator-independence evidence** (a clean-room Python peer byte-agrees with the Go
  oracle) — not novel spec discovery.
- **A-PY-001/-007/-009/-010** (RESOLVED, operator) — hand-rolled codec / threading
  concurrency / `--name` keypair format / stdlib zero-dep test runner.
- **A-PY-002** (RESOLVED) — Ed448 native via cryptography, byte-verified (native-full-
  agility confirmed). **A-PY-003** (RESOLVED) — raw-key API spelling confirmed in-container.
- **A-PY-004/-008** (operator/research) — CPython distro-channel version drift
  (3.13.14 intent → 3.14.5 realized), transparency note, non-blocking.
- **A-PY-005** PEP 440 version = final `0.1.0` (pip excludes pre-releases by default) —
  operator (packaging convention).
- **A-PY-006** PyPI dist name `entity-core-protocol-python` confirm-non-squatted —
  operator (S5 registry step).
