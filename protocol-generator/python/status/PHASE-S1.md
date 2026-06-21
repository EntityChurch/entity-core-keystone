# Phase S1 — Python peer — Summary

**Peer:** `entity-core-protocol-python` (CPython) — clean-room clone of the hand-
written sibling `entity-core-py` (the Go situation: same-as-sibling peer, value =
independence + adoption, NOT spec discovery).
**Branch:** `lang/python` (worktree). **Phase:** S1 (profile
research + authoring). **NO podman / NO build / NO toolchain run** (S1 boundary).
**Spec read:** `spec-data/v7.75` (complete SHA-pinned V7 snapshot; full body present —
no snapshot-lag caveat, like Ruby/Go).

## Exit criteria — met

- [x] `protocol-generator/python/profile.toml` — every field populated, **no `TBD`**.
- [x] `protocol-generator/python/arch/PROFILE-RATIONALE.md` — written (one section per
      major choice + clean-room discipline + adoption/independence framing).
- [x] `containers/python-toolchain/Containerfile` — **authored** (fedora:43 base, S1;
      pinned, NOT built; build-time Ed25519+Ed448 assertion baked in).
- [x] `protocol-generator/python/status/SPEC-AMBIGUITY-LOG.md` — initialized; 7 entries
      (all S1 library/pin/packaging/concurrency guesses; **no spec-semantics gap** at
      S1 — well dry for a same-as-sibling peer).
- [x] `protocol-generator/python/status/PHASE-S1.md` — this file.

## Profile decisions (the headline calls)

| Axis | Decision | Why |
|---|---|---|
| **Codec strategy** | `native` | A-005 holds 13th time — own the canonical layer regardless of library |
| **CBOR** | hand-rolled (`_cbor.py`); cbor2 **rejected** | cbor2 `canonical=True` = RFC-8949 **bytewise** (WRONG order; ECF = length-first) + no decode-side float-min / tag-6-reject (A-PY-001) |
| **Crypto** | `cryptography` 48.0.0 — **native-full-agility** | Ed25519 **AND Ed448** + SHA-2 all native (OpenSSL backend); the Haskell/Ruby result, NOT hybrid-FFI. PyNaCl rejected (Ed25519-only) |
| **Agility posture** | Ed25519 + SHA-256 floor; **Ed448 + SHA-384 NATIVE** | same `cryptography` surface; no FFI, no opt-in sub-lib (contrast OCaml/Zig/Go DEFERRED). A-PY-002 verifies bundled OpenSSL ships Ed448 (container assert + S2 byte-pin) |
| **SHA-256/384** | stdlib `hashlib` | native, OpenSSL-backed, zero-dep |
| **base58 / varint** | hand-rolled | small; keeps single-runtime-dep story |
| **Error model** | **exceptions** — `EntityCoreError(Exception)` tree | Python idiom; `Exception`-rooted (not `BaseException`) = Ruby `StandardError` analogue; shape mirrors C#/TS/Ruby |
| **Concurrency** | **threading** (thread-per-connection) + `Lock`-guarded store + `Condition` demux | IO-bound; GIL released on blocking IO + crypto C-ext → adequate for §7b without asyncio. GIL ≠ compound-atomic → explicit Lock mandatory (A-PY-007). TCP_NODELAY everywhere |
| **Integers** | native arbitrary-precision `int` — **no head-form carrier trap** | BEAM/Ruby result, 3rd such peer; but explicit shortest-head-form selection still required on encode + non-shortest reject on decode |
| **Bytes** | `bytes`/`bytearray`/`memoryview`, never `str` | Ruby ASCII-8BIT / TS Uint8Array discipline |
| **Naming** | PEP 8 — `snake_case` funcs/vars/modules, `PascalCase` classes, `SCREAMING_SNAKE` consts | |
| **Build / layout** | `pyproject.toml` + **hatchling**, **src-layout**, no setup.py | modern PEP 517/518; src-layout dodges import-shadowing |
| **Test** | **pytest** (dev-only dep) | de-facto standard; runtime deps unaffected (core ships ONE runtime dep) |
| **Packaging** | PyPI; dist `entity-core-protocol-python`, import `entity_core`; **version `0.1.0`** | PEP 440: final `0.1.0` (NOT `0.1.0rc1`) — pre-releases are pip-excluded by default → would break adoption (A-PY-005). Full keystone id on dist name (A-PY-006) |
| **License** | **Apache-2.0** | S9 default (Python ecosystem mixed, no mandate) |

## Container pin choices (S11 ≥30-day rule)

| Pin | Version | Age | S11 status |
|---|---|---|---|
| **cryptography** (only runtime dep) | **48.0.0** | **44 days** | ✅ clears the floor; the **newest** that does (48.0.1 / 49.0.0 are < 30 days → rejected). Carries CVE-2026-39892 + CVE-2026-34073 fixes forward; OpenSSL 3.5.x wheels |
| **CPython** (fedora:43 distro) | 3.13.14 | < 30 days (patch) | ⚠️ A-PY-004 — distro-channel relaxation: 3.13.x series long-stable (3.13.0 = 2024-10), reviewed channel → "pin exactly for repro" (Go `golang-1.25.10` precedent); any 3.13.x patch accepted |
| **fedora:43** base | tag (digest at S2) | — | — | reviewed distro base; digest pinned at first build (S2 lock-step) |

**Dev-only tools** (pytest / ruff / mypy) are NOT runtime deps; pinned in the dev-extra
at S2, not in the core image.

## Ambiguity-log entries raised (7, all S1-level — none blocking)

- **A-PY-001** — hand-roll CBOR (cbor2 wrong-order + no decode-side enforcement) — *operator*
- **A-PY-002** — Ed448 native via cryptography's bundled OpenSSL (verify at container-build + S2) — *operator*
- **A-PY-003** — exact `cryptography` raw-key API spelling (confirm in-container S2) — *operator*
- **A-PY-004** — CPython 3.13.14 patch < 30 days; distro-channel relaxation — *operator*
- **A-PY-005** — PEP 440 final `0.1.0` (not a pre-release suffix) — *operator*
- **A-PY-006** — dist name = full `entity-core-protocol-python` (PyPI normalized) — *operator*
- **A-PY-007** — threading (not asyncio) for §7b; explicit Lock-guarded store — *operator*

**No spec-semantics ambiguities at S1** (expected: same-as-sibling peer, dry discovery
well). Any S2/S3 spec gap against v7.75 → new `A-PY-NNN` + arch escalation.

## Anything that would block S2 (codec) — NONE

S2 can start the codec immediately. Open items for S2 to verify (not blockers):

1. **Codec spike first** (PHASE-S1-PROFILE mandate): push `map_keys.*` + `float.*`
   vectors through the hand-rolled encoder before the full build. `ffi` is the
   documented fallback if the spike fails (not expected).
2. **A-PY-003** — confirm the `cryptography` raw-key API spelling in-container.
3. **A-PY-002** — byte-verify Ed448 against the agility corpus (the container build
   already asserts it's reachable).
4. **Lockfile** — pin the `cryptography==48.0.0` wheel **hash** (committed
   requirements lockfile with `--require-hashes`) + the fedora:43 base **digest** at
   first build (S2 supply-chain lock-step per the brief).
5. **Head-form discipline** — arbitrary-precision `int` removes the carrier trap but
   NOT the explicit shortest-head-form-width selection (encode) + non-shortest-reject
   (decode) obligation.

## Planned S3 surface (baked into the profile `[bootstrap]` block per the brief)

- `--name NAME` persistent identity (loads Ed25519 from `~/.entity/peers/NAME/keypair`,
  PEM = base64 of a 32-byte seed) — enables the multisig accept-path to run vs the oracle.
- Genuine §3.6 K-of-N multisig (root-only M3 + distinct-signer M4 threshold + M6
  local∈signers) + an **accept-path unit test**.
- §6.9a seed-policy bootstrap (self owner-cap detached-sig + default discovery floor),
  per `shared/seed-policy/`.
