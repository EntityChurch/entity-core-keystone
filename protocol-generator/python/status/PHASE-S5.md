# Phase S5 — Publish (entity-core-protocol-python)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version:** `0.1.0` (PEP 440 final pre-1.0 — A-PY-005) · **Spec basis:** V7
spec-data **v7.75**. · **Peer:** Python (CPython, **clean-room** — derived from the V7 spec +
keystone lifecycle contracts + language-neutral sibling profiles, **NOT** from the hand-written
sibling `entity-core-py`). · **Branch:** `lang/python` (worktree), local-only.

S5 polishes the S4-conformant clean-room Python peer into a *ready-to-publish* PyPI artifact.
`/entity-rosetta` never publishes (lifecycle §Publishing) — this phase produces the artifacts +
the build/operator runbook; an operator uploads when arch signs off v0.1 AND the PyPI name is
confirmed non-squatted. This doc is the release-readiness record, the packaging record, and the
findings/escalation summary for the keystone steward (§6).

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | **665 / 292P / 268W / 0F / 93S**, machine-verified `failed==0` AND `total==665` @ oracle `entity-core-go e8524ed` (`status/CONFORMANCE-REPORT.{md,json}`). All 16 core categories 0-FAIL. Recorded **665·0F @ e8524ed**. |
| Codec byte-identical (S2) | ✅ | **69/69** vs `conformance-vectors-v1`, first run, 0 codec fixes. **Re-ran GREEN at S5** (stdlib zero-dep runner `tests/conformance/harness.py`, `--network=none`). |
| multisig accept-path | ✅ | **11/11 · 0 skip**, incl. `valid_2of3_peer_signed_accepted` (genuine K-of-N ACCEPT; host `--name conformance`). |
| origination-core (reentry) | ✅ | **3/3** over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry` — §6.11 reentry wire-proven vs a Go reference). |
| §9.5 53-type registry | ✅ | **53/53** byte-identical (content_hash recomputed by the Python codec, asserted equal to the Go reference @e8524ed — not ingested). |
| Native-full-agility (Ed25519 **+ Ed448**) | ✅ | Both curves native via `cryptography` (one runtime dep, bundled OpenSSL 3.5.x), zero FFI — the Haskell/Ruby class. Byte-verified vs the v7.71 `KEY-TYPE-ED448-1` pin; the container build hard-asserts both curves at image-build (A-PY-002). |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0 notice, identical to the cohort/repo-root S9 default); `pyproject` `license = "Apache-2.0"`, bundled into the wheel `dist-info/licenses/LICENSE`. |
| README + conformance badge | ✅ | `README.md` — clean-room caveat, conformance verdict `665·0F @ e8524ed`, the native-full-agility-incl-Ed448 note, `pip install` + the in-container build/run, `--name`/`--validate` usage; links `status/CONFORMANCE-REPORT.md`. |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0` tracks V7 spec-data v7.75; the A-PY-005 version-spelling note carried. |
| Package metadata (`pyproject.toml`) | ✅ | hatchling backend, src-layout package discovery (`src/entity_core`), name/version `0.1.0`/description/`license`/keywords/classifiers/`requires-python >=3.9`, the `cryptography==48.0.0` runtime dep, console-script `entity-core-peer = entity_core.host:main`, `output/`+pycache excluded from wheel/sdist. **`python -m build` succeeds** (wheel + sdist) — see §2. |
| Wheel imports + console-script | ✅ | The installed wheel imports `entity_core` + `entity_core.peer` (from the install location, not `src/`); `__version__ == 0.1.0`; `encode({"a":1}) == a1616101` (canonical CBOR); `entity-core-peer --help` runs (exit 0). |
| Toolchain pin (S11) | ✅ | CPython **3.14.5** (fedora:43 distro channel — reviewed channel, age floor relaxes to "pin exactly"; A-PY-004/008) + `cryptography==48.0.0` (≥30-day cool-down clear), wheel HASH-pinned in `requirements.txt` (`--require-hashes`). pytest/ruff/mypy = dev-only `[dev]` extra. |
| CI config (Podman, offline) | ◑ runnable, not wired | the build/codec/conformance loop runs sealed-offline in `python-toolchain` today (`run-s4.sh`, `run-origination-core.sh`, `harness.py`, all `--network=none`). A committed CI *workflow* is deferred **cohort-wide** (no peer has one wired) — lands at S10 or when arch defines the shared CI home. |
| Public API surface | ◑ documented | Tier 1 `entity_core.__all__` (codec/identity/signatures/errors) + Tier 2 `entity_core.peer`; leading-underscore modules (`_cbor`/`_base58`/`_varint`) signal "internal, may churn". Explicit semver freeze deferred to publish-prep / first consumer (§3). |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; **no ⚑ arch asks** (dry well — corroboration-only); all A-PY-001…010 owner-/research-routed (§4). |
| **Published to PyPI / tagged** | ⛔ **deferred** | operator action — requires the dist name confirmed non-squatted (A-PY-006) AND arch v0.1 sign-off (§6). No auto-tag, no `twine upload`. |

**Promotion gate `0.1.0` → stable** (lifecycle §Version-pin): (a) S4 fully green ✅ *and*
(b) ≥1 external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not
yet met** (no Python consumer wired). The 0-major already honestly signals pre-stable; a 1.0
promotion waits on a consumer. (Note: Python does **not** carry the Ruby/CL `0.1.0-pre`
spelling wrinkle — PEP 440 accepts a bare `0.1.0`, and pip would *exclude* an `rc`/`a`/`b` tag
by default, so the final `0.1.0` is the correct "early peer, installable-by-default" spelling;
A-PY-005.)

---

## 2. Packaging record (the S5 build, verified in-container)

Built + verified in `entity-core-keystone/python-toolchain:latest` (fedora:43, CPython 3.14.5,
host podman — not a toolbox). The offline core image carries **only** the runtime dep
`cryptography` (no PEP 517 backend; A-PY-010), so per the phase contract the **build** runs in a
**thin network-on layer** (`pip install build`), while the **codec gate** stays on the sealed
offline image:

```bash
# Build (thin network-on layer; hatchling backend pulled into an isolated build env):
podman run --rm -v "$PWD/protocol-generator/python":/pkg:Z -w /pkg \
  entity-core-keystone/python-toolchain:latest \
  sh -c 'pip install build && python -m build'
#  → entity_core_protocol_python-0.1.0-py3-none-any.whl  (52 KB)
#  → entity_core_protocol_python-0.1.0.tar.gz            (sdist, 58 KB)

# Codec gate (sealed-offline, stdlib zero-dep runner — re-ran GREEN at S5):
podman run --rm --network=none -v "$PWD":/work:Z \
  -w /work/protocol-generator/python entity-core-keystone/python-toolchain:latest \
  sh -c 'PYTHONPATH=src python tests/conformance/harness.py'
#  → wire-conformance (core-python, corpus v1): 69/69 PASS, 0 FAIL
```

**Build outcome — clean:**
- `python -m build` produces both `entity_core_protocol_python-0.1.0-py3-none-any.whl` and the
  sdist `.tar.gz` (pure-Python, `py3-none-any`, hatchling backend).
- **Wheel contents:** the `entity_core` package + `entity_core.peer` subpackage, `METADATA`,
  `entry_points.txt`, `dist-info/licenses/LICENSE`. **No** `output/`, `__pycache__`, `.pyc`,
  oracle binaries, or `run-*.sh` scripts leaked into the wheel **or** sdist (the
  `[tool.hatch.build.targets.{wheel,sdist}]` discovery + `exclude` verified).
- **Install + import:** installed into a venv carrying `cryptography==48.0.0` (`--no-deps`,
  `--no-index`); `import entity_core, entity_core.peer` succeeds **from the installed location**
  (not `src/`); `entity_core.__version__ == "0.1.0"`; `encode({"a":1}) == a1616101`.
- **Metadata (from the installed dist):** `Name: entity-core-protocol-python`,
  `Version: 0.1.0`, `License-Expression: Apache-2.0`,
  `Requires-Dist: cryptography==48.0.0` (+ pytest/ruff/mypy gated behind `extra == 'dev'`),
  `Requires-Python: >=3.9`, console-script `entity-core-peer = entity_core.host:main`.
- **Console-script:** `entity-core-peer --help` runs (exit 0) — the installed-wheel form of the
  `python -m entity_core.host` driver `validate-peer` dials.

**Not published.** No `twine upload`, no git tag, no PyPI registration — operator action (§6).
The built artifacts are disposable (built into `/tmp/dist` in-container) — **not** committed.

## 3. Public-surface (the S5 "settle the surface" decision)

The stable contract is the README §Install two tiers — **Tier 1** the `entity_core.__all__`
re-exports (codec `encode`/`decode`/`ByteKey`, varint/base58, `content_hash`, peer-id, the
`sign_*`/`verify_*` family, the `EntityCoreError` lattice) and **Tier 2** the full peer
`entity_core.peer` (`Peer`, `listen`, transport/store/capability/handlers). The leading-
underscore modules `_cbor`/`_base58`/`_varint` are PEP-8-conventional "internal, may churn"
(Python has no compiler-enforced privacy — the convention is the contract, the Ruby/CL class,
not Go's `internal/`). A hard semver freeze (and any `__all__` tightening) is a publish-prep /
first-external-consumer pass — documented, not enforced, at `0.1.0`, matching the cohort
dynamic-language peers (Ruby/CL).

## 4. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-PY-* items are resolved-in-peer and owner-routed; **none block release. There are no
⚑ arch asks from this peer.** Full text in `status/SPEC-AMBIGUITY-LOG.md`; summary:

- **A-PY-001** (RESOLVED, operator) — hand-rolled canonical-CBOR (no Python lib delivers ECF;
  `cbor2 canonical=True` is RFC-8949 bytewise, the wrong order). The 13th-peer A-005 pattern.
- **A-PY-002** (RESOLVED) — Ed448 native via `cryptography`, byte-verified → **native-full-
  agility confirmed** (no FFI, no second crypto source). **A-PY-003** (RESOLVED) — raw-key API
  spelling confirmed in-container.
- **A-PY-004 / -008** (operator/research) — CPython distro-channel version drift (3.13.14 S1
  intent → 3.14.5 realized at S2 build); transparency note, conformance-neutral, non-blocking.
- **A-PY-005** (operator) — PEP 440 version = final `0.1.0` (pip excludes pre-releases by
  default; a bare `0.1.0` is the installable-by-default "early peer" spelling).
- **A-PY-006** (operator) — PyPI dist name `entity-core-protocol-python` confirm-non-squatted at
  first publish; fall back to a variant if taken.
- **A-PY-007** (RESOLVED, operator) — thread-per-connection (`threading`, not asyncio) for the
  §7b concurrency floor; `Lock`-guarded store + `Condition` reentrant demux.
- **A-PY-009 / -010** (RESOLVED, operator) — `--name` keypair file = base64-of-32-byte-seed;
  the S2/S3 gates run under a stdlib zero-dep runner (offline core image has no pytest).

**Corroborated (read as ratified v7.75 text, not re-litigated):** peer-id §1.5 canonical form,
the 401/403/401 §5.2/§5.2a trichotomy, §4.10 resource_bounds (413 + chain-depth→400), the
A-JAVA-010 §1.1 arbitrary-ECF-`data` shape, lowercase address-space hex (the A-CL-009 trap). The
one S4 peer fix — §4.6/§7.1 `400 unsupported_key_type` for an unknown embedded `key_type` (the
AGILITY-UNKNOWN-1 vector) — was a **clean, unambiguous spec requirement** the peer had under-
implemented, **not a guess**, so it added no ambiguity entry.

## 5. Findings / escalation summary (for the keystone steward)

- **Clean-room held.** No file under any `entity-core-py` checkout was opened, read, or
  referenced at any phase S1–S5; every protocol-shaped decision grounds in a V7 §-pointer or the
  Go conformance oracle (the permitted ground truth). The §4.6 `unsupported_key_type` fix was
  arrived at from the spec + the oracle's named vector, independently of the sibling.
- **Framing — adoption + generator-independence cross-check.** Python is a **same-as-sibling
  adoption peer**; its value is an independent reimplementation (clean-room, one-runtime-dep,
  native-full-agility) that **byte-agrees with the Go oracle** + an idiom-completeness data point
  on the dynamic/scripting axis (arbitrary-precision `int`, duck-typed `data`, threading-under-
  GIL). It is **not** a spec-refinement vehicle.
- **No new spec defect — the discovery well is dry, as expected.** Python read the COMPLETE
  v7.75 snapshot and **corroborated** the inherited cohort findings live against the oracle
  rather than surfacing anything new. The ambiguity log is **all operator-level** (library/pin/
  packaging/host-CLI/test-harness decisions) — **zero arch asks**.
- **Notable confirmations:** A-PY-002 **native-full-agility incl. Ed448 confirmed** (byte-
  verified, no FFI — the Haskell/Ruby class). The S4 §4.6 fix is a **clean spec requirement, not
  a guess**. The codec is byte-identical to the cross-blessed corpus AND the Go oracle (e8524ed).

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar, an
external consumer confirms the peer, AND the PyPI name is confirmed available:

1. **Decide in-repo vs standalone repo.** Per-language sibling repos are deferred keystone-wide
   (S10); current default is in-repo under `protocol-generator/python/`.
2. **Confirm `entity-core-protocol-python` is non-squatted** on pypi.org (A-PY-006); pick a
   variant if taken. (PyPI normalizes dist names per PEP 503 — case/underscore variants collide.)
3. **Settle the public-surface freeze** (§3): tighten `__all__` if desired; the underscore-module
   convention already signals internal. Optionally privatize harder before 1.0.
4. **Set `[project.urls]`** `Repository`/`Homepage`/`Changelog` to the chosen repo's URLs
   (currently unset — A-PY-006), and `repository_url` in `profile.toml [publishing]`.
5. **Build** in a thin layer (§2): `pip install build && python -m build` → wheel + sdist.
6. **Publish** — `twine upload dist/*` (after a PyPI API token). **Tag the release** at the
   reviewed commit at this point only (lifecycle §"no auto-tag"). Promote to `1.0.0` only once
   the external-consumer promotion gate (§1) is met.
7. **Wire CI** (`run-s4.sh` + `run-origination-core.sh` + `harness.py` in `python-toolchain`,
   `--network=none`, assert `failed==0` + the codec 69/69) to the chosen repo's runner, or fold
   into the keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
8. **Pin discipline** (S11): CPython 3.14.5 + the HASH-pinned `cryptography==48.0.0` stay exact;
   re-pinning is deliberate + reviewed.

---

## 7. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged to
PyPI — gated on the name check A-PY-006 + arch v0.1; stable promotion pending an external
consumer; public-surface freeze pending; CI runnable-offline but not wired to a remote — all by
design). **Regression GREEN at S5:** the wheel + sdist build clean (hatchling), the installed
wheel imports `entity_core` + `entity_core.peer` and the console-script `entity-core-peer` runs,
and the **codec gate re-ran 69/69 · 0 FAIL** sealed-offline. The S4 figure is unchanged
(**665·0F @ e8524ed**, multisig 11/11, origination 3/3, 53-type 53/53). Ambiguity log finalized
+ routed — **no ⚑ arch asks** (dry well; all operator/research). Operator handoff (§6) prepared.
**S5 objective met; the Python peer is publish-ready and parked at `0.1.0` pending arch v0.1
sign-off + the PyPI name check.**

**Readiness:** `lang/python` is ready for operator merge into keystone `master` — S1–S5 complete,
conformance + codec gates green, clean-room held, no arch escalations.
