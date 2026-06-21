# entity-core-protocol-go — Spec / Profile Ambiguity Log

Per PROMPT-CONSTANTS "Ambiguity-log discipline": every guess goes here, no silent
guesses. Entries escalate to architecture as proposal candidates per the
stewardship handoff. **No blocking-severity items** — S1 + S2 exit criteria met
(S2 codec reached 69/69 byte-identical; A-GO-005 added, informational).

Most of this peer's spec-shaped decisions are NOT ambiguities: they are **pre-
resolved cohort traps** carried in from the settled cohort state (v7.75, uniform
576·0F·89skip across 9 peers) and recorded in the profile + rationale rather than
re-litigated here (peer_id §1.5 `hash_type=0x00`, lowercase `%02x` hex tree-paths,
§5.2 401/403/401-unresolvable trichotomy, `data` arbitrary-ECF, §4.10 413/400-not-403
with depth 64 / 16 MiB, §7b store-safety + TCP_NODELAY). They are settled spec
readings, not open questions. The genuine S1-author items are below.

---

## A-GO-001: CBOR library (fxamacker/cbor) vs hand-rolled canonical codec

**V7 section:** ENTITY-CBOR-ENCODING §2.2, §4.x, §6.3 (deterministic encoding rules
2–6 + tag rejection)
**Profile field:** `[codec].cbor_library`
**Your guess:** Hand-rolled canonical CBOR (`internal/cbor`), NOT a third-party
module. `fxamacker/cbor` (the one credible Go candidate, with a CTAP2/Core-
Deterministic encode mode) was considered and rejected.
**Rationale:** (1) The library's deterministic mode does not give ECF's full
guarantees for free regardless — recursive major-type-6 tag rejection on **decode**
→ `400 non_canonical_ecf` (§6.3), **decode-side** shortest-float minimality (Rule 4
on receive), exact float16 special-value bytes (Rule 4a), raw-byte fidelity for the
arbitrary-ECF `data` field — all of which must be hand-written on top of it anyway.
(2) Byte-exactness for a content-addressing substrate must be owned + proven
vector-by-vector. (3) Dependency-minimization (supply-chain stance) — the hand-roll
keeps `go.sum` empty. This is the A-005 pattern every prior native peer confirmed.
**Escalation:** operator — local (Go) decision; not a spec gap. Documented swap-bar:
a future maintainer may adopt the library only after proving it reproduces
`map_keys.*` / `float.*` / `tag_reject.*` byte-for-byte AND enforces decode-side
rejection.

## A-GO-002: Ed448 not in Go stdlib or golang.org/x/crypto — agility seam deferred

**V7 section:** §1.5 / §13.1 crypto-agility seed tables (v7.67); `key_type=0x02`
Ed448 *validated*, not *required* (§9.1 floor unchanged)
**Profile field:** `[codec].ed448_library = { name = "DEFERRED" }`
**Your guess:** DEFER Ed448. The Ed25519/SHA-256 conformance floor is fully native
(`crypto/ed25519` + `crypto/sha256`); SHA-384 agility hashing is native
(`crypto/sha512`); only the Ed448 *signature* family is gapped.
**Rationale:** Go's stdlib has no Ed448, AND `golang.org/x/crypto` has no Ed448
either (it carries ed25519-adjacent + NaCl-family primitives, not the Ed448/Goldilocks
curve). No reviewed-channel pure-Go audited Ed448 exists (no BouncyCastle-equivalent).
This is the **same gap Zig (A-ZIG-002) and OCaml (A-OC-002) hit** — confirming a
cross-cohort finding that the "second managed-crypto provider" route (C#'s
BouncyCastle) does not generalize to languages lacking one. Does NOT affect the
v7.75 `--profile core` target (576·0F). Likely resolution when agility lands: hybrid
native-Ed25519 + **FFI-Ed448** via cgo (consume `libentitycore_codec` for the Ed448
family only) — Go's C-ABI FFI is first-class.
**Escalation:** research — informational, mirrors A-ZIG-002 / A-OC-002 (already an
accepted cohort pattern). No new arch ask; recommend the hybrid-FFI shape if/when the
dual-algorithm conformance-floor raise reaches Go.

## A-GO-003: nint negative-integer range carrier on the uint64 decode path

**V7 section:** §3.2 native type system (`primitive/int` full range); ENTITY-NATIVE-
TYPE-SYSTEM corpus `int.10/15/16/17`
**Profile field:** `[idiom].uint64_native`
**Your guess:** Carry the `[-2^64, -1]` CBOR `nint` band with explicit `uint64`
arithmetic on decode (the additional-info value encodes `|n|-1`), surfacing values
that exceed `int64` per the spec's documented range mapping; capture as an S2 vector
check.
**Rationale:** Go has native fixed-width `int64`/`uint64` (clean, unlike OCaml's
63-bit `int` A-OC-001 or TS's BigInt F7), but the full `nint` band [-2^64,-1] does not
fit `int64`. The spec documents the 0..2^64-1 / -1..-2^64 range; the carrier choice
for the out-of-`int64` negative band is an impl decision the spec leaves to the type
system, not a wire ambiguity. Decided at S1 as an S2 watch-item rather than an open
guess — the wire form is unambiguous; only the in-memory carrier is a Go choice.
**Escalation:** operator — local decision (carrier representation); the wire encoding
is spec-pinned and unambiguous. Validate byte-exactly against the `int.*` corpus at S2.

## A-GO-004: package layout / module path placeholder

**V7 section:** absent (packaging is profile/ecosystem territory, S5)
**Profile field:** `[layout].module_path`, `[publishing].package_id`
**Your guess:** module path `github.com/entity-core/entity-core-protocol-go`;
public API at module root (`package entitycore`), codec internals under
`internal/{cbor,base58,varint}`, S4 host under `cmd/`.
**Rationale:** Go's import-path-as-identity convention needs a module path at
`go.mod` authoring; the exact repo URL is a publish-time decision (S5). The chosen
path follows the cohort's `entity-core-protocol-<lang>` naming. `internal/` gives
compiler-enforced encapsulation of codec internals.
**Escalation:** operator — local decision; the URL host (`github.com/entity-core` vs
another) is confirmable at first publish, NOT a build blocker (the module builds and
tests under any chosen path).

---

## A-GO-005: corpus version skew — profile pins v7.75, no v7.7x ECF corpus past v7.71 (S2)

**V7 section:** ENTITY-CBOR-ENCODING Appendix E (conformance fixture versioning)
**Profile field:** `[spec].codec_corpus = "v7.75"`; PHASE-S2-CODEC §E.3 example
names `v7.56`
**Your guess:** Ran S2 against `shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`
— the latest vendored copy. This is **safe and non-ambiguous**: the v7.71 MANIFEST
states the ECF codec corpus "did not change across the whole v7.56→v7.71 window"
and the file is byte-identical (SHA `41d68d2d…`) in v7.56/v7.70/v7.71. There is no
`v7.72`–`v7.75` `test-vectors/` directory (only `spec-data/` advances that far), so
the ECF conformance corpus at the profile-pinned v7.75 reading IS the unchanged
v7.71 file. The PHASE-S2 contract's `v7.56` path in its example is illustrative; the
harness auto-selects the newest present copy of the identical artifact.
**Rationale:** The codec corpus is immutable + additive per Appendix E.5; the byte
content has been stable since the v1 cross-bless (commit `23db254`).
Choosing the newest vendored copy of the identical file is the conservative
reading. No fixture was patched or fudged.
**Escalation:** research — informational. Recommend keystone vendor a
`test-vectors/v7.75/` (even if it is a byte-identical re-stamp of the unchanged
`.cbor`) so the `(spec-version, fixture-version)` reproducibility coordinate the
profile pins resolves to a literal directory, rather than relying on the
"unchanged-since-v7.56" MANIFEST note. NOT a conformance blocker — 69/69 is exact
against the file that IS the v7.75 ECF corpus.

---

## A-GO-006: §5.2 flat "DENY → 403" under-specifies the §4.6 authn(401)/authz(403) boundary (S3)

**V7 section:** §5.2 (verify-request verdict), §4.6 (handshake authn), §5.5 (chain
walk grantee resolution), §4.10(b) (chain-depth → 400)
**Profile field:** `[error_model]` status mapping (already anticipates 401/403/401-
unresolvable/400)
**Your guess:** Implemented `verifyRequest` as a **4-way verdict** rather than the
flat ALLOW/DENY the §5.2 pseudocode literally reads:
- `VerdictAuthnFail` → **401** (missing/mismatched/invalid request signature, or the
  author identity unresolvable) — an *authentication* failure, distinct from authz;
- `VerdictAuthzDeny` → **403** (capability absent / chain invalid / grantee≠author /
  revoked) — the §5.2 AUTHZ_DENY;
- `VerdictUnresolvableGrantee` → **401** (§5.5 carve-out: a grantee that cannot be
  resolved during the chain walk is an *unresolvable* condition, not a denial);
- `VerdictChainTooDeep` → **400 chain_depth_exceeded** (§4.10(b) structural excess,
  gated BEFORE the per-link authz walk — arch ruling: structural ≠ authz).
**Rationale:** A single 403 for both "you failed to authenticate" and "you lack the
capability" loses the §4.6 distinction the caller needs (re-authenticate vs. request a
broader cap). The §4.10(b) 400 is an explicit arch ruling already in the profile. The
401-unresolvable-grantee carve-out lets a caller distinguish a transient resolution gap
from a hard denial. This is the SAME trichotomy the spec-first cohort independently hit
and flagged — **Zig A-ZIG-006, OCaml A-OC-008 (arch F20), Swift A-SW-010, Common-Lisp**;
the Go peer (built clean-room from the spec + the CL blueprint, NOT the oracle) lands on
it too. The convergence across now-5+ independent peers is the finding: §5.2's flat DENY
is an under-specification, and the operational reading is the 3-way authn/authz/
unresolvable split + the §4.10(b) 400.
**Escalation:** arch — spec needs clarification. NOT a new ask (F20 already tracks it);
this entry records the Go peer's independent corroboration so the convergence count is
visible. NOT a conformance blocker — the trichotomy is what the cohort's signed-off
576·0F state already encodes.

---

## A-GO-007: live `--profile core` total at oracle `75c532e` is 653, not the docs' 576 (S4)

**V7 section:** §9.0 core-profile category set (the profile-owned authoritative list)
**Profile field:** `[conformance].conformance_profile = "core"`; the recorded target
"576 total · 0 FAIL · 89 skip"
**Your guess:** Treat the **binary gate** (`summary.failed == 0`) as authoritative and
report the live **653 total · 0 FAIL · 94 skip** at oracle `75c532e`, rather than
forcing the run to the stale 576 figure. The 576→653 delta is entirely in the
non-failing counts: `75c532e` ships newer extension categories (`relay`,
`transport_family`, `serving_mode`, encryption-adjacent, …) that did not exist in the
576-era registry and that SKIP under `--profile core` (auto-allowlisted carve-outs),
plus a wider `type_system` probe (374 checks — 53 floor + matched-if-present extension
vocabulary that WARNs).
**Rationale:** the phase contract names the gate as a clean `Result: PASS` / `failed == 0`
under the §9.0 core-profile, and explicitly says the profile (not a hand-listed total)
IS the gate; the oracle owns the authoritative category list. The total is an emergent
count of that evolving list, so a moving total across oracle commits is expected and
non-anomalous as long as `failed == 0` and the skips are profile carve-outs (93) +ed the
local-env multisig skip (1). 0 FAIL-severity records confirms the summary.
**Escalation:** research — informational. Recommend the keystone refresh the recorded
per-language conformance target string to the live `75c532e` value (653·0F·94S) so the
reproducibility coordinate matches the pinned oracle, rather than carrying the 576 figure
from an earlier oracle. NOT a conformance blocker.
