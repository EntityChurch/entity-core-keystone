# entity-core-protocol-csharp — Spec / Profile Ambiguity Log

Per S3: every guess, deviation, or profile-gap the generator resolved during a
phase is recorded here. Items escalate to architecture (spec) or research
(profile) as proposal candidates. **No silent guesses.**

Phase S2 (codec). Conformance: 69/69 byte-identical.

---

## A-001: shortest-float (Rule 4) is hand-rolled, not delegated to the CBOR library

**V7 section:** `ENTITY-CBOR-ENCODING` §4.1 Rule 4 + Rule 4a (specials)
**Profile field:** `codec.cbor_library.canonical_mode`
**Your guess:** The canonical encoder uses `System.Formats.Cbor` `CborWriter` in
`Ctap2Canonical` mode for all structure (map sort, minimal ints, definite
lengths), but **floats are hand-rolled** (`CanonicalCbor.EncodeFloat`) and spliced
in via `CborWriter.WriteEncodedValue`. Selection: specials → canonical f16; else
the smallest of f16⊂f32⊂f64 that round-trips exactly.
**Rationale:** No `System.Formats.Cbor` conformance mode performs Rule 4
shortest-float minimization — it writes the precision it is handed (eval risk R1).
Every reference impl (Go/Rust/Py) hand-rolled this; Python's cbor2 C-ext shipped
the W2 bug here. Verified against all 14 `float.*` vectors + a unit battery.
**Escalation:** operator — local implementation decision, informational. (Pattern
is now established across 4 impls; candidate for a profile note that native CBOR
libs generally need a hand-rolled float pass.)

---

## A-002: profile `ed25519_library` version `23.4.0` does not exist as a stable release

**V7 section:** absent (library-choice, not spec)
**Profile field:** `codec.ed25519_library.version`
**Your guess:** Pinned `NSec.Cryptography` **25.4.0** instead of the profile's
`23.4.0`.
**Rationale:** NSec has no stable `23.4.0` — the 23.x line is previews only
(`23.5.0-preview.1` … `23.9.0-preview.3`); the stable cadence is 22.4.0 → 24.4.0
→ 25.4.0 → 26.4.0. `dotnet restore` of `23.4.0` silently bumps to 24.4.0
(NU1601). 25.4.0 (~13 months old → S11-clean) is
net9-compatible and pins libsodium 1.0.20.1. Chosen over 26.4.0
(only ~38 days old — too close to the S11 floor to be comfortable) and
24.4.0 (predates .NET 9). Ed25519 is deterministic (RFC 8032), so the version
choice is conformance-neutral — confirmed: all 3 `signature.*` vectors are
byte-identical to the Go/Rust/Py-blessed signatures.
**Escalation:** research — update `profile.toml` pin authoritatively + record the
NSec stable-cadence fact so the next net9 profile author doesn't re-hit it.
(Profile already edited to 25.4.0 with an inline note; this asks research to
bless it.)

---

## A-003: profile `base58_library` was unpinned (TBD) — hand-rolled

**V7 section:** `ENTITY-CORE-PROTOCOL-V7` §8.5 (Bitcoin alphabet)
**Profile field:** `codec.base58_library` (was absent / "TBD" per the eval)
**Your guess:** Hand-rolled Base58 (Bitcoin alphabet) in `Base58.cs` (~80 lines,
encode + decode, leading-zero handling); added `base58_library = "hand-rolled"`
to the profile.
**Rationale:** The eval flagged the profile gap and leaned hand-roll: it's a small
primitive, and hand-rolling dodges a NuGet dependency + an S11 pin. Verified
against all 3 `peer_id.*` vectors (incl. the multi-byte-varint key_type=128 case)
+ a round-trip unit test.
**Escalation:** research — record the decision in the profile authoritatively
(done inline; asks research to bless). No spec impact.

---

Phase S3 (peer machinery). Smoke green (C#↔C# loopback).

---

## A-004: S3 smoke is C#↔C# loopback, not against the Go reference peer

**V7 section:** PHASE-S3-PEER.md smoke-runner step 2 ("boots a reference peer, e.g.
`entity-core-go entity-peer`")
**Profile field:** absent
**Your guess:** The S3 smoke boots two C# peers over real loopback TCP and drives
the full §4.1 handshake + authenticated dispatch between them, rather than against
the Go `entity-peer`. Cross-impl validation is performed in S4 via
`entity-core-go/cmd/validate-peer`.
**Rationale:** The phase doc lists the reference peer with "e.g." — it is one option.
A self-contained C#↔C# smoke proves the wire path (framing, handshake, chain verify,
request_id demux) without entangling first-run debugging with cross-language wire
deltas, which are precisely what S4's live oracle exists to surface ("then connect
it to the other peers" per the operator). The Go `entity-peer`/`validate-peer`
binaries are present in the sibling repo and used in S4.
**Escalation:** operator — local sequencing decision; revisited at S4.

---

## A-005: `supports_revocation = false` (revocation check skipped in verify_request)

**V7 section:** §5.1, §5.2 step 4 (revocation is SHOULD-level, gated on
`supports_revocation`)
**Profile field:** absent
**Your guess:** The dispatcher runs `verify_request` with `supports_revocation =
false`, skipping the `is_revoked` tree-walk.
**Rationale:** §5.2 makes revocation checking SHOULD-level and explicitly permits
`supports_revocation = false` for "implementations without persistent-capability
extensions" (compute/continuation/inbox/subscription) — none of which the core peer
ships (they are out-of-scope extensions). Revocation becomes MUST only for those
extensions, which install it with their own context. The `is_revoked` algorithm,
`capability_path_for`, and `unknown_root_policy` will land when the first persistent-
cap consumer does.
**Escalation:** operator — conformant default for a core-only peer; research may want
to record it as the recommended core-peer setting.

---

## A-006: `system/capability` handler implements `request` only; `delegate`/`revoke` → 501

**V7 section:** §3.6, §6.2 (capability handler operations)
**Profile field:** absent
**Your guess:** `CapabilityHandler.request` is fully implemented (issues a root token
from the peer's own authority, bounded by local policy = grant-as-requested).
`delegate` and `revoke` return 501 `not_supported`.
**Rationale:** `request` is what the §4.4 initial grant authorizes and is the only
capability op the connection flow depends on, so leaving the handler out entirely
would make the initial grant reference a non-existent handler. `delegate` is
underspecified in core (the op params are just the parent token — the grantee of the
delegated token has no home in the shape; see F13). `revoke` is `put(path, null)`
plus an optional revocation list and only bites once `supports_revocation` is on
(A-005). Both are honest 501s, not faked passes (S5).
**Escalation:** operator (implement when revocation/delegation land) + arch (F13: the
`delegate` grantee under-specification).

---

## A-007: handlers handler (MUST, §6.9) and types handler (SHOULD) not yet implemented

**V7 section:** §6.2, §6.9 (bootstrap: tree + handlers + connect are MUST), §6.1
(native-code↔manifest binding is implementation-defined)
**Profile field:** absent
**Your guess:** Bootstrap installs the **tree** and **connect** handlers (MUST) plus
the **capability** handler (SHOULD). The **handlers handler** (`system/handler`
register/unregister — also MUST per §6.9) and the **types handler**
(`system/type:validate` — SHOULD) are **not yet implemented**. The peer is therefore
not yet §6.9-complete.
**Rationale:** The S3 smoke (handshake + authenticated dispatch + 404 + request_id
demux) does not exercise them, so they are not on the critical path to the phase
gate. Implementing `register` faithfully needs the §6.1 mechanism for binding
language-native executable code to a freshly-registered manifest — which the spec
leaves implementation-defined and which warrants its own small design (a delegate /
factory registry keyed by pattern, distinct from the entity-native `expression_path`
path). Deferring it cleanly is better than a half-wired version. This is the
flagged top item for S3 completion; `validate-peer` (S4) is expected to surface it.
**Escalation:** operator (implement to reach §6.9 completeness) + research (F11: the
§6.1 native-binding mechanism is a per-language design point every generated peer
hits — worth a diagnostics note).

---

## A-008: authenticate nonce-echo is not validated against a stored sent-nonce

**V7 section:** §3.8 (`authenticate.nonce` = "other peer's nonce echoed back"), §4.6
(authenticate signature verification)
**Profile field:** absent
**Your guess:** The connect handler verifies the authenticate signature (proving key
possession over the signed authenticate entity, which contains a nonce) but does
**not** check that the echoed nonce equals the nonce this peer sent in its own hello.
**Rationale:** §4.6's verification algorithm reconstructs the authenticate entity and
verifies the signature; it does not state a nonce-equality check, and the hello-nonce
this peer generated is not currently retained per-connection. Without the echo check,
a signature captured on one connection could be replayed on another (the nonce binds
the signature to *a* challenge but the receiver never confirms it is *its* challenge).
This is a hardening gap, not a smoke blocker.
**Escalation:** arch (F12: §4.6 should state the nonce-echo equality check explicitly
— a likely spec under-specification) + operator (retain the sent nonce per-connection
and validate the echo once F12 resolves).

---

## Notes (not ambiguities, recorded for the next phase)

- **Decode strictness (N2):** the decoder runs `System.Formats.Cbor` in
  `Ctap2Canonical` *and* an explicit recursive tag-reject (`PeekState == Tag →
  throw`), per eval R4 ("don't trust library defaults"). All 5 `tag_reject.*`
  (incl. the deep-nested-in-`included` case) reject correctly.
- **N4 fidelity:** entity `data` is carried as `EcfValue.PreEncoded` and spliced
  verbatim via `WriteEncodedValue` (validates well-formedness, never
  re-serializes). Mirrors the C impl's `EV_PREENCODED`.
- **R5 zero-hash sentinels:** not exercised by any S2 vector (decode of optional
  hash fields is peer-layer); carry to S3 and confirm against the 7.56 text.

---

Phase S4 / Block 3 (resync to v7.71 + crypto-agility seam).
Codec 69/69 unchanged; agility byte-verification 24/24 (KEY-TYPE-ED448-1,
HASH-FORMAT-SHA-384-1, MATRIX-M2/M3/M6, reject paths).

---

## A-009: Ed448 provider is BouncyCastle (profile had no Ed448 library)

**V7 section:** §1.5 `key_type` seed table (Ed448 `0x02`, validated v7.67)
**Profile field:** `codec.ed448_library` (was absent — the profile pinned only Ed25519)
**Your guess:** The crypto-agility seam wires Ed448 (`0x02`) live via
`BouncyCastle.Cryptography` **2.4.0** (added `ed448_library` to the profile). Ed25519
stays NSec/libsodium; SHA-256/384 stay in-box `System.Security.Cryptography`.
**Rationale:** NSec/libsodium has **no Ed448** — the validated second key family needs
a different provider. BouncyCastle was chosen over (a) FFI to our own
`libentitycore_codec` (Block 1's vendored Ed448) and (b) a managed Ed448 microlib,
because: it is **pure-managed** (keeps the peer native-first, the profile's whole
thesis — no P/Invoke for a *core* op), it is an **independent crypto source** from
libsodium (a free cross-check), and the registry seam makes the provider a one-line
swap if it ever needs to change. S11: 2.4.0 is well over 30 days old; lockfile
committed. **Byte-verified:** BouncyCastle Ed448 is byte-identical to the Go/Rust/Py
cohort pins (and transitively to our Block-1 FFI Ed448 on seed `0x42`) — RFC 8032 is
deterministic, so this is a hard equality, not a coincidence.
**Escalation:** research — record `ed448_library` in the profile authoritatively + the
fact that net9 has no in-box/libsodium Ed448 (the next native-first profile hits this).
Also tracks against arch **G2** (the C-ABI's crypto symbols are algorithm-named — the
FFI Ed448 path stays available as the documented alternative for no-managed-lib
ecosystems).

---

## A-010: codec-primitive content hash vs. agility content_hash_format dispatch

**V7 section:** §1.2 (`content_hash_format` — "interpretation, not routing", v7.68)
**Profile field:** absent
**Your guess:** Two distinct content-hash surfaces coexist. (1) `EntityCodec.ContentHash`
is the **codec primitive**: `LEB128(formatCode) || SHA256(body)` — the format code is an
opaque varint prefix, the body is always SHA-256. (2) `Entity.Create(type, data, format)`
+ `HashFormats` is the **agility layer**: the format code *selects* the digest family
(SHA-256 / SHA-384) and rejects unknown codes (`unsupported_content_hash_format`).
**Rationale:** The S2 codec corpus uses `content_hash` format codes as **varint-width
probes over SHA-256 bodies** (e.g. `content_hash.4`, `format_code=128`) — it predates
multi-hash and asserts the *encoder* emits the right prefix bytes. Routing that primitive
through the family-selecting registry broke `content_hash.4` (128 is "unsupported" as a
*family* but valid as a *synthetic prefix*). The two intents are genuinely different: the
corpus tests codec mechanics; the agility registry tests protocol interpretation
(`VARINT-MULTIBYTE-1` rejects 128 *at the entity/interpret layer*, which the agility
harness confirms). Keeping them separate preserves 69/69 **and** the agility reject paths.
**Escalation:** operator — local layering decision; informational. Candidate diagnostics
note: native impls should not conflate the ECF content-hash *encoder primitive* with the
agility *content_hash_format* family dispatch.

---

## A-011: §10.1 register dispatch round-trip pulls compute/entity-native vocab into the core gate

**V7 section:** §6.13(a), §6.2 (behavioral register); PROPOSAL-V7-V7.74 §10.1 (the
core-tier dynamic-register gate); §9.4 (body-binding mechanism is impl-private)
**Profile field:** absent
**Your guess (F1):** `register`/`unregister` execute the five normative writes
behaviorally (no 501). A dynamically-registered handler resolves by tree walk and, having
no in-process body, dispatches its `expression_path`. The keystone **body-binding seam**
(impl-private per §9.4) evaluates the minimal `compute/literal` shape and returns a
`compute/result` — exactly what the Go gate's step-4 round-trip asserts (`numEq(val, 42)`).
Richer expression bodies return `501 unsupported_expression` (they need the compute
extension). `compute/literal` / `compute/result` are read/emitted as **type labels only**
— NOT registered in the §9.5 core type floor (type_system stays at 53, GREEN).
**Rationale / finding:** the Go gate (`cmd/internal/validate/core_register_gate.go`)
hardcodes Go's *entity-native compute* as the body-binding seam — it `TreePut`s a
`compute/literal(42)` at `<pattern>/expr`, registers with `expression_path`, then dispatches
op `compute` and asserts the response round-trips `42`. But `EvaluateExpression` is the
**compute extension's** pluggable seam in Go (`core/protocol/dispatch.go`); a *pure* core
peer (no compute) has nothing wired. So as drafted, the `--profile core` §10.1 round-trip
cannot pass without a core peer evaluating a `compute/literal` — i.e. it pulls extension
vocab into the core gate. The proposal frames the seam as impl-private ("Peers with a
different body-binding mechanism plug a different seam here"), but validate-peer is a fixed
binary that always puts a `compute/literal` and expects `42` — a keystone peer cannot plug a
different seam without the validator cooperating. **The 5 writes (gate steps 1–3, 5) are
unambiguous core and fully covered; only step 4 (dispatch round-trip) carries this coupling.**
**Escalation:** **architecture (S3 → proposal candidate).** Options for arch/Go to rule:
(a) the §10.1 round-trip SHOULD detect the absence of a body-binding seam and SKIP step 4
(scoring steps 1–3+5 only) for non-compute peers; (b) a minimal `compute/literal` evaluator
is declared part of the core body-binding floor (then it belongs in the spec, not just the
gate); or (c) the validator gains a peer-declared body-binding-seam negotiation. Keystone
ships option-(b)-shaped behavior (the minimal literal seam) to keep the round-trip GREEN now;
flag for a ruling. Verified end-to-end by `RegisterRoundTripTests` pending the Go gate landing
in our oracle.

## A-012: unregister type-teardown + system-path registration guard

**V7 section:** §6.2 ("`unregister` reverses all five steps"); §6.2 ("user-installed
handlers MUST NOT register at `system/*`")
**Profile field:** absent
**Your guess (F1):** (1) `unregister` removes the manifest, interface, grant, and
grant-signature (writer/unregister symmetry — the half-removed grant/sig state is the
hazard the symmetry prevents; the Go gate asserts the sig removal). It does **not** remove
installed `system/type/*` entities — types may be shared across handlers, so blind removal
on unregister is unsafe; left in place. (2) System-path registration is governed solely by
the **dispatch cap-check** on `EXECUTE.resource` (`system/*` scope required to install at a
`system/*` pattern), per §6.2's own registration-cap examples — no separate user-vs-bootstrap
guard, since every wire `register` is by definition non-bootstrap and the cap scope is the
enforcement.
**Rationale:** type-teardown is untested by the §10.1 gate (it sends no `types`), and
shared-type removal is a correctness hazard with no spec-pinned ownership/refcount model.
The cap-check is the spec's stated authorization mechanism for install location.
**Escalation:** operator/architecture — informational. If a type-ownership/refcount model
for unregister teardown is desired, that is a spec addition (candidate). Until then, leaving
types in place is the safe reading.
