# entity-core-protocol-swift — Spec Ambiguity Log

Every guess / judgment call made while generating the Swift peer (peer #7). Format per
PROMPT-CONSTANTS.md S3. Items escalate to architecture as proposal candidates via
`research/stewardship/`. **No silent guesses.**

`A-SW-NNN` convention. Severity: a **blocking** item halts the dependent phase; the rest
are recorded decisions / escalations. No blocking items at S1 exit.

---

## S5 finalization — owner + escalation status

Every item tagged at phase exit; none block release. ⚑ = spec-text-tension corroboration routed
to architecture as a v7.75-candidate spec-refinement finding.

| Item | Owner | Status |
|---|---|---|
| **A-SW-001** Ed448 native gap | research — profile/agility | **deferred** (hybrid-FFI when agility in scope; does not touch the §9.1 floor) |
| **A-SW-002** Swift `String` → wire ops on UTF-8 bytes | operator — local | **resolved / informational** (codec discipline; spec unambiguous) |
| **A-SW-003** CryptoKit unavailable on Linux → swift-crypto | operator — local | resolved (platform fact, S1) |
| **A-SW-004** XCTest vs swift-testing | operator — local | resolved (XCTest; non-blocking) |
| **A-SW-005** swift-asn1 explicit older pin (S11) | operator — local | **resolved** (explicit `exact: "1.7.0"`) |
| **A-SW-006** §7a/§7b GUIDE-carried, not in spec-data | research — track arch open-item | resolved-in-peer |
| **A-SW-007** ⚑ §7.3 vs Appendix E signature preimage | **architecture** | escalated (corroboration; first to surface the §7.3-vs-Appendix-E text tension) |
| **A-SW-008** ⚑ §7.4 vs §1.5 peer-id derivation | **architecture** | escalated (high; 4th-peer corroboration of A-OC-007 / A-ZIG-001) |
| **A-SW-009** §9.5 53-type registry render | operator — local | **RESOLVED** at S4 (53/53 byte-identical) |
| **A-SW-010** ⚑ §4.2/§5.1 "403" vs §5.2a 401/403 | **architecture** | escalated (corroboration of F20 / A-OC-008) |
| §7b bounded-pool / blocking-syscall finding | operator — local | resolved-in-peer (PHASE-S4.md §8; dedicated OS thread for blocking I/O; reusable generator guidance) |

The §7b finding is recorded narratively in PHASE-S4.md §8 (not given its own A-SW number — it is
a Swift-runtime-mechanics defect, not a spec ambiguity). All other items have full entries below.

---

## A-SW-001: Ed448 (key_type 0x02) native gap — DEFERRED

**V7 section:** §1.5 key_type table (0x02 Ed448, canonical hash_type 0x01 SHA-256-form);
§7.3 (Ed448 validated v7.67); §8.1. Crypto-agility *higher bar*, NOT the §9.1 floor.
**Profile field:** `[codec].ed448_library = { name = "DEFERRED", version = "none" }`
**Your guess:** Defer Ed448 at the profile level. The Ed25519 (`key_type 0x01`) + SHA-256
(`content_hash_format 0x00`) §9.1 conformance floor is fully native via swift-crypto and
is unaffected. swift-crypto / BoringSSL does NOT expose Ed448 (BoringSSL omits it;
CryptoKit has no Ed448 surface), and there is no audited pure-Swift Ed448.
**Rationale:** Same gap OCaml hit (A-OC-002, resolved via hybrid FFI) and Zig deferred
(A-ZIG-002). When agility is in scope the likely shape is a **hybrid**: native Ed25519 +
FFI Ed448 consuming `libentitycore_codec` (C-ABI v1.1 `ec_ed448_*`) for the Ed448 family
only — Swift C interop (a C system-library target + module map over `entitycore_codec.h`)
makes this clean. Deferring with a documented escalation beats a silent gap or an
unaudited hand-roll. Does not block the floor.
**Escalation:** research — profile/agility (the OCaml hybrid-FFI pattern is the precedent;
this is the third peer to hit the same Ed448 native gap, reinforcing the cross-peer
finding that no surveyed native crypto stack covers Ed448).

---

## A-SW-002: Swift String is grapheme-counted + non-Int-indexable — wire ops MUST use UTF-8 bytes

**V7 section:** ENTITY-CBOR-ENCODING §2.1 (text string "Length in bytes (UTF-8)"),
§2.2 Rule 2 (map keys "sorted by encoded length, then lexicographically"), §7.4 (peer_id
base58 + lowercase-hex display).
**Profile field:** `[codec].cbor_library` note; `[idiom].utf8_byte_view_for_wire = true`;
`[memory].bytes_type`.
**Your guess:** The codec treats `String` strictly as a UTF-8 carrier. Text-string CBOR
length = `String.utf8.count` (UTF-8 byte count), **never** `String.count` (grapheme
clusters). Map-key lexicographic ordering runs over the **encoded UTF-8 key bytes**
(`[UInt8]` comparison), **never** Swift `String` comparison (Unicode-canonical /
locale-aware). All wire access is via `String.utf8` / `[UInt8]`; never `String`'s
Int-less indexing.
**Rationale:** Swift `String.count` is grapheme clusters and `String` is not random-access
by `Int` — the single defining Swift idiom trap and the reason peer #7 exists (the
unsaturated string/encoding axis; A-CL-009 proved it is live). The S1 spike showed
`"café".count == 4` vs `.utf8.count == 5`. Using `String.count` for a CBOR length or
`String` ordering for map keys would silently diverge from the wire for any non-ASCII
data. This is a generation-discipline guess (how to map the spec's byte-oriented rules
onto Swift's grapheme-oriented String), not a spec ambiguity — but it is the highest-risk
judgment call, so it is logged.
**Escalation:** operator — local decision (codec implementation discipline). NOT a spec
gap; the spec is unambiguous (bytes/UTF-8). Recorded as the headline Swift watch-item +
reusable generator guidance for any future grapheme-string language (Swift, and partially
Elixir's binaries — though Elixir binaries are already byte-oriented).

---

## A-SW-003: CryptoKit unavailable on Linux — swift-crypto is the correct source

**V7 section:** §7.3 (Ed25519 production signing); §1.5 (key_type 0x01); §8.1/§8.2.
**Profile field:** `[codec].ed25519_library`, `[codec].sha256_source`, `[deps].swift_crypto`.
**Your guess:** Use **swift-crypto** (github.com/apple/swift-crypto), NOT CryptoKit.
**Rationale:** The peer builds + runs on Linux (fedora:43 container). CryptoKit is an
Apple-platforms-only framework (Darwin); it does not exist on Linux. swift-crypto is
Apple's open-source, audited, BoringSSL-backed implementation of the *exact CryptoKit API*
supported on Linux — `Curve25519.Signing` (Ed25519, RFC-8032 deterministic),
`SHA256/384/512`. One audited SwiftPM dependency. **Build-proven at S1** (the spike ran
SHA-256/384 + Ed25519 sign/verify correctly in-container). Not really an ambiguity — a
platform fact — but recorded so a future operator does not "reach for CryptoKit."
**Escalation:** operator — local decision (settled at S1; no spec/profile gap).

---

## A-SW-004: XCTest vs swift-testing — chose XCTest

**V7 section:** absent (test-framework choice; conformance harness shape).
**Profile field:** `[testing].framework = "xctest"`.
**Your guess:** Use **XCTest** (toolchain-bundled, dependency-free) for the conformance
harness + behavioral tests, over the newer macro-based **swift-testing**.
**Rationale:** XCTest is the longest-settled, zero-extra-dependency default shipped with
the toolchain (run by `swift test`), keeping the supply-chain stance tight (no version to
age-check beyond the toolchain pin). swift-testing IS bundled with Swift 6.2's toolchain
and is increasingly idiomatic — it clears S11 via the toolchain pin — but XCTest is the
conservative default for a conformance-bearing harness. swift-testing's parameterized-test
ergonomics could win for the corpus-table tests; revisit at S2 if so.
**Escalation:** operator — local decision (revisitable at S2; non-blocking).

---

## A-SW-005: swift-asn1 transitive auto-resolve breaches the S11 30-day cool-down — explicit older pin

**V7 section:** absent (supply-chain / S11 standard).
**Profile field:** `[deps].swift_asn1 = "1.7.0"`; `[layout].resolved_file` (Package.resolved committed).
**Your guess:** Pin swift-asn1 **explicitly to 1.7.0** (~59 days old)
to OVERRIDE SwiftPM's auto-resolution to **1.7.1** (~6 days old), which
**violates the S11 ≥30-day cool-down**. swift-asn1 is a
transitive dependency of swift-crypto 3.14.0 via a version *range*.
**Rationale:** S11 mandates every dependency — transitive included — be pinned to a version
≥30 days old, and a range-resolved transitive dep is the easy place to breach it. Verified
at S1 that the explicit 1.7.0 pin satisfies swift-crypto 3.14.0 and resolves cleanly; the
committed `Package.resolved` then locks both swift-crypto and swift-asn1 by exact revision.
A future re-pin (e.g. when swift-asn1 1.7.1 ages past 30 days, or a CVE forces a newer one)
is deliberate + reviewed, re-applying the rule. This is the S11/keystone payoff in
miniature — a real cool-down breach caught + fixed at profile time.
**Escalation:** operator — local decision (S11 applied as written; logged as the reusable
SwiftPM generator pattern: always explicitly pin range-resolved transitive deps to clear
the cool-down). Worth a research note as cross-peer guidance for any future
range-resolving package manager (SwiftPM, Cargo with caret ranges, npm).

---

## A-SW-006: §7a/§7b conformance scaffolding is GUIDE-carried, not in v7.74 spec-data

**V7 section:** GUIDE-CONFORMANCE.md §7a (validate handlers) + §7b (concurrency gate) —
explicitly NOT in the three normative spec-data files (per the v7.74 MANIFEST note).
**Profile field:** `[spec].conformance_scaffolding = "guide-conformance-7a-7b"`.
**Your guess:** The Swift peer derives its **protocol surface** from spec-data/v7.74, but
picks up the **conformance scaffolding** (the two `system/validate/{echo,dispatch-outbound}`
handlers behind a `--validate`/builder opt-in, off by default; the §7b store
concurrency-safety gate) from `GUIDE-CONFORMANCE.md` + the keystone generator menu at S3/S4
— not from spec-data.
**Rationale:** The v7.74 MANIFEST explicitly flags this split (§7a/§7b live in the
non-normative guide, not the snapshot). A spec-first peer that reads only spec-data would
otherwise MISS the conformance handlers and fail S4. Recorded now so S3/S4 pulls them from
the right source. (Open arch item per the MANIFEST: whether to fold GUIDE-CONFORMANCE into
the spec-data snapshot set or keep it operator-carried — noted, not owned by Swift.)
**Escalation:** research — operator-carried convention; track the arch open-item on whether
GUIDE-CONFORMANCE joins the snapshot set.

---

## A-SW-007: signature corpus signs the ECF preimage, not the content_hash (§7.3 tension) — CORROBORATION

**V7 section:** §7.3 Signature Computation — NORMATIVE: `message = entity.content_hash`
(the full 33-byte hash bytes, format code + digest). ENTITY-CBOR-ENCODING Appendix E
`signature` category: "the 64-byte Ed25519 signature over the **canonical-ECF-encoded
entity**."
**Profile field:** `[codec].ed25519_library` (the signing surface).
**Your guess:** The `signature` conformance vectors (`signature.1/2/3`) sign over the **raw
ECF bytes of `{type, data}`** — the content_hash *preimage* — NOT over the 33-byte
content_hash. The Swift harness signs `ContentHash.ecfOfEntity(type:data:)` to match the
corpus (the conformance ground truth, S5). Signing over the content_hash instead produced
3/3 byte-MISMATCHES; signing over the ECF preimage produced 3/3 byte-IDENTITY.
**Rationale:** This is **not a fresh Swift discovery** — it is the cross-peer convention the
FFI rust/c impls + the Go/Rust/Py oracle cohort locked at corpus-v1
(the FFI-RUST first-pass session note #3 states verbatim:
"`signature` is Ed25519 over `ECF(entity)` — **not over the content_hash**"; the C-FIRST-PASS
note #3 and the SESSION-HANDOFF "6 codec-correctness facts" repeat it). Swift is the **7th
independent peer** to arrive at it and the first to surface the §7.3-vs-Appendix-E **textual
tension** explicitly in its own log: §7.3's pseudocode says `message = entity.content_hash`,
while the normative Appendix E corpus (which supersedes Appendix A as the conformance gate,
§E preamble) signs the ECF. These are not the same bytes. The two are reconcilable only if
"sign the entity" is read as "sign the entity's canonical encoding" and §7.3's
`entity.content_hash` is treated as illustrative shorthand, not literal. The corpus wins
(S5: oracle is ground truth); §7.3's prose is the loser and should be tightened.
**Escalation:** arch — spec needs clarification. §7.3 NORMATIVE pseudocode (`message =
entity.content_hash`) literally contradicts the normative Appendix E `signature` vectors
(`message = ECF({type,data})`). Recommend §7.3 be amended to state the signed message is the
ECF encoding of `{type, data}` (the content_hash *preimage*), or explicitly cross-reference
that the conformance corpus signs the preimage. Low-severity (every peer already builds to
the corpus, so no interop break) but it is a real normative-text contradiction the keystone
should surface — exactly the spec-quality-crawler payoff.

---

## A-SW-008: §7.4 NORMATIVE peer-id derivation contradicts §1.5 canonical-form table — CORROBORATION

**V7 section:** §7.4 (Peer ID Derivation — NORMATIVE), §1.5 (Identity canonical-form
table, v7.65), §9.1 floor bullet "Peer ID derivation (§7.4)".
**Profile field:** `[codec].ed25519_library`; `PeerID.fromEd25519` / `Identity`.
**Your guess:** Construct the Ed25519 peer_id per the **§1.5 canonical-form table**:
`Base58(varint(0x01) ‖ varint(0x00) ‖ public_key)` — `hash_type = 0x00`
identity-multihash, the digest **IS** the raw 32-byte public key (v7.64/v7.65). NOT
`SHA-256(public_key)`.
**Rationale:** §7.4's v7.74 text now opens "See §1.5 canonical-form per `key_type`
table — this algorithm defers to that table," and its pseudocode dispatches
`hash_type = canonical_hash_type(key_type)` → `0x00` for Ed25519, `digest =
public_key`. So the *current* §7.4 body is reconciled with §1.5. BUT: (a) the §9.1
MUST-implement floor still cites the bullet by the bare number "Peer ID derivation
(§7.4)", and (b) §7.4 retains a "NORMATIVE" stamp that historically (pre-v7.64) read
as the SHA-256-of-pubkey form, which is now only a decode-time wire-acceptance
carve-out (§1.5 Amendment 4/D), explicitly **NOT a valid construction form for
v7.65+**. A spec-first reader who lands on the §9.1 "§7.4" pointer first, or recalls
the pre-v7.64 §7.4 prose, can still construct the wrong (SHA-256) form. The canonical
construction lives in §1.5; §7.4 is derived. This is the **fourth peer** to surface
the §7.4-vs-§1.5 peer-id tension independently — OCaml **A-OC-007** (headline,
§7.4-vs-§1.5), Zig **A-ZIG-001**, and the C#/TS ports all arrived at identity-multihash;
Swift (spec-first on the v7.74 surface) corroborates. Strong convergence signal that
§7.4's NORMATIVE stamp + the §9.1 floor pointer should be re-pointed at §1.5 (make §1.5
the canonical home, §7.4 explicitly REFERENCE-deferring) so the construction form is
unambiguous from any entry point.
**Escalation:** arch — spec needs clarification. Recommend: (1) demote §7.4 from
NORMATIVE to REFERENCE (it already defers to §1.5), or annotate that the *construction*
contract is §1.5 and §7.4 is the illustrative wrapper; (2) re-point the §9.1 floor bullet
"Peer ID derivation" to **§1.5** (canonical) rather than §7.4. No behavioral change — the
cohort + all keystone peers already build to identity-multihash; this is a spec-text
discoverability fix. Mirrors A-OC-007.

---

## A-SW-009: full §9.5 53-type registry render DEFERRED to S4 — **RESOLVED (S4)**

**RESOLUTION:** The full 53-type render landed at S4 (`TypeRegistry.swift` — the FSpec/TypeDef
render-from-model builder, the cross-blessed C#/TS/OCaml/Zig design). Byte-diffs **53/53
byte-identical** to the Go reference vectors (`type-registry-vectors-v1.cbor`) — verified offline by
`TypeRegistryTests` (`swift test`) AND live by the `type_system` conformance category (108/108 PASS).
First-run clean (the S2 byte-green codec meant the only risk was field-shape data, caught per-type by
the digest diff). Swift 6 strict concurrency required `FSpec`/`TypeDef`/`FSpecBox` to be `Sendable`
for the static `allTypes` table (`FSpecBox` = a `final class Sendable` with an immutable `let value`).
No spec ambiguity surfaced — a phase-scoping deferral, now closed. The original S3 deferral text:

---



**V7 section:** §9.5 Core Type Floor Manifest (53 types); §9.0 `type_system` category.
**Profile field:** absent (S3/S4 phase-scoping decision).
**Your guess:** S3 wires the **render-from-model seam** (`TypeRegistry.swift`: declare
→ render via the byte-green S2 codec → publish at `/{peer}/system/type/{name}`) and
seeds a **minimal representative subset** (~16 of the 53 — the types dispatch +
discovery-floor reads exercise). The full 53-type field-spec render + the byte-diff
against the Go reference type-registry vectors (the S8 drift target) is **deferred to S4**.
**Rationale:** The smoke + S3 exit need only that `system/type/*` reads resolve and the
publication path is live; the precise field-spec carriers (`array_of`/`map_of`/
`union_of`/`optional`/omit-empty) for byte-identity are the `type_system` conformance
concern, landed at S4 with the oracle byte-diff in hand. Deferring with the seam in
place (not a stub) matches **Zig A-ZIG-008** and OCaml's S4 type-land exactly — a phase
deferral, not a guess. The minimal seed publishes valid `system/type` entities; S4
swaps the subset for the full 53 + runs the diff.
**Escalation:** operator — local decision (phase scoping; S4 completes it). Tracked as
the top S4-entry precursor.

---

## A-SW-010: §4.2/§5.1 "missing auth fields → 403" vs §5.2a "Author absent → 401" — built to §5.2a

**V7 section:** §4.2 (Pre-Authorization Rules — "EXECUTE targeting any other path
without auth fields MUST be rejected (status 403)"), §5.1 ("Peers MUST reject requests
missing either [author/capability] with status 403"), §5.2a verdict-to-status table
("Request-time §5.2 step 2 — Author absent → **401** authentication_failed").
**Profile field:** absent.
**Your guess:** Build to **§5.2a** — a request-time EXECUTE on a non-connect path with
**author absent** → **401 authentication_failed** (auth-class), and **capability
absent** (author present + signed) → **403 capability_denied** (authz-class). The
§5.2a enumeration is the v7.73 load-bearing table that explicitly splits the auth(401)/
authz(403) boundary; it post-dates and refines §4.2/§5.1's flat "403".
**Rationale:** §5.2a is the normative enumeration that absorbed RULING-F14 (the
auth-vs-authz boundary three peers independently converged on); it is the single source
of truth for the (status, code) tuple per §5.2's own pointer. §4.2 and §5.1 predate it
and say a flat "403" for "missing auth fields", conflating the author-absent (can't
authenticate → 401) and capability-absent (authenticated but no authority → 403) cases
that §5.2a separates. A spec-first reader landing on §4.2/§5.1 first would build the
wrong status for author-absent. The cohort's `security`/`authz` categories assert the
§5.2a tuples, so §5.2a wins.
**Escalation:** arch — spec consistency. Recommend §4.2 and §5.1 cross-reference §5.2a
for the per-field status split (or soften their "403" to "per §5.2a") so the three
surfaces don't read as contradicting. Low interop risk (§5.2a is the gate), real
spec-text tension. Likely already latent in prior peers' logs under the F14/A-OC-008
auth/authz-boundary finding; Swift surfaces the §4.2/§5.1-vs-§5.2a *text* tension
specifically.
