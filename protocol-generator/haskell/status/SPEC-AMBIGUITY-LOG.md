# entity-core-protocol-haskell — Spec Ambiguity Log

Every guess / judgment call made while generating the Haskell peer (peer #8). Format per
PROMPT-CONSTANTS.md S3. Items escalate to architecture as proposal candidates via
`research/stewardship/`. **No silent guesses.**

`A-HS-NNN` convention. Severity: a **blocking** item halts the dependent phase; the rest
are recorded decisions / escalations. **No blocking items at S1 exit.**

---

## S1 exit — owner + escalation status

| Item | Owner | Status |
|---|---|---|
| **A-HS-001** Pure `Either CodecError a`; IO exceptions edge-only | operator — local | resolved (Haskell idiom; error axis low-yield) |
| **A-HS-002** Lazy-eval / strictness discipline in a byte-exact codec | operator — local | **RESOLVED at S2 with concrete evidence** (below) — strictness is space-safety + 1 UTF-8 string-length correctness trap; no surprising lazy-eval wrong-bytes hazard |
| **A-HS-008** Agility `decode_reject` codes are a peer/validate policy, not codec | operator — local | resolved (informational; codec encodes the multi-byte varint, rejection of unallocated §1.2 codes is S4) |
| **A-HS-003** Concurrency = green-threads + STM (TVar) | operator — local | resolved (S3 decision; codec is pure/sync) |
| **A-HS-004** hspec vs tasty vs HUnit | operator — local | resolved (hspec; non-blocking, revisitable at S2) |
| **A-HS-005** cabal-offline mechanics (cold-store index lookup) | operator — local | resolved-at-S1 (warm-store + committed freeze + pinned index-state) |
| **A-HS-006** §7a/§7b GUIDE-carried, not in spec-data | research — track arch open-item | resolved-in-peer (pick up at S3/S4) |
| **A-HS-007** Ed448 NATIVE (crypton) — first native-full-agility peer | research — agility ledger | **resolved / data point** (no defer, no FFI — distinct crypto outcome) |

### S3 exit

| Item | Owner | Status |
|---|---|---|
| **A-HS-009** §9.5 53-type render-from-model: seam + minimal seed at S3, full byte-exact render + byte-diff → S4 | operator — local | **RESOLVED at S4** (below) — full 53-type registry rendered from the in-code model; 53/53 content_hash byte-identical to the Go vectors first run; `type_system` 0 FAIL |
| **A-HS-010** entity-native dispatch evaluates minimal `compute/literal` (the §10.1 round-trip half) — compute vocab in the core path | research — track arch (mirrors A-011/A-OC-010) | recorded (harmless; **no longer gate-exercised** — the §10.1 round-trip now runs through §7a `validate_echo_dispatch`; kept until Go drops it, no flag-day) |
| **A-HS-011** `--seed-policy <file>` JSON parse is the next increment; in-code builders are the S3 floor | operator — local | recorded (cohort-aligned; S5 increment) |
| **A-HS-012** S3 transport deps (`network`/`stm`/`time`/`containers`) pinned in the committed freeze at the pinned index-state | operator — S11 re-pin audit | recorded (LTS-snapshot floor + pinned index-state; confirm `network 3.2.8.0` clears the 30-day floor at re-pin) |

### S4 exit — `validate-peer --profile core` PASS, 0 FAIL

| Item | Owner | Status |
|---|---|---|
| **A-HS-009** §9.5 53-type registry render | operator — local | **RESOLVED** — see below |
| **A-HS-007** Ed448 NATIVE — agility-availability data point | research — agility ledger | **CONFIRMED live at S4** — `crypto_agility key_type_ed448_1` PASS in the core gate with zero FFI; full agility corpus (Ed448 + SHA-384 KATs) runs in-process, no opt-in sub-library (the only such peer). See A-HS-007 update below. |

No new `⚑` spec-text-tension item surfaced at S4 (coverage peer, expected): the
peer-id §7.4→§1.5 reconciliation, the §4.6 401/403 boundary (the ROLE `authz_revoked`
carve-out passing via `authz_revoked_core_1`), and the §PR-8/§5.5a granter frame all
landed consistently with the cohort against the LIVE oracle — an 8th independent
corroboration, not a discovery. **0 peer-correctness fixes; 1 oracle iteration to PASS.**

No new `⚑` spec-text-tension item surfaced at S3 (coverage peer, expected): the
peer-id §7.4→§1.5 reconciliation, the §4.6 401/403 boundary, and the §PR-8/§5.5a
granter-frame shape all landed consistently with the cohort — an 8th independent
corroboration, not a discovery.

No `⚑` spec-text-tension items surfaced at S1: reading v7.74 directly found the peer-id
§7.4-vs-§1.5 tension (OCaml A-OC-007 / Zig A-ZIG-001 / Swift A-SW-008) **already reconciled in
the v7.74 §7.4 body** (the E1 erratum — §7.4 now defers to the §1.5 table), so Haskell
corroborates the *reconciliation* (a 5th read landing on a consistent §7.4 → §1.5) rather than
re-surfacing a contradiction. Codec/peer-build-time findings (hex-case A-CL-009 neighborhood,
the auth/authz 401/403 boundary) are not S1-profile-visible; they re-evaluate spec-first at S2/S4.

---

## A-HS-001: pure codec = `Either CodecError a`; IO exceptions only at the transport edge

**V7 section:** absent (error-model idiom; the protocol pins *status codes* 400/401/403, not a
host-language error mechanism).
**Profile field:** `[error_model].style = "either"`, `error_type = "CodecError"`,
`pure_codec = true`, `io_exceptions_at = "transport-boundary-only"`.
**Your guess:** The pure codec is a total function returning `Either CodecError a` (threaded by
`do`-notation in the `Either` monad); decode/encode failures are *values* (constructors of
`CodecError`), never thrown exceptions. `Control.Exception`/`throwIO`/`bracket` appear ONLY at
the impure S3 transport boundary (sockets/IO). Protocol-status failures map a
`CodecError`/verdict constructor → status code (400 non_canonical_ecf / 401 / 403) at the
module boundary.
**Rationale:** `Either e a` is THE idiomatic Haskell pure-error shape; a pure codec has no IO,
so an exception path would be un-idiomatic (and impossible without `unsafePerformIO`/`error`,
which we forbid on wire data — `no_partial_on_wire`). This converges in SHAPE with OCaml's
`result` (Either-like ADT — the error axis is low-yield and shown idiom-neutral across the
cohort), but is arrived at independently and is *stronger*: OCaml catches a decode-path
exception at the boundary; the Haskell codec has no exception path at all.
**Escalation:** operator — local decision (host-language idiom; no spec/profile gap). Recorded
because it is the primary error-model judgment call.

---

## A-HS-002: lazy-evaluation / strictness discipline in a byte-exact codec — THE headline impl-watch-item

**V7 section:** ENTITY-CBOR-ENCODING §2.2 Rule 2 (map keys "sorted by encoded length, then
lexicographically"), Rule 4 (shortest float), §2.1 (text string "Length in bytes (UTF-8)"),
§4 (raw-byte fidelity). The spec is byte/UTF-8-explicit; this is a host-language mapping call.
**Profile field:** the entire `[memory]` section + `[idiom].prefer_strict_bytestring`,
`force_at_accumulation`, `utf8_byte_view_for_wire`, `language_pragmas` (StrictData/BangPatterns).
**Your guess:** Defeat Haskell's default laziness deliberately wherever bytes accumulate or
determinism matters: (1) strict `Data.ByteString` on the wire path (NOT lazy `ByteString`); the
encoder emits via `Data.ByteString.Builder` and forces to a strict `ByteString`. (2)
`Data.Text` for text strings, with the CBOR text-string length = UTF-8 byte count via
`Data.Text.Encoding.encodeUtf8` — **never** `Text` length (code points). (3) `BangPatterns` /
`seq` / `$!` / strict data fields (`!Field`, `StrictData` pragma) wherever bytes/lengths
accumulate — the map-key length sort, the byte-length fold, the digest input, and decode
position threading are forced; no lazy thunk reaches the wire. (4) `deepseq`/`force` decoded
structures at the API edge before they enter long-lived store state.
**Rationale:** Haskell is lazy by default (every binding is a thunk until forced) — the defining
idiom seam, unique among all 8 peers. In a byte-exact codec a lazily-accumulated buffer can
build a space-leaking thunk chain, and a non-forced fold can defer evaluation in ways that
(while pure) blow the stack or mis-time strictness. This is the ONE place an *implementation*
finding (not a spec finding) could surface from peer #8. **Where it bites (S2 watch-item):**
encoder accumulation, the map-key length sort, decode position threading. QuickCheck round-trip
+ strictness properties (encode∘decode == id; no leaking thunk) are layered at S2 as robustness
insurance.
**Escalation:** operator — local decision (codec implementation discipline; the spec is
unambiguous that lengths/ordering are byte/UTF-8-oriented). Recorded as the **headline Haskell
watch-item** + reusable generator guidance for any future lazy/non-strict language. NOT a spec
gap.

### S2 RESOLUTION — concrete evidence

Built the codec under the full discipline and **probed each hazard concretely** (a probe, not
precaution). Findings:

1. **The ONE genuine correctness trap is the UTF-8 byte-length vs code-point-length confusion,
   and it is a STRING-LENGTH bug, not strictly a laziness bug.** Probe: the string `"héllo☃"` has
   **6 code points but 9 UTF-8 bytes** (`é` = 2 bytes, `☃` = 3). The encoder MUST (and does) emit
   the CBOR text head with length **9** via `Data.Text.Encoding.encodeUtf8` then `BS.length`. A
   naive `Data.Text.length` — the obvious Haskell call — emits **6**, a silently corrupt wire form
   + wrong content_hash. This is the loud flag for any future `Text`-carrying peer. Enforced in
   `EntityCore.Codec.CBOR.buildValue (VText t)`.
2. **No surprising lazy-eval *wrong-bytes* hazard exists in the codec.** A fully-lazy encoder would
   still produce byte-identical output (encoding is pure). The strictness work
   (strict `ByteString` accumulator forced via `BL.toStrict`; map-sort keys bang-materialised
   before `sortBy`; strict decode cursor + `StrictData` fields; `deepseq` at the edge) is a
   **space-leak / determinism-hygiene** discipline: without it the encoder retains the unencoded
   `Value` tree through the fold and re-forces encoded keys during the sort (a leak), but the bytes
   are still right. Verified: a 5000-key map encodes + forces cleanly; the QuickCheck
   `encode (force v) == encode v` property holds over 100 cases (output is thunk-timing-independent).
3. **Net A-HS-002 verdict:** "strictness = space-safety + determinism, plus one UTF-8 string-length
   correctness trap." Reusable generator guidance for any lazy/non-strict language: (a) text wire
   length is ALWAYS `encodeUtf8`-bytes, never the language's string length; (b) force the encode
   accumulator; (c) materialize map-sort keys strictly. The "implementation finding peer #8 could
   surface" surfaced as expected — a discipline + one trap — not a latent wrong-bytes bug.

---

## A-HS-008: agility `varint`/`format-code` `decode_reject` codes are a peer/validate policy, not codec

**V7 section:** §1.2 (`content_hash_format` seed table), §1.5 (`key_type` seed table) — the set of
*allocated* codes is a policy table.
**Profile field:** `[spec].codec_corpus` ("Agility corpus IN SCOPE").
**Your guess:** The 3 agility `decode_reject` probes (`varint-multibyte.1` code 128,
`varint-reserved-ff.{1,2}` code 255, `format-code-interpretation.1` code 0x42) assert
`unsupported_content_hash_format` / `unsupported_key_type` — a **peer/validate-layer** responsibility,
NOT a codec one. The S2 codec's `contentHash` faithfully encodes the multi-byte LEB128 varint prefix
and computes the digest for any code (defaulting unknown codes to SHA-256); *rejecting* an unallocated
code per the §1.2/§1.5 seed table is an S4 surface. The codec-reachable agility crypto vectors (Ed448
pubkey/peer_id/entity/signature + SHA-384 content_hash) ARE exercised at S2 (7/7 native PASS).
**Rationale:** The codec is a total pure transform; the seed-table allocation policy is mint/validate
behavior. Pinning the multi-byte varint *decoder existence* (the actual codec invariant N1) is done by
`peer_id.3`/`content_hash.4` in the main corpus. Recorded so S4 wires the unallocated-code rejection at
the right layer rather than forcing the codec to carry the seed table.
**Escalation:** operator — local decision (layer placement; informational). Non-blocking.

---

## A-HS-003: concurrency = GHC green threads + STM (TVar) — a 3rd data-race-free store shape

**V7 section:** §4.8 / §6.11 (inbound concurrent with outbound; reentry), §6.13b (handler
outbound closure), GUIDE-CONFORMANCE §7b (store concurrency-safety gate). Not exercised by the
codec (S2 is pure/synchronous).
**Profile field:** `[concurrency].style = "green-threads-stm"`, `primitive = "STM (TVar) +
forkIO"`, `structured = "async library"`, `race_free_shape = "STM-transactional"`.
**Your guess:** At the peer (S3) the live store is a `TVar` (or a small set of `TVar`s) mutated
inside `atomically`; one `forkIO` green thread per connection; request_id↔continuation
correlation via an `MVar`/`TVar` demux map; the `async` library (`withAsync`/`race`/
`concurrently`) for structured concurrency. The codec stays pure + synchronous.
**Rationale:** GHC green threads + STM are the idiomatic Haskell concurrency story. STM gives a
**3rd data-race-free store shape** after the Elixir actor (message-serialized) and the Swift
actor (await-serialized) — here *transactional* (composable, lock-free, retry-based) — the
natural §7b-gate target. Recorded now; final shape decided at S3 (where the §7b concurrency gate
runs).
**Escalation:** operator — local decision (S3 concurrency design; codec unaffected).

---

## A-HS-004: hspec vs tasty vs HUnit — chose hspec

**V7 section:** absent (test-framework choice; conformance harness shape).
**Profile field:** `[testing].framework = "hspec"`, `property_testing = "quickcheck-optional"`.
**Your guess:** Use **hspec** (the RSpec-style `describe`/`it` standalone framework, in the
pinned Stackage LTS 23.27 set) for the conformance harness + behavioral tests, over **tasty**
(a test-tree framework hosting HUnit/QuickCheck/hspec providers) and bare **HUnit**. Layer
**QuickCheck** property tests (round-trip + strictness) at S2.
**Rationale:** hspec is the single most-used standalone Haskell test framework, reads cleanly for
corpus-table conformance assertions, and clears S11 via the LTS snapshot pin (no separate
age-audit). tasty is the documented alternative if a multi-provider tree (HUnit + QuickCheck +
hspec together) is wanted at S4. QuickCheck is a strong fit for the A-HS-002 lazy-eval robustness
probe.
**Escalation:** operator — local decision (revisitable at S2; non-blocking).

---

## A-HS-005: cabal `--network=none` cold-store index lookup — warm-store + committed freeze is the offline path

**V7 section:** absent (S1 container / S11 reproducibility mechanics).
**Profile field:** `[container].offline_after_resolve = true`; `[layout].freeze_file`.
**Your guess:** The S2 offline build loop pre-populates the cabal store on a single networked
resolve (`cabal build` / `cabal run` with network on), commits `cabal.project.freeze` + a pinned
`index-state`, and thereafter builds against the **warm store** (`cabal build --offline`); the
**compiled artifact** runs fully `--network=none`. A *cold-store* `cabal build` still consults
the remote Hackage index (cabal refreshes the package index / mirror list), so `--network=none`
on a cold store fails — that is cabal mechanics, not a dependency gap.
**Rationale:** Proven at S1: the throwaway crypton spike compiled with network on, and the
**built binary re-ran under `--network=none` green**; a fresh `cabal build --offline` on a clean
store tried to reach `hackage.haskell.org` (DNS refused → fail) because the index lookup precedes
the store hit. The committed freeze + pinned index-state + warm store is the deterministic offline
recipe (the cabal analog of Swift's "commit Package.resolved + populate .build"). The codec build
itself needs no network once the store is warm.
**Escalation:** operator — local decision (S1-resolved; recorded as the reusable Cabal-peer
offline pattern: resolve-once-then-warm-store, not "every build offline"). Non-blocking.

---

## A-HS-006: §7a/§7b conformance scaffolding is GUIDE-carried, not in v7.74 spec-data

**V7 section:** GUIDE-CONFORMANCE.md §7a (validate handlers) + §7b (concurrency gate) —
explicitly NOT in the three normative spec-data files (per the v7.74 MANIFEST note).
**Profile field:** `[spec].conformance_scaffolding = "guide-conformance-7a-7b"`.
**Your guess:** The Haskell peer derives its **protocol surface** from spec-data/v7.74, but picks
up the **conformance scaffolding** (the two `system/validate/{echo,dispatch-outbound}` handlers
behind a `--validate`/builder opt-in, off by default; the §7b store concurrency-safety gate) from
`GUIDE-CONFORMANCE.md` + the keystone generator menu at S3/S4 — not from spec-data.
**Rationale:** The v7.74 MANIFEST explicitly flags this split (§7a/§7b live in the non-normative
guide, not the snapshot). A spec-first peer reading only spec-data would otherwise MISS the
conformance handlers and fail S4. Recorded now so S3/S4 pulls them from the right source. The §7b
gate is a natural fit for the STM store shape (A-HS-003). (Open arch item per the MANIFEST:
whether to fold GUIDE-CONFORMANCE into the spec-data snapshot set or keep it operator-carried.)
**Escalation:** research — operator-carried convention; track the arch open-item on whether
GUIDE-CONFORMANCE joins the snapshot set (same item Swift A-SW-006 flagged).

---

## A-HS-007: Ed448 is NATIVE via crypton — Haskell is the FIRST native-full-agility peer (data point)

**V7 section:** §1.5 key_type table (0x02 Ed448, canonical hash_type 0x01 SHA-256-form); §7.3
(Ed448 validated v7.67); §8.1. Crypto-agility *higher bar*, ABOVE the §9.1 floor (key_type 0x01
Ed25519 + content_hash_format 0x00 SHA-256).
**Profile field:** `[codec].ed448_library = { name = "crypton Crypto.PubKey.Ed448", version =
"1.0.4", strategy = "native" }`; `[spec].codec_corpus` note ("Agility corpus IN SCOPE").
**Your guess:** Source Ed448 (`key_type 0x02`) NATIVELY from crypton `Crypto.PubKey.Ed448` — NOT
deferred, NOT FFI. The crypto-agility higher bar (Ed448 + SHA-384) is reachable in-band for this
peer, so the agility corpus is in scope (no A-SW-001-style gate).
**Rationale:** **Build-proven at S1** — the crypton spike ran an Ed448 sign/verify round-trip
returning True (57-byte pubkey, 114-byte signature, RFC-8032 deterministic), from the SAME audited
C-backed library as Ed25519, with no FFI and no separate dependency. This is a distinct point on
the cross-peer crypto-availability ledger: OCaml hit the Ed448 native gap (A-OC-002 → hybrid FFI),
Zig deferred (A-ZIG-002), Swift deferred (A-SW-001), and Common Lisp had pure-Lisp Ed448
(ironclad, KAT-gated). Haskell is the **first peer with native full agility incl. Ed448 from an
audited C-backed library**. Not really an ambiguity — a capability fact — but recorded as the
crypto data point that distinguishes peer #8 and feeds the agility-availability synthesis.
**Escalation:** research — agility ledger (the cross-peer crypto-availability finding; Haskell is
the native-full-agility data point alongside OCaml/Zig/Swift's gap and CL's pure-lang impl).

### S4 CONFIRMATION

Confirmed live against the oracle: `crypto_agility` 4/4 + `format_agility` 10/10 PASS under
`--profile core`, incl. **`key_type_ed448_1` PASS (not SKIP)**. The shipped core peer
needs **no agility sub-library at all** — Ed448 + SHA-384 are in the same crypton import as
Ed25519/SHA-256, and `test/AgilitySpec.hs` runs the full Ed448 sign/verify KATs in-process
(25/25, unregressed). HONEST SCOPE: the oracle's `crypto_agility` category is also satisfied
by the FFI-deferred peers (Zig's report shows `key_type_ed448_1` PASS too) — that check
exercises peer-id/key-type string handling at the protocol surface, not a live core-gate
Ed448 signature. The native-vs-FFI distinction lives at the test-corpus / library-availability
layer (where the agility ledger tracks it), not in the `--profile core` scoreboard. The data
point stands: Haskell is the only peer with native full agility and no opt-in sub-library.

---

## A-HS-009: §9.5 53-type registry render — seam + minimal seed at S3, full render deferred to S4

**V7 section:** §9.5 (the 53 core types), §3.9 (type-registry render).
**Profile field:** absent (render-from-model is a cross-peer ruling, not a profile field).
**Your guess:** S3 wires the render-from-model SEAM (`EntityCore.TypeDefs.publish` over an
in-code `coreTypes` model list, through the native S2 codec) + a MINIMAL core-type seed (the 8
primitives + the system types the connect/discovery surface references) so the tree is non-empty
and discovery works. The full §9.5 53-type byte-exact render + the type-registry byte-diff is
deferred to S4 — it is a render-table port (more rows into the same seam), not new protocol
machinery, and the byte-diff gate belongs with the validate-peer `type_system` category.
**Rationale:** Mirrors Swift A-SW-009 / the OCaml `type_defs_data` table. The seam is the single
edit-point: dropping the full 53-entry model list into `coreTypes` lights up the publisher + diff
unchanged. Carrying the full table at S3 would front-load a mechanical port with no smoke-surface
payoff.
**Escalation:** operator — local (S4 work item; non-blocking).

### S4 RESOLUTION

`src/EntityCore/TypeDefs.hs` rewritten into the full render-from-model registry: an
`FSpec`/`TypeDef` builder (`type_ref` / `array_of` / `map_of` / `union_of` / `key_type` /
`byte_size` carriers, omit-empty; `name` / `extends` / `fields` / `layout`) with the **53
core types declared in code** (faithful port of the cross-blessed C#/TS/OCaml/Zig
enumeration). `publish` renders each as a `system/type` entity through the byte-green S2
codec and binds it at `/{peer}/system/type/{name}`.

A build-time byte-diff (`test/TypeRegistrySpec.hs`, in the conformance suite) renders all
53 and compares each `content_hash` digest against the canonical Go-rendered
`type-registry-vectors-v1.cbor` set → **53/53 byte-identical on the first run** (the codec
being byte-green at S2 left field-shape data as the only risk; the omit-empty + canonical
key-sort matched the Go encoder first try). Live: `type_system` 108 PASS / 194 WARN / 0
FAIL under `--profile core` (a core peer publishes only the §9.5 floor; non-floor probes
WARN matched-if-present, refined G4 / F17). **RESOLVED.**

---

## A-HS-010: entity-native dispatch evaluates the minimal `compute/literal` body (compute vocab in the core path)

**V7 section:** §6.13(a) (dynamic register → dispatch), §10.1 (the register round-trip gate),
GUIDE-CONFORMANCE §7a (the A-011 resolution).
**Profile field:** absent.
**Your guess:** A dynamically-registered handler with no in-process body evaluates its
`expression_path` body; the minimal `compute/literal` shape returns a `compute/result` (the §10.1
round-trip shape), richer bodies → 501. This pulls the `compute/literal`/`compute/result` vocab
into the core dispatch path.
**Rationale:** Identical to OCaml A-OC-010 and the cohort-wide A-011. The unified §7a resolution
replaces the §10.1 `compute/literal` round-trip with the native `system/validate/echo` dispatch —
so this evaluator is no longer gate-exercised. Kept (harmless) until Go drops it, to avoid a
flag-day; the §7a echo handler is the real resolve→dispatch proof.
**Escalation:** research — track the arch close (the §7a/§10.1 cleanup; mirrors A-011).

---

## A-HS-011: `--seed-policy <file>` JSON parse is the next increment; in-code builders are the S3 floor

**V7 section:** §6.9a (Peer Authority Bootstrap), keystone `shared/seed-policy/` convention.
**Profile field:** absent (the builder shape is per-language idiom).
**Your guess:** S3 ships the in-code `SeedPolicy` builders (`standardPolicy` = the §4.4 floor;
`SeedPolicyDebugOpen` = the degenerate `default → *`) wired through the real §6.9a mechanism
(owner cap at L0 + dual-form authenticate lookup). The `--seed-policy <file>` JSON parse of the
shared schema is the forward shape, not the S3 floor.
**Rationale:** Exactly the cohort's S3 position (C#/TS/OCaml all shipped the in-code builders, with
file-parse the next increment). The CLI flag + builder API are present; only the JSON loader is
deferred.
**Escalation:** operator — local (S4/S5 increment; non-blocking).

---

## A-HS-012: S3 transport deps — `network`/`stm`/`time`/`containers` pinned at the index-state

**V7 section:** absent (S11 supply-chain / S1 container mechanics).
**Profile field:** `[deps]`; `[layout].freeze_file`.
**Your guess:** S3 adds `network 3.2.8.0`, `stm 2.5.3.1`, `time 1.12.2`, `containers 0.6.8` (the
peer's TCP transport + STM store + clock + maps). All are pinned in the committed
`cabal.project.freeze` regenerated at the pinned index-state (the same pinned
Hackage snapshot as S2). `stm`/`time`/`containers` are GHC-boot / LTS-23.27 libs; `network` is the
one non-boot socket dep, which the pinned index-state selects at `3.2.8.0`. The peer remains
self-contained (no system packages; `network` builds via its bundled Configure).
**Rationale:** The OCaml peer used stdlib `Unix`+`Thread` (zero extra dep); Haskell's idiomatic
socket layer is `network` (in LTS 23.27), so it is the right pin — the cost is one non-boot dep.
The pinned index-state IS the age floor (the cleanest S11 answer per A-HS-005): no per-dep manual
audit, the snapshot date caps every selectable version.
**Escalation:** operator — S11 re-pin audit (confirm `network 3.2.8.0` clears the ≥30-day floor at
the next deliberate re-pin; the index-state already bounds it ≤ the LTS snapshot).

---

## S5 finalization — every item tagged; nothing untagged

S5 publish gate: the ambiguity log is finalized — each item carries an owner + a
resolved/deferred/escalated status. **No NEW spec finding escalates from peer #8** (the 8th,
pure-functional/lazy corroboration peer): the peer-id §7.4→§1.5 reconciliation, the §4.6 401/403
boundary, and the §PR-8/§5.5a granter frame all landed consistent with the cohort against the
live oracle — an 8th independent corroboration, not a discovery.

| Item | Owner | Final status |
|---|---|---|
| **A-HS-001** pure `Either CodecError a`; IO exceptions edge-only | operator — local | **resolved** (Haskell idiom; stronger than OCaml `result` — no codec exception path at all) |
| **A-HS-002** lazy-eval / strictness in a byte-exact codec | operator — local | **resolved at S2** — purity ⇒ codec laziness-immune; one UTF-8 string-length trap; strictness = space-safety + determinism. Reusable lazy-language guidance recorded |
| **A-HS-003** STM + green-threads concurrency | operator — local | **resolved** — §7b gate 5/5 structural at S4 (3rd data-race-free store shape) |
| **A-HS-004** hspec vs tasty/HUnit | operator — local | **resolved** (hspec) |
| **A-HS-005** cabal offline mechanics | operator — local | **resolved** (warm-store + committed freeze + pinned index-state; re-proven sealed-offline at S5) |
| **A-HS-006** §7a/§7b GUIDE-carried, not in spec-data | research — track arch open-item | **resolved-in-peer** (picked up at S3/S4; arch open-item whether GUIDE-CONFORMANCE joins the snapshot — same as Swift A-SW-006) |
| **A-HS-007** Ed448 NATIVE via crypton — first native-full-agility peer | research — agility ledger | **resolved / data point** — confirmed live at S4 (`crypto_agility` PASS, no FFI, no opt-in sub-library) |
| **A-HS-008** agility decode-reject codes are peer/validate policy, not codec | operator — local | **resolved** (informational; layer placement) |
| **A-HS-009** §9.5 53-type render-from-model | operator — local | **RESOLVED at S4** (53/53 content_hash byte-identical to the Go vectors, first run) |
| **A-HS-010** entity-native dispatch evaluates minimal `compute/literal` | research — track arch (mirrors A-011/A-OC-010) | **recorded / deferred** — no longer gate-exercised after the §7a resolution; harmless, kept until Go drops it (no flag-day) |
| **A-HS-011** `--seed-policy <file>` JSON parse | operator — local | **recorded / deferred** — in-code builders are the floor; file-parse is the next increment (cohort-aligned) |
| **A-HS-012** transport deps pinned at index-state | operator — S11 re-pin audit | **recorded / deferred** — confirm `network 3.2.8.0` clears the 30-day floor at the next deliberate re-pin; index-state already bounds it |

**Escalated to architecture (carried, not blocking):** A-HS-006 (GUIDE-CONFORMANCE snapshot
question), A-HS-007 (cross-peer agility-availability ledger data point), A-HS-010 (the §7a/§10.1
`compute/literal` cleanup, mirrors A-011). All others are operator-local, resolved or a recorded
deferral. **No blocking items at S5 exit.**
