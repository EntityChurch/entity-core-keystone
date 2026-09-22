# SQL peer — Spec Ambiguity / Findings Log

Per PROMPT-CONSTANTS: every guess goes here; no silent guesses. This is also where the
**authority-as-query expressibility findings** land as S3 authors the interior — those are
the probe's primary deliverable, not a byproduct. Escalation targets: arch (spec needs
clarification) / research (profile needs a field) / operator (local decision).

---

## A-SQL-001: codec provenance label reads `spec-data v7.71`, snapshot is v0.8.0 (V8) — **RESOLVED at S2 (byte-identity proven)**

**RESOLUTION (2026-07-16, S2):** PROVEN by byte-identity, not assumed. The
delegated `libentitycore_codec` — whose `ec_impl_info()` still reads
`spec-data v7.71` — produced **byte-identical output for all 71 v0.8.0 corpus
vectors** (encode/decode/hash/peer-id/signature), run in-container, capped,
`--network=none`: `71/71 PASS, 0 FAIL @ codec c-abi 1.1`. The V7→V8 core wire is
byte-unchanged (the MANIFEST claim is now wire-confirmed, not taken on faith); the
provenance string is a cosmetic build-metadata lag in the FFI-C impl, NOT a wire
divergence. Non-blocking, closed. The label re-stamp remains a research/
ffi-generator cosmetic (see A-SQL-006 for a *second* lag in the same impl's
bundled header). Original entry below.

---



**Spec section:** MANIFEST.md (v0.8.0) — "core wire byte-unchanged across V7→V8"
**Profile field:** `[deps].libentitycore_codec`
**Observation:** The `libentitycore_codec.so` built from `entity-core-codec-ffi-c` reports
`ec_impl_info()` = `"c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 / libsodium 1.0.22 (+ …)"`.
Our spec-data snapshot is **v0.8.0 (V8)**. Per the V8 MANIFEST the **core wire contract is
byte-unchanged** across the V7→V8 cutover (the 0.7.77 naming pass was extension-side; no
CBOR/wire change), so the codec is wire-correct against v0.8.0 despite the label.
**Guess/decision:** Non-blocking. Proceed — the provenance string is a build-metadata label
lag in the FFI-C impl, not a wire divergence; the S1 GO-gate ec_sha256 KAT passes and the
S2 wire differential will confirm byte-identity against the v0.8.0 corpus.
**Escalation:** research/ffi-generator — the C-ABI impl's provenance label should re-stamp
to the V8 snapshot on its next rebuild (cosmetic). Not an arch/spec item.

---

## A-SQL-002: SQLite INTEGER is 64-bit signed — uint64 wire range cannot be a SQL column

**Spec section:** §1.5 / ENTITY-CBOR-ENCODING (integer tower, uint64 head-forms)
**Profile field:** `[number_model]`
**Observation:** SQLite `INTEGER` is signed 64-bit; it cannot represent `[2^63, 2^64-1]`.
**Guess/decision:** Non-blocking, resolved in the profile: the CBOR integer head-form + the
uint64 boundary + the mt7 shortest-float ladder all live in the **host codec seam**
(`libentitycore_codec`), which owns the wire bytes regardless. SQL only computes over
authority-domain numbers (chain depth ≤64, K-of-N counts/thresholds, ms timestamps, path
lengths) — all within int64. Out-of-int64 wire integers ride as opaque host blobs/handles,
never as SQLite INTEGER. No head-form self-test obligation falls on SQL.
**Escalation:** operator — local design decision, documented. Not a spec gap (the spec is
fine; this is a substrate-fit note).

---

## A-SQL-003 (RESOLVED at S3 — the probe's central question): the seam split

**RESOLUTION (2026-07-16, S3):** Characterized from the RUNNING artifact (src/sql/*.sql exercised
by the authority harness 13/13 + run live in the peer; connectivity 22·0F PASS). The line falls
EXACTLY where hypothesized, now with precise outcomes per element (see profile
`[authority_interior_expressibility]`):

- **Stays SQL, expresses cleanly** (the authorization DECISION half): §5.2 verify ladder (one CASE
  ladder, arm order = algorithm order, crypto inline), §5.5 chain-walk (WITH RECURSIVE = the
  canonical transitive-closure), §3.6 K-of-N (GROUP BY … HAVING — the sharpest fit), §6.6
  longest-prefix (ORDER BY length DESC LIMIT 1), §5.10 verdict-time (a bound column → pure-function
  determinism), §4.10(b) depth pre-check (max(depth)>64 over the walk CTE).
- **Leaks to host, as predicted** (the protocol SEQUENCING + I/O half): §6.5 op-switch + frame
  sequencing + connection lifecycle, §4 handshake state machine + PoP. SQL owns the DECISION,
  invoked once per request; the host owns everything stateful-sequential.
- **The precise rule (the finding):** *everything that is a PURE FUNCTION of the projected request
  facts stays SQL; everything STATEFUL-SEQUENTIAL leaks to the host.* Authorization is a query;
  the protocol around it is a state machine. Two genuinely spec-shaped sub-findings surfaced from
  the encoding: A-SQL-007 (GLOB peer-wildcard segment-anchoring) and A-SQL-008 (the §3.6
  path-scope/id-scope split maps onto two SQL match strategies — the relational form is SHARPER
  than the prose's single uniform matches_scope). Both are candidate `HANDOFF-TO-ARCH` notes.

Original hypothesis entry below (kept for provenance).

---

## A-SQL-003 (was OPEN — the probe's central question, S3 filled in): the seam split

**Spec section:** §5.2 / §5.5 / §5.5a / §5.10 / §6.5 / §6.6 / §3.6 (K-of-N)
**Profile field:** `[authority_interior_expressibility]`
**Observation / hypothesis (S1):** The bet is that the *authorization decision* half of
entity-core (verify ladder, delegation chain-walk, scope-match, K-of-N, handler resolution)
is relational and expresses **cleanly** in SQL, while the *protocol sequencing + I/O* half
(§6.5 op-switch, §4 handshake state, connection lifecycle) is stateful-imperative and
**leaks to the host**. Characterizing exactly where that line falls — and whether any
authority rule is *awkward or impossible* to express declaratively (→ a spec-shaped finding)
or *cleaner* than the imperative spec text implies (→ a GUIDE note / amendment candidate) —
IS the deliverable.
**Guess/decision:** Not a guess to resolve at S1 — this is the **work item for S3**. Each
sub-finding gets its own `A-SQL-00N` entry as it is authored (e.g. "the §5.2 ladder ORDER is
implicit in the CASE arms — does the spec pin the 401-vs-403-vs-unresolvable precedence
tightly enough for a declarative encoding, or is it prose-ordered?"). The profile's
`authority_interior_expressibility` table tracks hypothesis → outcome → finding per element.
**Escalation:** arch — any element that is awkward/impossible/cleaner-than-implied is a
proposal candidate; route via a packet in `docs/outbox/` (the F32–F39 channel).

---

## A-SQL-004 (NOTE, watch at S3/S4): multisig oracle category is rejection-only

**Spec section:** §3.6 K-of-N multisig
**Profile field:** `[conformance].multisig_accept`, `[authority_interior_expressibility].k_of_n_multisig`
**Observation:** Durable cohort lesson: the `multisig` validate-peer category was
rejection-only (100% malformed→403), so a fail-closed peer passes **without implementing
K-of-N** (vacuous green). For a probe whose whole point is expressing K-of-N as
`GROUP BY … HAVING count(DISTINCT signer) >= k`, a vacuous pass would be the worst outcome.
**Guess/decision:** Mandatory at S3/S4 — author a genuine **2-of-3 multisig accept-path unit
test** in the direction the oracle can't cover, asserting the SQL `HAVING` clause actually
admits a valid quorum (not just rejects a bad one).
**Escalation:** operator/research — implementation discipline, pre-registered so it isn't
skipped. Not a spec gap.

---

## A-SQL-005 (NOTE, resolved at S2): delegated `content_hash` supports format 0x00/0x01 only → `content_hash.4` (format 128) is correct-unsupported, not a byte-match

**Spec section:** §4.1a / C-ABI v1.1 (`ec_content_hash_with_format`), corpus `content_hash.4`
**Profile field:** `[codec].cbor_library` (delegated), `[conformance].wire_corpus`
**Observation:** Corpus vector `content_hash.4` carries a synthetic
`format_code = 128` (a ≥0x80 multi-byte-varint forward-compat probe). The delegated
`libentitycore_codec` implements only the allocated codes — `0x00` SHA-256 / `0x01`
SHA-384 — and returns `EC_DECODE_ERROR (unsupported_content_hash_format)` for any
other code (`cc_content_hash_format_supported()` = `{0,1}`). So the seam **cannot
and must not** emit `content_hash.4`'s canonical bytes.
**Guess/decision:** Non-blocking, correct. The vector's own `.diag` note allows
exactly this: "impls that don't yet support arbitrary codes report unsupported
rather than emit wrong bytes." The harness counts `content_hash.4` as
**PASS-by-correct-unsupported** (an `EC_DECODE_ERROR` for a code ∉ {0,1}), and
prints a `NOTE` line. The multi-byte-varint prefix path (N1) is still exercised
positively by `peer_id.3` (key_type 128 → `0x80 0x01`, byte-matched) and by the
`ec_hash_format_code_encode(128)` self-test. Gate stays `71/71 PASS`.
**Escalation:** operator — a delegated-codec capability boundary, documented. Not a
spec gap and not a peer bug (fail-safe: refuse rather than fabricate bytes).

---

## A-SQL-006 (FINDING, S2): the FFI-C impl's bundled header (baked into the image) lags the canonical C-ABI spec header — omits `ec_ed25519_seed_to_pubkey`

**Spec section:** C-ABI v1.1 header contract (`ffi-generator/c-abi/spec/entitycore_codec.h`)
**Profile field:** `[codec].interop_source`, `[deps].libentitycore_codec`; `containers/sqlite-toolchain/Containerfile`
**Observation:** The `sqlite-toolchain` image bakes `/opt/codec/include/entitycore_codec.h`
by copying the FFI-C impl's OWN `include/entitycore_codec.h`. That bundled copy is
**stale**: it declares `ec_ed448_seed_to_pubkey` but NOT `ec_ed25519_seed_to_pubkey`
— even though the built `.so` **exports** `ec_ed25519_seed_to_pubkey` (`nm -D`
confirms it). The C-ABI spec is explicit ("Every conforming implementation ships
THIS header, unchanged") — the authority is `ffi-generator/c-abi/spec/`, and it
declares the symbol (v1.1, line ~143). So the impl's `include/` copy has drifted
from the canonical header it is supposed to be a verbatim copy of. Same *class* of
lag as A-SQL-001 (the impl's build metadata trailing the canonical snapshot).
**Guess/decision:** Non-blocking. The S2 Makefile builds against the **canonical
spec header** (`CODEC_HDR ?= ../../ffi-generator/c-abi/spec`), NOT the image's
bundled copy — the authoritative contract, and it matches the `.so`'s exports. Gate
green. Two clean follow-ups for the ffi-generator arm (cosmetic, not arch/spec):
(1) re-sync `entity-core-codec-ffi-c/include/entitycore_codec.h` to the canonical
spec header; (2) have the Containerfile copy the **spec** header (single source of
truth) rather than the impl's drift-prone `include/` copy.
**Escalation:** research/ffi-generator — header + provenance re-sync on the FFI-C
impl's next rebuild. Not an arch/spec item.

---

## A-SQL-007 (FINDING, S3): §5.4 matches_pattern's peer-wildcard `/*/` is SEGMENT-anchored; SQL GLOB `*` is not

**Spec section:** §5.4 matches_pattern (peer wildcard `/*/rest`)
**Profile field:** `[authored].scope_match`, `[authority_interior_expressibility].scope_matching`
**Observation:** matches_pattern encodes cleanly as `value GLOB canonicalize(pattern)` for the pattern
classes the core surface uses — exact, trailing-subtree `prefix/*`, local `*`→`/{frame}/*`, and
universal `/*/*` are all byte-exact under SQLite GLOB (verified: authority harness allow/deny/404 +
connectivity 22·0F). The ONE divergence: §5.4's peer wildcard `/*/rest` treats `*` as EXACTLY ONE
path segment (the peer id), but SQLite GLOB `*` matches any run of characters INCLUDING `/`. So a
pattern like `/*/system/tree` would (under a naive GLOB) also match `/PEER/x/system/tree`, over-
matching by one+ segments. `/*/*` is unaffected (rest is itself `*` = whole subtree).
**Guess/decision:** Non-blocking for the core gate (no core cap uses `/*/specific` middle-wildcard;
the exercised set is byte-exact). The faithful general encoding needs segment-anchoring — a recursive-
CTE segment tokenizer, or an app-defined `matches_pattern(value,pattern)` — which trades some
legibility for exactness. Documented as the boundary where GLOB stops being a faithful matches_pattern.
**Escalation:** research — a generator note for any future declarative-substrate peer (GLOB ≠
segment-anchored). Not an arch/spec defect (the spec is precise; SQL's GLOB is the looser tool).

---

## A-SQL-008 (FINDING, S3 — candidate HANDOFF-TO-ARCH): the §3.6 path-scope/id-scope split maps onto TWO SQL match strategies — sharper than the prose's uniform matches_scope

**Spec section:** §3.6 (path-scope vs id-scope types), §5.2 matches_scope, §5.4 canonicalize
**Profile field:** `[authority_interior_expressibility].scope_matching`
**Observation:** §5.2 `matches_scope` applies `matches_pattern(canonicalize(value), canonicalize(pattern))`
UNIFORMLY across all four grant dimensions. But §3.6 already types the dimensions into TWO scope
KINDS: `path-scope` (handlers, resources — values are tree paths) and `id-scope` (operations, peers —
values are identifiers). Canonicalizing an IDENTIFIER as a path (`'get'` → `/{peer}/get`) is symmetric-
but-meaningless — it only works because both sides get the same transform. The relational encoding made
this fall out naturally: path-scope dims canonicalize (granter frame, §5.5a); id-scope dims match RAW
(`op GLOB 'get'`, `op GLOB '*'`). Two scope TYPES → two match STRATEGIES, cleanly. (Discovered as a real
bug first — canonicalizing operations against the granter frame while comparing a raw value broke the
ALLOW path; the fix IS the split.)
**Guess/decision:** The two-strategy split is correct and is what the SQL authors. The finding is that
the prose's single uniform `matches_scope` is arguably LESS precise than the type system it operates
over — an amendment could note that id-scope matching needs no path canonicalization (the value/pattern
are identifiers). A legibility/precision gain the declarative encoding surfaced.
**Escalation:** arch (candidate `HANDOFF-TO-ARCH`) — a clarifying note that id-scope matching is raw
identifier matching, path-scope is canonicalized-path matching. Non-blocking; both give identical
results for same-peer caps (the difference is only visible under the id-scope-canonicalization pathology).

---

## A-SQL-010 (RESOLVED at S4): verdict arm precedence — unresolvable-grantee (401) precedes grantee-mismatch (403)

**RESOLUTION (2026-07-16, S4):** The live `authz` category pins it. AUTHZ-GRANTEE-1 presents a
cap whose leaf grantee is itself unresolvable and expects **401 unresolvable_grantee** (the §5.2
PR-3 carve-out), NOT the 403 grantee-mismatch. `verify_ladder.sql` was reordered so the §5.5
unresolvable-grantee arm runs BEFORE the leaf grantee==author arm (both still fail closed; only
the code precedence changed). The S3 authority harness stays 13/0F (grantee_mismatch check 4
uses a RESOLVABLE mismatched grantee → still 403; unresolvable check 5 → 401), so the reorder is
safe. The A-SQL-010 "documented ordering choice" is now the pinned behavior. Original NOTE below.

---

## A-SQL-009 (partially RESOLVED at S4): §5.2 check_resource_scope arms

**RESOLUTION (2026-07-16, S4):** The CONCRETE resource-target arm is live + core-gated — the host
projects `exec.data.resource.targets[]` (a bare `{targets:[…]}` map, NOT an entity — a projection
shape note) into `request_resource`, and `tree_operations` + `security` pass 0-fail over it. The
heavier PATTERN-overlap arm (`patterns_overlap`/`strip_wildcard`) + `is_attenuated` scope_subset
remain exercised only by the delegate-handler-gated foreign-granter ext vectors a core peer
honest-SKIPs — a documented completion item, not a core gap. Original NOTE below.

---

## A-SQL-009 (NOTE, S3): §5.2 check_resource_scope pattern-overlap arm authored + tested, not core-gated

**Spec section:** §5.2 check_resource_scope (pattern targets: grant-exclude/caller-exclude overlap)
**Profile field:** `[authority_interior_expressibility].scope_matching`
**Observation:** verify_ladder.sql's resource check implements the CONCRETE-target arm (every target
covered by resources.include and not in resources.exclude). The full §5.2 PATTERN-target arm (for each
grant exclude overlapping a pattern target, a caller exclude must cover it — `patterns_overlap` +
`strip_wildcard`) is the heavier subset arithmetic; it is exercised by the caps a core peer actually
presents only via the concrete arm. `is_attenuated` scope_subset (§5.6) is likewise authored at the
concrete/GLOB level; the deep foreign-granter attenuation vectors (`AUTHZ-ATTENUATION-FOREIGN-GRANTER-*`)
need the `system/capability:delegate` handler machinery a core peer honest-SKIPs.
**Guess/decision:** Non-blocking. Concrete arm is correct + tested (harness scope-deny + 404 + allow).
The pattern-overlap arm is a documented completion item for S4 if a vector reaches it; it is expressible
in SQL (a NOT EXISTS over canonicalized grant excludes with a `patterns_overlap` predicate) but adds
bulk. Named so it is not mistaken for complete.
**Escalation:** operator/research — an S4 completion item, pre-registered. Not a spec gap.

---

## A-SQL-010 (NOTE, S3): verdict arm precedence for the compound grantee-unresolvable + unreachable case

**Spec section:** §5.5 "Behavioral note — error precedence" (ChainUnreachable takes precedence)
**Profile field:** `[authority_interior_expressibility].s52_verify_ladder`
**Observation:** verify_ladder.sql checks the per-link `unresolvable_grantee` (401) arm BEFORE the
`chain unreachable` (403) arm. §5.5 says ChainUnreachable/ChainTooDeep takes precedence over per-level
validation in the COMPOUND-failure case (both fail closed; only the code differs). For the reachable
chains a core peer presents this never diverges (grantee-unresolvable fires on a reachable chain →
401; an unreachable chain's collected grantees resolve → 403). The spec itself flags this as a
tolerable code-precedence nuance ("impls with negative tests asserting specific error codes for
compound-failure cases will need updating").
**Guess/decision:** Non-blocking; both fail-closed. Left as authored (the ladder's arm order mirrors
the §5.2 algorithm's per-step order). If an S4 vector asserts the code on a compound failure, move the
reachability arm above the grantee arm. Documented so the ordering is a choice, not an oversight.
**Escalation:** operator — a documented ordering choice. Not a spec gap.

---

## A-SQL-011 (NOTE, S4): host-plumbing projection shapes (not spec gaps, generator notes)

**Spec section:** §1.4 (uri scheme), §3.2 (resource-target), §9.5 (type-registry vectors)
**Profile field:** the S4 host projection (`project_and_verify`) + `seed_types`
**Observation:** three shape facts the S4 projection had to get right, worth carrying to any
future declarative/seam peer (each surfaced as a live-oracle FAIL first, none is a spec defect):
(1) the wire dispatch **uri carries the `entity://{peer}/…` scheme** — normalize to the absolute
`/{peer}/…` form before `resolve.sql` / handler-path matching; (2) `exec.data.resource` is a
**bare map `{targets:[…]}`**, NOT an entity with a `.data` level — projecting a level too deep
silently drops the target and every fetch falls back to the handler root (a 404 wall); (3) the
shared type-registry vector `data` is a **CBOR byte string WRAPPING** the ECF TypeDefinition map
— store/serve the inner map bytes, not the byte-string envelope (else the oracle decodes a bstr
where it wants a TypeDefinition). Also: canonical CBOR **map-key ordering is load-bearing** for
the peer-built `included` map (byte-sorted 33-byte hash keys) and listing `entries`
(length-then-lex segments) — a build-order map fails `encoding.ecf_key_ordering`.
**Guess/decision:** All resolved in the host (peer.c / handlers.inc.c). Non-blocking; the spec is
precise on all three — these are projection-plumbing notes, the S4 analogue of the S3 seam-split.
**Escalation:** research — a generator note for the next seam-hybrid / declarative peer. Not arch.

---

## S5 finalization — escalation ledger (2026-07-16)

Every item is CLOSED here: resolved, or named-owner-escalated. Nothing is left open
or unowned. Two items carry a live spec-shaped escalation to architecture (the
probe's payoff); the rest are resolved or routed to research/ffi-generator/operator
as non-blocking cosmetic / substrate-fit / generator notes.

| Item | Class | Status | Owner / escalation |
|---|---|---|---|
| A-SQL-001 | codec provenance-label lag (`v7.71` string) | RESOLVED (S2, byte-identity proven) | research/ffi-generator (cosmetic re-stamp) |
| A-SQL-002 | SQLite int64 ≠ uint64 wire range | RESOLVED (S1, seam owns wire ints) | operator (substrate-fit note; not a spec gap) |
| A-SQL-003 | the seam split (central question) | RESOLVED (S3, characterized from running artifact) | — (the finding: authorization is a query, protocol is a state machine) |
| A-SQL-004 | multisig oracle is rejection-only | RESOLVED (S3/S4, genuine 2-of-3 accept test) | operator/research (implementation discipline) |
| A-SQL-005 | delegated codec: `content_hash` format 128 unsupported | RESOLVED (S2, PASS-by-correct-unsupported) | operator (delegated-codec boundary) |
| A-SQL-006 | FFI-C bundled header lags canonical spec header | RESOLVED (S2, build against spec header) | research/ffi-generator (header re-sync) |
| **A-SQL-007** | **§5.4 peer-wildcard `/*/` is segment-anchored; SQL GLOB `*` is not** | **OPEN — escalated to arch, overseer-routed** | **architecture** (HANDOFF-TO-ARCH; non-blocking for core gate) |
| **A-SQL-008** | **§3.6 path-scope/id-scope → two SQL match strategies, sharper than uniform `matches_scope`** | **OPEN — escalated to arch, overseer-routed** | **architecture** (HANDOFF-TO-ARCH; non-blocking) |
| A-SQL-009 | §5.2 pattern-overlap arm + `is_attenuated` not core-gated | PARTIALLY RESOLVED (S4, concrete arm live); completion item | operator/research (documented, not a gap) |
| A-SQL-010 | verdict arm precedence (401 unresolvable vs 403 mismatch) | RESOLVED (S4, ladder reordered, pinned by `authz`) | operator (was a documented ordering choice) |
| A-SQL-011 | host-plumbing projection shapes (uri scheme / bare-map resource / bstr-wrapped type data / key ordering) | RESOLVED (S4, host) | research (generator note for the next seam peer) |

**Arch-routed (A-SQL-007 + A-SQL-008):** both are non-blocking for the `--profile
core` gate (the exercised core cap set is byte-exact under the current encoding).
They are the probe's spec-shaped payoff — surfaced *because* the relational encoding
is sharper than the prose. The overseer is authoring the
a packet in `docs/outbox/`; architecture pulls it in on its own
schedule (never a cross-repo edit). No architecture repo is touched from here.
