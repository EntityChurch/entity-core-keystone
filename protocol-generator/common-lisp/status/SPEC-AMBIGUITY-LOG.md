# entity-core-protocol-common-lisp — Spec Ambiguity Log

> Discipline: every guess goes here; no silent guesses. Items escalate to
> architecture/research via `research/stewardship/`. Common Lisp is peer #5 — the
> most distant idiom built so far (S-expressions, CLOS multiple dispatch, the
> condition system, image-based development, dynamic typing, macros) — so its
> value is the NEW probes it surfaces by deriving from V7 in that idiom. Entries
> prefixed `A-CL-` to namespace from the C#/TS/OCaml/Elixir logs.
>
> Phase coverage so far: **S1 (profile), S2 (codec), S3 (peer), S4 (conformance),
> S5 (publish + architecture review)**.

---

## S5 closeout — publish-readiness + the finding-set finalization

S5 polished the S4-conformant peer to publish-ready and wrote the cross-peer
architecture review (`status/ARCHITECTURE-REVIEW.md`). No new spec ambiguities were
surfaced by the wire-touching surface (it was frozen + 0-FAIL at S4); the regression
re-ran GREEN after packaging (**S2 69/69 · S3 11/11 · S4 568 · 284P/195W/0F/89S**).
One NEW packaging-class finding surfaced (A-CL-010, ASDF version field), and the
S4 hex-case finding A-CL-009 was given its standalone entry below. Final finding set:

- **⚑ arch (spec-refinement) — A-CL-002, A-CL-007, A-CL-009.** Peer-id §7.4-vs-§1.5
  (3rd spec-first corroboration), format_code 128 asymmetry (2nd independent), tree-path
  hex-case unspecified (NEW). These are the architecture escalation bundle.
- **note (idiom-neutrality) — A-CL-008.** §6.6 dispatch maps cleanly onto CLOS multiple
  dispatch; five idioms converge on the same dispatch behavior — a tightness signal.
- **research/arch (provenance) — A-CL-001.** v7.73/v7.74 spec-data snapshot still missing.
- **operator (packaging) — A-CL-003 (sb-thread), A-CL-004 (Quicklisp dist), A-CL-005
  (pure-Lisp Ed448 trust, RESOLVED), A-CL-006 (SBCL SHA, RESOLVED), A-CL-010 (ASDF
  version field, NEW).**

Public-surface decision (the S5 "settle the surface" step): CL has no module-private
keyword, so package exports ARE the surface. The peer-package export block is now tiered
(Tier 1 model+identity / Tier 2 full peer / a labelled test-client+address-space helper
block that is NOT stable API) — the CL analogue of pruning Zig's `root.zig` re-exports,
but DOCUMENTED not compiler-enforced (the in-repo smoke/type-registry execs are library
clients of `empty-params`/`resource-target`/`scope`/`hex`, so they can't be hard-pruned
without moving the tests under the system — exactly OCaml's `.mli`/`private_modules`
deferral rationale). Version parked at the `0.1.0-pre` LINE (ASDF `:version` = `0.1.0`,
the `-pre` marker in CHANGELOG/README per A-CL-010).

---

## S4 closeout — `validate-peer --profile core` PASS · 568 · 0 FAIL

The gate is GREEN: **568 total · 284 pass · 195 warn · 0 FAIL · 89 skip → PASS**
(oracle rebuilt from `entity-core-go` HEAD `d39aaf2` with the §7a wire-gate). Same
cohort fixed-point as OCaml (284P/195W/0F/89S). origination-core **3/3** incl
`dispatch_outbound_reentry` over real two-peer TCP (carry-in (c) exercised, not
SKIPped). All 7 first-run FAILs were CL **code bugs**, not spec ambiguities —
fixed by deriving the correct behavior from V7 + the cohort, never by doctoring the
oracle:

1. **A-CL-009 (NEW, corroboration ⚑) — lowercase-hex is the address-space path
   convention.** The §3.5/§3.4 invariant-pointer paths (`system/signature/{hash}`),
   the §5.1 revocation marker path (`system/capability/revocations/{hash}`), and the
   §6.9a policy paths are keyed by **lowercase** hex of the entity content_hash —
   matching the Go oracle's `hex.EncodeToString` and the sibling peers' `%02x`. The
   CL `hex` helper emitted **uppercase** (`~2,'0x`), which was internally consistent
   (so S3's CL-to-CL loopback passed) but produced case-mismatched tree-path keys the
   oracle (lowercase) could not find → 404 on the register grant-signature
   (`core_register_grant_signature_at_invariant_path`) and the revoke marker
   (`revoke_happy_path_writes_marker`). **The convention is NOWHERE stated normatively
   in V7** — it is implicit in the reference impl's `hex.EncodeToString` default.
   **Escalation: arch** — V7 §3.4/§3.5 (and the §1.5 content_hash hex rendering)
   SHOULD state hex-case explicitly (lowercase) since tree paths are case-sensitive
   string keys; this is a latent interop trap for any peer whose stdlib hex defaults
   to uppercase (CL, some Pascal/Ada/SQL hex builtins). Fixed in `peer-model.lisp`
   `hex` → lowercase; all path writes/reads route through it so internal consistency
   is preserved. Corroborates the general "hex-case unspecified" class.

2. **§PR-8 / V2(a) cross-peer dispatch boundary — code bug, fixed (no new ambiguity).**
   `check-resource-scope` canonicalized a cap's grant resource patterns against the
   LOCAL (verifier) frame; a peer-local bare-`*` cap presented cross-peer was wrongly
   ACCEPTED (`captok_form_dispatch_minted_pl_presented_xpeer`). Fixed to canonicalize
   the grant's own include/exclude against the **granter's** peer_id (resolved at the
   dispatch site via `resolve-granter-peer-id`), per the cohort's signed-off V2(a)
   shape (OCaml `capability.ml`). The S3 code carried a comment claiming this was
   "exercised at S4" — it was a stub; now actually implemented. Caller targets stay
   on the local frame (§5.4). No spec ambiguity — the cohort fix is byte/behavior-
   convergent.

3. **§5.7 delegation caveats — code bug, fixed (no new ambiguity).** The chain walk
   enforced scope-subset + temporal attenuation but NOT the parent's
   `delegation_caveats` (`no_delegation`, `max_delegation_ttl`, `max_delegation_depth`)
   → `chain_no_delegation_denied` + `chain_max_delegation_ttl_denied` wrongly ACCEPTED.
   Added `check-delegation-caveats` (§5.7) applied per-link in
   `verify-capability-chain`, plus the §5.5a per-link granter frames in
   `scope-subset`/`grant-subset`/`is-attenuated` (hard-fail deny on an unresolvable
   link granter). Direct port of the cohort's signed-off §5.7 + Amendment-1 shape.

- **A-CL-001 (spec-data snapshot stops at v7.72; v7.73/v7.74 surface cohort-sourced)
  — STILL OPEN, S4 byte-provenance note re-stated.** The oracle was rebuilt from
  `entity-core-go` HEAD (`d39aaf2`), so the conformance check-set IS at HEAD; but the
  peer's v7.73+ behavior (register grant-signature invariant-pointer path, §PR-8
  granter-frame, §5.7 caveats, §7a handlers) was authored against the cohort + the
  oracle's own check messages, not a SHA-pinned v7.73/v7.74 spec-data snapshot (which
  remains absent locally). The build is oracle-verified-correct, but its v7.73+ byte
  provenance still traces to siblings + oracle, exactly the gap A-CL-001 flags.
  **Escalation UNCHANGED (research/arch):** land the v7.74 spec-data snapshot.

- **WARNs (195) — cohort-known classes, confirmed.** 194 are `type_system` non-§9.5-
  floor type vocabulary (matched-if-present: the Go reference peer publishes its
  ENTIRE ~131-type registry incl. extension type *definitions*; a core peer correctly
  publishes only the 53 §9.5 floor → the rest WARN, never FAIL — refined G4,
  [[type-registry-core-vs-extension]]). 1 is `tree_operations.cleanup` ("failed to
  remove test entity (non-critical)"), the same oracle-marked non-critical warn OCaml
  carries (the 1-check 284P/195W vs C#/TS 285P/194W delta). None are new problems.

- **SKIPs (89) — all §9.0 profile auto-allowlisted carve-outs, not disguised FAILs.**
  The oracle itself marks them SKIP under `--profile core`: whole extension categories
  (subscriptions/continuations/revision/clock/history/query/local_files/compute/
  origination/attestation/quorum/identity/role/durability/content/…), the in-category
  EXTENSION-TREE §9 tree ops (snapshot/diff/extract/merge) + extension handler probes
  (inbox/continuation/subscription/revision), plus 3 extension-vocabulary carve-outs:
  `security.handler_scope_denied` (targets `system/subscription` ext; core 404s before
  §5.4 per §6.5 resolution-first), `authz_delegate_grant_1` (targets `system/role`
  ext), and `authz_revoked_1` (expects ROLE §5.5 401 `capability_revoked` vocabulary;
  the core peer's revocation denial is 403 `capability_denied` and PASSES via
  `authz_revoked_core_1`). All cohort-consistent (F18/F19).

---

## S3 closeout — resolutions + the v7.74 escalation re-stated

- **A-CL-001 (v7.73/v7.74 spec-data snapshot missing) — ESCALATION RE-STATED, still
  OPEN.** The S3 peer layer was resynced to the **v7.74 peer surface** (register /
  outbound-dispatch / emit live-hooks + the §6.9a owner-cap bootstrap + the §7a
  conformance handlers) by mirroring the C#/TS/OCaml/Elixir folded-proposal builds —
  **NOT** from a SHA-pinned spec-data snapshot, because the local `spec-data/` stops
  at **v7.72**. Concretely, what S3 had to source from the cohort peers (OCaml's
  `peer.ml` was the closest precedent) rather than from a v7.73/v7.74 snapshot:
    1. **§6.13(a) register's five normative writes** (handler manifest, associated
       types, self-issued signed grant, grant-signature at the §3.5 pointer, interface
       index) — taken from the cohort's register impl, not a v7.74 §6.13(a) snapshot.
    2. **§6.13(b) the handler-facing outbound seam shape** + the §6.11 reentry framing
       (request_id demux over the inbound connection) — from the cohort transport.
    3. **§6.13(c) the emit consumer-registration primitive + the "live with zero
       consumers" MUST** — from the cohort store, not a v7.74 §6.10/§6.13(c) snapshot.
    4. **§6.9a Peer Authority Bootstrap** (the owner-cap L0 write-set, the §6.9a.0
       detached-signature shape, the v7.64 dual-form authenticate-time lookup) — from
       the cohort's signed-off F27/Phase-2 shape (OCaml `peer.ml`), since §6.9a is a
       Phase-2 proposal not yet in any local snapshot.
    5. **§7a conformance handlers** (`system/validate/echo` +
       `system/validate/dispatch-outbound`, opt-in under `--validate`, cap=in-band) —
       from GUIDE-CONFORMANCE §7a as folded into the cohort, not a snapshot.
  **Escalation (UNCHANGED, now S3-blocking-for-byte-provenance):** research/arch — the
  keystone needs a **SHA-pinned v7.73/v7.74 spec-data snapshot at HEAD** so the peer
  layer's byte provenance traces to a pinned spec copy rather than to sibling peers.
  The build is behaviorally correct (loopback GREEN, S2 unbroken), but its v7.73+
  surface is cohort-sourced, which is exactly the provenance gap S2 flagged. NON-
  blocking for the S3 gate; blocking for clean S4 byte-provenance.

- **A-CL-003 (concurrency = native sb-thread) — RESOLVED, VALIDATED at S3.** The
  one-native-thread-per-connection model (accept→serve→reader, inbound EXECUTE
  dispatched on its own thread, request_id→waitqueue correlation under a mutex) is
  built on `sb-thread` with **no third-party dep** and satisfies N6/N7 — verified by
  the 8-way request_id demux check (8 concurrent EXECUTEs each correlate to their own
  response). Matches the shape OCaml arrived at (A-OC-003-revised). bordeaux-threads
  stays deferred (localized swap if ECL/CCL/ABCL portability is later wanted).

- **F27 (Peer Authority Bootstrap) — matched the cohort, NO friction.** Per the
  carry-in, this peer does NOT try to solve the OPEN F27 finding; it reaches
  write/grant-gated ops via the **`--debug-open-grants`** degenerate seed exactly as
  the cohort does, and builds the §6.9a seed-policy machinery in OCaml's signed-off
  shape so a future F27 Phase-2 fold is a generalization, not a conflict. Both the
  default-seed scenario (discovery floor) and the open-grants scenario
  (register/echo) pass — the authn(401)/authz(403) split is clean.

---

## S2 closeout — resolutions + corroborations

- **A-CL-002 (peer_id §7.4-vs-§1.5)** — **CONFIRMED/RESOLVED in code.** The §1.5
  canonical-form + size-cutoff path is implemented (`peer-id-from-public-key`):
  Ed25519 ≤32B → `hash_type=0x00` identity-multihash (raw pubkey); Ed448 >32B →
  `hash_type=0x01` SHA-256(pubkey). Verified end-to-end by the Ed448 KAT: the derived
  peer_id `3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4` is byte-equal to the
  locked v7.71 SHA-256-form pin. The stale §7.4 SHA-256-of-pubkey form is NOT a
  construction path. THIRD spec-first peer to corroborate (Zig, OCaml, now CL) —
  arch escalation stands.
- **A-CL-004 (Quicklisp dist pin)** — **RESOLVED.** The pinned dist carries
  ironclad **v0.61** (its ironclad archive resolves to `ironclad-v0.61.tgz`); the build
  asserts on it. Note: ironclad's transitive deps under this dist are
  alexandria + bordeaux-threads + global-vars + nibbles (more than the S1
  nibbles+alexandria estimate); none are codec runtime deps.
- **A-CL-005 (pure-Lisp Ed448 trust)** — **RESOLVED, gate PASSES.** Native ironclad
  Ed448 is byte-equal to the RFC-8032 pins (57-B pubkey, 114-B signature, §1.5
  peer_id) for seed `0x42×57` + the §1.1 fixture message. Pure-Lisp Ed448 is trusted;
  the hybrid-FFI fallback (OCaml A-OC-002 route) is NOT needed. Second native-path
  agility peer (after Elixir), first via a pure-Lisp crypto library.
- **A-CL-006 (SBCL source SHA)** — **RESOLVED.** Verified SHA-256
  `3ba53e654b60feb7c4f50466199d6d5260f2661c711ba22d4b770b655400d57b` (official
  SourceForge release, GPG-signed, bz2-integrity checked) filled into the
  Containerfile; build fails closed on mismatch.

---

## A-CL-001: spec-data snapshot stops at v7.72 while spec HEAD is v7.74 (folded)

**V7 section:** repo-wide (snapshot vs HEAD), not a single section.
**Profile field:** `[spec].v7_version_pinned` / `codec_corpus`.
**Your guess:** Derive the profile + codec from `spec-data/v7.72` (the latest
snapshot) and the `test-vectors/v0.8.0` corpus (byte-identical encoding spec
v7.71→v7.72, SHA-verified upstream). The v7.73 (nonce-echo §4.6) and v7.74
(register/outbound/emit/owner-cap §6.13/§6.9a + §7a conformance handlers) folds are
**peer-layer** (S3+), not codec — so S1/S2 are unaffected. Resync the peer layer to
the v7.74 surface at S3, mirroring the C#/TS/OCaml/Elixir builds.
**Rationale:** Same posture peers #1–4 took (cf. A-ELX-001, A-OC-S3 resyncs). The
codec scope is clean at the snapshot; the peer-layer skew is real but does not block
S1/S2.
**Escalation:** **research/arch** — the v7.73/v7.74 spec-data snapshot is missing;
the keystone needs a SHA-pinned snapshot at HEAD for the S3 peer-layer build.
NON-blocking for S1/S2.

---

## A-CL-002: §7.4 NORMATIVE peer-id pseudocode contradicts the §1.5 v7.65 canonical-form table — corroborates A-ZIG-001 / A-OC-007 (THIRD spec-first peer) ⚑

**V7 section:** §7.4 "Peer ID Derivation — NORMATIVE" + the §1.5-line-436 path
skeleton (`Base58(key_type || hash_type || hash(pubkey))`) vs §1.5
"Canonical form per `key_type` (v7.65 v1 contract)" table.
**Profile field:** `[spec]` note + `[codec]` (recorded as a construction mandate).
**The finding.** §7.4's pseudocode, labelled **NORMATIVE**, and the §1.5 line-436
skeleton derive an Ed25519 peer_id from `hash_type = 0x01` with the digest being
**SHA-256 of the public key** (confirmed in `spec-data/v7.72`:
`ENTITY-CORE-PROTOCOL-V7.md` line ~3599 — `digest = SHA256(public_key)`). The §1.5
canonical-form table (v7.65 v1 contract) mandates the **OPPOSITE** for Ed25519:
`hash_type = 0x00` **identity-multihash**, the digest **IS the raw public_key, no
hash** (confirmed: line 448 — "`0x00` identity-multihash … The digest IS the
public_key (v7.64)"). The two are byte-different; a peer that constructs from the
§7.4 form fails `authenticate` step-3 identity binding
(`peer_id == derive(public_key)`) against any conforming peer and gets
`401 identity_mismatch`.
**Your guess (the mandate baked into the profile):** derive the Ed25519 peer_id from
the **§1.5 canonical-form table** (`hash_type = 0x00`, raw pubkey) and **ignore the
stale §7.4 / line-436 SHA-256-form**. Per §1.5's own "Wire-acceptance carve-out"
(Amendment 4 / D, line 493), the SHA-256-form is at most a backwards-compat *decode*
form, never the canonical *construction* form.
**Why this is logged proactively (the saved cycle).** S2's conformance corpus uses
**opaque digests**, so a WRONG peer_id construction **passes S2** and only blows up
at the **S4 handshake**. Two prior spec-first peers (Zig A-ZIG-001, OCaml A-OC-007)
implemented the §7.4 NORMATIVE form literally and burned a full debug cycle each.
Baking the §1.5 form into the profile at S1 dodges the third occurrence.
**Escalation:** **arch — §7.4 (and the §1.5 line-436 skeleton) are STALE and
contradict the §1.5 v7.65 canonical-form table.** §7.4 should reference the §1.5
table or carry the identity-multihash construction directly. This is the **third
spec-first peer** to corroborate the contradiction (after Zig and OCaml) — a strong
signal it is a real spec defect, not a one-peer misread. Resolved locally by
following §1.5.

---

## A-CL-003: Concurrency model — native SBCL threads (idiom decision, validated at S3)

**V7 section:** §4.8 / §6.11 / §6.12 (N6/N7 — inbound concurrent with outbound;
reentrant transport + request_id demux; §6.11 reentry over the inbound connection).
**Profile field:** `[async].style` = `native-threads`.
**Your guess:** Use **one SBCL native thread (`sb-thread`) per connection** plus a
`request_id -> condition-variable` correlation table guarded by a mutex. SBCL native
threads need no third-party dependency; `bordeaux-threads` (the cross-impl
portability layer) is deferred until ECL/CCL/ABCL portability is actually wanted.
**Rationale:** This is the CL analogue of the C#-`Task` / TS-`Promise` / OCaml-`eio`
/ Elixir-processes fork, and it matches the shape OCaml *arrived at* when it revised
its S1 eio decision to stdlib threads at S3 (A-OC-003-revised): for a `--profile
core` peer the N6/N7 invariants are met by one-thread-per-connection without
structured-concurrency machinery. The codec (S2) is pure/synchronous, so this is
**not exercised yet** — validated at S3.
**Escalation:** operator — local S6 decision; recorded so S3 does not re-litigate it
silently. A swap to `bordeaux-threads` would be localized to the transport module.

---

## A-CL-004: Quicklisp dist pinning + offline build mechanics

**V7 section:** absent (toolchain/supply-chain, not a spec question).
**Profile field:** `[deps].quicklisp_dist` / `[deps].ironclad`.
**Your guess:** Pin the **Quicklisp dist to `2026-01`** and use it **only at
container-build time** to install ironclad 0.61 + its deps (nibbles, alexandria)
into a world-readable on-disk ASDF source registry under `/opt/quicklisp`. After
that layer the image needs no network: the dev loop runs `--network=none` and ASDF
resolves ironclad from disk. The build **asserts the resolved ironclad version** so
a dist that does not carry exactly 0.61 fails the build (re-pin the dist that does
and re-stamp the Containerfile header).
**Rationale:** Mirrors the BEAM image's "pre-install deps at build time, run fully
offline" pattern and the project's strong supply-chain stance (S1 containers-only,
S11 pins). Quicklisp dists are monthly and immutable once published, so a dist tag is
a reproducible pin. ironclad is a registry-channel package, so the ≥30-day age floor
applies with full force — 0.61 (2024-08) clears it by ~22 months.
**Escalation:** operator — local build/supply-chain decision. CAVEAT to verify at
S2: confirm the exact dist tag that ships ironclad 0.61 (the dist tag is a date);
the build assertion catches a mismatch.

---

## A-CL-005: Pure-Lisp Ed448 (ironclad) — trust surface; gate on RFC-8032 KAT byte-equality at S2 (verification note, not a gap)

**V7 section:** §1.5 (key_type registry, `ed448` `0x02` validated, v7.67 seed
table); agility corpus `KEY-TYPE-ED448-1`, `HASH-FORMAT-SHA-384-1`, `MATRIX-M2/M3/M6`.
**Profile field:** `[codec].ed448_library` = ironclad (native).
**Your guess:** Source Ed448 (and Ed25519, SHA-256/384) **natively from ironclad**
— no FFI, no opt-in sub-library, no hybrid. The §9.1 floor (Ed25519 + SHA-256) and
the agility higher bar (Ed448 + SHA-384) are both reachable from the default build.
**Rationale + the note.** This is the **headline contrast with OCaml** (A-OC-002,
which had no native Ed448 and sourced it over the C-ABI) and **matches Elixir's**
native-Ed448 position — but by a different mechanism (ironclad is a *pure-Lisp*
impl; Elixir's Ed448 is the OpenSSL NIF). A pure-Lisp Ed448 is a **larger trust
surface** than an OpenSSL primitive, so the S2 plan **gates trusting it on RFC-8032
§7.4 known-answer-test byte-equality** (the same ground-truth check the C FFI used
for its vendored curve448) BEFORE accepting it for the agility corpus's 114-byte
signature / peer-id vectors. If the KAT fails (unlikely — ironclad has shipped Ed448
since 2018), the documented fallback is the hybrid-FFI route OCaml used.
**Escalation:** operator — verification plan, not an ambiguity. Recorded so S2 does
not skip the KAT gate and trust the pure-Lisp curve math blind.

---

## A-CL-006: SBCL source-tarball checksum is a placeholder until verified in-container at S2

**V7 section:** absent (toolchain/supply-chain).
**Profile field:** `[deps].sbcl` (the Containerfile `SBCL_SHA256` ARG).
**Your guess:** The Containerfile source-builds SBCL 2.6.4 from the pinned
SourceForge tarball with a `sha256sum -c` gate, but the checksum value is a
`REPLACE_WITH_VERIFIED_SHA256` placeholder authored at S1 (S1 does NOT run podman /
fetch the tarball, per the phase boundary). S2 (first build) MUST fetch the tarball,
verify its SHA-256 against the value published on sbcl.org / its signature, and
substitute the real digest — the build **fails closed** until then (the placeholder
will never match).
**Rationale:** Honors the S1 "no build/no fetch" boundary while keeping the supply
chain pinned: the recipe is checksum-gated by construction, the value is filled in by
the phase that is actually allowed to fetch. This is the SBCL analogue of the BEAM
image's OTP-tarball handling.
**Escalation:** operator — S2 must fill the verified checksum before the first build
is trusted. NON-blocking for S1 (authoring only).

---

## A-CL-007: ECF `format_code = 128` construct-vs-receive asymmetry (inherited from A-OC-004; re-confirm at S2)

**V7 section:** `ENTITY-CBOR-ENCODING.md` §4.3 (Hash Format Registry — 0x80
unallocated), §4.7 (verify ecfv1-sha256; unknown formats). Test surfaces: ECF
`content_hash.4` (construct) vs agility `VARINT-MULTIBYTE-1` (decode/reject).
**Profile field:** absent — a spec/oracle question.
**Your guess (provisional, to confirm at S2):** Follow the OCaml resolution
(A-OC-004): on **construction**, emit `varint(format_code) ‖ SHA256(ECF(body))` for
whatever `format_code` the caller supplies (so `content_hash.4` with code 128
passes); on **receive/verify**, reject any unsupported/unallocated `format_code`
with `unsupported-content-hash-format` (so `VARINT-MULTIBYTE-1` rejects 0x80 01).
**Rationale + the carry-forward.** OCaml (peer #3, spec-first) surfaced that the two
normative corpora treat `format_code = 128` **oppositely** and that the asymmetry is
**not stated** in §4.3/§4.7 — a fresh reader could plausibly reject 128 on both
sides and fail `content_hash.4`. Common Lisp, deriving fresh, expects to hit the
same fork at S2; logging it now so it is not re-discovered as a surprise. If CL's
fresh derivation reaches the SAME resolution independently, that is additional
corroboration of the arch proposal A-OC-004 raised.
**Escalation:** **arch — spec needs a clarifying sentence** (per A-OC-004): state
that construction serialises the caller-supplied `format_code` while
receive/verify MUST reject unsupported codes. Confirm or refute at S2 from the CL
side.

**S2 outcome — CONFIRMED, independently.** CL's fresh derivation hit
the same fork and landed on the SAME resolution: `content-hash` (construct) emits
`varint(format_code) ‖ SHA256(ECF(body))` for the caller-supplied code (so
`content_hash.4` with code 128 passes — byte-equal to the corpus pin), while
`resolve-content-hash-format` (receive/verify) rejects any unallocated code with
`unsupported-content-hash-format`. This is the SECOND spec-first peer (OCaml, now
CL) to independently reach the asymmetry — additional corroboration of the
A-OC-004 arch proposal that §4.3/§4.7 should state the construct-vs-receive split
explicitly.

---

## A-CL-008: §6.5/§6.6 dispatch maps cleanly onto CLOS multiple dispatch — idiom convergence note (not a gap)

**V7 section:** §6.5 (dispatch chain) / §6.6 (handler resolution + operation dispatch).
**Profile field:** `[idiom].clos_dispatch = true` (the distant-idiom probe).
**The probe.** Common Lisp is the first peer to express operation dispatch as a CLOS
GENERIC FUNCTION with MULTIPLE DISPATCH on `(handler-class × operation)`: each MUST
handler is a class, each operation is a method on `HANDLE-OP` specialized by the
handler class AND an EQL specializer on the operation keyword, and "unknown operation
→ 501" is the **default method** rather than a `| other ->` fall-through. The four
prior peers (C#/TS/OCaml/Elixir) all express the SAME §6.6 surface as a
single-dispatch `switch`/`match op with` ladder inside one function per handler.
**Finding.** The §6.6 dispatch contract is **idiom-neutral**: the `(handler, op)` pair
the spec already treats as the dispatch key is literally the CLOS specializer tuple,
so the multiple-dispatch decomposition lands on byte/behavior-identical dispatch with
NO spec ambiguity surfaced. The convergence of four single-dispatch idioms + one
multiple-dispatch idiom on the same dispatch behavior is mild corroboration that §6.6
is well-specified (a tightness signal). No change requested.
**One CL-specific footgun (recorded, resolved locally):** `cl:identity` is a LOCKED
standard symbol, so the L1 identity struct cannot be named `identity`. Resolved by
naming the struct `keypair` with `(:conc-name identity-)` so the public accessors stay
`identity-hash` / `identity-peer-id` / … (the cohort's surface) while the type name
dodges the package lock. Implementation detail, not a spec matter.
**Escalation:** none — convergence/idiom note for the cross-peer architectural review
ledger (corroborates the §6.6 surface is idiom-neutral across five idioms).

---

## A-CL-009: address-space tree-path hex-case is unspecified in V7 (lowercase is the de facto convention) — NEW ⚑

**V7 section:** §3.4 / §3.5 (invariant-pointer paths `system/signature/{hash}`), §5.1
(revocation marker path `system/capability/revocations/{hash}`), §6.9a policy paths,
and the §1.5 content_hash hex rendering — none state hex-CASE normatively.
**Profile field:** absent — a spec/oracle convention question.
**The finding (surfaced live at S4).** The §3.4/§3.5/§5.1/§6.9a address-space paths are
keyed by the **hex of the entity content_hash**, and those tree paths are
**case-sensitive string keys**. The Go oracle renders them with `hex.EncodeToString`
(**lowercase**) and the sibling peers with `%02x` (**lowercase**). The CL `hex` helper
emitted **uppercase** (`~2,'0x`), which was internally consistent — so S3's CL-to-CL
loopback PASSED — but produced case-mismatched tree-path keys the oracle (lowercase)
could not find → 404 on the register grant-signature
(`core_register_grant_signature_at_invariant_path` + unregister symmetry) and the §5.1
revoke marker (`revoke_happy_path_writes_marker` + `revoked_cap_denied_on_use`). **The
convention is NOWHERE stated normatively in V7** — it is implicit in the reference impl's
`hex.EncodeToString` default. This is exactly the class of trap a self-consistent peer
hides until cross-impl: any peer whose stdlib hex defaults to uppercase (CL `~x`, some
Pascal/Ada/SQL hex builtins) passes its own loopback and fails the oracle.
**Your guess (the fix):** render all address-space hex **lowercase** to match the Go
oracle + the cohort. Fixed `peer-model.lisp` `hex` → lowercase; all path writes AND reads
route through it so internal consistency is preserved while interop is restored.
**Why this is logged ⚑.** It is a latent interop trap that the conformance corpus only
catches at the live (S4) gate, not at the codec (S2) gate, and is invisible to a
single-peer loopback. The CL idiom (default `~x` is uppercase) is what surfaced it — a
distant-idiom probe paying off.
**Escalation:** **arch** — V7 §3.4/§3.5 (and the §1.5 content_hash hex rendering) SHOULD
state hex-case explicitly (lowercase) since tree paths are case-sensitive string keys.
Corroborates the general "hex-case unspecified" interop-trap class. Resolved locally.

---

## A-CL-010: ASDF's `:version` field has no SemVer pre-release channel — packaging note (NEW)

**V7 section:** absent (build/packaging, not a spec question).
**Profile field:** `[publishing]` / version-pin (S5 §Version-pin).
**The finding (surfaced at S5 packaging).** The keystone lifecycle parks pre-release peers
at the **`0.1.0-pre`** version LINE. ASDF's component `:version` field, however, accepts
**dotted-integer versions ONLY** (`PARSE-VERSION`); a `"0.1.0-pre"` value is rejected at
load with `WARNING: Invalid :version specifier … using NIL instead`, leaving the loaded
system with a NIL version — strictly worse than a clean dotted version (a consumer's
`(asdf:version-satisfies …)` then can't reason about it). There is no SemVer pre-release
or build-metadata channel in the ASDF version grammar.
**Your guess (the fix):** carry the parseable **`0.1.0`** in the three `.asd` `:version`
slots (so the systems load warning-free and `component-version` is reasonable), and carry
the **`0.1.0-pre` pre-release LINE** out-of-band in `CHANGELOG.md` + `README.md` +
`status/PHASE-S5.md` (with a header note in each). This is the honest CL-idiom resolution:
ASDF tracks the release version; the human-facing pre-release marker lives in the docs.
**Rationale.** No other peer hit this: opam (OCaml), `build.zig.zon` (Zig), `package.json`
(TS), `.csproj` (C#), and `mix.exs` (Elixir) all accept a SemVer `-pre`/`-rc` suffix
directly. ASDF is the one cohort build-system whose version grammar is strictly numeric —
a small distant-idiom packaging wrinkle, not a spec matter.
**Escalation:** **operator** — local packaging decision; recorded so a future promotion to
`0.1.0` (or a `0.2.0-pre`) re-applies the same split (numeric in `.asd`, `-pre` in docs)
rather than re-litigating it. NON-blocking for the gate.
