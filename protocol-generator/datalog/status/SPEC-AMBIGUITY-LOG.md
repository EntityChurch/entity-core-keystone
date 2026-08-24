# entity-core-protocol-datalog — Spec / Profile Ambiguity Log

Every guess, deferral, and finding for the Datalog peer. Format per
`lifecycle/PROMPT-CONSTANTS.md`. No blocking-severity items at S1. `A-DL-*` numbering.

The `[expressibility]` findings (which §5/§6.6 surface expressed cleanly as rules vs.
leaked to the host) are the **payoff of this probe** — S3 logs each one here as it
authors, and they synthesize into the S5 `authority-as-query.md` retrospective.

---

## A-DL-001: Runtime selection — embedded Ascent vs. batch Soufflé vs. CozoDB

**Spec section:** absent (build-tooling decision)
**Profile field:** `[engine]`
**Your guess:** Embedded **Ascent 0.8.0** in a **Rust** host. Rejected batch Soufflé
(per-request C++ process-spawn/harness tax; batch not embedded), CozoDB (whole DB engine
+ CozoScript dialect, heavier seam), Datafrog (low-level iteration library — rules not
legible as rules → fails the wrapper-guard), Nemo (existential rules, heavier than needed).
**Rationale:** genuine bottom-up/set-oriented/terminating Datalog (the hard requirement) +
in-process (no spawn tax) + Rust already owns the codec/crypto/socket story (cleanest
seam). Proven by the GO-gate build (all three legs green in the real substrate).
**Escalation:** operator — local decision (recorded, resolved at S1).

## A-DL-002: Distinctness from the Prolog peer

**Spec section:** absent (paradigm-probe design)
**Profile field:** `[distinctness]`
**Your guess:** Ascent is provably distinct from SWI-Prolog on evaluation (bottom-up
semi-naive fixpoint vs. top-down SLD), semantics (set-oriented vs. ordered clause DB +
backtracking), and control (no cut/backtracking/non-termination; terminating by
construction). The §5.5 delegation closure is authored as a monotone recursive rule to
least fixpoint — the SecPAL/Binder trust-management shape.
**Rationale:** the probe's finding depends on this distinctness; a collapse into Prolog's
model would make the finding a re-run. GO-gate leg 1 exercised the bottom-up closure.
**Escalation:** research — the distinctness IS the discovery axis (informs LANDSCAPE/
PARADIGM-MAP once the peer lands).

## A-DL-003: Codec provenance version skew (v7.71 vs. target v0.8.0) — **RESOLVED (S2)**

**Spec section:** §1.x wire core (V7→V8 cutover)
**Profile field:** `[spec] version_pinned`
**Your guess:** Accept the in-repo `libentitycore_codec` (ec_impl_info → `spec-data
v7.71`) for the v0.8.0 (V8) target, on the AGENTS.md guarantee that the **core wire is
byte-unchanged across V7→V8**. Confirm at S2; rebuild the codec if a v0.8.0-stamped C-ABI
build lands.
**Rationale:** same codec the pd/oz/io seam-hybrid peers consume; core-wire-unchanged is
an explicit ecosystem invariant. Non-blocking.
**Escalation:** research — S2 verification task (codec pin freshness).
**RESOLUTION (2026-07-16, S2, byte-identity — not assumption):** the v7.71-labelled
`libentitycore_codec` (`ec_impl_info` = `c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 /
libsodium 1.0.22`) produced **byte-identical output for all 71 v0.8.0 corpus vectors**
(encode + decode_reject + content_hash + peer_id + signature), run in-container /
capped / offline via `run-s2.sh`. This PROVES the core wire is unchanged across V7→V8
for every surface the corpus touches. No divergence → **no `HANDOFF-TO-ARCH`
warranted.** Closed.

## A-DL-004: Scope/resource glob match — rule vs. host-asserted fact (§5.5a)

**Spec section:** §5.5a (scope/resource prefix + the "*"/"/*/*" dual form)
**Profile field:** `[authored] scope_match`, `[expressibility] s55a_scope_match_expected`
**Your guess:** The scope/resource GLOB match may need a host-asserted `scope_covers(
GrantScope, ReqPath)` fact if the Datalog atom model can't express glob/prefix directly;
the MATCH DECISION is a fact, the DECISION LOGIC (how a covered scope feeds the verdict)
stays a rule. Pre-resolve the A-PD-017 dual-form trap: the open/debug seed needs
`resources = ["*", "/*/*"]` (bare-star is granter-local, not universal).
**Rationale:** string-glob is a host strength; forcing it into rules would be the
wrapper-guard's inverse failure (contorting the paradigm). The seam is drawn at what
Datalog can't cleanly do. S3 confirms whether a prefix rule suffices or a host fact is
needed — a genuine expressibility finding either way.
**Escalation:** arch — a clean/awkward scope-match is a spec-shaped expressibility datum.

## A-DL-005: Temporal validity (expiry / not-before) — host clock, rule comparison

**Spec section:** §5.2 (capability_expired / not-yet-valid)
**Profile field:** `[expressibility] temporal_expected`
**Your guess:** Datalog has no clock; the host asserts `now(T)` + `expires_at(Tok,T2)` as
facts, and the COMPARISON (`temporal_valid <-- now(T), expires_at(Tok,E), T < E`) is a
rule.
**Rationale:** time is external state (host); the ordering relation is deductive. Pre-
resolve A-PD-016: content-addressed mint `created_at` must be **ms precision** (second-
truncation aliases same-scope same-second mints → the revoke-probe cascade in the full
profile run).
**Escalation:** research — profile field guidance; S3 confirms.

## A-DL-006: K-of-N multisig — accept-path unit test mandatory

**Spec section:** §3.6 / §3.9 (K-of-N threshold)
**Profile field:** `[authored] k_of_n`, `[testing] accept_path_tests`
**Your guess:** Author K-of-N as a Datalog counting aggregate (`allow(H) <-- threshold(
H,K), count of distinct verified_signer(H,_) >= K`) AND add a genuine 2-of-3 accept-path
unit test — the `multisig` oracle category was 100% malformed→403 for prior peers
(rejection-only → a fail-closed peer passes vacuously without the primitive).
**Rationale:** the durable "conformance-green can be vacuous" lesson; the accept path is
exactly what the oracle can't cover and what the aggregate must actually implement.
**Escalation:** research — accept-path test is a standing keystone discipline.

## A-DL-007: §6.5 dispatch sequencing + §4 handshake — expected leak to host

**Spec section:** §6.5 (op-switch / dispatch sequencing), §4 (handshake lifecycle)
**Profile field:** `[authored] leaks_to_host`, `[expressibility] s65/handshake_expected`
**Your guess:** These leak to the Rust host — Datalog has no sequencing and no mutable
connection state. This is EXPECTED and is itself part of the seam-split finding, not a
failure.
**Rationale:** the authorization-DECISION half is deductive (fits); the protocol-
SEQUENCING + I/O half is stateful-imperative (host). Documenting where/why is the probe's
co-equal deliverable.
**Escalation:** research — the seam split is the headline finding (→ S5 authority-as-query
retrospective).

## A-DL-008: content_hash.4 synthetic format_code 128 — dual-acceptance (S2)

**Spec section:** §1.2 / §4.1a (content_hash_format LEB128 codes); N1
**Profile field:** `[codec] varint_handling`; `[testing]`
**Your guess:** The `content_hash.4` vector (`format_code: 128`) has canonical bytes
present, but the ECF corpus note allows an impl to **either** emit them **or** report
`unsupported_content_hash_format`. `libentitycore_codec` supports only {0x00 SHA-256,
0x01 SHA-384} (agility `VARINT-MULTIBYTE-1` rejects 128), so it returns
`EC_DECODE_ERROR`. The S2 harness treats a `Decode` error on a `format_code ≥ 2`
content_hash vector as the **conformant report-unsupported branch** — logged as a
`note:`, counted PASS (not FAIL).
**Rationale:** the vector is explicitly dual-accepting; forcing an "emit wrong bytes"
match would violate the codec's own supported-code set. The LEB128 varint framing
(N1) is still exercised — `hash_format_code_encode(128)` → `[0x80,0x01]` is unit-tested
directly.
**Escalation:** operator — local harness policy, matches the vector's stated contract.

## A-DL-010: §5.2 verdict + §5.5 delegation express CLEANLY as rules (S3) — the headline

**Spec section:** §5.2 (verify_request verdict), §5.5 (delegation chain)
**Profile field:** `[expressibility] s52_verdict_observed`, `s55_delegation_observed`
**Observed (S3, authored `src/authority.rs`):** both express as legible bottom-up
Datalog, confirming the S1 hypothesis. §5.5 delegation is the **two-rule transitive
closure** to least fixpoint (`confers(c) <-- verified_root(c)` /
`confers(c) <-- verified_link(c,p), confers(p)`) — the SecPAL/Binder trust-management
shape; what imperative peers (the go/rust reference `verify_capability_chain`) walk with
an explicit loop + depth counter + per-link mutable state is the spec's implicit
recursion made explicit. §5.2 verdict is a **derived** `allow(c)` relation; **fail-closed
is structural** — the absence of an `allow` tuple IS denial (the closed-world assumption),
whereas an imperative peer encodes fail-closed as an explicit final `return Deny`
fallthrough that a refactor can drop silently.
**Finding / escalation:** research/arch — the deductive structure of the authority model
is real and legible. **Candidate HANDOFF-TO-ARCH** (see A-DL-013 for the framing).
The wrapper-guard held: the rules DRIVE the verdict end-to-end (S3 loopback + Go-interop
gate exercises `authorize()`), not decoration over a host if-ladder.

## A-DL-011: §5.5a scope match — glob DECISION host-side, CONJUNCTION a rule (S3)

**Spec section:** §5.5a (scope/resource prefix + the "*"/"/*/*" dual form)
**Profile field:** `[expressibility] s55a_scope_match_observed`; refines A-DL-004
**Observed:** exactly the predicted seam. The string-glob **decision** (prefix + dual-star)
leaked to the host, asserted as per-grant per-dimension facts (`g_op` / `g_handler` /
`g_peer` / `g_resource`); the **within-grant conjunction** is a clean 5-way join
(`scope_ok(c) <-- scope_grant(c,g), g_op(c,g), g_handler(c,g), g_peer(c,g), g_resource(c,g)`).
NEW nuance: the correctness property "all four dimensions covered by ONE grant, NOT four
different grants" falls out of the join on the grant index `g` for free — imperative peers
enforce it with a nested loop + a per-grant flag; the rule cannot express it wrong. The
A-PD-017 dual-form seed `["*","/*/*"]` was baked into `open_grants_scope()`.
**Escalation:** arch — a clean expressibility datum (the join encodes a correctness
invariant structurally).

## A-DL-012: K-of-N distinctness is a FIXPOINT property, not an EDB property (S3)

**Spec section:** §3.6 / §3.9 (K-of-N threshold), §5.5 M4
**Profile field:** `[expressibility] k_of_n_observed`; `[authored] k_of_n`
**Observed — a genuine expressibility surprise:** the counting aggregate expresses cleanly
(`quorum_met(c) <-- threshold(c,k), agg n = count() in distinct_signer(c,_), if n >= k`),
BUT Ascent deduplicates **derived (IDB)** tuples, NOT **pre-seeded (EDB)** relation
vectors. Counting the EDB `multisig_signer` relation directly counted a **duplicated**
signature twice → a 1-of-3 quorum falsely met a 2-of-3 threshold. The distinctness the
trust-management literature attributes to Datalog is a property of the **fixpoint**, not of
externally-loaded facts. Fix = a one-line copy-rule (`distinct_signer(c,s) <-- multisig_signer(c,s)`)
moving the facts into the IDB where set semantics apply. **Silent if missed** — the count
is just wrong, no error. Pins the mandatory 2-of-3 accept-path (A-DL-006) as a unit test
(`k_of_n_2_of_3_accept_path`) + the negative `k_of_n_duplicate_signer_does_not_inflate`.
**Escalation:** research — a reusable Datalog-substrate lesson (any peer counting an
externally-loaded relation for a threshold hits this).

## A-DL-013: the SEAM SPLIT — dispatch/handshake/temporal leak to host (S3) — the finding

**Spec section:** §6.5 (dispatch sequencing), §4 (handshake lifecycle), §5.2 (temporal)
**Profile field:** `[expressibility] s65/handshake/temporal_observed`, `finding_observed`
**Observed:** the co-equal deliverable. The **authorization-decision** half (§5.2 verdict,
§5.5 closure, §3.6 K-of-N, §5.5a conjunction, §6.6 resolution) is deductive and lives in
`src/authority.rs` as rules; the **protocol-sequencing + I/O** half is stateful-imperative
and correctly leaks to the Rust host (`dispatch.rs` / `host.rs`): §6.5 op-switch has no
ordering in Datalog; the §4 handshake is a mutable per-connection state machine
(nonce→established); framing/crypto/store are bytes/effects. Temporal validity was
**folded into the host-established facts** (the clock stays entirely host-side) rather than
asserted as `now(T)`+`expires_at(E)` + a comparison rule — a judgment call trading rule
visibility for a cleaner seam. The seam falls almost exactly where S1 predicted.
**Candidate HANDOFF-TO-ARCH:** the spec prescribes §5.2/§5.5 **imperatively**
(verify_request walks a chain; check_permission loops grants), but the underlying logic is
a **monotone deductive system**. An "authority-as-query" appendix could specify the verdict
as a DERIVATION — making fail-closed + the within-grant conjunction structural invariants
rather than prose MUSTs an imperative implementation can violate silently. Does the spec's
authority model have an implicit deductive structure that imperative peers obscure? — S3
says **yes**, for the whole §5/§6.6 decision surface.
**Escalation:** arch — **escalated to arch, overseer-routed** (the overseer is authoring the
`HANDOFF-TO-ARCH` for the authority-as-query appendix; synthesized in
`research/evaluations/authority-as-query.md`). This peer's full-gate green + the wrapper-guard
holding at the live bar are the evidence backing the handoff. **Open, named-owner (arch).**

## A-DL-014: §6.6 handler resolution — longest-prefix as stratified negation (S3)

**Spec section:** §6.6 (handler resolution — longest-prefix-first tree-walk)
**Profile field:** `[expressibility] s66_resolution_observed`; `[authored] handler_resolution`
**Observed:** clean-rule. A second `ascent!` block (`Resolver`) expresses the backward
tree-walk declaratively: `longer_exists(p) <-- candidate(p,lp), candidate(_,lq), if lq>lp`
then `resolved(p) <-- candidate(p,_), !longer_exists(p)` (stratified negation — "the
candidate with no strictly-longer candidate"). The visual-paradigm probes (FLOW-DESIGN)
flagged §6.6 as the surface most easily buried behind a host `resolve()`; here the host
provides only prefix **membership** (which handler-bearing ancestors exist), and the
**longest-prefix SELECTION** is the rule — the mechanism is on the canvas, not hidden.
**Escalation:** research — confirms §6.6 is deductively expressible (not just delegation).

## A-DL-015: the §9.5 type floor is a HOST render, not authority logic (S4)

**Spec section:** TYPE-SYSTEM §8–§10 / V7 v7.72 §9.5 (the 53-type Core Type Floor)
**Profile field:** `[expressibility]` (new datum); `[authored]` (unaffected)
**Observed (S4):** the largest single S4 bucket (107 fail) was the unpublished type
floor. The fix is entirely host-side: render the 53 core `system/type` definitions
NATIVELY (`src/types.rs`, a fluent `FSpec`/`TypeDef` builder mirroring the reference
registry's field shapes, rendered through the byte-green C-ABI codec) and seed them at
`system/type/<name>`; the oracle fetches them via a `system/tree` get with a
`system/type/*` resource target (confirmed by the baseline 404-not-501 — the fetch is a
tree get, so seeding the store suffices; no `system/type` GET handler is needed). This
is the durable "render natively, don't ingest bytes" lesson applied — the Go-rendered
`shared/test-vectors/v0.8.0/type-registry-shapes.json` is the drift target, NOT a byte
source. **The finding:** the type registry is *published DATA*, orthogonal to the
§5/§6.6 authority-decision interior — a clean example that "not everything a core peer
serves is authority logic." Completing it (and every other S4 handler) added ZERO
`ascent!` rules; the deductive interior authored at S3 passed the full live-peer gate
unchanged. This CONFIRMS the A-DL-013 seam split at the higher bar.
**Escalation:** operator/research — an implementation datum (reusable: any peer's type
floor is a host render), not a spec gap. Feeds the S5 authority-as-query retrospective.

## A-DL-009: SELinux build-seam — CARGO_TARGET_DIR off the bind mount (S2)

**Spec section:** absent (build-tooling)
**Profile field:** `[container]`
**Your guess:** On an SELinux-enforcing host, `ld` denies "failed to set dynamic
section sizes: Permission denied" when writing a shared object (Ascent's proc-macro
dylib, `ascent_macro.so`) onto the `:Z`-relabelled `/work` bind mount. `run-s2.sh`
sets `CARGO_TARGET_DIR=/tmp/dl-target` (container-local) so linking happens on the
container filesystem; `Cargo.lock` is a plain file write next to `Cargo.toml` on the
mount and still persists to the host.
**Rationale:** first Rust-crate build on the mount in this repo (pd = C/make, prolog =
swipl); the proc-macro dylib link is what trips SELinux, not the peer binary. A
build-tooling workaround, not a spec/profile gap.
**Escalation:** operator — recorded for the S3/S4 Rust build loop (same env applies).

---

## S5 finalization — disposition of every item (2026-07-16)

At publish, every `A-DL-*` item is either **RESOLVED** or **named-owner-escalated** (no
blocking-severity item remains open unowned).

| Item | Surface | Disposition |
|---|---|---|
| A-DL-001 | runtime selection (embedded Ascent) | **RESOLVED (S1)** — operator, GO-gate-proven |
| A-DL-002 | distinctness from Prolog | **RESOLVED (S1)** — research; the discovery axis, confirmed bottom-up ≠ SLD |
| A-DL-003 | codec provenance V7→V8 skew | **RESOLVED (S2)** — byte-identical 71/71; no handoff warranted |
| A-DL-004 | §5.5a scope glob — rule vs. host fact | **RESOLVED (S3)** — superseded by the A-DL-011 observation |
| A-DL-005 | temporal validity | **RESOLVED (S3)** — folded host-side (A-DL-013); ms-precision trap pre-resolved |
| A-DL-006 | K-of-N accept-path unit test | **RESOLVED (S3/S4)** — accept-path test + live 2-of-3 accept both green |
| A-DL-007 | §6.5/§4 leak to host | **RESOLVED (S3)** — confirmed as predicted; the seam split (see A-DL-013) |
| A-DL-008 | content_hash format_code 128 dual-accept | **RESOLVED (S2)** — operator harness policy, matches the vector contract |
| A-DL-009 | SELinux `CARGO_TARGET_DIR` build seam | **RESOLVED (S2)** — operator; documented in README + run scripts |
| A-DL-010 | §5.2/§5.5 express cleanly as rules | **RESOLVED (S3)** — the headline expressibility finding; feeds A-DL-013 |
| A-DL-011 | §5.5a conjunction as a join invariant | **RESOLVED (S3)** — a clean expressibility datum; feeds the arch handoff |
| A-DL-012 | K-of-N EDB-vs-IDB distinctness | **RESOLVED (S3)** — fixed (copy-rule); **durable cross-substrate implementation lesson**, research-owned |
| A-DL-013 | the SEAM SPLIT / authority-as-derivation | **ESCALATED TO ARCH, overseer-routed** — the arch-handoff candidate; `HANDOFF-TO-ARCH` in progress. **Open, named-owner (arch).** |
| A-DL-014 | §6.6 resolution as stratified negation | **RESOLVED (S3)** — confirms §6.6 is deductively expressible |
| A-DL-015 | §9.5 type floor is a host render | **RESOLVED (S4)** — an implementation datum (type registry = published data ≠ authority logic), operator/research |

**Net:** 14 resolved, 1 named-owner-escalated to arch (A-DL-013, overseer-routed). The
`[expressibility]` findings (A-DL-010/011/012/013/014/015) are synthesized in the S5
retrospective `research/evaluations/authority-as-query.md` (overseer-authored — outside
this peer-local S5 scope).
