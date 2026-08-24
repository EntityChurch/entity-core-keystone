# entity-core-keystone — status

_Updated: 2026-07-11 · public: v0.8.0 (master)_

## Where it is

The **canonical cross-language conformance keystone** for the entity-core
ecosystem (provided, not mandatory — anyone may build a ground-up
implementation instead). Its `/entity-rosetta` generator skill turns the one
pinned spec snapshot into a full **core-protocol peer**
(`entity-core-protocol-<lang>`, V8 Layers 0–4: substrate, identity,
interaction, capability, bootstrap) for any target language, and it owns the
**codec C-ABI** (`ffi-generator/c-abi/spec/`, building `libentitycore_codec`)
for languages without mature canonical-CBOR + Ed25519 stacks. Generating peers
is the *means*; the *end* is **spec refinement** — running the generator across
many languages surfaces every spec ambiguity and feeds it back to architecture.
Maturity: **initial public research-preview, v0.8.0 (V8)**. A **24-language**
peer cohort is in place and uniformly conformant; the pipeline is past
first-build and into steady-state maintenance. The two newest are alien-substrate
probes: **Tcl** (#23 — Everything-Is-A-String) and **Rexx** (#24 — native-decimal
number model), both complete S1→S5 and measured natively at `cc1970f`
(**682·0F** each). Peer **#25 (Forth** — the stack-machine/no-types substrate) is
now in build via the overseer + per-stage-sub-agent orchestration
(`protocol-generator/shared/lifecycle/ORCHESTRATION.md`).

The single pinned input is `protocol-generator/shared/spec-data/v0.8.0/` (a
verbatim, SHA-256-pinned snapshot of the normative specs) plus the co-versioned
golden vectors in `protocol-generator/shared/test-vectors/v0.8.0/`. At the V8
cutover the core spec was de-versioned (`…-V7.md` → `…​.md`) with the **core
wire byte-unchanged**; the `v7.*` snapshots were retired.

## Where we left off

The closed cohort is **24 generated core peers** (OCaml, Swift, Haskell, Go,
Lean, C#, TypeScript, Java, Kotlin, Elixir, Common Lisp, Rust, Python, Zig, C,
C++, Ada, Ruby, Prolog, PHP, Dart, COBOL, Tcl, Rexx), every one full S1→S5 and
**`validate-peer --profile core` 0-FAIL**. **Rexx** (the native-decimal
number-model probe) is the newest — measured **natively** at `cc1970f`
(**682·0F**, 291P/295W/0F/96S; genuine 2-of-3 multisig accept-path;
origination-core `dispatch_outbound_reentry` 3/3). Its S4 surfaced two
§4.9/§4.10 resilience findings, both fixed (unbounded per-request signature
ingest A-RX-014; the §4.10(c) connection-admission cap). **Tcl** (the EIAS
probe) preceded it at the same **682·0F**. The whole cohort is now normalized on
the reproducible public-HEAD oracle `cc1970f` (2026-07-10 re-normalization). The
`--profile core` **0-FAIL** gate at `cc1970f` is *proven* the same gate the cohort
converged against — its normalized core-gate fingerprint (the 16-category set +
53-type floor, comment-invariant) is `8261a03…`, and the now-retired pin `e8524ed`
differed only by a V8 comment reword that leaves that fingerprint untouched — so
every peer's verdict carries. COBOL was measured **natively** at `cc1970f`
(**291·0F Result: PASS**); the 21 others' extension-inflated **665** full-suite
totals (non-gating; `passed` 291–293 / `skip` 95–96 from extension *matched-if-
present* WARN/PASS) were measured @ the retired `e8524ed` and are carried, not
re-measured — the core 0-FAIL gate is what carries and what `cc1970f` certifies. Per-peer truth (spec version, oracle
commit, codec strategy, crypto floor, known gaps, packaging, tier) lives in
`CONFORMANCE-MATRIX.md` — check it, not this narrative.

Engineering attention has shifted from *adding languages* to two tracks:

1. **Spec-refinement maintenance** — the discovery well is dry on the current
   wire surface, so the value is re-running the cohort against each spec
   amendment, not peer #22-as-discovery. This is tier-tracked: a **Tier-1**
   lockstep set (OCaml · Swift · Haskell · Go · Lean) re-runs on every amendment
   and converges to 0-FAIL before the change is considered landed; Tier-2/Tier-3
   catch up as capacity allows.
2. **The extensibility frontier** — the core↔extension↔SDK boundary. The
   peer-authority bootstrap and the grant-signature placement questions (the old
   "F27/F28") are **resolved** and ratified upstream; the keystone's cross-peer
   **seed-policy convention** is authored (`protocol-generator/shared/seed-policy/`).
   What remains open is the handler-register / outbound-dispatch surface (below).

**COBOL — the 22nd peer (complete).** An FFI-hybrid peer (COBOL value-codec +
`libentitycore_codec` for crypto/SHA-2/framing/base58/Ed25519). It is the peer
where the extensibility surface is exercised end to end — the §6.5 dispatch
chain, `register`/`unregister` (the 5 writes), the seed-policy peer-owner
bootstrap, and now the **§6.11 handler-initiated outbound-dispatch reentry
seam**. State: **289 PASS · 0 FAIL** VALIDATE=0; **291 PASS · 0 FAIL — Result:
PASS** VALIDATE=1 (one honest `t1_3_no_head_of_line` skip allow-listed — its
256 KiB staging payload exceeds the single-threaded host's 64 KiB frame cap, so
the probe can't stage; §4.10(a)-conformant oversize drain). Certified on
`entity-core-go` public HEAD `cc1970f`, whose core gate is proven functionally
identical to the now-retired `e8524ed` (comment-only `profile.go` reword; same
normalized fingerprint). The seam: a C `ec_reentry` pump on the active poll slot (serialized
single-outbound with frame pushback — no request_id map, no deadlock), an
`env-kind` frame classifier, and a full `dispatch-outbound-handler`.
(`protocol-generator/cobol/status/`.)

Stable at the v0.8.0 research-preview line. COBOL's close proved out the §6.11
handler-facing outbound-dispatch seam on a single-threaded poll host; bringing
that seam (and `register`/`unregister`) across the rest of the cohort is the
standing extensibility-frontier work. No protocol changes are in flight.

## Backlog

From `CONFORMANCE-MATRIX.md` §3 (catch-up) and `research/stewardship/SPEC-FINDINGS-LOG.md`:

**Cohort normalization (catch-up).**

- **CLI `--name` normalization** on **C** and **Ada** — both still expose
  identity via `-seed` only; standardize on `--name` persistent-identity to
  match the cohort and enable the multisig accept-path. (Medium.)
- **Verify genuine §3.6 multisig** on the five later-folded peers (C, Ada, Ruby,
  Prolog, Go) — confirm K-of-N is genuine (M3 structure + M4 distinct-signer
  threshold + M6 local ∈ signers) with a positive accept-path test, not
  frame-only, matching the original-cohort closeout. (Medium. Multisig is not in
  `--profile core`, so this does not affect any peer's 0-FAIL.)
- **Ed448 / SHA-384 agility** for the deferred peers (Swift, Zig, C, Ada, Go) —
  the Ed25519 + SHA-256 floor ships; Ed448 via the FFI-hybrid pattern or a
  native lib. (Demand-driven.)
- **Package-registry publish** — peers parked at `0.1.0-pre`/`0.1.0`;
  per-ecosystem upload is an operator step gated on a community pull. (Demand-driven.)
- **Scorecard label fix** — a provenance off-by-one in two peers' baseline
  oracle label (`62044c5` → `b30a589`, the true v7.75 baseline where
  `resource_bounds` activates). (Low.)

**Extensibility frontier (the core↔extension↔SDK boundary).**

- **Handler `register`/`unregister` as a core MUST** (was the generic "F11
  spike") — §6.2/§6.9 make dynamic `register` core protocol, yet the original
  reference trio (C#, TS, OCaml) 501-stubbed it; `--profile core` never exercised
  it because the `handlers` category is static manifest introspection. Wire the
  protocol op to the existing native-binding registry (V1.0/L0 peer-owner write
  now; V2.0/L1 cap-checked follow-on). COBOL has built this; bring the cohort
  along. (Open.)
- **Handler-facing outbound dispatch / §6.11 reentry seam** — no peer yet exposes
  a handler-reachable `execute` closure; §4.8/§6.11 make concurrent outbound
  dispatch (reader-task + request_id correlation) part of the core §9.1 floor.
  This is the one piece blocking COBOL's VALIDATE=1 close and the substrate
  guarantee that an installed handler can originate a request. (Open.)
- **Core-tier oracle extensibility checks** — `--profile core` is a
  hand-maintained Go category map with no machine link to the spec, and it tests
  neither dynamic register nor outbound origination; a peer can pass while being
  responder-only. Ask upstream for a core-tier register + minimal-origination
  check. (Open; oracle-side.)

## Waiting on

- **Architecture** — the steady-state engine is "spec amendment lands → Go ships
  the matching `validate-peer` update → re-vendor oracle → re-run". So the next
  substantive maintenance cycle is gated on the next spec amendment / oracle
  update from upstream. (Per the hand-off boundary, the keystone never edits the
  spec or the oracle; spec/oracle disagreements are escalated as
  `HANDOFF-TO-ARCH-*.md`, not patched here.) The extensibility-frontier oracle
  asks (core-tier register + origination checks) are also upstream-gated.
- **Operator decision** — whether/when to do the demand-driven registry
  publishes; nothing forces it absent a community pull.

## Done recently

- **Alien-substrate probes Tcl (#23) + Rexx (#24) completed — cohort → 24.** Two
  probes on the least-saturated wire axes: Tcl (Everything-Is-A-String) and Rexx
  (native-decimal number model, no binary int/float type). Both full S1→S5,
  FFI-hybrid (hand-rolled canonical CBOR + crypto over `libentitycore_codec`),
  measured natively at `cc1970f` — **682·0F** each. Rexx's S4 surfaced and fixed
  two §4.9/§4.10 resilience findings (A-RX-014 unbounded signature ingest; the
  §4.10(c) connection cap); Tcl was clean corroboration. Per-peer truth in
  `CONFORMANCE-MATRIX.md`.
- **Orchestration pattern documented.** The overseer + per-stage-sub-agent model
  used to drive the pipeline (a fresh sub-agent per S-phase, the overseer tracking
  transitions and gating each stage on its oracle verdict) is now written down at
  `protocol-generator/shared/lifecycle/ORCHESTRATION.md`, cross-referencing the
  meta-repo parallel-languages runbook rather than duplicating it.
- **COBOL peer completed — cohort → 22.** The §6.11 handler-initiated
  outbound-dispatch reentry seam, the last open extensibility gap, is implemented
  on the single-threaded poll host (a C `ec_reentry` pump on the active slot with
  frame pushback + `env-kind` classifier + a full `dispatch-outbound-handler`).
  `--profile core` **291·0F, Result: PASS** (VALIDATE=1), 289·0F VALIDATE=0 (no
  regression). Certified on public-HEAD oracle `cc1970f` (core gate proven ≡
  retired `e8524ed` via the normalized fingerprint). Surfaced a process finding —
  the core-gate sha256 anchor was comment-fragile (a V8 comment reword false-
  alarmed "core gate moved") — **now fixed** (see next bullet).
- **Oracle re-normalization + anchor hardening (2026-07-10)** — re-pinned the
  cohort's oracle to the reproducible public HEAD `cc1970f` (the mirror rewrote
  history, so the old `e8524ed` no longer resolves), and hardened
  `oracle-bootstrap.sh` to fingerprint the *normalized* core gate (16-category set
  + 53-type floor, `8261a03…`) instead of the raw `profile.go` sha256 — comment
  rewords no longer false-alarm, real category drift still trips it (regression-
  tested both ways). Matrix §3 items closed; the two profile.go blobs differing
  only by a comment proves the whole cohort's 0-FAIL gate carries to `cc1970f`.
- **Oracle normalization** — the whole 21-peer cohort re-run on one oracle
  (`e8524ed`) to a uniform **665·0F**; the when/why-to-re-vendor rule is captured
  in `research/diagnostics/oracle-vendoring-policy.md` (incl. the build-once-into-
  repo-root provenance-hygiene lesson behind the superseded per-oracle totals).
- **`run-s4` oracle-path defaults** normalized to the repo-root convention across
  C, Ada, Ruby, Prolog, Rust, Python — they run with no `ORACLE` override.
- **Clean-room Rust + Python peers** built and merged (the large-ecosystem
  adoption peers, the 16th + 17th generated), plus the C++ / Kotlin / PHP / Dart
  reach peers — bringing the closed cohort to 21, all 0-FAIL.
- **Peer-authority bootstrap resolved + convention authored** — the startup
  owner-capability + seed-policy model was ratified upstream (V7 §6.9a /
  `PROPOSAL-V7-PEER-AUTHORITY-BOOTSTRAP`), and the keystone's cross-peer
  seed-policy file-format + CLI convention shipped at
  `protocol-generator/shared/seed-policy/` (owner authority as a self-signed
  root capability, not a debug mode; `--debug-open-grants` is the degenerate
  `default→*` policy). The companion grant-signature-placement question converged
  on the §3.5 invariant-pointer path (`system/signature/{grant_hash}`).
- **Authz dispatch-boundary + chain-attenuation surfaces** closed across the
  reference impls (granter-aware cap-resource canonicalization at the dispatch
  boundary and per-link in the chain walk).
- **Spec-data / oracle** advanced to the V8 surface; the spec was de-versioned at
  the V8 cutover with the core wire byte-unchanged.

## Next

0. **Forth (#25) — in build now** via the overseer + per-stage-sub-agent pattern
   (`ORCHESTRATION.md`). The stack-machine / concatenative / no-types substrate —
   a generator-stress probe, expected FFI-hybrid (COBOL/Tcl/Rexx family: gforth,
   hand-rolled CBOR, crypto + sockets over a C external extension, fixed-width
   cells → int head-form self-test). A second machine is building **Fortran** in
   parallel off this same status. Corroboration/robustness first; a fresh spec
   finding is the upside, not the expectation (the well is dry on the current
   surface).
1. **Extensibility surface across the cohort**: with COBOL's §6.11
   outbound-dispatch seam landed (peer 22 closed), bring `register`/`unregister`
   (V1.0/L0) and the handler-facing outbound-dispatch seam across the remaining
   peers. *(Oracle re-normalization onto `cc1970f` + anchor hardening — done.)*
2. **Work the catch-up backlog**: `--name` on C + Ada, then verify genuine
   multisig + add accept-path tests on the five later-folded peers (C, Ada, Ruby,
   Prolog, Go); fix the scorecard label off-by-one.
3. **Hold Tier-1** (OCaml · Swift · Haskell · Go · Lean) in lockstep — re-run and
   converge to 0-FAIL the moment the next spec amendment / oracle update lands;
   catch up Tier-2/Tier-3 as capacity allows.
4. Treat **package-registry publish** and **Ed448/SHA-384 agility** as
   demand-driven — pick them up on a concrete adopter request, not speculatively.
