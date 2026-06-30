# entity-core-keystone — status

_Updated: 2026-06-30 · public: v0.8.0 (master)_

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
Maturity: **initial public research-preview, v0.8.0 (V8)**. A 21-language peer
cohort is in place and uniformly conformant; the pipeline is past first-build
and into steady-state maintenance, with a 22nd peer (COBOL) near-complete.

The single pinned input is `protocol-generator/shared/spec-data/v0.8.0/` (a
verbatim, SHA-256-pinned snapshot of the normative specs) plus the co-versioned
golden vectors in `protocol-generator/shared/test-vectors/v0.8.0/`. At the V8
cutover the core spec was de-versioned (`…-V7.md` → `…​.md`) with the **core
wire byte-unchanged**; the `v7.*` snapshots were retired.

## Where we left off

The closed cohort is **21 generated core peers** (OCaml, Swift, Haskell, Go,
Lean, C#, TypeScript, Java, Kotlin, Elixir, Common Lisp, Rust, Python, Zig, C,
C++, Ada, Ruby, Prolog, PHP, Dart), every one full S1→S5 and **`validate-peer
--profile core` 0-FAIL on a single current oracle** (`entity-core-go` HEAD,
`e8524ed`; **665 total · 0F**, with the `passed` 291–293 / `skip` 95–96 spread
being extension *matched-if-present* WARN/PASS only — the core verdict is
uniform: **0 FAIL, 0 core-floor gap**). The whole cohort was normalized onto
that one oracle with uniform oracle-path defaults, so the conformance verdict is
now apples-to-apples across all peers. Per-peer truth (spec version, oracle
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

**COBOL — the in-progress 22nd peer.** An FFI-hybrid peer (COBOL value-codec +
`libentitycore_codec` for crypto/SHA-2/framing/base58/Ed25519). It is the peer
where the new bootstrap surface is exercised end to end — it builds the §6.5
dispatch chain, `register`/`unregister` (the 5 writes), and the seed-policy
peer-owner bootstrap. State: **289 PASS · 0 FAIL** on `--profile core` (oracle
`33f35fd`, VALIDATE=0); under VALIDATE=1 its one FAIL is the §6.11
outbound-reentry seam (`dispatch-outbound` is still a 503 stub on the
single-threaded poll-loop host). To join the closed cohort it needs that seam
finished and a re-run normalized onto the `e8524ed` oracle. (`protocol-generator/cobol/status/`.)

Stable at the v0.8.0 research-preview line; no code or protocol changes are in
flight. The next substantive work is finishing the extensibility surface —
bringing `register`/`unregister` and the §6.11 handler-facing
outbound-dispatch seam across the cohort, then closing **COBOL** under
VALIDATE=1 and re-normalizing it onto the `e8524ed` oracle to make the cohort 22.

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

1. **Finish the extensibility surface**: bring `register`/`unregister` (V1.0/L0)
   and the §6.11 handler-facing outbound-dispatch seam across the cohort, then
   close **COBOL** under VALIDATE=1 and re-normalize it onto `e8524ed` to make
   the cohort 22.
2. **Work the catch-up backlog**: `--name` on C + Ada, then verify genuine
   multisig + add accept-path tests on the five later-folded peers (C, Ada, Ruby,
   Prolog, Go); fix the scorecard label off-by-one.
3. **Hold Tier-1** (OCaml · Swift · Haskell · Go · Lean) in lockstep — re-run and
   converge to 0-FAIL the moment the next spec amendment / oracle update lands;
   catch up Tier-2/Tier-3 as capacity allows.
4. Treat **package-registry publish** and **Ed448/SHA-384 agility** as
   demand-driven — pick them up on a concrete adopter request, not speculatively.
