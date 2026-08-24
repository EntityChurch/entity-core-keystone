# entity-core-keystone — status

_Updated: 2026-07-12 · public: v0.8.0 (master)_

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
Maturity: **initial public research-preview, v0.8.0 (V8)**. A **28-language**
peer cohort is in place and uniformly conformant; the pipeline is past
first-build and into steady-state maintenance. The six newest are all
alien-substrate probes, every one complete S1→S5 and measured natively at
`cc1970f` (**682·0F** each): **Tcl** (#23 — Everything-Is-A-String), **Rexx**
(#24 — native-decimal number model), **Forth** (#25 — stack-machine/typeless
substrate), **Smalltalk** (#26 — pure-object/live-image/message-passing
substrate), **Fortran** (#27 — fixed-width **signed-only** integer model, no
portable unsigned type; native IEEE floats), and **APL** (#28 — the **array /
value model**, the array as the primitive value). All six completed via the
overseer + per-stage-sub-agent orchestration
(`protocol-generator/shared/lifecycle/ORCHESTRATION.md`). The final four —
Forth + Smalltalk (one machine) and Fortran + APL (a parallel machine) — were
built **concurrently on two machines and merged here** (2026-07-12): this doc
and `CONFORMANCE-MATRIX.md` reconcile the count → **28** and assign the four
concurrent-probe ordinals. Ordinals among the concurrent four are cosmetic
(all "probe" tier). **APL was the last named alien-substrate candidate** in
`research/LANDSCAPE.md`, so the deliberate substrate sweep is now complete and
steady-state is fully spec-refinement maintenance.

The single pinned input is `protocol-generator/shared/spec-data/v0.8.0/` (a
verbatim, SHA-256-pinned snapshot of the normative specs) plus the co-versioned
golden vectors in `protocol-generator/shared/test-vectors/v0.8.0/`. At the V8
cutover the core spec was de-versioned (`…-V7.md` → `…​.md`) with the **core
wire byte-unchanged**; the `v7.*` snapshots were retired.

## Where we left off

The closed cohort is **28 generated core peers** (OCaml, Swift, Haskell, Go,
Lean, C#, TypeScript, Java, Kotlin, Elixir, Common Lisp, Rust, Python, Zig, C,
C++, Ada, Ruby, Prolog, PHP, Dart, COBOL, Tcl, Rexx, Forth, Smalltalk, Fortran,
APL), every one full S1→S5 and **`validate-peer --profile core` 0-FAIL**. The
last four are the **two-machine concurrent probe wave** (Forth + Smalltalk on one
machine, Fortran + APL on the other), all at **682·0F @ cc1970f**:

- **APL** (#28 — the **array / value-model** probe; the whole canonical-CBOR codec
  expressed as array transforms, ⊤/⊥ base-256 + ⍋-graded map-key ordering) — full
  S1→S5, FFI-hybrid (pure-APL value codec + crypto/base58/framing over
  `libentitycore_codec` via a GNU APL `⎕FX` native-fn shim; **native `⎕FIO`
  sockets, no C net-shim**); **682·0F** (291P/295W/0F/96S; genuine 2-of-3 multisig
  accept-path). Its one wire-touching edge — GNU APL's exact integer ceilings at
  2^63-1 and **silently promotes to lossy IEEE double** above it, so the uint64
  tower cannot be a native scalar at all — closes as **corroboration** (an 8-octet
  big-endian array carrier reproduces the full unsigned tower byte-exact;
  *sharper* than Fortran's controllable signed-carrier, same result). No arch
  finding; banked the durable GNU-APL-1.9 cookbook A-APL-012…017 (the `--script`
  reader rejecting `:If`/dfn-guards; monadic `⊃`=disclose-not-first;
  `≡`=rank-sensitive; two real `⎕FIO` `select` bugs read from the interpreter
  source).
- **Fortran** (#27 — fixed-width **signed-only** integer-model probe; no portable
  unsigned type, native IEEE floats) — full S1→S5, FFI-hybrid (pure-Fortran value
  codec bound **directly via `iso_c_binding`**, no C wrapper — cleaner than the
  Rexx/Tcl shims); **682·0F** (292P/294W/0F/96S; genuine 2-of-3 multisig
  accept-path; §6.13(b) handler-outbound reentry seam wired **live** at S4). Proved
  the signed-carrier uint64 tower carries `[2^63, 2^64-1]` byte-exact
  (corroboration). Banked an arch-bound corpus finding — **A-FTN-012 / F30** (the
  corpus `tag_reject` vectors are vacuous: they reject on trailing-data, not the
  §6.3 tag scanner; `research/stewardship/HANDOFF-TO-ARCH-2026-07-11-ftn-tag-reject-corpus.md`).
  The wave produced **two distinct corpus-coverage findings**: this F30 (tag_reject,
  Fortran) and a separate **F29** from the other machine (an array-of-maps
  ≥24-byte-head gap, corroborated across Forth + Smalltalk;
  `HANDOFF-TO-ARCH-F29-corpus-gap.md`). Both branches independently grabbed F29
  from the shared base → renumbered ours to F30 at this merge.
- **Smalltalk** (#26 — pure-object/live-image/message-passing probe) — **682·0F**
  (291P/295W/0F/96S; genuine 2-of-3 multisig + a 4/4 in-image unit; origination
  `dispatch_outbound_reentry` 3/3), exact Rexx/Forth parity. Codec as a polymorphic
  **`encodeOn:` double-dispatch** over tagged `EcValue` objects (the A-ST-000
  answer, not a translated type-switch), in-process **UFFI** crypto (no co-process),
  bignum uint64 carried FREE. S4 flushed out four peer code bugs — chief **A-ST-016**
  (catch the ROOT `Error`: one live `doesNotUnderstand:` on an unexercised path
  cascaded 229 FAILs on a no-static-check substrate) — plus the durable **A-ST-012**
  polymorphic-absent-sentinel finding.
- **Forth** (#25 — stack-machine/typeless probe) — **682·0F** (291P/295W/0F/96S;
  genuine 2-of-3 multisig; origination 3/3), exact Rexx parity. A
  **native-float-bits** codec (gforth `SF!`/`DF!` give real IEEE bits; only f16 +
  shortest ladder hand-rolled) and the **cleanest FFI binding in the family**
  (in-process `libcc` `c-function`, native BSD sockets — no co-process). S4 flushed
  out seven peer code bugs (chief the concurrency payoff A-FT-025).

**Rexx** (#24) and **Tcl** (#23) preceded the wave at the same **682·0F**. The whole cohort is now normalized on
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
   The handler-`register`/`unregister` write surface and the §6.11
   handler-outbound reentry seam — long carried here as open cohort-wide work —
   are in fact **implemented and passing across the cohort** (audit 2026-07-12,
   below): the §10.1 register gate is 10/10+ and origination-core
   `dispatch_outbound_reentry` is 3/3 on ~every peer. What genuinely remains is
   **oracle-side**: `--profile core` gates neither, so those closures are
   invisible in the gating number (the reason this drift went unnoticed).

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
handler-facing outbound-dispatch seam on a single-threaded poll host — but it was
**not** the only peer to carry it, and "bring the seam + `register`/`unregister`
across the rest of the cohort" is **no longer standing work**: the 2026-07-12
audit (Backlog) found both already implemented and green cohort-wide via the
`run-origination-core.sh` and §10.1 register-gate runners. No protocol changes
are in flight.

## Backlog

From `CONFORMANCE-MATRIX.md` §3 (catch-up) and `research/stewardship/SPEC-FINDINGS-LOG.md`:

**Cohort normalization (catch-up).** — **✅ ALL THREE DONE 2026-07-12.**

> **The catch-up backlog closed — and surfaced a real masked defect.** Verifying
> "genuine multisig" meant making the oracle's accept-path probe
> (`valid_2of3_peer_signed_accepted`) actually RUN (provision the peer keypair +
> boot `--name conformance`) instead of SKIP. It exposed **4 of the 5 later-folded
> peers as FRAME-ONLY**: **Ruby, Go, C, Ada** each rejected a *valid* co-signed
> 2-of-3 cap — a masked conformance defect the reject-dominated `multisig` category
> hid (a fail-closed peer passes all 10 reject probes vacuously; the accept probe was
> skipping). The accept-path FAIL **gates** (a SKIP is auto-allowlisted, a FAIL is
> not), so this was a real 0-FAIL risk once exercised. All four fixed with genuine
> §3.6 M3/M4/M6 (modeled on the genuine Prolog peer) → **682·0F, accept-path PASS @
> `cc1970f`**; Prolog + COBOL were already genuine. Full write-up:
> `research/stewardship/FINDING-2026-07-12-frame-only-multisig-cohort.md`.

- ~~**CLI `--name` normalization**~~ ✅ DONE — wider than framed: **neither Go nor
  Ruby actually had `--name`** (only `--seed`; the matrix overclaimed it) and
  **Prolog's `--name` was a fake** (ignored, seed hardcoded). All five (C, Ada, Ruby,
  Go, Prolog) standardized on the canonical convention: default seed `0x11×32`;
  `--name NAME` loads `~/.entity/peers/NAME/keypair` (Go/Ada default `0x01`→`0x11`).
- ~~**Verify genuine §3.6 multisig**~~ ✅ DONE — 4 of 5 were frame-only; all fixed
  (see finding). Ruby/Go carry unit tests; the Ada fix uncovered **A-ADA-014** (a
  latent §PR-8 fixed-length-String crash); C logged **A-C-011** (a pre-existing
  pthread churn-flake, unrelated).
- ~~**Scorecard label fix**~~ ✅ DONE (`62044c5`→`b30a589` across 9 peer reports).
- **Ed448 / SHA-384 agility** for the deferred peers (Swift, Zig, C, Ada, Go) —
  the Ed25519 + SHA-256 floor ships; Ed448 via the FFI-hybrid pattern or a
  native lib. (Demand-driven.)
- **Package-registry publish** — peers parked at `0.1.0-pre`/`0.1.0`;
  per-ecosystem upload is an operator step gated on a community pull. (Demand-driven.)

**Extensibility frontier (the core↔extension↔SDK boundary).**

> **Audit 2026-07-12 (register + outbound seam).** Prompted by a review challenge
> to the "COBOL + Fortran only" framing, the cohort was swept for both surfaces.
> Result: the first two items below, long carried as open cohort-wide work, are
> **already done and green across the cohort** — corrected inline. Only the
> oracle-side item survives. Evidence is each peer's own `status/` reports; the
> closures live in the `run-origination-core.sh` and §10.1 register-gate runners,
> which are **separate from `--profile core`** — so they never surfaced in the
> gating number, which is why the drift persisted here uncorrected.

- ~~**Handler `register`/`unregister` as a core MUST**~~ **✅ DONE cohort-wide**
  (was the generic "F11 spike"). §6.2/§6.9/§6.13(a) dynamic `register` is
  implemented and passing the **§10.1 register gate 10/10+** (rust 13/13) on
  ada · c · cpp · dart · elixir · haskell · kotlin · ocaml · python · rust ·
  swift · typescript · zig (+ COBOL/Fortran). Swift's report: "register/unregister
  (§6.13a five writes — **NOT a 501-stub**)"; TS: "now implemented behaviorally
  (v7.74 §6.13(a) MUST)"; OCaml even filed a *finding* against the Go register
  gate. The historical "C#/TS/OCaml 501-stubbed it" is a pre-v7.74 state. The
  `handlers` category (static manifest introspection) still doesn't exercise it —
  that gap is the oracle-side item below, not a peer gap.
- ~~**Handler-facing outbound dispatch / §6.11 reentry seam**~~ **✅ DONE
  cohort-wide.** origination-core **`dispatch_outbound_reentry` 3/3** (over real
  two-peer TCP, `reference_connect`·`reference_ready`·`dispatch_outbound_reentry`)
  on ~every peer with `run-origination-core.sh` (21 peers) plus COBOL's
  `t1_2_concurrent_reentry` (8-concurrent) and Fortran's live-at-S4 seam. A
  handler-reachable `execute` closure demonstrably exists everywhere (the §7a
  `system/validate/dispatch-outbound` conformance handler originates the outbound
  request). Under a **single-peer** `--profile core` run the `origination`
  category shows an **auto-allowlisted SKIP** (reference-peer-gated) — that is
  by-design, not a missing seam; the seam runs green via `run-origination-core.sh`
  with a Go `entity-peer` reference.
- **Core-tier oracle extensibility checks** — `--profile core` is a
  hand-maintained Go category map with no machine link to the spec, and it gates
  neither dynamic register nor outbound origination; a peer can pass the gate
  while being responder-only, **and — as this audit showed — a peer that has fully
  built both can have that fact go untracked because the gate never exercises it.**
  Ask upstream for a core-tier register + minimal-origination check. (**Open;
  oracle-side** — the one genuinely-remaining extensibility-frontier item.)

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

- **The two-machine concurrent probe wave completed + merged — cohort → 28.**
  Four alien-substrate probes built concurrently on two machines (Forth +
  Smalltalk on one, Fortran + APL on the other) and merged 2026-07-12, each full
  S1→S5 via the overseer + per-stage-sub-agent orchestration with every stage's
  oracle verdict independently re-run before commit, all **682·0F @ cc1970f**.
  Per-peer truth in `CONFORMANCE-MATRIX.md`:
  - **APL (#28)** — the **array / value-model** probe. FFI-hybrid: pure-APL
    canonical CBOR as array transforms (⊤/⊥ base-256 + ⍋ grade) + crypto over
    `libentitycore_codec` via a GNU APL `⎕FX` native-fn shim; **native `⎕FIO`
    sockets (no C net-shim)**. 291P/295W/0F/96S; genuine 2-of-3 accept-path.
    Numeric edge — GNU APL's exact int ceilings at 2^63-1 and silently promotes to
    lossy double above, so the uint64 tower rides an 8-octet array carrier, never a
    scalar — closes as **corroboration** (sharper than Fortran, same result).
    Interpreter is **GNU APL 1.9 built from a SHA-256-pinned source tarball** (no
    APL is in fedora dnf; the native-fn shim combines into a GPLv3 binary with
    `apl` — isolated to the APL peer, the Apache-2.0 source stays one-way
    compatible). Banked the GNU-APL-1.9 cookbook A-APL-012…017; no arch finding.
  - **Fortran (#27)** — the fixed-width **signed-only** integer-model probe.
    FFI-hybrid, C-ABI bound **directly via `iso_c_binding`** (no C wrapper).
    292P/294W/0F/96S; signed-carrier uint64 tower proven byte-exact across
    `[2^63, 2^64-1]`; §6.13(b) reentry seam wired live at S4. Banked **A-FTN-012 /
    F30** (vacuous corpus `tag_reject` vectors) as a `HANDOFF-TO-ARCH`. (Distinct
    from the other machine's **F29** — an array-of-maps ≥24-byte-head corpus gap;
    both branches took F29 from the shared base, so ours renumbered to F30 here.)
  - **Smalltalk (#26)** — the pure-object/live-image/message-passing probe (Pharo
    13.0). FFI-hybrid: pure-Smalltalk canonical CBOR as a polymorphic `encodeOn:`
    double-dispatch over tagged `EcValue` objects + crypto via in-process UFFI.
    291P/295W/0F/96S + a 4/4 in-image unit; origination 3/3; bignum uint64 FREE. No
    fresh spec finding but four peer code bugs surfaced + fixed — chief **A-ST-016**
    (catch the ROOT `Error`: one live `doesNotUnderstand:` on an unexercised path
    cascaded 229 FAILs on a no-static-check substrate) — plus the durable **A-ST-012**
    polymorphic-absent-sentinel finding. `make dist` + Metacello/Tonel; `0.1.0-pre`.
  - **Forth (#25)** — the stack-machine/typeless probe. FFI-hybrid: pure-Forth
    **native-float-bits** canonical CBOR + the **cleanest FFI binding in the
    family** (in-process `libcc` `c-function`, native BSD sockets, no co-process).
    291P/295W/0F/96S, exact Rexx parity. No fresh spec finding but seven peer code
    bugs surfaced + fixed (chief the concurrency payoff A-FT-025, a latent
    `pend-new` missing-return only concurrent §6.11 reentry exposed). `0.1.0-pre`.
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

0. **The concurrent probe wave — DONE and merged (cohort → 28).** Forth (#25),
   Smalltalk (#26), Fortran (#27), and APL (#28) — four alien-substrate probes
   built concurrently on two machines and merged 2026-07-12, all **682·0F @
   cc1970f** (see "Where we left off"). **APL was the last named alien-substrate
   candidate** in `research/LANDSCAPE.md`, so the deliberate substrate sweep is
   **complete** and steady-state is now fully **spec-refinement maintenance** —
   re-running the cohort against each spec amendment. The wave confirmed the well
   is dry on the current wire surface once more: clean corroboration, only
   code-bug findings + **two distinct corpus-coverage findings** (F29 array-of-maps
   ≥24-byte-head, Forth/Smalltalk; F30 tag_reject vacuity, Fortran), no fresh wire
   finding.
1. **Extensibility surface** — the peer-side `register`/`unregister` +
   handler-outbound seam is **DONE cohort-wide** (2026-07-12 audit; see Backlog),
   *not* standing work. The remaining piece is the **oracle-side** core-tier
   register + minimal-origination check (upstream ask), so the peer-side closures
   are actually gated by `--profile core` rather than only by the separate
   `run-origination-core.sh` / register-gate runners.
2. **Work the catch-up backlog**: `--name` on C + Ada, then verify genuine
   multisig + add accept-path tests on the five later-folded peers (C, Ada, Ruby,
   Prolog, Go); fix the scorecard label off-by-one.
3. **Hold Tier-1** (OCaml · Swift · Haskell · Go · Lean) in lockstep — re-run and
   converge to 0-FAIL the moment the next spec amendment / oracle update lands;
   catch up Tier-2/Tier-3 as capacity allows.
4. Treat **package-registry publish** and **Ed448/SHA-384 agility** as
   demand-driven — pick them up on a concrete adopter request, not speculatively.
