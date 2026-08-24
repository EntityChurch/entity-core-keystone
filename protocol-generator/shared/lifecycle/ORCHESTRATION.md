# Running the S1→S5 pipeline as an overseer + per-stage sub-agents

> Process note (plain prose, not a state machine — per AGENTS.md). This is *how*
> we drive the phase contracts in this directory, not a new set of gates. The
> gates are still the ones in `PHASE-S*.md` and the oracle.

There are two ways to run `/entity-rosetta <lang>` S1→S5:

1. **Single session, all five phases inline.** One agent walks S1→S5 in one
   context. Simple, but the context accumulates every phase's noise; late phases
   drift and slow down (the "it took quite a bit of time" problem).
2. **Overseer + sub-agents (this note).** A primary/overseer session holds only a
   thin coordination thread and spawns a **fresh sub-agent per stage**. Each
   sub-agent starts clean, does one phase, hands back a report; the overseer
   reviews it against the phase gate and either advances or bounces it back.
   Fresh-context-per-stage is what keeps late phases from bogging down.

## Relationship to the coordination-layer runbook (the established practice)

The coordination discipline itself — the worktree/two-clone model, memory-seeding,
and S4-port-isolation for concurrent runs — is owned by an internal coordination
runbook that is **not part of this repo and is not published**. It is named here by
role rather than by path, because a public reader cannot open it and a citation they
cannot resolve is worse than none. What matters for anyone reading *this* file is
that the discipline lives somewhere else on purpose: **do not duplicate it here.**

**Per-stage-sub-agent is the practiced model, not a new idea.** That runbook's
prose header talks about "a sub-agent per language," but its own proof records are
explicit that the *actual* decomposition was per **stage**: *"one sub-agent per
phase, all background"* (the Common Lisp and Zig full-pipeline entries). The
overseer spawns a fresh sub-agent for S1, reviews, spawns a fresh one for S2, and
so on — tracking only the transitions between them. The parallelism ceiling
reached so far was **two languages at once** (C+Ada, Ruby+Go+Prolog), each still
decomposed stage-by-stage and gated forward on its own report — not two languages
each run end-to-end in a single sub-agent. This note just writes that practice
down in the keystone repo so it's local to the phase contracts it drives.

## The overseer does / does not

The overseer (primary session):

- **Does:** brief each stage sub-agent; review its report against the phase exit
  gate; run/read the oracle verdict at the gate; commit each green stage locally
  (DCO-signed); decide advance-vs-bounce; keep the ambiguity/findings log honest;
  write the handoff.
- **Does NOT:** write peer code, hand-roll the codec, run `podman build` inline,
  or "just fix it myself." Stage work happens in the sub-agent. If the overseer
  starts editing `src/`, the pattern has collapsed back to single-session.

## The briefing packet (what each stage sub-agent gets)

A fresh sub-agent has none of the overseer's context, so brief it explicitly:

- The phase contract: `lifecycle/PROMPT-CONSTANTS.md` + `lifecycle/PHASE-S<N>-*.md`.
- The profile: `protocol-generator/<lang>/profile.toml` (once S1 authors it) — the
  authority on every library/idiom/packaging choice. *Profile decides; the agent
  doesn't.*
- The prior stage's handoff: `protocol-generator/<lang>/status/PHASE-S<N-1>.md`
  and the ambiguity log, so it picks up where the last stage left off.
- Cohort precedents to study (not copy): the nearest already-shipped peers. For
  an FFI-hybrid alien substrate, that's COBOL / Tcl / Rexx (`status/` + `profile.toml`).
- The boundaries: spec-data is immutable, oracles are never doctored, no writes
  outside the working tree, container-bound execution with the resource caps.

## The per-stage gates (advance only when the gate is green)

| Stage | Sub-agent produces | Gate the overseer checks before advancing |
|---|---|---|
| **S1** profile | `profile.toml`, `arch/PROFILE-RATIONALE.md`, `containers/<lang>-toolchain/`, `status/PHASE-S1.md`, ambiguity log | Every profile field populated (no `TBD` blocking S2); container authored; no blocking-severity ambiguity |
| **S2** codec | codec `src/`, `status/PHASE-S2.md` | **`wire-conformance` byte-identical — 69/69, 0 fail** (or the FFI differential) |
| **S3** peer | peer `src/`, smoke runner, `status/PHASE-S3.md` | **Smoke runner green** (handshake both ways + 404 + `request_id` demux); peer compiles; reads as native `<lang>` |
| **S4** conformance | `CONFORMANCE-REPORT.{md,json}`, `status/PHASE-S4.md` | **`validate-peer --profile core` Result: PASS — 0 FAIL**; skips honestly allow-listed; report is `N·0F @ <oracle-commit>` |
| **S5** publish | README, license, CI, packaging, `status/PHASE-S5.md`, matrix row | Publishable artifact; **no green report → no publish**; `CONFORMANCE-MATRIX.md` row added |

A failed gate **bounces to the same stage** (re-spawn or `SendMessage` the stage
sub-agent with the specifics) — never advance on a red or a skip. A skip counts as
a failure until it's bisected and honestly allow-listed.

## Isolation on this machine

The parallel runbook's worktree/two-clone model is for a machine running several
languages at once. On a machine building **one** language, the established local
convention is to build **in-place on `dev`** (that's how Tcl #23 and Rexx #24 were
done here), committing per stage. The stage sub-agents share this one tree — which
is *required* for the per-stage model, since S2 builds on S1's committed profile,
S3 on S2's codec, and so on. Commits stay **local; pushing is a deliberate
operator step** (no force-push, no history rewrite — the golden rules hold).
