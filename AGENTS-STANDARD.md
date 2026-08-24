# AGENTS-STANDARD.md — how we work (entity-core ecosystem)

**This file is identical in every entity-core repo** — the ecosystem-wide conventions,
maintained in one place and injected unchanged into each repo (the same overlay
mechanism as the community-health files, [ADR-0010]). Your repo's own `AGENTS.md` sits
beside it and adds the repo-specific details (languages, build/test commands, layout,
boundaries). When the two seem to differ, the repo `AGENTS.md` wins on repo-specific
facts; this file wins on ecosystem conventions.

> **For any agent, not just Claude** ([ADR-0016]). Claude reads it via `@AGENTS.md` in
> `CLAUDE.md`; every other agent reads it as the plain sibling file it is.

## What this ecosystem is

entity-core is a **protocol** plus an ecosystem of independent implementations and
tooling, built entirely with AI. It is a **polyrepo** ([ADR-0010]): one spec, several
ground-up reference implementations (`entity-core-{go,rust,py}`), a canonical
conformance anchor (`entity-core-keystone`), formal models, and UI/tooling repos — each
with an independent lifecycle. You are working inside one of them; see its `AGENTS.md`.

## Golden rules (the don't-break-it floor)

- **Never lose or rewrite history.** No history-destroying rebase/reset on shared
  branches, no clobbering remote refs. **Never force-push** (`--force` /
  `--force-with-lease`) — anywhere. If a non-fast-forward ever seems necessary, **stop
  and ask**, don't force it.
- **Stay in your tree.** Don't reach changes into sibling or meta repos. Cross-repo
  coordination goes through the maintainers / a review hand-off, not by editing a
  neighbor's directory. If you *do* read a sibling repo, treat its git as read-only:
  `git status` first, stage **specific paths**, never `git add -A` in a repo that isn't your
  working directory.

## Build & toolchain

- **System toolchains, minimal dependencies** (supply-chain conscious): prefer stock
  tools (e.g. raw `podman run`, not podman-compose); avoid `mise` / `just` / bespoke
  toolchain managers.
- **`make <verb>` is the build interface.** Most repos are thin `make` orchestration over
  **podman** (host needs only `make` + `podman`). A standard verb vocabulary
  (`build` / `test` / `lint` / `fmt` / `check` / `clean`, container-default with a
  `-native` opt-in) is converging — see your repo's `AGENTS.md` for its exact targets.
- **Default branch is `master`** (not `main`).

## Contributing

- **DCO sign-off required** ([ADR-0006]): `git commit -s` → `Signed-off-by:`, from an
  **accountable human** who certifies the right to submit and stands behind the work.
  No CLA. Code is **Apache-2.0** ([ADR-0005]); spec text is licensed separately ([ADR-0007]).
- **AI is welcome and unrestricted** ([ADR-0017]) — this ecosystem is AI-native. No
  AI-usage limit, no mandatory disclosure trailer. The gate is the accountable human +
  the **quality bar**, applied equally however much tooling was used.
- **Open a PR; keep CI and the conformance suite green.** A **tag is a release**, not a
  push — a docs/`AGENTS.md` change doesn't get its own tag ([ADR-0015]). *(The exact
  branch-promotion model is still settling; this file stays contributor-facing.)*

## Working across the polyrepo

- **The spec is upstream; implementations implement, they don't define it.** Don't invent
  wire formats, primitives, opcodes, or handler semantics in an implementation repo.
  Implement against the **landed spec**, not in-flight proposals. Hit a gap or ambiguity?
  **Log it** (e.g. `docs/SPEC-AMBIGUITIES.md`) and route it upstream — don't paper over
  it locally. The locked wire core is never renumbered; unknowns are MUST-ignore ([ADR-0002]).
- **Read the source, not memory.** Sibling implementations are interop *context*, not a
  template to copy. Verify against the actual code/spec.
- **Prove a negative before you claim it.** Before asserting "X is missing / not implemented
  in repo Y," run an exhaustive named search (and `git log --since` for recent additions) —
  an absence claim from a partial grep is how false "spec gaps" and false "sibling bugs" get
  filed. (Pass this discipline on to any agent you spawn.)
- **Pin citations to `(symbol, path, commit)`, not line numbers.** Line numbers expire the
  moment the file moves; a symbol + path (+ commit when it matters) stays resolvable.

## Respect the protocol

Significant or normative/protocol changes are **proposal-first**, not a direct edit
(wording-only hygiene can go direct). Conformance to the spec is the contract; honor the
locked wire core and the stability tiers ([ADR-0004]).

## Methodology — Disciplines, Doctrines & the Ratchet

**Every repo runs this. The tier differs; the ratchet does not.** The full framework is
`METHODOLOGY.md` — injected beside this file, identical everywhere. Read it once; then your
repo's own charter, which carries the local grounding.

We build OS-level software. Conformance is the contract at the core and is nearly sufficient
there. It stops being sufficient the moment work leaves the core — a browser engine, a game
engine, a GUI toolkit, an FFI boundary, a GC we do not own. Out there **green tests are not
evidence of a working system**, and the methodology is what keeps that from being free.

Four artifact kinds, four jobs — do not conflate them:

- **Disciplines** — invariants, the *what*. Checked continuously, on every diff.
- **Doctrines** — procedures, the *how*. Opened at task-start (Feature / Audit / Foundation).
- **Substrate model** — ground truth about the platform. Read before any lifetime, leak,
  render, or persistence work.
- **Anti-pattern catalog** — named failure modes, each with a source commit.

**The law — the ratchet.** *A feature must make us stronger, not weaker.* Every feature and
every audit ends by feeding what it taught back into the disciplines, **in the same session**.
Feature: the close-out review. Audit: the process review — the audit of the audit, which is
non-skippable. **If it didn't land in the charter / `AGENTS.md`, it didn't land.**

**The promotion ladder.** Rules are earned on evidence, never speculation. Bit us once →
anti-pattern catalog. Bit us a **second time in a different shape** → ratified discipline.
Between the two it is a **candidate**: apply it, but don't yet claim it generalizes. A
discipline added on speculation is removed if unearned within a release cycle. **A discipline
with no enforcement point is theater** — name the file, grep, lint rule, or gate test.

**D1–D12 are universal and transfer verbatim** (use the kernel · L1 default, L0 back door ·
capability-typed dispatch · bounded interfaces · declared composition · per-host namespaces ·
symmetric state · surface spec drift · accounting · real-session coverage · inventory boundary ·
read canonical sources). **Above those, each repo earns its own on its own bugs** — copying
another repo's substrate disciplines is a category error.

**Tiers** (your `AGENTS.md` declares yours and links its docs):

| Tier | Runs | Who |
|---|---|---|
| **Full** | D1–D12 + native · Feature + Audit + Foundation doctrines · substrate model · catalog | Complex non-deterministic runtimes (browser, engines, GUI/FFI stacks) |
| **Core** | D1–D12 + native · **Audit doctrine** · catalog · review questions | Reference implementations, conformance anchor, tooling — conformance gates the wire, not process drift or accounting |
| **Authoring** | Lifecycle disciplines · **Audit + Foundation doctrines** · catalog | Spec / formal repos — no runtime to hold; the corpus is the substrate |

**Conformance does not exempt a repo from this.** It gates the wire; it does not catch process
drift, stale build-state claims, unaccounted accumulation, or a discipline quietly eaten by a
legitimate competing pressure. Those need the ratchet.

## Honesty & conformance ([ADR-0012])

- **Conformance is the contract**, not the version number. Green unit tests ≠ a release;
  the **full conformance suite** is the gate. `entity-core-keystone` is the canonical
  anchor (provided, not mandatory — anyone may build a ground-up implementation).
- **Every published conformance number is reproducible and anchored on a CONTENT DIGEST**
  — `N·0F @ <core_gate_fingerprint / check_set_digest>`, with the P/W/F/S breakdown, never
  a bare percentage. A skip counts as a failure; never label a failure "pre-existing"
  without bisecting. A "matches the spec" claim needs evidence (a grep / `file:line`), not
  an assertion.
  > **Changed 2026-08-23 ([ADR-0012] Amendment 1). This used to say `@ <oracle-commit>`.**
  > [ADR-0027] authors every published commit fresh at the release boundary, so public
  > `master` is a different history from `dev` — **a `dev` SHA has never resolved for a
  > public reader and never will.** It already fired on the flagship claim: keystone's
  > published matrix reads `665·0F @ e8524ed`, and `e8524ed` exists in no repo in the
  > ecosystem. A commit SHA is now a **non-normative convenience** and, where given, MUST
  > be reachable from `master` or a release tag.
- **Never overclaim.** The ground-up impls (go/rust/py) are independent code bases;
  keystone-generated peers share a generation lineage — and a cohort of implementers all
  passing one author's vectors is **cohort-consistent, not independent convergence**.
  State the distinction precisely. (And conformance-green ≠ correct if the test asserts
  the wrong thing.)

## Documentation & tree hygiene ([ADR-0009], [ADR-0018])

Clean as you go — drift is rejected at the PR gate by a tree-hygiene linter (hard-gate
the contract, flag the cosmetics):

| Category | Lives in |
|---|---|
| Reference / durable docs, specs | `docs/`, `docs/{architecture,reference,spec}/` — edit in place |
| Agent guidance | `AGENTS.md` + `AGENTS-STANDARD.md` + `CLAUDE.md` (root) |
| Dated status / handoffs | `docs/status/` (`STATUS.md`, `HANDOFF-*`, `CHECKPOINT-*`) — ephemeral, **and never published** ([ADR-0031]) |
| **Ecosystem ADRs** (the decisions that bind every repo) | **`docs/adr/ecosystem/` — injected, read-only** ([ADR-0030]) |
| Your repo's own ADRs | `docs/adr/` (`NNNN-slug.md`) — your numbering, your call |
| Scratch / local | `.gitignore` — never committed |

- **One canonical home per fact** — cross-reference, don't duplicate; the upstream/
  authoritative source wins on overlap. Never dump handoffs or analysis at repo root.
- **Archive, don't delete** — move closed docs to `docs/archive/` with an `INDEX.md`
  breadcrumb; status snapshots are immutable once published; no `-v2` files.

## The decisions that bind you are IN YOUR REPO now ([ADR-0030])

**`docs/adr/ecosystem/` carries the full text of every ecosystem ADR**, injected
byte-identical alongside this file. Until 2026-08-23 it did not exist, and this standard
cited nine ADRs by number that were physically absent from all eleven repos — so if you
have been citing `[ADR-0023]` without being able to read it, that was our defect, not
yours. **Read the ADR before citing it.** It is now local.

- **`[ADR-NNNN]` unqualified always means the ecosystem ADR.** Cite your own repo's ADRs as
  `[<repo>-ADR-NNNN]`. The two numbering spaces are different decisions — ecosystem
  `[ADR-0002]` is the version scheme; `entity-browser-rust`'s own `0002` is its Tauri
  release model.
- **Do not edit anything in `docs/adr/ecosystem/`** — same rule as this file and
  `METHODOLOGY.md`. Propose the change to meta; it is re-injected. `inject-overlay.sh
  --check` fails on drift.
- **These are internal.** They are not in your `CANONICAL-DOCS.toml` and should not be.

## Cite by CONTENT, never by commit SHA — in anything that publishes ([ADR-0012] Am. 1)

**An identifier is only a pin if it resolves for the audience it ships to.** Published
commits are authored fresh at the release boundary ([ADR-0027]), so **public `master` is a
different history from `dev`** — an internal SHA in a published document resolves to
nothing, forever, by construction. It is not broken by the release; it was never valid.

- **In a canonical doc:** cite by content — *"the commit that fixed the corpus root"*, a
  **release tag**, or a **content digest** (sha256, `core_gate_fingerprint`). Content
  digests are immune and are the model; the ecosystem already has ~4,000 of them.
- **In an internal doc:** cite SHAs freely. `docs/status/`, handoffs and proposals are not
  a publication surface.
- **Check it:** `python3 <arch-tools>/spec-tool/cli.py pins --root .` — scoped to your
  `CANONICAL-DOCS.toml` keep-list, resolves cross-repo, never flags 64-hex content hashes.
  Reader by default. **Run it before a release cut and after adding any commit citation to
  a canonical doc.** The measured backlog was 808 fleet-wide on 2026-08-23;
  `entity-core-protocol` is at **0**, which is the proof it is finishable.

## What DevOps owns, and what you own ([ADR-0031])

**You do not manage publication. You declare; DevOps publishes.** Several repos have been
curating documents for a public reader, which is both work you should not be doing and a
job you are not positioned to do.

| | Owner |
|---|---|
| **What in your repo is canonical** | **you** — `CANONICAL-DOCS.toml`, and that is the whole interface |
| Which files reach public `master`, the release branch, the gates, the forge push | **DevOps** — `canon-filter`, `leak-audit`, `public-regress`, the promote pipeline |
| Your internal docs | **you**, unconstrained — see below |

**Write your internal status docs for the next session, not for an audience.** They are
never published ([ADR-0031]: `docs/status/` publishes **nothing**, including `STATUS.md`,
which used to be the one exception). Keep them frank — blockers, half-verified
measurements, seat-by-seat argument, mistakes. That candor is why they are useful, and it
survives only because nobody outside reads them. **No scrub obligation, no pin hygiene, no
audience.**

What the public reader actually gets from you: `README.md` (what this is), `CHANGELOG.md`
(what changed), and your conformance artifact if you have one. All already declared.

## Multi-forge ([ADR-0014])

**GitHub is canonical** for contributions (issues + PRs); **Codeberg is a one-way,
append-only mirror.** Never push to the mirror; never `git push --mirror` / `--prune`.

## Local agent context (your own, not shared)

This file is the **shared** layer. For your **own** local context — scratch notes,
working memory, personal preferences, machine-specific paths — use the repo's
**git-ignored `AGENTS.local.md`** (the personal counterpart to this `AGENTS.md`,
mirroring `CLAUDE.local.md`; [ADR-0020]), or a git-ignored **`.agents/`** directory
for anything larger than one file. Both are injectable, never committed, never shared,
and are where per-contributor or personal-style notes live **instead of** this shared file. (For us, it also replaces the
drift-prone per-machine `~/.claude` memory — durable shared facts live here in the repo;
local context lives, untracked, in that directory.)

---

## Your repo's `AGENTS.md` adds

Language version(s) · exact `make` build & test verbs (full suite + single test) · source
layout · **boundaries — do NOT modify** (generated code, frozen spec files, secrets,
vendored trees) · curated repo-specific facts. Keep it **short** — this standard already
carries the cross-cutting "how we work."

<!-- Reference ADRs (meta `docs/adr/`): 0001 record-ADRs · 0002 SemVer · 0004 tiers ·
0005 Apache-2.0 · 0006 DCO · 0007 spec-license · 0009 doc-hygiene · 0010 polyrepo+inject ·
0012 conformance · 0014 multi-forge · 0015 branch/release · 0016 AGENTS.md · 0017 AI-policy ·
0018 tree-hygiene · 0019 build-vocabulary (Proposed) · 0020 local-agent-context dir (Proposed) ·
0021 canonical-docs link integrity (Proposed) · 0027 release-history-model ·
0028 methodology · 0030 ADRs-ship-into-every-repo · 0031 status-docs-not-published.
**These are no longer a reading list you cannot reach — the full text is in
`docs/adr/ecosystem/` in this repo ([ADR-0030]).** -->
