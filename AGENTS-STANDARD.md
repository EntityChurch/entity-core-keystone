# AGENTS-STANDARD.md — how we work (entity-core ecosystem)

**This file is identical in every entity-core repo.** It is maintained in one place and
injected unchanged ([ADR-0010]). **Do not edit it in your repo** — propose changes upstream.

Your repo's own `AGENTS.md` sits beside it and adds the repo-specific details (languages,
build/test commands, layout, boundaries). Where the two differ, the repo `AGENTS.md` wins
on repo-specific facts; this file wins on ecosystem conventions.

For any agent, not just Claude ([ADR-0016]).

## What this ecosystem is

entity-core is a **protocol** plus an ecosystem of independent implementations and
tooling, built entirely with AI. It is a **polyrepo** ([ADR-0010]): one spec, several
ground-up reference implementations (`entity-core-{go,rust,py}`), a canonical
conformance anchor (`entity-core-keystone`), formal models, and UI/tooling repos — each
with an independent lifecycle. You are working inside one of them; see its `AGENTS.md`.

## Golden rules

- **Never lose or rewrite history.** No history-destroying rebase or reset on shared
  branches. No clobbering remote refs. **Never force-push** (`--force` /
  `--force-with-lease`), anywhere. If a non-fast-forward seems necessary, **stop and ask.**
- **Stay in your tree.** Do not reach changes into sibling or meta repos. Cross-repo
  coordination goes through a review hand-off. If you read a sibling repo, treat its git as
  read-only: `git status` first, stage **specific paths**, never `git add -A` in a repo that
  is not your working directory.

## Build & toolchain

- **System toolchains, minimal dependencies.** Prefer stock tools (raw `podman run`, not
  podman-compose). Avoid `mise`, `just`, and bespoke toolchain managers.
- **`make <verb>` is the build interface.** Most repos are thin `make` orchestration over
  **podman**; the host needs only `make` + `podman`. Standard verbs: `build` `test` `lint`
  `fmt` `check` `clean`, container-default with a `-native` opt-in. See your repo's
  `AGENTS.md` for its exact targets.
- **Default branch is `master`.**

## Contributing

- **DCO sign-off required** ([ADR-0006]): `git commit -s`, from an **accountable human**
  who certifies the right to submit and stands behind the work. No CLA. Code is
  **Apache-2.0** ([ADR-0005]); spec text is licensed separately ([ADR-0007]).
- **AI is welcome and unrestricted** ([ADR-0017]). No usage limit, no disclosure trailer.
  The gate is the accountable human plus the quality bar, applied equally however much
  tooling was used.
- **Open a PR; keep CI and the conformance suite green.** A **tag is a release**, not a
  push ([ADR-0015]).

## Working across the polyrepo

- **The spec is upstream; implementations implement, they do not define it.** Do not invent
  wire formats, primitives, opcodes, or handler semantics in an implementation repo.
  Implement against the **landed spec**, not in-flight proposals. On a gap or ambiguity:
  **log it** (`docs/SPEC-AMBIGUITIES.md`) and route it upstream. The locked wire core is
  never renumbered; unknowns are MUST-ignore ([ADR-0002]).
- **Read the source, not memory.** Sibling implementations are interop context, not a
  template to copy. Verify against the actual code and spec.
- **Prove a negative before you claim it.** Before asserting "X is missing / not implemented
  in repo Y", run an exhaustive named search and `git log --since`. Pass this on to any
  agent you spawn.
- **Pin citations to `(symbol, path, commit)`, not line numbers.**

## Respect the protocol

Significant or normative changes are **proposal-first**, not a direct edit; wording-only
hygiene may go direct. Conformance to the spec is the contract. Honor the locked wire core
and the stability tiers ([ADR-0004]).

## Methodology — Disciplines, Doctrines & the Ratchet

**Every repo runs this. The tier differs; the ratchet does not.** The full framework is
`METHODOLOGY.md`, injected beside this file. Read it once, then your repo's own charter.

Five artifact kinds — do not conflate them:

- **Disciplines** — invariants, the *what*. Checked on every diff. **D1–D12 are the
  ecosystem's; yours start at D13.**
- **Doctrines** — procedures, the *how*. Opened at task-start. **There are exactly three —
  Feature, Audit, Foundation — they live in `METHODOLOGY.md` §7, and you do not write one.**
- **Workflows** — your substrate's procedures, under a doctrine's step. `docs/**/WORKFLOW-*.md`.
  As many as you earn. **`DOCTRINE-*` is a reserved filename; use `WORKFLOW-*`.**
- **Substrate model** — ground truth about the platform. Read before any lifetime, leak,
  render, or persistence work.
- **Anti-pattern catalog** — named failure modes, each with a source commit.

**Load by trigger, not all at once.** `AGENTS.md` and this file are always in context and stay
small; `AGENTS.md` names the trigger and does not carry the content. Read `METHODOLOGY.md`
§1–§4 once on cold start. Open **one** doctrine when its input arrives — a feature asked for,
*"Y is broken"*, a surface you have not designed against — plus the substrate model before
lifetime/render/persistence work. Everything else is looked up when something points at it.
Then research the actual area, from canonical sources (D12), never from a summary.

**The ratchet: a feature must make us stronger, not weaker.** Every feature and every audit
ends by feeding what it taught back into the disciplines, **in the same session**. Feature:
the close-out review. Audit: the process review, which is non-skippable. **If it did not
land in the charter or `AGENTS.md`, it did not land.**

**The promotion ladder.** Rules are earned on evidence, never speculation. Bit us once →
anti-pattern catalog. Bit us a **second time in a different shape** → ratified discipline.
Between the two it is a **candidate**: apply it, do not claim it generalizes. A discipline
added on speculation is removed if unearned within a release cycle. **A discipline with no
enforcement point does not count** — name the file, grep, lint rule, or gate test.

**D1–D12 are universal and transfer verbatim** (use the kernel · L1 default, L0 back door ·
capability-typed dispatch · bounded interfaces · declared composition · per-host namespaces ·
symmetric state · surface spec drift · accounting · real-session coverage · inventory boundary ·
read canonical sources). **D1–D12 are reserved: your own disciplines are numbered from D13,
and you earn them on your own bugs.** Do not copy another repo's substrate disciplines, and
do not reuse a universal number for one.

**Tiers** — your `AGENTS.md` declares yours and links its docs:

| Tier | Runs | Who |
|---|---|---|
| **Full** | D1–D12 + native · Feature + Audit + Foundation doctrines · substrate model · catalog | Complex non-deterministic runtimes (browser, engines, GUI/FFI stacks) |
| **Core** | D1–D12 + native · **Audit doctrine** · catalog · review questions | Reference implementations, conformance anchor, tooling |
| **Authoring** | Lifecycle disciplines · **Audit + Foundation doctrines** · catalog | Spec and formal repos |

**Conformance does not exempt a repo from this.** It gates the wire, not process drift,
stale build-state claims, or unaccounted accumulation.

## Honesty & conformance ([ADR-0012])

- **Conformance is the contract**, not the version number. Green unit tests are not a
  release; the **full conformance suite** is the gate. `entity-core-keystone` is the
  canonical anchor — provided, not mandatory.
- **Every published conformance number is reproducible and anchored on a CONTENT DIGEST** —
  `N·0F @ <core_gate_fingerprint / check_set_digest>`, with the P/W/F/S breakdown, never a
  bare percentage. **A skip counts as a failure.** Never label a failure "pre-existing"
  without bisecting. A "matches the spec" claim needs evidence — a grep or `file:line`.
- **A commit SHA is a non-normative convenience** and, where given, MUST be reachable from
  `master` or a release tag ([ADR-0012] Am. 1).
- **Never overclaim.** The ground-up implementations are independent code bases;
  keystone-generated peers share a generation lineage. A cohort all passing one author's
  vectors is **cohort-consistent, not independent convergence.** Conformance-green is not
  correct if the test asserts the wrong thing.

## Documentation & tree hygiene ([ADR-0009], [ADR-0018])

Clean as you go. Drift is rejected at the PR gate by a tree-hygiene linter.

| Category | Lives in |
|---|---|
| Reference / durable docs, specs | `docs/`, `docs/{architecture,reference,spec}/` — edit in place |
| Agent guidance | `AGENTS.md` + `AGENTS-STANDARD.md` + `CLAUDE.md` (root) |
| Dated status / handoffs | `docs/status/` (`HANDOFF-*`, `CHECKPOINT-*`, dated snapshots) — **never published** ([ADR-0031]) |
| The rolling canonical status log | **`docs/STATUS.md`** — one file, not dated. **Publishes if you declare it** |
| Ecosystem ADRs | **Not in your repo.** Cite by number, do not copy |
| Your repo's own ADRs | `docs/adr/` (`NNNN-slug.md`) — your numbering, your call |
| Scratch / local | `.gitignore` — never committed |

- **One canonical home per fact.** Cross-reference, do not duplicate; the authoritative
  source wins on overlap. Never dump handoffs or analysis at repo root.
- **Archive, do not delete.** Move closed docs to `docs/archive/` with an `INDEX.md`
  breadcrumb. Status snapshots are immutable once published. No `-v2` files.

## The ecosystem ADRs

- **`[ADR-NNNN]` unqualified means the ecosystem ADR.** Cite your own repo's as
  `[<repo>-ADR-NNNN]`.
- **Citing by number is fine anywhere**, published or not.
- **Do not keep a copy of the ecosystem ADRs in your repo**, and do not write prose that
  sends a reader to one as a path. Propose changes upstream.
- **Do not declare anything under `docs/adr/` in `CANONICAL-DOCS.toml`.** ADRs do not publish.

## Cite by CONTENT, never by commit SHA — in anything that publishes ([ADR-0012] Am. 1)

Published commits are authored fresh at the release boundary ([ADR-0027]), so public
`master` is a different history from `dev`. **An internal SHA in a published document
resolves to nothing.**

- **In a canonical doc:** cite by content, a **release tag**, or a **content digest**
  (sha256, `core_gate_fingerprint`).
- **In an internal doc:** cite SHAs freely. `docs/status/`, handoffs and proposals are not
  a publication surface.
- **Check it:** `python3 <arch-tools>/spec-tool/cli.py pins --root .` — scoped to your
  `CANONICAL-DOCS.toml`, resolves cross-repo, never flags 64-hex content hashes. **Run it
  before a release cut and after adding any commit citation to a canonical doc.**

## Publication ([ADR-0031])

**You declare; the release pipeline publishes.** Do not curate documents for a public
reader.

| | Owner |
|---|---|
| What in your repo is canonical | **you** — `CANONICAL-DOCS.toml`, and that is the whole interface |
| Which files reach public `master`, the release branch, the gates, the forge push | not yours |
| Your internal docs | **you**, unconstrained |

- **Everything a published file says is addressed to a reader outside this ecosystem.**
  Write it for them. Ecosystem operations — release tooling, gates, internal paths, who
  decided what and when — do not belong in any file you declare canonical.
- **Write your internal status docs for the next session, not for an audience.** Under
  `docs/status/` nothing is published: no scrub obligation, no pin hygiene, no audience.
  Keep them frank.
- **The rolling status log lives at `docs/STATUS.md`**, outside `docs/status/`. Declare it
  if you want a public reader to have it.

A public reader gets: `README.md`, `CHANGELOG.md`, `docs/STATUS.md` if you declare it, and
your conformance artifact if you have one.

## Multi-forge ([ADR-0014])

**GitHub is canonical** for contributions. **Codeberg is a one-way, append-only mirror.**
Never push to the mirror; never `git push --mirror` or `--prune`.

## Local agent context

This file is the **shared** layer. For your own local context — scratch notes, working
memory, personal preferences, machine-specific paths — use the git-ignored
**`AGENTS.local.md`**, or a git-ignored **`.agents/`** directory for anything larger than
one file ([ADR-0020]). Both are injectable, never committed, never shared. Per-contributor
and personal-style notes go there, **not** in this file.

---

## Your repo's `AGENTS.md` adds

Language versions · exact `make` build and test verbs (full suite and single test) · source
layout · **boundaries — do NOT modify** (generated code, frozen spec files, secrets,
vendored trees) · curated repo-specific facts. Keep it **short**.

<!-- Reference ADRs (meta `docs/adr/`): 0001 record-ADRs · 0002 SemVer · 0004 tiers ·
0005 Apache-2.0 · 0006 DCO · 0007 spec-license · 0009 doc-hygiene · 0010 polyrepo+inject ·
0012 conformance · 0014 multi-forge · 0015 branch/release · 0016 AGENTS.md · 0017 AI-policy ·
0018 tree-hygiene · 0019 build-vocabulary · 0020 local-agent-context · 0021 canonical-docs
link integrity · 0027 release-history-model · 0028 methodology · 0031 status-docs.
Full text is authored upstream. Cite by number; do not link a public reader at a path. -->
