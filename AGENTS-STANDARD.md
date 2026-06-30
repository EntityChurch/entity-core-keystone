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

## Methodology — Disciplines & Doctrines (where it applies)

Repos with **complex, non-deterministic runtimes** (the browser, a game engine — far
enough from the spec that conformance alone can't hold them) run the entity-OS
**Disciplines & Doctrines** methodology: per-repo **Disciplines** (invariants, the *what*),
**Doctrines** (Feature/Audit task procedures, the *how*), a **substrate model** (ground
truth), and **the ratchet** (every feature/audit feeds its lessons back — *a feature must
make us stronger, not weaker*). The methodology lives in **canonical docs inside the repo**
that runs it; that repo's `AGENTS.md` **declares it and links those docs** — this standard
only notes that it exists and is **selective** (not every repo). Spec/formal repos lean on
conformance + formal methods instead.

## Honesty & conformance ([ADR-0012])

- **Conformance is the contract**, not the version number. Green unit tests ≠ a release;
  the **full conformance suite** is the gate. `entity-core-keystone` is the canonical
  anchor (provided, not mandatory — anyone may build a ground-up implementation).
- **Every published conformance number is reproducible and oracle-pinned**
  (`N·0F @ <oracle-commit>` with the P/W/F/S breakdown — never a bare percentage). A skip
  counts as a failure; never label a failure "pre-existing" without bisecting. A
  "matches the spec" claim needs evidence (a grep / `file:line`), not an assertion.
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
| Dated status / handoffs | `docs/status/` (`HANDOFF-YYYY-MM-DD.md`, `STATUS-*`, `CHECKPOINT-*`) — ephemeral |
| ADRs (rationale) | `docs/adr/` (`NNNN-slug.md`) |
| Scratch / local | `.gitignore` — never committed |

- **One canonical home per fact** — cross-reference, don't duplicate; the upstream/
  authoritative source wins on overlap. Never dump handoffs or analysis at repo root.
- **Archive, don't delete** — move closed docs to `docs/archive/` with an `INDEX.md`
  breadcrumb; status snapshots are immutable once published; no `-v2` files.

## Multi-forge ([ADR-0014])

**GitHub is canonical** for contributions (issues + PRs); **Codeberg is a one-way,
append-only mirror.** Never push to the mirror; never `git push --mirror` / `--prune`.

## Local agent context (your own, not shared)

This file is the **shared** layer. For your **own** local context — scratch notes,
working memory, personal preferences, machine-specific paths — use the repo's
**git-ignored local agent directory** (e.g. `.agent/` *(name TBD — [ADR-0020])*).
It's injectable, never committed, never shared, and is where per-contributor or
personal-style notes live **instead of** this shared file. (For us, it also replaces the
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
0021 canonical-docs link integrity (Proposed). -->
