# AGENTS-STANDARD.md — how we work (entity-core ecosystem)

**This file is identical in every entity-core repo.** It is maintained in one place and
injected unchanged ([ADR-0010]).

### Changing this file — the process

**If and when you judge that something here justifies a change, make the change in your copy.
We review it.** You do not need permission first and you do not need to send a packet first.

1. **You make the edit**, in your own repo. Keep it general enough to belong in every repo — if
   it is only true of your seat, it belongs in your own `AGENTS.md` instead.
2. **Meta reconciles it, then re-syncs every copy.** Every repo's copy is diffed against the
   master and each edit is adopted for everyone or dropped with a reason you receive.
   Reconciliation happens **before** the overwrite, never instead of it.
3. **If it is critical enough that it cannot wait for the next publish, say so** — a midstream
   update is available. That is the exception, not the route.

**This is not a licence to fork the file, and it is not an invitation to casual editing.** The
bar is that you judged it justified. **An edit you thought was right and did not make is a
finding nobody receives** — that is the failure this process exists to prevent.

Your repo's own `AGENTS.md` sits beside it and adds the repo-specific details (languages,
build/test commands, layout, boundaries). Where the two differ, the repo `AGENTS.md` wins
on repo-specific facts; this file wins on ecosystem conventions.

For any agent, not just Claude ([ADR-0016]).

## What loads, and when ([ADR-0028] Am. 1)

**Two files are always loaded: your repo's `AGENTS.md` and this one. Read both in full, first,
every session.** Keep both small — **`AGENTS.md` ≤ 30 KiB, this file ≤ 24 KiB, measured in
bytes, not lines.** **Each cap governs its own file on disk, not the sum an agent loads** —
the binding constraint is a loader that reads `AGENTS.md` alone and truncates above 32 KiB.

**Everything else is opened by trigger, never speculatively.** A tier-0 file **names** the
trigger; it does not carry the content. Any section of one that could be replaced by *"when X,
open Y"* is replaced by it.

| tier | what | when |
|---|---|---|
| **0 — always** | your `AGENTS.md` · this file | every session, in full, before anything else |
| **1 — cold start** | `METHODOLOGY.md` §1–§4 · your repo's discipline charter · the newest handoff in `docs/status/` | once, when you need to know how work is done here |
| **2 — by trigger** | the **one** doctrine matching the task (`METHODOLOGY.md` §7) · your substrate model · the `WORKFLOW-*` a doctrine's step names | at task start |
| **3 — looked up** | `docs/agents/memory/`, entered through its `INDEX.md` · anti-patterns · guides · references · dated status docs · `METHODOLOGY.md` §5–§11 | when something points at them |

**`METHODOLOGY.md` is carried in your repo and is NOT loaded by default.** It is long on
purpose, because it is read by trigger. **The summary in the Methodology section below is what
you are expected to know without opening it**, and that section names the triggers.

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
  **podman**. Standard verbs: `build` `test` `lint` `fmt` `check` `clean`, container-default
  with a `-native` opt-in. **Your repo declares its own host contract** — name what the host
  actually needs, in your `AGENTS.md`, rather than inheriting a sentence from here.
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
  wire formats, primitives, opcodes, or handler semantics with no proposal behind them.
  **Implement against a landed proposal or draft; you do not wait for the fold** — the
  reference implementations lead, and building a proposal is how it earns its fold. For
  something complex, spike a POC and feed it back as a proposal. On a genuine ambiguity with
  real degrees of freedom, **log it** (`docs/SPEC-AMBIGUITIES.md`) and route it upstream. The
  locked wire core is never renumbered; unknowns are MUST-ignore ([ADR-0002]). A repo that
  must track only the *landed* spec (e.g. the conformance anchor) declares that in its own
  `AGENTS.md`; it is not the ecosystem default.
- **Read the source, not memory.** Sibling implementations are interop context, not a
  template to copy. Verify against the actual code and spec.
- **Prove a negative before you claim it.** Before asserting "X is missing / not implemented
  in repo Y", run an exhaustive named search and `git log --since`. Pass this on to any
  agent you spawn.
- **Pin citations to `(symbol, path, commit)`, not line numbers.**

## Routing packets — how a finding reaches another seat

**Delivery in this polyrepo is: you commit a document to your own tree and the other party
reads it.** There is no notification and no queue, so **a packet nobody enumerates is a
packet nobody receives.**

A routing packet lives in **`docs/outbox/`** — packets you have **sent**, and nothing else —
named `ROUTING-<date>-<letter>-<recipient>-<slug>.md`. Once its recipients have acknowledged
it, it moves to **`docs/archive/outbox/`**. **Never declare either in `CANONICAL-DOCS.toml`**:
routing is internal. Not `inbox/` — that name is protocol surface in three repos.

It **MUST** open with an addressee block, each field on its own line:

```
**To:** `entity-core-go`
**From:** `entity-system-generator`
**cc:** `entity-core-rust`, `entity-core-py`
**Re:** <full stem of what this answers — never an abbreviated form>
**Tip:** `dev` @ <sha>
```

`To:`, `From:` and `Tip:` are required. **A packet whose claim cannot be re-derived is an
opinion**, so the tip is not optional. **Your addressable name is your repo's directory
name**, and you state it in one line of your `AGENTS.md`.

- **`To:` names repositories, one per line-item, never a person or a nickname.** Write the
  full repo name. A brace list (`entity-core-{go,rust,py}`) is fine and is expanded.
- **Check a `To:` by OPENING the named tree and finding the subject in it.** A
  wrong-but-parseable `To:` is indistinguishable from a right one to every instrument there
  is. Address the repo that holds the subject, not the one whose name matches the topic.
- **`cc:` is a real distinction, not decoration** — it says *this is not addressed to you and
  you are not on the hook for it.* A packet you need acted on goes in `To:`.
- **The three fields go on their own lines.**

### The id is unique or it is not an id

`<date>-<letter>` is unique to one repository on one day, which is not unique.

- **Cite a packet by its FULL stem**, never by date and letter alone — a citation the reader
  cannot resolve is the failure that matters.
- **Letters are per-day and per-repo** — never reuse one within a day in your own tree.

### Record what you deliberately did NOT send

**Your tracker gets a section for what you analysed and chose not to route**, with the reason,
including anything you drafted and withdrew. **Deliberately-not-sent is invisible from the
other side and reads identically to forgotten.**

### Tracking what is open between two seats

**Keep one tracker per counterpart at `docs/status/TRACKER-<counterpart-repo>.md`** — a living
index, edited in place, so *"what is open between us"* is never reconstructed from a directory
listing. Four sections: **open asks · corrections you owe them · filed, nothing owed back ·
closed.**

- **Stable ids, never renumbered.** A closed ask keeps its id.
- **An ask is one sentence naming what must be decided**, not a summary of the packet.
- **"Filed, nothing owed back" is a real section.** Most documents belong there; a review sent
  for information is not an open ask.
- **Say what state delivery is in.** *Filed* ≠ *routed* ≠ *answered*. Default to not
  established.
- **Archived is not delivered.** Close an ask on the counterpart's receipt or reply, never
  because your own side of the work finished.

### Receiving — the watermark

**Every packet addressed to you gets a row on your tracker**, created by the session that
learns of it, and it is discharged only by the owner confirming in their own tree. Answering
in a reply and never recording it silts up the channel: the reply is in your outbox, and the
next session reads neither. **A row is owed for packets you decline too** — from the sender's
side a refusal and a silence are indistinguishable.

**But first you have to know it exists.** One line in each
`docs/status/TRACKER-<counterpart>.md`:

```markdown
_Last read `<counterpart>`'s outbox through `<date>`, at `dev` @ `<short-sha>`._
```

Fetch their repo, list their `docs/outbox/` for a filename dated after your watermark, read
the header, act or ignore, then move the line and record the tip you scanned at. That is the
whole protocol — no tool, no registry, nobody writing into anyone else's tree. It finds
packets that named you wrong and packets where you are only `cc:`, and it answers *"what have
I not seen?"*

Two things keep it honest, and skipping either turns it into a control that lies:

- **Fetch first, and go by the date in the filename — never file mtime.** A checkout you have
  not pulled lists nothing new and looks exactly like a clean scan, and your watermark then
  advances **past** packets you never saw — a permanent miss, not a late one. The tip you
  record is what makes *"nothing new and I checked"* a different claim from *"nothing new."*
- **If you cannot reach a counterpart's tree, write that in the tracker.** *Could not look* is
  not *nothing to see*, and an omitted row reads as clean.

**Any scanner of yours keyed to a PATH rather than to a counterpart goes blind the day a
counterpart moves, and prints byte-identically to a clean scan.** Glob both homes, and name a
counterpart with neither rather than counting it as zero.

**And when you move your own packets, re-run your full gate set.** An exclusion keyed to
`docs/status/` has just stopped covering them: a gate that fires on a packet you did not
change is the gate starting to work, not the migration breaking something.

## Respect the protocol

Significant or normative changes are **proposal-first**, not a direct edit; wording-only
hygiene may go direct. Conformance to the spec is the contract. Honor the locked wire core
and the stability tiers ([ADR-0004]).

## Methodology — Disciplines, Doctrines & the Ratchet

**Every repo runs this. The tier differs; the ratchet does not.** The full framework is
`METHODOLOGY.md`, carried beside this file and **opened by trigger, not by default.** What
follows is the standing summary: know this much without opening it.

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

**Load by trigger, not all at once.** Open `METHODOLOGY.md` when one of these fires, and open
only the part named. Open **one** doctrine, at task start, never speculatively.

| when | open |
|---|---|
| you need to know how work is done here, and have not read it this session | **§1–§4** — the five kinds · the ratchet · the promotion ladder · D1–D12 |
| you are building something that was asked for | **§7.1 Feature Doctrine** |
| *"Y is broken"*, or something feels wrong | **§7.2 Audit Doctrine.** A1 is the prime: **trace a value before you theorize** |
| you are opening a surface you have never designed against | **§7.3 Foundation Audit Doctrine** |
| you are touching lifetime, leaks, rendering or persistence | your **substrate model**, before the code |
| a crash, a cohort sweep, a platform-specific procedure | your repo's **`WORKFLOW-*`** |
| you are about to add, change or claim a rule | **§3** the promotion ladder |
| a named failure mode is in play | **§8** the anti-pattern catalog |
| you are deciding what loads when | **§12** progressive discovery |

**Then go and read the actual area** — the spec section, the substrate's real behavior, the
sibling implementation's source — canonically, per D12, never from a summary of a summary.

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

**Tiers** — **Full** (complex non-deterministic runtimes: browser, engines, GUI/FFI stacks) ·
**Core** (reference implementations, the conformance anchor, tooling) · **Authoring** (spec
and formal repos). Your `AGENTS.md` declares yours and links its docs; `METHODOLOGY.md` §9
says what each tier runs.

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
| Dated status / handoffs | `docs/status/` (`HANDOFF-*`, `CHECKPOINT-*`, dated snapshots, `TRACKER-*`) — **never published** ([ADR-0031]) |
| Routing packets you have sent | `docs/outbox/`, archived to `docs/archive/outbox/` — **never published, never declared** |
| What you learned, by topic | `docs/agents/memory/` + `INDEX.md` — living, indexed, **declared**. An entry that could become a check should become one |
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
- **In an internal doc:** cite SHAs freely. `docs/status/` and handoffs are not a
  publication surface.
- **"Internal" is set by your DECLARATION, not by the directory's name.** Check
  `CANONICAL-DOCS.toml` before assuming a directory is internal: a `[[keep_tree]]` puts a
  whole directory on the published surface silently — no file changes, and nothing in the
  documents says so. **After declaring a keep_tree, re-read every rule and re-scope every
  gate that keyed on the old boundary.**
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

### Declaring what a directory IS

`[[doc]]` and `[[keep_tree]]` say **publish this**. `[[area]]` says what a directory *is*, and
`[[living]]` marks a durable file edited in place; **neither publishes unless it says so.**

| table | keys | |
|---|---|---|
| `[[area]]` | `path`, `kind`, `publishes` | `kind` ∈ **`status` · `archive` · `outbox` · `memory` · `reference` · `adr` · `vendor`** |
| `[[living]]` | `path` **or** `glob`, `internal` | `internal = true` → durable **and never published** |

**`kind` is a CLOSED vocabulary. An unknown one is an error, never a default** — a
silently-ignored declaration is a check reporting clean while switched off.

- **`[[living]] internal = true` satisfies every "must be declared" check.** *Declared* and
  *published* are different questions. Memory that is a straight move out of `AGENTS.md`
  carries finding ids, sibling paths and gate names: declare it internal, and move a file to
  `[[doc]]` when it has been rewritten for a stranger.
- **Dated prose deeper than your top-level doc roots is invisible to the release filter and
  PUBLISHES.** Declare it as an `[[area]]`. Deletion shows up in a diff; this does not.

## Multi-forge ([ADR-0014])

**GitHub is canonical** for contributions. **Codeberg is a one-way, append-only mirror.**
Never push to the mirror; never `git push --mirror` or `--prune`.

## Local agent context

Scratch notes, personal preferences and machine-specific paths go in the git-ignored
**`AGENTS.local.md`**, or a git-ignored **`.agents/`** directory for more than one file
([ADR-0020]). Both are injectable, never committed, never shared — **not** in this file.

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
