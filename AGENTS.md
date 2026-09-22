# entity-core-keystone — AGENTS.md

Read **AGENTS-STANDARD.md** first. This file adds entity-core-keystone specifics.

## Overview

The **canonical conformance anchor** for the ecosystem (provided, not mandatory — anyone
may build a ground-up implementation instead). The `/entity-rosetta` generator skill
produces a full core-protocol peer (`entity-core-protocol-<lang>`) for any target language
from the pinned spec snapshot + conformance oracles + per-language profiles. **Generating
peers is the means; spec refinement is the end** — every run surfaces spec ambiguities that
feed back to architecture. A generated peer is *done* when the oracle loop says so
(statistical convergence on conformance — see the shared standard), not when it is provably
bug-free; other language communities pull it in and surface the rest.

Also owns the **codec C-ABI**: a language-agnostic contract (`ffi-generator/c-abi/spec/`)
with interchangeable implementations (`entity-core-codec-ffi-{rust,c}`), all building the
same `libentitycore_codec.{so,dylib,dll}` + `entitycore_codec.h` (provenance via
`ec_impl_info()`, not the filename). Languages without mature canonical-CBOR + Ed25519
stacks consume it; native-codec languages cross-check against it.

Out of scope: standard-extension implementations (TREE, CONTENT, IDENTITY, ATTESTATION,
QUORUM, REGISTRY, RELAY). Community installs those atop the generated peer.

## How we work here — tier **CORE**

This repo runs the entity-OS methodology at the **Core** tier — the framework is
`METHODOLOGY.md` (injected, identical everywhere; read it once). Conformance gates the wire
here. It does **not** catch process drift, stale build-state claims, unaccounted accumulation,
or a discipline quietly eaten by a competing legitimate pressure. Those need the ratchet.

What binds today:

- **Universal disciplines D1–D12** (`METHODOLOGY.md` §4) — apply as written; nothing to re-derive.
- **The review questions** (§6) — run on every diff.
- **The Audit Doctrine A0–A12** (§7.2) — open it for *"Y is broken"* or *"something feels
  wrong,"* including when the thing that feels wrong is our own process. **A1 is the prime:
  trace a value before you theorize.** The Foundation Audit Doctrine (§7.3) when opening a new
  surface to design against.
- **The ratchet** — every audit ends by syncing what it taught into this file or into
  [`docs/agents/memory/`](docs/agents/memory/INDEX.md), same session. **If it didn't land in one
  of them, it didn't land.** Which one: *would a competent newcomer need this **before** their
  first change* (here) *or only when they hit the thing it describes* (memory)?
- **The promotion ladder** (§3) — bit us once → an anti-pattern entry; a second time in a
  different shape → a ratified discipline. Candidates are applied, not yet claimed to generalize.
  **A discipline with no enforcement point is theater** — name the grep, the lint rule, or the
  gate test.

The anti-pattern catalog this tier owes is [`docs/agents/memory/`](docs/agents/memory/INDEX.md) —
every entry is a named failure mode with its mechanism and its enforcement point. What is still
owed is the *promotion* pass over it: turning entries into checks (see that directory's own rule).
The disciplines that bind hardest here are the **honesty** ones ([ADR-0012],
`METHODOLOGY.md` §4 D8/D10), because this repo is the conformance anchor and an overclaim from
here propagates to every implementer: every number oracle-pinned with its P/W/F/S breakdown and
never a bare percentage; a skip counts as a failure; never label a failure "pre-existing"
without bisecting; and **cohort-consistent is not independent convergence** — a cohort of
generated peers all passing one author's vectors shares a generation lineage, and that
distinction is stated precisely or not at all.

## Setup / environment

- **Containers everywhere (Podman, no host writes).** Every build, test, and conformance
  run happens inside a per-toolchain `containers/<toolchain>/` image (`fedora:43` base; e.g.
  `containers/base/`, `containers/go/`, `containers/lean-toolchain/`). No host filesystem
  writes outside the working tree's `output/` dirs; use the `make extract` pattern to pull
  outputs back out for inspection. **Cap resources on every podman run/build** (the
  `PODMAN_BUILD_CAPS`/`PODMAN_RUN_CAPS` `--memory`/`--memory-swap` ceilings; `CAP_SWAP ==
  CAP_MEM` → a runaway container is OOM-killed cleanly at the cap instead of dragging the
  host into swap; tune per-host via `caps.local.mk`, see `RESOURCE-CAPS.md`).
- **Every pinned RPM comes from Koji, and every base image is pinned by digest.** The
  `fedora`/`updates` dnf repos carry only the CURRENT build of a package, so an exact-NVR
  `dnf install` pin rots without warning; Koji retains every NVR ever built at a stable URL.
  Fetch via `containers/koji-fetch.sh`, record a SHA-256 at fetch time (Koji's raw archive
  predates distro GPG signing), and carry the **version-locked dependency closure** — a pin
  without its siblings dies later with `nothing provides X = <the version you pinned>`, which
  reads as rot and is not. Any image that vendors a dependency closure derives it from the
  tree's OWN lockfile, never from a restatement of the top-level pins.
- **Three container gates, because they answer three different questions.**
  `tools/containers-gate.py` (in `make lint`, offline, ~0.1 s) — no rolling pins, every base
  digest-pinned, every download digest-verified. `make images-audit` (network, no build) — every
  recorded pin still resolves, still hashes, still carries its closure. **`make images-cold`
  (`--no-cache`, all 46, ~35 min) — the only one that asks the adopter's question.** The first
  two passing means the recipes are well-formed, NOT that they work, and **none of the three
  asks whether the recipe still fits the tree — only running a peer does.** Run the cold build
  before any release and whenever `containers/` changes.
  → [`memory/CONTAINERS-AND-BUILD.md`](docs/agents/memory/CONTAINERS-AND-BUILD.md)
- **Per-language worktree model:** each target lives under `protocol-generator/<lang>/`
  (generated `src/`, `profile.toml`, `templates/`, `status/`, `reference/`, `run-s4.sh`,
  `run-origination-core.sh`). Shared, language-agnostic inputs are in
  `protocol-generator/shared/`.
- **Three-arm split** — each arm owns its own status; cross-arm coordination flows through
  `research/`:

  | Arm | Owns | Lives in |
  |---|---|---|
  | protocol-generator | Per-language full-peer generation; profile authoring; per-language status + ambiguity logs | `protocol-generator/<lang>/` |
  | ffi-generator | FFI binding generation (codec FFI first; future WASM) | `ffi-generator/<shape>/` |
  | research | Landscape eval, validate-peer + diagnostics knowledge, stewardship + escalation | `research/` |

## Build & test

User-facing surface is the `/entity-rosetta` skill (`skills/entity-rosetta/` — a
tool-neutral Agent-Skill, not in a vendor dir; any SKILL.md-aware agent can run it):

```
/entity-rosetta <lang>                 # full S1 → S5 pipeline
/entity-rosetta <lang> --phase codec   # codec layer only
/entity-rosetta <lang> --phase peer    # peer machinery only
/entity-rosetta <lang> --phase verify  # conformance only
/entity-rosetta --profile-only <lang>  # S1 only: research + author profile
/entity-rosetta --list                 # status across all language targets
```

Two conformance **oracles** are ground truth (built from `entity-core-go`, see Boundaries):

- **`wire-conformance`** — pure codec oracle (lower bar). Codec + types must pass
  byte-identical to `entity-core-codec-ffi`.
- **`validate-peer`** — live-peer oracle (higher bar). Full peer passes the extension-free
  categories; driven per language via `run-s4.sh`.
- **`--profile core` is the gating profile** (extension-free categories); `--profile full`
  exists for full peers. Run a single category with `validate-peer ... -category <name>`
  (e.g. `-category multisig`, `-category type_system`).
- Reference peer `entity-peer` + the oracle binaries are rebuilt from `entity-core-go` HEAD
  with `CGO_ENABLED=0 GOWORK=off` in `containers/go` (`cmd/` is its own module with local
  `replace`; without `GOWORK=off` the workspace forces `-mod=mod` errors). They are
  gitignored local tools placed in `output/s4-oracles/` — **not auto-rebuilt**, so when arch
  adds validator vectors the vendored binary is stale and silently runs the OLD check set;
  always rebuild from go HEAD and verify the new vectors compiled
  (`strings .../validate-peer | grep <vector_name>`).
- **The core-gate FINGERPRINT does not certify the gate — the CHECK-SET DIGEST does.**
  `core_gate_fingerprint` hashes *which categories run* and is blind to *what they assert*; new
  hard checks land inside EXISTING core categories, so it has stayed byte-identical across five
  pins. `oracle-bootstrap.sh` requires the fingerprint **and** `check_set_digest` to match
  before it says "nothing to do", and exits 3 rather than building a different oracle.
  **Attribute new checks BY CATEGORY against `coreProfileCategories`, never by commit message.**
- **Never raise `-timeout` to make a red run green, and read the human output, not just the
  JSON.** `-timeout` is a GLOBAL budget (default `10m`; verify with `validate-peer -h`), so one
  hung check can starve whole categories — the human output shouts `!! WHOLE CATEGORIES NEVER
  RAN`, the JSON files them under `skipped`. **Grep any census JSON for `budget_exhausted`
  before trusting its summary**; a starved run is an incomplete measurement and its P/W/F/S is a
  floor. Record the budget alongside the breakdown. To surface a starved category, prefer
  `-category <name>` — but note that **naming a category OVERRIDES the `--profile core`
  carve-out**, so read such a run for the one check you are chasing, never for its Summary line.
- **One census at a time.** Two concurrent runs share `output/scratch/`, ports and the host
  budget, and the loser's failures read as peer defects. `CONCURRENCY` is a knob on the census
  itself and its default is 1 for exactly this race.
  → [`memory/ORACLE-AND-PINS.md`](docs/agents/memory/ORACLE-AND-PINS.md) ·
  [`memory/CENSUS-AND-REPORTS.md`](docs/agents/memory/CENSUS-AND-REPORTS.md)
- **A capability claim about a peer reads `unknown` until a harness executes it.** A source
  grep is not a census: an exported symbol is not a reachable seam (reachability is decided at
  the packaging boundary, which is a different construct in every language), a live entry point
  can write to a container nothing reads, and one refusal can be implemented at two layers where
  only the one that runs first is observable. Ask the running peer.
  → [`memory/PEER-HOST-AND-SEAMS.md`](docs/agents/memory/PEER-HOST-AND-SEAMS.md) ·
  [`memory/WIRE-AND-CODEC.md`](docs/agents/memory/WIRE-AND-CODEC.md)
- **NAME THE CONTRACT LAYER BEFORE WRITING THE ENFORCEMENT — `docs/CONTRACT-LAYERS.md`.** Three
  layers: **core protocol conformance** (binds every implementation; authority is arch + the go
  oracle; we consume and author none of it), **the keystone peer contract** (binds only the peers we
  generate; ours; four kinds — a convention filling a spec-delegated gap like `seed-policy/`, a
  transcription of a normative rule like `scope-matching/`, a derived drift target like
  `type-registry/`, and an additional obligation the protocol deliberately does not impose, which is
  where the host contract lives), and **project discipline** (binds this repo, no peer). A rule that
  cannot name a layer is either an unrouted spec finding — which belongs upstream — or a preference.
  **The load-bearing consequence: the fourth kind has NO upstream referent, so nothing can supersede
  it and nothing watches it.** The standing measured rule is that the one axis with no external
  authority (S3) is the one whose checks went stale, silently, while the peers stayed `756 · 0F`.
  **So a requirement of that kind ships with its executable gate or it does not ship** — not a census
  document, not a table, not a source read.
- **The keystone peer contract suite (v2.0-draft.1, provisional) — `tools/peer-contract/run.sh <peer>`.**
  One Go driver for every language measures a peer's *contract host* (`run_host(argv,
  install_fixtures)`, a separate package, specified byte-for-byte in
  `protocol-generator/shared/peer-contract/FIXTURE-HOST.md`), plus a few local tests for what the wire
  cannot see; `report.py` computes `certified | not-certified` from `requirements.toml`, and
  `report.py --check` recomputes every committed `status/KEYSTONE-PEER-REPORT.json` in `make lint`.
  **`plant.py <peer>` is part of bringing a peer up, not an extra**: named defects in a scratch copy must
  turn named cases red after an unplanted copy runs green. `rust` is the one peer brought up (certified,
  13/13 plants caught). `docs/spec/SPEC-KEYSTONE-PEER.md` v1.0 stays pinned until v2 is ratified.
- **Peer startup convention: `--name NAME`** loads the peer's Ed25519 identity from
  `~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed) — persistent
  identity + peer-manager interop. `--validate` enables the `system/validate/*` conformance
  handlers, **off by default** (`dispatch-outbound` is a standing dialer, never live in
  production). `--debug-open-grants` is the degenerate seed policy `default→*`, deprecated.
- **Origination-core probes are reference-peer-gated** — a single-peer `run-s4` honest-SKIPs
  them; run them via `run-origination-core.sh`.

**No green report → no publish** (the shared standard's conformance gate).

## Project structure

Per-language layout under `protocol-generator/<lang>/`: `src/` (generated source),
`profile.toml`, `templates/`, `status/` (`PHASE-S*.md`, `CONFORMANCE-REPORT.{md,json}`,
`SPEC-AMBIGUITY-LOG.md`), `reference/` (golden drift files), `run-s4.sh`,
`run-origination-core.sh`.

Shared, language-agnostic — `protocol-generator/shared/`: `spec-data/<version>/` (pinned
spec snapshot — **`v0.8.2.31` is the newest vendored**, and what the cohort IMPLEMENTS is
**`0.8.2.31` on the 26 MAINTAINED-tier rows and `0.8.2.25` on the other 20** (`spec_pin` per peer,
gated by `tools/spec-pin-gate.py`, which reports the 20 with a count rather than failing). ⚠ **A
`.31` pin means SWEPT to `.31`, NOT that every `.31` rule is implemented — six behaviour items are
outstanding cohort-wide and NONE is gated by the pinned 778-check set**, so a `0F` row is silent
about all six; they are enumerated per item in `CONFORMANCE-MATRIX.md` footnote ¹⁴
(`resolve_peer_scope`, §7a.1b's `deadline_ms` `[MUST]` at **0 of 46**, §4.6 step 3's
binding-not-form test, §4.11's bounded close, tag depth, and `501`-only-after-`check_permission`).
**`v0.8.2.28` stays vendored-and-never-implemented on purpose** — `.29` withdraws text `.28`
carries, so a `.28` sweep implements a shape already retracted. `v0.8.2.11`, `v0.8.2.3`, `v0.8.2`
and `v0.8.0` are retained as point-in-time pins; `v7.*` retired at the V8 cutover. **The two are separate facts and
the gap between them is deliberate**: a snapshot is what peers are *written against*, and vendoring
runs AHEAD of implementation on purpose after `v0.8.2.25` was vendored *behind* it (its `MANIFEST.md`
records that as a provenance defect — *"the correct order is vendor, then implement"*). Neither is
the **oracle** pin, which is what peers are *measured* against and moves independently.
⚠ **DIFF A SNAPSHOT BY DIGEST, NEVER BY ITS `Version:` HEADER.** `ENTITY-NATIVE-TYPE-SYSTEM.md` is
`4.2.1` at both `v0.8.2.25` and `v0.8.2.28` and its CONTENT MOVED (`043fc80d…` → `cb0a63e2…`, §10.2's
signature basis). That is `entity-system-conformance`'s `F79`, and the header is not *wrong* — it is
merely *unchanged*, so nothing reports an error. ⬜ *This paragraph itself read "`v0.8.2` is the
current pin as of 2026-08-21 … no peer has been regenerated against `v0.8.2` yet" until 2026-09-16,
i.e. four snapshots and a whole cohort sweep out of date, with every gated number correct throughout
— the standing rule that **a pin is a claim and the sentence stating it rots while the numbers hold**,
landing in this file. ⚠ The sentence that used to close this note — *"`coherence-gate` check 6 gates
pin paragraphs in published prose; `AGENTS.md` is not a published surface and is not in its scope"* —
**was false in both clauses and is withdrawn (2026-09-17).** `AGENTS.md` is declared in
`CANONICAL-DOCS.toml`, ships on public `master`, and is **not** in `PIN_EXEMPT`, so check 6 has been
gating this file all along. The exempt set is `docs/{status,archive,outbox}/`, `CHANGELOG.md`,
`research/`, and the dated research trees under `protocol-generator/shared/` — all of them dated
records that must not be back-edited. That is the whole list; read it, do not remember it.*
`GUIDE-CONFORMANCE.md` is pinned BY HASH in the snapshot's `MANIFEST.md` — it stays out of
`spec-data/` (non-normative, arch-owned) but "operator-carried" meant unpinned, and peers derive
their whole conformance scaffolding from it), `lifecycle/` (S1–S5 phase prompts),
`seed-policy/` (peer-authority bootstrap convention, keystone-authored). FFI:
`ffi-generator/c-abi/spec/` (canonical C-ABI), `ffi-generator/<shape>/output/`.

**All-source-in-repo until stabilization** — generated source stays in
`protocol-generator/<lang>/src/`; FFI outputs in `ffi-generator/<shape>/output/`. Migration
to per-language sibling repos is deferred until the pipeline stabilizes / package-manager
friction demands it / a community asks. (FFI impls are *named* as future repos so they lift
out cleanly.)

The generator's phases are **loose LLM guidance, not a deterministic pipeline** — document
process as plain prose (a README), don't formalize it into state machines / DAGs / rigid
gates. Live status lives in each peer's `status/` + `research/stewardship/` session notes;
`CONFORMANCE-MATRIX.md` (repo root) is the adopter-facing per-peer/tier transparency
contract — check it (not the dated STATUS narrative) first.

## Boundaries — do NOT modify

- **`protocol-generator/shared/spec-data/<version>/`** — a verbatim, byte-for-byte,
  **SHA-256-pinned** snapshot of the authoritative normative specs, pinned to a source commit
  in `MANIFEST.md`. **Architecture's to author.** Never paraphrase, restructure, or "extract
  facts" into it (a literal copy *is* the maximally faithful reading of the no-paraphrase
  rule); each `<version>/` is **immutable** once stamped — amendments get a new subdirectory,
  never an in-place edit.
- **Conformance oracles never doctored.** If the oracle disagrees with the generated codec,
  the *generated* code is wrong — fix the code, don't relax the test. Oracle bugs escalate to
  arch/Go (a packet in `docs/outbox/`), never patched here. Derive behavior from the **spec**,
  not from the oracle's Go source — reading the oracle to match its code inverts the
  keystone's purpose; spec-vs-oracle divergence is a *finding*. (Authoring against the
  oracle's *type-registry shapes* is the one legitimate byte-exact exception — those shapes
  are the spec's type definitions.)
- **`protocol-generator/<lang>/reference/` golden files** — a drift signal (diff across runs),
  not a determinism guarantee; never edited to mask a regression.
- **Never write to the architecture repo** (or any sibling). Reviews, proposals, and feedback are
  **written in THIS repo's `docs/outbox/`**; the recipient pulls them in
  on its own schedule. A direct cross-repo commit, even with good content, lands as an
  unprovenanced surprise that can't be cleanly undone — the damage is the broken process. This
  also applies to *testing*: a gate whose obvious test is "edit the sibling's file" gets an env
  override instead (`PIN_GATE_GUIDE`), so nobody has to cross the boundary to exercise it.
- **The findings PUBLISH; the escalation stays a draft.** A handoff has two lives. As a
  **process artifact** it is dated, addressed and internal — the packet, in the repo's outbox
  directory (internal; it does not reach a public reader, so describe it, never link it). As
  **research output** it is the durable answer to *"we implemented this protocol 46 times, here
  is what we found wrong with the spec"*, and that belongs to an adopter: once written up it
  **moves to `protocol-generator/shared/findings/`** under an undated name, keeping its date in
  its own `**Date:**` header as provenance rather than as an identifier. **The register does NOT
  move** — `research/stewardship/SPEC-FINDINGS-LOG.md` is declared canonical, and the keep-list is
  fail-closed on a declared path that is absent ([ADR-0021]). Cite evidence from the register by
  **routing date, never by packet path**: `grep -n 'docs/outbox' research/stewardship/SPEC-FINDINGS-LOG.md`
  must return nothing, or the index is shipping while the evidence does not.
- **A PACKET NOBODY ENUMERATES IS A PACKET NOBODY RECEIVES.** Ecosystem convention:
  - **Our addressable name is `entity-core-keystone`** — the repo's directory name, and what a
    counterpart writes in a `To:` line.
  - **Packets we send live in `docs/outbox/`** (its own `README.md` states the convention where
    it lives, and this is a description rather than a link because that directory is internal
    and a published link into it resolves to nothing), one file per packet, never declared
    canonical (routing is internal; publishing the corpus is the expensive mistake). Acknowledged
    packets move to `docs/archive/outbox/`. A packet opens with `**To:**` / `**From:**` / `**cc:**`
    each on its own line, plus `**Re:**` (the FULL stem of what it answers, never an abbreviated
    id) and `**Tip:**` — *a packet whose claim cannot be re-derived is an opinion.*
  - **Packets we receive are found by watermark, one per counterpart.** Each
    `docs/status/TRACKER-<counterpart>.md` carries `_Last read <counterpart>'s outbox through
    <date>, at <branch> @ <sha>._` **Fetch their tree first**, list their `docs/outbox/` for a
    filename dated after the watermark, act or ignore, then move the line and record the tip you
    scanned at. A checkout you have not pulled lists nothing new and looks exactly like a clean
    scan. **If you could not reach a tree, write that in the tracker** — *could not look* is not
    *nothing to see*.
  - **Every packet addressed to us gets a row, including ones we decline** — from the sender's
    side a refusal and a silence are indistinguishable. Ids are stable and never renumbered (ours
    are the register's `F<NN>` for arch, and that deviation is stated in the tracker itself).
    **`Filed` ≠ `routed` ≠ `answered`; default to NOT ESTABLISHED**, and close on their receipt,
    never on our own completion.
  - **Derive the counterpart set from the world, not from the trackers you already keep** — a seat
    with no file of ours is an absent row in an absent table, and the control reports clean. Ask
    which seats keep a tracker for US.
  → [`memory/ROUTING-AND-TRACKERS.md`](docs/agents/memory/ROUTING-AND-TRACKERS.md) ·
  [`memory/PUBLICATION-AND-DOCS.md`](docs/agents/memory/PUBLICATION-AND-DOCS.md)
- **After any repo-wide mechanical commit** (global find/replace, date-stamp, rename), don't
  trust the "just docs" framing — re-verify the SHA-256 spec-data pins and machine-consumed
  values (lockfile build-metadata, Containerfile `ARG …=DATE`, Go pseudo-versions) before
  accepting. Run such transforms on prose `.md` only.
- Secrets: never read `config.secret` values (see the shared standard).

## Durable cross-language lessons — `docs/agents/memory/`

**The findings this work has earned live in [`docs/agents/memory/`](docs/agents/memory/INDEX.md),
one file per part of the system.** They are not optional reading and they are not a diary: each
entry names what happens, the mechanism, and its enforcement point, and most of `make lint`'s
gates started life as one of them. **Open the file whose symptom matches what you are
looking at** — that is what the column on the right is for.

| open | when |
|---|---|
| [`WIRE-AND-CODEC.md`](docs/agents/memory/WIRE-AND-CODEC.md) | a peer drops a frame, answers the wrong status or code, or two codec impls disagree |
| [`AUTHORITY-AND-SCOPE.md`](docs/agents/memory/AUTHORITY-AND-SCOPE.md) | a 403 that should not be, a delegated cap honoured that should not be, a wrong mint expiry |
| [`SUBSTRATE-AND-RUNTIME.md`](docs/agents/memory/SUBSTRATE-AND-RUNTIME.md) | the peer crashes, hangs, leaks, or a file will not compile for a language-specific reason |
| [`PEER-HOST-AND-SEAMS.md`](docs/agents/memory/PEER-HOST-AND-SEAMS.md) | an installed handler is unreachable, or an in-process surface differs from the wire |
| [`CONTROLS-AND-PLANTS.md`](docs/agents/memory/CONTROLS-AND-PLANTS.md) | a gate or test passes and you are not sure it asked anything |
| [`CENSUS-AND-REPORTS.md`](docs/agents/memory/CENSUS-AND-REPORTS.md) | a number moved, a peer looks unfairly good or terrible, or a result will not reproduce |
| [`ORACLE-AND-PINS.md`](docs/agents/memory/ORACLE-AND-PINS.md) | two numbers are not comparable, a run stopped early, or a pinned input moved |
| [`HARNESSES-AND-AXES.md`](docs/agents/memory/HARNESSES-AND-AXES.md) | `run-s*.sh` misbehaves, an axis has no cohort runner, or a gate rewrote a tracked file |
| [`CONTAINERS-AND-BUILD.md`](docs/agents/memory/CONTAINERS-AND-BUILD.md) | a build works only here, an image will not cold-rebuild, or a fix did not reach the artifact |
| [`FINDINGS-AND-ESCALATION.md`](docs/agents/memory/FINDINGS-AND-ESCALATION.md) | you are about to publish a count, a negative claim, or a correction to a counterpart |
| [`PUBLICATION-AND-DOCS.md`](docs/agents/memory/PUBLICATION-AND-DOCS.md) | a published document points at something a reader cannot open |
| [`ROUTING-AND-TRACKERS.md`](docs/agents/memory/ROUTING-AND-TRACKERS.md) | you are sending a packet, reconciling a tracker, or acting on a counterpart's claim |
| [`COHORT-SWEEPS.md`](docs/agents/memory/COHORT-SWEEPS.md) | a rule must land on every peer, or a cohort-wide claim needs a closing measurement |

Two rules about this directory, because both are load-bearing:

- **An entry that could become a check SHOULD become one, and is then deleted from memory.**
  Memory is where a finding waits *while it is still only prose* — not where findings retire.
  The maintenance pass is per entry: *could a test, a lint rule, a build assertion or a gate make
  this impossible instead of merely documented?*
- **Superseded in place, never appended.** A corrected entry is rewritten and says what it used to
  claim; git holds the history. Many entries there are corrections of earlier versions of
  themselves, and the correction is usually the valuable half.

**The ratchet lands here or in this file — nowhere else.** Every audit ends by syncing what it
taught into one of them, in the same session. If it did not land, it did not land.

For the *synthesized* narrative version — what translates across substrates, what needs a seam,
what does not — see [`research/SUBSTRATE-TAKEAWAYS.md`](research/SUBSTRATE-TAKEAWAYS.md); memory is
its operational source. The per-session `vNNN` / `peer-sN` diaries stay in `research/stewardship/`.
