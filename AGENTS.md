
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
- **The ratchet** — every audit ends by syncing what it taught into this file, same session.
  **If it didn't land here, it didn't land.**
- **The promotion ladder** (§3) — bit us once → an anti-pattern entry; a second time in a
  different shape → a ratified discipline. Candidates are applied, not yet claimed to generalize.
  **A discipline with no enforcement point is theater** — name the grep, the lint rule, or the
  gate test.

**Owed:** a standing `DISCIPLINE-*` doc assembling this repo's own rules with an anti-pattern
catalog. The disciplines that bind hardest here are the **honesty** ones ([ADR-0012],
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
- **Pin dnf packages to Koji, not just an exact NVR.** Every `containers/*/Containerfile`
  pins exact Fedora RPM NVRs (`gcc-15.2.1-7.fc43`), but the `fedora`/`updates` dnf repos only
  carry the CURRENT + recent build of each package — once a newer build ships, the pinned
  NVR vanishes from the repo metadata and `dnf install` dies with `No match for argument`,
  months (2026-07-27: eleven images) or even **hours** (`clang` 21.1.8-4→6.fc43 rotted mid-
  session the same day) later, with no warning until the next rebuild. **Koji** — the build
  system that produces those RPMs — retains every NVR ever built, forever, at a stable URL
  (`https://kojipkgs.fedoraproject.org/packages/<source-pkg>/<ver>/<rel>/<arch>/<binary-
  pkg>-<ver>-<rel>.<arch>.rpm`); fetching the volatile packages (gcc family, binutils, rust
  family, dotnet-sdk — anything that has ever rotted) from there via `containers/koji-
  fetch.sh` instead of `dnf install <NVR>` makes the pin reproducible from any machine,
  indefinitely, no machine-local cache required. `<source-pkg>` is the SRPM name, not always
  the binary name (gcc/gcc-c++/libstdc++*/libasan/libubsan ⇐ `gcc`; rust/cargo/clippy/
  rustfmt ⇐ `rust`; clang/libcxx* ⇐ `llvm`, NOT `clang`; dotnet-sdk-9.0 ⇐ `dotnet9.0`) —
  verify with a HEAD request before assuming otherwise. Koji's raw archive predates distro
  GPG signing, so integrity rides on a SHA-256 recorded at fetch time (the same trust model
  already used for the Nim/APL source tarballs), not GPG.
  **RETRACTED 2026-08-27 — this bullet used to end "Packages that haven't yet been observed
  to rot stay on a plain `dnf install <NVR>` pin; convert them the same way the first time
  they do." That is a policy of waiting to be broken, and it is withdrawn.** It left **36 of
  46 images** on rolling pins and **45 of 46** on a floating base tag, and the only reason it
  read as working is that nobody ever rebuilt without a cache. **Every pinned RPM now comes
  from Koji (0 rolling pins, enforced) and every base image is pinned by digest.**
- **AN IMAGE NOBODY REBUILDS FROM SCRATCH IS NOT A RECIPE, IT IS A LOCAL ACCIDENT — and the
  layer cache is what hides that from the machine that authored it.** Ratified 2026-08-27.
  The trigger was a request to bring peers to parity; the blocker was that the per-toolchain
  images were gone from the host and **nothing in the repo could tell us whether they still
  built.** They mostly did — the panic premise ("our NVRs don't work") was wrong, `c-toolchain`
  rebuilt in 26 s — but the *design* was one supersession away from the 2026-07-27 outage
  repeating, and two images were **already unbuildable and had been for weeks, silently**.
  Four distinct defect classes, all found by actually running the build:
  - **An incomplete pin is indistinguishable from rot, and it is the one you introduce
    yourself.** A Koji pin MUST carry its **version-locked dependency closure**:
    `rust-1.96.1-1.fc43` Requires `rust-std-static(x86-64) = 1.96.1-1.fc43`, `golang` requires
    `golang-bin` + `golang-src` at its own NVR, `glibc-static` requires `glibc-devel`. Pin the
    parent alone and it builds fine *until the rolling repo moves past the sibling*, then dies
    with `nothing provides X = <the exact version you pinned>` — which reads as rot and is not.
    **Four images shipped in that state** (`cargo` `datalog` `rust-wasm` `rust-wasm-wasmtime`),
    plus `asm-x86_64` whose `glibc-static-2.42-13` had *already* rotted against the base's
    `2.42-16`. Enforcement: `tools/koji-pin.py closure` (in `make images-audit`) reads
    `rpm -qpR` on each pinned RPM and reports any locked sibling not in the same group.
  - **Arch is a property of the BINARY, not the source package.** `koji-fetch.sh` hardcoded
    `x86_64`, but one source ships both — `glibc` → `glibc-static` is x86_64 while
    `sysroot-aarch64-fc43-glibc` is **noarch**; `rust` → `rust-std-static-wasm32-wasip1` is
    noarch. The hardcode turns a present package into a 404 that, again, reads exactly like a
    rotted NVR. Now tries both arches and says which it found.
  - **An upstream tarball can become UNFETCHABLE AT ITS RECORDED URL — but "deleted" is a
    conclusion, and ours was wrong. CORRECTED 2026-08-30.** This bullet used to read: *"GNU
    **removed** `apl-1.9.tar.gz` when 2.0 shipped — verified 404 across six mirrors and
    `ftp.gnu.org`, with the `apl/` directory listing exactly one file."* **GNU did not remove it.
    It REORGANIZED `gnu/apl/` into per-version subdirectories**, and
    `https://ftp.gnu.org/gnu/apl/apl-1.9/apl-1.9.tar.gz` answers **HTTP 200** (checked
    2026-08-30, `.sig` and Debian source alongside it). The 404s were real and the inference from
    them was not.
    **The methodological error is the durable half, and it is not about GNU: SIX MIRRORS OF ONE
    ARCHIVE ARE ONE OBSERVATION, NOT SIX.** Mirrors replicate layout, so checking more of them
    raises confidence without adding evidence — every one reproduced the same reorganization. A
    path change and a deletion are **indistinguishable from a single URL**, and the check that
    separates them is to `ls` the parent directory, which costs one request and was never run.
    **Before concluding an artifact is gone, list the directory above it.**
    The operational conclusion is unchanged and still correct: a distro archive (Koji,
    snapshot.debian.org) keeps everything at a stable path; **an upstream project's own download
    directory reorganizes without notice** — treat any `curl` of a project tarball as a rot risk
    equal to a dnf pin, and record the digest so any mirror, or any layout, can serve it.
  - **A mirror REDIRECTOR is not a mirror.** `ftpmirror.gnu.org` picks a different host per
    request and hands out ones that do not carry the project at all (measured: it 302'd to a
    host that 404'd while other mirrors served the file). Name the mirrors explicitly, in
    order, and let the digest make any of them safe.
  **Enforcement, three layers, because they answer different questions:** `tools/containers-gate.py`
  (in `make lint`, offline, ~0.1 s) — no rolling pins, every base digest-pinned, every remote
  download digest-verified; `make images-audit` (network, no build) — every recorded pin still
  resolves, still hashes, and carries its closure; **`make images-cold` / `tools/cold-build-gate.sh`
  (`--no-cache`, all 46, ~35 min) — the only one that asks the adopter's question.** The first two
  passing means the recipes are well-formed, NOT that they work; only the cold build knows that.
  Run the cold build before any release and whenever `containers/` changes. All three are
  regression-tested against planted defects.
  **AND NONE OF THE THREE ASKS WHETHER THE RECIPE STILL FITS THE TREE — the cold build proves the
  image BUILDS, not that the peer still RUNS against it.** RATIFIED 2026-08-28 (second occurrence of
  the incomplete-pin class, first in a non-RPM package manager, and it was introduced BY the
  46/46-green container overhaul). `containers/dart-toolchain` seeded its offline `PUB_CACHE` from
  its own throwaway pubspec pinning the three DIRECT deps exactly and letting every TRANSITIVE
  float. The `--no-cache` rebuild re-resolved `source_maps 0.10.13 → 0.10.14` and
  `vm_service 15.2.0 → 15.3.0` against pub.dev, the peer's committed `pubspec.lock` had not moved,
  and `dart pub get --offline --enforce-lockfile` correctly refused: *"Unable to satisfy
  pubspec.yaml using pubspec.lock"*. **The image built perfectly. The peer would not start.** Only
  running it asks the question, and `dart` had not been run since.
  **AN EXACT PIN ON THE DIRECT DEPS IS NOT A PIN ON WHAT LANDS IN THE CACHE** — the same statement
  `koji-pin.py closure` enforces for RPMs, in a package manager where nothing was watching. **The
  fix is never to regenerate the lockfile against whatever the image happened to resolve** (that
  rewrites a committed record to match an accident and breaks again on the next rebuild): the
  prefetch now seeds from the peer's OWN `pubspec.lock` with `--enforce-lockfile`, so the cache is
  the lockfile's closure BY CONSTRUCTION, the two cannot drift, and an unsatisfiable lockfile fails
  the IMAGE BUILD — which is the right place to find out. The second copy of the pins is deleted
  rather than re-synced. **Generalize: any image that vendors a dependency closure must derive it
  from the tree's own lockfile, not from a hand-maintained restatement of the top-level pins.**
- **A GUARD THAT WAS NEVER EXECUTED IS NOT A GUARD — and "it's just a preflight" is exactly how
  one ships unrun.** Candidate (first occurrence here, but it is the `check-set-gate --tracked`
  shape again: a control that watches the wrong copy). The 2026-08-23 release sweep added an
  oracle-existence preflight to `run-s4.sh` to fix a real defect (a missing oracle exited 0,
  so the documented Quick-start appeared to succeed while validating nothing). The guard tests
  `[ -x "$ORACLE" ]` on the **host**, but `$ORACLE` is a **container** path (`/work/...`, the
  repo root's mount point) — so it can never pass. **Every one of the 33 peers carrying it in
  that form exited 3 on the documented entry point**, from the day it landed until 2026-08-27,
  *(Sub-lesson from the same session, cheap and general: **a mechanical rewriter that cannot
  tell code from commentary must be scoped to the files it was asked about and must skip
  comment lines outright.** A `dnf install` canonicaliser run fleet-wide reflowed the words
  "dnf install erlang" out of a PROSE SENTENCE in `containers/beam/`, destroying the comment —
  it matched text, not a command. Anchor such patterns to the start of a line, exclude `#`
  lines, and pass an explicit target list rather than globbing the tree.)*
  and the same sweep **missed 5 peers** (`datalog io pd prolog sql`) which kept the original
  silent-false-green. Only the 8 that re-exec into the container before the guard runs, plus
  `unison` (which derives a host path), were correct. **Rule: a guard added across N files must
  be executed on at least one of them before the commit lands** — the fix is one `case` mapping
  `/work/*` back to the repo root, and five minutes of running it would have caught all 33.
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
  `core_gate_fingerprint` hashes the category set + type floor, i.e. *which categories run*.
  It is blind to *what those categories assert*. Measured at the `cc1970f → af8a582`
  bucket-B cutover: four hard-FAIL vectors were added **inside existing core categories**
  (`connectivity/handshake_nonce_single_use`, `authz/f40_id_scope_{exclude_literal,
  include_no_overgrant}`, `concurrency/t1_4_frame_write_atomicity`), most of the cohort
  flipped PASS → FAIL, and the fingerprint stayed **byte-identical** (`8261a033…`). So
  "same fingerprint ⇒ the verdict carries forward" is unsound and is withdrawn.
  `tools/oracle-pin.env` now also carries `check_set_digest` (sorted set of declared check
  names); `oracle-bootstrap.sh` requires **both** to match before it says "nothing to do"
  — comparing the fingerprint alone would have declared a stale oracle current and run the
  old check set over all 43 peers.
- **Never raise `-timeout` to make a red run green — and read the human output, not just the
  JSON, to find out whether the budget held.** `-timeout` is a **GLOBAL** budget, not
  per-category. **Its default is `10m` as of the `de8f807` oracle** (verify with
  `output/s4-oracles/validate-peer -h | grep -A2 timeout` — it was 60 s at earlier pins, and
  this file recorded 60 s until 2026-08-17; the nine harnesses once flagged for defaulting to
  5–15 min are mostly at-or-under the current default, so re-check before citing that as drift).
  Record the budget a run used alongside its P/W/F/S, or the number is not comparable.
  **The starvation asymmetry is the trap** (2026-08-17, asm/ISA trio — `research/stewardship/
  SESSION-2026-08-17-asm-budget-starvation.md`): when the budget expires mid-suite the oracle's
  *human* output shouts `!! WHOLE CATEGORIES NEVER RAN … this is coverage loss, not a slow
  peer`, but the *JSON* files those categories under `skipped` — so `{"failed": 1}` is all a
  summary-only reader sees. One hung check (`t2_2_connection_churn`, 599 s of a 600 s budget)
  starved **seven** categories including the core `resource_bounds`, hiding **two more real
  core FAILs**. Grep any census JSON for `budget_exhausted` before trusting its summary; a
  starved run is an **incomplete measurement**, and its P/W/F/S is a floor, not a result.
  Raising `-timeout` to *surface* a starved category as a one-off diagnostic is legitimate and
  is not what this rule forbids — but prefer `-category <name>`, which drives the hidden
  categories directly in seconds instead of re-running the whole suite behind the hang.
- **An anchor is only as good as its INPUT — `check_set_digest` was reading go's test fixtures.**
  Found by arch 2026-08-21 (`ROUTING-2026-08-21-m` §3), measured here before fixing.
  `oracle-bootstrap.sh` computed the digest over `git archive <ref> cmd/internal/validate | tar -xO`,
  and **`git archive` of a DIRECTORY includes `_test.go`** — so the anchor this repo makes
  *authoritative for carry-forward* ("Both must match, or the cohort re-runs") was hashing test
  fixtures alongside real checks. **A test fixture could order a 45-peer census.** Measured
  `d697b9a → c1b0708`: directory-with-tests moved `ca0c988f… → 3e749f37…` while the non-test declared
  set was **identical at 1137 names both sides**; the entire move was three strings in
  `runner_test.go` (`before_gate`, `behavioral_body_ran`, `behavioral_root`), none of which exists in
  the built binary. **Fixed** — `validate_sources()` enumerates non-test `.go` paths explicitly.
  The generalizable half: `core_gate_fingerprint`, one function down, had normalized against exactly
  this class for months (hash the *semantic content*, not the raw bytes) and **the normalization was
  never carried across to the neighbouring anchor** — when you harden one anchor, check its siblings
  for the same defect the same day. **Rule: a file the built oracle cannot contain must not be able to
  move the pin.** Enforcement: the path filter in `validate_sources()`; regression-test it by adding a
  `.Declare("x")` inside any `_test.go` and confirming the digest does not move. **Comparison
  consequence:** every digest recorded before this fix (`43c23708…`, `3cfd272f…`, `f3a1516d…`,
  `8574f9d6…`) used the old method and is NOT comparable to a new one — `de8f807` recomputed under the
  new method is `06ca8e10…` (1120 names). Never diff across the method boundary.
- **RATIFIED (third occurrence — and a FOURTH landed 2026-08-21 at `de8f807 → c1b0708`): an upstream
  that is "all extension work" can still move the
  core gate through ONE file — attribute new checks BY CATEGORY, never by commit message.**
  Measured 2026-08-20 at `de8f807 → d697b9a`: 60+ go commits whose subjects are almost entirely
  REGISTRY/REVISION/subscription work (`registry v1.19`, daily three-way rounds with arch), which
  reads as "extension churn, the pin is fine." It is not. `check_set_digest` moved
  `43c23708… → ca0c988f…` (1139 → 1156 declared checks) and **5 of the 17 new checks are inside
  the core `capability` category** — the 0.8.1 CAP fold's (r)–(v) plus the later CAP-6a ingest
  check (`configure_empty_grants_withdrawal`, `configure_rejects_base58_partial_prefix`,
  `request_mint_temporal_ceiling`, `request_ttl_zero_and_overflow`,
  `ingest_rejects_unrepresentable_expiry`). `core_gate_fingerprint` stayed byte-identical
  (`8261a033…`) for the **third** time in this exact shape (`cc1970f→af8a582`,
  `fceb61f→de8f807`, now this) — the pattern is reliable enough to plan around: **new hard
  checks land inside EXISTING core categories, so the fingerprint never moves.**
  **Enforcement, cheap and exact:** diff declared check names *per file*, then map each file to
  its category constant and test that constant against `coreProfileCategories` in
  `cmd/internal/validate/profile.go` — a file whose `cat…` const is not in that map cannot gate,
  and one that is, does. Nine files changed here; only `capability.go` was in the core set.
  Do NOT reason from `git log --oneline`, and do not treat a quiet-looking subject line as
  evidence. (Corollary, same session: **a sibling-repo audit conclusion has a shelf life of
  hours when the sibling is actively moving.** Our `4d47573` audit read arch at `cb5df2c` and
  correctly concluded "we owe nothing yet"; the CAP fold landed at `bdb48f2` **83 minutes
  later**. Record the sibling HEAD an audit was taken against — `4d47573` did — and re-resolve
  it at sign-off, not at audit time.)
- **`-category <name>` OVERRIDES the `--profile core` carve-out — a category driven directly is NOT
  the same measurement as that category inside a core run.** Cost real time 2026-08-21 while
  diagnosing `lean`: `run-s4.sh -profile core -category tree_operations` ran the EXTENSION-TREE ops
  (snapshot/diff/extract/merge) that `--profile core` skips wholesale, producing 29 FAILs that look
  like a catastrophic regression and mean nothing — the peer is a core peer and correctly does not
  implement them. Naming a category forces its whole check set regardless of profile. This does not
  retract the standing advice to drive a starved category with `-category` instead of re-running the
  suite — it sharpens it: **read such a run for the specific check you are chasing, never for its
  Summary line**, and never compare its P/W/F/S to a `--profile core` row.
- **TWO MEASUREMENTS AT ONCE IS ONE MEASUREMENT AND SOME WRECKAGE — AND ITS FAILURES LOOK LIKE
  PEER DEFECTS.** Candidate (2026-09-07, self-inflicted). Running `pp.sh <peer>` (a probe census)
  while a `--tier M3` census was in flight produced, in the tier run, `crystal` dying with
  `Thread#execution_context cannot be nil`, `odin` with `permission denied` writing its own JSON,
  and `datalog` with `Permission denied` on its cargo dep-info — three peers reported RED for
  reasons entirely outside their source. Both runs write `output/scratch/`, both allocate ports,
  and both are capped against the same host budget. Re-run serially: all three clean, **0 of 721
  severities moved**. **Enforcement: one census at a time, and treat any run whose failures are
  filesystem-permission or runtime-internal rather than protocol-shaped as contended until proven
  otherwise.** The census's own STALE-JSON guard is what caught it — it refuses to report a JSON
  the run did not write, which is the same discipline as the probe driver's mtime check.
  *(Sub-lesson, cheap: **`pgrep -f <pattern>` in a watcher loop matches the WATCHER**, because the
  pattern is in its own command line. `while pgrep -f run-cohort-census; do sleep 30; done` never
  exits, and after two of them are running, `pgrep` stops answering the question you are asking.
  Discriminate on something the watcher cannot contain — the log's completion marker, or a
  podman-process count.)*
- **`output/scratch/census/` is NOT scoped to the last run — stale per-peer JSONs from earlier
  censuses sit beside the fresh ones.** A `--tier M1` run leaves the other 40 peers' files untouched,
  so `grep -l budget_exhausted output/scratch/census/*.json` returns the `asm`/`riscv64` trio from a
  *previous* census and reads exactly like "this run starved." Scope every census-wide grep to the
  peers the run actually measured (or check mtimes) before drawing a conclusion from it — the
  starvation check itself is mandatory and unchanged, but it must be asked of the right files.
  **RATIFIED 2026-09-08 — the same is true of every `--probe <NAME>` directory, and it bites
  harder there because a probe report has no check-set gate behind it.** Re-reading
  `output/scratch/kind-c-connect-errors/*.json` after re-running six peers showed forty files, of
  which six were current and thirty-four were from a roster run two days older — including four
  peers whose defects had been fixed that morning and which the stale files still reported as
  failing. Nothing warns: the JSON is well-formed and carries no run identity. **Before reading a
  probe directory as a cohort picture, either re-run the whole roster or compare mtimes** — and
  prefer the roster run, because a mixed-age table is the one artifact that reads as a measurement
  and is not one.
- **TWO SITES FOR ONE REFUSAL, AND ONLY THE ONE THAT RUNS FIRST IS OBSERVABLE — so correcting the
  other is a measurable NO-OP that reads as "the fix did not work."** RATIFIED 2026-09-08 (`sql`),
  and it is the `ec_content_hash` link-order lesson moved INSIDE a single peer: there two
  implementations of one symbol and the linker chose; here two implementations of one §6.6
  resolution-miss and the call order chose. `sql` answered `404 not_found` where §3.3's 404 row
  (0.8.2.7) pins `handler_not_found`. The previous session changed the host's `resolve_handler()`
  miss at `peer.c:1010`, measured no change, and correctly concluded the answer came from
  somewhere else — then handed off the wrong somewhere ("a too-broad row in the `handler` table").
  **`verify_ladder.sql` carries its OWN resolution-miss rung, spelled `not_found`, and
  `project_and_verify` runs BEFORE `resolve_handler`**, so the host arm is unreachable for an
  unregistered path and the handler table was never suspect.
  **One TRACE print settled it in one run and no amount of reading would have**: the trace showed
  `resolve_handler` was only ever called with `system/tree`, i.e. the probe URI never reached the
  line under repair. That is A1 (trace a value before you theorize) pointed at *control flow*
  rather than at data. **Enforcement: when a fix to a refusal produces no measurable change, do
  not look for a second cause — instrument the site and confirm it EXECUTES.** And when a peer
  carries the same refusal at two layers, say so at both, name which one the wire observes, and
  keep the spellings in step: the backstop is worth keeping, silently diverging is not.
  and was wrong in both directions once measured: `ruby` was listed as having no
  established-gate yet returns 409; `sql` carries the 409 string yet returns **200**;
  `rust-wasm`/`rust-wasm-wasmtime` carry neither string yet return **401** (they are thin
  transport seams over the `rust` crate and inherit its fix — corroboration, not independent
  data points). Ask the running peer.
- **AN EXPORTED SYMBOL IS NOT A REACHABLE SEAM — reachability is decided at the PACKAGING BOUNDARY,
  and that boundary is a different construct in every language.** RATIFIED 2026-09-03 (the
  source-grep class again, in a new surface, and **two of the wrong calls were ours**). Answering
  `entity-system-generator`'s peer host contract — *can a third party install a handler into a
  constructed peer* — four peers were nominated as satisfying it from source reads, by three
  different seats, and **three of the four were wrong, each at a different boundary**:
  - `cpp` — **class scope.** We cited `include/entity_core/peer.hpp:91`; `private:` is at line 75, so
    `register_handler`, `lookup_handler`, `handlers_` **and the `Handler` typedef itself** are
    private. An external caller cannot even name the body type. Verified.
  - `csharp` — **assembly scope.** We cited a `public RegisterHandler` at `Peer.cs:177`. It is a
    public member of `internal sealed class Peer` (`:23`), and every type in the assembly is
    `internal` bar ten exception classes and `PeerId`. Verified: the public type list is exceptions.
  - `julia` — **a live public entry point onto a container nothing reads.** `register_handler!` is
    exported and writes a `Dict{String,Function}` commented *"extension seam"*; the dict is
    **declared once, written once, never read** — dispatch resolves through the store instead. This
    is the dangerous shape, because it reads as satisfied from every artifact a reviewer would open:
    an exported symbol, a typed container, and a doc comment naming it the seam.
    **FIXED 2026-09-08 — `julia` IS a live host now and this bullet is kept for the LESSON, not as a
    current fact about the peer.** `peer.jl` reads the dict at `_dispatch` (`get(p.handlers, stripped,
    nothing)`), the §11.6.1 entities are bound, and the H7 ordering — built-ins answer FIRST, the
    installed map takes the fallback arm — is asserted in the source at the read site. Measured
    independently on the wire 2026-09-09: `julia` verdicts `EVALUATES`. **The reason to leave the
    text standing is that the dead-map shape is what H5's `dispatch_read_site` field exists to catch,
    and it is the only recorded instance — deleting the example would delete the argument for the
    field.** Say which peer it was and that it was repaired; do not cite it as a live defect.
  **Two rules, and the second is the general one.** (a) **The entry point is not the seam; the seam
  is the line that READS the container.** A census that reads the registration site and stops cannot
  distinguish a working host from a dead map. (b) **"Is the member public" is the wrong question —
  ask whether it is reachable across the packaging boundary**, which is the class in C++, the
  **assembly** in C#, the module in Go, and the `exports` map in npm. Four nominations, four
  boundaries, three misses.
  **Enforcement, and it is the standing `unknown`-until-executed rule earning itself in advance: a
  capability claim about a peer reads `unknown` until a harness executes it.** The check that settles
  it installs through the public surface only, drives an EXECUTE from a second peer, and asserts a
  witness value derived from a request field **and** registration-time state — no `compute/literal`
  entity-native body can produce that, so a peer with no live index cannot pass on the fallback path.
  Both controls required (mutated harness → RED, unmutated → GREEN). One peer of 46 is measured.
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
spec snapshot — **`v0.8.2`** is the current pin as of 2026-08-21 (from `entity-core-protocol`
`106834c`; `v0.8.0` retained as a point-in-time pin, `v7.*` retired at the V8 cutover). **No peer
has been regenerated against `v0.8.2` yet** — every peer in the tree was generated against `v0.8.0`,
which is a tracked gap, not an oversight; `pd`'s F37 `system/identity/peer-id` debt is its one known
consequence. `GUIDE-CONFORMANCE.md` is now pinned BY HASH in that snapshot's `MANIFEST.md`
(`7d59fee6…`, `Status: Draft`) — it stays out of `spec-data/` (non-normative, arch-owned) but
"operator-carried" meant unpinned, and peers derive their whole conformance scaffolding from it), `lifecycle/` (S1–S5 phase prompts),
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
  arch/Go (a `HANDOFF-TO-ARCH-*.md`), never patched here. Derive behavior from the **spec**,
  not from the oracle's Go source — reading the oracle to match its code inverts the
  keystone's purpose; spec-vs-oracle divergence is a *finding*. (Authoring against the
  oracle's *type-registry shapes* is the one legitimate byte-exact exception — those shapes
  are the spec's type definitions.)
- **`protocol-generator/<lang>/reference/` golden files** — a drift signal (diff across runs),
  not a determinism guarantee; never edited to mask a regression.
- **Never write to the architecture repo** (or any sibling). Reviews, proposals, and feedback
  are **drafted** in THIS repo's `research/stewardship/` as `HANDOFF-TO-ARCH-*.md`; architecture
  pulls them in on its own schedule. A direct cross-repo commit, even with good content, lands as
  an unprovenanced surprise that can't be cleanly undone — the damage is the broken process.
- **The findings PUBLISH; the escalation stays a draft.** A handoff has two lives and they want
  opposite things. As a **process artifact** it is dated, addressed, in flight, and internal —
  `research/stewardship/HANDOFF-TO-ARCH-<date>-<slug>.md`, the vocabulary unchanged. As **research
  output** it is the durable answer to *"we implemented this protocol 46 times, here is what we
  found wrong with the spec"* — and that belongs to an adopter, not to a filing cabinet. So once a
  handoff is written up it **moves to `protocol-generator/shared/findings/`** under an undated
  name, keeping its date in its own `**Date:**` header as provenance rather than as an identifier.
  **The register does NOT move with it** — `research/stewardship/SPEC-FINDINGS-LOG.md` is declared
  canonical, and the release keep-list is fail-closed on a declared path that is absent
  ([ADR-0021]), so moving it aborts every unit whose historical manifest names the old path.
  **Two mechanical reasons the destination is what it is, both of which read as arbitrary until
  you hit them:** (a) `canon-filter`'s doc-root prefixes match at the START of a path, so anything
  under `research/` needs a keep-list entry per file forever, while `protocol-generator/**` is
  protected and publishes with **no declaration at all**; (b) `conform-audit` **R10** files any
  *dated-named* doc as an ephemeral snapshot — measured 2026-08-23, it flagged **41** of ours as
  ERROR and had never fired only because the gate audits the canon-filtered tree, where they were
  absent. Declaring them in place would have started the fire; renaming is what puts it out.
  **The failure this fixes is the shape to remember: the index shipped and the evidence did not.**
  `SPEC-FINDINGS-LOG.md` was public, calls one finding a *front door*, and every document it names
  was deleted from the public tree by a keep-list nobody had read as a keep-list. **Enforcement:**
  `git ls-files research/stewardship/HANDOFF-TO-ARCH-*` should only ever return handoffs that are
  still in flight — anything there that `SPEC-FINDINGS-LOG.md` cites as evidence is unpublished
  evidence. References in `docs/status/` and `docs/archive/` were deliberately left pointing at
  the old names — a dated snapshot that gets back-edited stops being evidence of anything — and
  the old→new map sits beside the register as an internal breadcrumb, undeclared on purpose.
- **A PACKET NOBODY ENUMERATES IS A PACKET NOBODY RECEIVES — one TRACKER per counterpart, at a
  predictable path, edited in place.** Ecosystem convention, adopted 2026-09-09 on arch's
  `SEAT-CLEANUP-INSTRUCTIONS-2026-09-09.md`. **`docs/status/TRACKER-<counterpart-repo>.md`**, four
  sections — *Open — asks* (stable ids, **one sentence naming what must be decided**, the packet's
  FULL stem, and the *kind* of answer) · *Corrections we owe them* · *Filed, nothing owed back to
  us* · *Closed*. Three today: `entity-system-architecture`, `entity-system-generator`,
  `entity-core-formalization`.
  **The failure it fixes is arch's, and it is the mirror of ours above.** Delivery here is *"commit
  a document to your own tree and the other party reads it"* — no queue, no notification — so a
  counterpart answering *"what does this seat need from us"* has to read a whole tree. Arch did,
  counted **one seat's private architecture notes as an inbox, and reported 44 open items where
  that seat's own tracker said eleven.**
  **Four rules, and the last two are the ones that will bite here.** Stable ids, never renumbered —
  ours are the register's `F<NN>` for arch, because minting a parallel `A-n` space for asks already
  cited in both trees is the citation-collision problem in a new place, and that deviation is
  stated *in* the tracker. **"Filed, nothing owed back" is a real section and most documents belong
  in it** — a review sent for information is not an open ask, and treating one as an ask is exactly
  what produced the 44. **`Filed` ≠ `routed` ≠ `answered`; default to NOT ESTABLISHED** — every row
  says which, and a packet committed to our tree with no cited reply is *not* delivered. **Archived
  is not delivered: close on their receipt, never on our own completion.**
  **Enforcement, and it is a reconciliation rather than a grep:** `git ls-files
  research/stewardship/HANDOFF-TO-*` names the packets, `docs/status/TRACKER-*.md` names the asks,
  and **every in-flight packet must appear in exactly one tracker section.** The trackers are under
  `docs/status/`, which never publishes ([ADR-0031]) — that is correct and deliberate: this is
  ecosystem operations, which by the publication rule does not belong in any file we declare
  canonical.
  **Routing, going forward only — do not rename history:** `docs/status/ROUTING-<date>-<letter>-<recipient>-<slug>.md`,
  opening with `**To:**` / `**From:**` / `**cc:**` **each on its own line**, `To:` naming
  REPOSITORIES (a brace list is fine), `cc:` meaning *not on the hook*. **Cite a packet by its FULL
  stem, never `ROUTING-<date>-<letter>`** — that id is unique to one repo on one day, which is not
  unique, and three ids in this ecosystem already reach three different packets each.
  **AND THE SECTION THAT SPECIFIES ALL THIS IS NOT IN OUR COPY OF THE STANDARD — a finding that
  was ALREADY MADE, better, by the seat next door.** The instructions say `AGENTS-STANDARD.md`
  §*Routing packets* *"already specifies this and it has simply not been adopted."* Measured across
  six repos the day we adopted it: the section exists in `entity-system-architecture` and
  `entity-system-generator` **only** — absent from `entity-core-keystone`, `entity-core-go`,
  `entity-core-protocol`, `entity-core-formalization` **and from the meta-root canonical copy.**
  `entity-system-generator`'s `HANDOFF-2026-09-09-c-the-outbox-nobody-could-route-and-the-standard-that-moved-in-one-tree.md`
  §1 had it first and with better evidence — line counts and sha256 (canonical and theirs 231 /
  `c3b32f98…`, arch's **305** / `674cfad7…`) — plus the mechanism, which we did not have: **arch
  edited its own copy under a clause arch added to its own copy the same day**, and the operator
  ruled that seat may take §*Routing packets* alone with a provenance blockquote. **We did NOT take
  it**: line 4 of our copy still says *"Do not edit it in your repo"* and no ruling reaches this
  seat, so the convention lives HERE, in the file that is ours to write.
  **Two things generalize.** (a) **Before recording that a convention was ignored, check that it
  was DELIVERED** — *"not adopted"* and *"not injected"* read identically from the receiving end
  and have opposite owners. (b) **Check whether a sibling already found it before writing it up as
  yours** — the standing rule to record corroboration with the same weight as a catch, reached from
  the side where WE are the second finder. `git log --since` in the sibling's `docs/status/` is one
  command, and it is the same discipline as re-deriving a routed claim.
- **After any repo-wide mechanical commit** (global find/replace, date-stamp, rename), don't
  trust the "just docs" framing — re-verify the SHA-256 spec-data pins and machine-consumed
  values (lockfile build-metadata, Containerfile `ARG …=DATE`, Go pseudo-versions) before
  accepting. Run such transforms on prose `.md` only.
- Secrets: never read `config.secret` values (see the shared standard).

## Durable cross-language lessons

Reusable peer-build knowledge worth carrying across runs (the per-session `vNNN` / `peer-sN`
diary lives in `research/stewardship/`, not here). For the *synthesized* narrative version —
**what translates across substrates, what needs a seam, what doesn't** — see
`research/SUBSTRATE-TAKEAWAYS.md`; the bullets below are its operational source:

- **Profile decides; the agent doesn't.** Library, error-model, async-style, naming, and
  packaging choices are all driven by `profile.toml` + `templates/`. Unauthorized decisions
  go to the ambiguity log — no picking "the popular logger." No language-specific syntax
  (Go tags, C# attributes, Rust derives) ever leaks into `shared/`.
- **No platform CBOR lib suffices for canonical ECF** (incl. Rust `ciborium`, .NET
  `System.Formats.Cbor`): every peer hand-rolls the shortest-float ladder + recursive
  major-type-6 tag-reject + length-then-lex key sort on top. This is why a from-spec C codec
  is reasonable, and why the FFI layer exists.
- **Integer head-form is a fixed-width artifact, not a protocol property.** Branch the
  profile by language class: fixed-width ints (OCaml int63 / C# ulong / TS bigint / Zig u64)
  must carry the head form + self-test `[2⁶³, 2⁶⁴−1]`; bignum languages
  (Elixir/Python/Ruby/Lisp/Haskell) carry the full range free.
- **Crypto availability is a spectrum** that the S1 profile must classify: native-stdlib /
  native-audited-lib-incl-Ed448 (Haskell crypton, Elixir OTP `:crypto`) / native-pure-lang
  (Common Lisp) / gap → **hybrid-FFI** via `libentitycore_codec` (OCaml/Zig/Swift; Ed448
  only, Ed25519+SHA stay native). Hybrid-FFI is scoped to an **opt-in sub-library** so the
  shipped default core peer stays self-contained + FFI-free.
  **Fifth tier — managed-runtime-NO-C-FFI (Unison #43):** the hybrid-FFI hatch is
  *structurally unavailable*, so agility can only be pure-language or **deferred** (deferral is
  fine — Ed448/SHA-384 WARN, they don't gate `--profile core`). Classify this at S1, since it
  removes the cohort's standard fallback. Sub-case worth its own probe: **a runtime can ship
  sign/verify and still ship no KEY DERIVATION.** UCM exposes `crypto.Ed25519.sign.impl` /
  `verify.impl` — and `sign.impl` takes the pubkey as an *argument* — but no keygen, forcing a
  hand-written GF(2²⁵⁵−19) implementation (base-2¹⁶ limb arithmetic + twisted-Edwards scalar
  mult + point compression). So at S1 probe for **keygen specifically**, not just "is Ed25519
  present". And on such a substrate treat the pubkey as *part of the identity* — derived once
  and carried; exposing `sign(seed, msg)` silently makes every signature pay a full keygen.
- **Concurrency taxonomy (§7b store-safety) — now FOUR structural shapes:** actor-isolation
  (Swift/Elixir) *or* STM-transactions (Haskell) satisfy store-safety structurally; raw-thread/image
  runtimes (Zig/CL) enforce it manually; single-thread event loops (Pd/TurboWarp/**Io**) serialize +
  cooperatively yield; **dataflow-variable (Oz/Mozart)** is the fourth — a single-assignment variable
  per pending request, no shared mutable state to guard. The §6.11 handler-outbound demux is ~free on
  actor/CSP **and dataflow** substrates (the dataflow variable *is* the demux — reader binds it, the
  handler `{Wait}`s, dispatch never blocks — A-OZ-006), a correlation-map tax on thread/async peers,
  and a **cooperative-yield** tax on single-thread event loops — factor into effort estimates. On a
  single event loop every per-request primitive must be non-blocking + non-accumulating (Io's S4 fail
  was a blocking send + a per-request `try`-coroutine leak, NOT a throughput ceiling — A-IO-025/026).
  **Algebraic-effects/abilities (Unison #43) is a fifth ROUTE, not a fifth shape** — worth stating
  precisely rather than inflating: `fork` green threads + a single `MVar` store (`take → pure fn →
  put`) lands on the *actor* guarantee (one owner, serialized mutation) but reaches it through the
  effect system rather than a mailbox. §6.11 demux is a per-request `Promise` — the dataflow-variable
  pattern in a different dress, so it sits with the ~free column, not the correlation-map tax (A-UN-004).
- **Prototype/delegation substrates: fence dynamic dispatch with the declared-op set.** Where §6.2
  op-dispatch is a real dynamic message-send (Io `perform`), every inherited slot (`clone`, `type`,
  `print`) becomes wire-reachable — check the op against the handler's manifest `operations` map
  *before* sending, and name methods out of the wire namespace (`op_get`, not `get`) (A-IO-004/007).
- **RATIFIED, cohort-wide, first landed 2026-08-21 in all five M1 peers: §6.3's rejection is a
  STATUS, not silence — "Rejection returns `400 non_canonical_ecf`" is the second half of the
  sentence and every peer was ignoring it.** `ENTITY-CBOR-ENCODING.md` §6.3 says implementations
  MUST reject a frame carrying a CBOR tag in a data field **and** that "Rejection returns
  `400 non_canonical_ecf`". Every M1 peer did the first half and dropped the frame on the floor for
  the second — `continue` (go, ocaml), a logged skip (haskell), `break`/close (swift), or a `none`
  that ended the read loop (lean). §4.9(c) deliver-or-signal says the same thing from the other
  direction. **Three distinct symptoms, one rule:** (a) the sender blocks until its own timeout, so
  a refusal is indistinguishable from a dead peer — 60 s of go's CAP-6a check was three of these;
  (b) the CAP-6a `ingest_rejects_unrepresentable_expiry` check scores it WARN, because a
  transport-level drop is a refusal but not the §5.2 disposition; (c) on a peer that *closes*
  instead of dropping it takes the whole connection with it — **that is where lean's 81 cascade
  FAILs came from.** *(The bignum shape can only reach a peer as a major-type-6 tag, so this is the
  only way CAP-6a's `>2^64` half is reachable at all.)*
  **Implementation shape, identical in all five:** keep the strict decoder byte-unchanged, add a
  salvage decode that yields/unwraps the tag instead of erroring, use it ONLY to recover
  `request_id`, answer 400, and keep serving. The frame is still rejected — no entity is built,
  nothing stored, the tag never interpreted — so §6.3's MUST NOT strip / preserve / interpret all
  still hold, and the `tag_reject` wire-conformance vectors keep their meaning because the
  ingestion path never sees the flag. **Enforcement:** grep each peer's read loop for a decode
  failure that neither responds nor is EOF — `envelopeOf*`/`decodeEnvelope` returning
  none/err with no `writeFramed` on that branch is the defect. Check the *reference* peer when
  unsure: `entity-peer` answers this check 6/6 in 1 ms.
  **THE §6.3 FIX CAN PRODUCE THE CASCADE IT EXISTS TO REMOVE, and it presents as a catastrophic
  regression.** `zig`'s first measurement after the fix came back **755 · 89F** — worse than the 3F
  it started at. `wire.makeResponse` CONSUMES its `result` entity and deinits it; the new
  `rejectFrame` also deferred a deinit on the same entity, so *answering* a rejected frame
  double-freed and killed the connection. The peer was refusing correctly (CAP-6a scored "refused
  all 6 variants") and then taking the connection down with it — `lean`'s shape exactly, reached
  from the opposite direction. **The standing diagnostic found it in one step with no hypothesis
  about zig at all**: first FAIL in RUN ORDER was idx 566 (`tree_operations/put_entity`, "broken
  pipe"), and the last check before the first transport error was idx 562 — the CAP-6a check. The
  gap between them is the defect; the 89 is noise. **Rule: on any peer whose response builder
  CONSUMES its result entity, the salvage path must not also free it.**
  **THE SALVAGE FLAG'S MECHANISM IS DECIDED BY THE PEER'S CONCURRENCY SHAPE, not by taste** — and
  choosing wrong is a race, not a compile error. Measured across 23 peers: a field on the
  cursor/decoder struct where one exists (`c c++ zig ada dart odin nim crystal php ruby io`); a
  threaded PARAMETER where readers are real threads or the runtime has no mutable module state
  (`oz` forks a thread per connection, `unison` a green thread per connection); a THREAD-LOCAL where
  readers are threads but threading the flag would touch eight clause heads (`prolog`); a
  namespace/global ONLY on a single-threaded event loop, where one frame is fully decoded before the
  next is read (`tcl rexx forth`). In every global case both entry points must set the flag, or a
  strict decode inherits a stale 1.
  **AND ON A DECODER WRITTEN AS FREE FUNCTIONS, THREADING THE FLAG THROUGH THE RECURSION IS NOT
  OPTIONAL — forgetting it fails silently in the only direction that matters.** `ruby`'s
  `Cbor.decode_value` recurses into arrays and maps; passing the flag only at the top level leaves
  every nested call strict, so the salvage decode still raises on the tag — **and the tag is always
  nested, inside `root.data`**. A cursor-struct peer gets this for free; a free-function peer needs
  it passed through the array arm, the map arm AND the map's key/value reads.
  **(a) and (c) are the SAME BUG but present as two different failure classes — and one of them
  does not look like a conformance failure at all.** Measured 2026-08-22 across `typescript` and
  `csharp`, whose census reports are identical where it counts: same 3 real FAILs at the same
  indices (558/559/560), same first-transport-error index (563). The *only* difference is what the
  peer does with the connection after refusing. `typescript` **closes** → every later check fails
  instantly → **84F on a valid, complete 755-check measurement**. `csharp` **drops and holds the
  connection open** → every later check waits out a timeout → CAP-6a alone burns **120 060 ms**
  (six variants × a 20 s block, against `go`'s 1 ms), `security` 600 s, `tree_operations` 380 s,
  the global budget expires, nine categories never run → **quarantined as an INVALID MEASUREMENT
  with a *smaller* FAIL count (52)**. So the hang-form is strictly harder to see: it scores lower,
  it is filed under "starved run / harness problem," and it reads as unrelated to the peers whose
  numbers went up. **Diagnostic, cheap, run it FIRST on any starved peer before theorizing about
  latency or resources: compare the first-FAIL index and the first-transport-error index against a
  known peer carrying this defect.** Matching indices means same bug, and the starvation is a
  symptom rather than a finding. That one comparison is what turned `csharp` from "new at this pin,
  not root-caused" into "it is `typescript`." **Corollary for the fix log: a §6.3 fix can move a
  peer out of INVALID entirely — do not budget it as two separate work items.** (Detail:
  `CONFORMANCE-MATRIX.md` §1c.)
- **A LANGUAGE'S "absent" AND "present but wrong type" COLLAPSE IN THE OBVIOUS ACCESSOR — and on a
  temporal field that is a fail-OPEN.** The CAP-6a mechanism, found identically in go
  (`Entity.Uint` → `(0,false)`), ocaml (`Model.uint_field` → `None`), haskell (`uintField` →
  `Nothing`), lean (`uintField` → `none`) and swift (`uintAt` → `nil`). Every one of these answers
  the same thing for a missing field and for `expires_at: -1`, so `if let ex = uintField(...)`
  silently **skips** the expiry check and honors a capability with a negative or bignum expiry —
  status 200. §6.2 CAP-6a names this exactly: a verifier "MUST NOT treat the unrepresentable field
  as absent." **The fix must run BEFORE the range check it protects**, because the range check is
  the thing the ambiguity defeats. Five languages, five different type systems, one bug — treat any
  `optional-typed` accessor over wire data as answering "unusable", never "absent", wherever the
  distinction is security-relevant.
  **RATIFIED and BROADENED 2026-08-22 across all 8 M2 peers — the fail-open has TWO mechanisms, and
  the second one does not involve a null at all.** The entry above describes only the first. Both
  were found in the same session, six peers, and the grep that catches one misses the other:
  - **Null-collapse** (rust `uint_field`→`None`, python `is_integer(v) and v >= 0`→`None`, elixir's
    guard→`nil`, plus the five M1 peers): the accessor answers the same "nothing" for absent and for
    present-but-negative, so the check **is skipped**.
  - **Arithmetic fail-open** (java/kotlin `Cbor.uint`→the `BigInteger` of ANY int, common-lisp
    `entity-uint`→`(when (integerp v) v)`): the accessor happily returns a NEGATIVE value, so the
    check **is not skipped — it runs and returns the wrong answer.** For a negative `not_before`,
    `now < not_before` is simply false, so the capability passes. No null, no `Option`, no skip; a
    reviewer grepping for "optional accessor over a temporal field" finds nothing here.
  **The rule is the same for both and it is the ordering, not the null-handling:** a representability
  check (`absent → legal · present-and-uint64 → legal · anything else → MALFORMED`) must run **before**
  the range comparison, because the range comparison is what the ambiguity defeats *in either shape*.
  **Enforcement, and it must be two greps, not one:** (a) any optional-typed accessor reaching a
  temporal field, and (b) any comparison against a temporal field whose accessor cannot itself reject
  a negative. **On a bignum substrate the `>2^64` half is a DELIBERATE range check, not an overflow
  trap** — python/elixir/CL/java/kotlin integers do not wrap, so a peer that "just does the
  arithmetic" never fires §5.6 rule 3 and silently saturates instead of dropping the term.
  **A THIRD SHAPE, and the greps above BOTH clear the peer that has it: the mechanism can be right
  and the FIELD LIST short.** `pd` (2026-08-28) had carried the correct three-way accessor since it
  was written — `entity_data_uint` returns 0 for absent, 1 for a uint64, **-1 for
  present-but-not-major-0** — and `authz_check_validity` already refused on the -1. It simply never
  ASKED about `created_at`: the guard covered `expires_at` and `not_before` only, the oracle probes
  all three, and the peer honored a capability whose `created_at` was negative. **CAP-6a is THREE
  fields. Grep the field list, not only the accessor** — an audit shaped around optional-typed
  accessors clears `pd` completely.
  **Fixed-width substrates need NO range test and writing one is dead code** — `unison`'s `Nat` and
  `forth`'s 8-byte TV argument make a present uint64 representable by construction, and a bignum can
  only arrive as a major-type-6 tag, rejected at decode. `forth` needs the opposite move instead:
  its `ent-uint` applies the TV's SIGN byte and hands back a negative cell, so the guard reads the
  tagged value directly because **the sign byte is exactly the bit the accessor discards**.
- **UNSEQUENCED ARGUMENT EVALUATION IS THE C HAZARD THIS WORK KEEPS RE-CREATING, and it compiles
  clean under `-std=c11 -pedantic -Wall -Wextra -Werror`.** Candidate — but it happened TWICE in one
  session, once avoided at authoring time (`c`) and once reintroduced five commits later (`sql`),
  which is the shape that earns a note. Folding a computed term into a MIN accumulator invites
  `min_defined(add_ttl(created, ttl, &t), t, &acc, &have)` — which READS and WRITES `t` in one
  unsequenced argument list. In `sql` it folded a garbage term, so `ttl_ms:0` minted the caller
  cap's expiry instead of `created_at`, and the oracle reported it as a CAP-6 rule-2 failure with no
  hint of undefined behaviour. **Rule: a term computed by an out-parameter lands in its own local
  BEFORE the call that consumes it.**
- **§5.5a's per-link granter frames scope the RESOURCE dimension ONLY — applying them to
  handlers/operations/peers is invisible until a DELEGATED cap arrives.** Found on swift 2026-08-21
  (candidate — one peer, but the enforcement point is exact and go/ocaml both carry the correct form
  with a comment). swift passed `childFrame`/`parentFrame` to all four dimensions of `grantSubset`
  and defaulted the `peers` scope to them too. That is **identical to correct behaviour whenever
  child and parent share a granter** — every self-issued path — which is why 745 of 755 checks
  passed. It breaks for exactly one case: a cap whose granter is the *caller*, where a parent
  handler scope of `["*"]` canonicalizes to `/<thisPeer>/*` while the child's canonicalizes to
  `/<callerPeer>/…`, so a **universal parent grant cannot cover any child grant** and every request
  presenting a delegated cap returns 403. Same trap on the §6.2 **mint-time** subset check, which
  must stay on the local frame on BOTH sides (go and ocaml say so in a comment; swift did not).
  **This is A-PD-017's "bare-star is granter-local, never universal" reached from the frame side
  rather than the seed side** — the two are the same defect wearing different clothes. **Enforcement:
  `grep -n 'scopeSubset\|grantSubset' <peer>` and check that only the RESOURCES call receives the
  granter frames.** Symptom to recognize: several unrelated-looking capability checks failing at
  once with 403 while everything self-issued passes.
  **RATIFIED 2026-08-28 — second occurrence (`sql`), and the enforcement grep is now cheap enough
  that it was run across the whole remaining cohort in one pass (clean: only swift and sql ever had
  it).** `sql`'s `sc` CTE canonicalized `dim IN ('handlers','resources')` against the granter frame,
  which is the same defect reached from `check_permission` rather than from `grantSubset`. Identical
  invisibility: 753 of 755 checks passed, because child and parent share a granter on every
  self-issued path.
  **AND THE CORRECT FRAME IS DIFFERENT ON DIFFERENT SURFACES — get this backwards and you fail in
  the OPPOSITE direction, which is why the one-line grep is not the whole rule.** Measured on `sql`
  and `datalog` the same day:
  - **Dispatch-time resource match** and **chain attenuation** (§5.5a surfaces 1 and 2) take the
    PER-LINK GRANTER frame. `datalog`'s `is_attenuated` passed `local` as BOTH frames, so a
    foreign-granted bare `*` canonicalized to the VERIFIER's `/{local}/*` and falsely covered a leaf
    naming the verifier's namespace — §5.5a names this exact failure ("canon-against-wrong-frame")
    and pins three vectors at it.
  - **The §6.2 MINT-TIME subset takes LOCAL on BOTH sides**, because that mint is self-issued and
    the granter is this peer on both. `sql`'s first cut read the parent side through the
    granter-framed CTE and **denied the CAP-5 probe outright**: the presented cap's
    `resources: ["*"]` canonicalized to `/{caller}/*` while the identical requested pattern
    canonicalized to `/{local}/*`.
  So the failure modes are mirror images — over-applying the frame REFUSES legitimate delegated
  caps, under-applying it ADMITS illegitimate ones — and a peer can have one without the other.
  Check both call sites, not just the one the grep lands on first.
  **THIRD SURFACE, and it is the one a fix to the other two makes VISIBLE rather than breaks**
  (`wasm-wat`, 2026-08-29). §5.5a names three surfaces; the two above are chain attenuation and
  the §6.2 mint. The third is the **dispatch boundary** — `verify_request` matching a presented
  cap's resource patterns against the incoming target path — and there the two sides take
  *different* frames: the cap's patterns frame against **its granter**, the request target
  against the **local peer**. Frame both against the local peer and a foreign-granted bare `*`
  becomes `/{verifier}/*` and authorizes the verifier's own namespace.
  **What makes it worth its own entry is how it surfaced.** `captok_form_dispatch_minted_pl_
  presented_xpeer` was *passing* while the peer refused every foreign-granted cap outright — a
  vacuous pass. Implementing the chain walk made it a real FAIL, because the cap now reached
  dispatch and dispatch had no frame. **A fix to one surface converts the next surface's vacuous
  pass into a true failure**, which reads as "my change broke it" and is the opposite. Enforcement:
  after landing §5.5a on any surface, re-run and expect the OTHER surfaces' foreign-granter vectors
  to move; a fully green run right after the first surface lands means the others were never
  exercised.
  **And a K-of-N root has NO granter frame — the local peer is the correct one, not a fallback.**
  §3.6's M6 already requires the local peer to be in the signer set and to have signed, and §5.5
  says a quorum cap's *"subsequent use is locally rooted"*. Deriving the frame from `granter`
  unconditionally simply fails on a quorum root (there is no single hash to derive from), which
  presents as "multisig is broken" and is a §5.5a bug.
  **Sub-lesson from the same peer, cheap and general: in a path-pattern matcher, test the parent's
  TRAILING `*` before testing whether the child path is exhausted.** `/{peer}/*` must cover
  `/{peer}/` — listing a namespace's own root is inside that namespace, not above it. Getting the
  order wrong refuses every root listing while every deeper path still works, so it looks like a
  permissions problem rather than a matcher problem. Two `tree_operations`/`universal_address_space`
  listing checks caught it; nothing else did.
- **A WRONG DENIAL CAN STAND IN FOR A MISSING CHECK, AND FIXING THE DENIAL IS THE ONLY THING THAT
  EXPOSES IT — so a fix that makes a peer's FAIL COUNT GO UP is a finding, not a regression.**
  Ratified 2026-08-28: two occurrences the same session, both in the peers that author the authority
  interior in a query language, which is exactly where a *specific* wrong refusal is most likely to
  land on a *specific* accept-path vector.
  - `sql`: the handlers over-scoping above denied every delegated cap. That denial was answering
    **three security vectors** (`authz_attenuation_foreign_granter_{1,deep,wildcard_leaf}`) and
    **two authz vectors** (`request_rejects_scope_widening`, `authz_scope_exceeds_1`). Correcting
    the frame took it 2F → **7F**, and the five new FAILs were the truth: the ladder had **no chain
    attenuation rung at all** and the handler passed requested grants through **verbatim with no
    §6.2 mint-bound check anywhere in the peer**. Both are now authored rungs; 0F.
  - `datalog`: `strip_peer` never handled the `entity://` form (no leading slash after the scheme),
    so the handlers dimension could not match any CONCRETE scope and delegated requests were denied
    one rung early. Fixing it exposed the same missing §5.5a frame isolation.
  **This is the INVERSE of "conformance-green can be vacuous", and the two are worth holding
  together.** That rule is about a rejection-only category passing a fail-closed peer — nothing is
  being asked. This one is about a peer answering the right question with the wrong mechanism: the
  vector *is* exercised, the verdict *is* correct, and the reason is unrelated to what the vector
  tests. Only a change that removes the wrong reason can tell them apart.
  **Enforcement, and it is a rule about the number rather than about the code: when a fix raises a
  peer's FAIL count, DO NOT revert to protect the row.** Read each new FAIL; if it names a check the
  peer never implemented, the peer was never passing it. Reverting restores a lower number and a
  worse peer, which is the overclaim this repo exists not to make.
  **THIRD AND FOURTH OCCURRENCE, 2026-08-29, and the scale is different: the missing feature can be
  a WHOLE SPEC SECTION, and a category with no accept-direction vector will never say so.** All four
  hand-authored peers — `asm-x86_64` `asm-arm64` `riscv64` `wasm-wat` — implement **no §5.5
  delegation chain at all**. Each requires a presented capability's `granter` to be the local peer
  and refuses everything else. `asm`'s own source states the trade: *"until the delegation-chain walk
  exists, fail closed: granter ≠ our identity_hash → 403. (Closes forged_root_capability and the
  chain-\* reject probes, which all require denial.)"* — **the author knew it was a stand-in and
  wrote down what it closed; nobody re-read that comment as a list of vectors passing for the wrong
  reason.** Roughly ten `security` chain vectors are in that state (`chain_no_delegation_denied`,
  `chain_max_delegation_ttl_denied`, `chain_per_link_temporal_denied`, `chain_mid_link_expiry_denied`,
  `chain_parent_exclude_drop_denied`, all three `authz_attenuation_foreign_granter_*`, …) — every one
  reject-direction, every one answered correctly by a peer that refuses all chains.
  **Two things generalize, and the second is the sharper one:**
  (a) **Suspect the hand-authored substrates specifically.** It is not chance that these four have it:
  chain walking is the most laborious part of §5.5 to write by hand, so it is the part that gets
  deferred, in assembly and in WAT alike. When a cohort defect is about *effort*, its distribution
  follows authoring cost, not language family — look at how the peer was written before assuming a
  substrate limit.
  (b) **A deferral comment is a conformance claim with no gate on it.** `until X exists, fail closed`
  is honest engineering and completely invisible to every number this repo publishes. **Enforcement:
  `grep -rniE 'until .* exists|deferred|not implemented|fail closed for now' protocol-generator/*/src/`
  and, for each hit, ask which vectors that branch is currently answering.** A peer at 2F with a
  comment like that is not a peer with two problems.
  **And the symptom that led here is worth carrying on its own: CAP-5/CAP-6 failing with `403` does
  NOT mean the §5.6 ceiling is missing.** Both checks present a *delegated* capability, so on a peer
  with no chain support they are refused two gates before the mint is reached, and the failure names
  a feature that is not the one broken. Trace the refusal to its gate before implementing what the
  check is named after — on `wasm-wat` that was one instrumented build and it invalidated a
  documented scope estimate ("an arity + data-segment edit … neither is hard").
  **FIFTH OCCURRENCE, 2026-08-30, and it is the other polarity: a wrong denial can hide a missing
  ANSWER, not only a missing check.** Landing the §5.5 chain walk on `asm-x86_64` let a `request`
  reach code that had been unreachable for as long as the capability gate refused every delegated
  cap two stages earlier — and four early-outs there (`author` / `params` / `params.data` /
  `params.data.grants` absent) fell off the end of the function answering NOTHING. Same shape on
  all three ISA peers and on `cobol`. **Add §4.9(c) to the list of things a blanket refusal can be
  concealing:** when a denial is removed, the newly-reachable code is untested by construction, and
  the first thing to check is not whether it decides correctly but whether it *replies at all*.
- **AN OP LADDER THAT DISPATCHES ON LENGTH MUST FALL THROUGH TO THE UNKNOWN-OP ANSWER, NEVER TO
  `return` — and a §4.9(c) silent drop bills the CALLER, so it presents as the peer being slow or
  under-resourced rather than wrong.** RATIFIED 2026-08-30 (two distinct shapes in one session; the
  second is the entry above). The three ISA peers route an operation by comparing its LENGTH first
  and only then its bytes. A length collision with an op they do route — `ping` against `echo`, both
  4 — failed the byte compare and jumped to the function's return with no frame written: not 501,
  not 400, nothing. `hello` (5) and `authenticate` (12) had the same hole.
  **What it cost, and why it was not found for months: every churn cycle ends with a `ping`, so
  every connection burned the caller's full 20 s read deadline.** `t2_2_connection_churn` reached
  cycle 29 of 100 inside the 10-minute budget, consumed all of it, and starved nine categories
  including three core ones — so all three peers were quarantined as INVALID MEASUREMENTS with a
  documented "connection-pressure family". **`CONFORMANCE-MATRIX.md` §1a's accumulation theory was
  wrong, and the 2026-08-29 measurement that ruled it out (peer healthy at the moment of failure,
  fds flat, children reaped) was right and pointed nowhere.** After the fix: `concurrency` 6/6 in
  1.1 s against 599 s, and the whole 755-check set runs.
  **The diagnostic that found it generalizes and the one that did not is worth naming too.** Reading
  the ladder finds nothing — the branch is three lines and looks like every other one. What found it
  in one build: set a flag in the frame WRITER, clear it at the top of dispatch, and print which
  operation returned WITHOUT having written. That question — *which dispatch answered nothing* — is
  cheap on any peer and is the direct form of §4.9(c). Sampling `/proc` and counting live children
  answered "the peer is healthy", which was true and useless.
  **Enforcement: in any length-then-bytes dispatch ladder, every byte-compare failure must target
  the unknown-op label.** Grep the ladder for a compare-failure branch whose target is the function
  epilogue rather than the next candidate or the 501 answer. Note the collisions are invisible to a
  reader who checks only the ops the peer implements — the defect is entirely about the ops it does
  NOT.
- **A FIXED BUFFER FILLED FROM WIRE DATA WITHOUT A SIZE TEST IS A REMOTELY-TRIGGERABLE PROCESS KILL,
  AND HARDENED libc MAKES IT LOOK LIKE A CRASH WITH NO CAUSE.** RATIFIED 2026-08-30 (`cobol`; three
  independent instances in one peer, which is the second shape rather than one bug). `tree-handler`
  did `compute nentlen = endo - eoff` then `move lk-env(eoff:nentlen) to nent(1:nentlen)` where
  `nent` is a fixed 8192-byte field. A 16 KiB `tree.put` — the oracle's own t1_4 staging payload —
  overflowed it, glibc's `_FORTIFY_SOURCE` aborted with `*** buffer overflow detected ***` and no
  backtrace, and **every check after that point failed with connection-refused: 24 of the peer's 30
  FAILs were one unchecked MOVE.** `store-put`/`store-bind` had it into a 4096-byte slot (so any
  entity over 4 KiB corrupted the store tables) and `cap-resolve` into an 8192-byte one.
  **The trap that cost the most time: the OVERSIZE path was correct and the IN-RANGE path was not.**
  The peer drains a frame past its 65535-byte cap exactly as §4.10(a) asks, and `resource_bounds`
  passes — so "oversize frames are handled" reads as evidence and is not. The trace showed a 264 109-
  byte frame drained across four reads without incident and then a perfectly ordinary 18 354-byte
  frame killing the process. **A payload bound is only a bound where the copy happens.**
  **Enforcement, and it is the same rule the AGENTS.md `nent`/`store` fix applies: the size test goes
  BEFORE the copy and produces a STATUS, not after it and not as a bigger buffer.** Grep any peer
  with fixed-extent fields for a copy whose length is computed from wire offsets
  (`endo - eoff`, `have - 4`, `end - start`) and check for a guard between the two. Raising the
  buffer instead of guarding just moves the threshold, and on a substrate where the store hands
  `lk-len` bytes back to the CALLER's fixed buffer it also creates a matching overflow on the read
  path — which is why `cobol`'s per-entity ceiling was left at 8192 and disclosed rather than raised.
- **OVER-CANONICALIZING AN ID-SCOPE DIMENSION FAILS IN BOTH DIRECTIONS AT ONCE — it overgrants AND
  over-denies, and one of the two is what a reviewer is not looking for.** RATIFIED 2026-08-30
  (`cobol`; the swift/sql §5.5a frame over-scoping reached from the F40 side, which makes it the
  same defect in a third dress). `cap-scope-match` canonicalized BOTH the value and the patterns
  against the local peer for handlers, operations and peers. §5.2/F40 makes those three ID-scope:
  matched literally, no frame. Measured simultaneously: an operations include of `/{local}/get`
  AUTHORIZED the bare operation `get` (`f40_id_scope_include_no_overgrant`), and an exclude of
  `/*/get` DENIED it (`f40_id_scope_exclude_literal`). Canonicalization turns a non-matching literal
  into a match, and "a match" is a grant on the include side and a refusal on the exclude side.
  **And fixing the matcher immediately exposed that the VALUE was wrong too** — the handlers
  dimension was being compared as the ABSOLUTE resolved path `/{peer}/system/capability` against
  grants that name handlers relatively, which only ever worked because the matcher canonicalized
  both sides. Removing the canonicalization took CAP-5/CAP-6 to 403; passing the bare handler id
  fixed both. **Two defects held each other up, and neither is visible while both are present.**
  Enforcement: for each scope dimension, ask what KIND of thing the value is. An id is compared
  literally; only a path takes §5.5a. If a matcher takes a frame parameter it must be reachable only
  from the resources dimension — a frame argument on an id-scope call site is the defect.
- **A `created_at` THAT IS A COMPILE-TIME CONSTANT IS A-PD-016 WITH THE CLOCK REMOVED ALTOGETHER.**
  Candidate (`cobol` 2026-08-30, first occurrence, but it is the standing content-addressed-aliasing
  rule at its limit). `mint-token` declared `01 created pic 9(18) comp-5 value 1700000000000.` and
  never assigned it, so every mint with the same grants and grantee hashed identically forever — and
  it silently makes any §5.6 ceiling meaningless, since the expiry would be derived from an instant
  in 2023. Enforcement: grep the mint path for a `created_at` that is not read from the clock, and
  sample that clock ONCE in the caller so the emitted birth instant and the expiry derived from it
  are the same value (the nim lesson, from the other end).
- **A RULE EXPRESSED IN TERMS OF A CPU FLAG IS NOT PORTABLE — restate it as a value comparison
  before porting it.** Candidate (`riscv64` 2026-08-30). §5.6 rule 3's "the term is DROPPED if it
  does not fit" is an overflow test; x86-64 reads the carry flag after `add`, aarch64 after `adds`,
  and **RISC-V has no condition-flags register at all**, so the port has to detect the wrap the way
  the ISA intends — the sum wrapped iff it is less than either operand. Getting this wrong compiles
  clean and passes every check that does not overflow; it silently saturates instead of dropping,
  which is exactly the CAP-6 defect the rule exists to prevent. The same shape appears on any
  bignum substrate from the other direction (§5.6 rule 3 is a DELIBERATE range check there, not an
  overflow trap) — the invariant is the value, never the mechanism.
- **A PARTIAL IMPLEMENTATION OF A NEW RULE IS WORSE THAN ITS ABSENCE — it produces a plausible value
  and reads as done.** Candidate (first occurrence, `nim` 2026-08-28, but the enforcement point is
  exact). `nim` was the only peer in the cohort that ALREADY had a §5.6 ceiling, and it was wrong
  three independent ways: (a) it carried only the request's `ttl_ms` term and never the caller
  capability's absolute expiry, so an over-long ttl minted a token that **outlived the capability
  authorizing it** — measured `expires_at 2102711331804` against a caller cap of `1787354931804`,
  ten years past its own authority; (b) it sampled `nowMs()` in the handler and AGAIN inside
  `mintTokenRaw` for `created_at`, so the emitted `created_at` and the expiry computed from it were
  two different instants; (c) `nowMs() + ttl` **wraps** on uint64, so an overflowing ttl minted an
  EARLIER expiry rather than dropping the term. Every one of those still emits an `expires_at` and
  still returns 200.
  **The general trap is in the oracle's own CAP-5 message and is worth quoting: *"a `<= caller_exp`
  check would pass this; CAP-5 requires the exact clamped value"*.** MIN_DEFINED is a value reached
  by CONSTRUCTION, not a bound verified by COMPARISON — any implementation that reaches it by
  comparison satisfies a weaker test than the one the oracle runs. **Enforcement: for a rule
  expressed as an exact computed value, grep the peer for a comparison against that value and treat
  a hit as unimplemented.**
- **THE "ABSENT" SPELLING IS A PER-PEER DECISION AND MUST BE READ FROM THE PEER — an accessor whose
  "something" conflates absent with present is the CAP-6a defect one level up.** Candidate
  (`smalltalk` 2026-08-28). The CAP-6a guard, written the obvious way as
  `v := aCap field: k. v ifNotNil: [ ... ]`, **denied every capability the peer had ever been shown**:
  176 FAILs, handshake still green, every authenticated request 403. `EcEntity>>field:` answers
  `EcAbsent default` for a missing key, **never nil** — the pure-object absent sentinel this peer
  uses throughout (A-ST-000) — so `ifNotNil:` is always true and every absent temporal field read as
  present-but-unrepresentable.
  CAP-6a is about an accessor whose *nothing* conflates ABSENT with MALFORMED. This is an accessor
  whose *something* conflates ABSENT with PRESENT. Same shape, opposite polarity, same discipline:
  **presence comes from the peer's own presence predicate** (`hasField:`, `hasKey`, `map_find != -1`),
  never from the language's null. **Two things made it slow to find, both worth knowing for the next
  live-image peer:** `make image` pipes the Pharo load through `grep -vi 'undeclared\|warning'`, so a
  compile diagnostic in a new method is suppressed by construction and the build still says `built`;
  and the failure presents as a mass 403 with a clean handshake, which reads like an authz regression.
  **Probing the predicate directly in the image answered it in one send** (`EcCapAuthz
  temporalFieldsRepresentable:` on an empty-data entity → `false`, expected `true`) where bisecting
  the conformance run would have taken an hour.
- **A REFUSAL IMPLEMENTED AT THE WRONG LAYER cascades exactly like a crash — and reads like one.**
  New shape of the standing cascade class, found on `lean` 2026-08-21 (candidate; the class is
  ratified, this *shape* is first-occurrence). Every prior instance was an *uncaught* fault — a bad
  string, a `doesNotUnderstand:`, a raise escaping a narrow catch. This one is a **deliberate,
  correct-in-intent refusal** delivered as a **transport drop**: `lean` refuses all six malformed-
  temporal capability variants (CAP-6a) by closing the connection instead of returning the §5.2
  `capability_denied` disposition the rule mandates. The oracle reuses that connection, so every
  check after `capability` gets `broken pipe` — **81 cascade FAILs from one refusal path**, scoring
  `83F` against its siblings' `2F`/`3F`. **What makes this shape distinct and worth its own entry:
  the peer is completely healthy.** Clean stderr, exit code 0, never crashes — so every reflex the
  crash-cascade lesson trains (look for the uncaught exception, grep the peer log, check for a
  non-ASCII literal) finds nothing, and the natural next inference — "the peer died" — is wrong.
  **Diagnosis that worked, and the order matters:** the oracle's own check message named the defect
  outright (*"0 capability_denied, 6 transport-drop"*) — read it before theorizing; then bisect by
  scope (`-category capability` alone → 2F no cascade; `-category tree_operations` alone against a
  fresh peer → 0F; full core run → first FAIL at idx 559 is a `capability` check and the last check
  before the first `broken pipe` at idx 563 is the CAP-6a one). **Cohort rule: "refuse" means emit
  the protocol-level disposition the spec names — a transport-layer close is not a refusal, it is a
  refusal *and* a denial of service to every subsequent request on that connection.** Enforcement:
  when a peer's FAIL count is an order of magnitude off its cohort siblings, find the first FAIL in
  *run order* and the last check before the first transport error — the gap between them is the
  defect, and the count is noise. (Pairs with the standing "diff the per-check severities before
  believing the headline number" rule, in the opposite direction: that one catches a peer looking
  unfairly *good*, this one catches a peer looking unfairly *terrible*.)
- **On any no-static-check substrate, the resilience frame catches the host's ROOT error class →
  500**, not just the codec's condition family — an uncaught per-request exception is a hang and
  violates deliver-or-signal (§4.9(c)). Two peers landed this independently: Oz (`""` IS `nil` → a
  raise escaped a narrow catch, hung the request; also never use `== nil` as a string sentinel —
  A-OZ-005) and Smalltalk (one `doesNotUnderstand:` cascaded 229 FAILs — A-ST-016). Cohort rule.
- **"FLAKY" AND "LOAD" ARE NOT DIAGNOSES — THEY ARE THE NAMES WE GIVE A RACE WE HAVE NOT LOOKED
  FOR YET. RE-RUN N TIMES AND COUNT.** RATIFIED 2026-09-01 (`zig`), and it is the sharpest process
  failure this repo has recorded because the wrong explanation was *written into a commit message*
  before anyone objected. A census run came back `756 · 288P/27F` — `t2_2_connection_churn` failing
  at cycle 53, then 27 downstream checks reporting connection-refused. An isolated re-run passed,
  and that single passing re-run was published as *"external load, not the change"*. It was not.
  **Re-run five times on an idle host: 3 of 5 FAILED.** Load was never the variable.
  **The intermittency was TWO independent remotely-triggerable process aborts**, and the peer's own
  `--profile core` suite had been carrying them for months:
  - **A use-after-free**: `readLoop` spawns a DETACHED thread per inbound EXECUTE holding a `*Io`
    and `*Conn` that point INTO the connection's `ConnState`, then returns the moment the client
    closes — and the caller frees that state immediately. `Segmentation fault … io.gpa.destroy(ctx)`.
  - **A panic inside a call documented as best-effort**: `setNoDelay` carried *"a failure just
    leaves Nagle on, not fatal"* and a `catch {}`, and aborted the process anyway, because
    `std.posix.setsockopt` maps `BADF`/`NOTSOCK`/`INVAL`/`FAULT` to **`unreachable`** (the stdlib's
    own comment on those arms is *"always a race condition"*) and `unreachable` is a PANIC, which
    no `catch` can intercept.
  **THE MEASUREMENT IS THE METHOD, and the middle row is the lesson:**
  `before 3/5 FAIL · after fix 1 → 1/6 FAIL · after fix 2 → 0/22 FAIL`. **Fix 1 alone reads as
  "mostly fixed" and ships a peer that still aborts** — one bug masked the other, and only counting
  over repeated runs could tell them apart. A single green re-run is not evidence a race is gone; it
  is one sample from a distribution nobody has measured.
  **Why churn specifically, and why months of green runs missed it:** 100 open → request → close
  cycles is a loop that closes the connection *mid-dispatch by construction*. A sequential suite
  never opens that window. **When a check that stresses lifecycle is the one that fails, suspect a
  lifetime bug, not the harness.**
  **Enforcement, and it is a rule about the report rather than the code: an intermittent result may
  not be attributed to anything until it has been re-run and the failure rate recorded.** Cite the
  count (`3 of 5`), never an adjective. If the mechanism is not named, the finding is "not
  root-caused", which is an honest state; "flaky" and "load" are claims, and both were false here.
  *(Sub-lesson, cheap and general: **a detached worker must not outlive the state it borrows.**
  Register the in-flight count BEFORE the spawn — the thread can finish before `spawn()` returns —
  release it LAST in the worker's teardown, because the owner may free everything the instant it
  reaches zero, and await it before the owner frees. And: **a "best-effort" wrapper is only
  best-effort if its failure path returns; check whether the library panics on the errno you are
  ignoring.**)*
  **Residual, named rather than folded into the win:** `resource_bounds/r3_connection_flood` failed
  **2 of those 22** post-fix runs and is a DIFFERENT intermittent — churn is 0/22 — not root-caused,
  handed off. Reporting a partial fix as a whole one is the same defect as reporting a race as load.
- **A TRANSIENT `accept()` ERROR MUST NOT END THE ACCEPT LOOP — a peer that stops LISTENING while
  the process stays alive and healthy reads as a crash and is invisible to every liveness check.**
  Candidate, two shapes found in one sweep (2026-09-01). `zig` had `server.accept() catch break`,
  fatal on its entire `AcceptError` set; `c` had `if (errno == EINTR) continue; break;` under a
  comment saying *"socket closed → stop"* — the intent is right, the code stops on `ECONNABORTED`,
  `EMFILE`, `ENFILE`, `ENOBUFS` and `EAGAIN` too, all recoverable. `ECONNABORTED` is the routine one:
  the client sends SYN then closes before the server accepts, which rapid churn manufactures. So one
  aborted connection can permanently kill the listener. **Say honestly what this was NOT: fixing
  both accept loops did not fix zig's churn failure** (the two entries above did) — it is a real
  defect in its own right, and conflating it with the bug found alongside it would have been the
  easy overclaim. Enforcement: `git grep -nE "accept\(\)? *(catch|orelse) *(break|return)"` plus a
  read of every `accept()` call site's error arm; the rest of the cohort (`cobol` `fortran` `rexx`
  `pd` `sql`) already skips a failed accept and keeps looping.
- **THE PEER'S DYING WORDS MAY NOT BE ON STDERR — CHECK WHICH STREAM THE RUNTIME USES BEFORE
  TRUSTING A CAPTURE THAT PRINTS NOTHING.** Candidate (`io`, 2026-09-07; the cohort-wide
  keep-the-peer-stderr fix meeting a runtime it does not cover). Io writes an uncaught exception
  AND its backtrace to **stdout**, so the harness's `cat build/s4-peer.err` guard — the one added
  precisely so a mid-run abort is not reported as "connection refused" — printed nothing while the
  peer died mid-put. The probe reported `no response header: EOF`, which is exactly the
  no-crash-empty-stderr reading that rule exists to prevent. Fixed by also dumping the stdout log,
  but **only when it contains an exception marker**: printing it every run would train people to
  skip it, which is the failure mode this file records three times. **Enforcement: for each peer,
  know which stream its runtime uses for an uncaught fault — and if the answer is stdout, the
  stderr guard is not a guard for that peer.**
  *(The bug it was hiding is worth its own line: in Io `==` binds TIGHTER than `&`, so
  `b & 0x80 == 0` parses as `b & (0x80 == 0)` and raises. **On any substrate, write bit tests with
  the explicit methods (`bitwiseAnd`, `shiftLeft`) rather than the operators, unless you have
  checked that language's precedence table** — a varint loop is the place this bites, and a
  single-threaded peer turns the raise into a dead process.)*
- **A RAW CONTROL BYTE IN A SOURCE FILE MAKES IT INVISIBLE TO EVERY GREP-BASED AUDIT — and the
  audit reports "absent", not "could not look".** RATIFIED 2026-09-01, two peers, same session.
  `dart/lib/src/peer/peer.dart` and `ruby/lib/entity_core/peer.rb` each wrote `"\x00"` as a
  **literal NUL byte** rather than the escape, in the same helper (`path_flex_ok?` /
  `_pathFlexOk` — a check for an embedded NUL in a path, correct at runtime). `file` calls both
  `data`; `grep` treats them as binary and, in a pipeline, prints nothing at all.
  **What it cost: the cohort-wide survey for the §1.4 gate put BOTH peers in the "no gate" bucket
  when both had one.** Acting on that would have added a second, redundant gate to each and
  published a wrong count of how many peers were missing the feature. Only the oracle caught it.
  This is the `vendor-unmatched` shape one level down — **a could-not-look that presents as a
  clean answer** — and it is the same reason `spec corpus --vendor` reports rather than passes.
  **Enforcement, and `grep -P '\x00'` is NOT it (it does not reliably match a NUL):** scan tracked
  files in Python — `b'\x00' in open(f,'rb').read()` — and treat any hit outside a declared data
  file as a defect. The full tree is clean apart from `cobol/src/core-types.dat`, which is data.
  **Generalize past NUL: before concluding a source-wide grep found nothing, confirm the grep could
  see the file.**
- **"THE SPEC DOES NOT SAY" IS A CLAIM ABOUT YOUR SEARCH, AND WE PUBLISHED ONE AS A CLAIM ABOUT THE
  SPEC — SEARCH THE SECTION THE BEHAVIOUR BELONGS TO, NOT THE WORDS THE QUESTION IS PHRASED IN.**
  RATIFIED 2026-09-01: **second occurrence of the false-negative class in two days**, and the pair
  is what earns it — the `dart`/`ruby` NUL byte above is a grep that **could not see** the file, this
  is a grep that **looked in the wrong vocabulary**, and both publish as a confident negative that
  reads identically to a real one.
  **F51** (`protocol-generator/shared/findings/peers-dimension-reachability.md`) was routed to arch
  on 2026-08-30 asking for a normative sentence on whether a core peer must resolve its own handler
  for a URI naming a FOREIGN peer's namespace. It states *"The spec answers this nowhere we can
  find"* — **four lines under a header citing `v0.8.2`, in which §1.4 line 300 reads *"the path MUST
  target the local peer's namespace. If the peer ID does not match the local peer, the peer MUST
  reject with status 400 (`invalid_request`)."*** Byte-identical in `v0.8.2.3`
  (`sha256(line) = 376953b9…`), i.e. it was in the snapshot we were building the whole cohort
  against.
  **The mechanism is dull and entirely reusable.** The search used the vocabulary of the QUESTION —
  `peers`, `target_peer`, `check_permission`, `extract_peer` — and the rule is written in the
  vocabulary of ADDRESSING. It contains none of those four terms. The finding even names where it
  expected the answer to be added (*"in §5.2 beside `extract_peer`, or in §6.6 beside handler
  resolution"*) and **never read §1.4, the section it is named after.**
  **Two things make it worse than an ordinary miss, and both are about direction.** (a) The finding's
  leading argument — the `peers` default is dead weight under the majority reading, *"the strongest
  argument we have that the minority of 6 is right"* — argued **against** settled normative text; it
  survived only because it was explicitly framed as an argument from construction rather than from
  the spec. (b) It is a **negative** claim, so nothing could contradict it: a wrong positive claim
  about the spec gets caught by the next person to read the cited line, while *"the spec is silent"*
  cites nothing and is never re-checked. It sat published for two days in the register, the matrix
  and `docs/STATUS.md`.
  **Say precisely what upstream did, because the flattering reading is available and is a second
  error.** 0.8.2.2/0.8.2.3 added the code NAME and the explicit prohibition on both wrong
  dispositions (§3.3's 400 table, §6.2's `handler_not_found` carve-out, §6.5 step 3's *"MUST NOT be
  reached by resolving a local handler … and letting §5.2 decide"*). **The MUST itself predates the
  finding.** So this is a WITHDRAWAL, not "arch resolved our ambiguity" — the sharpening is real and
  it is not what we asked for.
  **Enforcement, and it is a documentation rule rather than a grep, because a grep is what failed:**
  a finding that asserts a spec gap MUST record **which sections it read**, by number. That turns an
  unfalsifiable negative into a reviewable one — the next reader sees the hole instead of inheriting
  the conclusion — and it costs one line. Corollary for the cheap direction: **before claiming
  silence, read the section that OWNS the behaviour** (addressing rules live with addressing, not
  with authorization), and grep the spec for the *disposition* you would expect (`invalid_request`)
  as well as the *concept* — one `grep -c invalid_request` on `v0.8.2` returns 1 and it is the
  answer.
  *(Sub-lesson, measured the same session and worth its own line: **a WARN never meant a peer was
  safe.** `wasm-wat` WARNed on the retired check and still carried the defect — it refused, but by
  resolving locally and then failing authz. And **all six peers that PASSed the retired check needed
  the new gate**, which is not a coincidence: passing required exactly the behaviour §6.5 step 3
  forbids. A check whose PASS branch rewards a defect is worse than no check, and the oracle deleted
  it rather than re-pointing it.)*
- **A WIRE PROBE FAILS IN THE DIRECTION OF THE ANSWER IT IS LOOKING FOR — so a probe without a
  CONTROL is not a measurement, it is a rumour with a number attached.** RATIFIED 2026-08-30
  (three independent instances in one afternoon, building `tools/p47-probe` to measure the §4.7
  pre-hello `authenticate` divergence formalization routed to us). Every one of the three would
  have produced a confident, publishable, wrong finding, and **none was visible in the output**:
  - **A placeholder `content_hash`** (33 zero bytes) is rejected under §1.8 validate-before-trust —
    and `go` reports that rejection as **`400 non_canonical_ecf`**, a bare 400 that reads exactly
    like the row-10 answer being measured. The frame was structurally perfect.
  - **`key_type` sent as the numeric §1.5 registry code** when the wire field is **text**
    (`"ed25519"`) made four peers answer `400 unsupported_key_type` — a plausible *fifth behaviour
    class*, concentrated in the hand-authored group, which is exactly where a real one would be.
  - **A `hello` with no `nonce` field** is accepted by 38 peers and rejected by three with
    **`400 connection_sequence_error`** — the precise status *and code* under measurement.
  **Two controls, and the second is the one nobody thinks to build.** (a) A *positive* control on a
  fresh connection — here a plain `hello` that MUST answer 200; if it does not, the peer's result
  is UNTRUSTED and is a probe fault, not a finding. (b) A **differential** control that supplies the
  same input in a state where the answer should differ — here `hello` *then* the same
  `authenticate`. Control (a) catches a malformed frame; only control (b) catches a frame that is
  well-formed and asks the wrong question, which is how the `key_type` class was killed.
  **And (b) paid for itself twice, because it turned out to be the actual finding.** 38 peers answer
  `401 invalid_nonce` pre-hello and **the same thing post-hello** — they never model the pre-hello
  case, they just reach the nonce check and find nothing to match. So a 38–6 "majority" is 6 peers
  that decided something and 38 that got one reading for free. **Generalize past this probe: when a
  census counts implementations agreeing, check whether the agreeing ones DECIDED — an answer
  reached by fall-through is not a vote**, and cohort weight built from it is an overclaim.
  **Enforcement:** no wire probe lands without a positive control asserted in the same run and
  recorded per-peer in its output (`trusted: false` must suppress the peer's result), plus a
  differential control wherever the input under test is a *state* rather than a *value*.
- **A ROUTED SOURCE CENSUS CAN BE EXACTLY RIGHT, AND SAYING SO IS AS IMPORTANT AS A CORRECTION.**
  Same session. `entity-core-formalization` censused 46 peers by reading source, explicitly flagged
  it as unmeasured, and left 11 unresolved. Measuring all 45 buildable peers found **zero
  disagreements across the 34 they committed to**. The standing rule to re-verify a routed claim
  exists for *calibration in both directions* — the point is that the check is cheap and answers
  directly, not that packets are unreliable — and a rule only ever exercised on the miss quietly
  becomes "distrust the sender." Record the corroboration with the same weight as a catch.
  What the measurement DID add is the part a source read structurally cannot reach: the 11
  unresolved, and the sequence-distinguished dimension above, which needs each peer's behaviour on
  *two* inputs. **Prefer measuring what a source read cannot see over re-deriving what it already
  got right.**
- **RATIFIED, FIFTH OCCURRENCE OF THE FALSE-NEGATIVE CLASS AND THE FIRST THAT UNDERSTATES A
  CAPABILITY: A SURVEY KEYED ON A LIST YOU AUTHORED CANNOT SEE WHAT YOU DID NOT THINK OF, AND IT
  REPORTS "ABSENT" RATHER THAN "COULD NOT LOOK."** 2026-09-04, re-deriving the host contract's H4
  packaging survey. The four earlier members all *hid* something (`dart`/`ruby`'s NUL byte — a grep
  that could not SEE the file; F51 — the wrong VOCABULARY; the de-versioning sweep — a pattern that
  could not SPAN the construction; the `host.err` sweep — the right token in the WRONG BRANCH).
  **This one manufactures a false "nothing owed here"**, which is the direction nobody re-checks.
  The survey in circulation split the cohort **26 with a packaging unit / 20 that structurally
  decline**. Measured from each peer's own `[publishing]` block: **25 registry-published · 13
  source-vendored · 8 undeclared**, and **11 of 46 rows disagree**. Five peers that publish to a
  real registry were filed as declining — `fortran` (fpm), **`lean` (Reservoir via Lake, and it is
  an M1 peer)**, `prolog` (SWI-Prolog pack), `smalltalk` (Metacello), `unison` (unison-share).
  **The mechanism reproduced three times in one sitting, on me, while writing the correction**: a
  scan for `package.json Cargo.toml pyproject.toml …` missed `ada`'s `alire.toml`, then `lean`'s
  `lakefile.lean`, then `prolog`'s `pack.pl` — and `prolog`'s sources live in `prolog/prolog/`, so a
  source grep scoped to `src/` returns nothing for it either. Every miss printed a confident row.
  **Enforcement: derive a cohort survey from the tree's OWN declarations — `profile.toml`, the
  roster, a manifest the peer authored — never from an inventory of names you wrote down.** A peer
  with no declaration is then a *reviewable gap*; under a filename list, "declines" and "the
  surveyor had not heard of this package manager" are the same output. Corollary, and it is the
  cheap tell: **a survey whose misses all fall on the unfamiliar members is not noisy, it is
  measuring your familiarity.**
  **Sub-lesson, and it is a design rule rather than a grep: A REQUIREMENT CAN CONFLATE TWO
  INDEPENDENT AXES, AND THE COHORT IS WHERE YOU FIND OUT.** H4 reads *"usable as a library and not
  only as a standalone binary"* — which is really *(a) is there an in-process construction surface*
  and *(b) is there a distribution unit*, and peers answer them **opposite** ways: `c` has no
  registry and is the most library-shaped artifact in the tree (`.a` + `.so` + `make install` + a
  `.pc`, pkg-config being C's actual distribution convention), while `node-red`/`turbowarp` ship a
  `package.json` and are **applications**. A single `host | declined` field gets both wrong, in
  opposite directions. Detail: `protocol-generator/shared/evaluations/extension-host-packaging-boundaries.md`.
- **A NEW SEAM MUST BE ORDERED BEHIND THE BEHAVIOUR A CHECK ALREADY DRIVES, OR IT CAN MOVE A
  CONFORMANCE NUMBER.** Candidate (first occurrence, `typescript` H7, 2026-09-04; the enforcement
  point is exact). Adding an installable evaluator to the §6.13(a) entity-native path is only safe
  because the built-in `compute/literal` branch answers **first** and is unaffected by anything
  installed — that branch is what `core_register_body_binding` drives on all 46 peers. Consulted
  *before* it, an installed evaluator silently owns a check the peer is measured on; consulted
  *after*, a peer with no evaluator is byte-identical to the peer before the seam existed.
  **Measured both ways**: unmutated → `758 · 317P/336W/0F/105S`, exactly 1 of 758 severities
  different from the committed report and that one the documented `t1_1_concurrent_demux` flake, so
  zero checks moved; the plant that preempts the literal path reddens exactly the fast-path test.
  **Rule: when adding a seam to a path a conformance check already exercises, the built-in floor
  goes first and the seam gets the fallback arm — and assert that with its own test, because the
  ordering is invisible in any run where the seam is uninstalled.**
- **A PEER CAN OFFER TWO SURFACES FOR ONE OPERATION, AND THE ORACLE DRIVES EXACTLY ONE OF THEM —
  the other is the one an extension host is told to use.** RATIFIED 2026-09-06: two shapes in one
  session, both on `typescript`, both routed by `entity-system-generator` out of building `CONTENT`,
  and both **structurally invisible to `--profile core`**.
  - **Registration.** The wire `system/handler:register` op forwards a full §3.7 manifest verbatim
    (`handlers-handler.ts:53,82`), so an `operations` map carrying `input_type`/`output_type`
    reaches the interface entity. The IN-PROCESS `registerHandler` declared
    `operations: readonly string[]` and rendered each op as an **empty** `operation-spec` — so a
    handler installed the way a host installs one could publish operation NAMES and nothing else,
    and the extension had to re-write its own interface entity afterwards. §3.7 calls those types
    the thing *"tooling and code generators rely on to derive op shapes without per-extension
    knowledge"*. **`python`'s bootstrap already carried `(op, input_type, output_type)` triples in
    `_CORE_SPECS`** — so this was a cohort outlier and a sibling had the answer, which is the
    standing *"when a scope question has 45 existing answers in the tree, ask them"* rule again.
  - **The response view.** `ExecuteResponse` was built from `envelope.root` **alone** at all three
    client sites, discarding the envelope's `included` map (§3.1) — which is how CONTENT returns a
    blob and its chunks. A caller using the peer's own client surface received the reference and
    could never obtain the referent. The server side was correct throughout.
  **Why neither could be measured, and it is not an oracle gap:** the oracle is a WIRE client. It
  builds its own envelopes and reads ours directly; it never constructs the peer's `Handler` type
  and never goes through the peer's `ExecuteResponse`. So a defect in either surface sits outside
  every conformance category by construction — confirmed rather than assumed: both fixes moved
  **0 of 721** severities, and the only difference against the tracked report was the documented
  `t1_1_concurrent_demux` flake (WARN in 3 of 3 runs, so the tracked PASS is the outlier and the
  report was left alone).
  **Enforcement: for any operation a peer exposes BOTH over the wire and in-process, diff what the
  two ACCEPT and what each PUBLISHES.** A narrower in-process surface is the defect, every time,
  because the wire one is the one under test. Generalize past registration: any type that wraps a
  wire message for a caller (`ExecuteResponse`, a session, a client) must be checked against the
  ENVELOPE it was built from, not against the root entity — a field the oracle reads directly is a
  field a wrapper can silently drop.
  *(Sub-lesson, and it is the standing control rule pointed at my own prediction: **name which ARM
  a plant reddens, then RUN it.** The `python` H6 controls were written predicting checks 1 and 3;
  measured, the ACCESSOR plant reddens 1 and 4 and only the ENFORCER plant reddens 3. Two plants on
  **disjoint** checks is what proves the accessor arm and the enforcer arm are independently
  measured rather than one carrying the other — with a single plant, *"the number a body reads is
  the number in force"* would have rested on one observation. The prediction was recorded in the
  test's own docstring and corrected there.)*
- **A GATE MUST NOT REWRITE A COMMITTED ARTIFACT — and on 36 of 46 peers a bare `./run-s4.sh`
  DOES.** Found 2026-09-04 while diagnosing an unrelated change: `run-s4.sh` with no arguments
  defaults `-json-out` to `status/CONFORMANCE-REPORT.json`, **the tracked, signed-off record**. A
  human diagnostic run therefore silently republishes that peer's number, and mine banked a
  `t1_1_concurrent_demux` flake over a committed PASS before I noticed the `elapsed_ms` in the
  tracked file matched my run exactly. The census is unaffected — `run-cohort-census.sh` always
  passes an explicit destination — so this fires **only** on the invocation where overwriting is
  most wrong. This is the `python`/`ruby`/`prolog` hardcoded-args entry in a second shape: there
  the harness *ignored* the caller's args, here it *defaults* to the published path. **Enforcement:
  `grep -l 'json-out.*status/CONFORMANCE-REPORT.json' protocol-generator/*/run-s4.sh` should return
  nothing** — the default belongs in scratch, and writing the tracked report should require saying
  so (`JSON_OUT=`, or `run-cohort-census.sh --to-status`). Owed; 36 peers, mechanical, gateable in
  `harness-gate.py` as a third invariant of the same interface.
  *(Sub-lesson, and it cost me the whole edit set once: **commit before planting.** A
  plant/measure/restore loop that ends in `git checkout -- <dir>` restores to HEAD, which discards
  the uncommitted work the plants are testing — so plants 2 and 3 ran against a tree with none of
  the feature in it and reported a wall of compile errors that read like the plants failing. Commit
  first and `git checkout` becomes exactly the restore you meant.)*
- **A sibling clearing the bar with a costlier seam disproves a "substrate can't" ceiling.** Io's
  "single-threaded throughput ceiling" verdict was contradicted by Oz passing the same checks with
  *slower* co-process crypto → forced re-measurement → two fixable bugs, ceiling retracted. Cross-peer
  differentials are a first-class diagnostic; an unreconciled ceiling contradicted by the cohort is a
  pessimistic-direction overclaim, as much a misreport as a false green.
- **Memory-primary peers: scope §6.5 signature ingestion to *handler-discoverable* signatures.** The
  EXECUTE's own request signature (target == the root EXECUTE hash) is consumed inline by
  `verify_request` and never looked up post-dispatch — binding one per request grows an in-memory store
  by a unique entity per request → GC thrash → later-category timeouts under load. Ingest cap /
  identity / handshake signatures (reused → idempotent), skip the transient request sig. Two peers hit
  this independently (Io A-IO-022, Rexx A-RX-014) — an implementation discipline, not a spec gap (spec
  §6.5 is fine); pair it with a §4.10 connection-admission cap for the full resilience story.
- **Type registry: render natively, don't ingest bytes.** A peer publishes `system/type/*`
  via its language's reflection over its *own* data model + an override table for entity-type
  pins — single source of truth in code, with the Go-rendered vectors as a byte-exact
  diff/drift target. "Output these bytes to hit the check mark" adds zero independent signal.
  Scope to **core + operational + the type-system bootstrap** only; a core peer never
  pre-publishes extension vocabularies (extensions bring their own types when installed).
  **This rule now has an enforcement point and a known violator** (2026-08-17):
  `grep -rl 'system/type/compute/apply' protocol-generator/*/src/` should return **nothing**;
  it currently returns `asm-x86_64`, `asm-arm64`, `riscv64`, whose `src/typestore.s` publishes
  ~200 type entries including whole COMPUTE / CONTENT / CLOCK / CONTINUATION extension
  vocabularies. The oracle scores those *matched-if-present*, so over-publishing **converts
  283 `type_system` WARNs into PASSes** and makes those three peers read as `545P/42W` beside
  the cohort's `307P/327W` — **a higher pass count that means a scope violation, not better
  conformance.** The lesson generalizes past the type registry: when one peer's P/W split is
  structurally unlike the cohort's, diff the per-check severities before believing the
  headline number — a peer can look *better* than its siblings by doing something it
  shouldn't. (Detail: `CONFORMANCE-MATRIX.md` §1a.)
  **CLOSED 2026-08-30 — the grep returns nothing, and the fix is the cohort's cleanest example of a
  correct change that LOWERS a published number.** The trio was filtered to the 53-name core floor:
  `595P/54W → 313P/336W` (`asm-x86_64`) and `594P/55W → 312P/337W` (`asm-arm64`, `riscv64`), all
  three still `755 · 0F`. Verified per-check before/after on each peer: **exactly 282 checks changed,
  every one `type_system`, every one PASS→WARN, nothing outside that category moved.** The remaining
  deltas against `go` are all pre-existing and named elsewhere (F51 `authz_peers_target_from_uri`
  PASSes on all three; `authz_scope_exceeds_1` WARNed before and after; `r3_connection_flood` PASSes
  on `asm-x86_64` alone). **A 0-FAIL row does not retire an over-publication finding** — that stands,
  and it is why this one survived two weeks past the peers going green with no FAIL count drawing
  the eye to it.
  **THREE THINGS GENERALIZE, and the fix itself is the least of them.**
  - **The SCOPE FILTER BELONGS AT THE POINT OF PUBLICATION, NOT IN THE HARVEST.** These peers have
    no data model to reflect a registry over, so `typestore.s` is harvested byte-exact from the
    *reference* peer — which is a **FULL** peer and therefore serves every standard-extension
    vocabulary. The over-publication was not a mistake in the harvest; it was the *absence of a
    scoping step between harvesting and publishing*. The harvest stays intact (it is evidence of
    what the reference peer serves, and re-harvesting to prune it destroys that); `gen-typestore.py`
    filters. Generalize: **whenever a peer's data is captured from a richer source than the peer
    itself, name the filter and put it in the generator** — capture and publish are different scopes
    and the gap between them is silent.
  - **A KEEP-LIST, NEVER A DROP-LIST — the same argument as `CANONICAL-DOCS.toml`, one layer down.**
    A drop-list of extension prefixes fails **open**: a vocabulary added to a future harvest
    publishes silently and nothing objects. A keep-list of the 53 floor names fails **closed**: an
    omitted core type is a hard `type_system` FAIL on the next run, i.e. loud. Prefer the failure
    mode that shouts, and assert it in the generator (`CORE_FLOOR - harvested` must be empty) so it
    fires at generation time rather than at S4.
  - **`riscv64`'s `reference/typestore/` HAD NEVER BEEN COMMITTED — 0 files tracked, not gitignored,
    simply absent.** Its `gen-typestore.py` could not run from a clean clone and its `src/typestore.s`
    was a committed artifact with **no in-tree input**, byte-identical to its siblings' and
    unreproducible. This is the `forth` `bin/peer.fs` shape one level up: there the *entrypoint* went
    untracked, here the *generator's input* did, and in both cases everything worked locally forever.
    **Enforcement, and it is cheap: for any `tools/gen-*.py` that reads a directory, check
    `git ls-files` on that directory returns non-empty** — a generator whose input is untracked is a
    generator nobody can run but you. All three now regenerate byte-identically from their own
    committed harvest.
  **The cohort corroboration is worth recording because it was exact, not approximate:** 8 peers
  (`rust python haskell ocaml swift java c typescript`) publish a set **byte-for-name identical** to
  `go`'s 53, none publishes a 54th name, and none publishes any extension vocabulary. The floor is a
  hardcoded, order-stable list replicated across each peer's `tools/gen-typedefs.py`. When a scope
  question has 45 existing answers in the tree, ask them before deriving one.
- **A RESOURCE BOUND MUST RELEASE ON THE SAME PATH IT IS TESTED ON — and a bound that never
  releases presents as a DEAD PEER, not as an over-permissive one.** Candidate (first occurrence
  here was `asm-x86_64`'s §4.10(c) admission cap, 2026-08-29; ported to `asm-arm64` and `riscv64`
  2026-08-30, where the same double-reap was required and the failure mode would have been
  identical). A fork-per-connection parent that counts admissions must reap **twice** — once before
  the blocking `accept4` and **again after it returns** — because the first reap runs before the
  parent parks, so every child that exits while it is parked is still counted as live when it wakes.
  At an idle peer that is invisible; at the bound it is fatal. Measured: the peer correctly refused
  194 of 256 flood connections and then refused **the one probe that followed**, with every child
  already gone and the count still reading 64. The oracle named it outright — *"admission slots
  leaked; the bound must release when connections close."* **Generalize past sockets: for any
  counter that gates admission, the release path must be reachable from the same loop that reads the
  counter, and it must run AFTER the blocking call, not only before it.**
  Two sub-lessons from the port, both cheap: **§4.10(a)'s "reject BEFORE fully buffering" forbids the
  drain that looks more polite** — draining a declared body to keep the stream framed *is* the
  fully-buffering the section forbids, done one buffer at a time, and a sender declaring 4 GiB and
  sending 1 KiB parks the peer forever while no 413 is ever emitted. And **a connection-wide socket
  idle deadline is NOT the §6.11(c) per-request deadline** — §6.11 separately forbids implementing
  that one as a connection-wide primitive; the two are only compatible because a forked child owns
  its connection exclusively and serves one frame at a time. Say which one you built.
- **FFI shared-lib gotchas** (every `entity-core-codec-ffi-<lang>` + any dual-impl
  differential): with a verbatim header + linker version-script, do **not** use
  `-fvisibility=hidden` (hidden symbols can't be promoted by `global:` → zero exports; let
  the version script alone control exports, verify with `nm -D`). A same-soname differential
  needs `dlmopen(LM_ID_NEWLM, …)`, not `dlopen` (glibc dedups by soname → silently compares a
  lib against itself).
- **WHICH `ec_content_hash` DID YOU JUST TEST? LINK ORDER DECIDES WHICH SYMBOL WINS, AND A
  DIFFERENTIAL AGAINST "the same `.so`" IS WORTHLESS IF THE PEER DOES NOT CALL THAT `.so`.**
  RATIFIED 2026-09-07 (`asm-x86_64`), and it is the standing *"an exported symbol is not a
  reachable seam"* rule reached from the opposite side: there a symbol that looked reachable was
  not; here a symbol that looked like **the** implementation was a *different one with the same
  name*. It cost a whole session and produced a published `Not root-caused.`
  The peer refused the oracle's 256 KiB `t1_3` staging entity with `hash_mismatch`. The diagnosis
  traced **every input** — type string, byte-string head, all 262 144 payload bytes against the
  sender's filler, length, frame containment — and confirmed that *"a standalone call to the same
  `libentitycore_codec.so` with exactly those bytes returns the SENDER's hash."* Every clause true.
  **The peer never calls that function.** Its `Makefile` links `codec.o` **before**
  `-lentitycore_codec`, so the native `ec_content_hash` in `src/codec.s` wins and the `.so` supplies
  only the crypto floor — **and the Makefile says so, in a comment three lines above the link rule.**
  A byte-perfect input trace against a function that is never invoked is an unfalsifiable green.
  **Enforcement, and it is one command before any FFI-vs-native differential: ask the BINARY which
  one it resolved** — `nm -C bin/host | grep ' T ec_content_hash'` (a `T` means the peer defines it
  and the `.so`'s copy is dead), or read the link line for a local object preceding the `-l`. In a
  `dlopen` differential, **assert that `dlsym` did not hand back the symbol you are linked against**
  (`(void*)so != (void*)native`, abort if equal) — that check is four lines, it fired as intended
  here, and without it the harness compares the codec to itself and prints `identical`.
  **Two more defects came out of it, and each would have kept the check red alone.**
  - **A FIXED BUFFER MUST NAME THE INPUT BOUND IT IS SIZED AGAINST, AND "it has an overflow guard"
    IS NOT THAT.** `ecf_scratch` was `.space 65536` while the peer accepts frames to `MAX_FRAME`
    = 16 MiB (`b_req` is already 16 MiB, the store arena 64 MiB) — **256× smaller than the input it
    can legally receive**, with a perfectly correct `.Loverflow` guard on top. This is the `cobol`
    fixed-field lesson's *sibling, not its twin*: cobol had a copy with **no** size test, this has a
    right one on a buffer sized against nothing, so the failure is not corruption but a **capacity
    gap presenting as a wrong answer**. Sizing it to `MAX_FRAME` is a **derived** bound, not the
    "raise the buffer instead of guarding" move that entry forbids — and check the *shape* before
    fearing the cost: this is one `.bss` arena **per process**, demand-paged, where cobol's was
    `LOCAL-STORAGE` per call per recursion level. Enforcement: for every fixed buffer that receives
    wire-derived data, state the bound in a comment AT the declaration and tie it to the constant it
    tracks; a buffer whose size is a bare literal is one nobody has compared to the frame cap.
  - **AN UNCHECKED RETURN CODE FROM A FALLIBLE RECOMPUTE LIES IN THE DIRECTION OF BLAMING THE
    SUBMITTER.** `admit_put` called `ec_content_hash` and went straight to the `memeq`. On failure
    that function unwinds leaving `out` **UNWRITTEN**, and `ch_admit` is `.bss` — zeros, or the
    previous admission's digest — so a peer capacity limit was emitted as `400 hash_mismatch`: **an
    accusation about the submitter's bytes.** Fixed to distinguish `-3` `EC_DECODE_ERROR` (genuinely
    the submitter's, → `invalid_request`) from `-2` `EC_OUT_OF_SPACE` (ours, → `413
    payload_too_large`), and the `-2` arm is **kept after** the capacity fix made it unreachable,
    because a silent `-2` becoming a false accusation is wrong at any buffer size. **Enforcement: on
    any verification path, grep for a call whose result is compared without its status being tested
    — and note the tell, which is that the failure mode is a CONFORMANT-LOOKING refusal**, not a
    crash. Being unreachable, it was then **executed by planting the old 64 KiB cap and re-running**
    (`tree put status 413`, against `hash_mismatch` unfixed) — the standing *a guard that was never
    executed is not a guard* rule, applied to an arm added the same day.
  **THE SIBLING CHECK IS WHAT MADE THE SECOND HALF REAL, AND IT INVERTED THE OBVIOUS READING:
  "INTERCHANGEABLE IMPLEMENTATIONS" AGREE ON SUCCESS AND WERE NEVER ASKED ABOUT FAILURE.**
  `asm-arm64` and `riscv64` have no `codec.s`, so the *capacity* half is x86_64's alone — but both
  carried the identical unchecked return code, and the C `.so` returns `EC_OK` for any non-NULL
  argument, so the arm reads as **dead code** and leaving it alone reads as the disciplined call.
  The C-ABI has **two** interchangeable impls, so the other one was measured instead of reasoned
  about: `conformance/abi_failset_probe.c` finds **5 of 8 `type` inputs diverge** — Rust's
  `ec_content_hash` runs `str::from_utf8` and answers `EC_INVALID_ARGUMENT`, C hashes the bytes —
  and every divergent case is a **non-UTF-8 `type`, which is attacker-controlled wire bytes on the
  §6.3 put path** (CBOR major 3 does not enforce UTF-8, and step 1b only checks non-empty). So the
  "dead" arm is live the moment a peer links the other impl. **`abi_differential`'s 101 probes are
  structurally blind to this because they drive VALID input** — the `ec_entity_original_bytes`
  export-asymmetry entry above, in a BEHAVIOURAL rather than a presence shape — and §4.1 declares
  **no failure set at all**, so neither impl is violating anything written down. **Rule: a
  cross-implementation differential must drive REFUSAL inputs, not only accepted ones; two impls
  agreeing on every valid vector is not interchangeability, it is a shared happy path.** And
  before dismissing an error arm as unreachable, ask *unreachable under which implementation* —
  the answer for a swappable dependency is not a property of your code. Recorded, unresolved on
  purpose, in `ffi-generator/c-abi/status/FFI-ARM-STATE.md` §3: picking a winner is a behaviour
  change for 34 linking peers and a real design question, not a patch.
  **And record the machinery that worked, because it is the reason this was found at all:** the gap
  was disclosed in `CONFORMANCE-MATRIX.md`, allowlisted **by name** in `skip-provenance-gate.py`, and
  that allowlist's own doc says removing the entry is part of closing the gap. An honestly-labelled
  `Not root-caused.` with a named enforcement hook is what a later session picks up; a reverted
  ladder and a restored `316P` would have left nothing to find.
- **A SHARED LIBRARY'S LIFETIME ASSUMPTION IS PART OF ITS ABI, AND "the process exits" IS AN
  ASSUMPTION ABOUT THE CALLER THAT NO CALLER IS TOLD ABOUT.** Candidate (first occurrence, found
  2026-09-04 while measuring `cobol`'s capacity work; the enforcement point is exact and the blast
  radius is the whole hybrid-FFI tier). `libentitycore_codec` leaks an entire `ec_value` tree on
  **every** `ec_encode_ecf` and `cc_content_hash` — both on the per-request path — and the reason is
  written in its own source: *"the harness + ABI calls are short-lived; we malloc value nodes and
  never free the tree (process exits)"*. That is true of the conformance harness it was developed
  against and **false of every long-running peer that links it**, which is what the library exists
  for. Measured on `cobol`: **~1 KB per dispatched request, 23.3 MB per `--profile core` suite**,
  tracking requests rather than connections (a connection-heavy category costs 80 kB per run; a
  request-heavy one 419 kB over ~449 requests). Unbounded and remotely triggerable.
  **Three things generalize, and the third is why it survived.** (a) **Bisect before attributing** —
  this was found while raising `cobol`'s buffers 8×, which is exactly the change you would blame;
  measuring `HEAD` gave **23.3 MB/suite before against 22.3 MB after**, so it is neither new nor
  worsened, and saying so is the finding. (b) **`grep -c 'free('` on an allocating module is a
  one-line audit** — four hits in `ecf.c`, none of them a value node. (c) **The comment even names
  the fix — *"a v2 arena (`ec_arena_*`) replaces this for the long-running peer decode path"* — and
  `ec_arena_new()` is `malloc(1)`.** The arena is honestly documented as unnecessary *for decode*
  (which borrows spans); nobody noticed that made the sentence's promise about *encode* vacuous. So
  this is the standing **"a deferral comment is a conformance claim with no gate on it"** rule
  landing in SHARED code, where the deferral was resolved on one path and quietly inherited on the
  other. **Enforcement: for any FFI entry point that constructs an owned tree, the same function
  must free it — and a library whose correctness depends on the caller being short-lived must say so
  in its HEADER, where a consumer reads it, not in an implementation comment.**
  **FIXED the same day, and the verification is the part worth copying, because a wrong `free` in a
  library seven peers link is strictly worse than the leak it removes.** A recursive `ev_free`, a
  release at every entry point that builds a tree **on every exit path including the error ones**,
  and child arrays switched to a ZEROING allocator so a partially built tree is walkable — the
  decoder fills them element by element and can fail partway, which is the difference between "free
  on the error path" and a wild pointer. Two leaks were worse than the encode one and neither was in
  the original hypothesis: `ec_envelope_find_signature_for` leaked one tree **per included entity**,
  both its `continue`s skipping the release, and the decoder leaked its partial tree on **every
  malformed input** — remotely triggerable by bad bytes alone, with no valid request needed.
  **Verified at four levels, in this order:** the codec's own regression suite and the 71-vector ECF
  corpus; `cobol` three times, byte-identical to its committed report; the **full 46-peer census** —
  46/46 conforming, all comparable, **exactly 2 of 34 868 severities different** from the tracked
  reports and both the documented `t1_1_concurrent_demux` timing flake; and the leak itself, which
  goes from +22.7 MB per suite to **flat from the first suite onward**.
  **And the 13 agility-corpus failures the harness reports are IDENTICAL at HEAD** — that harness
  does not implement those vector kinds — which is only knowable by running it at HEAD. A red you
  did not cause looks exactly like one you did.
- **A blanket `**/bin/` gitignore rule with a per-peer allowlist silently swallows a new
  peer's entrypoint if nobody adds its exception.** Found 2026-08-17 (W-REGISTER-GUARD
  remediation): `.gitignore` un-ignores `bin/` for ocaml/rust/cobol/apl/smalltalk/fortran/
  julia (interpreted/JIT entrypoint SOURCE, not a compiled-binary dir) but never gained an
  entry for forth — so `protocol-generator/forth/bin/peer.fs` was **never committed**, from
  S3 (`0267303`) through S4/S5-complete, even though every prior session's green report
  (`682·0F` etc.) was real and reproducible *from that session's own working tree*: the file
  existed locally, `git add .` silently skipped it every time (no error, no warning), and it
  never propagated to a fresh clone or `git worktree add` — which is exactly how this session
  found it missing. Rexx/Tcl's `bin/peer.{rex,tcl}` happened to already be tracked before a
  matching blanket rule could apply to them (git doesn't retroactively untrack), which is why
  only forth hit this. **Enforcement:** any peer whose `run-s4.sh`/`Makefile`/`LOAD.md` names
  a `bin/<entry-file>` must have a matching `!protocol-generator/<lang>/bin/` pair in the root
  `.gitignore`, or `git ls-files protocol-generator/<lang>/bin/` returns empty while the file
  sits untracked on disk — check that grep whenever a peer's own gate can't reproduce a status
  doc's claimed green from a clean clone/worktree.
- **RATIFIED — A NEGATIVE CLAIM ABOUT A SIBLING'S CORPUS IS THE SAME UNFALSIFIABLE SHAPE AS "THE SPEC
  DOES NOT SAY", AND WE SHIPPED TWO OF THEM IN ONE PACKET.** 2026-09-04. The F51 rule already covers
  *"the spec is silent"*; this is its second surface — *"we do not find this anywhere in your ledger or
  your proposal"* — and it is worse in one respect: a spec is one corpus you can enumerate, while a
  sibling's ledger, proposals, guides and routing packets are four, and nobody re-reads a claim that
  something is ABSENT. `HANDOFF-TO-ARCH-2026-09-04` §2 opened with exactly that sentence about the
  `EXTENSION-COMPUTE` builtins/D1 interaction. **It is in the proposal** — `PROPOSAL-EXTENSION-HOST-
  INSTALL-SEAM.md` §7's homes table rules it explicitly (*"no edit needed, it is scoped to
  bootstrap-registered builtins and stays true under D1"*). §3b asked whether the frozen compute
  corpus is owed publication; **`GUIDE-CONFORMANCE` §7c answers it in the section we were quoting**,
  and more sharply than we asked (*"built, cross-blessed, and homeless"*). Both withdrawn at sign-off,
  struck in place rather than deleted.
  **The mechanism is F51's exactly and it is worth naming twice: we searched the vocabulary of the
  QUESTION, not of the DOCUMENT that owns the answer** — and in §3b we did not read to the end of the
  section we were citing. **Enforcement, and it is the F51 rule with its scope widened: a finding that
  asserts an absence in ANY corpus — the spec, a sibling's ledger, a sibling's proposals — must record
  which documents it searched, by name.** One `grep -rn builtins docs/proposals/active/` would have
  stopped this leaving the tree. Corollary for outbound packets specifically: **the exculpatory and
  the accusatory halves fail differently — an "already handled, nothing owed" is checked by the
  recipient, a "you have never addressed this" lands as a correction to them and is checked by nobody.**
  *(The re-resolution that caught both is the standing rule paying out for the third time —* record the
  sibling HEAD an audit was taken against and re-resolve it at SIGN-OFF, not at audit time. *Drafted
  against arch `06904ab`, signed off against `7792f61`, twenty commits later, and the delta withdrew
  two of the packet's four asks. Budget the re-resolution; it is not optional and it is minutes.)*
- **RATIFIED, FIFTH OCCURRENCE — PLAN AROUND IT: `core_gate_fingerprint` DOES NOT MOVE WHEN THE CORE
  GATE GAINS CHECKS, AND "the spec delta is minor" IS A JUDGEMENT ABOUT TEXT WHEN THE QUESTION IS
  ABOUT THE WIRE.** Measured 2026-09-04 for `0.8.2.3 → 0.8.2.7`. **One of three** normative files
  moved, `+80/−12` — which reads as trivial and is not. The go oracle grew **+15 declared checks, 0
  removed**, and **13 are `catConnectivity`, a CORE category**; `profile.go` did not move, so the
  fingerprint stayed byte-identical at `8261a033…` for the fifth time in this exact shape. The
  executed core set goes **758 → 772**.
  **Two method notes, both of which cost time here.** (a) **A `.Declare("…")` grep is the wrong
  vocabulary** — `connectivity_conn_errors.go` is 774 new lines registering checks as `const name =
  "…"`, so a Declare-only scan reported **+4** where the truth was **+15**. Our own
  `oracle-bootstrap.sh check_set_digest` already handles both forms; **use the repo's canonical
  extractor rather than authoring a third one**, and if you must grep, prove the pattern sees a check
  you know exists. (b) **A three-lineage probe is a strong prior and is not a cohort claim.** Building
  the HEAD oracle to scratch and running `go`, `rust` and `python` returned an **identical**
  `772 · 324P/336W/5F/107S` — same five failures, nothing else moving — which is good enough to
  scope the work as *one authored fix propagated 46 times* and NOT good enough to publish. Say which
  you have. **Build the candidate oracle to a scratch path and leave the pinned one alone**: a probe
  that clobbers `output/s4-oracles/` has destroyed the measurement state it was trying to inform.
- **RATIFIED — AN ARM WITH HARNESSES AND NO COHORT RUNNER IS ONE NOBODY IS MEASURING, AND
  "IT ISN'T PEER-SCOPED" IS WHY IT ESCAPED, NOT A REASON IT SHOULD HAVE.** 2026-09-04, and it
  is the standing *"a second axis with no cohort gate is an exclusion nobody declared"* rule
  one level up: that rule was about an AXIS inside `protocol-generator/`, this is a whole
  **arm** outside it. `tools/run-axis-sweep.sh` sweeps `protocol-generator/*`; `ffi-generator/`
  is not peer-scoped, so it sat in **no sweep and no `make lint` gate** — while **34 peers link
  the artifact it builds**. The codec leak closed the same day had been on the per-request path
  of every one of them for months and was found **by accident**, while measuring an unrelated
  peer's capacity work. Every harness that would have caught it already existed
  (`regression_test`, `conformance_harness`, `abi_differential`); nothing ran them on a
  schedule. **Enforcement: `ffi-generator/c-abi/run-ffi-gate.sh`, and the arm is listed in
  `run-axis-sweep.sh --list` even though its runner is separate** — S4's precedent, for the
  same reason. **The inventory is the control, not the sweep engine**: a thing absent from the
  list is an exclusion nobody declared, and the fix for "it doesn't fit the table's shape" is a
  row saying where its runner lives.
  **THE FIX DID NOT REACH THREE OF ITS CONSUMERS, BY THE BUILD-ONLY-IF-MISSING SHAPE THIS FILE
  ALREADY RECORDS TWICE** (`node-red`'s `dist/`, `turbowarp`'s installs). Nine peers declared
  the codec `.so` as a **bare make file target** — a file target with no prerequisites runs its
  recipe only when the file is ABSENT — so once built it was `Nothing to be done` forever, no
  matter what happened to the codec's source. Measured: `asm-arm64` and `riscv64` were linking
  cross-builds dated **2026-07-15** and `io` a peer-local copy dated **2026-07-27**, confirmed
  **by symbol** (`nm`: no `ev_free`) rather than by mtime alone. **Three of the nine said `if
  absent` in the comment above the rule** — the defect was written down and never read as one,
  which is the deferral-comment class in a Makefile.
  **The fix is DERIVED prerequisites, never a hand-listed set** (`$(shell find $(CODEC_SRC)/src
  $(CODEC_SRC)/include ...)`): a literal file list is a second copy of the dependency graph and
  a second copy drifts — the dart/csharp lockfile rule, in make. cmake still does the
  incremental work; make only decides whether to call it. **Both directions must be exercised
  or the fix is unmeasured**: touch a source → all nine rebuild; leave it current → all nine
  say `Nothing to be done`. Without the second control you have not fixed staleness, you have
  replaced it with an unconditional rebuild, which passes the first check identically.
  **Enforcement: `git grep -n 'libentitycore_codec.so:$'` — a `.so` target whose line ends at
  the colon has no prerequisites and cannot see a source change.**
  **And re-measure the peers the artifact moved under**: all three reproduced their committed
  row at the pinned check set (`asm-arm64`/`riscv64` **0 of 758** severities different, `io`
  **1 of 758** — the documented `t1_1_concurrent_demux` flake, WARN→PASS, so the tracked report
  was **left alone** under the standing "a single sample is not a rate" rule).
- **A PROBE COUNT IS NOT A SYMBOL COUNT, AND A DIFFERENTIAL IS SILENT ABOUT EXACTLY THE SURFACE
  IT DOES NOT DRIVE.** Candidate (first occurrence, enforcement exact). `abi_differential.c`
  published **"71/71"** — since grown to 101 — as evidence that the two C-ABI codec impls are
  "interchangeable". It `dlsym`s **19** symbols; the spec declares **27**. So a symbol the two
  impls disagree about is invisible to a green run unless it happens to be one of the 19 — and
  one was: `ec_entity_original_bytes` is exported by the C impl and **has never been implemented
  in Rust** (no commit ever added it). **Say the conformance verdict precisely, because the
  flattering framing and the alarming one are both wrong:** spec §4.1 declares that symbol
  **OPTIONAL** ("MAY be provided"), so Rust is **conformant** — and it is still a footgun,
  because both impls ship the same soname and artifact name and are advertised as drop-in
  interchangeable, so a consumer that links one and swaps the other gets an unresolved symbol.
  **Enforcement: the differential now enumerates every spec-declared symbol, `dlsym`s it on
  BOTH libraries, and prints the asymmetry plus how many symbols it actually drives (19/27).**
  It **reports** rather than fails — an optional symbol present on one side is not a defect and
  hard-failing would hold the gate permanently red, the "teaches people to skip it" mode this
  file records twice. What it must never do again is stay silent. **Generalize: any harness
  that publishes a count as evidence of equivalence must also publish the SURFACE that count
  ranges over** — otherwise the number grows while the coverage does not, and nobody can tell.
- **A STALE-BUILD-ARTIFACT CARRIER YOU HAVE NOT MET YET IS THE ONE THAT WILL READ AS "THE FIX DID
  NOT REACH THIS PEER".** Candidate (2026-09-07, `rust-wasm-wasmtime`; the standing rule in a new
  shape). The three inheriting peers (`rust-wasm`, `rust-wasm-wasmtime`, `node-red`) take their
  parent's fix by rebuilding rather than by editing, and two of the three did. The third runs
  `out/peer.cwasm` — the **wasmtime AOT artifact** — and the census hardcodes `NOBUILD=1` for both
  wasm rows, so rebuilding the `.wasm` left a `.cwasm` five days older beside it and the probe
  reported the peer as completely unchanged. The Makefile's `out/peer.cwasm: out/peer.wasm`
  prerequisite is correct; **nothing had ever run it**. **Enforcement: for an inheriting peer, list
  EVERY derived artifact between the parent's source and the byte the peer executes** — here
  source → `.wasm` → `.cwasm` — and rebuild the last one, not the first. A parent fix that "did not
  propagate" is a claim about a build graph, not about the child.
- **A LEAK PROBE MUST CROSS THE PUBLIC BOUNDARY ONLY — the shipped test binaries' leak output
  is the HARNESS's and reads exactly like the library's.** Candidate, same session. The first
  ASan run of `regression_test` + `conformance_harness` reported **12 and 67 leak records at
  HEAD**, after the leak was fixed and verified — every one of them a tree the *harness* built
  directly, or the corpus it holds for the life of the process. A peer never does that: it only
  ever crosses the exported `ec_*` surface. A probe restricted to that surface reports **0**,
  and the pre-fix tree reports **141** on the same probe. **The stacks look identical** —
  `xmalloc → ev_new → …` in both cases — so the distinction is not visible in the output and
  has to be built into the driver. **Enforcement: `conformance/abi_leak_probe.c` calls only
  exported symbols, and drives MALFORMED input as well as valid** (two of the three fixed leaks
  were on decoder error paths, reachable by anyone who can send bytes and by no valid request).
  **And validate the instrument against a control before believing its result**: both the ASan
  probe and the RSS probe were run against the pre-fix tree first (141 records · 5 552
  bytes/pass) and only then against HEAD (0 · 0.00). A detector that has never fired has
  measured nothing — and the RSS instrument needed its OWN control, because the ASan control
  validates ASan and says nothing about RSS sensitivity.
- **A REPRODUCE RECIPE THAT NAMES A BINARY THE REPO HAS NEVER CONTAINED IS A PUBLISHED NUMBER
  WITH NO EVIDENCE UNDER IT.** Candidate, same session, and it is the `forth bin/peer.fs` shape
  with the *harness* untracked instead of the entrypoint. `entity-core-codec-ffi-rust/README.md`
  documented `./target/release/conformance_harness <corpus>` and **"69/69 byte-identical to the
  vendored cross-blessed fixture"**; `conformance/README.md` cited the same harness by path;
  `MANIFEST.md` carried its number. The crate declares no `[[bin]]`, `src/bin` **has never
  existed in git history** (`git log --all -- 'src/bin*'` is empty — not deleted, never added),
  and the documented command exits `No such file or directory`. **The consequence is bigger than
  the wrong number:** it means the Rust impl has **no independent corpus harness at all**, so
  its only verification is the cross-impl differential — a **mutual** check that a defect both
  impls shared would pass. Withdrawn rather than restated. **Enforcement: run the reproduce
  recipe.** It is one command and it is the only thing that distinguishes a stale number from a
  fabricated one — and note the four documents agreed with each other, so cross-reading them
  corroborates the claim instead of testing it.
- **Conformance-green can be vacuous.** A rejection-only oracle category lets a fail-closed
  peer pass without implementing the primitive — and a non-core category never gates. The
  keystone payoff is the *finding* (an untested, inconsistently-implemented core primitive)
  as much as the fix; always add an accept-path unit test in the direction the oracle can't
  cover. **Pin-scoped correction (Unison #43, 2026-07-19): `multisig` is NO LONGER the
  example.** The standing text cited it as "100% malformed→403"; at `cc1970f` the category
  ships a genuine accept vector, `valid_2of3_peer_signed_accepted`, which was a hard FAIL
  against the Unison peer until real K-of-N landed and passes after. The *lesson* stands;
  that *factual claim* is stale — do not treat a green `multisig` as automatically vacuous,
  and re-check any category's accept/reject mix against the CURRENT oracle pin before
  calling it rejection-only.
- **A score is only a score if every peer was measured on the same checks — and that is now
  ENFORCED, not assumed.** `tools/check-set-gate.py` requires every report in a census to have
  executed the identical check set, pinned as `core_executed_check_set_digest` in
  `tools/oracle-pin.env` (**`7aa6f3de…` = 778 checks @ `78db4a9`**; the retired values are recorded
  as `retired_core_executed_check_set_digest*` in that same file — **no two are comparable, so never
  diff a row across a re-pin**. This sentence itself named the 755-check set as current for three
  flips; `coherence-gate` check 6 now gates the class and found it here), and hard-fails on any
  `budget_exhausted` category; `tools/run-cohort-census.sh` runs it automatically and **exits
  non-zero when a census is not comparable**. Note the distinction from the neighbouring pin:
  `check_set_digest` is what the oracle SOURCE declares, `core_executed_check_set_digest` is
  what a run EXECUTED — **the gap between them is exactly where a bad number hides**, and only
  the second one can catch a run that quietly stopped early. Re-measure the cohort and re-pin
  it whenever `ref` changes. **A peer that deviates is not a low-scoring peer, it is an
  INVALID MEASUREMENT** — quarantine it, never list it in the same column as the others.
  *(Measured 2026-08-17: 42 of 45 peers produced a byte-identical 740-check set, so the oracle
  itself is deterministic and consistent — the failure mode is a run that stops early, not an
  oracle that tests different things.)*
  **The gate itself had this bug, in the input it reads (found + fixed 2026-08-22).**
  `check-set-gate.py` overlays `output/scratch/reverify/` on top of the census dir so a
  post-rebuild re-verification supersedes a stale census row — correct in intent, but the overlay
  was **unconditional**, and that directory is scoped to neither a run nor an oracle pin. Three
  reports left there on 2026-08-17 at the retired `de8f807` pin (740 checks) therefore outranked
  the fresh 2026-08-21 `c1b0708` census (755 checks) indefinitely, and the gate condemned
  `node-red` / `rust-wasm` / `rust-wasm-wasmtime` as non-comparable — **7 bad peers reported where
  the truth was 4** — on four-day-old evidence measured against a different check set. It reads
  exactly like a real finding: the diff it prints (*"NEVER RAN capability(5), type_system(10)"*) is
  precisely the 5 new CAP checks, i.e. the most plausible-looking result it could have produced.
  **Fixed:** the overlay now applies only when it is *newer* than the census report it would
  replace, and says so on stderr when it skips one. **Rule, and it is the same one the stale-build-
  artifact entry at the end of this file states from the other side: an input that PREDATES what it
  supersedes is not an override, it is drift.** Enforcement: `stat -c %Y` both sides — any
  "supersedes" mechanism (overlay dirs, `-fixed.json` scratch files, vendored binaries) needs a
  recency check, or it silently pins the past over the present. Sanity-check for this specific
  trap: if the gate's report disagrees with `CONFORMANCE-MATRIX.md` §1a on *which* peers are
  INVALID, suspect the input before the peers.
- **RATIFIED (third occurrence of the stale-input class, and the first where the stale artifact was
  the COMMITTED one): a gate that only reads gitignored scratch says nothing about what a CLONE
  shows.** Found 2026-08-22 in the release sweep. Every tracked
  `protocol-generator/<lang>/status/CONFORMANCE-REPORT.{md,json}` had drifted a full oracle pin
  behind `CONFORMANCE-MATRIX.md` §1 — **38 peers at the retired `de8f807` 740-check set, 4 at 682,
  1 at 645, `io` unreadable, NONE at the current 755** — while §1 published fresh 755-check numbers.
  Several `.md` files still led with `cc1970f`/`b30a589`-era banners quoting `552`/`576` totals from
  oracle `cb54f5b`. **§1 was never wrong** (it is census-backed) — the defect is that the *only*
  numbers an adopter can read without re-running anything contradicted the published row, in the
  peer's own directory, and **every gate we had pointed at `output/scratch/`, which is gitignored.**
  **The cause was structural, and the structure was correct in isolation:** `run-cohort-census.sh`
  deliberately never writes tracked reports (a census must not silently rewrite 45 signed-off
  records) and `output/` is gitignored — two individually sound decisions that between them left
  *no* path to refresh a committed report, so it rotted for months with nothing watching.
  **The generalizable rule: for every artifact you PUBLISH a number from, name the gate that reads
  the COMMITTED copy.** Reproducible-from-the-pin (which is what [ADR-0012] requires and what we had)
  is not the same property as *consistent-in-the-tree*, and only the second one is what a reader
  actually experiences. **Enforcement: `tools/check-set-gate.py --tracked`, run by `make lint`** —
  it fails when a peer published as 0-FAIL carries a committed report from an older check set, and
  deliberately only *reports* peers with disclosed debt (a gate held permanently red by tracked
  backlog gets ignored, which is worse than no gate; fixed peers rejoin the gated set automatically,
  so it ratchets one way). Refresh with **`tools/run-cohort-census.sh --to-status <peer>`** — the
  missing destination, added to the *same* dispatch table rather than a second copy of it.
  **Refreshing a tracked report is a MEASUREMENT, never a file copy** — hand-copying
  `output/scratch/census/<peer>.json` onto a tracked report fabricates exactly the provenance the
  census/status separation exists to protect.
  **The PROSE sibling is what a human opens first, and nothing gated it — so it is GENERATED now,
  not hand-written.** `tools/status-banner.py` (added 2026-08-28) writes the `CONFORMANCE-REPORT.md`
  banner from that peer's own tracked JSON, and **refuses to write one from a report that is not at
  the pinned check set** — a banner is a publication of a number, and publishing one off a stale or
  starved measurement is the defect the tracked gate exists to prevent. It also declines to claim
  *"everything below predates this measurement"* when there is nothing below (three peers had no
  `.md` at all; the 2026-08-22 hand pass asserted exactly that falsehood for `lean`). **And it cites
  the executed check-set DIGEST rather than the oracle commit** — these files publish, and a `dev`
  SHA resolves for no outside reader ([ADR-0012] Am. 1). The 2026-08-22 hand pass wrote
  `oracle entity-core-go @ c1b0708` into all thirteen; generating the banner is what stopped that
  reaching the other twenty-six. **Rule: a per-peer number that publishes gets written by a tool that
  reads the measurement, not by a person reading the measurement.** (All 13 publishable peers were re-measured, not copied,
  and each reproduced its published number exactly — which is also the strongest evidence the
  release numbers are real.) **Two sub-lessons worth their own greps:** (a) the new gate had a bug in
  the shape it exists to catch — `collect()` keyed reports by *path stem*, and every tracked report is
  named `CONFORMANCE-REPORT.json`, so all 45 collapsed into one dict entry and the gate would have
  "passed" having examined a single file; **any dict keyed by `Path.stem` over a conventional
  filename is a collision waiting to happen** — key by the meaningful path component. (b) A one-off
  formatting pass over 13 prose reports must not assert history that does not exist: `lean` had never
  had a `.md` companion, so the generated *"everything below predates this measurement"* line was
  false for exactly one peer — check the generated text against each target, not just the template.
- **RATIFIED (fourth occurrence of the stale-input class, and the one that had ALREADY FIRED IN
  PUBLIC): an identifier is only a pin if it resolves for the audience the claim is published to.
  A commit hash never does. Publish the content digest.** Raised by the operator, measured by arch
  (`ROUTING-2026-08-23` / `COHORT-OPEN-ITEMS` §1k **P-1**), landed here 2026-08-23, and now the
  ecosystem rule: **[ADR-0012] Amendment 1** — *"the digest is the normative anchor; `N·0F @
  <digest>` is the citable form."*
  **The mechanism, and it is not a rewrite story.** [ADR-0027] authors every published commit
  **fresh at the release boundary**, so public `master` is a *different history* from `dev` — `dev`
  is never rewritten and `master` is fast-forward-only; the two lines simply are not the same line.
  A `dev` SHA has therefore **never** resolved for a public reader and never will. It is not
  degraded at release; **it was invalid on arrival for the audience we ship it to.**
  **It had already fired here, twice, and one instance was live.** Published `CONFORMANCE-MATRIX.md`
  reads `665·0F @ e8524ed`; `e8524ed`, `33f35fd`, `b30a589`, `75c532e` resolve in **no repo in the
  checkout** — they died in go's 2026-07-10 mirror history rewrite. [ADR-0012] calls oracle-pinned
  conformance *"our single strongest credibility artifact,"* and on the public surface it was
  unverifiable by an outsider **and by us**.
  **The galling part is that this repo diagnosed it correctly six weeks ago and built the fix.**
  `core_gate_fingerprint` was created on 2026-07-10 *in response to that exact death*, and
  `oracle-pin.env` has carried the proof in one line ever since — `retired_ref_4 = e8524ed
  (unreproducible after mirror history rewrite; same fingerprint)`. **The commit died; the
  fingerprint carried the verdict across its death.** What never happened is that the practice
  reached the *documents*: the pin then quietly regressed from `cc1970f` (which **is** on go's
  public `master`) to a dev-only commit, with nothing objecting, because nothing asked.
  **A local fix that never reaches the rule is not landed — it is a habit in one seat, and it
  decays.** That is this repo's own ratchet law failing in the direction it was written to prevent.
  **And "just re-point `ref` at a public commit" is NOT available — check before promising it.**
  Measured 2026-08-23: go's public `master` HEAD is `cc1970f` (the v0.8.0 release) and its `dev` is
  **514 commits** past it, so **the oracle the whole cohort was measured on exists on no public
  branch under any name**. Any publicly-resolvable commit we could cite is a *different oracle*.
  The digest is not the convenient option, it is the only honest one.
  **What landed:** the three anchors are the pin and the commit is labelled internal
  (`tools/oracle-pin.env` gained a "WHICH FIELD IS THE PIN" block); §1's column is `Oracle pin`
  carrying `core_executed_check_set_digest` (`95edd774…`) in all 46 rows; a new
  **[The pin](CONFORMANCE-MATRIX.md)** section publishes all three anchors plus the reproduction
  recipe **and the limit a digest does not fix** — until go publishes a `master` carrying this
  oracle, an outsider can *verify* an oracle they have but cannot *obtain* ours.
  **Enforcement: `tools/pin-gate.py`, run by `make lint`.** It watches the two ways a content
  anchor stops being trustworthy, and note that **neither is "someone typed a commit hash"**:
  (a) the §1 pin column reverting to a commit — 45 published numbers hang off that one column and
  the reversion would look completely normal; (b) a hand-copied 64-hex digest drifting from
  `oracle-pin.env`. **(b) is the one worth internalizing: a wrong digest is strictly worse than a
  wrong commit hash**, because nobody proofreads 64 hex characters and a bad commit at least fails
  loudly when someone tries to resolve it. Regression-tested against all three planted defects.
  Cross-repo resolvability across the whole published surface is arch's `spec pins`
  (`entity-system-arch-tools`), which resolves cross-repo and attributes by owning repo — do not
  build a second copy of it here.
  **Sub-lesson, and it is the same defect one level down: we retired four pins by COMMIT and never
  recorded the content identity of any of them.** `retired_ref*` carried the commit and the
  *source-declared* digest, but never `core_executed_check_set_digest` — the one anchor a published
  per-peer number is actually measured against. So the retired 740-check set existed in this tree
  only as the 8-hex prefix `8537d875…` quoted in prose, with **no full value anywhere**, and every
  historical figure was therefore unanchored in exactly the way we were fixing going forward.
  Recovered by recomputing from the committed reports still at that set — 26 peers agree
  byte-for-byte, which is better provenance than the original record would have been — and now
  recorded as `retired_core_executed_check_set_digest{,_1,_2}` (740 / 682 / 645).
  **Rule: retiring a pin means recording its content identity, not just its successor.** When you
  build a durable anchor, apply it to the history you already have, not only to the next entry —
  the same "harden one anchor, check its siblings the same day" reflex the `check_set_digest`
  test-fixture fix earned.
  **Deliberately NOT swept, and say so rather than let it read as an oversight:** the dated `>`
  build-log note blocks and the closed-items ledger keep their dev SHAs, under an explicit
  disclaimer in §1's reading note. A build log that gets back-edited stops being evidence of
  anything. 152 unreachable citations → **85**, all of them historical.
  **Two gate defects found while doing it, and both generalize past this repo.** (i) **A backtick
  span that WRAPS A LINE is invisible to a per-line scan.** `README.md` — the front door — published
  ``…309P/337W/3F/106S\n@ c1b0708` `` and arch's `spec pins` never reported it, at 152 or at 85,
  because the span opens on the previous line. That is the headline number on the credibility
  artifact anchored to a dead identifier, with the gate saying clean. **Scan the joined text, not
  lines** — recover the line number from the match offset. **A false negative in a gate is worse
  than a false positive, and this class correlates with prose quality**: the more carefully a
  document is wrapped, the better its citations hide. (ii) **A file that records both commits and
  digests hands out commit-shaped exemptions for free.** Our own first cut accepted any recorded hex
  as an anchor prefix, and `oracle-pin.env` holds `commit = c1b0708c1679…`, so `c1b0708` matched it
  and the bare-SHA check **passed a planted defect**. Harvest only 64-hex sha256 and explicitly
  truncated `…` forms; a bare 40-hex commit is never an anchor. **Both were caught by planting the
  defect, not by reading the code** — the regression suite is the enforcement point, and a gate
  without one is just a script that has never been wrong yet.
- **A FRESH CLONE BUILT THE WRONG ORACLE, EXITED 0, AND WOULD HAVE REPORTED THE COHORT GREEN.
  The build was never broken — that is what made it dangerous.** Measured 2026-08-23 against a
  genuine fresh clone (a detached keystone worktree with no `output/`, plus `git clone --no-local
  --single-branch --branch master` of go — 2 commits, pinned ref absent), because "does an adopter's
  build still work" is not answerable by reading the script.
  **What happened, in order:** `ref = c1b0708` did not resolve → R1 fell back to HEAD `cc1970f` →
  **`core_gate_fingerprint` MATCHED BYTE-FOR-BYTE** (`8261a033…`; it has been identical across all
  five pins, so it raises nothing, ever) → `check_set_digest` differed → printed a **NOTE** → built,
  installed, **exit 0**. The resulting binary is missing `request_mint_temporal_ceiling`,
  `ingest_rejects_unrepresentable_expiry` and `configure_empty_grants_withdrawal` (`strings`-
  verified) — **the three checks that are this release's entire finding.** An adopter following the
  documented path gets a clean build, a green run, and 32 peers passing that `CONFORMANCE-MATRIX.md`
  says fail, and concludes our matrix is wrong. **A falsely-GREEN result out of a SUCCESSFUL build is
  the worst thing this repo can emit**, and a warning on stderr inside a wall of `go: downloading`
  lines is not a control. **Rule: an anchor mismatch is a HARD STOP with a non-zero exit, never a
  NOTE.** `oracle-bootstrap.sh` now exits 3 with the cause and the remedy (`REPIN=1` is the explicit
  escape hatch for a deliberate re-pin).
  **Second bug, same session, worse shape: the "nothing to do" short-circuit compared the install
  against ITSELF.** `HAVE`/`HAVE_CS` came from `PROVENANCE.txt` (what is installed) and
  `CORE_FP`/`CHECK_SET` from the ref being built; on a second run both described the same wrong
  oracle, so they agreed trivially and the script printed *"NOTE check-set digest differs from
  committed pin"* and *"matches BOTH … nothing to do"* **three lines apart**. **A self-consistency
  check reads exactly like a correctness check and is not one** — always name the authority side of
  a comparison (here: the committed pin), and be suspicious of any equality test whose two operands
  are derived from the same source.
  **Third hole, closed at the same time:** `run-cohort-census.sh` read the pin's `ref` only as a
  *label* to stamp the roster and never checked the installed binary, so a whole census could run on
  a wrong oracle and stamp 45 rows `@ c1b0708`. `check-set-gate.py` does catch it afterwards, but as
  *"42 peers are not comparable"* — which reads as a peer problem and sends you looking in the wrong
  place **after** the multi-hour run. It now preflights the installed digest against the pin and
  refuses in seconds. **Ask the cheap question before spending the hours.**
  **The good half, and it is the whole justification for content pinning — PROVEN, not argued.**
  Simulated the post-release world: a go clone whose `master` carries a **freshly authored commit
  `592ff26`** (never seen by us, `c1b0708` unreachable by name) with the same tree. `oracle-bootstrap`
  falls back, matches both anchors, builds — and the resulting `validate-peer` is **byte-identical**
  to our pinned one (`c3827af8…`). **The commit hash is genuinely not needed; the digests are
  sufficient and the build is reproducible.** So the current gap is purely that go has not published
  this oracle yet — a sequencing dependency, not a design flaw. **Enforcement: re-run this three-
  scenario test (public-master clone → must exit 3 · our tree → must exit 0 · re-authored publish →
  must build byte-identically) before any release that claims an adopter can reproduce a number.**
- **`CANONICAL-DOCS.toml` IS A KEEP-LIST, NOT A SCRUB-LIST — undeclared means DELETED FROM THE
  PUBLIC TREE, and for months this repo's own header said the opposite.** Found 2026-08-23
  (fleet-wide by the arch-tools first full pass, routed to us as a release blocker).
  `canon-filter` (`entity-core-devops` release-builder, `internal/canon`) removes every file it
  does **not** find declared, within its scope. Our header described a *scrub-list of name
  patterns* (`**/HANDOFF*`, `PROPOSAL-*`, `CLAUDE.md`, …), which is the wrong model **in the
  dangerous direction**: it reads as "undeclared files are dropped only if they match a
  pattern," and under it **eight files that were already on public `master` sat undeclared and
  one release away from silent deletion** — `AGENTS.md` `AGENTS-STANDARD.md` `CHANGELOG.md`
  `CLAUDE.md` `CODE_OF_CONDUCT.md` `CONTRIBUTING.md` `RESOURCE-CAPS.md` `SECURITY.md`. **No
  other gate sees this**: leak-audit asks whether it is safe to publish, conform-audit whether
  it conforms, the build whether it works — none asks *does this still contain what we already
  gave people*. Only `[6/6] public-regress` does, and it is new.
  **Know the scope exactly, because it decides what a mistake can destroy** (verified by reading
  `internal/canon/canon.go`, not by inference): **only PROSE is ever dropped** — `.md .markdown
  .rst .txt .adoc` plus `.patch`/`.diff` — **and only** when it is loose at the top level (no `/`
  in the path) or under a doc-root **prefix** (`docs/ doc/ reviews/ review/ research/
  explorations/ proposals/ validation/ stewardship/ status/ reports/ notes/ handoffs/ audits/
  planning/ design/ designs/` and their singular/plural twins). Everything else — source,
  configs, vectors, `.py`, `.sh` — is **always kept, wherever it sits**. **Prefix means at the
  START of the path** — `strings.HasPrefix`, so `protocol-generator/<lang>/status/*.md` is out
  of scope and never has been at risk.
  **CORRECTED 2026-08-24, and the correction is the lesson: this entry said "droppable REGARDLESS
  OF EXTENSION," which was true of the tool when written and is now false.** `canon-filter` was
  fixed to prose-only on 2026-08-23 after the old rule shipped an `entity-core-go` mirror that
  **failed its own test suite on a clean clone** — it had stripped four conformance `.cbor`
  vectors and a `.json` baseline that published code reads, because they were filed under
  `docs/validation/`. *Location is not function.* The operator's ruling on the fix shape is worth
  carrying: **"we fix our thing that doesn't strip out essential things from repos"** — not a
  keep-list entry per artifact, which would be a permanent public-surface commitment made to work
  around a filter defect. **The general rule: a documented fact about someone else's tool has a
  shelf life, and re-reading the source is cheap.** We caught this only because a routed strip
  list disagreed with our own recomputation by exactly three `.sh` files — **diff a supplied list
  against your own before accepting either.**
  **Enforcement:** simulate before every release — walk `git ls-tree -r origin/master`, subtract
  the declared set, apply those two scope rules, and require the remainder to be empty or
  declared in `.release-removals`. Currently: **0 undeclared deletions, 1 declared**
  (`docs/status` — [ADR-0031], and it is a MOVE of `STATUS.md` to `docs/`, not a withdrawal).
  **RATIFIED 2026-08-23, second occurrence and a different shape: "regardless of extension" is
  the half that bites is *prose under a doc root*, because that is where the durable writing
  lives.** The first occurrence was eight prose files. The second was **fourteen** — five
  cross-cutting paradigm surveys under `research/evaluations/`, `rt13-write-concurrency-classes.md`
  under `research/diagnostics/`, and eight dated cross-cutting syntheses at `research/` top level
  including the **954-line red-team review of our own claims** and one that calls itself *the
  front-door document*. Every one was named from the published surface: the surveys from
  `AGENTS.md`, `CONFORMANCE-MATRIX.md`, four peers' `PROFILE-RATIONALE.md`, `sql/profile.toml` and
  two `Containerfile`s; `rt13` from the go and rust peers' concurrency **test source**; three
  syntheses from a published finding.
  **The sharpest instance is still not a doc link at all — `tools/check-set-gate.py` PRINTS a
  diagnostic's path at RUNTIME as the reader's next step** — but note the correction directly
  above: that diagnostic is a `.sh` and, since the 2026-08-23 prose-only fix, was never actually
  at risk. **The instinct was right and the reason was wrong**, which is worth more than being
  right for the right reason would have been: it is why the scope statement got re-derived from
  source instead of carried forward.
  **THE FIX IS TO MOVE THE FILE, NOT TO DECLARE IT — operator ruling, 2026-08-23, and it
  reverses what this entry said when it was first written a few hours earlier.** The reflex on
  finding an undeclared file that ought to publish is to add a `[[doc]]` block, and it is wrong:
  **`CANONICAL-DOCS.toml` declares CANONICAL DOCS. It is not a catch-all for whatever needs to
  survive the filter.** A probe script, a paradigm survey and a forwarding map are none of them
  canonical documentation, and declaring them turns the keep-list into a junk drawer nobody can
  audit — it stops answering *what is this repo's documentation* and starts answering *what did
  somebody once need to keep*. All nine moved to `protocol-generator/shared/{diagnostics,
  evaluations}/` instead, beside the findings, which is the same move for the same reason.
  **The standing answer to the whole class: `protocol-generator/**` is outside every doc-root
  prefix and publishes with NO declaration at all. Anything that must ship and is not
  documentation goes there; declaration is reserved for documents.** The keep-list grew by
  exactly one entry across the whole release-readiness push — `docs/STATUS.md`, which is a
  canonical doc — while 33 documents moved into publication without touching it.
  **RATIFIED 2026-08-24, third occurrence, and it is now a GATE rather than a grep —
  `tools/link-gate.py` check 2, in `make lint`.** A published file must not NAME a path the
  release strips. Check 1 (link resolution) is structurally blind to this: the target exists in
  our tree, so the link resolves here and is dead for the reader. The three occurrences were the
  sixteen non-doc citations that defeated the first findings rename, the diagnostic
  `check-set-gate.py` printed at runtime, and — found by DevOps' independent pass, not by us —
  **three source comments citing dated snapshots, two of them in published peer source, a `.c`
  and an `.s`.**
  **We had already run this check and reported "one hit." It was three.** The scan was scoped to
  `*.sh *.py *.go *.rs *.toml Makefile` and never opened a `.c` or an `.s`; and it matched bare
  basenames, so 66 of 69 raw hits were `README.md` colliding with itself, which is precisely the
  noise that makes a reader dismiss the other three. **Two failure modes in one grep — wrong file
  set, and a signal-to-noise ratio that hid the answer inside its own output.** Match FULL PATHS,
  scan EVERY extension.
  **And the wrapped form is not an edge case here — it was two of the three.** The gate reads the
  JOINED text and tolerates a comment marker on the continuation line (`//`, `#`, `;`, `*`, `--`,
  `!`, `%`), because a path broken across a line with `# ` starting the next one is invisible to
  every per-line tool. Fourth time this shape has cost real time.
  **Severity is split on purpose, same principle as `check-set-gate`'s disclosed debt:** non-prose
  citations FAIL (shipped engineering provenance, small and actionable — currently 0), prose-to-
  prose citations are REPORTED and do not fail (26 dated snapshots cited from published docs,
  measured and parked by operator ruling). Hard-failing those would hold the gate permanently red,
  which teaches people to skip it — a failure mode written down twice in this file already.
  Regression-tested against all four cases: plain non-prose citation → exit 1, wrapped non-prose
  citation → exit 1, prose citation → exit 0 with a report, clean tree → exit 0.
- **THE ECOSYSTEM ADRs DO NOT PUBLISH — standing operator ruling, 2026-08-24. `docs/adr/ecosystem/`
  stays undeclared, all 33 strip, and that is the correct answer rather than a finding.** Cite
  `[ADR-NNNN]` by NUMBER in published prose freely — the number references a decision, not a
  promise of a file — but **never send a published reader to the PATH**, because that directory is
  not in the mirror. The transport question (with [ADR-0030] retracted there is no automated
  injection, so hand-synced copies rot) is **correctly identified and deliberately unanswered** —
  blocked behind a decision on what publishing an ADR means at all. Hand-sync, say so in the
  commit message, and **do not build a local mechanism for it.**
  **The near-miss is the part to remember, because it came in through good behaviour.** We
  re-synced `AGENTS-STANDARD.md` faithfully; the authored copy then said *"`docs/adr/ecosystem/`
  carries the full text of every ecosystem ADR… It is now local."* `AGENTS-STANDARD.md` is
  **declared**, so the cut would have published a canonical document telling a reader to open a
  directory the release deletes — **the index shipping while the evidence does not, inside the
  standard that warns about that exact shape.** The four already-public repos were clean only
  because their copies were *stale*; keystone was first precisely because it was in sync.
  **Being current is not the same as being correct, and a re-sync inherits the upstream's
  defects along with its fixes** — so after every overlay pull, grep the *published* surface for
  paths the release strips, not just for drift. That grep found three more in **our own**
  authored files (`AGENTS.md`, the keep-list header, `link-gate.py`'s comment) that the upstream
  repair could not have touched.
- **A ROUTED LIST THAT DISAGREES WITH YOUR OWN RECOMPUTATION BY THREE FILES IS A FINDING, NOT A
  ROUNDING ERROR.** 2026-08-24: DevOps sent a 119-file strip list; recomputing it here gave
  **122** — the delta was three `.sh` files under `research/diagnostics/`. Chasing that gap is
  what surfaced that `canon-filter` had been **corrected to prose-only** on 2026-08-23 and that
  our documented scope statement had been false ever since (see the keep-list entry above).
  **Neither list was wrong about its own tool; ours was wrong about a tool that had changed.**
  Enforcement, and it is cheap: **recompute any supplied inventory and diff it** — the diff is
  the question worth asking, and a zero diff is a corroboration worth having. Pairs with the
  routed-claim rule below: this is the same discipline applied to a *list* rather than a *claim*.
- **VERIFY A ROUTED CLAIM BEFORE ACTING ON IT, ESPECIALLY THE EXCULPATORY HALF — a packet's
  parenthetical "we checked, this one doesn't apply to you" is the sentence most likely to be
  wrong and least likely to be re-checked.** Same session, first occurrence, candidate. The
  routing packet listed **seven** at-risk files and added *"(`RESOURCE-CAPS.md` was named in the
  original fleet-wide finding. Checked: it is **not** on your public `master`, so it does not
  apply to you.)"* It **is** on our public `master` — confirmed identical across `origin`,
  `github` and `codeberg` at `d8c2b0a` — and the release pipeline's own source comment says so
  outright (*"and keystone `RESOURCE-CAPS.md`"*, `dev-pipeline/promote/promote.sh`). Acting on
  the packet as written would have shipped a release that **deleted a published file**, and the
  exemption is precisely the part a reader skims. The general form pairs with A1 (trace a value
  before you theorize): **an inbound claim that reduces your work is still an inbound claim.**
  Enforcement is the simulation above — one command, answers the question directly, and needs no
  trust in anyone's list.
  **Re-run 2026-08-23 on the next packet, and this time the routed claim held — record that too,
  or the rule degenerates into "distrust the sender."** The follow-up packet named two internal-
  token leaks on the publishable surface (`protocol-generator/shared/lifecycle/ORCHESTRATION.md`
  naming the coordination repo as *"the canonical source"*, and one line in the P-1 finding).
  Running the check ourselves — a case-insensitive `git grep -E` for every literal in
  `leak-audit`'s `internal-tokens.local` denylist (the coordination-repo name, the build-host
  name, the ops host and the ops address; read them from that file, and **do not transcribe them
  into a committed document** — the leak-detector's own denylist must not become a leak, which
  this paragraph got wrong on its first draft and its own scan caught) over the whole tree minus
  `docs/status`, `docs/archive` and the injected ADRs — returned **those two and nothing else.**
  Both were fixed with the packet's own corrected copies. **What the
  verification is for is calibration in both directions:** the point is that the check is cheap
  and answers directly, not that packets are unreliable. One line, two minutes, and it either
  corroborates the sender or catches the thing they skimmed.
- **RATIFIED, FOURTH OCCURRENCE OF THE PUBLISHED-PROSE CLASS — A CITATION THAT NEVER RESOLVED IS
  INVISIBLE TO EVERY GATE, AND THE ONE WE HAD WAS NAMED IN AN ECOSYSTEM ADR TWO MONTHS AGO.**
  2026-09-09, found by hand-walking the published surface during a status audit with all eleven
  gates green. Three instances, one class — **published prose rots exactly where the gates are
  scoped somewhere else** — and the third is the durable one:
  - **The canonical register cited in-flight escalation packets by PATH.** `SPEC-FINDINGS-LOG.md`
    is declared canonical; F54 and F58 each ended `Routed in \`…/HANDOFF-TO-ARCH-<date>-<slug>.md\``,
    and those packets are undeclared under a doc-root prefix, so they strip. That is the standing
    *"the index shipped and the evidence did not"* shape **in the exact file AGENTS.md names as its
    enforcement point** — and `link-gate` is right not to fail it, because prose-to-prose citations
    are parked by ruling. **A parked class still needs a rule for the one member the ruling was not
    about: the register's evidence citations.** Fixed by naming the ROUTING DATE, never the path —
    the packet is a process artifact, the finding is the research output, and only the second one
    publishes. **Enforcement: `grep -n 'research/stewardship/HANDOFF' research/stewardship/SPEC-FINDINGS-LOG.md`
    must return nothing.**
- **A GAP IN THE SPEC DOES NOT PRODUCE A GAP IN THE CODE — IT PRODUCES WHATEVER THE EXISTING BRANCH
  ALREADY DID, AND THAT BRANCH WAS WRITTEN FOR A DIFFERENT FRAME.** RATIFIED 2026-09-10, and it is
  **A1 missed on a security clause by the seat that keeps quoting A1.** Our F66 sub-item said a
  K-of-N-rooted credential *"cannot be classified as presented authority and falls back to the
  ambient arm — under-acceptance, not a hole."* It was a **live over-acceptance in `entity-core-go`,
  `entity-core-rust` and `entity-core-py`**, found by `go` building it. §5.5's root-granter check has
  a multi-signature branch — correct for its original purpose, a peer verifying its **own** group
  root, where the frame is the **local** peer — and `0.8.2.18` repurposed that frame to the
  **target**. Neither rule is wrong alone; **they composed into a hole.**
  **We reasoned from what the text UNDERDETERMINES to what an implementation would therefore do, and
  never opened a `verifyRootGranter`.** That inference is always unsound: an undefined case does not
  reach a well-marked "undefined" branch, it reaches whatever branch already matches, and the
  question is only ever *which existing code claims this input*. **Enforcement: a finding that says
  a spec gap is benign must cite the implementation line that makes it benign** — file and symbol,
  in at least one artifact. A claim about behaviour with no `file:line` under it is a claim about
  the text, and those two are different findings with different severities.
  **The generalizable half is arch's and it is worth carrying verbatim: changing what a shared
  parameter MEANS re-scopes every check that reads it, and those readers are listed nowhere.**
  Before repurposing a frame, a peer id, a "local" argument — enumerate its readers. Every prior
  instance in this arc was one rule with a home nobody found; this is **two correct rules whose
  composition nobody enumerated**, which is a new shape and the harder one to grep for.
  *(Two sub-lessons from answering it. **A mechanism sentence in a "transferable lesson" paragraph is
  what other implementers self-check against, so its precision is load-bearing** — arch's said the
  branch accepts a root when the frame peer is *"merely among the signers"*; `go` also requires a
  verified signature, so the real tell is a **co-signed** root, and someone testing
  listed-but-unsigned finds it correctly refused and wrongly concludes they are clean. And
  **a correction can land in the rule and miss its own restatement**: `05b7f74` fixed §1.4 in three
  lines and left §9.1's conformance floor — the section a new implementation builds from — still
  publishing the withdrawn conditional. Check the floor, the summary and the index whenever a rule
  moves; that is this file's own harden-one-anchor rule, and it caught arch the day after it caught us.)*
- **AN OPEN QUESTION IS AN UNFALSIFIABLE NEGATIVE WEARING A POLITE FACE — AND WE PUBLISHED ONE
  THAT THE SECTION OWNING THE *TYPE* HAD ANSWERED SINCE 0.8.1.** RATIFIED 2026-09-10, and it is the
  F51 class in its third shape. F51 was *"the spec does not say"*; the `HANDOFF-TO-ARCH-2026-09-04`
  pair was *"we do not find this in your corpus"*; this one is **"does rule X reach surface Y?"** —
  which reads as diligence, routes as an ask, and is the same claim about our own search.
  **F50** asked whether F40's id-scope pin reached `scope_subset`, reasoning *"F40 names
  `matches_scope` only; `scope_subset` is pattern-vs-pattern, not value-vs-pattern."* §3.6's
  id-scope grammar paragraph — **in our own pinned snapshot, four lines above the table we were
  quoting** — ends *"An implementation on the canonicalizing reading is **non-conformant** and MUST
  adopt the literal matcher."* It binds the **scope type**, not a function. There was never a
  question.
  **The mechanism is F51's exactly, one level up: we searched the vocabulary of the FUNCTION a
  prior finding named, instead of the section that owns the TYPE.** F40 said `matches_scope`, so we
  looked at call sites of `matches_scope`; the obligation is written about *id-scope patterns*, and
  a grep for the function cannot see it. **Enforcement, and it is the F51 rule with its scope
  widened again: a finding that asks whether a rule REACHES a surface must record which sections it
  read, by number — and must read the section that owns the TYPE of the thing being matched, not
  only the one that owns the function doing the matching.**
  **Two consequences worth holding separately.** (a) **The cost was mis-stated in the flattering
  direction**: we recorded the eventual fold as *creating* cohort work, when the truth is our 46
  peers were **non-conformant against the spec we are pinned to**, at `778 · 0F`, for as long as
  the grammar has existed. *"Behind a ruling"* and *"non-conformant at your own pin"* have different
  owners and different urgency, and the first is what an open question turns the second into.
  (b) **`entity-core-formalization` found it independently, graded it correctly, and got there by
  checking our PIN first** — their own finding was weaker until they confirmed the rule was in text
  we had already adopted. Recorded as corroboration with the same weight as a catch; **checking the
  receiving seat's pin before grading a divergence is a rule worth taking from them.**
- **A BOUND ON A DEFECT'S REACH CAN BE ENFORCED BY A FUNCTION'S CALLER, NOT BY THE FUNCTION — so a
  sweep over the matcher cannot find it, and a refutation built from that sweep is refuting the
  wrong input space.** Candidate (first occurrence, 2026-09-10, enforcement exact). Refuting a
  routed refutation: a sibling withdrew a published bound (*"both divergences need a leading `/`"*)
  on the witness `operations: ["*/apply"]` admitting `["compute/apply"]` — ordinary namespaced
  operation names, no leading slash, and it looks decisive. **§5.4 `canonicalize` rejects `*/`
  outright** — *"Reject bare peer wildcard — ambiguous without leading /"* — so the pattern never
  reaches a matcher under EITHER reading, and §5.4's `matches_pattern` has no interior segment
  wildcard to match it with anyway. The witness fails twice before the defect is reachable.
  **The withdrawn bound was not only correct, it was STRUCTURAL and neither side had said so:**
  `canonicalize` refuses `*/`-leading patterns by construction, so `/*/rest` is the only
  peer-wildcard form that can ever reach a matcher, and it carries the leading `/`. That is a
  theorem about the canonicalizer, not a generalization from the two rows that happened to diverge
  — which is what both the original claim and its retraction were.
  **Enforcement: when probing the reach of a defect in function `F`, enumerate what `F`'s CALLERS
  reject before `F` runs. The input space of `F` is not the input space of the system**, and a
  `#eval`-style sweep over `F` alone will manufacture witnesses that cannot occur. **And measure a
  refutation the same way you would measure a claim** — this one took lifting the peer's own
  `canonicalize`/`matches_pattern`/`scope_subset` and running five cases, three of them controls;
  the controls are what proved the instrument rather than the conclusion.
- **AUDITING OUR OWN RULING FOUND A COHORT-WIDE BYPASS IN ALL THREE GROUND-UP IMPLEMENTATIONS.**
  Recorded 2026-09-10 as the payout of the standing *"the exculpation most likely to be wrong is
  the one WE wrote"* rule, extended to rulings. We proposed γ (PD-2 gate 1a) and it was folded at
  `0.8.2.17`; auditing it three days later found that it **relocated** the handler-grant ceiling
  rather than keeping it, and that in the shape it was written for the credential is
  **caller-supplied**. Arch folded the correction as `0.8.2.19` and `entity-core-go` reports the
  bypass was *"cohort-wide — rust and py carry the identical bypass."* **A ruling you authored and
  a sibling adopted is not evidence it is right; it is three seats sharing one unexamined argument.**
  The tell to look for is a defense that bounds the wrong party — γ's was *"a caller can steer the
  handler only toward peers that have already granted this peer something,"* which bounds the
  TARGET's exposure and says nothing about the HANDLER's authority.
- **A MARKDOWN TABLE WHOSE HEADER DECLARES FEWER COLUMNS THAN ITS ROWS CARRY DROPS THE EXTRA
  COLUMNS AT RENDER — SILENTLY, IN THE CANONICAL REGISTER, FOR SIX FINDINGS AT ONCE.** RATIFIED
  2026-09-10, found while appending F63–F67 rather than by any gate. `SPEC-FINDINGS-LOG.md` —
  the file `AGENTS.md` names as canonical for every finding, and which **publishes** — carried a
  **three-column** header (`| ID | Kind | Disposition |`) over rows carrying **six** cells. Under
  GFM everything past column three is discarded, so **F54, F58, F59, F60, F61 and F62 rendered
  with their Cites, Owner and Disposition columns invisible** — the `Open — surfaced`, the asks,
  and the routing state, i.e. the entire reason a reader opens the register. This is the standing
  *"the index shipped and the evidence did not"* class reached through a **column count** instead
  of a keep-list, and it is worse in one respect: the source file is complete and correct, so
  reading it in a diff, a grep or an editor shows nothing wrong. **Only the render is lossy.**
  `F59` was separately mangled by a `` `\|| true` `` in its prose — the first pipe escaped, the
  second not — which split its last cell into three.
  **Enforcement: count UNESCAPED pipes per row and require every row to equal its header.** One
  line, and it is the whole check: `re.split(r'(?<!\\)\|', line)`.
  **Sub-lesson, and it is the examined-zero-things rule catching the instrument again: my first
  counter used `line.count('|')`, which counts ESCAPED pipes too** — so it reported F59 at 8 cells
  *after* the escaping had correctly fixed it, and I nearly "fixed" a correct line twice. A
  counter over a syntax with an escape character must model the escape. **Validate it against two
  controls before believing either direction** — `| a | b | c |` must read 3 and `| a \| b |` must
  read 1; both were run, and the second is the one that would have failed.
  *(Third thing the same session taught, and it is the false-negative class in its **flattering**
  direction at cohort scale — seventh occurrence. Surveying `scope_subset` typing by asking "does
  this peer's capability file mention `id-scope`?" returned **40 typed / 6 untyped**. False:
  the file mentions id-scope for `matches_scope`, which landed with F40, while `scope_subset`
  beside it is untyped. Truth is **0 of 20**. **The discriminator is the function SIGNATURE, not
  the file's vocabulary** — a `scope_subset` with no scope-type parameter cannot dispatch on one
  whatever its neighbours say. The H4 packaging entry records the first member that *understated*
  a capability; this one **overstates conformance**, which is the direction nobody re-checks.)*
- **RATIFIED — A COUNT INHERITS THE SHAPE OF THE SEARCH THAT PRODUCED IT, AND THE SHAPE IS INVISIBLE
  IN THE NUMBER. THREE INSTANCES IN ONE AUDIT, THREE DIFFERENT MECHANISMS, TWO SEATS — AND ONE WAS
  OURS, RELAYED VERBATIM INTO A NORMATIVE PROPOSAL.** 2026-09-11, reviewing arch's `0.8.2.20` draft.
  The false-negative family already in this file is about a search that *could not see* its target
  (a NUL byte, the wrong vocabulary, a pattern that could not span the construction). **This is its
  arithmetic half: the search saw everything it looked at, and what it looked at was the wrong
  population.** All three published as a bare integer, which is the form that carries no provenance.
  - **MEMBER OMISSION — a claim of the form *"A and B do X; C and D do Y"* over a FIVE-member cohort
    names four and leaves the fifth to be inferred.** Ours. `f68-caller-exclude-wire-census.md`
    published *"`ocaml` and `python` have no arity check … `csharp`, `typescript` count"*, and
    **the generated `go` has the identical defect** (`handlers.go:231-243` tests `len(targets)==0`
    then returns `targets[0]`). Three, not two — and the missed member is in the reproducing set,
    because the head selection is *why* it reproduces. Nobody re-read it: the sentence is
    well-formed, the four it names are correct, and the fifth is absent rather than wrong. It was
    relayed into `entity-core-protocol` `564055f` §6 and two architecture packets before being
    re-derived. **Enforcement: enumerate every member of a cohort BY NAME, including the ones the
    claim is not about.** A cohort sentence that does not sum to the roster is a defect regardless
    of whether its named members are right.
  - **LINE COUNT vs SITE COUNT, and a CROSS-REFERENCE IS NOT A RAISE.** Arch's. The proposal states
    *"`EXTENSION-ROLE` raises `malformed_resource` at five sites"*; the document contains **three**
    occurrences, of which **one** is a `return error(...)`, one is prose stating the rule, and one is
    a comparison *about a different code*. The five is a `grep -rn` returning five LINES across
    **three documents**, one of them arch's own `DESIGN-REGISTER`. **Enforcement: `grep -c` counts
    lines and `grep -o | wc -l` counts occurrences, and NEITHER counts sites** — classify each hit as
    raise / statement / citation before it becomes a number in a normative document.
  - **A SENTENCE-SHAPED SWEEP CANNOT FIND A BLOCK-SHAPED RESTATEMENT.** Arch's, and it is their own
    `L23` pointed back at them. `G4` withdraws a characterization at **three** sentences; it occurs
    at **seven** places, and the four unswept ones are §9.1 MUST Implement, **two pseudocode comments
    inside the very block that implements the rule**, the layer table, and a second occurrence on
    `G4`'s own cited line. The proposal's whole argument is that *the block is what gets implemented
    and the prose beside it is not* — and the sweep took the prose.
  **The common enforcement, and it is one line rather than three: publish the SURFACE a count ranges
  over, never the count alone** — *"N sites, in documents X/Y/Z, classified as raises"*. That is the
  `abi_differential` *"71/71 over 19 of 27 symbols"* rule generalized off harnesses and onto prose,
  and each of the three above is caught by it. **Corollary, measured twice here in one day:
  recomputing a supplied inventory is minutes and the diff is always the question worth asking** —
  arch's `22 targets[0] sites across 5 documents` recomputes to **28 across 7**, the extra two being
  `guides/`, i.e. the sweep was scoped to `specs/` while the mechanism it serves (*a function
  nameable in the pseudocode both sides copy*) lives or dies on the guides. **A scope boundary is
  the most common reason a diligent count is wrong, and it never appears in the count.**
  *(Sub-lesson, and it is the standing "check the floor, the summary and the index whenever a rule
  moves" rule recurring at the SHORTEST possible distance: §9.1's conformance floor was missed again,
  in the same arc, four commits after the seat recorded the lesson about missing §9.1. **A lesson
  written down in a status doc is not an enforcement point.** The floor is where a new implementation
  builds from, so it is the site whose staleness costs the most and the one a sweep reaches last —
  put it FIRST in the sweep order, not last.)*
- **A SWEEP MUST RUN OVER BOTH MOODS — A CALL IS WRITTEN AS PSEUDOCODE WHERE IT IS IMPLEMENTED AND AS
  PROSE WHERE IT IS OBLIGED, AND A FOLD THAT CORRECTS ONE LEAVES THE OTHER MANDATING WHAT IT NOW
  FORBIDS.** RATIFIED 2026-09-13 reviewing the `K1`–`K6` proposal — **third occurrence in one arc, and
  this one is `L23`'s mirror.** `L23` (ours, at `0.8.2.20`) was a *sentence*-shaped sweep that could
  not find a *block*-shaped restatement; here a **block-shaped sweep missed the sentence-shaped ones**.
  `K5` rules `handler_pattern` REQUIRED and names **3 of 8** three-argument call sites; of the five it
  misses, **three are normative MUSTs** (`EXTENSION-COMPUTE` `:2178` `:2196`, `EXTENSION-REVISION`
  `:3966`) that write the forbidden short form *inside the obligation*, plus a fourth pseudocode site
  in a document nobody was looking at (`EXTENSION-TRANSACTION` `:324`). **Enforcement: classify every
  hit as pseudocode / normative prose / definition / citation before it becomes a number**, and state
  the surface the count ranges over — the `abi_differential` rule, applied to a corpus.
  **AND THE ENFORCEMENT GREP THAT SHIPS WITH SUCH A SWEEP IS THE NEXT THING TO MEASURE, BECAUSE A CALL
  SITE WRAPS.** `K6`'s proposed gate — `grep -rn "check_path_permission(" | grep -v "system/tree"` —
  returns **13 hits today and ~9 post-fold against a claimed 2**: 4 of 9 sites carry the frame on the
  *continuation* line, so they fire forever **including after the fix**, and the two survivors it names
  live in a different repo than the one the command scans. **Fifth time in these two trees that a
  per-line scan has missed or manufactured a hit on a wrapped construct** (after `README.md`'s wrapped
  backtick span, `coherence-gate`'s wrapped pin clause, `link-gate`'s wrapped citation, and the
  de-versioning sweep). **Scan the JOINED text; recover the line number from the match offset** — and
  before proposing a gate, RUN it and compare the output to the postcondition you claimed, because a
  gate whose stated answer is 2 and whose real answer is 9 is switched off in a week.
- **A RULING THAT PINS ONE DISPOSITION ACROSS TWO CONFORMANT MECHANISMS RE-CREATES THE
  MECHANISM-SHAPED MUST IT JUST CORRECTED — THE STATUS CODE IS PART OF THE MECHANISM, NOT PART OF THE
  PROPERTY.** Candidate (first occurrence, 2026-09-13, `K1.7`; enforcement exact). The proposal gets
  the hard half right — *resolve authority only through a verified address*, stated as a **property**
  with two conformant mechanisms, explicitly because the mechanism-shaped wording would have specified
  the one structurally-immune seat into non-conformance — and then, **one paragraph later**, pins a
  single disposition (`AUTHZ_DENY`, with 401 declared non-conformant) for the violation. Under
  mechanism 2 (discard the key, address by validated `content_hash`) a forged **author** entry is not
  *detected* anywhere; the lookup simply **misses**, and §5.2a's landed normative table already answers
  that miss — *"Author not in envelope `included`" → **401** `authentication_failed`*, the value just
  declared non-conformant. **A uniform verdict is reachable only by mechanism 1, because mechanism 2
  has no single site to attach one to.** The general form: **when a rule admits N mechanisms, every
  observable consequence of violating it — status, code, which layer refuses — is a property of the
  mechanism unless the rule also fixes the detection point.** Enforcement: for each conformant
  mechanism named in a ruling, trace the violation through it and write down what the wire shows; if
  the answers differ, the disposition is per-site or the mechanism list is a fiction. *(Sub-lesson,
  and it is the standing "a check can pass for the wrong reason" rule from the other end: the seat
  being asked to change its status chose the auth class **deliberately**, and its own forgery test
  asserts that class specifically **in order to discriminate between two guards**. Before asking a
  seat to change a disposition, read what its test uses the disposition FOR.)*
- **THE COHORT READ AN INDICATIVE SENTENCE AS A CONSTRAINT AND THREE GROUND-UP IMPLEMENTATIONS READ IT
  AS A DESCRIPTION — AND WHICH ONE YOU ARE BUILDING DECIDES IT, NOT THE MOOD.** Recorded 2026-09-13,
  `K1` (the `included`-map-key forgery: every §5.2/§5.5 authority lookup resolves an entity **by
  wire-supplied key**, nothing bound the key to the value, so an attacker who knows a victim's identity
  hash files their own `system/peer` under it and is attributed the victim's authority). The invariant
  is stated **five times in the corpus, all indicative** (§3.1, `ENTITY-CBOR-ENCODING` §5,
  `ENTITY-NATIVE-TYPE-SYSTEM` §1057, `EXTENSION-QUERY` §473, `EXTENSION-REVISION` §938) and **never as
  an obligation** — and it was live at two of three ground-up seats. **At least 33 of our 46 peers
  already enforce it at the envelope decode boundary, most citing §3.1 in the source** (`go`
  `model.go:222` — and its `EntityOfCbor` *recomputes* the hash and trusts the recomputation over the
  carried bytes, which is the stronger property; `rust` a dedicated `IncludedKeyMismatch`; `c`/`cpp`
  *"§3.1 (N5): the included key MUST equal the entity's content_hash"*). **The reason is not that we
  are more careful: a peer generated from the schema builds a DECODER, and a decoder reads "keyed by
  content hash" as a constraint it must maintain, while a verifier built from §5.2 has no reason to
  look at §3.1 at all.** That is the sharpest argument this repo has produced for *where* an obligation
  belongs, and it is worth reaching for whenever a rule is being homed.
  **Say the limits, because this is the flattering direction and nobody re-checks those.** It is a
  **source read, not a drive** — the number is `unknown` until a probe drives it, and **the probe is
  owed** (mis-keyed `author`, `capability`, chain `granter` and `grantee` independently, positive
  control per peer). It is **one generation lineage** — 33 peers agreeing is cohort-consistent; the
  honest comparison is four lineages against three, not thirty-six against three. **And the survey
  under-reported itself three times in one sitting** — keyed first on filenames we chose (missed 14),
  then on one phrasing of the error string (missed 6), then on a second phrasing, because `c` and `cpp`
  write *"MUST equal"* where everyone else writes `!=`. **Every pass printed a confident
  classification**, which is the false-negative family's arithmetic half arriving three times in an
  hour: the 10 still-unclassified peers are *"could not look"*, not *"absent"*.
- **WHEN A FIND-RATE STAYS FLAT ACROSS MANY FOLDS, STOP LOOKING FOR THE NEXT DEFECT AND ENUMERATE
  THE DECISION SPACE — THE RECURRING FINDING IS THE ABSENCE OF THE ENUMERATION, NOT N DEFECTS.**
  Candidate (first occurrence, 2026-09-12, `tools/scope-cell-table.py` +
  `shared/findings/scope-algebra-cell-census.md`; enforcement exact). Twenty-one `0.8.2.x`
  revisions in twelve days moved almost nothing but ten functions of the §5 scope algebra, and
  every finding across four seats had one of three shapes: *this cell says A here and B there* ·
  *this cell is unreachable* · *the sweep covered 3 of 7 sites*. Enumerated from the pseudocode:
  **146 live cells, 37 with a named vector**, and **every finding of the arc landed in a
  zero-coverage region** — while **F40, the one cell family that got vectors, is the one that
  closed and stayed closed.** That correlation is the diagnosis, and unlike *"the find-rate is the
  instrument, not the disease"* (true when written for newly-instrumented OLD surfaces, carried
  four weeks past its evidence onto text the cycle itself authored) **it is falsifiable**: the
  census publishes the prediction that the next finding lands in one of its four zeros.
  **Three things generalize past this arc.**
  - **THE REDUCTION IS THE VALUABLE HALF, NOT THE COUNT.** A naive product said 640; the space is
    146, and the single biggest factor is that **scope type is FIXED by the dimension and is not a
    free axis** (−320). Enumerating forces you to find that out. And the residual −126 named the
    *generator* in one sentence — `resources` is the only dimension whose subject is a
    set-with-exclusions rather than a value — which is what makes the next revision able to
    predict where it will need to look instead of discovering it.
  - **A COVERAGE TABLE MAPPED BY NAME FAILS IN BOTH DIRECTIONS FROM ONE MIS-ASSIGNMENT.** Filing
    `chain_parent_exclude_drop_denied` under the L1 caller-exclude arm (it drives the L3 delegation
    link) simultaneously reported a **false ZERO** on exclude-inheritance and a **false COVER** on
    the F68 arm. So a coverage claim is `unknown` until a harness drives it — the standing rule —
    and the cells that survive being wrong about the mapping are the ones worth publishing: here
    the four zeros hold either way, because no check in the set names that layer or dimension *at
    all*.
  - **THE INSTRUMENT NEEDED THE EXAMINED-ZERO-THINGS RULE TWICE IN ONE SITTING, AND ONLY THE
    PRINTED COUNTS CAUGHT IT.** The first cut reported `structurally dead 0` from two classifier
    branches that could not fire (the space already excluded them by construction — better design,
    dishonest reporting). The reduction rows then summed to 172 against an enumeration of 146.
    **Fix both the same way: stage each reduction from the one above and ASSERT CLOSURE, plus a
    non-zero assertion per stage** — a reduction that stops removing anything is a rule the code no
    longer implements, sitting there reading as load-bearing.
  **And the finding it surfaced is the shape to expect from this method: `matches_scope` dispatches
  on a `scope.type` read off the RECEIVED ENTITY while all 46 peers supply it from the call site,
  and nothing validates that value against the dimension anywhere** (§6.3, M3,
  `verify_capability_chain` and §5.6's relative child-vs-parent check all read, not assumed) — **F72,
  cohort cost zero.** Four seats reviewing §5 for twelve days could not see it because **the two
  readings agree on every well-typed grant**; only a table that asks each cell *what decides this,
  and who supplies it* separates them. **A defect invisible to every reading is visible to an
  enumeration, and that is the whole argument for building one.**
  - **A section headed "Current state" was anchored to a pin retired three flips earlier**
    (`CONFORMANCE-MATRIX.md` §4, `2026-08-30 @ the 755-check pin`, while §1 published `778`).
    `coherence-gate` is scoped to §1's rows and the 46 per-peer banners, so §2–§4 prose can go
    stale with every gate green. The table's contents were still TRUE — they record when each tier
    FIRST closed — so the fix is to say which question the table answers, not to back-date it.
  - **A HANDOFF-FROM-ARCH doc HAS NEVER EXISTED — `git log --all` on it is empty — and it was
    cited from `protocol-generator/shared/lifecycle/PROMPT-CONSTANTS.md`, which PUBLISHES.** Both
    link-gate checks are structurally blind to it: check 1 resolves markdown links in the
    bracket-then-parenthesis form and this is a **backticked inline path**, check 2 fires on
    non-prose citations only. **[ADR-0021]'s own
    follow-up list names it** — *"keystone HANDOFF-FROM-ARCH-v1 → non-HANDOFF name"* — having
    assumed it existed and needed renaming off a scrubbed prefix. It did not need renaming; it
    needed deleting, and the sentence it anchored was redundant with line 31 of its own file.
  **Three things generalize, and the second is a correction of this entry's own first draft.**
  (a) **A dangler that never existed cannot be found by any diff, any rename sweep, or any tool
  that reasons from history — only by resolving the path.**
  (b) **THE OBVIOUS GATE DOES NOT SURVIVE THE TREE, AND MEASURING IT IS WHAT SAID SO.** This entry
  first prescribed "harvest every backticked `.md` and stat it" as a link-gate check 3. Measured:
  **863 candidates → 318 unresolved**, because root-relative shorthand (`status/PHASE-S2.md` means
  *this peer's*) is correct prose and unresolvable by construction; scoping to repo-rooted paths
  gives **418 → 38**, and even those carry an irreducible ambiguity because **`docs/` is a top-level
  directory here AND in every sibling**, so the generator's `docs/spec/…` is indistinguishable from
  ours by path alone. That is the standing *"a check that cannot separate its signal from its noise
  is broken, not weak — scope it or drop it, and say which"* rule applied to a gate **I had already
  written into this file**. It ships as a probe with its triage in its own docstring
  (`shared/diagnostics/backticked-path-resolution-probe.py`), not as an eleventh-and-a-half gate.
  (c) **THE DISCRIMINATOR IS NOT "DOES IT RESOLVE" — IT IS LIVE INSTRUCTION vs PROVENANCE.** Of the
  38, one was a live instruction (*"escalate per `X`"*) and was fixed; **~15 are `research/RELEASE-
  READINESS.md`, a peer-selection slate that also never existed here**, cited by four peers' dated
  phase records — and those were deliberately NOT rewritten, because a dated snapshot that gets
  back-edited stops being evidence of anything. Sweeping the two together would have destroyed
  fifteen records to fix one pointer. **Fix what points a reader somewhere on purpose; leave what
  records what was believed on a date.**
  (d) **An ADR follow-up item is a claim about the tree with no gate on it** — this one was wrong
  about the defect's nature for two months and nothing re-read it. When an ADR names a known defect
  in your repo, resolve it or record why it is still open; an unactioned follow-up reads as tracked
  and is not.
- **NO GATE ASKS WHETHER THE PUBLISHED TREE IS INTERNALLY COHERENT — and every defect this
  release cycle was found by walking it by hand.** Ratified 2026-08-23 (arrived as the one habit
  the release earned, and it is now ours because we are the repo it kept finding things in).
  The six release gates ask six different questions — is it safe (`leak-audit`), does it conform
  (`conform-audit`), does it build, is the identity right, did anything vanish
  (`public-regress`), is the promotion text clean — and **none of them asks whether a published
  document points at something a reader can open.** Neither do ours: `check-set-gate.py` checks
  that numbers are comparable, `pin-gate.py` that anchors resolve, `tier-status.py` that M1 is
  current. All three would pass a tree in which every internal link is broken.
  **The measured yield of one hand-walk, this session:** a README contradicting itself two lines
  apart (13 publishable, "binds 40"); four runtime-referenced diagnostics deleted at release; 23
  findings whose index published and whose evidence did not; two internal-token leaks; **and one
  nobody had routed** — `protocol-generator/fortran/status/` cited two findings at
  `research/stewardship/HANDOFF-TO-ARCH-*.md` paths that had not existed since those findings were
  archived weeks earlier, dangling from a *published* file the whole time.
  **Budget the pass; it is not optional and it is not automated.** Cheap partial enforcement that
  is worth having anyway: resolve every relative markdown link in the tree against disk
  (`\[[^\]]*\]\(([^)#\s]+)\)` → `(referrer.parent / target).exists()`) — it is ~20 lines, it runs
  in a second, and it would have caught the fortran dangler and every link the findings move
  broke. It does **not** catch inline-code paths in backticks, prose fragments, or a path printed
  by a tool at runtime, which is why the hand-walk stays.
- **AN ENV OVERRIDE DROPPED AT A CONTAINER BOUNDARY PRODUCES A SUCCESSFUL RUN AND A WRONG-SHAPED
  ARTIFACT — the discriminator is the OUTPUT SHAPE, never the exit code.** RATIFIED 2026-09-06,
  found by driving a probe across the whole roster for the first time (`tools/put-probe`, §6.3's
  put-admission census). **Eight of 46 peers silently ran the REAL validator** and wrote a perfectly
  good 758-check conformance report where a probe report was expected. Nothing failed: the run exits
  0, the file exists, `check-set-gate` would have been happy with it, and the only thing that says
  the measurement never happened is that the JSON has a `checks` key instead of a `cases` key.
  **The claim that said otherwise was ours, in the tree, and it was a source read wearing a
  measurement's clothes.** `run-cohort-census.sh` carried *"(Checked across all 46: only these
  two.)"* beside a `lean`/`unison` special case. That is the standing false-negative class — sixth
  occurrence, after the `dart`/`ruby` NUL byte, F51's wrong vocabulary, the de-versioning sweep's
  un-spannable pattern, the `host.err` right-token-wrong-branch, and the H4 packaging survey keyed on
  a self-authored filename list. **Enforcement, and it is one line rather than a grep: classify the
  ARTIFACT, not the source.** A conformance report sitting in the probe directory *is* a dropped
  `ORACLE`, and that check is indifferent to how many ways a harness can drop one.
  **TWO CAUSES, AND A SURVEY THAT FINDS ONE MISSES THE OTHER.** Five were self-relaunching harnesses
  (`forth fortran oz rexx smalltalk`) that `exec podman run` and forward nothing — so their own
  header's *"ORACLE/PORT/NOBUILD/VALIDATE env overrides"* line had been false for as long as it had
  existed. Three were hand-written branches **in the census itself** (`prolog rust-wasm
  rust-wasm-wasmtime`) predating `run_podman`'s `${ORACLE:+...}`. `apl` `lean` `unison` carry the
  same harness defect and were masked because the census happens to enter their containers directly.
  Fixed at the SOURCE — all eight harnesses forward their own documented overrides — which also
  **closes the carried `JSON_OUT`-not-forwarded-through-`lean` item**, where the documented escape
  hatch was dropped and a bare run therefore wrote the TRACKED report. Same defect, different
  variable, already on the list.
  **`${VAR:+-e VAR="$VAR"}`, never `-e VAR=${VAR:-default}`** — the second form SETS policy while
  appearing to forward it, which is the `cobol` `run-s4-host.sh` defect this file already records.
  **Verify a forwarding fix in BOTH directions or it is unmeasured:** the probe direction (6 of the 8
  now produce probe reports) says the variable arrives; only the conformance direction says the edit
  changed nothing — `lean` and `smalltalk` re-measured through the edited harnesses reproduced their
  committed reports at **exactly 0 of 758** severities different.
  *(Sub-lesson, and it is the examined-zero-things class inside the fix itself: **`[ -x <directory> ]`
  is TRUE.** The guard added to reject a missing probe binary was `[ -x "$dir/$PROBE" ]`, and with
  `$PROBE` empty — it was unexported and `census_one` runs under `xargs bash -c`, so only exported
  vars survive — it tested the DIRECTORY and passed. Every peer was then handed
  `ORACLE=/work/output/s4-oracles/` and died with `Is a directory`. The guard written to catch a
  missing name passed vacuously on the emptiest possible name; it is `-n` and `-f` and `-x` now.)*
- **A PROBE THAT FORWARDS MATERIAL IT DID NOT AUTHOR MUST VERIFY THAT MATERIAL AGAINST ITS OWN KEY,
  OR A SLICING BUG AND A PEER DEFECT ARE THE SAME OBSERVATION.** Candidate (first occurrence,
  enforcement exact). `put-probe` must replay the handshake's capability material verbatim on every
  authenticated EXECUTE — §5.2 step 3 resolves the cap out of that map — so it slices raw byte spans
  out of the response rather than re-encoding a decoded structure, because a one-byte difference
  changes a content hash and an unverifiable capability looks exactly like a peer that refuses.
  **The span arithmetic is then unfalsifiable from the outside**: five peers refused or dropped the
  probe's valid `put`, and "my slicing is wrong" and "these five peers are strict" predict the
  identical output. The self-check re-decodes every forwarded entry and re-hashes its `{type, data}`
  against the map key it is filed under (§3.1 requires them equal); it reports **0 of 4 bad on every
  peer**. **Generalize: whenever a harness replays bytes it received, assert the invariant the
  sender was obliged to satisfy — the assertion costs ten lines and converts an unfalsifiable
  suspicion into a measurement.**
  **RATIFIED AND CORRECTED 2026-09-07 — this entry used to end that sentence with *"and THAT is
  what licenses reporting the five as a peer-side observation instead of a probe bug."* It licensed
  no such thing, and the five were the probe.** `authedExecute` unions the probe's own peer entity
  into the forwarded `included` map, which already contains it (the probe IS the grantee), and the
  encoder sorted map keys **without deduplicating** — so every authenticated frame carried the same
  byte-string key twice, which is not canonical ECF at all. `csharp` refused the whole frame in
  strict CTAP2 mode on **every** case including the positive control; `typescript`/`node-red`
  dropped it silently.
  **AN INVARIANT CHECK LICENSES EXACTLY THE INVARIANT IT CHECKS.** The self-check verified that
  each forwarded entry AGREES WITH its key and said nothing about the keys being UNIQUE — and the
  fault was a duplicate key. Offering a narrow check as general assurance is how a probe fault gets
  published as a cohort finding about five peers, in a document whose own section title was *"and
  the probe is not the reason"*.
  **The peer that caught it is the peer we published as broken, and its refusal named the wrong
  cause** (`400 non_canonical_ecf — "CBOR tags are forbidden"`, one code and one message standing in
  for several canonicalization branches), which is what made a fault of ours look like a defect of
  theirs wearing their own error code. **When ONE peer of a cohort refuses what the others accept,
  the prior belongs on the instrument, not on the peer** — the strict one is the one telling you
  something. **Enforcement: the encoder deduplicates by construction (a map HAS unique keys) and
  reports the dropped count per peer, so the dedup can never be silent; and a probe's diagnosis of a
  refusing peer is not final until the peer's OWN error path has been read.** It took one
  three-line stderr print in `csharp`'s decode-refusal catch to turn "these five peers are strict"
  into `CborContentException: does not support duplicate keys`.
  **And the POSITIVE control caught two probe faults before either could become a cohort finding**,
  which is the p47 lesson paying out on its second instrument: a stray decode call left the
  forwarded material silently empty (`403 capability_denied`), and then a `system/peer` entity
  carrying `peer_id` in its hashable basis produced `401 unresolvable_grantee`. **§3.5 (v7.65) says
  `peer_id` MUST NOT be in that basis; §4.6's own pseudocode still shows the pre-v7.65 three-field
  form**, and the probe had been written against the pseudocode. Both would have published as
  cohort-wide defects. **A wire probe's first two runs are about the probe.**
- **AN ACCEPT-SIDE RULE IS NEW IMPLEMENTATION ON EVERY PEER, AND THE PEERS WHOSE `put` "WORKED"
  WERE THE ONES AUTHORING THE SUBMITTER'S CONTENT.** RATIFIED 2026-09-07, §6.3's `0.8.2.11` put
  admission ladder landed on all 46 peers (`shared/findings/put-admission-wire-census.md`). Arch's
  instruction — *"do not size the work from the assumption that they are conformant and this is a
  re-vendor"* — was right and the measurement was the maximum bad case: **0 of 46 implemented any
  row**; **36 accepted a two-key `{type, data}` submission and STORED it**, holding an entity under
  a hash nobody supplied; **10 bound a path to content that did not hash to the hash they were
  given** (a §1.8 failure the code table does not touch). Final shape: **+4,201 / −128 across 56
  files**, one ladder authored from the spec and propagated, 46 of 46 at 6 of 6.
  **Three things generalize past this rule.**
  - **The ladder had to REMOVE adjacent defects rather than sit beside them, and each was a
    DEFAULT or a FALLBACK doing authoring work.** `sql` defaulted an absent `type` to
    `"primitive/any"` — storing an entity under a type the submitter never sent, the same class as
    authoring its hash, one field over. `ada` and `datalog` treated a present-but-MALFORMED entity
    as the §6.3 REMOVAL case and **unbound the path**: a destructive reading of a value the spec
    says to refuse. Enforcement: on any receipt path, grep for a default applied to a field the
    submitter is required to supply, and check that the delete arm is `absent OR null` and not
    `absent OR unparseable`.
  - **A CONSTRUCTOR THAT COMPUTES IS THE DEFECT; NAME THE RECEIPT CONSTRUCTOR AND SAY WHERE IT MAY
    BE CALLED FROM.** Peers whose entity type only had an authoring constructor gained one
    (`Entity.admitted` / `ent-admitted` / `Ent_Admitted` / `admittedType:data:hash:`) whose doc
    comment states it is reachable only from the ladder that just verified those bytes. Where an
    existing `of_cbor`/`from_cbor` already recomputed and refused on a carried mismatch, step 2
    routes through it — **verifying is the opposite of authoring, and reusing the verifier is
    cheaper and safer than a second comparison.**
  - **NAME THE CODES A PEER CAN VERIFY, NOT THE CODES ITS CONSTRUCTION PATH WILL SERIALISE.** Every
    peer's `hashDigestLen` is its own: a fixed 33-byte hash field (`c` `cpp` `fortran` + the ISA
    trio) or a SHA-256-only primitive means `0x00` alone. So the SAME input answers
    `unsupported_content_hash_format` on different codes on different peers — which is the honest
    answer, and copying one peer's table across the cohort would have been a claim none of them
    could keep. This is §4.7's construction-vs-verification asymmetry as a per-peer fact.
- **A PREDICATE TEST BUILT ONLY FROM DENY CASES IS INDISTINGUISHABLE FROM ONE ASSERTING
  `False == False` — AND THE FIXTURE IS WHERE IT BREAKS, NOT THE PREDICATE.** Candidate
  (2026-09-07, `python` H9; the examined-zero-things class reaching a *test* rather than a gate,
  and the enforcement point is exact). `check_path_permission` shipped with one accept case and
  three deny cases, one per scope dimension. The grant fixture wrapped each grant in
  `Entity.make(...).to_cbor()` where `GrantRec` reads a **plain dict**, so every scope parsed
  **empty**, the function denied everything, and **all three deny controls passed.** Only the
  accept case saw it. **Rule: every authorization/predicate test needs at least one ACCEPT
  assertion, and it is the one that validates the FIXTURE** — the deny cases validate only that
  the function can say no, which a broken fixture guarantees for free. Corollary for the deny side:
  one deny case per DIMENSION, because a single deny cannot distinguish "the predicate checks the
  dimension I care about" from "the predicate denies".
  **THE SAME SESSION'S SIBLING, and it is about the SHAPE OF THE HARNESS rather than the fixture:
  a test of "whose identity is this" must be driven from a SECOND peer, or it passes against the
  fabricated value.** H8's defect is that a tree-change event with no execution context is
  indistinguishable from an AUTONOMOUS write, so a recorder fills in `EXTENSION-HISTORY` §2.1's
  autonomous reading — author = the LOCAL peer — and attributes a remote caller's write to itself.
  On a single-peer test the caller and the local peer **are the same identity**, so the fabricated
  value and the correct value are the same bytes and every assertion passes. The test therefore
  asserts `author == initiator.identityHash` **and** `author != responder.identityHash` over real
  loopback. Generalise: **whenever the defect is a value being DEFAULTED to something plausible,
  the control is an input for which the default and the truth differ** — and if your harness cannot
  produce such an input, the harness is the thing to fix, not the assertion.
  *(Both were then planted — revert the context at the write site, reassert — and each plant
  reddened exactly its own test while leaving the companion control green. Two plants on disjoint
  checks is what says the arms are independently measured rather than one carrying the other.)*
- **A GATE THAT PROVES EVERY WRITE AND NEVER READS BACK THROUGH THE SURFACE UNDER TEST HAS MEASURED
  HALF A FEATURE — and the missing half is the half the feature is FOR.** RATIFIED 2026-09-09 (F62),
  and it is FM-1g's *"a MUST with roughly no gate"* reached from the coverage side rather than the
  spec side. `core_register_*` is **nine** checks: op status, op result, manifest at path, handler at
  path (asserting the entity's TYPE), grant at path, grant-signature at the invariant path, and the
  unregister teardown. Every one is a write. **Not one then dispatches at the pattern it just proved
  exists** — so seven peers score `778 · 0F` while answering `404 handler_not_found` at a path where
  a `system/handler` entity is provably present, which §6.6 makes a **MUST** (*"the index MUST produce
  equivalent results to the tree walk"*). The two neighbouring checks that look like they cover it are
  pointed elsewhere, verified rather than assumed: `unsupported_operation_on_registered_handler`
  targets `system/tree`, a **bootstrap** handler, and `validate_echo_dispatch` drives a built-in.
  **Enforcement, and it is a question to ask of any gate family rather than a grep: list what the
  checks ASSERT and sort them into writes and reads. A family that is all writes is a family that has
  never used the thing it built.** The read-back is usually one line at the end of the gate that
  already holds the pattern, the grant and the connection.
- **A CENSUS FIELD THAT NAMES THE WRONG RUNG PRODUCES A SCOPE ESTIMATE THAT IS WRONG IN THE
  EXPENSIVE DIRECTION — AND THE FIELD THAT MISLED US IS THE ONE BUILT TO PREVENT EXACTLY THIS.**
  RATIFIED 2026-09-09, closing F62's remaining six. The finding sized them as one repair —
  *"they need a container the wire register can write before they can have an index at all"* —
  and that was **true of three and false of three**: `cobol`, `fortran` and `forth` were
  ALREADY walking the entity tree at §6.6, correctly, and the `404` came from the rung
  **below** resolution, where a body-selection ladder spelled *"I resolved this and have no
  body"* as `handler_not_found`. One arm each. The estimate came from the finding's own
  evidence table, which was built from each peer's H5 `dispatch_read_site` — and on those three
  that field named the **ladder**, not the resolution site. `dispatch_read_site` exists
  *precisely* to tell a live host from a dead map (it is the field the four wrongly-nominated
  hosts taught us to add), and it mis-scoped a repair by naming the second rung of a
  two-rung mechanism.
  **This is the standing "TWO SITES FOR ONE REFUSAL" rule reaching the CENSUS rather than the
  fix.** There the repair went to the unreachable site and measured as a no-op; here the
  *measurement* recorded the wrong site and the no-op was in the plan. **Enforcement: for any
  mechanism that resolves and then selects, the census field names BOTH rungs and says which
  one answered the observed status.** The one-line form — `resolve X (§6.6 walk, file:line);
  the ladder below it is BODY SELECTION, file:line` — is what all six now carry, and it is what
  makes the next reader's estimate right.
  **AND A WALK CAN BE CORRECT AND QUERY A KEY SPACE NOTHING ELSE WRITES.** `forth`'s
  `resolve-handler` was a faithful §6.6 backward walk over the store and was structurally blind
  to every wire write: `register-handler` bound its bootstrap `system/handler` entity at the
  **bare pattern** while `publish-handler-dispatch`, the §6.2 register op and every validator
  `TreeGet` use `/<local>/<pattern>`. Two key spaces for one fact, so §6.6 equivalence had
  nothing to be equivalent TO — and **reading the walk clears the peer**, because the walk is
  right. **Enforcement: for any store-backed resolution, enumerate every WRITE site's key form
  and require exactly one.** `git grep` the bind calls, not the lookup.
  **THE PLANT IS WHERE THAT SHOWS UP, AND A PLANT THAT BREAKS THE PEER HAS NOT DEMONSTRATED THE
  DEFECT.** Reverting only `forth`'s walk — leaving the canonical bootstrap bind — made every
  built-in unresolvable: positive control `404`, verdict `UNTRUSTED`, no case executed. That is
  a red, and it proves nothing about the repair. **Rule: a mutation control must reproduce the
  ORIGINAL symptom with the positive control still green.** If the positive control fails, the
  plant is too broad; widen the revert to the whole change and re-run (both halves back to the
  bare key → `NOT-RESOLVED`, which is the pre-fix peer exactly). The failed plant is worth
  recording rather than discarding — it is the cheapest proof that two edits are one change.
  *(Sub-lesson, and it is the examined-zero-things rule catching the person who keeps citing it:
  the script written to prove "0 severities moved" first printed **`0 of 0`**, because it read a
  `categories/checks` shape these reports do not have. **The denominator is the only reason that
  was visible.** Print the count AND assert it non-zero, in a throwaway diff script as much as in
  a gate.)*
- **THE COHORT IS THE INSTRUMENT THAT SEPARATES TWO CAUSES ONE PEER CANNOT DISTINGUISH — 404 AND 501
  AT THE SAME STEP ARE DIFFERENT DEFECTS, AND ONLY THE SPLIT SAYS SO.** Same finding, and it is the
  standing *"where a single peer cannot distinguish 'this peer is broken' from 'our request was', the
  verdict must defer to the cohort"* rule earning a second, sharper form. From one peer, a dispatch
  that fails after a successful register is just a failure. Across 46: **26 answer 200** (resolution +
  evaluation), **12 answer 501** — which *proves resolution succeeded* and the body could not run —
  and **7 answer 404**, which proves resolution never found what register wrote. The 501 group is what
  makes the 404 group a **§6.6 core** finding rather than a **§6.13(a) extension** one, and no amount
  of staring at any single peer produces that distinction. **Rule: before classifying a failure, ask
  what the OTHER answer to the same step would have meant, and check whether any peer gives it.**
- **A SOURCE TRACE ACROSS SEVEN PEERS PRODUCED A CONFIDENT WRONG CONCLUSION, AND THE SPEC SECTION THAT
  OWNS THE BEHAVIOUR REVERSED IT IN ONE READ.** Same session, and it is the F51 rule paying out in the
  *positive* direction for once. Tracing all seven `NOT-RESOLVED` peers showed dispatch resolving
  through a static op ladder, a pattern ladder or a bootstrap-only table, and **none of the seven
  mentions `expression_path` anywhere in its source** — from which the obvious conclusion is *"a
  missing extension feature, not a defect; the previous session's ranking was wrong."* That was drafted.
  Then §6.6 was actually opened: the walk is the definition, the index is the optimisation, and
  equivalence is a MUST. **The peers are failing a core requirement, the previous session's ranking was
  RIGHT, and the draft was one section away from publishing the opposite.** The cost of reading it was
  one `awk`. **Rule, and it is the cheap direction of the F51 lesson: before concluding that a measured
  behaviour is permitted, read the section that OWNS it — not the section your hypothesis is phrased
  in.** A source trace tells you what the code does; only the spec says whether it may.
- **A SHARED BUILD ARTIFACT IS NOT YOURS TO SWAP — AND `Text file busy` IS LUCK, NOT AN INTERLOCK.**
  Candidate (first occurrence, 2026-09-09, `tools/p47-run.sh`; enforcement exact). The p47 wrapper
  installs its probe **over** `output/s4-oracles/validate-peer` for the duration of a run, backs the
  real binary up, restores it on trap and verifies by hash — careful, documented, and built on one
  unstated assumption: that this repo is the only consumer of that path. It is not.
  **`entity-system-generator` invokes `<keystone>/output/s4-oracles/validate-peer` BY PATH from its
  own tree**, and one of its `--profile core` runs was live when the swap was attempted. What stopped
  it was `cp` answering **`Text file busy`** — the kernel refusing to write a *running* executable.
  **Had that seat been BETWEEN invocations, the copy would have succeeded**, their next run would have
  executed our probe, and it would have written a probe report where a conformance report was expected
  — the exact defect `p47-run.sh`'s own header describes, inflicted on a repo whose owners have no
  reason to look for it. The failure was also invisible from our side: the trap reported *"validator
  restored and hash-verified"*, which was TRUE (nothing was ever overwritten) while the restore's own
  `cp` had failed the same way and left the backup in place as a poison pill for the next run.
  **Enforcement: refuse to start while any process holds the artifact**, scanning `/proc/*/cmdline`
  and matching **`argv[0]` only** — a shell wrapper whose command line merely *contains* the path is
  not a holder, which is the standing `pgrep -f` trap (the pattern is in the watcher's own command
  line) reached from a second direction. Both directions exercised: the guard names the holding pid
  while a sibling's run is live, reports nothing for a path nobody holds, and does not match the
  watcher.
  **SUPERSEDED THE NEXT DAY BY THE BETTER FIX, AND THE ORDER IS THE LESSON: A GUARD ON A HAZARDOUS
  MECHANISM IS NOT THE SAME QUESTION AS WHETHER THE MECHANISM IS STILL NEEDED, AND NOBODY ASKS THE
  SECOND ONE AFTER SHIPPING THE FIRST.** `tools/p47-run.sh` is **deleted** (2026-09-09). The swap
  existed for one reason, stated in its own header: eight harnesses dropped an `ORACLE=` override at
  their container boundary. **Those eight were fixed at source on 2026-09-06** — recorded in this
  file, in the entry above — so the wrapper had been unnecessary for three days when the guard was
  written for it, and the guard is a careful control on a mechanism that no longer had a reason to
  exist. Measured before deleting, never assumed: the whole 46-peer roster driven through the plain
  `--probe` route produced **46 of 46 probe-shaped outputs**, with the two failure classes the swap
  was built for (`forth` self-relaunching, `prolog` a hand-written census branch) driven first, and a
  both-routes control on one peer confirming the route does not change the answer. **Ask whether the
  dangerous step is still load-bearing before you harden it** — the fix that removes a hazard beats
  the fix that guards it, and a header explaining *why* a mechanism exists is the thing to re-read
  when its justification has been repaired elsewhere.
  *(Two more defects fell out of retiring it, both the never-executed class: its documented per-peer
  form `p47-run.sh <peer>` had **never worked** — `--probe` takes an optional NAME, so the peer name
  was consumed as the probe name — and the holder guard is **start-only**, fine for the two-minute
  single-peer run it was tested on and not for the ~90-minute roster run. A guard that samples once
  at t=0 is not a lock, and the run length is what decides whether that matters.)* **Generalize: before a tool mutates a file under `output/`, ask which OTHER repos reference
  that path** — `git grep` in the siblings, not in your own tree — because the cross-repo consumer is
  invisible to every check you run locally.
- **A PIN IS A CLAIM, AND THE SENTENCE THAT STATES IT ROTS WHILE EVERY GATED NUMBER STAYS CORRECT.**
  RATIFIED 2026-09-09 (fifth occurrence of the stale-input class, and the first where the stale thing
  is the *anchor statement* rather than a report, an overlay or a build artifact). With **thirteen
  gates green**, five live sites in four published files named a RETIRED `core_executed_check_set_digest`
  in the present tense: **`README.md` twice — the front door, two flips stale**; `CONFORMANCE-MATRIX.md`
  footnote ², which defines what every cell in §1 MEANS, **three** flips behind; `docs/STATUS.md`;
  `docs/PROGRAM.md`; plus `AGENTS.md` itself and, worst, `PROGRAM.md`'s *"Disclosed gaps behind a
  0-FAIL row: **none** — the skip-provenance allowlist is empty"* published **one day after 46 F59
  entries went into that allowlist**. §1's 46 rows and the 46 per-peer banners were correct throughout,
  **which is precisely why nothing caught it** — `coherence-gate` is scoped to exactly those two
  surfaces.
  **The rule: for every number you gate, gate the sentence that says WHICH PIN it was measured at.**
  `coherence-gate` check 6 does it — in a live PARAGRAPH carrying a pin phrase, every digest and every
  `NNN-check` total must be the current one from `oracle-pin.env` — with four escape hatches so naming
  a retired pin stays cheap (a date within 80 characters, a `retired`/`superseded`/`then-current`/
  `first closed` marker, a `"quotation"` of former text, or a struck/✅ line).
  **Two method notes, both of which cost time here.** (a) **PER-LINE IS THE WRONG UNIT, for the fourth
  time in this file.** The clause that retires a pin *wraps*, so a per-line scan reads the marker and
  the value it governs as unrelated and fires on a correct sentence. Scan paragraphs and recover the
  line number from the offset — but **break the paragraph at list items, table rows and headings**, or
  one bullet naming the current pin puts the whole list in scope and a bullet nine items down
  recounting a 2026-08-28 measurement fires. Moving from lines to paragraphs took the check from 95 to
  **114** statements examined and the 19 it gained held two real defects. (b) **Assert the count, then
  distrust it in both directions**: an over-broad phrase list (`pinned\b`) took it to 776 statements
  and produced false positives on dated history, and the narrow list that fixed that had to be widened
  again — `pinned snapshot`, `NNN-check pin` — because the two real defects used forms the first list
  did not contain. A phrase list is a survey keyed on words you wrote down, so measure what it sees.

- **A GATE THAT EXAMINES ZERO THINGS PRINTS THE SAME WORD AS ONE THAT EXAMINES FORTY-SIX —
  always print the COUNT, and assert on it in the regression suite.** RATIFIED 2026-08-30
  (second occurrence of the vacuous-control class after `check-set-gate`'s `Path.stem`
  collision, which keyed 45 reports into one dict entry and would have "passed" having read a
  single file). Building `tools/coherence-gate.py`, its per-peer banner check searched for the
  compact `NNNP/NNW/NF/NNNS` form; the banners spell the same figures longhand
  (`755 total · 312 pass · 337 warn · 0 FAIL · 106 skip`), so the pattern matched **nothing**,
  every peer was `continue`d, and the gate printed *"OK — 46 §1 rows and **0** peer banners
  agree"*. **The only reason it was caught is that the line printed the number.** Reading the
  code would not have found it; the code is correct, it is the pattern that was wrong.
  **Enforcement, and it is one line in the self-test:** assert the count equals the population
  (`n_banners == len(peers)`), not merely that the error list is empty. An empty error list is
  the expected output of both a passing check and an absent one.
  **THIRD AND FOURTH OCCURRENCE 2026-09-02, both in PEER GATES rather than repo tooling, and the
  fix is the same one line in each.** `swift/run-s2.sh` ran `swift test` and trusted its exit
  code, which is 0 for a suite that executed 35 cases and for one that executed none — a dropped
  test file or a mis-declared target leaves it green. `smalltalk`'s `st_suite` grepped
  `failures=0 errors=0`, and an **empty** SUnit suite reports exactly that (`runs=0 passes=0
  failures=0 errors=0`), so a `buildSuite` over a class whose methods failed to compile passes
  perfectly. Both now assert the count — an XCTest floor (`SWIFT_TEST_FLOOR`, currently 35) and
  `runs=[1-9]` — and both were regression-tested by planting: floor raised above reality → exit 1;
  a synthetic `runs=0` line → rejected by the new pattern and accepted by the old one.
  **Generalise to every peer gate, not just the repo's own tooling: if a gate's success message
  does not contain a number, it cannot distinguish "all green" from "nothing ran."**
  **FIFTH, SIXTH AND SEVENTH OCCURRENCE 2026-09-09 — IN THE SAME FILE AS THE FOURTH, AND THE FIX
  FOR THE FOURTH DESCRIBES THEM IN ITS OWN COMMENT.** `smalltalk`'s `sunit` was fixed on 2026-09-02
  and its comment says, in these words, that *"`pharo eval` exits 0 whatever the suite reports, so a
  red suite printed `failures=3` and the target passed."* **Three sibling targets in the same
  Makefile had the identical defect and kept it**: `conformance`, `int-boundary` and `crypto-accept`
  each END by printing their own verdict (`=== crypto-accept: FAILED (1) ===`) and **nothing read
  it** — so three of the four members of that peer's own `gate` target could not go red. Measured
  rather than reasoned about: a planted bad SHA-256 KAT made the driver print `FAILED (1)` while
  `make crypto-accept` exited **0**.
  **This is the standing "harden one anchor, check its siblings the SAME DAY" rule failing at the
  shortest possible distance — the siblings were adjacent recipes in the file being edited — and
  what makes it worth a numbered entry is that the fix WROTE DOWN the class and still did not
  sweep it.** A comment explaining why a gate was unsound is a description of a defect class, not a
  record that the class was eliminated; the next reader (me) treated it as the latter for a week.
  **Enforcement, and it is a question rather than a grep: when a gate is fixed, list every OTHER
  target in the same file that ends in the same runner and check each one's exit path.** Corollary
  learned in the doing: **assert the GREEN verdict positively, never the absence of `FAILED`** —
  absence is a property of your pattern, presence is a property of the run, and a driver that dies
  midway or is renamed out from under the recipe prints neither word. Two of the six targets
  (`multisig-accept`, `selftest`) were deliberately left unwrapped because they already `Error
  signal:` on failure — **checked, not assumed**, because wrapping them would be a second control
  on one property while leaving them unchecked would have been the same mistake again.
  *(Adjacent, and the same session: a DETECTOR needs the same scepticism as a gate. A probe
  grepping its run log for `panic` reported **30 aborts in 30 clean runs**, because the oracle's
  `agility_decode_1` line contains the word in its own DESCRIPTION — "accepts key_type=0xFE
  without panic/hardcode-reject". **Scope a detector to the region that can contain the signal**
  — here the peer-stderr section, not the whole log — and treat a detector that fires on every
  sample exactly like one that fires on none: neither has measured anything.)*
  **The gate this came from is worth its own note, because it closes a hole the other five
  structurally cannot see.** `check-set-gate` asks whether numbers are COMPARABLE, `pin-gate`
  whether anchors RESOLVE, `link-gate` whether links reach real FILES — **all three pass a tree
  in which §1 publishes `595P/54W` for a peer whose own committed report says `313P/336W`.**
  Every documentation defect found in the two weeks before it existed was found by hand-walking
  the tree with `make lint` green throughout. It gates the 46 §1 rows and the 46 per-peer prose
  banners against the committed reports, and **reports rather than gates** superseded figures
  quoted elsewhere — this repo keeps those on purpose (footnote ⁷ preserves a peer's whole
  FAIL-count progression because the sequence is the finding), and hard-failing them would hold
  the gate permanently red, which is the "teaches people to skip it" failure written down twice
  already.
  **AND THE FIRST THING IT FOUND WAS OUR OWN, EIGHT DAYS STALE: 13 published banners were still
  anchored on a dead dev SHA.** `status-banner.py` was built on 2026-08-28 specifically so a
  per-peer number would cite the **content digest** rather than the oracle's commit ([ADR-0012]
  Am. 1) — and this file already records that *"the 2026-08-22 hand pass wrote `oracle
  entity-core-go @ c1b0708` into all thirteen; generating the banner is what stopped that
  reaching the other twenty-six."* **What it does not say, because nobody checked, is that the
  original thirteen were never regenerated.** They still named `c1b0708` — a `dev` commit that
  resolves for no outside reader — in files that **publish** (`protocol-generator/**` sits
  outside every doc-root prefix and ships with no declaration). `pin-gate` did not see them: it
  is scoped to §1's pin column and `oracle-pin.env`, not to per-peer status files.
  **This is the standing "when you build a durable anchor, apply it to the history you already
  have, not only to the next entry" rule failing again, in the same shape as the unrecorded
  `retired_ref*` digests** — a tool that prevents the defect going forward is not a fix for the
  instances already on disk, and nothing was watching them. All 46 are now digest-form, and
  `coherence-gate` fails on any banner citing an oracle commit, with a planted-defect test.
  **Generalize: after landing a generator that fixes a class, grep the tree for the class and
  count. If the count is not zero, the fix has not landed — it has only been scheduled.**
  **And one check was CUT rather than shipped noisy, which is the part to imitate.** The
  handoff asked for "flag a `§N` reference with no matching heading in the same file", and it
  sounds mechanical. It is not: there is **no textual discriminator between `§5` meaning *this
  file's* §5 and `§5` meaning the *spec's* §5**, and resolving against the pinned spec does not
  help because the spec has a §5. The heuristic that works on `CONFORMANCE-MATRIX.md` (whose
  own numbering, §1–§4, happens not to collide with the spec refs it makes at §5–§7b) produced
  **124 false positives and 0 true positives** across the tree, because a peer's `PHASE-S5.md`
  has a `## 7.` section and cites the spec's §7a/§7b. It is now scoped to three files with the
  fragility stated in the source. **A check that cannot separate its signal from its noise is
  not a weak check, it is a broken one** — scope it or drop it, and say which.
- **RATIFIED (second occurrence, different shape): a budget-starved run reads as a clean run,
  and the starved categories are where the real FAILs are.** First shape — **Unison #43**: two
  *slow* categories consumed the global budget and seven core categories reported
  `budget_exhausted`, which gates as FAIL but reads like a carve-out *skip*; diagnosing that as
  **latency** rather than as seven independent failures was the high-leverage move. Second
  shape — **asm-x86_64 / asm-arm64 / riscv64, 2026-08-17**: not slowness at all but a single
  **hung** check (`t2_2_connection_churn` burning 599 s of 600 s while every other category
  finished in ~0 ms), starving seven categories including the core `resource_bounds` — which,
  when driven directly, turned out to hold **two further real core FAILs** (`r1_payload_over_limit`,
  `r3_connection_flood`). Same masking mechanism, opposite cause. **Enforcement:** grep any
  census JSON for `budget_exhausted` before trusting its `summary` (the human output flags it
  with `!!`, the JSON does not — it files starved categories under `skipped`), and drive the
  starved categories with `-category <name>` rather than re-running the whole suite behind the
  hang. **Fix the peer; never raise `-timeout` to turn the report green** — raising it as a
  one-off *diagnostic* to surface hidden coverage is the opposite move and is fine.
- **The extensibility boundary is research, not a one-off.** "Does a core peer already
  support installing a handler + outbound dispatch?" surfaced three buildable gaps
  (handler-register stubbed / handler outbound dispatch / a retroactive hand-maintained
  `--profile core` map) — design the core ↔ extension ↔ SDK boundary, don't bolt on a spike.
  Compute is an entity-native handler dispatching through the *same* §6.6 path (dispatch
  uniformity).
- **Peer-selection: discovery yield is substrate-bound, not idiom-bound.** Spec gaps come
  from wire-touching axes (integer width / float model / crypto availability / string model);
  a peer novel only off-wire (concurrency / error-idiom / packaging) adds generator
  robustness, not new findings. The spec-discovery well has been dry on the current wire
  surface since ~15 peers and stays dry at 40 (every distinct integer/float/string/byte,
  crypto, concurrency, object-model, and execution-mode axis now probed) — steady-state
  value is **re-running the existing cohort against each amendment**,
  not adding language #N.
- **CURRENT STATE 2026-08-21 — the `c1b0708` re-pin IS landed; M1 is 5/5 at 0-FAIL.** Both anchors
  moved (oracle `de8f807 → c1b0708`, spec snapshot `v0.8.0 → v0.8.2`), `--tier M1` initially came
  back **0 of 5**, and all five were then fixed to **`755 · 0F — 312P/337W/0F/106S`**, identical
  across the five. `tools/tier-status.py --gate` exits 0. The failures were never regressions:
  §5.6's MIN_DEFINED mint ceiling (CAP-5/CAP-6) had **never been implemented in any peer** —
  `mintToken` set no `expires_at` at all — and no vector exercised it until this pin. Three defect
  classes came out of it, all now ratcheted above: the §6.3 rejection-status rule, the
  absent-vs-unrepresentable accessor collapse (CAP-6a, a fail-OPEN in three peers), and swift's
  §5.5a frame over-scoping. **The same fix is owed to the other 40 peers** — author it once from the
  spec and propagate; the five M1 diffs are the reference. One known intermittent, recorded not
  hidden: `go`'s `concurrency/t1_2_concurrent_reentry` (§6.11 reentry cross-talk) failed **once** in
  a census run and passed 3/3 isolated plus on the census re-run — unexplained, load-dependent, not
  yet root-caused. Full detail:
  `research/stewardship/SESSION-2026-08-21-release-repin-c1b0708-v0.8.2-and-M1-capability-gap.md`.
  **M1 AND M2 ARE NOW BOTH COMPLETE — 13 of 45 peers publishable (2026-08-22).** `typescript`
  (84F→0F), `csharp` (INVALID→0F), then `rust` `python` `java` `kotlin` `elixir` `common-lisp`
  (3F→0F each). **The fix shape did not change once across thirteen languages** — ~200 lines over
  5–6 files, the same five places (capability mint, codec salvage, wire 400, read loop, policy
  lookup) — and that invariance is itself the evidence the spec reading is right, not just that the
  tests pass. Two peers needed a lesson the first eleven did not: rust and common-lisp reached 0F
  while still scoring CAP-6a **WARN**, because the `>2^64` half arrives only as a major-type-6 tag
  and is therefore rejected at DECODE — it needs the §6.3 answer to be *scored* as a refusal at all.
  **So on any peer, §6.3 is not optional even when the FAIL count is already zero.**
  Remaining owed: 32 peers (M3, the probes, `node-red`/wasm).
  **Re-verified 2026-08-22 (release-readiness pass), and the cohort's remaining work is smaller than
  the 40 suggests.** Gate re-run from the committed artifacts: `make lint` OK (both spec snapshots),
  `tier-status.py --gate` exits 0, and the census is **41/45 comparable with exactly the 4 INVALIDs
  §1a names** — the extra three the gate had been reporting were the stale-overlay bug, now fixed.
  Failure composition measured across all 45 reports: **CAP-5 + CAP-6 (§5.6 ceiling) is the whole
  gap for all 40** unfixed peers; CAP-6a adds to 30 of them; CAP-2/3 to 8; **CAP-7 fails on nobody.**
  Only **two** peers carry a defect outside the CAP family — `cobol` (27, standing) and the asm/ISA
  trio's shared connection-pressure family (1 visible + 2 starved). Everything else in the cohort is
  one feature. `typescript` and `csharp` are the same §6.3 fix (§1c), not two.
  **CLOSED 2026-08-28 — the propagation is done. 39 of 45 measured peers are at `755 · 0F`, up from
  13.** 23 peers fixed in one pass (all of M3 but `cobol`, 11 probes, `sql`), plus three that were
  never broken (below). The fix shape did not vary across **thirty-six** languages. `make lint`'s
  tracked gate reports **39 publishable, 0 stale**; the census is 23/23 comparable at the pinned
  check set.
  **What remains is SIX SEPARATE PROBLEMS, not one — say it that way, because "6 peers still fail"
  invites the reader to assume it is the same debt.** `cobol` 30F (its standing liveness cascade),
  the asm/ISA trio (INVALID, connection-pressure), `wasm-wat` 2F and `turbowarp` 3F (hand-authored /
  exploratory, unstarted), `apl` unmeasurable. None of them is the mint ceiling.
  **THREE OF THE PEERS IN THAT COUNT WERE NEVER BROKEN, AND THE CENSUS SAID THEY WERE.**
  `rust-wasm`, `rust-wasm-wasmtime` and `node-red` are thin seams over `../rust` (a path dep) and the
  `typescript` engine; both parents were fixed 2026-08-22. `out/peer.wasm` was dated 2026-08-17 —
  **seven days older than the source it compiles** — and `run-cohort-census.sh` hardcodes `NOBUILD=1`
  for the wasm peers, while `node-red`'s harness rebuilds `dist/` only when `index.js` is MISSING,
  never when it is merely stale. A forced rebuild took all three to 0F on the first try. **This is
  the standing stale-build-artifact rule firing on a plain SIBLING-CRATE fix rather than on an
  isolated-worktree merge** — the trigger is broader than that entry says, and the check is the same
  one second: `stat -c %Y` the artifact against `git log -1 --format=%cI` the source it derives from.
  **Compounding it, `tools/tier-status.py` was applying `output/scratch/reverify/` UNCONDITIONALLY —
  the identical defect `check-set-gate.py` was fixed for on 2026-08-22, in the file sitting next to
  it, reading the same directory.** Three reports left there on 2026-08-17 at the retired 740-check
  pin therefore outranked the fresh census indefinitely, and those same three peers displayed as
  current-and-0-FAIL on eleven-day-old evidence measured against a different check set. Fixed the
  same way (overlay applies only when NEWER, and says so on stderr when it skips one).
  **This is the "harden one anchor, check its siblings the same day" rule failing on its own terms,
  six days after it was written down.** The sibling was not a subtle one — same directory, same
  overlay, same file naming. **Enforcement, and it is the cheap one this repo already prescribes:
  when `tier-status.py` and `check-set-gate.py --tracked` disagree about which peers are green,
  suspect the INPUT before the peers.** They disagreed here, and the tracked gate was right.
- **A MEASUREMENT'S PRECONDITION CAN BE A LAUNCH FLAG THE WHOLE COHORT HARDCODES — and under it the
  probe reports the guard holding, on every peer, for a reason that has nothing to do with the guard.**
  RATIFIED 2026-09-10 (`tools/f68-probe`, answering arch's F68 ask). **Every `run-s4.sh` in the cohort
  launches its peer with `--debug-open-grants`** — the degenerate `default -> *` seed policy — under
  which nothing is outside the caller's grant, so an AUTHORIZATION-BYPASS probe has nothing to bypass
  and every peer answers "refused" correctly and vacuously. This is the examined-zero-things class
  reaching the SUBJECT rather than the instrument: the probe is fine, the gate is fine, the *world the
  peer was started in* cannot contain the phenomenon. **Enforcement, and it is the antecedent control
  generalized: for any probe that measures whether a guard holds, the same request WITHOUT the bypass
  must be REFUSED in the same run, asserted per peer.** If it is not refused, the run is `VOID` rather
  than green — a deny-only probe on an authorization surface measures nothing, which is the objection
  this seat filed against another repo's check the day before and would have repeated here. The fix is
  to drive the peer's OWN harness with exactly the one flag removed (`tools/f68-probe/run.sh`), never a
  hand-rolled launch — the standing "compare against the harness the number actually came from" rule.
  **AND TWO PEERS REFUSING DOES NOT MEAN THE DEFECT IS ABSENT — ASK WHICH RUNG REFUSED.** Measured: all
  five backends skip a caller-excluded target identically, and `csharp`/`typescript` are saved by a
  **second, independent authorization site** in the tree handler that re-authorizes the path it is about
  to act on. The *messages* are what separate them (`Dispatcher.cs:164` "does not grant the operation"
  vs `TreeHandler.cs:96` "does not cover path"); the statuses are identical. This is the standing TWO
  SITES FOR ONE REFUSAL rule moved from the FIX side to the CENSUS side — there a repair went to the
  unreachable site, here a census would have recorded two peers as not having a defect they all have.
  **A green row on a bypass probe is a claim about a rung, so name the rung.**
  **And the discriminator was a DEAD GUARD**: `python` has that same function, unit-tested, and calls it
  **from nowhere** — the H5 dead-map shape, and the single reason `python` reproduces and `typescript`
  does not. `git grep` the call sites of any function a peer's safety rests on; a definition plus a test
  is not a dispatch path.
- **WHEN A FINDING SAYS *NOBODY VALIDATES X*, THE FIX IS A RULE ABOUT WHO SUPPLIES X — AND DEMANDING
  A REFUSAL WHEN X IS WRONG PUTS BACK THE MECHANISM THE SAME REVISION JUST REMOVED.** RATIFIED
  2026-09-14 (third instance in three days, and the third one is **ours**). F72 found that the §5
  scope type is specified as a value read off the received entity while all 46 peers supply it from
  the call site, and asked for two things. Clause 1 — *the type is a property of the DIMENSION,
  supplied by the call site* — is right and costs zero. **Clause 2, which our own tracker row asked
  for in these words (*"plus a malformed disposition for a scope whose declared type contradicts its
  dimension"*), obliges every implementation to PARSE a field clause 1 has just told it to ignore**:
  an implementation that ignores `scope.type` completely — the one clause 1 calls correct — cannot
  detect the contradiction at all. **Measured on the wire: `200` on 38 of 38, `403` on zero, and the
  no-`type`-at-all differential answered identically, so nothing in the cohort reads it in any
  direction; `entity-core-rust` has no scope object, `entity-core-py`'s has no `type` field, and
  `entity-core-go`'s grants are a struct of named dimensions.** So the population was not *2 of 3
  seats* but **~48 of 49 implementations**, and arch's fold notes and ours both said *"cohort cost
  zero"*.
  **The class, and it is why this is a rule rather than an incident:** `K1.5`/`K1.7` is the same
  shape (a property with two conformant mechanisms, then one pinned disposition that only mechanism 1
  can produce) and we caught it; this one arch caught and we caused. **Enforcement: for every ruling
  that names a mechanism-free PROPERTY, trace the violation through EACH conformant mechanism and
  write down what the wire shows. If the answers differ, the disposition is per-site or the mechanism
  list is a fiction** — and if a mechanism cannot even DETECT the violation, a disposition for it is
  a requirement to build the detector.
- **A PROBE'S FAMILY CONTROL MUST VOID ITS OWN FAMILY'S ROWS, OR THE PEER THAT REFUSES EVERYTHING
  READS AS THE ONLY PEER THAT IMPLEMENTS THE RULE.** RATIFIED 2026-09-14 (`tools/arc-probe`), and it
  is the examined-zero-things class reaching a SIBLING ROW rather than a gate. Five peers
  (`asm-x86_64` `asm-arm64` `riscv64` `sql` `wasm-wat`) refuse **every** `system/capability:request`,
  so their `403` on a mistyped scope graded as conformance and they printed as *the only five peers
  in the cohort enforcing the clause*. They refuse the **well-typed control identically**. Ungraded,
  that publishes `5 of 43` where the truth is `0`, in the flattering direction nobody re-checks.
  **A row cannot see its siblings, so the voiding cannot live in the per-row grader** — it is a
  post-pass over the assembled report, keyed on the family's own control, and `VOID` is its own
  state, never folded into "owed" (a peer whose control failed is unmeasured, not defective).
  **Two more grading defects from the same instrument, both found by the cohort rather than by
  reading, and both would have published a wrong claim:**
  - **GRADING A PEER NON-CONFORMANT FOR DOING WHAT THE REVISION RECOMMENDS.** `0.8.2.20`'s own
    comment says the diagnostic it removed from `canonicalize` *"belongs at admission (§6.5), which
    has a caller to answer"* — so the five peers that refuse a malformed path with a `400` at
    admission are doing exactly what it points at, and the first cut scored them `no`. **What a rule
    forbids and what it RECOMMENDS are different branches; a check that collapses them reddens the
    peers that read the text most carefully.** Read the revision's rationale, not only its MUST.
  - **A REFUSAL ON AN ADDRESS WITH NOTHING BEHIND IT IS A MISS, NOT A MECHANISM.** The capability
    arm points at a key holding nothing, so a key-TRUSTING peer misses exactly as a key-DISCARDING
    one does. Only the arm where the entity IS present at the wrong address discriminates. Reading
    the first arm's `403` as evidence of mechanism (b) is a claim the measurement cannot make, and
    six peers would have carried it. **Before attributing a mechanism to a refusal, ask what the
    WRONG implementation would have answered to the same input.**
  *(And the runner had a guard that COULD NOT EXECUTE, which is the standing never-executed-guard
  rule in a new shape: the guard was unreachable because the condition it guards against killed the
  script one line earlier. The image-name pattern `[a-z0-9.-]` omits `_`, so `asm-x86_64-toolchain`
  never matched, `grep` exited 1, and under `set -o pipefail` the ASSIGNMENT failed — `set -e` then
  killed the run **before** the `[ -n "$img" ]` guard written to report exactly that. The roster
  stopped at peer 29 and took the 17 behind it with it, leaving a bare non-zero exit as the only
  trace. Two fixes and both are general: **capture with `|| true` so the explicit guard is the thing
  that reports**, and **a roster loop must record a failing member and CONTINUE** — a run that stops
  at 29 of 46 and names nothing is worse than one that names one skip. `f68-probe`'s runner had
  carried the identical defect latent since it was written; fixed the same day, which is the standing
  harden-one-anchor-check-its-siblings rule actually being honoured for once.)*
- **A RULE STATED AS ARITHMETIC GETS IMPLEMENTED AS ARITHMETIC — and a count that is a correct
  CONSEQUENCE can be a hole as a PRIMITIVE, including one that removes a protection already in place.**
  Candidate (first occurrence, 2026-09-10, enforcement exact). Arch's F68 ruling has two halves: a
  general rule (*a handler MUST NOT act on a target the authorization check SKIPPED*) and an arithmetic
  (*count the EFFECTIVE set; 0 -> `path_required`, >1 -> `ambiguous_resource`, 1 -> proceed*). Measured:
  `targets:[P,Q] exclude:[P]` with `Q` in-grant has effective set `{Q}`, size 1, so the arithmetic says
  **proceed** — and all three vulnerable peers **return `P`**, because the handler selects raw
  `targets[0]`. The count is fully satisfied and the bypass is untouched. Worse, the two peers that are
  currently SAFE on that arm are safe because of a **raw** arity check (`Count != 1 -> 400`), which the
  ruling replaces with an effective count of 1 — so implementing the arithmetic literally **opens** an
  arm that is refused today. **Rule: when a rule has a set-shaped half and a number-shaped half, state
  the SELECTION and let the count follow — implementers code the primitive, because it is three branches
  and a pseudocode block can express it.** The tell to look for: a ruling whose two halves would be
  implemented by different people in different files, where only one of them is load-bearing.
- **A PROBE WHOSE SUBJECT IS AN *UNMATCHABLE* VALUE CANNOT TELL "THE VALUE WAS READ AND MATCHED
  NOTHING" FROM "THE FIELD WAS NEVER READ" — EVERY SENTINEL-SHAPED CHECK NEEDS A MATCHABLE-VALUE
  CONTROL BESIDE IT.** RATIFIED 2026-09-14 (`tools/arc-probe` `E2`), and it is the standing
  *"a wire probe fails in the direction of the answer it is looking for"* rule reaching a case
  where the probe was **right about its own question and silent about a bigger one**. `E1` mints a
  capability whose `resources.exclude` is `../nope` — the §5.4 sentinel — and asks whether the peer
  honours the grant anyway. A peer that reads grant excludes and finds the sentinel carves out
  nothing answers `200`; **a peer that never reads the exclude field at all answers `200`.** Same
  status, same code, two defects an order of magnitude apart, and the report's own prose
  (*"the exclude carved out nothing"*) asserted the half it could not see.
  **The control is one case and it is obvious once stated: exclude the VERY TARGET being requested**,
  which any exclude-reading peer must refuse. Measured: **40 of 44 answer `403`; four answer `200` —
  `asm-arm64` `asm-x86_64` `riscv64` `wasm-wat` — and on those four a capability's `exclude` has no
  effect at dispatch on ANY dimension**, so an attenuated capability is honoured as if unattenuated.
  `grant_scope_ok` tests `include` for all four dimensions and the string `exclude` does not occur in
  it. **They are exactly the four HAND-AUTHORED peers**, which is this file's own rule that a cohort
  defect about EFFORT distributes by authoring cost rather than by substrate — the same four that
  deferred the §5.5 chain walk.
  **Enforcement: for any check whose input is a value chosen because it matches NOTHING, a sibling
  case must supply a value chosen because it matches EVERYTHING the subject covers, and the family
  verdict must say outright when the first is unreadable because of the second.** Generalize past
  excludes: the same hole exists for any probe built on an empty set, a no-op pattern, or an absent
  optional — *"the peer processed it and it did nothing"* and *"the peer never looked"* are the same
  observation without a positive twin.
  *(And the measurement was blocked first by a SETUP question worth recording: seven peers reported
  the whole family VOID because they refuse `system/capability:request` under the §6.9a discovery
  floor, so nothing could be minted to test with. The probe runner removes `--debug-open-grants` for
  a reason that is about the **caller's** grant — under `default → *` there is nothing to bypass —
  and **that reasoning does not transfer to a family whose subject is a token the probe MINTS during
  the run**: widening the caller's floor decides only whether the mint is permitted, and cannot make
  a narrowed cap's own exclude look enforced when it is not. `tools/arc-probe/run-mint-floor.sh`
  drives the peer's UNMODIFIED harness and says in its header that only that family may be read out
  of it. **Before concluding a family is unmeasurable, ask whether the precondition that blocks it is
  a property of the SUBJECT or of the setup** — five of the seven were the setup.)*
- **A FAILURE COUNT CANNOT SAY WHETHER ANY PEER HAS THE MECHANISM AT ALL — CROSS-TABULATE AGAINST
  THE NEIGHBOURING ROW, AND THE EMPTY CELL IS THE FINDING.** RATIFIED 2026-09-14, driving the cell
  census's last two structural zeros (`tools/arc-probe` families F and G, `F84`/`F85`). `G2`
  composes a caller `exclude` that VACATES the §5.2 dispatch check with a grant that does not cover
  the excluded target, so §6.3's `check_path_permission` — which the spec calls *"not a secondary
  check … the sole enforcement wherever the subject is derived after dispatch"* — is the only thing
  standing. **33 of 43 peers served the uncovered path.** That number is a list of peers to fix and
  it is the wrong reading. The 2×2 against `A3` (selection among two IN-GRANT targets) is the right
  one:

  | | `G2` conforms | `G2` discloses |
  |---|---:|---:|
  | **`A3` conforms** | **0** | **0** |
  | **`A3` does not** | 10 | 33 |

  `A3` is `no` on **45 of 45** — not one peer selects from the effective set — and **the top row is
  EMPTY**: there is no peer where the selection is wrong and the path check catches it. So the
  finding is not *33 peers have a bug*, it is *a layer the spec designates as sole enforcement has
  zero working instances in the cohort*, which is a different claim with a different owner and a
  different repair. **The 10 that look safe are safe for unrelated reasons** — a raw arity check
  (the arm `F71` warns refuses a legitimate single-entry effective set), a raw-target count, a
  blanket 403 — which is the standing *"a check can pass for the wrong reason"* rule, and only the
  cross-tabulation exposes it. **Enforcement: whenever a probe row measures a BACKSTOP, tabulate it
  against the row measuring the thing it backs up. A backstop is only demonstrated by a peer that
  fails the primary and passes the backstop; if that cell is empty, nobody has it** — and a bare
  failure count will read as though somebody does.
- **BRING ONE OR TWO PEERS ALL THE WAY TO THE TARGET BEFORE SWEEPING 45 — IT IS THE ONLY THING THAT
  ANSWERS "IS THE TEXT IMPLEMENTABLE AS WRITTEN", AND IT PAYS FOR ITSELF IN ONE CORRECTION.**
  RATIFIED 2026-09-14 (`go` and `python` taken to `0.8.2.23`: the §3.3 ladder,
  `check_path_permission`, the listing filter — ~90 lines each, the shape identical across a static
  and a dynamic substrate). Three things came out of it that no amount of reading produced:
  - **A frame error of ours.** The first `go` cut threaded the per-link GRANTER frame into
    `check_path_permission` by analogy with §5.5a. §6.3's own block settles it —
    `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)`, and **there is no
    granter parameter to pass**. §5.5a governs chain ATTENUATION, where the subject is a pattern
    compared against a parent's pattern; that call site compares a CONCRETE LOCAL PATH. **The
    sibling `python` peer had it right and said so at the definition** (*"do not add a granter frame
    to it"*) — the standing *"when a scope question has 45 answers in the tree, ask them"* rule,
    reached from the side where the tree was right and we were not. Record that with the same weight
    as a catch.
  - **A genuine spec ambiguity, and the vanguard is what made it concrete rather than theoretical.**
    §3.3 says an empty effective list IS the absent case; §6.3's grammar makes the listing route a
    trailing-slash TARGET; and every peer answers an absent `resource` with a root listing while
    nothing in the check set objects. **Both vanguards keep the shipped behaviour and say so at the
    branch rather than resolving it unilaterally** — it is one sentence to ask now and a cohort-wide
    change after 43 peers are swept. **A sweep is the most expensive possible place to discover an
    ambiguity; a vanguard is the cheapest.**
  - **The measurement that turns a coverage complaint into a fact: `0 of 778` severities moved on
    EACH.** Two peers went from violating three landed MUSTs to conformant and the pinned check set
    could not tell. That is the same shape as `F62` and the H1 census, and it is a sharper argument
    for vectors than any count of uncovered cells.
  **Enforcement: for any cohort-wide rule not yet gated by the oracle, land it on two peers in
  DIFFERENT substrates and re-census both check-by-check before authoring the sweep.** Two is the
  number: one proves it compiles, two proves the shape transfers.
  *(Sub-lesson, and it is the examined-zero-things class in a new shape: **a count that disagrees
  with the detail printed beside it is worse than no count.** `arc-probe`'s family-A tally tested
  `Conforms == "yes"` while one row answers `"yes — total canonicalization…"`, so a fully conformant
  peer scored **4 of 5** next to a row printing five yeses. Prefix, not equality — and the tell is
  that the summary and the detail disagree, which is visible only because the detail was printed.)*
- **CLASSIFY A PROBE REPORT BY WHAT IT CONTAINS, NOT BY WHEN IT WAS WRITTEN — AND A ROSTER RUNNER
  THAT DIES PARTWAY MAY REPORT NOTHING.** RATIFIED 2026-09-14 (second occurrence of the stale-probe-
  directory class, and the control that fixed it is stronger than the mtime check the standing rule
  prescribes). A 46-peer roster run was launched as `nohup … &` inside a background runner — the
  double-backgrounding trap this file already records — and was killed at peer 19. `output/scratch/
  arc/` then held **45 well-formed JSONs**, 19 from the live binary and 26 from a run two hours
  older that **did not contain the families being counted at all**. Nothing warned. Reading the
  directory as a cohort picture would have published a table in which 26 rows were silently absent
  rather than measured.
  **The mtime check would have worked and the CONTENT check is better: ask whether each report
  carries the rows you are about to count.** A report from an older binary is definitionally
  missing them, and the check is indifferent to clock skew, to a peer re-run by hand mid-roster, and
  to the case where two runs are minutes apart. One loop, no judgement.
  **And the runner's own failure list did not name the peer that failed.** `unison` died on a
  `permission denied` writing a TRACKED transcript output and left its previous report in place; the
  content check is what surfaced it, and re-running it alone was clean — **a filesystem-permission
  failure is contention until proven otherwise**, which the standing rule says and which held again.
  **Enforcement: a cohort table is assembled by a loop that asserts the expected rows are present in
  every report, and prints the count of reports it rejected.**
  *(And a parser that cannot read a payload must say WHAT IT SAW. The listing reader reported
  *"no readable entry list"* for a listing that was right there — `entries` is a MAP on the
  reference peer, not an array — and separately for a peer whose `entries` map is **EMPTY**. Those
  are three different facts (wrong shape assumed · nothing enumerable here · genuinely unreadable)
  and **only one of them invalidates the control**; collapsing them sent the reader looking for a
  parser bug in the one case where the peer was the answer. A failed parse reports the field names,
  their types, and the first element's keys.)*
- **A MATCHER THAT IS ALSO A PROOF SURFACE TAKES A WRAPPER, NOT A NEW CLAUSE; AND A PEER WITH NO
  CANONICAL STRING TAKES A PREDICATE, NOT A SENTINEL.** Candidate (2026-09-14, from landing one rule
  in 45 languages — the value is in the two peers where the uniform transcription would have been
  wrong). `lean`'s `matchesSeg` is not only the running matcher, it is the **T5a proof surface**: a
  transitivity theorem plus five `rfl`-level arm-characterization lemmas depend on its exact clause
  order, so adding a first arm would re-derive all six to prove a property that is not about pattern
  matching. The guard went in `matchesSegNM` and `lake build EntityCoreProofs` still completes on
  `propext`/`Classical.choice`/`Quot.sound` alone — **which is the check that says the decision was
  right rather than merely cautious.** `pd` never materializes a canonical ABSOLUTE form for local
  grants (its matchers work peer-relatively), so there is no string for a sentinel to ride on; what
  the sentinel EXISTS FOR is two observable properties — *an unresolvable form never matches, in
  either operand* and *such a form in an EXCLUDE denies* — and both are implementable directly as a
  predicate on the pattern. **Rule: transcribe the PROPERTY, and let the representation be the
  peer's. Writing a literal `/never-match` into a peer with no canonical form to put it in is cargo,
  not conformance** — and say which you did, at the site, because the next reader will otherwise
  file the deviation as an omission.
- **WHEN A PEER ALREADY HAS A FAILURE FLAG, ITS FAILURE SET IS NOT THE SPEC'S — mapping the whole
  flag to a new sentinel imports every refusal the peer happens to bundle into it.** Candidate
  (first occurrence, 2026-09-14, `apl`, and the census is the only thing that caught it). Landing
  §5.4's total `canonicalize` meant making a matcher wrapper return `NEVER_MATCH` where it had been
  ignoring an existing `invalid`/`ok`/`Option` failure. On five peers that flag carries exactly the
  three reserved prefixes and the obvious mapping is correct. **On `apl` it does not**:
  `CapCanonicalize` also refuses a null byte, an empty segment, and — the one that bit — **an
  absolute path whose first segment is not a peer_id**, which is §5.4's `validate_absolute_path` and
  which §5.4 says explicitly is *"NOT called on patterns"*. Mapping the flag turned every `/*/…`
  peer-wildcard pattern unmatchable: **6 FAILs, every foreign-namespace check and three id-scope
  ones.** **Enforcement: enumerate the arms of the existing flag before reusing it, and map only the
  ones the spec's own function names.** The tell is that the wrapper reads as a one-line change and
  the peers where it is wrong look identical to the peers where it is right — only a per-check census
  diff separates them, which is why a cohort sweep of a matcher is not done without one.
- **A READ-LOOP FIX IS NOT INHERITED BY A PEER THAT REIMPLEMENTS THE READ LOOP — and depending on
  the crate that holds the fix looks exactly like inheriting it.** RATIFIED 2026-09-14 (the §6.3
  silent-refusal sweep reaching `rust-wasm`, `rust-wasm-wasmtime` and `node-red`), and it is the
  standing *"an inheriting peer takes its parent's fix by rebuilding"* rule with its limit found.
  Rebuilding genuinely propagates a fix in the parent's **codec, model or capability** modules — that
  is how all three took the §5.4 sentinel, verified on the wire rather than assumed. It does **not**
  propagate a fix in the parent's `read_loop`, because a thin transport seam's whole reason to exist
  is that it *owns* the read loop. The August §6.3 sweep landed `reject_non_canonical` in
  `peer/transport.rs`; these three kept `Err(_) => continue` and answered a refused frame with
  silence for four months, and `ingest_rejects_unrepresentable_expiry` was WARN on all three saying
  so. **Enforcement: when a fix lands in a parent, classify it by MODULE — a change below the seam
  propagates by rebuild, a change AT the seam must be made in each seam — and the cheap tell is that
  the inheriting peer's own source contains a function with the same job as the one you just fixed.**
- **A CONTROL MUST ASSERT THE PRECONDITION THE MEASUREMENT RESTS ON, NOT MERELY THAT THE STEP
  COMPLETED — and the cohort, not the peer, is what separates "your instrument is wrong" from "this
  peer is."** RATIFIED 2026-09-09, building `tools/host-seam-probe` for the H1 dispatch census
  (`shared/findings/host-seam-dispatch-wire-census.md`). Its first run reported `go` —
  which demonstrably HAS an entity-native evaluator — as having none. The probe had encoded the
  register-request's `manifest` as a full **entity** (`{type, data, content_hash}`) where the oracle's
  own `RegisterRequestData` carries it as a **bare map**; `MapField(manifest, "expression_path")`
  therefore read the entity's top level, found nothing, and the peer **bound a handler with no body
  reference while still answering 200**. Left unfixed the roster run would have published **all 46
  peers as non-hosts** — a cohort-wide finding, entirely ours.
  **The LANDED control existed and passed.** It asserted *"was something bound"* (200 at the pattern)
  when the measurement depended on *"does what was bound carry `expression_path`"*. Widening that one
  control named the fault in a single run. **Rule: for each step a measurement depends on, the control
  asserts the FIELD, not the status.** This is the standing examined-zero-things class one level in: a
  control can execute, pass, and check the wrong proposition.
  **Second half, and it is a rule about VERDICT DESIGN: where a single peer cannot distinguish "this
  peer is broken" from "our request was", the verdict must say so and defer to the cohort.** Ten peers
  bound a handler with no `expression_path`; from any one of them that is indistinguishable from the
  bug above. It is resolved by 26 peers having persisted the *identical* request — so the verdict is
  `REGISTER-DROPPED-EXPRESSION-PATH` with its resolution rule in the text, never `CONTROL-FAILED`
  (which blames us for a peer property) and never a flat defect claim (which overclaims from one
  observation). **And order the arms by which control is more fundamental**: `wasm-wat` both drops the
  path AND fails the differential, and reporting only the first implies its row becomes readable once
  the drop is fixed. It does not.
  **Calibration, recorded with the same weight as a catch:** a source trace of all 46 dispatch sites,
  made BEFORE the probe existed, predicted the binary question — does this peer evaluate an installed
  body — **correctly for 46 of 46**, sets identical peer for peer. The read was not wrong and the
  measurement was still necessary: only the wire produced the **three-way split** among the 20
  (reference dropped at register · bound but unresolvable · bound with no evaluator), which are three
  different repairs and are invisible in a read of the dispatch site. **A source read is not worthless
  because it is not a claim — it is a hypothesis worth stating precisely so a probe can confirm or
  refute it.**
- **AN IDEMPOTENT GENERATOR MUST RECORD WHAT IT OWNS, NEVER INFER IT FROM THE STATE IT JUST
  CREATED — the second run is where that bites, and the first run looks perfect.** Candidate (first
  occurrence, 2026-09-09, `tools/author-extension-host.py`; enforcement exact). The script decided
  whether a peer's `[extension_host]` block was hand-authored by asking *"does an `[extension_host]`
  section exist"*. On run 1 that was correct. **On run 2 the section existed because run 1 had made
  it**, so all 44 generated blocks were reclassified as hand-authored and regeneration **stripped
  `dispatch_read_site` from every one of them** — the load-bearing field, the entire reason H5 has
  that field. Fix: two markers (`FULL` = the script owns the whole block, `MEASURED` = a hand-authored
  block owns the prose and only the measured fields are injected), read from the file rather than
  inferred. **Enforcement: run any generator TWICE in its own test and require the second run to
  report zero writes.** A single run cannot detect this class at all.
  **AND THE CHECK PASSED THE STRIPPED TREE — SECOND OCCURRENCE IN ONE SESSION OF A CONTROL ASSERTING
  THE WRONG PROPOSITION.** `--check` verified the H1 keys were present and said *"46 examined, 0
  problems"* over 44 blocks whose `dispatch_read_site` had just been deleted. It printed the count,
  which this file already requires — **the count was right and the predicate was wrong**, so the
  examined-zero-things rule is necessary and not sufficient. **A gate must assert the field the
  artifact EXISTS FOR**, and for a generated block that is whichever field a human traced by hand.
  *(Two cheaper sub-lessons from the same tool, both caught by its own postcondition rather than by
  reading: **a fragment of `key = value` lines appended to a TOML file lands in whatever table the
  file ENDS in** — `[spec]` on all 46 — which is valid TOML and silently wrong, so emit the section
  header and then PARSE the result; and **interpolating traced source text into a TOML string needs a
  real escaper**, because the values quote code containing quotes and seven profiles stopped parsing.
  Both are the postcondition rule: verify the property, never that the edit was written.)*
  **CURRENT STATE 2026-09-09 — H1 IS MEASURED COHORT-WIDE: 26 of 46 peers can dispatch a
  third-party-installed body; 20 cannot, and nothing in the 778-check set says so.** Verified rather
  than assumed: `core_register_body_binding` asserts only that the §11.6.1 entities were BOUND,
  `unsupported_operation_on_registered_handler`'s `registeredURI` is **`system/tree`** (a BOOTSTRAP
  handler — "registered" means present), and `validate_echo_dispatch` drives the built-in
  `system/validate/echo`, the oracle's own declaration recording that the dispatch half was
  deliberately *"moved off compute/literal"*. **So a peer binds all four writes, scores `778 · 0F`,
  and has nowhere for a body to run.** None of it is a conformance failure — §6.13(a) is an extension
  surface — but two of the three failure shapes report SUCCESS for a registration that can never be
  dispatched, which is a promise the peer cannot keep. Two spec questions fell out and are recorded as
  questions, not assertions: **`no_handler_body` appears nowhere in `v0.8.2.11`** (it is `go`'s
  spelling, copied by 8 peers, and the cohort spells that failure four ways), and `pd` answers
  `501 not_implemented`, one of the four spellings §3.3 retired at 0.8.2.7 — though 0.8.2.8's
  carve-out for *"a domain code defined for a different failure"* may reach it.
  **CURRENT STATE 2026-09-07 — §6.3's `0.8.2.11` PUT ADMISSION LADDER is CLOSED at 46 of 46, 6 of 6
  on `tools/put-probe`, and it moved NO conformance check.** This is the first ACCEPT-side rule of
  the whole `0.8.2.x` arc and it was new implementation on every peer, not a re-vendor: measured
  first at **0 of 46 conformant**, with 36 peers accepting-and-storing a two-key `{type, data}`
  submission. The pinned oracle (`f313028`, executed set `d30c3dd0…`) carries no vector on this
  surface — its own `put` inputs all carry a well-formed `content_hash` — so **the ladder is
  additive at this check set, verified per-check against every committed report rather than by
  summary.** The oracle re-pin that WILL gate it is still deliberately open (`go` is 54+ commits
  past the pin and was landing `fix(tree)` work on this surface); the vendor and the re-pin stay
  decoupled. Detail: `shared/findings/put-admission-wire-census.md`.
  **CURRENT STATE 2026-09-01 — the `0.8.2.3` sweep is CLOSED at 46 of 46, `756 · 0F`, cohort-standard
  row `314P/336W/0F/106S`. The `755 · 0F` cohort row below is HISTORY.** Both anchors moved together
  (oracle `c1b0708 → f313028`, spec `v0.8.2 → v0.8.2.3`, executed set `95edd774… → d30c3dd0…`), two
  new core checks landed (`connect_prehello_authenticate` FM-1,
  `dispatch_inbound_foreign_namespace_refused` PD-1) and one was **deleted rather than re-pointed**
  (`authz_peers_target_from_uri`, whose PASS branch required the escalation — see the F51 withdrawal
  entry above). The last five peers (`pd` `wasm-wat` `asm-x86_64` `asm-arm64` `riscv64`) took the
  §1.4 address gate; all 46 tracked reports and prose banners were **re-measured**, not copied, and
  the matrix's own pin prose was a pin behind independently of the peers (`pin-gate` was red on
  `check_set_digest` and the spec-snapshot hashes — the re-pin updated `oracle-pin.env` and the code,
  and left the document that tells a reader what the pin IS).
  **Two verification-tool defects fell out of the refresh, and their correct answers are OPPOSITE —
  worth holding together, because "check the sibling for the same defect" argues for making them
  match and that would be wrong.** Both read `output/scratch/census/`, which a `--to-status` run does
  not write. `tier-status.py` is a status DISPLAY, so freshest-wins is right: it gained the tracked
  reports as a third recency-ranked source (keyed by peer DIRECTORY — every tracked report is named
  `CONFORMANCE-REPORT.json`, the `Path.stem` collision `check-set-gate` already shipped once).
  `check-set-gate.py --tracked` is a GATE ON those reports, and its census read is exactly what keeps
  the claim set independent of what it checks — deriving it from the tracked reports makes the gate
  *"every tracked report at the pinned digest is at the pinned digest"*, the `oracle-bootstrap`
  HAVE/WANT shape — so it REPORTS the drift instead. **A stale input is not always an override to
  fix; sometimes it is the independence you were relying on. Ask what question the tool answers
  before porting a sibling's fix into it.**
  *(And a third, cheap: `coherence-gate --self-test` died on `assert bad != matrix_text` because its
  planted defects named `755`-era literals. **That loud death is the design working** — a plant that
  silently matched nothing would make those checks vacuous — but a regression suite needing a hand
  edit on every re-pin is one nobody runs. **Derive plants from the file under test, never hardcode
  the figures.**)*
  **CLOSED 2026-08-30 — every peer in the cohort is at `755 · 0F`. 46 of 46, no exclusions.** The
  last five landed in one pass: `asm-x86_64`, `asm-arm64`, `riscv64` (INVALID → 0F), `cobol`
  (30F → 0F) and `apl` (excluded → 0F).
  **This paragraph said "45 of 45" and "`apl` remains unmeasurable and upstream-blocked — that is a
  toolchain fact, not a conformance one" for several hours, and every clause of that was false.**
  The toolchain had been fixed three days earlier, the upstream tarball was never deleted, and the
  exclusion was enforced by the census itself. See the exclusion entry above; it is the more
  important lesson of the two, because the wrong number was *published* and no gate could see it.
  **Say what this is and what it is not.** It is 46 peers passing one author's vectors at one pinned
  check set: **cohort-consistent, not independent convergence**, and the ISA trio is one lineage
  ported twice on top of that. It is not a claim that the peers are correct — three of the four
  defects closed here had been PASSING checks for months for reasons unrelated to what those checks
  test.
  **Three things the last four peers taught, all of them about how a defect DISGUISES itself:**
  - **The connection-pressure family never existed.** Three peers were quarantined for a "shared
    connection-pressure defect" and the actual cause was a §4.9(c) silent drop on a length-colliding
    op name — a correctness bug billed entirely to the caller's timeout, so it read as slowness.
    §1a's accumulation theory is retracted; the 2026-08-29 measurement that disproved it was correct
    and pointed nowhere, because it was answering "is the peer unhealthy" and the peer was fine.
  - **`cobol`'s 30 FAILs were 24 cascade + 5 real + 1.** One unchecked `MOVE` of wire data into a
    fixed field killed the process; every check after it reported connection-refused. **Count the
    cascade before budgeting the work** — the standing "first FAIL in RUN ORDER, last check before
    the first transport error" diagnostic gives the real number in one read of the census JSON.
  - **Two of the four peers had defects that were holding each other up.** `cobol`'s id-scope
    over-canonicalization and its absolute-handler-value were individually invisible; fixing either
    alone makes the peer worse. When a fix moves a number the WRONG way, the second defect is the
    finding — this is the standing "a fix that raises the FAIL count is a finding" rule with the two
    halves inside one dimension.
  **Owed, and named rather than quietly carried:** ~~the ISA trio still over-publishes extension type
  vocabularies~~ — **closed 2026-08-30**, the grep returns nothing and the three now read
  `313P/336W` / `312P/337W` / `312P/337W` against the cohort-standard `312P/337W` (the fix lowered
  the pass count by 282; see the type-registry entry above).
  ~~`asm-arm64`/`riscv64` never received b6371d7's four `host.s` hardenings~~ — **ported 2026-08-30;
  `r3_connection_flood` WARN→PASS on both, all three ISA rows now `313P/336W`, and the cohort finding
  moves 44/2 → 42/4.** `cobol` skips two concurrency checks its 65535-byte
  frame cap and 8192-byte entity ceiling make unreachable.
- **RATIFIED, and it BROADENS the routed-claim rule: the exculpation most likely to be wrong is the
  one WE wrote, because nothing routes it back for review.** Second occurrence 2026-08-30, in the
  same session as the `apl` exclusion below — which is the same defect wearing a different hat. The
  standing rule (*"verify a routed claim before acting on it, especially the exculpatory half"*)
  only ever pointed at **inbound** claims from a sibling repo. Both of this session's findings were
  self-authored exculpations that had never been re-read:
  - `CONFORMANCE-MATRIX.md` §3 carried `authz_peers_target_from_uri` for two weeks as *"WARN on
    every peer · **Low — inconclusive by design** · a single standalone peer cannot resolve
    `target_peer` against a synthetic foreign URI; needs a real two-peer harness. Not attempted
    since it was found 2026-08-16."* Measured: **40 WARN, 6 PASS**. The six return a full three-row
    verdict, so a standalone peer decides it fine and no harness was ever needed. The real split is
    one line of routing (a `!= localPeer → 404 handler_not_found` gate ahead of handler resolution),
    it is a **spec ambiguity worth a handoff**, and the phrase "inconclusive by design" had been
    doing the work of a decision nobody made.
  - `apl`'s `UNMEASURABLE — upstream-blocked` (below).
  **Both were single-command questions.** The severity-diff that answered the first is the standing
  highest-yield diagnostic in this file, applied to a *check* instead of a *peer*:
  `for each report → severity of check X`, then look at what the two groups have in common. **Rule:
  a row that explains why something CANNOT be measured, or need not be, is a claim — date it, name
  the command that would refute it, and re-run that command before citing the row.** A row asserting
  work is *owed* gets re-read every time someone looks for work; a row asserting work is *excused*
  is read once and never again, which is exactly backwards from how often each is wrong.
- **AN EXCLUSION IS A CLAIM WITH AN EXPIRY DATE — and the one that hides longest is enforced by
  the tool that would disprove it.** RATIFIED 2026-08-30 (`apl`; second occurrence of the
  stale-input class in the shape where the *gate itself* is the stale input, after
  `check-set-gate`'s unconditional reverify overlay). `apl` was carried for months as
  `UNMEASURABLE — upstream-blocked; excluded from census by standing policy`, and the published
  headline read `45 of 45 measurable` on the strength of it. **All three clauses were false**, and
  the peer measured `755 · 0F` on the first attempt in 109 s:
  - the *upstream* claim was a bad inference (see the tarball bullet above — GNU reorganized, it did
    not delete);
  - the *toolchain* claim had been repaired three days earlier and nobody re-checked — the image was
    force-bumped to APL 2.0 on 2026-08-27 and **built successfully on 2026-08-28**, so the label
    outlived its own cause;
  - the *policy* clause was a hard-coded `apl) ... rc=125` in `run-cohort-census.sh` plus an
    `$1 == "apl" { next }` in `roster_peers()`, so **the one peer nobody could measure was the one
    peer the census would not attempt.** An exclusion that suppresses its own falsifier is
    permanent by construction, and it degrades silently: nothing errors, nothing warns, the tier
    report just says `NO-REPORT` next to a note explaining why that is fine.
  **What makes this worse than an ordinary stale fact is what it does to a NUMBER.** "45 of 45
  measurable" reads as a complete measurement and was one unrun command away from "46 of 46" — the
  word *measurable* is doing load-bearing work that no gate checks, because a peer that is not
  measured produces no report to be found non-comparable. `check-set-gate` and `tier-status` were
  both green throughout; they can only audit reports that exist.
  **Enforcement, and it is structural rather than a grep: no per-peer exclusion may live in the
  measurement tooling.** `run-cohort-census.sh` now carries none, and `roster_peers()` no longer
  filters — every peer in `tools/peer-tiers.tsv` is measured, so a peer can leave the census ONLY
  by leaving the roster, where `tier-status.py` reports its absence as backlog. **Generalize: when
  you must skip something, encode the skip where it is VISIBLE as a gap, never where it is
  invisible as a policy** — and wire every exclusion to a re-check of the condition that justifies
  it, or delete it. *(Sub-lesson worth its own line: the peer had sat out THREE cohort-wide
  propagation passes because of the label — 7 of its 8 FAILs were defect classes closed elsewhere,
  including the §6.2 register guard that reached 44 of 45 peers on 2026-08-17 with `apl` the sole
  omission. **An excluded peer does not hold still; it accumulates every debt the cohort pays
  down**, so the cost of an exclusion grows with exactly the thing that makes it feel safe to keep.)*
  **AND THE HAPPIEST FORM OF THE SAME CLASS: A PUBLISHED MEASUREMENT CAN BE SUPERSEDED BY THE VERY
  RULING IT ASKED FOR, AND IT GOES STALE SILENTLY BECAUSE NOTHING ABOUT IT LOOKS WRONG.** 2026-09-09,
  the §4.7 pre-hello `authenticate` census. We measured a **38/6/1** cohort split on 2026-08-30 and
  routed the normative question; arch folded it **the next day** (0.8.2.1, FM-1), we vendored it at
  0.8.2.3 and swept the cohort at `5a53b75c`, and the oracle grew `connect_prehello_authenticate`.
  Re-measured today: **46 of 46 uniform**, split gone. The register and the matrix had recorded the
  *ruling* as closed; **the published TABLE of what the peers do was ten days stale in four places**
  and nothing could see it, because a dated measurement with a date on it reads as history whether
  or not it still describes the tree.
  **Two enforcement points, and the second is the reusable one.** (a) **When a finding routes a
  question, the answer landing upstream is a trigger to RE-MEASURE, not only to update a status
  cell** — the whole point of the cohort number was the disagreement, and a resolved disagreement
  changes the number. (b) **A finding that states its own exit condition has handed you a gate;
  re-read it when the condition fires.** This one said *"if architecture rules, the ruling belongs
  in `validate-peer` as a vector — at which point this probe should be deleted, not kept as a second
  source of truth."* That sentence decided the whole disposition ten days later and cost nothing to
  honour. **Write the exit condition into the finding; it is the cheapest gate in this file.**
  *(Sub-lesson, and it is calibration in the flattering direction: the one row that looked like a
  disagreement with `entity-core-formalization`'s source census — `csharp`, which they read as `400`
  and which now measures `401` — was **the sweep, not a miss**. A one-line `git show` on the sweep
  commit showed their reading was correct for the source they read. **Before recording a sibling's
  claim as wrong, check whether YOUR tree moved under it**, and date what each side was looking at.)*
- **A REFUSAL REACHED BY `throw` INTO A GENERIC CATCH IS NOT THE REFUSAL THE SOURCE APPEARS TO
  STATE — and the clause that states it can be DEAD CODE that has never once run.** Candidate
  (`prolog` 2026-09-01, but it is the standing "a source grep is not a conformance census" rule
  with the sharpest example yet). `authorized_dispatch/5` did `throw(not_local)` for the §1.4
  foreign-namespace case, and the clause *directly below it* answered `404 handler_not_found`
  (later `400 invalid_request`) — which reads, to any reader and to any grep, as the refusal.
  **A `throw/1` does not fall through to the next clause.** It unwound to `dispatch/4`'s
  `catch`, where the generic `chain_error_outcome/2` turned it into **`500 internal_error`**.
  Measured on the wire; a source read clears the peer completely.
  The second clause had never executed in the peer's entire history, and nothing noticed because
  no vector exercised the input until PD-1 landed one. **Enforcement: for any refusal implemented
  as a raised/thrown condition, name the handler that catches it and check that the handler
  produces the status the refusal intends** — a generic catch-all is a 500 factory, and in a
  language with clause-indexed dispatch a fallback clause beside a `throw` is the shape most
  likely to be mistaken for one.
- **A REFUSAL THAT EXISTS BUT CANNOT BE REACHED IS A §4.9(c) SILENT DROP — check that the answer
  path is REACHABLE, not just present.** Candidate (`apl` 2026-08-30, but it is the third time in
  three days that a §4.9(c) drop has been the finding, after the ISA op-ladder and `cobol`). `apl`
  already had a correct `400 non_canonical_ecf` branch in `OnFrame`, written and committed. It was
  dead code: the `WirePeek` that recovers the `request_id` used the **strict** decoder, so a frame
  carrying a major-type-6 tag returned `ok=0` two lines earlier and was dropped on the floor. The
  peer scored CAP-6a **WARN** — *"3 capability_denied, 3 transport-drop"* — while reading, in source,
  as if it answered. **Grepping for the status code finds this code and clears the peer.** What
  finds it is asking which decode the answer path depends on. The cohort-standard salvage decode
  (strict decoder byte-unchanged; salvage used ONLY to recover the id) took CAP-6a to PASS on all
  six variants **and cut the run from 149 s to 89 s**, because each dropped frame had been billing
  its caller a full timeout — the same "presents as slow, is actually wrong" signature as the ISA
  trio's op ladder.
- **RATIFIED, and it is the STALE-INPUT class reaching VENDORED DATA: a second copy of a corpus is
  a second authority, and the retired one answers.** 2026-09-02, closing the vector-layout migration.
  `shared/test-vectors/` held both `v0.8.0/agility-vectors-v1.cbor` (`8e7c5232…`) and
  `crypto-agility/agility-vectors.cbor` (`b5484e84…`); the peers' harnesses pointed at the first.
  The job read as directory-naming hygiene — `GUIDE-CONFORMANCE.md` §5.1 forbids a version stamp in
  a corpus directory or artifact name — and was actually a **supersession**: upstream had INVERTED
  `hash-format-sha-384.2` (the re-hash it used to pin is now a construction that MUST be refused,
  §4.5a item 1a floor-pins `system/peer`) and moved M3/M6 `expected_peer_a_content_hash` to
  floor-form. **Nothing failed while both copies existed**, because every peer reading the old path
  got the old bytes and agreed with them.
  **Why this carrier is worse than the artifact ones already recorded here** (a `.wasm` older than
  its source, a reverify overlay older than its census, a tracked report a pin behind): a stale build
  artifact is *derived*, so a rebuild reconciles it. **A vendored corpus reconciles with nothing** —
  it is authoritative by construction, so the duplicate is not stale data, it is a rival ground
  truth. Enforcement: **one copy of a vendored corpus, ever**; retired digests go in
  `shared/test-vectors/README.md` (keystone-owned — the corpora's own `CHANGELOG.md` are
  byte-identical vendors and must not be edited), so a supersession shows up as a changed digest
  rather than as two directories.
  **A TRANSCRIBED PIN IS A COPY WITH NO GATE ON IT, AND IT MAKES THE HARNESS COMPARE THE PEER TO
  ITSELF.** This is the half to carry. Four peers were affected and they split by *how* they consume
  the corpus, not by language: `elixir` and `ruby` LOAD it and both FAILED the same two gates the
  moment the duplicate went (`got 0166f421…, want 00af37ab…` — the peers were computing the
  forbidden SHA-384 form). `ocaml` and `csharp` TRANSCRIBE the values into their own source and both
  **PASSED** — `ocaml` at a confident `RESULT: PASS (25/25)` — while carrying the identical defect,
  because the peer computed the SHA-384 form and the test expected the SHA-384 form. That is the
  `oracle-bootstrap` HAVE/WANT shape in a new place, and the rule written then holds verbatim:
  **name the authority side of a comparison, and distrust any equality test whose two operands
  derive from the same source.** Enforcement: **when a corpus moves, re-run the peers that LOAD it
  AND the peers that TRANSCRIBE it — the second group is the one that will not tell you**; and a
  transcription site must name the corpus artifact it came from so the next reader can diff it.
  *(Detail, including the one peer predicted-failing and unmeasurable and the negative half nobody
  implements: `protocol-generator/shared/findings/superseded-corpus-duplicate-and-transcribed-pins.md`.)*
- **RATIFIED, second occurrence on the same peer and the sharper one: THE PEER'S OWN STDERR GOES TO
  A FILE INSIDE THE CONTAINER AND DIES WITH IT — four investigations found "no crash" because
  nobody had kept the evidence.** 2026-09-02, closing the `zig` `r3_connection_flood` item. Every
  `run-s4.sh` in the cohort launches the peer as `./host … >/tmp/host.out 2>/tmp/host.err &`. Those
  are **container** paths on a `--rm` container: when the run ends the stderr is gone, so a peer that
  aborts leaves a harness log reading *"connection refused"* and nothing else. Adding
  `cat /tmp/host.err` after the oracle call — one line — turned *"not root-caused, no crash, empty
  stderr"* into a stack trace on the first reproduction. **Before concluding a peer did not crash,
  confirm you kept its stderr.** (Pairs with the standing *"a source grep is not a conformance
  census"*: here the missing evidence was not in the tree at all.)
  **What it found, and it is a lifetime bug BELOW peer code:** `thread NNNNN panic: reached
  unreachable code` at `std/Thread.zig:1377` — `entryFn`'s `completion.swap(.completed, .seq_cst)`
  landing on the `.completed => unreachable` arm. That state is only reachable if a detached thread's
  `Instance` mapping was **reused while its previous thread was still inside that `defer`**:
  `detach()` makes the thread `freeAndExit()` its own stack+TLS+Instance mapping, and a concurrent
  `spawn()` can be handed the same address. This is the standing zig entry's *"a detached worker must
  not outlive the state it borrows"* with the stdlib's own bookkeeping as the victim rather than
  ours — so **`detach()` is the hazard, not just what you hand it.**
  **Measured: 5 aborts in 60 full `--profile core` runs (8%).** It presents first as
  `t2_2_connection_churn` failing mid-cycle, and only then as `r3`.
  **TWO REPORTING LESSONS, both about numbers we had already published:**
  (a) **The previous record said `r3` 2/22 and churn **0/22**. Re-measuring gave 4/22 and 2/22 — so
  churn was never 0**, and a "0" that came from too few samples had been carried forward as a fact
  distinguishing two bugs. The standing rule (*re-run N times and count*) already covers the failing
  case; extend it to the **passing** one: a 0-of-N is a rate estimate too, and its confidence is
  bounded by N.
  (b) **The oracle's failure text can name a mechanism that is not the mechanism.** `r3` reports
  *"admitted 0/256 … admission slots leaked; the bound must release when connections close"* — a
  precise, plausible, and completely wrong description of a peer that is simply **dead**. It is
  inferring from `connection refused`. Read a check's prose as a description of what it OBSERVED,
  never of what happened; the instrumented accept loop (which never exited) is what separated the
  two.
  **CLOSED separately in the same session, and do not let it absorb the above: `zig` had no §4.10(c)
  admission bound at all**, so a 256-connection flood became 256 concurrent threads and `r3` FAILED
  **9 of 30** runs with *"admitted all 256 … fell over on the serve probe … i/o timeout"* — plain
  saturation, no crash, accept loop healthy. A 64-connection bound (**reserved BEFORE the spawn**,
  because a detached thread can finish before `spawn()` returns; **released LAST in the worker's
  teardown**, because a slot must never be free while its resources are held) eliminated that shape
  entirely — **0 of 60** — and took `r3` WARN→PASS (`314P/336W → 315P/335W`). **Two independent
  defects behind one intermittent check, and fixing the first one does not touch the second**: this
  is the 2026-09-01 `zig` pattern (`3/5 → 1/6 → 0/22`) recurring, where one bug masked another and
  only counting over repeated runs told them apart. Reporting the bound as "the fix" would have been
  a partial fix sold as a whole one.
  **LANDED COHORT-WIDE 2026-09-02, and the sweep is the entry above one level up: only THREE of 46
  harnesses kept the peer's stderr, and the survey that said otherwise was wrong twice.** The item was
  deliberately deferred as "its own job"; doing it produced the defect it exists to catch, on the
  first run. Two failed surveys first, both already-named shapes:
  (a) `grep -l 'cat .*host\.err'` reported **39 of 46 already capturing.** Every one of those 39 cats
  the file ONLY on the **startup-failure** path (`host exited before LISTENING`), which by
  construction cannot fire for a peer that starts fine and dies mid-run — the only case the item is
  about. **A grep can match the right token in the WRONG CONTROL-FLOW BRANCH, and that reads exactly
  like a pass.** This is the fourth member of the false-negative family after the `dart`/`ruby` NUL
  byte (could not SEE the file), F51 (wrong VOCABULARY) and the de-versioning sweep (pattern could not
  SPAN the construction) — and it is the first that is a false POSITIVE, i.e. it manufactures
  confidence rather than absence.
  (b) Narrowing to `host.err` then reported 5 peers with **no stderr file at all**. They have one;
  `io`/`pd`/`sql`/`turbowarp` merge stderr into a combined log under their own names and `node-red`
  uses `/tmp/nr.err`. **The discriminator has to be STRUCTURAL — a `cat` of the peer's log AFTER the
  last oracle invocation — not textual.** By that measure the real state was 3 of 46.
  **Three shapes, decided by the harness and not by taste** (the same "the substrate decides" rule as
  the §6.3 salvage flag): append after the oracle call (38 peers + `node-red`); **split the streams
  first** where the launch merges them, since a combined log is never empty and a guard on it would
  dump the log every run — and fix the startup-failure path to print BOTH, or the split moves the
  evidence out from under the one guard that already worked; and **hold the exit code** on the five
  whose oracle call has no `|| true` under `set -e` (`io pd sql python ruby`), where a naive append
  runs only when the oracle SUCCEEDS and is therefore silently absent from every failing run.
  **Verified by RUNNING** — all 46 `bash -n`, 10 peers driven through the census covering every shape,
  then the full 46-peer census at `756`, 46/46 comparable. The guard was also observed FIRING
  (`go python pd sql` print a startup banner on stderr), which is the half normally left unverified.
- **RATIFIED — SECOND OCCURRENCE, DIFFERENT LANGUAGE, DIFFERENT ALLOCATOR: A DETACHED WORKER MUST NOT
  OUTLIVE THE STATE IT BORROWS.** `c`, 2026-09-02, found by the stderr capture above on its first
  cohort run: a 46-peer census in which 45 peers were 0F and `c` was **756 · 288P/335W/27F**, and the
  peer's own dying words were `free(): chunks in smallbin corrupted`. `reader_loop` dispatches each
  inbound EXECUTE on a **detached** thread whose job borrows `conn` and `io`, both living inside the
  connection's `serve_state`; the reader returns the moment the client closes and `serve_reaper`
  joined **only the reader** before freeing that state. `ec_io_free()` also `close()`s the fd, so a
  late write can land on a descriptor **already recycled by a later `accept()`** — a cross-connection
  write, not merely a lost response.
  **The ordering IS the fix and every clause is load-bearing:** reserve BEFORE the spawn (the worker
  can finish before `pthread_create` returns), release LAST in the worker (the owner may free
  everything the instant the count reaches zero), drain before the owner frees. `ec_session_close`
  carried the identical defect with a different owner and was fixed the same day — the standing
  *"harden one anchor, check its siblings"* rule, which this repo has now failed twice.
  **THE CATEGORY RUN DOES NOT REPRODUCE IT, AND THAT IS THE MEASUREMENT LESSON.** `-category
  concurrency` alone: **0 of 20** on the unfixed binary. Heap corruption is layout-sensitive and the
  crash needs the full suite, ~680 checks deep. On `--profile core`: **baseline 1 of 10 · fixed 0 of
  20**. State the resolution rather than implying proof — against a ~10% base rate, 20 clean runs is
  roughly 88% confidence. **Corollary to the standing "drive the starved category directly" advice:
  that is right for COVERAGE and wrong for a RACE — an isolated category is a different heap.**
- **A REPRODUCTION IS A MEASUREMENT SETUP, NOT A COMMAND — and if the probe script is not kept, the
  rate cannot be re-measured, only re-argued.** RATIFIED 2026-09-02 (`zig`), and it is the standing
  *"re-run N times and count"* rule failing at its own next step. That rule produced an honest number
  in the morning — **5 aborts in 60 full `--profile core` runs (8%)** — and the probe that produced it
  was never saved. The same afternoon, on the **same source**, the abort would not reproduce at all:
  **0 of 130** sequential runs at `--cpus=4`, uncapped across all 32 cores, and with 12 CPU burners
  oversubscribing the container, plus **0 of 100** `-category concurrency` runs. Nothing in the tree
  had changed. The only surviving evidence of how the morning had measured it was a **port number in
  a log** (`LISTENING 127.0.0.1:7714` on run 14 — one port per run, i.e. the runs were concurrent),
  and reconstructing that regime from scratch cost more than keeping the script would have.
  **Three things generalise, and the second is the one that changes what you write down:**
  (a) **Commit the probe beside the finding.** A rate is a claim about a setup; without the setup it is
  an anecdote with a denominator. `output/scratch/zig-abort-probe.sh` now carries its own conditions in
  its header, including the ones that did NOT reproduce.
  (b) **A fix for an intermittent you can no longer reproduce is justified STRUCTURALLY or not at
  all — and 100 clean runs is not evidence when the baseline is also 0 of 100.** Post-fix greens are
  the number everyone wants to publish and they say nothing here; the honest claim is *"the mechanism
  is removed and the count cannot speak to it"*, and the enforcement point is a grep (`detach()`
  returns 0 outside comments), not a tally.
  (c) **When the headline intermittent will not reproduce, measure what WILL.** The same change also
  removed a 20.6-second `t2_2_connection_churn` stall — unfixed **7 of 100**, fixed **0 of 100** — and
  a third build carrying only HALF the fix scored **10 of 100**, which is what isolated the cause to
  the other half. A variant that changes one half at a time is how an attribution stops being a story;
  it cost one extra 100-run batch and replaced a plausible sentence with a measured one.
- **`detach()` IS THE HAZARD, EVEN WHEN THE BORROWED STATE IS SAFE — the victim can be the RUNTIME'S
  OWN bookkeeping.** RATIFIED 2026-09-02 (`zig`, second occurrence in the same peer, and the entry
  above's structural half). The 2026-09-01 fix made the detached dispatch threads safe *for our
  memory* with an in-flight counter, and left the abort: Zig's `entryFn` ends in
  `switch (completion.swap(.completed))` whose `.completed => unreachable` arm can only be reached if
  an `Instance` mapping was reused while a previous thread was still finishing with it — which only
  the detached path can produce, because `freeAndExit` munmaps the thread's own stack+TLS from INSIDE
  the dying thread and the kernel's `CLONE_CHILD_CLEARTID` write lands afterwards. **Own the handle
  and the whole shape goes away**: `join()` frees the mapping from the owner, after the kernel is
  finished. Enforcement, cohort-wide and one line: `git grep -n 'detach()\|pthread_detach' -- '*/src/*'`
  and, for each hit, name what keeps the borrowed state alive. Answers found: `zig` none (fixed),
  `c` an in-flight count + drain (fixed 2026-09-02), `cpp` `shared_ptr` copies captured by the lambda
  (correct by construction — refcounting IS the discipline on that substrate), `python` daemon threads
  over refcounted state (no manual free, so no such class).
  **Sub-lesson worth its own line, because it was measured rather than reasoned: a SPIN is not a
  cheap `join`.** The counter it replaced was drained with a `std.Thread.yield()` busy-wait, and on a
  4-core container a reader spinning in that loop can starve the very dispatch thread it is waiting
  for — 7 of 100 runs paid a full 20-second request deadline for it. A futex wait cannot do that.
  Prefer the primitive that blocks; a yield-spin is a scheduler bet, not a synchronisation.
- **A COMMENT THAT NAMES A LIFECYCLE STEP IS NOT EVIDENCE THE STEP EXISTS — count the resource at two
  points in time instead of reading the code that manages it.** Candidate (`cpp` 2026-09-02, found by
  asking the `zig` question of its siblings the same day, which is the standing sibling-check rule
  paying out for the third time). `Listener::Impl::conns` was **push_back-only** — no `erase` anywhere
  in the file — under a struct comment reading *"keep its Io + Connection + reader thread alive until
  reaped."* Nothing reaped. `close_io()` only `shutdown()`s; `~Io` is what calls `::close(fd_)`, and it
  could not run while the list held the `shared_ptr`. **Measured on the running peer: 4 fds idle →
  1419 after one `--profile core` suite → 2834 after two**, linear, unbounded, and triggerable by
  anyone who can open a connection. It had never failed a run because the toolchain container's soft
  limit is **524288** — under the conventional 1024 the peer exhausts descriptors partway through a
  single suite and `accept()` starts returning `EMFILE`. **The generalisation is about which question
  finds it:** reading `transport.cpp` for a use-after-free (what the sibling sweep was looking for)
  clears this peer completely, because the `shared_ptr`s make the lifetimes correct — the defect is
  that they are *too* correct, held by a list with no other end. `ls /proc/<pid>/fd | wc -l` at idle,
  after one suite and after two is the whole diagnostic, and a leak is a CURVE where a high-water mark
  is a plateau.
- **AN INLINE `{ type X }` IMPORT IS STILL A VALUE IMPORT OF THE MODULE, AND THE EMITTED NO-OP CAN
  BLOCK A WHOLE BUILD TARGET.** Candidate (`typescript` → `turbowarp`, 2026-09-07).
  `import { type Socket } from "node:net"` leaves the STATEMENT a value import, so `tsc` emits
  `import {} from "node:net"` into `dist/` — harmless under Node, and fatal to an esbuild
  **browser** bundle that cannot resolve a Node builtin. That single emitted line is the entire
  content of `turbowarp`'s `ERROR: bundle build failed`, the reason **the one peer nobody could
  measure** carried that status for weeks. `import type { … }` elides the statement completely.
  **Bisected before being called pre-existing** — it reproduces with the parent's source restored
  to before the arc — which is the standing rule about never labelling a failure "pre-existing"
  without bisecting, and it is also what made the fix safe to make here rather than route.
  Enforcement: `grep -rn "import { type " <peer>/src` on any peer whose output is bundled for a
  non-Node platform.
- **PROSE IN A COMMENT IS CODE, IN ANY FORMAT WHERE PUNCTUATION TERMINATES A RECORD — and the errors
  it produces are invisible if the peer logs to a file that dies with the container.** Candidate
  (first occurrence, but the enforcement point is exact). `pd` had been printing three errors on every
  load for months: `canvas: no method for 'not'` and two `established_ok: no such object`. A Pd record
  ends at an **unescaped `,` or `;` including inside a `#X text` comment**, so the RT-6 anti-replay
  note's ordinary English punctuation — *"must be REJECTED, not re-processed"*, *"auth_decode;
  established_ok 0 -> 401"* — broke out of the comment and Pd **dispatched the remainder as messages**.
  **Severity, in both directions, because both matter:** it moved **no check** (`pd` is `756 · 0F`
  before and after; a per-check severity diff against `go` shows its only deficit is 7 `type_system`
  entries, nowhere near the handshake ladder). But it was harmless **only because the words after the
  separators named nothing** — the same defect one word over sends a live message to a live receiver
  (`; net_listen`, `; buf_reset`) at load, and nothing would have reported that either.
  **Enforcement: `protocol-generator/pd/tools/patchlint.py`, a prerequisite of `make external`**, so
  every conformance run of that peer checks it; regression-tested by planting. It is a FILE and not an
  inline recipe because the first cut was inline and Make+shell+python quoting mangled the backslash
  class into one that flagged already-escaped separators — **it reported 6 findings where the truth
  was 1, and a gate that returns the wrong answer is worse than no gate.** Generalize: **before
  trusting a load-time-clean claim, confirm the loader's diagnostics are being kept**, and treat any
  format where comments share a terminator with code (Pd, CSV-ish DSLs, some `.ini`) as executable.
  **RATIFIED 2026-09-08 — THIRD FORMAT, AND THE RULE IS NOW ABOUT THE ENCLOSING CONSTRUCT RATHER
  THAN ABOUT PUNCTUATION.** Pd's terminator is `,`/`;`; a Tcl `switch` body is a LIST so `#`
  between pairs is not a comment (both already recorded); and **a Smalltalk chunk-format `.st`
  embeds every method body in an OUTER string literal, so a single APOSTROPHE anywhere in a
  comment terminates it mid-sentence.** Writing *"§4.7's own reason"* into `EcPeer.st` would have
  done it. **The tell is cheap and it is a MEASUREMENT, not a memory: `HEAD` of that file contains
  zero apostrophes in 700 lines and exactly 38 odd-single-quote lines** — a file whose existing
  prose scrupulously avoids a common English character is telling you the character is fatal.
  Count before and after any edit and require the number to be unchanged. The prohibition is now
  written into the comment that nearly broke it, which is the only place a future editor will be
  looking. *(Second half of the same near-miss, and it is about the EDITOR rather than the format:
  the replacement also lost its doubled `''` string quotes to Python's own quoting and produced
  `code: invalid_request` — syntactically plausible, silently wrong. Both defects were caught by
  READING the written result; the scripted assertion succeeded on both.)*
- **AN AXIS'S PER-PEER GATES ROT EXACTLY WHERE NO COHORT RUNNER REACHES — the NO-GATE column is not a
  list of peers without tests, it is a list of tests nobody runs.** RATIFIED 2026-09-02, and it is the
  entry below (*a second axis with no cohort gate*) proven a second time by its own leftovers. That
  entry closed the S2 sweep at **37 GREEN / 0 RED / 9 NO-GATE** and recorded, in the same breath, that
  *"they probably have no separate codec suite"* was **a hypothesis of the same shape as the four
  claims this ratchet disproved.** It was. **Five of the nine had a real authored S2 surface, and four
  of those five were RED:** `asm-x86_64` (`make diff` — an L2 native-codec differential against the
  3-way-locked corpus, 71 vectors + 4 synthetic — plus parse-test and peers-scope-test), `asm-arm64`
  and `riscv64` (FFI seam KAT + the only `peers`-dimension guard in the tree), `wasm-wat` (three
  authored WAT test modules) and `unison` (a UCM corpus transcript + 15 pinned-invariant self-tests).
  Sweep now **46 GREEN, 0 RED, 0 NO-GATE**.
  **Four failure shapes, none of them visible to S4, and each is its own small lesson:**
  - **A test's stub list can be too COARSE, and then the test's own guard reads as a crash.** The asm
    trio's unit aborts if `grant_scope_ok` reaches a host/FFI extern — correct — but §5.5 put an
    `mcpy` (the peer's own leaf byte-copy) on that path, so it aborted **before printing anything**,
    because `abort()` does not flush stdio. Give the benign leaf a real implementation; keep the
    genuinely off-limits externs (crypto, peerid, `write_all`) aborting.
  - **BISECT THE UNIT, DO NOT ATTRIBUTE IT TO THE LAST INTERESTING COMMIT.** With the crash gone, two
    ACCEPT assertions failed and the obvious culprit was the §1.4 address gate that had just landed on
    exactly these peers. **It was not:** `0d2c45e` never touched `grant_scope_ok`. Measured 11/0 at
    `ab00ccf` and `041443c`, 9/2 from `f3acd7f`, **one line of diff** — `resource_matches` →
    the §5.5a-aware `resources_cover_target`. The fixture granted a bare `*`, which §5.5a makes
    GRANTER-LOCAL, and the synthetic token has no granter: **a test about the PEERS dimension was
    failing on RESOURCES.** The peer was never wrong, and both REJECT directions passed throughout,
    which is why nothing else noticed.
  - **A CROSS-COMPILE FLAG THAT ONE BUILD PATH ALREADY DOCUMENTS.** `riscv64` could not COMPILE its
    unit: the Debian sysroot is multiarch and the Fedora cross-gcc is not, and the peer Makefile calls
    `$(CC)` a *"LINK DRIVER only — no C compiled"*, true of everything except that one target. The
    codec's `riscv64-cross-toolchain.cmake` has carried the exact `-I` with the exact explanation
    since the sysroot was built. **When a build fails on a flag, grep the tree for that flag before
    deriving it.**
  - **A NON-ASSERT FAILURE IN AN ASSERT-CODED HARNESS READS AS A BROKEN BUILD.** `wasm-wat`'s
    dispatch-test died with an out-of-bounds write (`offset 0x00a00000, boundary 0x007fffff`) and no
    code-table entry: `dispatch.wat` keeps its store index at `0xA00000` while the unit grew memory to
    8 MiB. The live peer never hit it because `host.wat` grows to 5632 pages for per-connection
    buffers. **A unit that imports a module authored against a larger memory map inherits that map.**
  - **A TRANSCRIPT THAT NO LONGER TYPE-CHECKS, with the proof sitting in the tree.** `unison`'s corpus
    gate called `ed25519Sign` with two arguments after it became `(seed, pub, msg)`. The committed
    `conformance.output.md` still shows the **old 2-arg signature** while `peer-compile.output.md`
    shows the 3-arg — i.e. the repo contained, in two adjacent files, the evidence that the corpus
    gate had not run since. It now runs **71/71** with its sha check.
  **INHERITANCE MUST BE CHECKED, NOT ASSERTED — and that is what keeps it out of the exclusion trap.**
  The other four (`rust-wasm`, `rust-wasm-wasmtime`, `node-red`, `turbowarp`) genuinely have no codec
  of their own. Their `run-s2.sh` **verifies the dependency edge still exists** (`path = "../rust"`;
  the harness building from `protocol-generator/typescript`) and then runs the PARENT's gate. Fork a
  codec into a seam and the edge check goes RED — which is exactly the moment that peer would have an
  unmeasured codec. Regression-tested by planting a broken edge. **This is how to encode "it inherits"
  without a per-peer exclusion in the measurement tooling** (the `apl` lesson): the claim executes.
  **And two harness rules the peers themselves taught:** a gate must not rewrite a **committed**
  artifact (`ucm transcript X.md` writes `X.output.md`, and those are tracked — a gate that dirties
  the tree is one people stop running, so drive from a scratch copy); and where the runner's exit
  code is 0 for a completed-but-failing suite, **read the output text and print the COUNT** — the
  `smalltalk` `make sunit` defect. My first matcher then found `FAIL` in every transcript, because a
  ucm transcript **echoes its own source** and the source DEFINES the checker as
  `(if ok then "PASS " else "FAIL ")`. Match the rendered RESULT shape, not the word.
- **A "COMMITTED REPO OUTPUT" THAT IS GITIGNORED IS A BUILD THAT ONLY WORKS WHERE SOMETHING ELSE
  ALREADY RAN.** Candidate (`asm-x86_64`, 2026-09-02). Its Makefile header called
  `libentitycore_codec.so` a committed repo output; `ffi-generator/.../.gitignore` ignores `build/`.
  Both ISA siblings have a `codec` target that builds it and x86_64 had none — the link succeeded on
  any machine where another peer had already built the `.so`, and would fail on a clean clone. The
  false comment is what made the missing target look deliberate. **Enforcement: for any artifact a
  Makefile describes as committed, `git ls-files` it** — the same one-line check the `riscv64`
  `reference/typestore/` and `forth` `bin/peer.fs` entries already prescribe, applied to a
  build INPUT rather than an output.
- **AN INSERTED CALL AND THE DEFINITION IT NEEDS MUST BE ANCHORED TO THE SAME SCOPE — AND THE
  OBVIOUS ANCHOR IS IN A DIFFERENT SHELL ON A THIRD OF THE COHORT.** RATIFIED 2026-09-03, folding
  `-reference-peer` into all 46 `run-s4.sh`. Both defects were in MY sweep and both were found by
  running it, not by reading it:
  - **Scope.** The natural anchor for a `. <helper>` line is the harness's own `ORACLE=` default near
    the top. For the **19 peers that re-exec into their container that line runs on the HOST**, while
    the oracle invocation runs INSIDE — so the helper was sourced where `/work` does not exist and the
    function was undefined where it was called. Measured on `c`. **Fix: anchor the definition to the
    CALL SITE, not to the top of the file** — then the scope question cannot be asked wrongly. Same
    reasoning forced the teardown call to be `if command -v f >/dev/null; then f; fi`: the trap is
    installed *before* the helper is sourced, and an `&&` form returns non-zero, which under `set -e`
    aborts the teardown **before the target is reaped** — a helper detail turned into a leaked peer.
  - **A line-start anchor misses exactly the peers that had a REASON to deviate.** Five harnesses
    (`io pd python ruby sql`) write `rc=0; "$ORACLE" -addr … || rc=$?` because their oracle call has
    no `|| true` under `set -e` and the exit code has to be held — the deviation this file already
    documents. A `^"$ORACLE"` pattern skipped all five. **The peers that do not match your template
    are the ones that had a reason not to, so a template-shaped pattern misses them systematically,
    not randomly** — and five reads as "a few odd peers" rather than as a broken pattern.
  **Enforcement, and it is the postcondition rule again: gate the PROPERTY, not the edit.**
  `tools/fold-reference-peer.py --check` (ninth `make lint` gate) re-parses every harness for the
  four properties independently of how they got there, and **prints the count** — 46 of 46 — because
  a sweep that patched zero files prints the same word as one that patched 46.
- **NEW COVERAGE THAT TURNS A PEER RED IS THE COVERAGE WORKING — MEASURE THE BEFORE AND AFTER RATES
  BEFORE CALLING IT ANYTHING.** RATIFIED 2026-09-03 (`io`), and it is the standing *"a fix that raises
  a peer's FAIL count is a finding, not a regression"* rule reached from the coverage side rather than
  the fix side. Folding `-reference-peer` in took 45 peers to `758 · 0F` and `io` to **28F**. The
  temptation is to call a 50%-reproducing failure flaky, or to revert to protect a 46-of-46 row. Both
  are forbidden and the counting is what settles it:
  `pre-fold (756, no reference peer) 0 of 6 FAIL · post-fold (758, with it) 3 of 6 FAIL`, always at
  idx 678 `concurrency/t1_2_concurrent_reentry`, always 28 FAILs with 27 cascading behind one.
  **The three new checks all PASS, at idx 674–676, immediately before the failure** — so the finding
  is not that io fails the new checks, it is that nothing had ever driven io's reentry path
  immediately before the *concurrent* one. Control (reference peer up, origination not executed via
  `-category concurrency`): clean 6 of 6 — which **narrows toward residue over CPU contention and does
  not prove it**, because an isolated category is a different timing regime (the `c` lesson). So it is
  recorded as **NOT root-caused**, which is an honest state; "load" and "flaky" are claims.
  **The rule: a coverage change that reddens a peer gets a before/after RATE on the same host in the
  same session, and the peer leaves the publishable set until it is fixed.** Do not revert, and do not
  publish the passing sample — for an intermittent, cite the rate.
  **CLOSED THE SAME DAY, and the defect was real: A RESPONSE FRAME FOR A DIFFERENT IN-FLIGHT REENTRY
  ON THE SAME CONNECTION WAS SILENTLY DISCARDED.** Two reentries can be live on ONE connection —
  dispatching a non-correlated inbound EXECUTE re-enters `peer dispatch`, and that handler may itself
  call `outboundDispatch` on the same conn. The inner loop saw the OUTER `request_id` on a response
  frame, which matched neither its own rid nor the `system/protocol/execute` arm, and **fell off the
  end of the `foreach`.** The outer could never see that frame again, so it waited out its full
  20-second deadline — and on a single-threaded event loop that starves every connection behind it.
  **This is a §4.9(c) silent drop of a CORRELATED RESPONSE, and it presents as a concurrency/latency
  problem rather than a correctness one** — the same "bills the caller, so it reads as slow" signature
  as the ISA op-ladder and `cobol`'s oversize frame, one layer up. Fix: park a non-matching response
  under its rid for the loop that is waiting on it; check the park on entry and each pass.
  **Measured: pre-fix 3 of 6, post-fix 0 of 12** (p≈0.02% against that baseline), with a per-check
  diff confirming **exactly 1 of 758** severities moved and that one being the known
  `t1_1_concurrent_demux` timing flake (WARN in 5 of the 6 post-fix runs, so the stable row is
  unchanged).
  **Two things generalize.** (a) **The 20-second wall in the failure message was the peer's OWN
  deadline, not the oracle's** — reading which side owns a timeout is what turned "the oracle timed
  out" into "our loop waited for a frame that had already arrived and been thrown away." (b) **Build
  the small reproduction before the fix, not after.** Driving `-category origination` then
  `-category concurrency` against ONE long-lived peer reproduced it in **9 checks instead of 758**,
  in about a minute instead of twenty-five — and it also showed the small form is much rarer (~1 in
  9 vs 1 in 2), which is itself the evidence that accumulated state from the full run is part of the
  trigger. A cheap reproduction that is *rarer* than the real one is still worth having; just do not
  measure the fix with it.
- **RATIFIED — A CONTROL THAT CANNOT BE EXERCISED IS NOT A CONTROL, AND IT REPORTS THE SAME WORD AS
  ONE THAT PASSED.** Two occurrences in one session (2026-09-03), different mechanisms, and both
  produced a confident green from a plant that had never been applied:
  - **The mutation never landed.** A `sed -i 's|…ec_ed25519_sign(...)…|…|'` meant to corrupt a
    request signature died with ``unknown option to `s'`` (the pattern contained `||`), left the
    source UNMUTATED, and the run printed PASS. Caught only because the plant COUNT was checked
    (`grep -c 'PLANTED DEFECT'`) before the result was believed.
  - **The mutation could not reach the code.** `PROOF_FLOOR=99` against a harness that re-execs into
    its container, which did not forward the variable. The floor check ran at its default and
    passed. The gate was fine; the control was inert.
  **Enforcement, and it is one line each: assert that the plant is PRESENT before running the
  mutated case, and prefer a mutation applied by a tool that fails loudly** (python with the anchor
  asserted, not `sed`). For any control that crosses a container boundary, forward the variable
  explicitly and prove it arrived. This is the examined-zero-things class pointed at the regression
  suite instead of at the gate — and a regression suite is exactly where nobody looks for it.
  **THIRD OCCURRENCE 2026-09-04, and it inverts the second: FORWARDING A VARIABLE EXPLICITLY IS NOT
  NEUTRAL — an explicit `-e VAR=<default>` OVERRIDES the callee's own default, so a wrapper that
  "just passes things through" silently decides them.** The rule above says to forward a variable
  explicitly and prove it arrived. `cobol`'s `run-s4-host.sh` — the capped, documented, human-facing
  launcher, and the only `run-s4-host.sh` in the cohort — did forward it, as
  `-e "VALIDATE=${VALIDATE:-0}"`, against `run-s4.sh`'s own `${VALIDATE:-1}`. It arrived. It was
  wrong. **Measured: the documented by-hand entry point reports `312P/337W/0F/109S` and
  `Result: FAIL (un-allowlisted skips)` while the census reports the committed `315P/337W/0F/106S`**
  — the three are `t1_2_concurrent_reentry`, `handlers/validate_echo_dispatch` and
  `origination/dispatch_outbound_reentry`, each SKIPping with *"target peer not run with
  --validate"*. Nothing was wrong with the peer and nothing was wrong with the census. **The two
  entry points disagreed, and the one that was wrong is the one no cohort runner exercises** — the
  standing "an axis's per-peer gates rot exactly where no cohort runner reaches" rule, reaching a
  *wrapper* rather than a gate. It cost the first hour of the session: the baseline looked like a
  three-check regression against the committed report, which is the most alarming thing a baseline
  can do. **Enforcement: a wrapper that forwards `VAR=${VAR:-X}` must use the same `X` the callee
  does, or it is setting policy rather than forwarding.** `grep -n '\-e "[A-Z_]*=\${' ` over any
  launcher and diff each default against the script it invokes; and if a peer has a second entry
  point, run BOTH before trusting either — a baseline that disagrees with the committed report is
  more often the invocation than the peer.
- **A DOCUMENTED CHECK THAT NOTHING INVOKES IS THE 2d ROT PATTERN, AND ITS EXIT CODE IS USUALLY NOT
  THE CHECK EITHER.** RATIFIED 2026-09-03 (`lean`). `lake build EntityCoreProofs` was called *"the
  proof check"* in three of this repo's own documents and **no Makefile, script or harness built that
  target** — `run-s2.sh` built the peer, `run-s4.sh` builds `host`. `AGENTS.md` calls the Lean proof
  vector *"the highest-signal channel"*; it was ungated for its whole life.
  **The sharper half is that calling the tool would not have been enough.** Measured in the peer's
  own pinned toolchain: a `sorry` is a **warning** — `lake` prints `Build completed successfully` and
  **exits 0** — and a hand-written `axiom` substituted for a proof exits 0 with **no warning at
  all**; only a type-check failure is non-zero. **A gate trusting that exit code catches one failure
  mode in three, and misses the two a proof check exists for.** The check is the **axiom set**: no
  declaration may depend on `sorryAx` or on anything outside the Lean-standard three, plus a FLOOR on
  the number of graded declarations, because a module that stops emitting `#print axioms` passes
  every name check vacuously.
  **Generalize past Lean: for any gate that shells out to a build tool, ask what that tool does with
  the failure you actually care about before trusting its exit status** — this is the Gradle
  `UP-TO-DATE` and Maven no-tests lesson in a third package manager, and the answer differed from the
  documented one in two of three cases.
- **A UNIT THAT NOBODY RUNS FAILS IN THE DIRECTION THAT LOOKS LIKE A PEER BUG — AND THE COMMENT
  EXPLAINING WHY IT IS SAFE IS WHERE THE DEFECT LIVES.** Second occurrence 2026-09-03 (`sql`, after
  `apl`), and it closes the S3 axis at 18 GREEN / 0 RED. `sql`'s S3 selftest drove its **post-auth**
  EXECUTEs through a helper commented *"no author/capability — §4.2 pre-authorized"*. That sentence
  is true of the connect path and **false of every request after leg 2**, so the peer answered `401
  authentication_failed` — correctly — and the gate read as a peer regression for as long as nobody
  ran it. It had been red since the §5.5a/§6.2 authority work landed underneath it.
  **The fix is a real request, never a relaxed assertion**, and the shape generalizes to any
  self-driven client: the capability **cannot be rebuilt client-side** (its `created_at` is the
  peer's wall clock, so its hash is unpredictable), so leg 2 must be read **without discarding the
  frame** and its `included` entities copied out and re-presented verbatim. Assert the lifted
  material in leg 2's own line (`cap=33B included=3`) so a leg-2 shape change fails *there* rather
  than silently producing an unsigned leg 3.
  **Two controls, not one, and they must produce DIFFERENT dispositions** — corrupt the request
  signature → `401 authentication_failed`; withhold the grant material → `403 capability_denied`. One
  control would not distinguish "the signature is checked" from "something is checked."
- **A PATH SWEEP'S FALSE NEGATIVE IS THE DIRECTORY AS A SEPARATE STRING — VERIFY THAT PATHS RESOLVE,
  NEVER THAT THE OLD STRING IS GONE.** Candidate, same session, and it is the third false-negative
  grep in this file after the `dart`/`ruby` NUL byte (a grep that could not SEE the file) and F51 (a
  grep in the wrong VOCABULARY). This one is a grep whose PATTERN cannot span the construction. After
  rewriting `test-vectors/v0.8.0/<artifact>` cohort-wide, `git grep 'test-vectors/v0\.8\.0'` returned
  one benign hit and read as done. **Eight harnesses were broken**, because they build the path from
  parts — `File.join(…, "test-vectors", "v0.8.0", "conformance-vectors.cbor")`,
  `Path.join(["..", "shared", "test-vectors", "v0.8.0", name])` — so the sweep rewrote the FILENAME
  (a single token) and left the directory element untouched, and no pattern containing a slash could
  ever match. `crystal` and `elixir` failed outright on the next run; `julia` would have.
  **The check that works is not a better regex.** Resolve every referenced path against disk and
  assert it exists — ~20 lines, runs in a second, and it is indifferent to how the string was
  assembled. Generalize: **after a mechanical rename, verify the POSTCONDITION (the new thing
  resolves), not the ABSENCE of the old token** — absence is a property of your pattern, existence is
  a property of the tree.
  **Two sub-lessons from the same sweep, both cheap and both mine:**
  (a) **A repo-wide sweep must EXCLUDE `spec-data/` by construction, not by remembering.** Mine
  rewrote two SHA-256-pinned boundary files; `make lint` caught it on the next run. This file already
  says *"after any repo-wide mechanical commit … re-verify the SHA-256 spec-data pins"* — that rule
  fired and worked, and this is its **second occurrence**, so the standard is now stricter: the
  exclusion goes in the sweep script's own exclusion list beside `docs/status/` and `docs/archive/`,
  and the pin check stays as the backstop rather than as the only control.
  (b) **`cmd | tail` in a verification loop reports `tail`'s exit code, not the command's.** My first
  agility sweep printed `rc=0` for five peers, two of which had failed outright (`ocaml`: target not
  found; `csharp`: NuGet restore failed). Same family as the gate that examined zero things — the
  loop was structurally incapable of reporting a failure. Use `${PIPESTATUS[0]}`, or do not pipe.
  **RATIFIED 2026-09-02 — second occurrence, and it was committed to this file between them.** The
  first probe of the peers with no S2 gate ran `podman run … "cmd | tail -30"` and reported `rc=0`
  for **all five**; every one had failed — `go` on a wrong working directory, `rust` unable to resolve
  a vendored crate, `python` with no pytest, `typescript` with two real failures, `swift` with a
  compile error. **A written-down rule did not prevent the identical mistake**, which is the argument
  for putting the check in the tool rather than in the prose: `tools/run-s2-sweep.sh` captures each
  gate's status with no pipe at all and says so at the line where it would be tempting. The tell is
  the shape of the result, not the code — **a batch in which every member passes is a claim to
  distrust before reading it**, especially when the members share no toolchain.
- **A `run-*.sh` whose guard tests a CONTAINER path must be INVOKED in the container — and its
  failure is indistinguishable from a missing dependency.** Candidate, and it is the standing
  *"a guard that was never executed is not a guard"* entry met from the caller's side rather than
  the author's. Running the S2 sweep on the host, `prolog` died with `swipl: command not found` and
  `ocaml/run-agility.sh` with `missing /work/ffi-generator/…/libentitycore_codec.so — build the FFI
  codec first` **while that file existed on disk**: `$SODIR` is `/work/…`, the repo's mount point,
  which does not exist on the host. Both scripts are correct; both read as a broken toolchain or a
  missing artifact, which is a diagnosis pointing at the tree instead of at the invocation. Each
  script's header carries the `podman run` line it expects — **read it before believing the error**,
  and prefer `rc=127`/`file missing` as a signal to re-check HOW you invoked it.
  **RATIFIED 2026-09-02, and the fix is uniformity rather than documentation: `prolog`'s `run-s2.sh`
  now re-execs itself into its container like the 21 siblings that already did.** A cohort axis is
  swept by invoking one conventional entry point per peer; the odd one out does not fail *informatively*,
  it fails as `command not found`, which is the single most misleading exit a sweep can produce.
- **A TEARDOWN THAT SIGNALS IS NOT A TEARDOWN THAT WAITS — and when the symptom is a RACE BETWEEN TWO
  DURATIONS, only one of which you own, it is absent on exactly the peers you would test first.**
  RATIFIED 2026-09-02 (cohort-wide sweep, 45 of 46 harnesses). Every `run-s4.sh` tore its peer down
  with `trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT` — fire-and-forget. `kill(1)` DELIVERS a
  signal and returns, so the trap returns, the script exits, and **the peer is still holding the
  listening socket.**
  **The methodological half is the durable one, and it nearly killed the work.** The reported symptom
  was *"a back-to-back invocation in the same container cannot rebind the port."* Reproducing it on
  `go` (5 of 5 clean) and on `zig` (10 of 10 clean at a full `--profile core`) says the defect does not
  exist — and those are the two peers anyone reaches for. The symptom is a race between *how long the
  old peer takes to die* and *how long the next invocation takes to reach its bind*, so a slow build
  step hides it and a fast runtime hides it. **Only one of those two durations is a property of the
  harness. Measure that one.** A probe that connects to the port in a tight loop the instant the
  harness returns answers directly, in one run per peer: `rexx` **never** released it, `elixir` **>400 ms**
  (and the next invocation exited 1, alternating), `julia` **~88 ms**, `smalltalk` **~4 ms**, `crystal`
  `zig` `go` **0 ms**. After: every one of them 0–1 ms. Generalise past ports — **when a reported
  defect will not reproduce, ask whether the symptom is a race you only half own, and instrument the
  half you do.**
  **`crystal` had the correct teardown the whole time and nobody had looked** — the standing *"when a
  scope question has 45 existing answers in the tree, ask them before deriving one"* rule, in the one
  direction that is easy to miss: the cohort can already contain the fix. The sweep propagated
  `crystal`'s function rather than authoring one.
  **Enforcement: `tools/harness-gate.py`, in `make lint`** — exactly one non-comment `trap` per
  harness, it must name a FUNCTION (an inline `trap 'kill …'` is the defect by construction), that
  function must exist, and its body must `wait` on a pid. It deliberately does not gate the signal
  (`python` `ruby` `prolog` chose `-9` deliberately, and SIGKILL + `wait` is correct) or the poll
  bound. It asserts the harness count against the peer roster, so a peer with no `run-s4.sh` is an
  ERROR rather than a silent skip, and it is regression-tested against four planted defects plus that
  vacuity case. It found one on its first run: `crystal` writes `trap 'reap_host' EXIT`, and the
  first cut rejected the quotes.
  **A SWEEP OF 46 HARNESSES IS NOT VERIFIED BY `sh -n`, BECAUSE 11 OF THEM RE-EXEC INTO A CONTAINER
  AND THE EDITED TEXT IS A STRING THERE.** `sh -n run-s4.sh` parses that argument as a literal and
  returns 0 whatever is inside it — so the obvious check covers 35 files and reports 46.
  Reconstructing the block with a regex fails too, and fails *plausibly*: those blocks contain
  `PORT="'"$PORT"'"`, where the outer shell CLOSES the quote, splices a value and reopens it, so a
  scanner that stops at the first unescaped quote captures a fragment and `sh -n` then reports a
  syntax error in text that never existed. **Shim `podman` and let the real shell do the quoting**
  (`protocol-generator/shared/diagnostics/inner-container-script-check.sh`). Its own first cut read
  the argument after a literal `-c` and captured **nothing** for the four peers using `bash -lc`,
  reporting them as "no inner script" — a false clean, which is the same defect class the sweep was
  about. Corollary for any text inserted into those blocks: **not one apostrophe may appear in it**,
  comments included; the rewriter asserts that before it writes anything.
  **`rexx` is the peer that proves the rule, and its two defects were both invisible-by-construction.**
  (a) The listening socket is held by a reparented `ecnet` co-process, not by the harness child, so
  `wait` cannot see it — and the existing cleanup reached for **`pkill -f`, WHICH IS NOT INSTALLED IN
  THAT IMAGE** (nor are `pgrep` or `ps`). `2>/dev/null || true` swallowed the command-not-found and
  the cleanup reported success having reaped nothing, so the daemon survived *every* run and the
  second invocation in a container exited 1 forever. Bisected against HEAD before attributing it —
  identical there, pre-existing. **Generalise: `|| true` on a command that may not exist converts
  "missing tool" into "success", and a cleanup path is where nobody notices.** The fix scans `/proc`,
  which needs no tooling at all. (b) Every diagnostic this peer emits — including its `PEER FATAL
  SYNTAX` handler — was written as `call lineout stderr, …`, where **`stderr` is an unset REXX
  variable and therefore evaluates to the literal string `STDERR`, a FILENAME.** For as long as the
  peer has existed its dying words went to an untracked file in the working tree. **This is the
  cohort-wide keep-the-peer-stderr fix meeting its second half: the harness now preserves fd 2
  faithfully, and this peer was not writing to it.** `'<stderr>'` is the stream (pinned by
  `protocol-generator/rexx/test/stderr-stream-name.rex`, which shows both spellings side by side).
  Neither defect moved a check: `rexx` measured `756 · 313P/337W/0F/106S` before and after, equal to
  its committed report.
  **Verification standard used, and it is the one the sweep rule demands:** every *shape* executed,
  not one representative — `HOST_PID` at top level, `HOST_PID` inside a re-exec block, `PEER`, `PP`,
  `PDPID`, `NR_PID`, the five one-line `cleanup()` peers, and the three hand-edited ones. Six peers
  (`java` `sql` `python` `io` `pd` `rexx`) were run to a full `--profile core` and each reproduced its
  committed row **exactly**; seven more were driven through the port probe.
  **AND THE SIBLING CHECK FOUND THE SECOND INVARIANT: `run-s4.sh [validate-peer-args...]` IS THE
  DOCUMENTED INTERFACE, AND THREE PEERS DROPPED IT ON THE FLOOR.** Noticed because `python`
  rewrote its own tracked `CONFORMANCE-REPORT.json` during a teardown probe that had explicitly
  passed `-json-out /tmp/…`. `python` `ruby` `prolog` hardcoded their entire argument list, so
  `run-s4.sh -category connectivity` ran **756 checks where the caller asked for 25** *and*
  overwrote the signed-off record it was meant to be diagnosed against — the *"a gate must not
  rewrite a committed artifact"* rule, in a harness, with the artifact being the number this repo
  publishes.
  **The five-peer `'"$*"'` splice is the more interesting half, because the prediction was wrong
  and measuring is what corrected it.** `ada` `c` `common-lisp` `java` `kotlin` spliced `$*` into
  their container block, which reads like it flattens argv into ONE argument. It does not: the
  outer shell CONSUMES those quotes and the inner shell word-splits what is left, so ordinary
  flags survive — `java -category connectivity` measured **25 checks**, correctly. So it is a
  latent quoting hazard (any value containing a space, a glob or a `;` is mangled or re-executed),
  not a break. **Say which it is; a hazard reported as a break is as much a misreport as the
  reverse.** All eight now use the `bash -c SCRIPT bash "$@"` form the other four re-exec peers
  (`sql` `io` `pd` `datalog`) already had, where the interpreter word is argv[0] and the caller
  args arrive as `$1..` with quoting intact.
  **A THIRD SELF-AUTHORED EXCULPATION, AND THIS ONE WAS HALF TRUE, WHICH IS WHY IT SURVIVED.**
  `CONFORMANCE-MATRIX.md` §1 disclosed `cobol`'s two extra skips as *"payloads (256 KiB, 16 KiB)
  that its 65535-byte frame cap and 8192-byte per-entity ceiling cannot accept, and it now
  refuses them with `413` rather than crashing."* The 16 KiB one does: it exceeds the per-entity
  ceiling and `handlers.cob` answers a **correlated** 413. **The 256 KiB one exceeds the FRAME
  cap, never reaches any COBOL code, and was answered with NOTHING** — `netshim.c` drained the
  body and kept serving, which is the half of §4.10(a) about the connection, with a comment
  explaining why closing would break the caller's pooled connection, and no trace of the half
  that is a MUST (*"MUST reject … with `413 payload_too_large`"*). **A §4.9(c) drop bills the
  CALLER, so it reads as the peer being slow**: the check reported `i/o timeout` and was filed as
  a capacity skip. Fixed 2026-09-02 (`oversize-result` emits the section's *best-effort coded
  frame*; the `request_id` is unavailable **by construction**, because refusing before decoding
  is the point of the rule, so it goes out empty rather than guessed). `t1_3` now reports
  `tree put status 413`. **The counts did not move** — 756 · 312P/336W/0F/108S before and after —
  which is the whole reason it was safe to believe the row for three days. **A disclosure that is
  true of one of two cases reads exactly like a disclosure that is true.**
  **AND THE CEILING ITSELF IS SPEC-LEGAL, so say what is a defect and what is a bound.** §4.10(a)
  requires only that the maximum be FINITE; the protocol places *"no restriction on entity size"*
  and the 16 MiB frame figure is a SHOULD. The missing 413 was the defect; the capacity is a bound
  — and **a conformant peer can be recorded as FAILING for honouring it**, because the oracle
  scores the resulting refusal as a SKIP and prints *"skip(s) count as FAIL"*. Routed to arch as
  **F53** (`shared/findings/conformance-payload-capacity-floor.md`).
  **RAISING IT TAUGHT THREE THINGS, and the first is the one to carry.**
  - **A CEILING IS A FAMILY, NOT A NUMBER, AND THE FAMILY IS NOT THE LITERAL YOU GREPPED FOR.**
    In COBOL a LINKAGE item is a VIEW over the caller's storage, so a callee declaring
    `pic x(32768)` over a caller's `pic x(8192)` reads 32 KiB out of an 8 KiB field on any
    full-length `MOVE` — **a PARTIAL raise is more dangerous than no raise**, which is why this
    lands as one uniform edit or not at all. And the first pass, keyed on `pic x(8192)`, **missed
    `cbor.cob`'s map-pair value slot, which is `pic x(4096)`** — a second family. That pass would
    have shipped a peer whose handlers accept a 32 KiB entity and whose canonicaliser cannot carry
    one, i.e. a 413 traded for a canon error. **Enumerate the size literals and classify each,
    rather than substituting the one you noticed.**
  - **THE SIZE THAT LOOKS AFFORDABLE IS DECIDED BY WHERE THE BUFFER LIVES.** 512 KiB works
    *functionally* — both probes PASS — and is unusable: `cbor-canon` is **recursive** and its
    per-call `LOCAL-STORAGE` holds a 64-entry pair table, so a 512 KiB value slot costs **~34 MB
    per call per nesting level**. Measured: sustained load dropped **7454 of 10000** requests, the
    category went **15.5 s → 9 m 50 s**, and both robustness checks that had been passing FAILED.
    At 32 KiB the same table costs 2 MB and the suite runs in 55 s. **Before raising a buffer, ask
    whether it is `WORKING-STORAGE` (once) or `LOCAL-STORAGE` in a recursive program (per call, per
    level)** — the same declaration in the two places differs by orders of magnitude.
  - **THE TRADE HAD A LOSING SIDE AND IT HAD TO BE PUBLISHED.** `t1_4` went SKIP → PASS **and**
    `t1_1_concurrent_demux` went PASS → WARN, because the bigger buffers slowed the peer past the
    check's 0.70 concurrent/sequential ratio. Not flaky — **4 of 4 WARN after against 3 of 3 PASS
    before**, counted rather than assumed. The WARN is the *more accurate* label (the oracle's own
    text: *"not a §6.11 violation — informational … for runtimes that do not physically
    parallelize"*), but it still moves a published column, and reporting only the gain would be the
    overclaim. **Verified per-check: exactly 2 of 756 severities moved.**
  **CLOSED 2026-09-04, and the closing move RETRACTS the middle bullet's conclusion while confirming
  its measurement — which is the durable half: A CAPACITY THAT IS UNAFFORDABLE IN ONE DATA STRUCTURE
  IS NOT AN EXPENSIVE CAPACITY, IT IS THE WRONG DATA STRUCTURE, AND THE COST FIGURE CANNOT TELL YOU
  WHICH.** "512 KiB costs ~34 MB per call per level" was correct, reproducible, and led to the wrong
  conclusion, because the ~34 MB was a property of a table that **buffered every map value into a
  fixed per-pair slot** — so the measured price of capacity was really the price of that design at
  that capacity, and it read as a substrate limit. `cbor-canon` now records each pair's canonicalized
  KEY plus the INPUT OFFSET its value starts at, and canonicalizes values straight into the output in
  sorted-key order on a second pass; values are bounded by the output buffer alone. Per call, per
  level: **2.13 MB → 65.8 KB**, i.e. 33× *below* where it started, and the per-value ceiling is gone
  rather than raised. With that, the frame cap is 512 KiB, `t1_3` is PASS, and **the suite is faster
  than it ever was at 64 KiB: 47.9 s → 13–15.7 s over 7 of 7 runs.** The store took the same move for
  the same reason (1024 fixed slots → one arena addressed by offset), which decouples the ONE-entity
  ceiling from the ALL-entities footprint that was multiplying it. **Rule: when a measurement says a
  capacity is unaffordable, ask what is multiplying it before believing the substrate — a per-call ×
  per-level × per-pair fixed slot is three multipliers, and removing any one of them changes the
  answer by orders of magnitude.**
  **The third bullet's trade REVERSED, and that is worth as much as the trade was.** `t1_1_concurrent_
  demux` went WARN → **PASS**, undoing the loss recorded above: the peer got fast enough that the
  oracle's sequential baseline falls under its 50 ms floor and the speedup signal is suppressed.
  Verified the same way it was recorded — **exactly 2 of 758 severities moved, 7 of 7 runs identical,
  no `budget_exhausted`, executed digest equal to the pin.** A published trade is not permanent, and
  re-measuring the losing side after a redesign is part of the redesign.
  **A SECOND SIZE FAMILY EXISTS THAT IS NOT A DECLARATION AT ALL — the NAMED CONSTANT that tells a
  callee how big the buffer it was handed is.** The first bullet says to enumerate the size literals;
  it is not enough, because a mechanical sweep over `pic x(N)` leaves `01 entmax … value 32768`,
  `01 cap-entmax … value 32768`, `01 maxlen … value 20000` and `01 cap65 … value 65535` behind —
  four guards and capacity arguments that were CORRECT at the old sizes and become a silent
  truncation or a false 413 at the new one. `grep -n '<old size>' src/*.cob | grep -v 'pic x('` finds
  them in one line and finding them by test would have meant a `413` on a payload the transport had
  already accepted. **After raising a declaration family, grep for the same number as a VALUE.**
  **And the store geometry was the cheap half, exactly as recorded:** peak occupancy across a full
  run is **116–119 content entries against 1024 slots**, so the arena carries a 264 KB entity at a
  *smaller* total footprint than the 1024 × 32 KiB slot table it replaced (33.6 MB → 8 MiB + offsets).
  **The gate is `tools/harness-gate.py` — teardown AND args, one file, because both are
  invariants of the same interface.** It counts its ANCHORS, not just its failures: `46 wait ·
  46 forward · 11 hand argv across a container boundary`, and that 11 is asserted non-zero and
  independently corroborated by `inner-container-script-check.sh` finding the same 11. Six planted
  defects, and the two arg plants are on DIFFERENT victims (`go` plain, `java` re-exec) because
  the two shapes fail through different mechanisms.
- **THE ONE PEER WHOSE RUN WAS NOT SEALED OFFLINE, AND ITS OWN HARNESS SAID SO IN A COMMENT.**
  RATIFIED 2026-09-02 (`csharp`; third occurrence of the vendored-closure class after
  `dart-toolchain` and `ghc`/`python-toolchain`, and the first where the closure was not vendored
  AT ALL). `run-cohort-census.sh` gave `csharp` a network namespace while all 45 siblings ran
  `--network=none`, plus a host-local podman volume named `kc-nuget`: `dotnet restore` reaches
  nuget.org for the service index **even when every package is already cached**, so
  `--network=none` failed at restore rather than at download. On a machine that had not already
  populated that volume the peer produced `NU1301` and **no report at all**. The discipline that
  made this findable rather than invisible is worth copying: `run-s2.sh` carried the gap in prose
  — *"that is a real gap and it is named here rather than papered over with a comment claiming
  offline operation"* — so finding it was a `grep`, not an investigation.
  Closed the ratified way: the image seeds `/opt/nuget` at BUILD time from the peer's own
  `packages.lock.json` with `--locked-mode`, then **re-restores against an empty source list to
  prove the closure is complete**. Only the `.csproj` + lock files are copied in, never sources,
  so an ordinary peer edit does not invalidate the layer; an added project fails the restore,
  which is the fail-closed direction.
  **I NEARLY PUBLISHED A FALSE GREEN OFF IT, BY THE STANDING MECHANISM.** The first offline S4
  passed — while `obj/` and `bin/` were still on disk from an earlier network-enabled restore, so
  `dotnet` found `project.assets.json` and never re-resolved. **A vendoring fix must be verified
  with the local build state DELETED**, exactly as the `haskell` fix was verified with
  `.cabal-home` and `dist-newstyle` moved aside. Re-measured from clean: S2 24/24, S4
  `756 · 315P/335W/0F/106S`, equal to the committed report.
  **That clean re-run is also what exposed the second defect, and it is a rule about WHERE a build
  requirement lives.** `Microsoft.NETCore.App.Host.<rid>` is published for neither the SDK
  library-packs nor nuget.org, and only the `Host` csproj carried `<UseAppHost>false</UseAppHost>`
  — `Conformance`, `Agility` and `Smoke` relied on **every caller passing `-p:UseAppHost=false`**.
  `run-s2.sh` did. The two `dotnet test` / `dotnet run` commands **published in
  `status/CONFORMANCE-REPORT.md` as the reproduce recipe** did not, and failed offline. The
  property was right and its LOCATION was wrong. **A build requirement that every caller must
  remember is not a requirement, it is a trap** — treat a flag that appears at every invocation as
  evidence it belongs in the manifest. (Both published commands now run offline: 34/34 xUnit,
  71/71 corpus. The published xUnit count said 24.)
  **IT WAS NEVER ONE PEER — THE SAME DEFECT WAS ON THREE MORE, AND THE FIX FOR csharp NAMED THEM AND
  STOPPED.** Closed 2026-09-02, the same day. `typescript` ran `--network=none` but mounted a
  host-local `kc-npm` volume, so it was sealed from the registry and **dependent on a machine having
  warmed that volume**; `turbowarp` ran with a **network namespace** and `npm install` (not `ci`), so
  its conformance result depended on the registry being reachable and on whatever `install` resolved
  that day; `node-red` inherited both through the `typescript` build it delegates to. The closure now
  bakes into `containers/node24` from **all three peers' own committed lockfiles**, proved complete by
  wiping `node_modules` and re-running `npm ci --offline` **inside the image build**, and the census
  mounts no volume — mounting one at `/npm-cache` would shadow the baked closure, which the file says.
  Verified the ratified way, **with the local build state deleted**: `node_modules/` and `dist/` were
  removed from all three before measuring. `typescript` `756 · 315P/335W/0F/106S`, `turbowarp` and
  `node-red` `756 · 313P/337W/0F/106S`, 3/3 comparable at the pinned digest, no network, no volume.
  **The delete is what found the next one down: `typescript`'s S2 gate ran `npm test` directly and
  therefore depended on an UNTRACKED `node_modules/` sitting in the working tree** — from clean it
  died `tsc: command not found`, rc=127. Its `pretest` hook (added earlier the same day to fix a
  build-on-the-past defect) cannot help if the compiler was never installed. **Generalize: a gate that
  assumes a derived directory is a gate on somebody's machine.** `npm ci --offline` now runs first.
  *(`turbowarp` and `node-red` also carried the standing build-only-if-MISSING defect — the exact
  shape that had `node-red` measured against a week-old bundle on 2026-08-28. Installs are now guarded
  on the LOCKFILE mtime and the compile is unconditional.)*
  **One row moved and it is NOT reported as an improvement:** `typescript` measured `315P/335W`
  against its committed `314P/336W`, a single check — `concurrency/t1_1_concurrent_demux`, the
  timing-ratio one, WARN→PASS. Per-check diff confirmed **exactly 1 of 756 severities moved**. Two
  re-runs came back WARN, so the PASS is the outlier, the tracked report was left alone, and no
  banner was regenerated. **A single sample is not a rate**, and the temptation to bank a number that
  went the right way is exactly when that rule matters.
- **FIFTH AND SIXTH OCCURRENCE OF THE EXAMINED-ZERO-THINGS CLASS, AND THE FIFTH IS THE WORST FORM:
  AN INCREMENTAL BUILD TOOL DOES NOT RUN THE SUITE AT ALL.** RATIFIED 2026-09-02. `kotlin`'s S2
  gate was `gradle test --offline` and nothing else. Gradle's entire design is to skip work it
  believes current, so on **every invocation after the first**, sources unchanged, it prints
  `> Task :test UP-TO-DATE` / `BUILD SUCCESSFUL` and exits 0 having executed **zero** tests.
  Measured by running it twice. That is a step below `swift`/`smalltalk`, which at least invoked a
  runner that reported nothing. **Two changes and both are needed:** `--rerun` (task-scoped, so
  compilation still caches) forces execution, and a COUNT parsed from the JUnit XML is asserted
  against a floor — `--rerun` alone still passes a suite that silently lost its test classes, and
  the results directory is deleted first so a stale XML cannot satisfy the floor.
  **`java` is the sibling and needed the same floor for a different reason:** `mvn -o clean test`
  recompiles every time so there is no UP-TO-DATE hazard, but surefire PRINTS `Tests run: 16` and
  nothing asserts it, and **Maven exits 0 when it finds no tests at all**. So the scoping rule is
  not *"does the gate compare a number"* — it is ***which gates delegate to a tool that can
  succeed having run nothing***. Four found so far (Gradle, Maven, `swift test`, SUnit); all four
  are closed.
  **THE PLANTED FLOOR CAUGHT THE COUNTER ITSELF BEING VACUOUS, WHICH IS THE ARGUMENT FOR PLANTING
  IN ONE LINE.** `java`'s first cut ran `podman run … python3 - "$FLOOR"` with the script on a
  heredoc, and **`podman run` does not forward stdin without `-i`** — python read an empty script,
  printed nothing, exited 0. The counter written to prevent a vacuous gate WAS one, it looked
  correct on the page, and only a floor set above reality showed it. *(Sub-lesson for the survey
  side: my heuristic for "which of the other 44 gates assert a count" **mis-binned `smalltalk`**,
  whose assertion lives in the peer's `Makefile`, not in `run-s2.sh`. A survey that reads one
  conventional file cannot see a gate that delegates — do not publish a count from it.)*
- **A SECOND AXIS WITH NO COHORT GATE IS AN EXCLUSION NOBODY DECLARED — and it will be defended by
  the fact that the FIRST axis is green.** RATIFIED 2026-09-02, and it is the `apl` exclusion lesson
  moved up one level: there, the one peer nobody could measure was the one peer the census refused to
  attempt; here, an entire **axis** had no sweep, so the question was never asked of anyone.
  `CONFORMANCE-MATRIX.md` published **46 of 46 at `756 · 0F`** while, on the S2 (codec /
  crypto-agility) axis, **four peers were red or unrunnable and had been for a long time.** S4 has
  `run-cohort-census.sh` plus three gates on its numbers; S2 had nothing, and every defect below sat
  behind that one absence:
  - `haskell` — **unrunnable at all.** Its S2 report claimed *"Offline … verified GREEN"* against a
    warm store in a **gitignored in-tree `.cabal-home`** that one machine had warmed by hand, and only
    for the LIBRARY deps. Once runnable: 1 real FAIL.
  - `smalltalk` — `make sunit` died compiling its own driver, **and asserted nothing about the suite's
    counts regardless** (a red suite printed `failures=3` and the target passed).
  - `ocaml` — `test/selftest.exe` had been **FAILING** on a stale §7a expectation, unswept because the
    peer had no `run-s2.sh` and its one host-invocable script never builds it.
  - `typescript` — `npm test` ran `node --test dist/**` with **no build step**.
  - `python` — its tests `import pytest`, declared as a pyproject `dev` extra and installed **nowhere**;
    the suite had never run in its own image.
  **THREE OF THOSE ARE ABSENCE DEFECTS, NOT RED GATES — the peer had no entry point on the swept path,
  so it was neither measured nor reported as missing.** That is why `tools/run-s2-sweep.sh` reports
  **NO-GATE as a first-class outcome** and prints the count of each; a sweep that silently skips what
  it cannot find reproduces the exact hole it exists to close. Enforcement: `tools/run-s2-sweep.sh`
  (`--gate` fails on RED; `--gate-missing` additionally requires full coverage), driven off
  `peer-tiers.tsv` with **no per-peer exclusions in the measurement tooling** — a peer leaves the sweep
  only by leaving the roster, where its absence reads as backlog. Result at ratification: **37 GREEN,
  0 RED, 9 NO-GATE** of 46. The 9 are the hand-authored / thin-seam / exploratory groups (`unison`, the
  ISA trio, `wasm-wat`, both `rust-wasm`, `node-red`, `turbowarp`); *"they probably have no separate
  codec suite"* is a **hypothesis, and it is the same shape as the four claims this ratchet disproved.*
  **CLOSED the same day, and the hypothesis was wrong: 5 of the 9 had a real authored S2 surface and
  4 of those 5 were RED. Sweep is now 46 GREEN, 0 RED, 0 NO-GATE** — see the *"an axis's per-peer
  gates rot exactly where no cohort runner reaches"* entry above for the four failure shapes and for
  how the remaining 4 encode inheritance as an executable edge check rather than an exclusion.
  **Generalize past S2: for every axis a number is published on, name the sweep AND the gate. An axis
  with a per-peer harness and no cohort runner is one nobody is measuring.**
  **CLOSED 2026-09-02 by ENUMERATING THE AXES — and the enumeration is the artifact, not the sweeps.**
  The S2 entry above was written the same day and stopped at S2. There were **two more**: `run-s3.sh`
  (18 peers, two-direction loopback interop) and `run-origination-core.sh` (31 peers, §10.2/§6.11
  reentry). Neither had ever been run across the cohort. First sweep of each: **S3 12 GREEN / 6 RED,
  origination 16 GREEN / 15 RED** — *half the authored origination gates and a third of the authored
  S3 gates were failing*, while `CONFORMANCE-MATRIX.md` published 46 of 46 at `756 · 0F` and was not
  wrong. `tools/run-axis-sweep.sh` is now the single engine with the axis table as DATA (`--list`
  prints it), `run-s2-sweep.sh`-style copies are not made per axis, and **an axis absent from that
  table has no cohort runner, which is an exclusion nobody declared.** S4 is deliberately excluded and
  says why in the file: it has its own runner plus three gates on the comparability of what it emits.
- **EVERY VERIFICATION AXIS MUST NAME ITS AUTHORITY, AND THE ONE THAT CANNOT IS THE ONE THAT GOES
  STALE.** RATIFIED 2026-09-03, prompted by the operator asking the question nobody in this repo had
  asked in writing: *where did these gates come from, and did architecture specify them?* The answer
  was mostly reassuring and the exception was the whole finding.
  **`GUIDE-CONFORMANCE.md` §7.0 settles the taxonomy** (arch-owned, `guides/` in
  `entity-system-architecture`, pinned `f7d4191d…` in the `v0.8.2.3` manifest and verified
  byte-identical): there are exactly three kinds of artifact — a **`validate-peer` check** authored by
  `entity-core-go`, a **fixture corpus** authored by architecture, and an **impl-internal unit test**
  which is *"that repo, its own concern"* — and it states outright that **"`entity-core-keystone`
  authors none of these"** and that asking keystone for a vector *"asks the scorer to write the exam."*
  Mapped onto our four axes: **S4** is the oracle; **origination** is *the same oracle*
  (`-category origination -reference-peer`) — **not a separate suite at all, but the category a
  single-peer census structurally cannot reach**; **S2** is arch's two vendored corpora plus our
  `type-registry/` drift target, which is explicitly labelled derived and non-normative. **S3 is
  ours**: 17 of its 18 harnesses are hand-written assertions with no oracle behind them.
  **The correlation is the lesson and it is exact: the only axis with no external authority is the
  only axis whose checks went stale.** `apl`'s selftest handed `CapCheckPermission` an absolute path
  where the peer passes the stripped one; `sql`'s never signs its post-auth requests. Both peers are
  `756 · 0F` on the wire. An assertion with an oracle behind it MOVES when the oracle is re-pinned and
  `check_set_digest` makes that visible; **an assertion we wrote ourselves has nothing watching it**,
  so it drifts against the code it exists to check and fails in the direction that looks like a peer bug.
  **And the guide already offers the replacement, which we have never run.** §7's surface map lists a
  **Live peer matrix** — *"integration bugs (handler routing, identity resolution, cross-peer
  convergence) fixtures can't reach"* — verified by `validate-peer -peers <addrs>`. `grep -rn '\-peers '`
  across every harness and tool returns **nothing**. S3 is a hand-rolled approximation of a surface the
  oracle covers properly and we have never measured.
  **Enforcement, and it is a documentation rule because the defect is one of provenance rather than of
  code: an axis in `tools/run-axis-sweep.sh` must carry, in the file, the authority its checks derive
  from — oracle, vendored corpus, or "ours, impl-internal".** An axis that cannot name one is not
  conformance and must never be reported as though it were. Corollary for the reverse direction:
  **before authoring a check here, look for the oracle flag that already drives that surface** — three
  of our four axes are consumption, and the fourth exists partly because nobody checked.
  **AND THE COROLLARY IMMEDIATELY PAID OUT AND IMMEDIATELY BIT: `-reference-peer` IS THE ORIGINATION
  AXIS, AND `-peers` IS NOT THE S3 REPLACEMENT I HAD JUST RECOMMENDED.** Measured 2026-09-03 against
  the reference peer, one flag at a time — the only way to tell these apart, because each flag's
  effect is invisible from its help text:
  | invocation | executed | skips |
  |---|---:|---:|
  | `--profile core` (every census row) | **756** | 106 |
  | `+ -corpus <ecf.cbor>` | 756 | 106 — **no effect; `conformance` is not a core category** |
  | `+ -reference-peer <addr>` | **758** | **105** |
  | `+ -peers a,b` | **200** — a DIFFERENT suite | 38 |
  - **`-reference-peer` adds exactly three checks** (`origination/dispatch_outbound_reentry`,
    `reference_connect`, `reference_ready`) in place of one `origination: skipped` placeholder. **That
    is the whole origination axis.** The census has never passed the flag, which is the only reason
    31 peers carry a `run-origination-core.sh` and 15 do not. Folding it in retires an axis, deletes
    31 scripts, and covers the 15 for free — at the cost of a 756 → 758 re-pin and a 46-peer
    re-census. **A separate harness that exists because a flag was never passed is not an axis, it is
    a workaround with a directory.**
  - **`-corpus` changes nothing under core**, so S2 is genuinely independent rather than a
    hand-rolled duplicate of an oracle category — worth knowing before "simplifying" it away.
  - **`-peers` does not extend a core run; it switches to a 200-check multi-peer suite that is
    ENTIRELY standard-extension surface** — 38 skips across `convergence` (10), `route` (8),
    `relay_source_route` (6), `relay_offline_delivery` (5), `cross_peer_http_subscription` (5),
    `relay_multi_peer` (4), and one FAIL in `relay_offline_delivery_registry` **against go's own
    reference peer** (B not started with `--inbox-relay-registry`). RELAY / NETWORK / SUBSCRIPTION are
    out of scope here, so adopting it would mean measuring what we deliberately do not build.
  **THE PROCESS LESSON IS THE ONE TO KEEP, AND IT IS ABOUT MY OWN OUTPUT.** *"Retire S3 in favour of
  `validate-peer -peers`"* was recommended in writing, with a rationale, hours before anyone measured
  it — and it was wrong in the direction that would have cost the most: it proposed deleting a working
  (if unauthored) axis in favour of one measuring surfaces we do not implement. The standing rule is
  *"verify a routed claim before acting on it, especially the exculpatory half"*, already broadened
  once to *"the exculpation most likely to be wrong is the one WE wrote, because nothing routes it back
  for review."* **Broaden it again: a RECOMMENDATION is an exculpation about future work** — it says
  which effort is unnecessary — and it is read once, acted on, and never re-derived. **Measure the flag
  before proposing the migration.** One `podman run` with four invocations answered it in ninety
  seconds and reversed the conclusion.
  **RATIFIED 2026-09-12 — second occurrence, different shape, and this one was refuted by the
  OPERATOR rather than by us.** The cell census (§5) offered *"could canonicalization move to mint
  time"* as the shape of question worth asking once — hedged as unverified, and still a
  recommendation about a **wire-affecting migration across 46 peers and three ground-up
  implementations**. The objection was one sentence — *the granter is always known at grant
  creation, so both readings freeze the same value* — and checking it case by case took twenty
  minutes: **extensionally equivalent in every single-granter case, and the only divergence is the
  K-of-N root, where the proposed direction is STRICTLY WORSE** (no single granter exists to
  freeze). The bug class it targeted was **already gated** — only one of four layers takes a
  non-local frame, and §5.5a ships three vectors on it. **So the rule is not "hedge the
  recommendation", it is BUILD THE CASE TABLE BEFORE PROPOSING**: the first occurrence was
  reversed by four invocations, this one by seven rows, and in both the artifact that settles it is
  cheaper than the paragraph arguing for it. Strike a withdrawn recommendation **in place with its
  case table** — *"we asked and the answer was no, here is why"* is worth more to the next reader
  than silence, and it is what stops the same migration being re-proposed in a month.
  *(Sub-lesson, cheap and general: **a `PARTIAL … do not cite this total` banner can be a property of
  YOUR INVOCATION rather than of the peer.** An ad-hoc run against a peer started `-open-access` with
  no `--name`/keypair prints exactly that banner, reports `Result: FAIL (un-allowlisted skips)`, and
  inflates passes 314P/336W → 650P/0W via the type-registry matched-if-present effect. Our census logs
  emit `Result: PASS (with warnings)` and no banner — checked, not assumed. I had drafted this as a
  cohort-wide overclaim finding before reading `output/scratch/census-logs/go.log`. **Compare against
  the harness the number actually came from, never against a hand-rolled invocation of the same tool.**)*
- **A RULE WITH TWO INDEPENDENT VARIABLES NEEDS A VECTOR AT THE CORNER — TWO CHECKS THAT EACH COVER
  ONE AXIS READ AS COVERAGE OF THE SURFACE, AND NEITHER CAN SEE THE INTERSECTION.** Candidate (first
  occurrence, 2026-09-07), and it is the first thing the first **Kind C** independent check found, on
  its first roster run. §4.7's 0.8.2.6 note is a table over two variables — connection *state*
  (pre-establishment / established) × *address* (own namespace / foreign) — and pins the corner:
  a pre-establishment EXECUTE naming a **foreign** namespace is `400 invalid_request`, **not** the
  `401 authentication_failed` the own-namespace row takes, because *"a 401 names a remedy that does
  not exist"* for an address no authentication state can fix. The oracle ships
  `execute_before_established_refused` (pre-establishment × own) and
  `dispatch_inbound_foreign_namespace_refused` (established × foreign). **A peer that evaluates
  authentication first passes both** — on the own-namespace input 401 IS correct, and on the foreign
  input it is already authenticated. Measured: **36 of 45 peers answer 401 (or, `sql`, 403) where the
  table pins 400**, every one of them at `756 · 0F`. The 9 that get it right are what make it a
  defect rather than a reading.
  **The diagnostic that generalizes is cheap: for any rule stated as a TABLE, enumerate the cells and
  ask which vector supplies each one.** Coverage is counted per check, and a check names one input;
  a two-variable rule has four cells and two checks can only reach two of them. Do this before
  concluding a surface is covered — "there are checks on this" is an answer about the axes.
  **A DIFFERENTIAL CONTROL MUST VARY EXACTLY ONE THING, AND MINE VARIED TWO — a control that cannot
  separate its own two explanations is not a control, it is a second copy of the case.** The finding
  is only reportable because a differential re-sends the same foreign URI on an ESTABLISHED
  connection: all 36 answer `400 invalid_request` there, so the address IS recognised and the
  ordering is the defect rather than our URI being malformed. **The first cut sent it UNSIGNED** —
  which answers `401 authentication_failed` on any address, because an EXECUTE with no verified
  signer is auth-class by §5.2a — so it returned the identical status to the case it existed to
  disambiguate and discriminated nothing. It read as "the peer does not recognise the URI", i.e. as
  *our* bug, which would have killed a true finding. **Before trusting a differential, name the two
  explanations it is separating and check that only one variable moved.**
  **AND "THE ORACLE HAS NO VECTOR FOR X" IS A CLAIM ABOUT *WHICH* ORACLE — ask the candidate, not the
  pin, whenever a re-pin is in flight.** Same session, and it withdrew half of this finding before it
  left the tree. The check also caught `501 operation_not_supported` (4 peers) and `401
  missing_author` (5 peers) — minted codes on a surface §4.7 declares a *"MUST-emit contract"* — and
  reasoning from the **pinned** oracle, where the covering checks do not exist, that read as a second
  coverage gap and was drafted as one. The **candidate** oracle catches both by name, asserting the
  code and not just the status (`unsupported_operation_on_registered_handler`,
  `execute_before_established_refused`), plus a third of the same class we never drove. So they are
  ordinary cohort debt the re-pin gates, and the honest report is **corroboration between two
  independently authored readings**, not an accusation. This is the standing *"verify the exculpatory
  half"* rule pointed at the accusatory half of my own draft, and it cost one `python3 -c` against a
  report the census had already written.
  *(Sub-lesson, cheap and it silently truncated a 46-peer run: **`nohup cmd &` inside a
  background-task runner exits IMMEDIATELY and the census is killed partway through.** The wrapper
  reports exit 0, the log ends mid-roster with no error, and 17 of 46 peers have JSONs — which reads
  exactly like a completed run of a smaller roster. Let the runner background it; do not background
  it twice. The leftover containers then produced `odin: script file read error: Permission denied`
  on the next run, which is the standing contention signature — a filesystem-permission failure is
  contention until proven otherwise, and it was.)*
  **CLOSED 2026-09-08 AT 46 OF 46, AND THE CLOSING IS A HARDER CLAIM THAN THE FINDING WAS:
  INDEPENDENT CONVERGENCE IS NOT EVIDENCE OF CORRECTNESS WHEN THE TEXT IS EXPLICIT.** The three
  ground-up implementations — `entity-core-{go,rust,py}` — and our own `go` peer, four separate
  lineages, all answered `401` on this row. This repo's standing warning is the opposite one:
  *"a cohort all passing one author's vectors is cohort-consistent, not independent convergence."*
  Here the convergence was genuinely independent **and on the wrong side of a table that names the
  status, the code, and its own reason in one paragraph**, with §1.4 supplying the MUST. Nine
  keystone peers already answered `400`, which is what made it reportable at all.
  **So the rule cuts both ways and the discriminator is the TEXT, not the tally**: agreement among
  implementations is evidence about a spec's SILENCE and evidence about nothing when the spec
  speaks. Where it speaks, AGENTS.md's boundary already decides it — *derive behavior from the
  spec, not from the oracle* — and the honest form of the report is the one used here: implement
  the text, say plainly that four independent implementations disagree, and route the vector ask
  rather than assume the answer. **State the reversal cost when you do it** (25 peers × a
  three-line hoist) so the decision stays cheap to unwind if arch rules the other way.
  **The propagation itself was one shape in 37 languages and that invariance is the evidence.**
  Every peer already HAD the gate, below the §5.2 verdict where it is unreachable for an
  unauthenticated caller — so this was an ORDERING change, not a feature, and the diff is
  hoist-plus-a-note in 33 of them. **Four needed a different shape and each reason is worth
  keeping**: `forth`/`smalltalk` had it one rung down (after authn rather than after authz, a
  smaller move); `pd` took a three-line canvas REWIRE that moves the single existing rung rather
  than adding a second; `prolog`'s lived in a clause reachable only on `allow`, and the old check
  is KEPT as a restatement so the two cannot drift; and `oz` was expressed as the FIRST BRANCH of
  the existing verdict chain rather than as a wrapping `if/else`, because wrapping meant +2 `end`s
  outside and −1 inside a run of eighteen contiguous `end` tokens. **On a substrate whose block
  structure the compiler checks by counting, prefer the edit that changes no counts** — binding a
  pure verdict one line earlier costs nothing observable and cannot be got wrong.
  **Verified the way the ratchet requires and the number is the point: 3 of 34 868 severities moved
  across all 46 tracked reports, all three the same documented `t1_1_concurrent_demux` timing flake,
  two against us and one for.** Reporting only the flattering one would have been the error this
  file records twice; none of the three was banked.
- **A HANDLER PREDICATE MUST ACCEPT EVERY §1.4 SPELLING OF THE PATH, AND THE ONE THE ORACLE USES IS
  THE BARE PEER-RELATIVE FORM.** Candidate (2026-09-08, `asm-x86_64` then ported to three more).
  §4.7's row 10 — *an operation name the responder does not implement, in any state* → `400
  invalid_request` — has to be scoped to the CONNECT handler, because the same unknown operation on
  `system/tree` is `501 unsupported_operation` and on an unregistered path `404 handler_not_found`.
  The obvious way to scope it is to reuse whatever the peer already computed for the address gate,
  and on the asm peers that is `derive_handler`, which strips an `entity://<peer>/` prefix and
  **falls back to `system/tree` for anything else**. `validate`'s `connectURI` is the bare
  `"system/protocol/connect"` — no scheme — so the reuse matched nothing, the peer kept answering
  501, and the build was clean. **A predicate written for one caller's path form is not reusable by
  a second caller with a different one**: the new `uri_is_connect` accepts all three spellings and
  says at its definition why `derive_handler` is not it. Enforcement is the check itself — but the
  cheap tell is that a scoping predicate which never fires looks identical to a peer that has not
  been changed.
- **A CANDIDATE ORACLE CAN MAKE THE DOCUMENTED ENTRY POINT REPORT `FAIL` — AND EXIT NON-ZERO — ON A
  PEER THAT IS 0-FAIL, INCLUDING THE REFERENCE PEER.** Candidate (2026-09-08, and it is a re-pin
  blocker rather than a peer defect). At go `78db4a9` (778 executed) `connectivity/
  connect_ping_before_hello` SKIPs on any peer that does not serve the NETWORK-extension `ping`,
  and that skip is **not** in the §9.0 profile carve-out: the run prints `106 skip(s)
  auto-allowlisted … 1 skip(s) count as FAIL` and ends `Result: FAIL (un-allowlisted skips)` with
  a JSON summary of `0 failed`. **`go` does this too**, which is what makes it upstream's and not
  ours — and checking `go` first is the whole diagnostic, one run against the reference peer
  instead of an investigation into the peer in hand. The blast radius is the five harnesses that
  propagate the oracle's exit code rather than `|| true`-ing it (`io pd python ruby sql`): those
  will exit 1 on a green run the moment the pin flips. **Route it with the re-pin; do not raise it
  as a peer finding, and do not paper over it by adding a `|| true` — the harnesses that hold the
  exit code hold it deliberately.**
- **A PER-PEER ENTRY POINT ONLY WORKS THE WAY ITS AUTHOR HAPPENED TO INVOKE IT, AND NOTHING FINDS
  THAT UNTIL SOMETHING INVOKES IT DIFFERENTLY — this one class was 15 of the 21 failures across two
  axes.** RATIFIED 2026-09-02, and it is the third and largest occurrence of the shape already
  recorded for `prolog`'s `run-s2.sh` (*"a `run-*.sh` whose guard tests a CONTAINER path must be
  INVOKED in the container"*). **Fourteen** `run-origination-core.sh` were inside-container-only and
  died from the host with `cd: /work/...: No such file or directory`; `prolog` added `swipl: command
  not found`. Every one of them named the correct `podman run` line **in its own header comment** —
  the invocation was documented and not executed. Fixed by making each script re-exec itself into the
  image its header already named; 15 RED → 0 in one pass, verified by running every one.
  **Two things generalize.** (a) **The defect is invisible to the author by construction**: it only
  appears under an invocation the author never used, so it cannot be found by reading, only by
  sweeping. (b) **`rc=127` and `cd: No such file` are the signature** — both read as a broken tree or
  a missing toolchain, i.e. they point the reader at the peer instead of at the call. Enforcement:
  every per-peer entry point is invoked by its axis sweep from the host, so a new one that is
  container-only fails the first time the axis runs. *(Sub-lesson: `go`'s was a different bug wearing
  the same clothes — it mounted `protocol-generator/go/output/s4-oracles`, a path that has never
  existed, and failed with `statfs`. Do not batch-classify by exit signature alone; read each log.)*
- **A REFERENCE BUILT FROM A SIBLING CHECKOUT'S HEAD IS AN UNPINNED INPUT DECIDING A VERDICT — and
  it can be a DIFFERENT REPO than the one you think.** RATIFIED 2026-09-02 (`ada`), and it is the
  content-anchor rule ([ADR-0012] Am. 1) reaching the one axis nobody had swept. `ada`'s `run-s3.sh`
  did `go build ./entity-peer ./probe-peer` out of `$HOME/projects/entity-systems/entity-core-go`,
  printed the HEAD it used, warned if the tree was dirty, and carried on. Measured: that directory is
  **a different line of history altogether** — branch `main`, remote `digi`, subjects *"testing
  validate continuation refinements"* — in which the pinned commit `f313028` **does not exist**. The
  canonical sibling is `<keystone>/../entity-core-go` (what `oracle-bootstrap.sh` defaults to) and it
  has the pin. So the gate reported `[FAIL] session established (§4.1 handshake) — authenticate
  failed`, which reads as an `ada` defect and is not one: pointed at the pinned artifacts it is
  **GREEN, 3 check-groups, both directions**.
  **The fix is to consume `output/s4-oracles/`, never to build a reference** — those artifacts are
  content-anchored and `oracle-bootstrap.sh` hard-stops rather than falling back silently. `datalog`
  and `sql` already did this; `ada` was the only S3 harness that did not. **`probe-peer` joined the
  pinned set in the same commit**, because the reason `ada` was building its own was that the pinned
  set carried a reference *responder* and no reference *client* — **if the reference peer is pinned,
  so must be the reference client**, or the gap gets filled by whatever is on the disk.
  **Enforcement: `git grep -n "entity-core-go\|GO_ORACLE" -- "protocol-generator/*/run-*.sh"` must
  only ever match a COMMENT.** A harness that names the sibling repo at all is one that can build
  something the pin does not describe.
- **A UNIT THAT NOBODY RUNS GOES STALE UNDER A PEER THAT KEEPS GETTING FIXED, AND IT FAILS IN THE
  DIRECTION THAT LOOKS LIKE A PEER BUG.** RATIFIED 2026-09-02, two peers, both at `756 · 0F` on the
  wire while their own S3 selftests were red — which is the inverse of the standing *"a check that
  passes can be passing for a reason unrelated to what it tests"* and just as misleading.
  - `apl`: `[FAIL] permission check ALLOWs system/tree:get`. The assertion passed
    `CapCheckPermission` the **absolute** `/{peer}/system/tree` while `DispatchInner` passes
    `StripLocal pattern` and the fixture grants the handler **relatively** (`CapGrant('system/tree')`).
    An absolute path cannot match a relative grant, so the unit could only ever deny. This is the
    `cobol` id-scope lesson exactly — *an id is compared literally, and the value handed to the
    matcher decides everything* — sitting in a test that had not run since the peer took that fix.
  - `sql`: `[FAIL] 404 unregistered path → status=401`. The selftest sends its post-auth EXECUTEs
    through a helper commented *"no author/capability — §4.2 pre-authorized"*, which is true of the
    connect path and false of everything after it. The peer correctly answers
    `401 authentication_failed`; the unit never signs. It passed while the peer was more permissive
    and has been red since the §5.5a/§6.2 authority work landed under it.
  **Enforcement is the sweep — there is no static form of this.** A stale unit compiles, runs, and
  reports a confident failure about the wrong thing. What made both diagnosable in minutes was
  reading the peer's OWN call site for the function under test and comparing argument shapes, and, for
  `sql`, **printing the disposition CODE next to the status**: `401` is nine different sites in that
  file and `401 authentication_failed` is one. **A gate line that prints only a status is a gate line
  that will be misread** — the code costs one field and names the branch.
- **AN IMAGE THAT RESOLVES THE LIBRARY CLOSURE AND NOT THE TEST CLOSURE LOOKS COMPLETE — the peer
  builds, and only the GATE is missing its dependencies.** RATIFIED 2026-09-02: second and third
  occurrence of the `dart-toolchain` class (*"any image that vendors a dependency closure must derive
  it from the tree's own lockfile"*), and the new half is **which** closure.
  - `ghc-toolchain` vendored **nothing**; the header claimed a resolve step that did not exist. The
    closure lived in a gitignored `.cabal-home`, and `cabal test --offline` died with fourteen
    `refusing to download the package` lines. Fixed by seeding `/opt/cabal-home` at image-build time
    from the peer's **own** `cabal.project.freeze` **with `--enable-tests`** — that flag is the entire
    defect: an unqualified `cabal build` resolves the library only.
  - `python-toolchain` installed `requirements.txt` and stopped. pytest was declared under
    `[project.optional-dependencies] dev` and installed nowhere. **A declared extra nobody installs is
    a dependency that does not exist.** Fixed with a hash-pinned `requirements-dev.txt`, kept separate
    from the runtime lock so the shipped closure stays one dependency, and installed in the image from
    that file — never from a restatement of the pins in the Containerfile.
  **Both prove completeness AT IMAGE BUILD**, by re-resolving `--offline` after the seed: an
  unsatisfiable lockfile fails the image, which is the right place to find out. **Enforcement: for any
  peer whose gate needs deps the peer itself does not, run the gate from a tree with the local caches
  MOVED ASIDE** — `haskell` was verified with both `.cabal-home` and `dist-newstyle` renamed, because
  "it works here" is not the question an adopter asks.
- **A TEST SCRIPT THAT DOES NOT BUILD IS A GATE ON THE PAST.** Candidate (`typescript`, 2026-09-02),
  and it is the standing stale-build-artifact rule reaching the *test runner* rather than the artifact.
  `package.json` had `"test": "node --test dist/test/**"` with no compile step, so `npm test` graded
  whatever was last built. Measured: `dist/test/corpus.js` still named
  `test-vectors/v0.8.0/conformance-vectors-v1.cbor` — a directory **and** a filename both retired in
  the 2026-09-01 de-versioning — while `test/corpus.ts` had been correctly updated the same day; 2 of
  65 failed against a day-old build of correct source. Fixed with npm's `pretest`/`preconformance`
  hooks; 65/65. **Enforcement: read every peer's test entry point for a build step, and treat its
  absence as a defect even when the suite is green** — green is what it looks like right up until the
  source changes. (`node-red`, which rebuilds `dist/` only when `index.js` is MISSING, is the same
  shape already recorded.)
  **AND THE SAME CLASS HAS AN mtime-GRANULARITY FORM THAT NO `--force` FIXES.** The first full S2 sweep
  reported `elixir` RED with the source plainly correct. `mix` compares source mtime to artifact mtime
  at **one-second resolution** and treats equal as up-to-date; the restored file and its `.beam` both
  read `07:57:15`, so the previous build's code ran. `mix compile --force` did not help (different env);
  only `rm -rf _build` did. **The direction that matters is the opposite one — the same mechanism
  yields a false GREEN after a fix.** When a result contradicts a change you just made, suspect the
  cache before the code, and `stat -c %Y` both sides.
  **RATIFIED 2026-09-04, second occurrence, and the new shape is that the STALE THING IS THE SOURCE:
  `cp -a` PRESERVES mtimes, so restoring a saved tree after building something else in between hands
  the build system a source file OLDER than the objects compiled from a DIFFERENT version of it.**
  The bisect pattern this file prescribes everywhere — save the work, `git checkout --` to HEAD,
  build, measure, restore — is what creates it: save at 07:11, build HEAD at 07:13 (objects now
  07:13), `cp -a` the work back (source is 07:11 again), rebuild → **cmake reports success and
  recompiles nothing**, and the binary under test is HEAD's. Measured: the codec leak fix appeared to
  change the leak rate not at all (22.7 MB/suite before and after), which is exactly the reading that
  says "your hypothesis was wrong, abandon it". `touch`ing the sources and rebuilding took it to
  **flat — zero growth after the first suite**. **The fix was correct and the measurement said
  otherwise for a reason that had nothing to do with either.**
  **Two rules, and the second is the one that scales.** (a) **After restoring a saved tree, `touch`
  it** — or copy with `cp` rather than `cp -a`, since only the metadata preservation is harmful here.
  (b) **A build step that reports success is not evidence it BUILT anything** — this is the
  examined-zero-things class in a compiler: `cmake --build` prints the same `Built target` whether it
  compiled four files or none. Grep its output for the compile lines you expect (`Building C object
  .../ecf.c.o`) and treat their absence as a failed rebuild, exactly as a gate must print its count.
- **THE §2.4a NEGATIVE HALF NEEDS A CONSTRUCTOR, NOT AN ASSERTION — a refusal observed through the raw
  primitive is the bypass the rule exists to forbid.** RATIFIED 2026-09-02 across five peers.
  `hash-format-sha-384.2` was **inverted upstream**: it used to assert that re-hashing the fixture
  `system/peer` under `content_hash_format = 0x01` SUCCEEDS; §4.5a **item 1a** pins `system/peer` to the
  ECFv1-SHA-256 floor **unconditionally**, so the construction cannot exist and the vector now asserts
  the refusal. The corpus's `verifier_requirement` is the load-bearing clause — *"The refusal MUST be
  observed through the pinned peer-entity constructor"* — and every harness that touched this vector
  called the **raw digest function**, which is exactly the hand-built bypass that let a forbidden
  construction score green. So the work is a **peer change, not a test edit**: separate the §4.5a
  AUTHORING entry point from the digest primitive and refuse there — `haskell`
  `ContentHash.authorContentHash` (routed through by `Identity.identityOfSeed`, so the pin is a
  constraint the peer EXECUTES rather than a property it happens to have), `ocaml`
  `Peer_identity.build_peer` (result-typed; `~home` kept so the caller must still say what it is
  authoring under), `csharp` `Entity.Create`, `elixir`/`ruby` `Hash.author_content_hash`.
  **The guard goes on the AUTHORING path ONLY** — the receive path recomputes under the format an
  entity declares, which is wire acceptance and a separate surface item 1a does not speak to.
  **Two corollaries, and the second is the wider one.** (a) `ocaml` and `csharp` had carried this as a
  *comment saying it was owed* — the standing "a deferral comment is a conformance claim with no gate
  on it", in a file whose whole job is to be the gate. (b) **`elixir` and `ruby` dispatch on the
  vector's `kind` and both ended in `_ -> []`, so when upstream changed the kind from
  `content_hash_under_format` to `construct_reject` the branch SWALLOWED it** — no gate, no skip, no
  message, and the suite reported the same confident green having never asked. An unhandled kind is now
  a named FAILURE in both, and `haskell` asserts the corpus's full id set. **Enforcement: a
  corpus-driven harness must fail on a vector it cannot drive, and a name-driven one must assert the
  corpus's id set** — the count is the only thing that distinguishes "all pins pass" from "the pins I
  happen to know about pass" (`elixir`/`ruby` went 34 → 36 gates, which is what said the vector was
  being asked at all).
- **MAINTENANCE TIERS ARE ACTIVE — do not run a 45-peer census for a re-pin.** (Turned on
  2026-08-17; the policy existed as prose since ~15 peers and was never honoured, because §4
  named 17 peers of a 46-peer cohort so "re-run Tier-1" was undefined for the other 29.) The
  rule now: **an oracle re-pin is landed when `M1` is re-run and 0-FAIL** — `go` `haskell`
  `lean` `ocaml` `swift`, 5 peers. `M2` (8) catches up behind it, `M3` (13) on spare
  capacity / pre-release / adopter ask, `probe` (18) when its own axis is touched, and
  `exploratory` (2) never gates. **Run everything only before a release** — tiering governs
  the cadence *between* releases, never what a release claims, and it never affects whether a
  peer may be published ("no green report → no publish" is unchanged for every tier).
  - **Roster: `tools/peer-tiers.tsv`** — the single canonical home, all 46 peers, one tier
    each, plus the oracle pin each peer's current verdict was measured at. `CONFORMANCE-MATRIX.md`
    §1's `Maint.` column mirrors it; §4 explains it. Nothing else defines a tier.
  - **Commands:** `tools/tier-status.py` (where every peer stands; `--gate` exits non-zero
    unless M1 is current and 0-FAIL) · `tools/run-cohort-census.sh --tier M1` ·
    `--tier M1,M2` · `--stale` (only peers behind the current pin). A tier run gates **only
    the peers it ran**, or the exit code stops meaning anything.
  - **`M` is a deliberate prefix.** These are NOT `research/LANDSCAPE.md`'s tiers 1–5, which
    classify the *language landscape* ("what is worth building"). Both used to be bare
    `1`/`2`/`3` and were routinely conflated. They do not correlate — verified: `ocaml` is
    landscape Tier 5 and maintenance **M1** (lowest pull, highest discovery yield);
    `rust`/`python` are landscape Tier 1 and maintenance **M2**; `lean` is **M1** and does not
    appear in `LANDSCAPE.md` at all.
  - **A stale lower tier is a tracked state, not a failure.** Record it, don't panic-fix it:
    `tier-status.py` prints `STALE@<pin>` for any peer behind the current `ref`.
- **Lean proof vector** (the highest-signal channel): build the conformant peer first, then
  prove selected invariants in Lean — a proof needing an unstated hypothesis is an
  under-specified precondition (→ `A-LEAN-*` finding), a counterexample is a spec defect.
  Prove what's feasible; an unprovable-here-but-spec-sound invariant is a documented scope
  boundary, not a failure. Distinguish **soundness from completeness** in every theorem
  (conformance vectors never flag that gap); the proof covers the authority *logic interior*
  — crypto, the IO/concurrency shell, and the adversarial-input parser stay owned by KATs,
  race tests, and fuzzing. Ship the peer mathlib-free; proofs live in a `proofs/` target.
- **Visual/dataflow paradigms: author the protocol IN the language, don't wrap it.** A peer whose
  §6.5 collapses to one delegated `dispatch(frame)` call with a few façade blocks is a *wrapper*,
  not a paradigm probe — the logic must be visible on the canvas/graph (FLOW-DESIGN's wrapper-guard).
  **Foreground the *actual algorithm*, not a cosmetic proxy for it:** a §6.6 handler resolution belongs
  on the canvas as the visible *tree walk* (repeat-until, longest-prefix-first), not hidden in a seam
  `resolve()` call behind a literal `if pattern == "system/tree"` ladder — the switch reads as naive
  name-matching and buries the real mechanism (the remaining pattern→body switch is a genuine Scratch
  limit — no call-proc-by-dynamic-name — so label it as body-selection, not resolution).
  Draw the FFI seam at what the substrate *genuinely* can't do (bytes/maps/sockets/crypto/store), and
  author the rest (the §6.5/§5.2 *sequence*, status codes, op-switch, guard ladders). Values the
  substrate can't hold ride as **opaque handles**; readable fields are plain reporters. **Decomposing
  the folded logic surfaces bugs** (both Node-RED #31 and TurboWarp #32: a single collapsed dispatch
  hid real conformance defects — e.g. a folded §5.2 verdict masked the single-401 grantee carve-out,
  chain-depth-before-authz, and unchecked revocation). **Verify without the real runtime** via an
  **oracle-driven interpreter of the actual authored artifact** (TurboWarp: `run-blocks.mjs` runs the
  real `project.json` block graph vs `validate-peer`) — faithful, low-risk, a real number each
  iteration; the real-VM run is the final confirmation caveat. Frame-cap (§1.6) is load-bearing on a
  single-threaded substrate: an oversize frame stalls the peer and cascades into downstream timeouts.
  **Legibility needs decomposition into *named units*, not just "on the canvas"** — one 400-block
  tower is as unreadable as the code it replaced; split into a short dispatch *spine* + one
  procedure/subgraph per handler (Scratch `define …`; `stop this script` in a proc is the
  early-return, the spine's `stop` after the call ends dispatch). **Cooperative yielding between
  requests is load-bearing for connection-churn (§6.11 t2_2) on a single-threaded interpreter** — a
  serial queue-drain flushes no responses until it finishes, so under rapid open→handshake→close the
  oracle tears connections down before their response lands → *dropped requests* → a cascade of
  downstream failures. Yield to the event loop between hats (`await setImmediate`; the model real
  Scratch already uses — one script-step per tick) and it's solid. Diagnostic discipline: heavier
  per-request work (authoring a hot handler) only *exposes* this latent scheduling bug, it isn't the
  cause — prove it by reverting the suspected handler and re-measuring (delegated-connect *also*
  failed t2_2; the serial drain was the real root). The full **field survey + when-to-stop verdict**
  lives in `protocol-generator/shared/evaluations/visual-paradigms.md` (all THREE paradigms now probed — **Pure Data
  (#33) closed the reactive-patch track at full-gate `Result: PASS` on the real runtime**, the only
  visual probe to do so). Pd's adds: **the transport belongs in the seam when the runtime's own
  primitive is disqualified at source level** (`[netreceive]` broadcasts every reply, no per-conn
  id — structural, not inconvenient; the dispatch/verdict logic stays on canvas); **§6.11 reentry on
  a single-threaded canvas is a bounded synchronous send+wait on the SAME fd** (non-response frames
  hand back to the connection's assembler — behavioral presence, not architecture, is the contract);
  and per-request transient state as single-owner seam globals is safe ONLY under one-frame-fully-
  dispatched-before-the-next serialization (the reactive twin of Scratch's no-thread-locals).
- **Content-addressed mint timestamps: ms precision is CORRECTNESS, not formatting** (A-PD-016). A
  token is `{grants, grantee, granter, created_at}` — second-truncated `created_at` makes same-scope
  same-second mints hash-identical, so the oracle's revoke probe aliases the session floor cap and
  the marathon 403-cascades (isolated category runs stay green; only the full profile exposes it).
  Sibling trap: the **open/debug seed needs `resources: ["*", "/*/*"]`** — §5.5a bare-star is
  granter-local, never universal, so without the absolute all-peers form the seed can't cover
  foreign namespaces and universal_address_space silently skips (A-PD-017).
- **Authority IS a query; the protocol around it is a state machine (the declarative-query/logic
  frontier, now closed).** SQL (SQLite) + Datalog (embedded Ascent, bottom-up/terminating) both land
  `682·0F Result: PASS @ cc1970f` authoring the §5/§6.6 interior *in the query language*: §5.2 ladder,
  §5.5 delegation closure (recursive CTE / recursive rule to least fixpoint — the SecPAL/Binder shape),
  K-of-N (`HAVING count(DISTINCT)` / counting aggregate), §6.6 (`ORDER BY length DESC` / stratified
  negation). Everything *pure-function-of-the-projected-facts* fits — often more legibly than the prose;
  everything *stateful-sequential* (§6.5 dispatch, §4 handshake, framing/crypto/store) leaks to the
  host. The wrapper-guard is what makes it a probe not a wrapper, and it held **through S4** on both:
  completing the S4 handler surface added **zero** imperative allow/deny — the verdict never migrated out
  of the authored interior (that absence is itself the datum). Two spec-shaped findings (F40 typed
  §3.6 scope matching, surfaced by SQL as a real ALLOW bug; F41 the §5/§6.6 decision surface is a
  monotone deductive system → an authority-as-derivation appendix makes fail-closed + the §5.5a
  within-grant conjunction *structural invariants* not silently-violable MUSTs). Logic-substrate impl
  trap: **a bottom-up engine dedups DERIVED tuples but not pre-seeded EDB**, so K-of-N distinctness needs
  an explicit IDB copy-rule before the count — silent if missed, and only the accept path exposes it
  (pairs with the rejection-only-oracle vacuous-green lesson) (A-DL-012). Full synthesis:
  `protocol-generator/shared/evaluations/authority-as-query.md`.
- **Oz: a non-ASCII byte baked into a compiled string constant can crash the peer at
  runtime, not at compile time.** `ozc` accepts a literal containing U+00A7 (`§`) inside a
  `"..."` string with zero warning, but concatenating it into a live error message via `#`
  (e.g. `"§6.2: ..."#Pattern`) made the register-reserved-pattern fix (2026-08-17,
  register-guard session) crash the request handler with an internal `Tell: 403 = 500`
  unification failure inside the shared `OutErr` helper — which kills the connection and
  cascades into ~100 unrelated FAILs across every later category in the same run (broken
  pipe / i/o timeout), reading as a huge regression rather than the one bad string it was.
  Isolated by A/B: the identical `OutErr`/`#`-concat call shape with an ASCII-only literal
  is clean every time; only the `§`-bearing literal reproduces the crash. No prior OutErr
  call site in this peer had ever put a non-ASCII literal into a runtime string (grep-
  verified), so this was never hit before. Root cause not fully traced past "a U+00A7 byte
  inside a compiled Oz string constant" — worth a real trace if a second peer or a second
  non-ASCII literal hits the same class; until then, treat any non-ASCII byte in an Oz
  runtime string constant as suspect and keep the citation ASCII (`"section 6.2: ..."`) in
  wire-visible text, reserving `§`-style citations for source comments (never compiled to
  a runtime value, confirmed safe) (A-OZ-008).
- **RATIFIED (second occurrence, different shape — promoted off the candidate ladder):
  a non-ASCII byte in a WIRE-VISIBLE string can crash a peer's own encode path,
  independent of language/substrate.** Io hit this independently on the same
  register-guard work (2026-08-17): a `"§6.2: ..." .. pattern` error message crashed
  `EntityCodec encode` with `ec: encode_error: text Sequence is not valid UTF-8 (bytes
  must ride EcBytes)` inside the hand-rolled `utf8_valid()` C validator
  (`protocol-generator/io/src/entitycodec/IoEntityCodec.c`) — even though the emitted
  bytes (`0xC2 0xA7`, confirmed via `od -c` on the source file) ARE valid UTF-8 by
  manual trace of that exact validator's own logic, and the oracle's reserved-pattern
  vector (`system/validate/core-register-forbidden`, `entity-core-go`
  `cmd/internal/validate/core_register_gate.go`) is plain ASCII, ruling out the dynamic
  `pattern` operand as the source. Root cause not traced further than that (same
  standard as A-OZ-008 — flag, don't over-invest); the peer is single-threaded, so the
  uncaught exception killed the whole process and cascaded `connection refused` across
  every later category (104 FAILs from ONE bad string, `Result: FAIL` on the first
  run). Isolated by the same A/B this class always uses: swap `§6.2` for ASCII
  `section 6.2` in the wire string only (keep `§` in source comments, which are never
  encoded) → `Result: PASS`, `0 failed`, both target checks PASS, no other line
  touched. **Discipline, cohort-wide, effective now:** treat any wire-VISIBLE string
  literal (an error `message`, any field the codec will CBOR-text-encode and send) as
  ASCII-only until a peer has a *proven* non-ASCII wire round-trip test; `§`-style
  spec citations stay confined to comments in every peer regardless of language,
  authoring convenience or the sink language's own claimed encoding correctness — Oz's
  string constant was independently corrupted at compile-time, Io's own UTF-8
  validator rejected byte-correct UTF-8, two peers, two unrelated compilers/encoders,
  same failure shape. No enforcement grep yet (both instances were caught by the
  peer's own `run-s4.sh`, not by static analysis) — a candidate lint would be
  `grep -RP '"[^"]*[\x80-\xff]' protocol-generator/*/src` scoped to fail()/err()/
  Out_Err()-style wire-message call sites specifically, not comments.
- **`tools/run-cohort-census.sh` reuses on-disk build artifacts by design (`NOBUILD=1` /
  build-only-if-missing) — invalid the moment source changes were verified inside an
  ISOLATED WORKTREE rather than the primary tree.** Found 2026-08-17, W-REGISTER-GUARD
  closeout: the primary tree's post-remediation census reported fresh `FAIL` on
  `core_register_reserved_*` for `rust-wasm`/`rust-wasm-wasmtime`/`node-red` — all three
  already individually verified PASS during their own fix session. A1 (trace before
  theorize): `rust-wasm`'s `out/peer.wasm` mtime was **three weeks older** than the
  source fix that supposedly produced it — `run-cohort-census.sh` hardcodes
  `NOBUILD=1` for both wasm peers (their `run-s4.sh` skips `make peer`/`make aot`
  entirely under that flag), and `node-red`'s `run-s4.sh` only rebuilds the shared TS
  `dist/` if `dist/src/index.js` is *missing*, never if it's merely stale — so both
  reused a binary/bundle built **before** the fix existed, because every batch agent
  that fixed these peers worked in a separate `git worktree` with its **own**
  gitignored build cache (`target/`, `dist/`, `out/`) that a `git merge` of tracked
  source files never touches. Root-caused, not assumed: confirmed via `stat` mtime
  comparison before forcing a rebuild, not by re-running and hoping. **Fix applied**:
  force-rebuilt all three in the primary tree (`make peer`/`make aot` outside
  `NOBUILD`, one `npm`/`tsc` pass for the shared TS `dist/`), re-ran, confirmed 0
  FAIL. **Discipline: after any isolated-worktree fix lands via `git merge`, a
  peer whose build output is a gitignored cache (not source-derived at every
  `run-s4.sh` invocation) needs an explicit rebuild in the primary tree before its
  next census run is trustworthy — a clean `--profile core` verdict from
  `run-cohort-census.sh` right after a worktree-based fix is NOT evidence the fix
  reached the tested binary; check the artifact mtime against the source fix's
  commit time first.** First occurrence — candidate, not yet a second-shape
  confirmation for promotion, but the enforcement point is concrete: `stat -c %Y`
  the peer's build output vs `git log -1 --format=%cI` the peer's fixed source file,
  before trusting a census FAIL as real for any peer just merged from a worktree.
