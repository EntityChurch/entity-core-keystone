
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
- **`output/scratch/census/` is NOT scoped to the last run — stale per-peer JSONs from earlier
  censuses sit beside the fresh ones.** A `--tier M1` run leaves the other 40 peers' files untouched,
  so `grep -l budget_exhausted output/scratch/census/*.json` returns the `asm`/`riscv64` trio from a
  *previous* census and reads exactly like "this run starved." Scope every census-wide grep to the
  peers the run actually measured (or check mtimes) before drawing a conclusion from it — the
  starvation check itself is mandatory and unchanged, but it must be asked of the right files.
- **A source grep is not a conformance census.** The bucket-B RT-6 audit was grep-derived
  and was wrong in both directions once measured: `ruby` was listed as having no
  established-gate yet returns 409; `sql` carries the 409 string yet returns **200**;
  `rust-wasm`/`rust-wasm-wasmtime` carry neither string yet return **401** (they are thin
  transport seams over the `rust` crate and inherit its fix — corroboration, not independent
  data points). Ask the running peer.
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
  `tools/oracle-pin.env` (**`95edd774…` = 755 checks @ `c1b0708`**; was `8537d875…` = 740 @
  `de8f807` — the two are NOT comparable, so never diff a row across a re-pin), and hard-fails on any
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
