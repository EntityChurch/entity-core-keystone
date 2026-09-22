# Containers and build — keystone memory

Podman images, pinned dependency closures, offline sealing, and the stale-build-artifact family.

**Arrive here when:** a build works here and nowhere else, an image will not rebuild from scratch, or a fix did not reach the artifact under test.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- A blanket `
- A STALE-BUILD-ARTIFACT CARRIER YOU HAVE NOT MET YET IS THE ONE THAT WILL READ AS "THE FIX DID NOT REACH THIS PEER"
- AN ENUMERATED IGNORE LIST FAILS OPEN, AND THE OMISSION IS ALWAYS THE NEWEST ARTIFACT
- A "COMMITTED REPO OUTPUT" THAT IS GITIGNORED IS A BUILD THAT ONLY WORKS WHERE SOMETHING ELSE ALREADY RAN
- THE ONE PEER WHOSE RUN WAS NOT SEALED OFFLINE, AND ITS OWN HARNESS SAID SO IN A COMMENT
- AN IMAGE THAT RESOLVES THE LIBRARY CLOSURE AND NOT THE TEST CLOSURE LOOKS COMPLETE — the peer builds, and only the GATE is missing its dependencies
- A TEST SCRIPT THAT DOES NOT BUILD IS A GATE ON THE PAST
- `tools/run-cohort-census.sh` reuses on-disk build artifacts by design (`NOBUILD=1` / build-only-if-missing) — invalid the moment source changes were verified inside an ISOLATED WORKTREE rather than the primary tree
- Pin dnf packages to Koji, not just an exact NVR
- AN IMAGE NOBODY REBUILDS FROM SCRATCH IS NOT A RECIPE, IT IS A LOCAL ACCIDENT — and the layer cache is what hides that from the machine that authored it

---

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

- **AN ENUMERATED IGNORE LIST FAILS OPEN, AND THE OMISSION IS ALWAYS THE NEWEST ARTIFACT.** Candidate
  (2026-09-17). `protocol-generator/c/.gitignore` names `conformance` `smoke-bin` `entity-peer-c`
  `typereg-bin` `spike` — and not `scope-bin`, a later Makefile target, so a **3.1 MB ELF executable
  was committed** and nothing objected. Found when `make clean` inside an axis sweep **deleted a
  TRACKED file**, which is the only signal such a mistake produces. Same shape as the root `**/bin/`
  allowlist that swallowed `forth`'s entrypoint, in the opposite direction: there an omission HID a
  source file, here it PUBLISHED a binary. **Enforcement: a scan over the git BLOBS at HEAD for an
  ELF/Mach-O/PE magic, with the read count asserted equal to the listed count.**
  ⚠ **AND THE FIRST FORM OF THAT SCAN WAS VACUOUS ON THE ONE FILE IT WAS CHASING** — it read the
  WORKING TREE, where the binary was already deleted, so `open()` failed, the file was silently
  skipped, and it printed `0 tracked native binaries` over a tree that had one. **A scan of tracked
  files must read them from git, not from disk, or a deleted-but-tracked file is invisible by
  construction** — and asserting `read == listed` is what turns that from a silent skip into a stop.

- **A "COMMITTED REPO OUTPUT" THAT IS GITIGNORED IS A BUILD THAT ONLY WORKS WHERE SOMETHING ELSE
  ALREADY RAN.** Candidate (`asm-x86_64`, 2026-09-02). Its Makefile header called
  `libentitycore_codec.so` a committed repo output; `ffi-generator/.../.gitignore` ignores `build/`.
  Both ISA siblings have a `codec` target that builds it and x86_64 had none — the link succeeded on
  any machine where another peer had already built the `.so`, and would fail on a clean clone. The
  false comment is what made the missing target look deliberate. **Enforcement: for any artifact a
  Makefile describes as committed, `git ls-files` it** — the same one-line check the `riscv64`
  `reference/typestore/` and `forth` `bin/peer.fs` entries already prescribe, applied to a
  build INPUT rather than an output.

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
