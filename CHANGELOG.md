# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Work since the initial public research-preview. No release has been cut; this section is a
running record, not a version claim. **`CONFORMANCE-MATRIX.md` is the authoritative per-peer
state** — the entries here are a summary of what moved and why, and they defer to it on numbers.

### ISA host hardening ported (2026-08-30) — `asm-arm64` and `riscv64` reach `313P/336W`

`asm-x86_64`'s four `host.s`/`dispatch.s` hardenings went across to the other two ISA peers, so all
three now sit on the same row: the child closes the **inherited listen fd**; a **30 s socket idle
deadline** bounds a connection waiting on bytes that never arrive; the **§4.10(c) admission bound**
caps live connection children at 64 and refuses the rest by close; and the **§4.10(a) oversize path**
answers `413 payload_too_large` immediately rather than draining the declared body first.

- `r3_connection_flood` WARN → PASS on both. **Exactly one check moved on each peer**, verified
  per-check before against after; both stay `755 · 0F`.
- **This was ISA parity, not catch-up.** `r3_connection_flood` was WARNing on 44 of 46 peers with
  only `asm-x86_64` and `pd` self-bound, and is now 42 of 46. §4.10(c) is a SHOULD that most peers
  delegate to the supervisor; the cohort-wide finding is unchanged.
- **The admission counter has to be reaped twice** — before the blocking `accept4` *and* after it
  returns. The first reap runs before the parent parks, so children that exit while it is parked are
  still counted as live when it wakes; at the bound that makes a working cap present as a dead peer.
- **On RISC-V the bound is a value comparison, not a compare-then-branch-on-flag**, since the ISA has
  no condition-flags register — the same restatement §5.6 rule 3's overflow test needed.
- §4.10(a)'s "reject *before* fully buffering" forbids the drain that reads as the more polite
  choice: draining a declared body to keep the stream framed is the fully-buffering the section
  forbids, one buffer at a time.

### ISA type-registry scope (2026-08-30) — **a correct fix that lowered a published pass count by 282**

The last unambiguous defect behind a green row is closed. `asm-x86_64`, `asm-arm64` and `riscv64`
published ~200 type-registry entries including whole standard-extension vocabularies — `compute/*`,
`system/registry/*`, `clock/*`, `continuation/*`, `relay/*`, `query/*` and more — against the
standing rule that a core peer never pre-publishes them. The oracle scores non-floor types
*matched-if-present*, so those entries had been converting **282 `type_system` WARNs into PASSes**.

- **`src/typestore.s` is now filtered to the 53-name core floor.** `asm-x86_64` `595P/54W →
  313P/336W`; `asm-arm64` and `riscv64` `594P/55W → 312P/337W`. All three remain `755 · 0F`, and all
  three now sit on the cohort-standard row instead of above it.
- **The pass count falling by 282 IS the fix.** Verified per-check on each peer, before against
  after: exactly 282 checks changed, every one in `type_system`, every one PASS→WARN, and nothing
  outside that category moved. The three remaining severity deltas against `go` are all pre-existing
  and named elsewhere. A higher pass count from a scope violation is not better conformance.
- **The scope filter belongs at the point of publication, not in the harvest.** These peers have no
  data model to reflect a registry over, so the store is harvested byte-exact from the *reference*
  peer — which is a full peer and serves every extension vocabulary. The harvest is left intact as
  evidence of what it serves; `gen-typestore.py` filters, carrying the floor as a fail-closed
  **keep-list** (a drop-list would silently publish whatever a future harvest adds, while a missing
  floor type is a loud hard FAIL).
- **`riscv64`'s harvest input had never been committed** — 0 files tracked, not gitignored, simply
  absent — so its generator could not run from a clean clone and its `typestore.s` was an artifact
  with no in-tree input. Now committed; all three regenerate byte-identically from their own copy.

The floor was corroborated exact rather than assumed: `rust python haskell ocaml swift java c
typescript` publish a set byte-for-name identical to `go`'s 53, with no extension vocabulary in any
of them.

### `apl` was never unmeasurable (2026-08-30) — **45 → 46 of 46, the cohort closes for real**

Filed hours after the entry below, which claimed the cohort was closed at 45 with `apl` excluded
"for an upstream toolchain reason." That claim was wrong in three independent ways, and each was
checkable in under a minute:

- **GNU did not delete `apl-1.9.tar.gz`.** It reorganized `gnu/apl/` into per-version
  subdirectories when 2.0 shipped. `ftp.gnu.org/gnu/apl/apl-1.9/apl-1.9.tar.gz` answers **HTTP
  200**. The 2026-08-27 investigation checked six mirrors, found the *flat* path 404 on all of
  them, and read that as deletion — but every mirror carries the same reorganization, so six
  agreeing sources were six copies of one observation. **A path change and a deletion look
  identical from a single URL, and mirroring does not make the sample independent.**
- **The image was not unbuildable.** It had been moved to APL 2.0 on 2026-08-27 and **built
  successfully on 2026-08-28**. Nobody ran the peer against it.
- **The census hard-coded `apl) ... rc=125`**, so the one peer nobody could measure was the one
  peer the census would not attempt. The exclusion removed the only thing that could falsify it.

One harness invocation produced a valid 755-check measurement in 109 s. Final:
**`755 · 0F — 311P/338W/0F/106S` at digest `95edd774…`**, measured twice by two destinations of the
same tool and agreeing byte-for-byte. `check-set-gate.py --tracked` reads **46 / 46**.

**Seven of the 8 failures were cohort classes this peer had sat out**, including the §6.2
reserved-pattern register guard that reached 44 of 45 peers on 2026-08-17 — `apl` was the sole
omission, and the label is why. Two are worth naming:

- **The F40 id-scope pair reproduced `cobol`'s two-defects-holding-each-other-up shape exactly.**
  `handlers`, `operations` and `peers` are ID-scope (§5.2/F40) and must match literally; all three
  were being canonicalized, so an include of `/{local}/get` authorized the bare `get` while an
  exclude of `/*/get` denied it. Removing the canonicalization alone takes every CAP check to 403,
  because the handlers dimension was separately compared as the *absolute resolved path* against
  grants that name handlers relatively. Neither defect is visible while the other stands.
- **The §6.3 400 branch existed and was unreachable.** `OnFrame` had the
  `400 non_canonical_ecf` response ready, but the `WirePeek` that recovers the `request_id` used the
  strict decoder, so a tagged frame bailed two lines earlier and was dropped on the floor. The
  cohort-standard salvage decode took CAP-6a from WARN to PASS on all six variants and cut the run
  from 149 s to 89 s — the dropped frames had been billing each caller a full timeout. **A refusal
  that exists but cannot be reached is a §4.9(c) silent drop.**

**The rule, ratcheted in `AGENTS.md`: an exclusion is a claim with an expiry date.** This one
asserted a fact about someone else's web server, was never re-checked, survived the repair of its
own cause, and was enforced by the tool that would have disproved it — while silently converting a
published headline from a measurement into an assumption. `run-cohort-census.sh` now carries no
per-peer exclusion at all; a peer can only leave the census by leaving the roster, where
`tier-status.py` reports it.

*Also corrected here: `AGENTS.md`'s ratified lesson "an upstream tarball can be DELETED, not merely
superseded" rested on this false premise. The conclusion — record the digest, prefer an archive —
survives; the evidence for it does not, and the entry now says so.*

### The cohort closes (2026-08-30) — 41 publishable peers → **45 of 45 measurable**

*(Superseded the same day by the entry above: it was 46 of 46, and `apl` was measurable. Left in
place because the four peers below are accurate and the wrong premise is the more useful record.)*

The last four peers reached `755 · 0F` at the pinned check set. `apl` remains unmeasurable for an
upstream toolchain reason (GNU deleted the pinned tarball), which is not a conformance state.

**Two of the four had been misdiagnosed, and saying so is the point of this entry.**

- **`cobol` 30F → 0F — 24 of the 30 were a cascade.** `tree-handler` copied the wire entity into a
  fixed 8192-byte field with the length computed from wire offsets and no test between the two. A
  16 KiB `tree.put` — the oracle's own staging payload — overflowed it, glibc's `_FORTIFY_SOURCE`
  **terminated the peer**, and every check after that reported connection-refused. Two more copies
  of the same shape were reachable from the wire. All three now bound before the copy and answer a
  status. **The peer's oversize-frame path was correct throughout**, which is exactly why the defect
  survived: `resource_bounds` passes, so "oversize frames are handled" reads as evidence. The
  in-range path was the one without a guard. Underneath sat five real defects, including a
  `created_at` that was a compile-time constant and an id-scope dimension that was being
  canonicalized — which overgranted *and* over-denied at the same time.
- **`asm-x86_64` · `asm-arm64` · `riscv64` INVALID → 0F — the "connection-pressure family" never
  existed.** These three were quarantined for months as starved runs. The cause was a §4.9(c) silent
  drop: the op-routing ladder compares an operation's *length* before its bytes, `ping` collides
  with `echo` at length 4, and that branch returned without writing any frame. Every
  connection-churn cycle ends with a `ping`, so every cycle burned the caller's full 20 s read
  deadline; the suite's 10-minute budget expired at cycle 29 of 100 with nine categories never run.
  `concurrency`: 599 s → 1.1 s, 6/6. **A silent drop is billed to the caller, so it presents as the
  peer being slow rather than wrong** — five separate investigations of the peer's health all
  correctly found a healthy peer. `CONFORMANCE-MATRIX.md` §1a carries the retraction with the
  superseded measurements left intact.
- **All three ISA peers also gained the full §5.5 delegation chain**, §5.6 attenuation, §5.5a
  framing, §3.6 K-of-N and the §6.2 mint ceiling, ported from `wasm-wat`. Their CAP-5/CAP-6 failures
  were never the mint: both checks present a *delegated* capability and were refused two gates
  earlier by a fail-closed root-trust placeholder. `asm-arm64` and `riscv64` came back
  severity-identical on all 755 checks.

**Disclosed rather than closed.** The ISA trio still over-publishes extension type vocabularies, so
their `594-595P/53-55W` is a scope violation and not better conformance than the cohort-standard
`312P/337W` *(closed later the same day — see the ISA type-registry scope entry above)*;
`asm-arm64`/`riscv64` never received `asm-x86_64`'s §4.10(c) admission bound (a SHOULD,
scored WARN); `cobol` cannot accept two concurrency probes' payloads and now refuses them with `413`
instead of crashing. **45 of 45 is cohort-consistency, not independent convergence** — one
generation lineage, one author's vectors, one pinned check set.

### The CAP propagation (2026-08-28) — 13 publishable peers → 39 of 45

One unimplemented spec feature, measured across the cohort, now closed everywhere it could be
closed. §5.6's MIN_DEFINED mint ceiling was absent in **every** peer — `mintToken` set no
`expires_at` at all — and no conformance vector exercised it until the 2026-08-21 re-pin.

- **36 languages, one fix shape, unchanged.** Roughly 200 lines over five or six files, in the
  same five places every time: capability mint, codec salvage decode, wire `400`, read loop,
  policy lookup. **That invariance is the evidence the spec reading is right**, not merely that
  the tests pass — a reading that needed 36 different shapes would be 36 different readings.
- **Two peers were carrying more than the CAP trio, and both surfaced the same way — fixing a
  wrong denial made the FAIL count go UP, and the new failures were the truth.** `sql` went
  2F → 7F → 0F: a §5.5a scope-canonicalization bug had been denying every delegated capability,
  and that wrong denial was answering five checks it had nothing to do with — the peer had no
  chain-attenuation rung at all and no §6.2 mint-bound check anywhere. `datalog` was the same
  shape via an `entity://` URI-parsing defect. **When a fix raises a peer's FAIL count, do not
  revert to protect the row.**
- **A partial implementation of a new rule is worse than its absence.** `nim` was the only peer
  that already had a §5.6 ceiling, and it was wrong three independent ways: ttl-only, so a minted
  token outlived the capability authorizing it by ten years; the clock sampled twice, so the
  emitted `created_at` and the expiry derived from it were different instants; and an overflowing
  ttl wrapped to an *earlier* expiry instead of dropping the term. All three still returned `200`
  with a plausible-looking `expires_at`. **MIN_DEFINED is a value reached by construction, not a
  bound verified by comparison** — grep for a comparison against the clamped value and treat a
  hit as unimplemented.
- **Three peers in the count were never broken.** `rust-wasm`, `rust-wasm-wasmtime` and
  `node-red` are thin seams over `../rust` and the `typescript` engine, both fixed 2026-08-22.
  They were measured against build artifacts a week older than the source they compile: the
  census hardcodes `NOBUILD=1` for the wasm peers, and `node-red`'s harness rebuilds only when
  its bundle is *missing*, never when it is merely stale. Forced rebuild → 0F, first try.
- **`tools/tier-status.py` was applying its reverify overlay unconditionally** — the identical
  defect `check-set-gate.py` was fixed for six days earlier, in the file beside it, reading the
  same directory. Three reports from a retired pin therefore outranked the fresh census
  indefinitely. Overlay now applies only when newer, and says so on stderr when it skips one.
  **When two gates disagree about which peers are green, suspect the input before the peers.**
- **`tools/status-banner.py`** generates each peer's prose `CONFORMANCE-REPORT.md` banner from
  that peer's own committed JSON, and refuses to write one from a report that is not at the
  pinned check set. A per-peer number that publishes now gets written by a tool that reads the
  measurement, not by a person reading the measurement.

**What remains is six separate problems, not one shared debt:** `cobol` 30F (its standing
liveness cascade), the `asm-x86_64`/`asm-arm64`/`riscv64` trio (INVALID measurements, a
connection-pressure family), `wasm-wat` 2F and `turbowarp` 3F (hand-authored / exploratory,
unstarted), and `apl` (upstream-blocked, unmeasured). None of them is the mint ceiling.

### Release readiness (2026-08-23) — the published tree is what we actually claim it is

No peer changed and no number moved. This was the pass that asked, for the first time, whether the
tree a reader receives matches the tree we describe — and the answer was no in eight places.

- **Every published number is anchored on a CONTENT DIGEST, not a commit** ([ADR-0012] Amendment 1).
  Published commits are authored fresh at the release boundary, so a hash from our internal history
  resolves for no outside reader — and it had already fired: the matrix on public `master` anchored
  its 665-check counts on an oracle commit that exists in no repo in the ecosystem, killed by a
  mirror history rewrite six weeks earlier. (Naming that commit here would repeat the defect this
  entry describes, which is how it got into the ecosystem standard's own copy.) The three anchors are now
  published beside the numbers with the reproduction recipe; `tools/pin-gate.py` gates against the
  column reverting to a commit and against a hand-copied digest drifting from `tools/oracle-pin.env`.
- **A fresh clone built the WRONG oracle and exited 0.** `oracle-bootstrap.sh` fell back to a public
  commit whose check set is missing the three `capability` checks that are this release's entire
  finding, printed a NOTE, and installed it — so an adopter got a clean build, a green run, and 32
  peers passing that the matrix says fail. An anchor mismatch is now a **hard stop, exit 3**. A
  second bug in the same script compared the install against itself and reported agreement.
  All 46 peer harnesses gained a preflight; they had been exiting 0 with no oracle present.
- **The 25 spec findings now publish.** `SPEC-FINDINGS-LOG.md` is declared canonical, ships, indexes
  every finding and calls one a front door — and every document it named was being deleted from the
  public tree. They moved to `protocol-generator/shared/findings/` under undated names, with an
  index. Two of them were already dangling from *published* peer status docs at paths that had not
  existed for weeks.
- **Nine more named-but-deleted files** — four diagnostics and five cross-cutting paradigm surveys,
  moved to `protocol-generator/shared/{diagnostics,evaluations}/`. One of them was printed by
  `check-set-gate.py` at runtime as the reader's next step.
- **Eight already-public top-level files were one release from silent deletion** — `AGENTS.md`,
  `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` and four more sat undeclared under a keep-list
  the repo had documented as a scrub-list. Declaring them is the whole fix.
- **`docs/STATUS.md`** — the rolling log moved out of `docs/status/` and publishes again; the dated
  snapshots beside it do not. Separable by path rather than by filename.
- **New gate:** `tools/link-gate.py` (in `make lint`) resolves every relative markdown link against
  disk. Nine gates ran across this repo and the release pipeline and none asked whether a published
  document points at something a reader can open.
- **Two internal-token leaks** removed from files that already publish.
- **README** corrected a self-contradicting peer count and a cohort breakdown that accounted for 43
  of 46 peers.

### Tier M2 complete (2026-08-22) — **13 of 45 peers publishable**, and the CAP-6a fail-open has two mechanisms

- **Tier M2 is 8/8 at `--profile core` 0-FAIL**, so M1 and M2 are both complete and **13 peers are
  publishable, up from 5.** `rust` `python` `java` `kotlin` `elixir` at `755 · 0F —
  312P/337W/0F/106S`; `common-lisp` at `755 · 0F — 311P/338W/0F/106S`; plus `typescript`
  (`312P/337W`) and `csharp` (`313P/336W`). All six new reports are check-set-comparable with zero
  `budget_exhausted` categories.
- **`typescript` (84F) and `csharp` (INVALID) were ONE defect, not two.** Both were §6.3's missing
  `400 non_canonical_ecf`; the only difference is what the peer does with the connection after
  refusing. `typescript` **closes** → every later check fails instantly → 84F on a valid, complete
  755-check run. `csharp` **drops and holds the connection open** → every later check waits out a
  timeout (CAP-6a alone: 120 060 ms) → budget expires, 9 categories never run → quarantined as an
  INVALID measurement with a *smaller* FAIL count (52). **The hang-form is strictly harder to see:
  it scores lower and files under "harness problem."** The diagnostic that resolved it was cheap —
  compare the first-FAIL index and first-transport-error index against a peer known to carry the
  defect; identical (558/559/560, onset 563) means same bug. `csharp`: 18 m 20 s → **7.2 s**.
- **CAP-6a's fail-open has TWO mechanisms, and the grep that catches one misses the other.** M1
  found only the first. **Null-collapse** (`rust`, `python`, `elixir` + all five M1 peers): the
  accessor answers the same "nothing" for absent and for present-but-negative, so the check is
  **skipped**. **Arithmetic fail-open** (`java`, `kotlin`, `common-lisp`): `Cbor.uint` returns the
  `BigInteger` of *any* int, `entity-uint` is `(when (integerp v) v)` — a negative flows straight
  through, so the check **is not skipped; it runs and returns the wrong answer**, because
  `now < not_before` is false for a negative `not_before`. No null, no `Option`, no skip. **The
  invariant is the ordering, not the null-handling:** a representability check must run *before* the
  range comparison in either shape. Both greps are named in `AGENTS.md`.
- **§6.3 is not optional even when the FAIL count is already zero.** `rust` and `common-lisp` reached
  0F while still scoring CAP-6a **WARN**: the `>2^64` half can only arrive as a major-type-6 tag and
  is rejected at decode, so it needs the §6.3 answer to be *scored* as a refusal at all.
- **The fix shape did not change once across thirteen languages** — ~200 lines over 5–6 files, the
  same five places (capability mint, codec salvage, wire 400, read loop, policy lookup). That
  invariance is itself evidence the spec reading is right, not merely that the tests pass.
- **Tooling fix:** `check-set-gate.py`'s `output/scratch/reverify/` overlay was **unconditional**,
  and that directory is scoped to neither a run nor a pin. Three reports left there on 2026-08-17 at
  the retired 740-check pin outranked the fresh 755-check census indefinitely,
  condemning `node-red`/`rust-wasm`/`rust-wasm-wasmtime` as non-comparable — **7 bad peers reported
  where the truth was 4**, on four-day-old evidence. The overlay now applies only when *newer* than
  what it would replace. **An input that predates what it supersedes is not an override, it is drift.**
- **Committed per-peer reports had drifted a pin behind the matrix — found AND fixed this session.**
  Every tracked `protocol-generator/<lang>/status/CONFORMANCE-REPORT.{md,json}` was at the retired
  740-check set or older (38 at 740, 4 at 682, 1 at 645, none at 755); several `.md` files still led
  with two-pins-ago banners quoting `552`/`576` totals. §1 of the matrix was never wrong —
  it is census-backed — but **a clone showed each peer's own committed report contradicting its
  published row**, and nothing gated those files. The cause was structural, not an oversight:
  `run-cohort-census.sh` deliberately never writes tracked reports (a census must not silently
  rewrite 45 signed-off records) and `output/` is gitignored, so no driver could refresh them.
  **Fixed three ways:** `run-cohort-census.sh --to-status` adds the missing destination to the *same*
  per-peer dispatch table (explicit opt-in, never the default — a second copy of that table is how
  the destinations would drift apart again); all **13 publishable peers were re-measured** against the
  pinned oracle, each reproducing its published number exactly (13/13 comparable); and
  `tools/check-set-gate.py --tracked` — now run by `make lint` — fails if a peer published as 0-FAIL
  carries a report from an older check set. Regression-tested by planting a 740-check report on `go`.
  That gate also fixed a real bug of its own: `collect()` keyed reports by path stem, and every
  tracked report is named `CONFORMANCE-REPORT.json`, so 45 peers collapsed to a single entry.
  The 32 unfixed peers' reports remain behind **by design** — they owe the *fix*, not the paperwork,
  and rejoin the gated set as the CAP fix reaches them. **Refreshing a tracked report is a
  MEASUREMENT — never hand-copy a census JSON onto one.**

### Release re-pin (2026-08-21) — both anchors moved, **M1 fixed, re-pin landed, full cohort re-measured**

- **Spec snapshot re-pinned `v0.8.0` → `v0.8.2`** (`protocol-generator/shared/spec-data/v0.8.2/`,
  a verbatim `cmp`-verified copy from `entity-core-protocol`, SHA-256-pinned per file in the snapshot's `MANIFEST.md`). **No peer has been
  regenerated against it yet** — that is a tracked gap; `pd`'s F37 `system/identity/peer-id` debt
  (3 files, the only peer affected, grep-verified) is its one known consequence.
- **`GUIDE-CONFORMANCE.md` is now pinned by hash** (`7d59fee6…`, `Status: Draft`) in that
  snapshot's `MANIFEST.md`. It stays out of `spec-data/` (non-normative, arch-owned), but
  "operator-carried" meant *unpinned* while every generated peer derives its conformance
  scaffolding from it — so no generation was reproducible. Now it is.
- **Oracle re-pinned — the 740-check set `8537d875…` → the 755-check set `95edd774…`.** 18 declared checks added; **5 gate `--profile core`,
  all in the `capability` category** (CAP-5, CAP-6, CAP-6a, CAP-2/3, CAP-7), the other 13
  extension-only. Attributed by resolving each check to its category *constant* and testing that
  against `coreProfileCategories` — never from commit messages. `core_gate_fingerprint` stayed
  byte-identical for the **fourth** consecutive time in this shape.
- **`--tier M1` re-run: all 5 peers FAILED, and all 5 were then FIXED** — `go` `haskell` `lean`
  `ocaml` `swift` now sit at **`755 · 0F — 312P/337W/0F/106S`**, identical across the five.
  `tools/tier-status.py --gate` exits 0; **the re-pin is landed.**
- **The failures were never regressions — they were a spec feature nobody had implemented.** §5.6's
  MIN_DEFINED temporal ceiling was **absent in every peer**: `mintToken` set no `expires_at` at all,
  so a `request`-minted ROOT token had no lifetime bound. No vector exercised it until this pin.
  Three defect classes came out of the fix, each ratcheted in `AGENTS.md` with an enforcement point:
  **(1)** §6.3's *"Rejection returns `400 non_canonical_ecf`"* — every peer rejected an undecodable
  frame and then said nothing, and on a peer that closes, one bad frame kills the connection (that
  is `lean`'s 81 cascade FAILs, and `typescript`'s 81); **(2)** CAP-6a fails **OPEN** because the
  idiomatic accessor collapses "absent" and "present but not a uint", so a capability with
  `expires_at: -1` skipped the expiry check and was honored with 200 — three of five peers;
  **(3)** `swift` only, §5.5a's per-link granter frames scope the **resource dimension only**, and
  over-applying them made a universal parent grant cover no child grant the moment a delegated cap
  arrived.
- **Full 45-peer census then run at that pin** — so every cell in `CONFORMANCE-MATRIX.md` is a
  fresh measurement at one pin, and the two-pin split is gone. **31 of the 40 unfixed peers fail
  nothing but the new CAP checks** (29 at exactly 3F with a byte-identical breakdown, 2 at 2F):
  **one missing feature measured 31 times, not 31 defects.** `typescript` 84F is 3 real + 81
  cascade (lean's defect); `cobol` 30F is the CAP trio plus its standing 27. **Four peers produced
  INVALID MEASUREMENTS** — `csharp` (new at this pin, 698/755) and the `asm`/`riscv64` trio
  (714/755), all starved; quarantined, not scored.
- **Tooling fix (found by arch):** `check_set_digest` was computed over `git archive` of
  `cmd/internal/validate`, which **includes `_test.go`** — so the anchor this repo makes
  authoritative for carry-forward was hashing go's test fixtures, and a fixture edit could order a
  45-peer census. Measured: the old method moved `ca0c988f… → 3e749f37…` while the real declared
  set was identical at 1137 names. Fixed via a non-test path filter. Digests recorded before this
  fix are **not** comparable to ones after it.

### Conformance oracle

- Re-pinned four times, ending at the current 755-check set `95edd774…`. (The intermediate pins
  are recorded by content in `tools/oracle-pin.env`; the commit hashes they were built from are
  internal and resolve for no public reader — [ADR-0012] Amendment 1.)
  Each carried a full cohort re-measurement. `tools/oracle-pin.env` records what moved at every
  step — including the 2026-08-21 note that `check_set_digest` values before the test-file fix are
  not comparable to ones after it.
- **`check_set_digest` added alongside `core_gate_fingerprint`, and both are now required to
  match** before `oracle-bootstrap.sh` will call an oracle current. The fingerprint tracks
  *which categories run*, never *what they assert* — at the 2026-07-27 cutover four hard-FAIL
  vectors landed inside existing core categories under a byte-identical fingerprint, so the
  old "same fingerprint ⇒ the verdict carries forward" rule was unsound and is withdrawn.

### Conformance fixes, cohort-wide

- **RT-6 (§4.6 nonce single-use)** — closed on all measured peers. 31 wrong-status peers fixed
  mechanically; 7 peers had a real anti-replay hole (a replayed authenticate was re-accepted
  with 200). Root-caused an unrelated unsolicited §4.1 "leg 3" reverse-authenticate,
  independently implemented and independently buggy in three peers.
- **F40 (§5.2 typed scope matching)** — closed cohort-wide via the shared id-scope literal
  matcher (`protocol-generator/shared/scope-matching/`).
- **§6.2 register-reserved-pattern guard** — a register at a reserved `system/*` pattern must be
  refused with 403. Normative pre-existing text that no peer enforced, because the oracle's
  negative-half check did not exist until 2026-08-11. Now enforced by 44 of 45 measured peers.

### Cohort

- Grew well past the original 21 peers; **46 now in the tree, 45 measured, 13 at `--profile core`
  0-FAIL** — tiers M1 (5, fixed 2026-08-21) and M2 (8, fixed 2026-08-22) — **at the 755-check pin**
  (the other 32 owe the §5.6 mint-ceiling fix — see the two entries above; they were 40-at-0-FAIL
  against the superseded 740-check set). Added the ISA ports (`asm-arm64`, `riscv64`), the WebAssembly siblings, the
  visual-paradigm probes (Node-RED, TurboWarp, Pure Data), the authority-as-query probes
  (SQL, Datalog), and the alien-substrate sweep (Tcl, Rexx, Forth, Smalltalk, Fortran, APL, Io,
  Oz, Unison, …). These are **cohort-consistent, not independent convergence** — see the README.
- `tools/run-cohort-census.sh` added: the first re-runnable cohort-wide driver.

### Known-open (not hidden)

- `asm-x86_64` / `asm-arm64` / `riscv64` — **INVALID MEASUREMENTS** at that pin (714 of 755
  checks, 7 starved categories each) on top of a connection-pressure failure family.
  `CONFORMANCE-MATRIX.md` §1a. **These three are why `tools/check-set-gate.py` exits non-zero
  cohort-wide (42/45 conforming); that exit code is the expected, documented state, not a
  regression.** *(`csharp` was a fourth at this pin until 2026-08-22, when it was root-caused as
  `typescript`'s §6.3 defect in its hang-form and fixed — §1c.)*
- ~~`typescript` 84F~~ **fixed 2026-08-22** — it was 3 real FAILs + 81 cascade from one
  connection-killing §6.3 defect, the same one `lean` had. Now `755 · 0F`. `CONFORMANCE-MATRIX.md` §1b.
- ~~Per-peer `status/CONFORMANCE-REPORT.{md,json}` records one pin behind, cohort-wide~~ **fixed
  2026-08-22 for all 13 publishable peers**, and now gated by `make lint`
  (`check-set-gate.py --tracked`). The 32 unfixed peers' reports stay behind by design — they owe
  the CAP *fix*, not the paperwork. See the 2026-08-22 entry above and matrix §3.
- **`python` and `kotlin` unit suites were not run** in the M2 pass — they need pytest / Gradle-plugin
  downloads and the toolchain images are sealed offline. A pre-existing environment limit, not a
  regression, and explicitly not claimed as run. Their 755-check `--profile core` conformance runs are
  the actual gate and are 0F. Suites that did run: `rust` 37/37, `elixir` 28/28, `java` smoke 11/11,
  `common-lisp` smoke PASS.
- **`common-lisp` scores one WARN off the cohort** (311P/338W vs 312P/337W):
  `concurrency/t1_1_concurrent_demux` reports no parallel speedup under load, reproduced on two
  consecutive runs. The check names itself informational and explicitly **not** a §6.11 violation, so
  it does not gate — but it is a real difference and it is in the matrix row, not hidden.
- **`go`'s `concurrency/t1_2_concurrent_reentry`** failed once in a census run and passed 3/3
  isolated plus on the re-run. Load- or timing-dependent, not root-caused, in no published cell.
- `cobol` carries a standing 27-FAIL liveness cascade. `apl` is upstream-blocked and unmeasured.
- `turbowarp` remains an exploratory, non-deployable probe and is not gated.
