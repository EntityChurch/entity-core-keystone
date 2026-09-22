# entity-core-keystone — status

_Updated: 2026-09-06 · oracle pin: the 758-check set `c34abcae…` · spec snapshot **`v0.8.2.11`** (vendored; no peer regenerated against it yet)_

> **For where this is going — the seats keystone sits between, the state of every verification
> axis, the measured size of the queued work and what freeze looks like — see
> [`docs/PROGRAM.md`](PROGRAM.md).** This file is the current-state note; that one is the
> trajectory.

> **`CONFORMANCE-MATRIX.md` is authoritative for every per-peer number.** This file is a
> short orientation note, deliberately kept thin. When the two disagree, the matrix wins.
> The revision this one replaces is archived verbatim at
> `docs/archive/STATUS-2026-08-23-13-peer-95edd774.md` — it described a 13-publishable cohort
> and listed "propagate the CAP fix to the remaining 32 peers" as the next step, both closed on
> 2026-08-28. A superseded status revision is archived rather than corrected in place, because a
> snapshot that gets back-edited stops being evidence of anything.

## Where it is

The **canonical cross-language conformance keystone** for the entity-core ecosystem
(provided, not mandatory — anyone may build a ground-up implementation instead). The
`/entity-rosetta` generator skill turns one pinned spec snapshot into a full **core-protocol
peer** (`entity-core-protocol-<lang>`) for any target language, and the repo owns the **codec
C-ABI** (`ffi-generator/c-abi/spec/`) for languages without mature canonical-CBOR + Ed25519
stacks. Generating peers is the *means*; **spec refinement is the end**.

Maturity: **0.8 pre-release research surface.** Oracle-pinned and reproducible, still
evolving as spec amendments run through the generator.

## Conformance state

**46 peers in the tree · 46 measured · all 46 at one pin — the 758-check set
`c34abcae…` (2026-09-03).** The pin is a content digest, not a commit; `CONFORMANCE-MATRIX.md`
§"The pin" carries the full anchor set and why. Nothing is carried forward from an earlier pin.

| State | Count | Peers |
|---|---:|---|
| **0-FAIL** — publishable | **46** | M1 5/5 · M2 8/8 · M3 13/13 · probe 18/18 · exploratory 2/2 |
| Not measured | 0 | — |

**The headline changed on 2026-09-03 and it changed in the honest direction.** The census now passes
`-reference-peer`, so the executed set went **756 → 758** and three `origination` checks run for all
46 peers rather than the 31 that happened to have a separate harness. Forty-five peers are at 0-FAIL
on the larger set. **`io` briefly was not** — the new coverage exposed a real §4.9(c) silent drop in
its §6.11 reentry loop, which was found and fixed the same day (item 11). New coverage that reddens a
peer is the coverage working, and this is what it bought.

**The two sets are NOT comparable and no row may be diffed across the boundary.**

The most recent re-pin added a check for a **privilege escalation**, and five peers were live to
it. An inbound EXECUTE naming *another* peer's namespace must be refused on the address itself,
before any handler is resolved. Four peers instead stripped the foreign peer id, resolved their
own handler at what remained, and let the caller's grant authorize it — status **200**. A fifth
refused, but reached the refusal by resolving locally and then failing the authorization check,
which is the same defect with a luckier outcome and is why a passing-looking result meant
nothing here. All five now refuse at canonicalization. The pattern is the recurring one in this
repo: **a check that passes can be passing for a reason unrelated to what it tests**, in both
directions.

**Read the 46 as a statement about the wire, not about the peers.** They share a generation
lineage and pass one author's vectors at one pinned check set: **cohort-consistent, not
independent convergence**. Three of the four defects closed on 2026-08-30 had been *passing*
checks for months for reasons unrelated to what those checks test — and one of the four peers
was quarantined that whole time under a diagnosis that turned out to be wrong. One row carries a
disclosed gap behind a green verdict — `cobol`'s two unreachable concurrency payloads — named in
`CONFORMANCE-MATRIX.md` §1a and its footnotes rather than left to be discovered. The ISA trio's
type-registry over-publication was the second such gap and is **closed as of 2026-08-30**; the fix
*lowered* those peers' pass counts by 282, which is what closing a matched-if-present scope
violation looks like.

**The last five peers, 2026-08-30.** `cobol` 30F → 0F: 24 of the 30 were a cascade behind one
unchecked copy of wire data into a fixed field, which hardened libc turned into a process kill.
`asm-x86_64`, `asm-arm64` and `riscv64` INVALID → 0F: the "connection-pressure family" they were
quarantined for was a §4.9(c) silent drop — an op-routing ladder that dispatches on length
answered *nothing* for `ping`, which collides with `echo` at 4 bytes, so every connection cost
the caller a full 20 s timeout and the suite's budget expired with nine categories never run.
All three also gained the §5.5 delegation chain, ported from `wasm-wat`. And `apl` — carried as
"unmeasurable, upstream-blocked" — turned out to be measurable all along: the container had built
on 2026-08-28 and nobody re-ran the peer, GNU had *reorganized* rather than deleted the 1.9
tarball, and the census hard-coded a skip that made the exclusion self-perpetuating. One run,
109 s, 8 real FAILs, all closed the same session (§1d).

**The fix shape did not vary across thirty-seven languages** — roughly 200 lines over five or six
files, in the same five places every time (capability mint, codec salvage decode, wire `400`,
read loop, policy lookup). That invariance is the strongest evidence the spec reading is right,
rather than merely that the tests pass.

**Two peers were carrying more than the CAP trio, and both were found the same way: fixing a
wrong denial made the FAIL count go UP, and the new failures were the truth.** `sql` went
2F → 7F → 0F once a §5.5a scope-canonicalization bug stopped standing in for two authorization
checks it had never implemented; `datalog` was the same shape via an `entity://` URI-parsing
defect. `nim` was the only peer that already *had* a §5.6 ceiling, and having a wrong one was
worse than having none — it minted tokens that outlived their own authority by ten years and
still returned `200`.

**Publication rule is unchanged: "no green report → no publish."** Today it withholds nothing — all
forty-six peers have a green report at the 758-check pin. Per [ADR-0012] they are **cohort-consistent, not independent
convergence** — they share a generation lineage and, for the FFI-hybrid peers, one codec `.so`.

## The verification axes

Conformance is **one of four** per-peer axes, and until 2026-09-02 only it had a cohort runner. The
other three were measured per-peer, by hand, whenever someone happened to touch them — which is to
say they rotted, invisibly, behind a green conformance number that was never wrong. The inventory is
now data in `tools/run-axis-sweep.sh` (`--list`); an axis absent from it has no cohort runner.

**Run them with one command: `make gate`.** There is no "re-run S2" or "re-run S3" as a separate
act. `make check` is static only — it runs `lint` plus a `test` target that prints a paragraph and
verifies no peer behaviour — and until 2026-09-03 no target ran the verification at all. That is
how a tree publishing 46 of 46 could carry 21 failures on two axes simultaneously.

**Where each axis gets its authority.** This matters because keystone **authors no conformance**:
`GUIDE-CONFORMANCE.md` §7.0 (architecture-owned, pinned `f7d4191d…` in the `v0.8.2.3` manifest)
names three kinds of artifact — oracle checks authored by `entity-core-go`, fixture corpora authored
by architecture, and impl-internal unit tests which are "that repo's own concern" — and says
outright that *"`entity-core-keystone` authors none of these"*, that asking it for a vector *"asks
the scorer to write the exam."*

| Axis | What it asks | Authority | State |
|---|---|---|---|
| **S2** codec / crypto-agility | do our bytes match the corpus | **architecture** — ECF + crypto-agility fixture corpora, vendored byte-identical, digest-pinned (guide §2, §6) | 46 GREEN · 0 RED |
| **S4** conformance | the published number | **`entity-core-go`** — the `validate-peer` oracle, `--profile core`, pinned by content digest | 46 GREEN · 0 RED |
| ~~**origination**~~ | *(retired 2026-09-03)* | folded into S4 — the census now passes `-reference-peer`, so its three checks run for **all 46** peers instead of the 31 that had a harness | n/a |
| **S3** loopback interop | do two peers talk, both directions | **ours** — hand-written assertions, 17 of 18 with no oracle behind them | **18 GREEN · 0 RED** · 28 no gate |

So three of the four axes are consumption of somebody else's ground truth, and nothing in them is
invented here. One is not, and it is the one that rotted.

**S3 is the open question, and it should be answered rather than carried.** Under the guide's
taxonomy it is row three — an impl-internal test, explicitly legitimate and explicitly *not*
conformance. It must never be reported as though it were conformance.

> **This paragraph used to end by recommending that S3 be retired in favour of the oracle's
> `-peers` surface. That recommendation was measured and withdrawn the same day (item 8), and the
> withdrawal did not reach this section for a further day.** `-peers` does not extend a core run; it
> switches to a different 200-check suite that is entirely standard-extension territory we
> deliberately do not build. The flag has now been run — that much of the old text is simply out of
> date — and what it measures is not ours. **What S3 needs is a decision about what it IS (item 9),
> not a replacement.** The durable form of the answer is `docs/CONTRACT-LAYERS.md`: S3's *content*
> is verification of a keystone-specific peer property, and its *authority* is ours, which is a
> legitimate combination and the one that carries the highest rot risk.

**Why the hand-written axis is the one that went stale is not a coincidence.** An assertion with an
oracle behind it moves when the oracle is re-pinned, and the check-set digest makes that visible.
An assertion we wrote ourselves has nothing watching it: `apl`'s passed an absolute path where the
peer takes a stripped one, `sql`'s never signs its post-auth requests. Both peers are `756 · 0F` on
the wire. **A test with no authority behind it drifts against the code it is meant to check, silently.**

**First sweep of S3 and origination found 21 failures** — a third of the authored S3 gates and half
the authored origination gates. Fifteen were one class (an entry point that only worked the way its
author invoked it), one was an unpinned Go reference built from the wrong sibling checkout, two were
the stale assertions above. All twenty-one are closed as of 2026-09-03: `sql`'s selftest was the last, and it was the test
that was wrong — it drove its post-auth EXECUTEs through a helper commented *"no author/capability —
§4.2 pre-authorized"*, which is true of the connect path and false of everything after leg 2. It now
presents a signed, capability-bearing request built from the grant material lifted out of leg 2, and
two planted controls confirm the green discriminates: a corrupted signature returns `401
authentication_failed`, withheld grant material returns `403 capability_denied`.

**A `NO-GATE` column entry is backlog, not an exemption.** It means that peer has no harness on that
axis; the count is printed on every run so it cannot quietly become an exclusion, which is the
standing `apl` lesson.

## What's next

**Two live items, both measured. Everything below them is closed and kept for the record.**

**A. The `0.8.2.11` catch-up — bounded on the emit side, UNMEASURED on the accept side.** Our
snapshot is `v0.8.2.3`; the protocol is at **`0.8.2.11`** — **eight** fourth-component bumps — and
arch has consolidated the whole arc into **one vendor step**. No flag day for the code-slot half.
Measured 2026-09-06 rather than guessed: **all 3** normative files moved (`+117/−24` together); the
go oracle grew **+26 declared checks, 0 removed**, of which **19 land in core categories** —
11 + 2 in `catConnectivity` and **6 in `catTreeOps`** — attributed by mapping each check to its file
and each file's category const against `coreProfileCategories`, never by name.
`core_gate_fingerprint` is **byte-identical across the pin** (`8261a033fe1af56b…`), so it will not
warn us, **for the sixth time in this exact shape**. The candidate declared digest at go HEAD is
recorded in `docs/status/HANDOFF-2026-09-06` rather than here: it anchors a sibling commit that moved
four times on 2026-09-06, so it is a measurement and not yet a pin, and this file publishes.

**The `0.8.2.11` fold is the first ACCEPT-side rule of the arc, and it is why this row is no longer
just a catch-up.** §6.3 adds a `put` admission ladder — structure, then hash — governing what a peer
**accepts** rather than what it emits. A submitted entity must be a map with non-empty text `type`,
present `data`, and a well-formed `content_hash`; any failure is `400 invalid_request`, a hash
disagreement is `400 hash_mismatch`, and **a peer MUST NOT compute a missing `content_hash` on the
submitter's behalf** — accepting the two-key `{type, data}` form leaves the peer holding an entity
under a hash nobody agreed to. **The `tree:put` admission of all 46 peers has never been driven**;
the row did not exist until `EXTENSION-TREE` v4.4 and had no predicate until v4.5. Arch's instruction
is explicit and is followed here: *do not size this from the assumption that the cohort is
conformant.*

**MEASURED 2026-09-06, and it is the maximum.** `tools/put-probe` drives the ladder over the wire on
every peer. Of the **40 peers it could be measured on, ZERO implement any row**. **37 of 40 accept
the two-key `{type, data}` form and 36 of them STORE it** — the peer authors a hash the submitter
never supplied. **40 of 40 accept an empty-string `type`.** **10 of 40 accept an entity whose
`content_hash` does not match its own content**, which is a §1.8 validate-before-trust failure
independent of the code table. The strings `invalid_request`, `hash_mismatch` and
`unsupported_content_hash_format` are emitted by **no peer, on any input, on this surface**. Five
peers are **unmeasurable** (they refuse or drop even a valid `put`; the probe's own self-check is
clean on all five, so this is reported as an observation about them and not as a probe fault) and
`turbowarp` is unbuildable — coverage is stated as **40 measured / 5 unmeasurable / 1 unbuildable**.
**So this is not a re-vendor and not a code-spelling sweep**: two of the three defect classes sit
outside the code table entirely. Detail:
`protocol-generator/shared/findings/put-admission-wire-census.md`.

The ordering question §6.3 raises — step 1 strictly precedes step 2, and no single-fault vector can
discriminate it — is reported **INDETERMINATE cohort-wide** rather than inferred: every peer accepts
the step-1-only input, so there is no refusal for a step-2 refusal to be ordered against.

**The figures in the rest of this paragraph are the previous pin's and are a FLOOR.** They were taken
at `0.8.2.7` against go `c42bbf3`; the delta above supersedes their scope but the per-defect detail
still holds.
Probed on three peers of three lineages (`go`, `rust`, `python`) against an oracle built to scratch —
a diagnostic, not a census — all three returned an **identical** `772 · 324P/336W/5F/107S`, with all
five failures among the new connect-path checks and nothing else moving. **Five failures are three
defects:** §4.5's `protocols` field is not enforced at all, the connect op ladder answers an unknown
operation as a handler `501` where `0.8.2.4` pins `400 invalid_request`, and the second-hello state
check misses mid-handshake (`409`). Separately, four peers (`asm-x86_64` `asm-arm64` `riscv64` `pd`)
emit `not_implemented` at 501 where the **slot** rule retires it — remedy is one word. Separately, the
**404 slot** diverges on up to 8 peers (five confirmed emitting `not_found` where §3.3 pins
`handler_not_found`), which is new and is ours. One authored
fix propagated 46 times, the shape of the §5.6 sweep, then re-pin and re-census.

**B. The keystone specification layer — unblocked and not started.** Three digest-pinned documents
under `docs/spec/` covering obligations that bind *our* peers and nobody else's, which is why nobody
upstream will write them. Arch has accepted the boundary. The cheapest real progress is the
library-surface sweep: of four peers nominated as satisfying the host contract **from source reads**,
three were wrong, each at a different packaging boundary, and `typescript` is the only verified host.

*(Detail and sizing for both: [`docs/PROGRAM.md`](PROGRAM.md) §3.)*

---

1. ~~**`authz_peers_target_from_uri`**~~ ✅ **CLOSED 2026-09-01 — and we had the answer the whole
   time.** This item described a cohort split (40 WARN / 6 PASS) over whether a peer must resolve
   its own handler for a URI naming *another* peer's namespace, and reported the spec as silent.
   **It is not silent.** §1.4 *URI and Path Model* says an inbound EXECUTE's path **MUST** target
   the local peer's namespace and a mismatch **MUST** be rejected with `400 invalid_request` — text
   that is byte-identical across both spec snapshots we have been building against, in the very
   section the question was about. Our search used the vocabulary of authorization (`peers`,
   `target_peer`, `check_permission`); the rule is written in the vocabulary of addressing, and
   contains none of those words. **A "the spec does not say" claim is a claim about the search.**
   The upshot: refusing is correct, and *both* groups had the disposition wrong — the 40 answered
   `404 handler_not_found`, the 6 answered `403` or `200`. The check has been retired in favour of
   one that tests the refusal directly, all forty-six peers now pass it, and the escalation it
   guards against (strip the foreign peer id, resolve locally, let a matching `peers` grant
   authorize it) is closed cohort-wide. Full correction:
   [`peers-dimension-reachability.md`](../protocol-generator/shared/findings/peers-dimension-reachability.md).
2. ~~**The ISA trio's type-registry over-publication**~~ ✅ **CLOSED 2026-08-30**
   (`CONFORMANCE-MATRIX.md` ⁹). `typestore.s` published ~200 entries including whole
   standard-extension vocabularies, which the oracle scores *matched-if-present* — so 282
   `type_system` checks that WARN for every other peer PASSed for these three, which was the whole
   reason they read `594-595P/53-55W` against the cohort-standard `312P/337W`. Now filtered to the
   53-name core floor: `313P/336W` / `312P/337W` / `312P/337W`, all still `755 · 0F`, exactly 282
   checks changed and none outside `type_system`. **The fix lowered a published pass count**, which
   is the correct direction here and the one a reviewer reverts by reflex. Two things surfaced in
   the doing: the filter lives in the generator as a fail-closed **keep-list** (the harvest is taken
   from the FULL reference peer and stays intact as evidence), and **`riscv64`'s harvest input had
   never been committed**, so its generator could not run from a clean clone.
3. ~~**Port `asm-x86_64`'s four `host.s` hardenings to `asm-arm64` and `riscv64`**~~ ✅ **DONE
   (2026-08-30)** — the inherited listen fd, the 30 s socket idle deadline, the §4.10(c) admission
   bound and the §4.10(a) oversize path. `r3_connection_flood` WARN→PASS on both, exactly one check
   moved on each peer, and all three ISA rows now read `313P/336W` at `755 · 0F`. Done for **ISA
   parity, not catch-up**: `r3_connection_flood` was WARNing on **44 of 46 peers** with only
   `asm-x86_64` and `pd` self-bound, and is now 42 of 46. §4.10(c) is a SHOULD that most peers
   delegate to the supervisor, so this never gates — and describing it as something two ISA peers
   owed a third had it backwards. Two things worth carrying: the admission counter must be **reaped
   twice** (before the blocking `accept4` *and* after it returns, or children that exit while the
   parent is parked still count as live and the bound presents as a dead peer), and on **RISC-V the
   bound is a value comparison** rather than a compare-then-branch-on-flag, the same restatement
   §5.6 rule 3's overflow test needed.
3a. ~~**The vector-layout migration**~~ ✅ **DONE (2026-09-02)** — and it was not the rename it
   looked like. `GUIDE-CONFORMANCE.md` §5.1 forbids a version stamp in a corpus directory or
   artifact name; `shared/test-vectors/v0.8.0/*-vectors-v1.*` broke that twice, across 90 functional
   consumers that **no `run-s4.sh` reads**, so the S4 census could not have caught a mistake. The
   corpora are now `ecf-conformance/`, `crypto-agility/` and a new keystone-owned `type-registry/`,
   each with a changelog in place of a version integer. **What the move exposed:** the directory
   held the crypto-agility corpus TWICE, and the copy the peers actually read had been **superseded**
   upstream — `hash-format-sha-384.2` inverted (the re-hash it pinned is now a construction that MUST
   be refused; §4.5a item 1a floor-pins `system/peer`) and the M3/M6 identity hashes moved to
   floor-form. Nothing failed while both copies existed. `elixir` and `ruby`, which LOAD the corpus,
   failed two gates each the moment the duplicate went; `ocaml` and `csharp`, which TRANSCRIBE the
   pins, **passed while carrying the identical defect**, because peer and test were wrong in the
   same direction. All four fixed and re-measured. `haskell` is predicted to fail and is
   **unmeasured** — its image cannot resolve its own test-suite dependencies, so that peer's S2 has
   no runnable gate here, which is a bigger finding than this one. **No published conformance number
   moves**: the agility corpus is not in `--profile core`, and a second axis was red on two peers
   while the gated axis was green.
3b. **`zig`'s intermittent process abort** — **MECHANISM REMOVED 2026-09-02 (`3d5db91`); the rate
   cannot be re-measured, and that is the honest state.** *(This item read "OPEN … not fixed" until
   2026-09-03, which was stale by a few hours — the fix landed the same session it was filed. The
   row asserting work is owed is the row people re-read, so it should have been the first thing
   corrected.)* The peer now `join()`s its dispatch threads instead of `detach()`ing them, so the
   `std.Thread` `Instance`-reuse window is gone by construction; the enforcement is a grep
   (`detach()` appears in `zig/src/` only inside comments explaining its removal). **The
   justification is structural, not statistical, and the numbers are why:** the abort measured
   **5 in 60** runs in the morning, and by the afternoon it would not reproduce at all — 0 of 130
   sequential runs, 0 of 100 category runs, on the *unfixed* source. So post-fix greens prove
   nothing here and are not claimed. What *was* measurable: the same change removed a 20.6-second
   `t2_2_connection_churn` stall, unfixed **7 of 100**, fixed **0 of 100**, with a half-fix build
   scoring **10 of 100** to isolate the cause. Four earlier investigations reported "no crash, empty
   stderr" because `run-s4.sh` writes the peer's stderr to a path inside a `--rm` container — the
   evidence was being deleted every run. **Closed separately in the same session:** the peer had no
   §4.10(c) admission bound at all, so a 256-connection flood became 256 concurrent threads and `r3`
   failed **9 of 30** runs on plain saturation; a 64-connection bound eliminated that shape (**0 of
   60**) and took `r3` WARN→PASS, moving zig to `315P/335W`. Two independent defects behind one
   check — the bound is not the fix for the abort.
3c. **`sql`'s S3 selftest** — OPEN, root-caused 2026-09-02, not fixed. The peer is right and the
   test is under-built: it sends its post-auth EXECUTEs through a helper commented *"no
   author/capability — §4.2 pre-authorized"*, true of the connect path and false of everything
   after it, so the peer correctly answers `401 authentication_failed` and two checks fail. It
   passed while the peer was more permissive and has been red since the §5.5a/§6.2 authority work
   landed under it. Fixing it means lifting the granted capability entity out of the leg2
   response's `included` and re-including it with a request signature — real CBOR work in
   `src/host/peer.c`, where a subtle error produces a false green, which is worse than the red.
   The diagnostic is landed: the check line now prints the disposition **code**, not just the
   status, because `401` is nine sites in that file and `401 authentication_failed` is one.
4. **`cobol`'s 8192-byte per-entity ceiling**, if a peer that can hold larger entities is wanted.
   Two concurrency probes stage 256 KiB and 16 KiB payloads; the first cannot fit its 65535-byte
   frame cap at all, and the second is refused with `413`. Raising the ceiling means raising every
   reader's buffer in lockstep — the store hands `lk-len` bytes back to a caller's fixed buffer —
   and missing one reintroduces exactly the overflow class that was just closed.
5. **Regenerate the cohort against the `v0.8.2` spec snapshot.** Every peer in the tree was
   generated against `v0.8.0`; the snapshot has been pinned since 2026-08-21 and no peer has moved
   to it. Tracked, not overlooked — **but measured 2026-08-30, the gap is much smaller than "no
   peer has been regenerated" implies, and it is a PROVENANCE gap far more than a BEHAVIOUR one.**
   The pinned oracle post-dates the 0.8.1/0.8.2 work, so the conformance loop has already dragged
   every peer onto the v0.8.2 reading of the surfaces it tests: F40 typed id-scope matching
   (`f40_id_scope_include_control` / `_exclude_literal` / `_include_no_overgrant`), RT-14 lowercase
   hex in path segments (`hash_hex_path_segment_lowercase`), RT-6 nonce single-use elevated to a
   MUST (`handshake_nonce_single_use`), and the key_type gate — **all PASS on all 46 peers today.**
   So regeneration buys the *untested corners*, the provenance of what each peer was authored
   against, and confidence that nothing v0.8.2 says is unimplemented where no vector looks. Scope
   it from the spec diff (≈197 changed lines in `ENTITY-CORE-PROTOCOL.md`, 29 in the CBOR encoding,
   40 in the type system), not from the assumption that the cohort is a version behind on the wire.
6. **Package-registry publish** and **Ed448/SHA-384 agility** stay demand-driven.
7. ~~**Fold `-reference-peer` into the census**~~ ✅ **DONE 2026-09-03.** The census now passes
   the flag; the executed set moved **756 → 758** (`core_executed_check_set_digest`
   `d30c3dd0…` → `c34abcae…`), the three `origination` checks replaced the single
   `origination: skipped` placeholder, and the delta is exactly +3/−1 and nothing else —
   verified by diffing the sorted check-name sets. **The origination axis is retired and its 31
   harnesses are deleted**; the 15 peers that never had one now carry the checks. All 46 re-censused
   and all 46 tracked reports, prose banners and §1 rows re-measured (never copied). The invariant is
   gated: `tools/fold-reference-peer.py --check`, the ninth `make lint` gate, regression-tested
   against four planted defects. **Cost, stated plainly: `io` regressed — see item 11.**
8. ~~**Retire S3 in favour of `validate-peer -peers`**~~ ❌ **WITHDRAWN 2026-09-03, same day it was
   proposed — measure before recommending.** The proposal was that the oracle's Live-peer-matrix
   surface should replace our hand-written S3 assertions. Measured: `-peers` does **not** extend a
   core run, it switches to a **different 200-check suite**, and that suite is *entirely* standard
   extension territory — its 38 skips are `convergence` (10), `route` (8), `relay_source_route` (6),
   `relay_offline_delivery` (5), `cross_peer_http_subscription` (5), `relay_multi_peer` (4), and its
   one FAIL is `relay_offline_delivery_registry` needing a peer started with `--inbox-relay-registry`.
   **RELAY, NETWORK and SUBSCRIPTION are explicitly out of scope for this repo** (`AGENTS.md`), so
   adopting `-peers` would mean measuring surfaces we deliberately do not build. It is not the
   replacement for S3 and running it is not owed. *(The underlying observation still stands and is
   still worth recording: that flag has never been run here. What it measures is simply not ours.)*
9. ~~**Decide what S3 IS**~~ ✅ **SETTLED 2026-09-03 — option (a): keep it, labelled.** It is
   implementation-internal detail the spec permits, which `GUIDE-CONFORMANCE.md` §7.0 files as row
   three — *"that repo, its own concern"* — and which the guide's §7 surface map immediately
   qualifies with *"wire conformance doesn't exempt it."* So it stays, it is **never reported as
   conformance**, and the 28 `NO-GATE` peers are **not backlog**. What it is *not* is a lesser gate:
   it remains the only axis whose checks have gone stale under peers that kept getting fixed
   (`apl`, `sql`, both `756 · 0F` on the wire throughout), because an assertion with no external
   authority has nothing watching it. The general form of that boundary — what binds every peer,
   what binds only the peers we generate, and what binds only this repo — is now
   **`docs/CONTRACT-LAYERS.md`**.
10. ~~**Run the Lean proof gate here**~~ ✅ **DONE 2026-09-03 — and the claim it was making was
   false.** `lake build EntityCoreProofs` was called *the proof check* in three of this repo's own
   documents and **no Makefile, script or harness built that target**; `run-s2.sh` built the peer,
   `run-s4.sh` builds `host`. Worse, **the exit code is not the check**: measured in the peer's own
   pinned toolchain, a `sorry` is a *warning* — `lake` prints `Build completed successfully` and
   exits **0** — and a hand-written `axiom` substituted for a proof exits 0 with no warning at all.
   Only a type-check failure is non-zero, so a gate trusting the exit code catches one failure mode
   in three, and misses the two a proof check exists for. `protocol-generator/lean/run-s2.sh` now
   builds the target and **grades the axiom set**: no declaration may depend on `sorryAx` or on any
   axiom outside the Lean-standard three, and the count of graded declarations must meet a floor,
   because a module that stopped emitting `#print axioms` would pass every name check vacuously.
   **Measured: 40 declarations graded, all clean** (37 until 2026-09-06; the three §5.5a companion
   theorems below took it to 40 and the floor moved with them). Regression-tested by planting a `sorry` (caught)
   and by raising the floor above reality — which was **not** caught on the first attempt, because
   the harness re-execs into its container and did not forward the variable, so the control could
   not run. Fixed and both plants now fire. The false parenthetical is corrected in all three
   documents rather than quietly dropped. *(The sibling gate in `entity-core-formalization` grades
   the same declarations against a declared per-declaration axiom set and is the stronger check;
   this one is the keystone-side obligation — the target our own documents name is now built and
   graded by the axis that runs on every peer.)*

   **CLOSED 2026-09-06 — the second half, and it found a real gap in our proof coverage.** The
   companion proposal (`PROPOSAL-DRAFT-2026-08-30-KEYSTONE-HFRAMED`) had been sitting unadopted for
   six days; both files it pinned by digest were still byte-identical, so its asks applied unchanged.
   Its finding: `grantPattern_namespace_isolation` proves §5.5a namespace isolation for the
   **peer-relative** pattern form only, and the `hframed` hypothesis that scopes it is **false** for
   the absolute form — verified here by evaluation, `canonSegs "P" "/Q/*" = ["Q","*"]`. That is not a
   defect in the peer: §5.5a *requires* cross-peer authority to be expressed absolutely, and the
   pass-through branch implements it correctly. It is a theorem whose name reads wider than the
   theorem, and our own comment calling the hypothesis *"mechanical stdlib plumbing"* is what created
   that reading. **§5.5a now has a theorem per pattern form** — `absolutePattern_names_one_peer`
   (asked for), plus `canonSegs_absolute_frame_independent` and `wildcardPattern_peer_agnostic`
   (not asked for, and they complete the table). Each was witness-checked for non-vacuity, because a
   theorem with an unsatisfiable hypothesis proves nothing.
   **One ask was declined and the reason corrects the comment a second time:** discharging `hframed`
   from a syntactic `¬ p.startsWith "/"` is not mechanical either. Core Lean ships **five constants
   matching `splitOn` and not one theorem** among them; `splitOnAux` is `@[irreducible]`, well-founded
   over raw byte positions, with `extract` cutting a `ByteArray` under a UTF-8 validity proof — and
   the proofs target is deliberately mathlib-free. So the comment was wrong about scope *and* wrong
   about cost, and only the first was routed to us. Reply, with both new digests for their ledger:
   `research/stewardship/HANDOFF-TO-FORMALIZATION-2026-09-06-hframed-adopted-and-the-proof-gate-closed.md`.
   The shipping-library edit in the same commit (`String.dropRight` → `dropEnd`, deprecated in
   4.29.1) was re-measured rather than assumed: **0 of 758 severities moved.**

11. ~~**`io` is RED at 28F**~~ ✅ **FIXED 2026-09-03, same day, and the defect was real.** The
   `-reference-peer` fold exposed it; it did not create it. **A response frame for a DIFFERENT
   in-flight reentry on the same connection was silently discarded.** Two reentries can be live on
   one connection, because dispatching a non-correlated inbound EXECUTE re-enters `peer dispatch`
   and that handler may itself call `outboundDispatch` on the same conn. The inner loop then saw the
   outer's `request_id` on a response frame, matched neither its own rid nor the
   `system/protocol/execute` arm, and fell off the end of the `foreach`. The outer loop could never
   see that frame again, so it waited out its **full 20-second deadline** — and on this
   single-threaded event loop that starves every other connection behind it. So a §4.9(c) silent
   drop of a *correlated response*, presenting as a concurrency and latency problem rather than a
   correctness one. The fix parks a non-matching response for its own loop instead of dropping it.
   **Measured: pre-fix 3 of 6 full-suite runs failed, post-fix 0 of 12** (p≈0.02% by chance against
   that baseline). Per-check diff: exactly **1 of 758** severities moved, and it was
   `t1_1_concurrent_demux` WARN→PASS, which is the known timing-ratio flake — WARN in 5 of the 6
   post-fix runs, so the stable row is `316P/337W/0F/105S`, identical to the pre-fix passing run.
   The fix removed the failure mode and changed nothing else.

12. ~~**Note to `entity-core-go`: a bare `-peers` core run is red against their own reference peer**~~
   ✅ **DRAFTED 2026-09-03** at
   `research/stewardship/HANDOFF-TO-ARCH-2026-09-03-peers-core-run-red-on-reference.md`, in flight.
   `validate-peer -profile core -peers a,b` against two instances of the pinned `entity-peer`
   returns `200 total, 161 passed, 1 failed, 38 skipped` — the FAIL naming a missing
   `--inbox-relay-registry`. Reads as a harness/config gap their own `validate-complete.sh` exists
   to close, not a peer defect, and RELAY/NETWORK/SUBSCRIPTION are out of scope here so we are not
   asking for the 38 skips. The one ask is whether a bare `-peers` run should preflight its own
   configuration and skip-with-a-reason rather than FAIL.

**New this session — `tools/coherence-gate.py`, in `make lint`.** The sixth root-level gate, and
the first that asks whether a document agrees with itself: all 46 primary-table rows and all 46
per-peer prose banners must equal the peer's committed report. The other five ask whether numbers
are comparable, whether anchors resolve, whether links reach real files — and all of them pass a
tree publishing `595P/54W` for a peer whose own report says `313P/336W`. It found one defect
immediately: 13 published banners were still anchored on a dead `dev` commit eight days after the
tool that prevents that shipped. **It does not retire the hand-walk**, and notably does not catch
the `§5` defect that motivated half of it — there is no way to distinguish "§5 of this file" from
"§5 of the spec".

**Closed 2026-08-30 — the cohort. `cobol` and the three ISA peers reached `755 · 0F`, and two of
the four had been misdiagnosed.** `cobol`'s 30F was 24 cascade + 5 real + 1: an unchecked copy of
wire data into a fixed 8192-byte field let a 16 KiB `tree.put` trip glibc's fortify check and kill
the process, after which every check reported connection-refused. The ISA trio's "connection-
pressure family" was a §4.9(c) silent drop — an op ladder that dispatches on length answered
*nothing* for `ping`, which collides with `echo` at 4 bytes, so every connection cost the caller a
full 20 s timeout until the budget expired. Both diagnoses had survived multiple investigations
because a silent drop bills the caller and a fortify abort leaves no trace. The trio also took the
§5.5 delegation chain, ported from `wasm-wat`. `CONFORMANCE-MATRIX.md` §1a carries the retraction
with the superseded measurements left intact.

**Closed 2026-08-29 — `wasm-wat` got a real §5.5 delegation chain and is `755 · 0F`.** Its three
remaining failures were never the mint ceiling: the peer had no chain walk at all, so CAP-5, CAP-6
and CAP-6a were refused two gates before the mint they are named after, and about ten `security`
chain vectors were passing because it refused every chain rather than because it evaluated one.
The walk, §5.5a canonicalization on both the attenuation and dispatch surfaces, §5.6 attenuation
including constraints/allowances and the nil-vs-finite expiry rule, delegation caveats, CAP-6a
representability and §3.6 K-of-N all landed together; the row reached what was then the
cohort-standard 312P/337W/0F/106S. Two of the mistakes along the way were found only by measuring: framing the
chain surface without the dispatch surface, and a pattern matcher that refused every root listing.

**Closed 2026-08-29 — `turbowarp`, the other peer the propagation had not reached, took the
ordinary CAP fix and is `755 · 0F`.** The fix shape did not vary in the 37th language either:
MIN_DEFINED by construction rather than a `<= caller_exp` comparison, `created_at` sampled once,
overflow terms dropped, and `grants: []` accepted as the CAP-2 withdrawal form. Measured twice by
two destinations of the same tool, agreeing byte-for-byte.

**Closed 2026-08-28 — the CAP propagation, 13 publishable → 39.** All of M3 but `cobol`, 13 of
the 18 probes, and `node-red`. Three of the peers in that count were **never broken**:
`rust-wasm`, `rust-wasm-wasmtime` and `node-red` are thin seams over `../rust` and the
`typescript` engine, both fixed on 2026-08-22, and were being measured against build artifacts a
week older than the source they compile. A forced rebuild took all three to 0F on the first try.
Fixing that surfaced a tooling defect worth naming: `tools/tier-status.py` was applying its
reverify overlay unconditionally — the identical bug `tools/check-set-gate.py` had been fixed for
six days earlier, in the file beside it, reading the same directory. It disagreed with the tracked
gate about which peers were green; the tracked gate was right.

**Closed 2026-08-23 — the release-readiness pass.** Three defects routed in from DevOps, plus five
more found by walking the published tree by hand:

- **The 25 spec findings now publish.** They moved `research/stewardship/` →
  `protocol-generator/shared/findings/` under undated names. `SPEC-FINDINGS-LOG.md` — declared
  canonical, and therefore shipping — indexed all of them, called one a front door, and every
  document it named was being deleted from the public tree by the release keep-list. The register
  itself deliberately did **not** move (canon-filter is fail-closed on a declared path that is
  absent). Two of the 25 were archived findings cited from *published* fortran files at paths that
  had not existed for weeks.
- **Nine more files that the published surface names were being deleted** — four diagnostics and
  five cross-cutting paradigm surveys, now under `protocol-generator/shared/{diagnostics,
  evaluations}/`. The sharpest was not a doc link: `check-set-gate.py` prints the starved-categories
  probe's path *at runtime* as the reader's next step.
  **The fix for this class is to MOVE the file, not to declare it.** `CANONICAL-DOCS.toml` declares
  canonical documents; `protocol-generator/**` is outside every doc-root prefix and publishes with
  no declaration at all. Net keep-list change for the whole pass: **+1 entry, this file.**
- **This file moved `docs/status/` → `docs/`** and publishes again, per [ADR-0031] as corrected: the
  *dated* snapshots are working memory, the single rolling log is canonical. The move is the durable
  half — the two kinds are now separable by path instead of by remembering a filename.
- **Two internal-token leaks fixed** on files that already publish. Post-move re-scan: 0 hits across
  2,706 publishable files.
- **README self-contradiction** ("13 of 45 publishable" then "binds 40 peers"), plus a missing 4F
  group that had it accounting for 43 of 46 peers.
- **New gate — `tools/link-gate.py`, in `make lint`.** Nine gates run across this repo and the
  release pipeline and none asked whether a published document points at something a reader can
  open. It caught three breaks the findings rename itself introduced.

**Closed 2026-08-24 — the strip list, the ADR ruling, and a correction to our own rule.**

- **The eight dated cross-cutting syntheses now publish** — the red-team critical review of our
  own claims (954 lines), the convergence set, substrate-theory alignment, the machine-boundary
  assessment. `protocol-generator/shared/syntheses/`, undated, with an index. They were stripping
  at release while three of them were cited from the published surface. **The `research/` bucket
  of the strip list is now empty**; the remaining 111 files are the four buckets that are correct
  by ruling — ADRs, `docs/status/`, `docs/archive/`, in-flight `research/stewardship/`.
- **The ecosystem ADRs do not publish** — standing operator ruling. All 33 strip, deliberately.
  Citing `[ADR-NNNN]` by number stays fine; pointing a reader at the path does not.
- **Our documented `canon-filter` scope was FALSE and is corrected.** It said prose under a doc
  root drops "regardless of extension"; the tool was fixed to **prose-only** on 2026-08-23 after
  the old rule shipped a go mirror that failed its own test suite on stripped `.cbor` vectors.
  Found because a routed 119-file strip list disagreed with our own recomputation by three `.sh`
  files. Only the `.md` diagnostic was ever at risk; the moves stand, the recorded reason did not.
- **A near-miss that arrived through good behaviour:** the faithfully re-synced
  `AGENTS-STANDARD.md` pointed a public reader at `docs/adr/ecosystem/`, which strips. DevOps
  repaired the master; we re-synced again and found **three more of the same in our own authored
  files**, which their repair could not have reached.

**Closed 2026-08-22 — the committed reports match what we publish.** Every tracked per-peer
`status/CONFORMANCE-REPORT.{md,json}` had drifted a full oracle pin behind the matrix, so a clone
showed each peer contradicting its own published row. §1 was never wrong — it is census-backed — but
nothing gated those files. All 13 publishable peers were **re-measured** (each reproduced its
published number exactly) and `make lint` now runs `check-set-gate.py --tracked`. As of 2026-08-28
all 40 publishable peers carry a committed report at the pinned check set; the remaining 5 stay
behind by design — they owe the *fix*, not the paperwork.

## Where the detail lives

| Question | Doc |
|---|---|
| Where this is going, and how it ends | `docs/PROGRAM.md` |
| Per-peer conformance, tiers, catch-up backlog | `CONFORMANCE-MATRIX.md` |
| What the substrates taught us | `research/SUBSTRATE-TAKEAWAYS.md` |
| What 46 implementations found wrong with the spec | `protocol-generator/shared/findings/` |
| Session records / in-flight escalations | `research/stewardship/`, `docs/status/` |
| Oracle + spec pin provenance | `tools/oracle-pin.env` |
| Maintenance tier roster | `tools/peer-tiers.tsv` |
