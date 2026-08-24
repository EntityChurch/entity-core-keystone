# entity-core-keystone — Conformance & Status Matrix

**The transparency contract for adopters.** Before you pull a generated peer, check its row here. A peer being a spec-version behind, or lacking Ed448 agility, or carrying a known gap, is a **documented, tracked state** — not a surprise. "This peer doesn't do X yet" lives here, in the open, with a tier that tells you when it'll be caught up.

**Cohort:** **46 peers in the tree · 45 measured · all 45 measured at ONE pin, `entity-core-go @ c1b0708` (2026-08-21).** Every number in §1 is a fresh measurement at that pin — nothing is carried forward, and the two-pin split this file carried earlier today is gone.

| | Peers |
|---|---|
| **0-FAIL @ `c1b0708`** (13) | `go` `haskell` `lean` `ocaml` `swift` (**tier M1**, 5/5) · `common-lisp` `csharp` `elixir` `java` `kotlin` `python` `rust` `typescript` (**tier M2**, 8/8) — M2 completed 2026-08-22 |
| **3F — the CAP gap only** (23) | `ada` `c` `cpp` `crystal` `dart` `datalog` `fortran` `io` `julia` `node-red` `odin` `oz` `pd` `php` `prolog` `rexx` `ruby` `rust-wasm` `rust-wasm-wasmtime` `tcl` `turbowarp` `unison` `zig` |
| **2F** (2) | `sql` `wasm-wat` — the CAP-5/CAP-6 pair; both already refuse CAP-6a correctly |
| **4F** (3) | `forth` `nim` `smalltalk` — CAP trio + one further `capability` check |
| **Larger** (1) | `cobol` — 30F (CAP trio + its standing 27-FAIL liveness cascade) |
| **INVALID MEASUREMENT** (3) | `asm-x86_64` `asm-arm64` `riscv64` — starved runs, **not scores** (§1a). *(`csharp` was the fourth; fixed 2026-08-22 — §1c.)* |
| **Not measured** (1) | `apl` — upstream-blocked, unchanged (§3) |

**The headline is one sentence: `--profile core` gained three `capability` checks, and every peer that has not been fixed fails exactly those three.** After the M1 (2026-08-21) and M2 (2026-08-22) passes, **32 peers remain unfixed — 3 of them INVALID measurements, 29 scored — and 25 of those 29 fail nothing but those checks**: 23 at exactly 3F with a byte-identical P/W/F/S, and 2 (`sql`, `wasm-wat`) at 2F because they already refuse CAP-6a correctly. The remaining 4 are `forth`/`nim`/`smalltalk` at 4F (the CAP trio plus one further `capability` check) and `cobol` at 30F (the trio plus its standing 27). That uniformity is the finding. It is **not** 32 independent regressions; it is one unimplemented spec feature (§5.6's MIN_DEFINED mint ceiling), measured across the cohort. **The thirteen fixed peers show what the fixed state looks like, and their diffs are the reference for the rest** (§3). *(Pre-M2 this sentence read "31 of the 40 unfixed" — correct on 2026-08-21, superseded by the M2 pass.)*

**Reading a row.** Each `--profile core` cell is `total · NF — P/W/F/S`, measured at the oracle's **default 10-minute global `-timeout`**. The **`NF` figure is the gate**; the `total` is extension-inflated and non-gating (it moves between oracle builds without any verdict changing). A skip counts as a failure unless it is an explicit `--profile core` extension carve-out. Per [ADR-0012] these peers are **cohort-consistent, not independent convergence** — they share a generation lineage and, for the FFI-hybrid peers, one codec `.so`; a cohort of generated peers all passing one author's vectors is not 40 independent confirmations.

**Spec surface:** Entity Core **v0.8.2** is the pinned snapshot (`protocol-generator/shared/spec-data/v0.8.2/`, from `entity-core-protocol` `106834c`) — but **no peer has been regenerated against it yet.** Every peer below was generated against **v0.8.0** and measured against the `c1b0708` / `de8f807` oracle. That gap is deliberate and tracked: the oracle is what gates the wire, and a snapshot reaching a peer is a regeneration question with its own cadence. One known named consequence — **`pd` still carries F37's pre-rename `system/identity/peer-id` in 3 files** (grep-verified in this tree: `pd` is the *only* peer that does); `pd` is tier M3 and out of this release's scope. Standard extensions are out of scope — every peer below is a *core* peer. The core wire contract is byte-unchanged across the V7→V8 cutover (see that dir's `MANIFEST.md`). The oracle's core category set + type floor (`cmd/internal/validate/profile.go`) is what gates `--profile core`; its committed anchors — `core_gate_fingerprint` **and** `check_set_digest` — are in `tools/oracle-pin.env`. **Both must match for a verdict to carry forward**: the fingerprint alone tracks *which categories run*, never *what they assert* (established at the `af8a582` cutover, where four hard-FAIL vectors landed inside existing core categories under a byte-identical fingerprint).

**Conformance gate:** `validate-peer --profile core` — the extension-free categories (`connectivity`, `encoding`, `type_system`, `origination`, `resource_bounds`, `concurrency`, + the §10.1 register / §7a conformance-handler gates).

**Where §1's numbers come from, and what is *not* in the repo — read this before citing a cell.** Every `--profile core` figure in §1 is generated from the centralized census, `output/scratch/census/<peer>.json`. **`output/` is gitignored, so those artifacts are not committed** — the numbers are *reproducible from the pin* (`tools/oracle-bootstrap.sh` rebuilds the oracle at `tools/oracle-pin.env`'s `ref`; `tools/run-cohort-census.sh` re-runs the cohort), not *archived in the tree*.

**The committed per-peer records now agree with §1 for every peer we publish.** The 13 publishable peers' `protocol-generator/<lang>/status/CONFORMANCE-REPORT.{md,json}` were re-measured at `c1b0708` on 2026-08-22 and each reproduced its §1 row exactly; `make lint` runs `tools/check-set-gate.py --tracked`, which fails if a peer published as 0-FAIL carries a committed report from an older check set. **The other 32 peers' committed reports are still at the retired 740-check set** — they are behind on the *fix*, not merely on the paperwork, and the gate reports them without failing on them (§3). *(Until 2026-08-22 this was true of all 45, including the publishable ones: a clone showed each peer's own report contradicting its row here. §1 was never wrong; nothing gated those files.)* **§1 remains authoritative for the cohort; a peer's `status/` report is that peer's own last measurement.** Refresh one with `tools/run-cohort-census.sh --to-status <peer>` — it is a **measurement**, never a copy of the census JSON.

*The previous header block — the accreted `cc1970f`-era cohort paragraph — is archived verbatim at `docs/archive/CONFORMANCE-MATRIX-header-pre-de8f807.md`. Do not cite figures from it.*

> ## ✅ CURRENT (2026-08-21 · extended 2026-08-22) — re-pinned to `c1b0708` + spec `v0.8.2`; **M1 and M2 both fixed, re-pin LANDED**
>
> **Read this before pulling any peer. It supersedes the 2026-08-17 banner below.** Both anchors were re-pinned on 2026-08-21: the spec snapshot to **`v0.8.2`** (`entity-core-protocol` `106834c`) and the oracle to **`c1b0708`** (`entity-core-go` HEAD). Tier **M1 was re-run, came back 0 of 5, was fixed, and is now 5/5 at `755 · 0F — 312P/337W/0F/106S`** — identical across all five. `tools/tier-status.py --gate` exits 0. **The full 45-peer census then ran**, so every row in §1 is a fresh `c1b0708` measurement.
>
> **Extension, 2026-08-22 — tier M2 is now 8/8 and 13 of 45 peers are publishable.** `typescript` (84F → 0F) and `csharp` (INVALID → 0F) turned out to be the **same** §6.3 defect in its two presentations (§1b/§1c), not two problems; `rust` `python` `java` `kotlin` `elixir` `common-lisp` then took the same CAP fix and all landed 0F. **The fix shape did not change once across thirteen languages** — ~200 lines over 5–6 files, the same five places — and that invariance is the evidence the spec reading is right, not just that the tests pass. Two lessons appeared only past the M1 sample and are ratcheted in `AGENTS.md`: **CAP-6a's fail-open has two mechanisms** (null-collapse, and an arithmetic fail-open involving no null at all — one grep does not catch both), and **§6.3 is not optional even when a peer is already at 0F** (`rust`, `common-lisp` were 0F while still scoring CAP-6a WARN).
>
> **What moved in the gate, attributed BY CATEGORY** (never by commit message): 18 declared checks added `de8f807 → c1b0708`; each resolved to its declaring file, that file's category *constant* read, and the constant tested against `coreProfileCategories`. **5 gate `--profile core`, all `catCapability`** — CAP-5 `request_mint_temporal_ceiling`, CAP-6 `request_ttl_zero_and_overflow`, CAP-6a `ingest_rejects_unrepresentable_expiry`, CAP-2/3 `configure_empty_grants_withdrawal`, CAP-7 `configure_rejects_base58_partial_prefix`. The other 13 are extension-only. `core_gate_fingerprint` stayed byte-identical (`8261a033…`) for the **fourth** consecutive time in this shape.
>
> **These were never regressions — they are a spec feature nobody had implemented.** §5.6's MIN_DEFINED temporal ceiling was **absent in every peer**: `mintToken` set no `expires_at` at all, so a `request`-minted ROOT token had no lifetime bound of any kind. No vector exercised it until this pin. §3 carried this as *"Deferred — do not start"* since 2026-08-17, correctly at the time (the normative text landed 44 minutes after that decision) — and the bill came due here.
>
> **Three defect classes came out of the M1 fix, each now ratcheted in `AGENTS.md` with an enforcement point:**
> 1. **§6.3's rejection is a STATUS, not silence.** *"Rejection returns `400 non_canonical_ecf`"* is the second half of the sentence and **all five peers ignored it** — dropping or closing on an undecodable frame instead of answering. On a peer that closes, one bad frame takes the connection: **that is where `lean`'s 81 cascade FAILs came from, and `typescript`'s 81 (§1b).**
> 2. **CAP-6a failed OPEN in three peers.** `Uint`/`uint_field`/`uintField`/`uintAt` all answer "nothing" for BOTH an absent field and a present non-uint one, so a capability with `expires_at: -1` **skipped the expiry check** and was honored with `200`. §6.2 CAP-6a names it: a verifier "MUST NOT treat the unrepresentable field as absent."
> 3. **`swift` only: §5.5a's per-link granter frames scope the RESOURCE dimension ONLY.** Applying them to all four dimensions is identical to correct whenever child and parent share a granter — every self-issued path — and makes a *universal* parent grant cover **no** child grant the moment a delegated cap arrives. 745 of 755 checks passed while every delegated cap returned 403.
>
> **The cohort result is one number repeated:** **31 of the 40 unfixed peers fail nothing but the new CAP checks** — 29 at exactly 3F with a byte-identical P/W/F/S, and 2 (`sql`, `wasm-wat`) at 2F because they already refuse CAP-6a correctly. This is one missing feature measured 40 times, not 40 defects. `typescript` additionally carries lean's §6.3 cascade (81 of its 84). `cobol` carries its standing 27. — ***As measured on 2026-08-21. After the M2 pass the counts are 32 unfixed / 25 CAP-only; `typescript`'s cascade is fixed. See the 2026-08-22 extension above and §1's header line. The finding is unchanged; only the counts moved.***
>
> **Four peers produced INVALID MEASUREMENTS** — `csharp` (698/755), `asm-x86_64`/`asm-arm64`/`riscv64` (714/755) — all with `budget_exhausted` categories. They are quarantined, not scored (§1a). **`csharp` was new at this pin and is now ROOT-CAUSED (2026-08-22): it is defect class 1 above in its hang-form**, not a separate problem — same three real FAILs at the same indices as `typescript`, but it drops the frame and holds the connection open instead of closing, so downstream checks time out rather than fail fast and the budget expires (§1c). Fixing §6.3 should restore a valid measurement *and* take it to 0F.
>
> **Publication is unchanged: "no green report → no publish."** Today that means the five M1 peers, and only those.
>
> Full session record, including the fix shape for each defect class and one recorded-not-hidden intermittent: `research/stewardship/SESSION-2026-08-21-release-repin-c1b0708-v0.8.2-and-M1-capability-gap.md`.

> ## ⛔ SUPERSEDED (2026-08-17) — oracle re-pinned to `de8f807`; §6.2 register-reserved-pattern gate CLOSED cohort-wide
>
> **Read this before pulling any peer — it supersedes the 2026-07-28 banner below.** `tools/oracle-pin.env` re-pinned `fceb61f` → `de8f807` (2026-08-16; arch's `SIGNOFF-2026-08-16-vector-set-final.md` — **the vector set is final, no further arch-side vector work is queued**). `core_gate_fingerprint` stayed byte-identical (same 16 core categories) but `check_set_digest` moved, which per standing policy re-triggered a full census regardless of the unchanged fingerprint — see `tools/oracle-pin.env`'s de8f807 entry for the full accounting.
>
> **Finding, universal at first census (2026-08-16): `core_register_reserved_refused` / `core_register_reserved_publishes_nothing` FAILed on all 45 measured peers.** `ENTITY-CORE-PROTOCOL.md` §6.2 (normative, pre-existing text — not a new rule) requires a handler register at a reserved `system/*` pattern to be refused with `403`; no peer enforced it because the oracle's negative-half check for this rule didn't exist until Go's 2026-08-11 commit. Full finding + reference fix shape:
> `research/stewardship/SESSION-HANDOFF-2026-08-17-oracle-repin-de8f807-and-reserved-pattern-gap.md` (the original finding) and
> `research/stewardship/SESSION-HANDOFF-2026-08-17-w-register-guard-partial-remediation.md` (the 31-peer first pass).
> (Note: the reference oracle's own citation for this rule, `"V7 §6.6"`, is stale under the de-versioned v0.8.0 spec — the rule is actually at §6.2. Filed to arch as `HANDOFF-TO-ARCH-2026-08-17-v7-section-citation-drift.md`; every keystone peer fix below uses the corrected `§6.2` citation, not the stale one.)
>
> **Closed 2026-08-17: 44 of 45 measured peers now enforce the guard, confirmed by a fresh centralized `tools/run-cohort-census.sh` run.** `apl` remains unmeasurable (unchanged, upstream-blocked, excluded per standing policy). `turbowarp` — the exploratory, non-deployable, "delegates the whole §6.5 engine" probe (§1, never a real peer, never in scope for this fix) — still FAILs both checks, unchanged, out of scope by design.
>
> **Of the 44 fixed, 40 are fully `--profile core` 0-FAIL.** The other 4 carry a separate, pre-existing FAIL — confirmed byte-identical by check name before/after in each fix's own commit, not touched or made worse by this pass: `cobol` (standing liveness-crash cascade, 27 FAILs) and `asm-arm64`/`asm-x86_64`/`riscv64` (1 FAIL each, `t2_2_connection_churn`).
>
> **Correction (2026-08-17, later same day): the asm trio's "1 FAIL" was NOT the whole story, and the "peer-latency flake" label this banner previously used was wrong in kind.** See **§1a** — that one FAIL consumed the entire global `-timeout` budget, which silently suppressed **7 whole categories including the core `resource_bounds`**, hiding **2 further real core FAILs**. Measured, not inferred.
>
> **Process finding worth reading if you're about to trust a census run right after a worktree-based fix:** the *first* full census after all 45 fixes landed showed 3 false FAILs (`rust-wasm`, `rust-wasm-wasmtime`, `node-red`) — not a fix regression, but `tools/run-cohort-census.sh`'s deliberate `NOBUILD=1` / build-only-if-missing reuse of on-disk build artifacts silently testing **stale, pre-session binaries** left over in the primary tree, because the actual fixes were verified inside isolated `git worktree`s with their own separate gitignored build caches that a source-only `git merge` never touches. Root-caused via build-artifact `mtime` vs. fix-commit-time comparison (not assumed), fixed by forcing a rebuild in the primary tree, re-verified 0 FAIL on all three. Ratcheted in `AGENTS.md`.
>
> **Fixed peers (44):** `go` `python` `rust` `rust-wasm` `rust-wasm-wasmtime` `typescript` · `elixir` `prolog` `common-lisp` `lean` `unison` `datalog` · `crystal` `nim` `odin` `php` `forth` `rexx` `tcl` · `smalltalk` `oz` `io` `julia` `sql` `pd` `wasm-wat` · `dart` `ruby` `node-red` · `ada` `cobol` `fortran` `haskell` `ocaml` `swift` · `c` `cpp` `csharp` `java` `kotlin` `zig` · `asm-x86_64` `asm-arm64` `riscv64`.
>
> **The per-peer rows in §1 are now refreshed against this pin (2026-08-17).** Every `--profile core` cell below is a fresh `de8f807` measurement carrying its own P/W/F/S, generated mechanically from the centralized census (`output/scratch/census/`, plus the post-rebuild re-verification for `node-red`/`rust-wasm`/`rust-wasm-wasmtime`). Two peers that had never had a row of their own — `asm-arm64` and `riscv64` — were added in the same pass.

> ## ⛔ SUPERSEDED (2026-07-28) — every `682·0F @ cc1970f` verdict below is HISTORICAL
>
> **Read this before pulling any peer.** The cohort has been **re-measured three times** since
> `cc1970f`: `af8a582` (bucket-B: RT-6 hard-FAIL + the F40 exclude/include rows), `fceb61f`
> (arch's F40 control-row + RT-6 class-split response), then a **same-day remediation pass**
> fixing every peer the `fceb61f` measurement found non-compliant, every peer inside its own
> pinned `containers/<toolchain>/` image under podman. Current result, post-remediation:
>
> **44 of 45 measured peers (`turbowarp` untouched this pass) · 40 pass `--profile core` · 4 FAIL
> · 1 not measurable (`apl`, unchanged).** Passing (new, beyond the `fceb61f` 6):
> `ada` `c` `common-lisp` `cpp` `crystal` `csharp` `dart` `datalog` `elixir` `forth` `fortran`
> `haskell` `io` `java` `julia` `kotlin` `lean` `node-red` `ocaml` `odin` `oz` `pd` `php` `prolog`
> `rexx` `ruby` `smalltalk` `sql` `swift` `tcl` `typescript` `unison` `wasm-wat` `zig`, plus the
> unchanged `go` `python` `rust` `rust-wasm` `rust-wasm-wasmtime` `nim`. `nim` still carries a
> non-gating RT-6 WARN (401, wrong code); `rust-wasm`/`rust-wasm-wasmtime` are still thin
> transport seams over `rust`.
>
> **F40 (§5.2 typed scope matching): CLOSED cohort-wide.** `forth` and `smalltalk` — the only 2
> peers left with a real, attributable canonicalization defect — converted to the id-scope literal
> matcher (`shared/scope-matching/`), same shape as the other 34 peers. All three oracle vectors
> now PASS on both. `scope_subset` (§5.5a, F50) deliberately left unconverted in both, pending the
> still-open arch ruling. **New, unrelated finding surfaced by both fix agents independently**:
> neither peer's `check_permission` evaluates the `peers` grant dimension at all — not touched,
> needs its own investigation (session doc §5).
>
> **RT-6 (§4.6 nonce single-use): CLOSED cohort-wide — `handshake_nonce_single_use` now PASSES on
> every one of the 44 measured peers.** 31 "wrong-status" peers fixed with the pinned-status
> mechanical fix (401 invalid_nonce, matching each peer's own existing idiom for that status); the
> 7 "replay-accepted" peers (the actual anti-replay security hole — a replayed authenticate was
> silently re-verified and re-accepted with 200) got a real missing established-state check added.
> The `af8a582`/`fceb61f` census's standing "status=0" mystery on `csharp`/`node-red`/`typescript`
> was NOT a decode-outcome ambiguity as suspected — it was an **unsolicited §4.1 "leg 3" reverse-
> authenticate**, independently implemented (and independently buggy) in all three, sent
> proactively to every accepted connection in violation of the spec's explicit MUST NOT for a
> client-style initiator. Root-caused live (not from a source read) and fixed in all three, plus a
> second, distinct connect-path routing bug found alongside it in the same three. A fourth bug —
> unrelated to RT-6/F40 — was found and fixed along the way: a Pd `route`-object outlet-shift wiring
> defect in `pd`'s canvas that had silently starved its entire authz/dispatch stage. Full detail,
> including the batch-run-flakiness methodology note (isolate before trusting a mid-batch FAIL),
> in the session doc below.
>
> **Remaining 4 FAILs are pre-existing, unrelated to RT-6/F40** (confirmed via their own
> `handshake_nonce_single_use` now reading PASS): `asm-arm64`/`asm-x86_64`/`riscv64` (the standing,
> already-documented `t2_2_connection_churn` peer-latency class) and `cobol` (the standing,
> already-documented liveness-crash class). Neither touched this pass.
>
> **The `682·0F @ cc1970f` figures below are retained as a historical record of what that pin
> certified. They are not a claim about this tree.** `cc1970f`/`af8a582`/`fceb61f` all share an
> *identical* `core_gate_fingerprint` — the fingerprint tracks which categories run, not what they
> assert, so "the verdict carries forward at the same fingerprint" is **withdrawn** (established at
> the `af8a582` cutover). `tools/oracle-pin.env` carries a `check_set_digest` for exactly this
> reason.
>
> Per-peer table, per-vector breakdown, the leg-3/Pd root-cause writeups, and the still-open punch
> list: `research/stewardship/SESSION-2026-07-28-fceb61f-RT6-F40-remediation.md` (successor to
> `research/stewardship/HANDOFF-TO-ARCH-2026-07-28-fceb61f-cohort-remeasurement.md`, itself
> successor to `research/stewardship/HANDOFF-TO-ARCH-2026-07-27-af8a582-cohort-remeasurement.md`).

> **⛔ Superseded — "Reading the conformance numbers" (the `cc1970f` carry-forward note).** This note asserted that every peer's gate verdict was certified at `cc1970f` and that the `665` totals carried forward unchanged. **Both halves are withdrawn.** The carry-forward argument rested on the core-gate fingerprint alone, which tracks *which categories run* and not *what they assert* — disproven at the `af8a582` cutover, where four hard-FAIL vectors landed inside existing core categories under a byte-identical fingerprint. The cohort has since been re-measured at `af8a582` → `fceb61f` → `de8f807`. **Current numbers are the §1 table and footnote ²; the header's "Reading a row" replaces this note.** Kept as a marker so a reader who remembers this paragraph learns it was retired, not moved.

> **Wire-conformance corpus — F29/F30 re-vendor (2026-07-12).** The ECF codec corpus (the *lower-bar* `wire-conformance` axis, distinct from the `validate-peer --profile core` gate above) advanced **69 → 71 vectors**: arch added F29's `nested.5`/`nested.6` (array-of-maps ≥24/≥256-byte inner-text head boundary) and regenerated F30's `tag_reject.1/2/3/5` (now canonical-except-the-mt6-tag, genuinely gating the §6.3 tag scanner). Vendored from `entity-core-protocol` @ `be54baf` as `9695b1f1…` (supersedes `41d68d2d…`), artifact decode-verified per the F16 lesson (71 vectors, all canonical bytes matched `.diag`, nested pins exact). **Cohort codec re-run: 71/71 (0 FAIL) across all 27 codec peers** (cobol: 70 pass / 1 documented C-ABI carve-out skip on `content_hash.4`; go independently tallied 66 encode_equal + 5 decode_reject). **F29 + F30 CLOSED** (`SPEC-FINDINGS-LOG.md`). This **closes the alien-substrate discovery sweep** (Tcl/Rexx/Fortran/Forth/Smalltalk/APL): F29/F30 were the last corpus asks it produced; the spec-discovery well is dry on the current wire surface — steady state is re-running this cohort against each amendment, not adding language #N. *(**F31 CLOSED** the same day: 4 peers (elixir/csharp/cobol/typescript) had a peer-layer unit test fail while codec-green + S4-conformant. Bisected to two **stale-test** causes, both test-side — no handler/peer code was wrong: (A) the §7a dispatch-outbound reentry tests sent the `value` field as a bare scalar instead of the `{value:X}` echo-shape entity-data map the §7a.1 contract requires (per the Go oracle + the passing kotlin test); (B) cobol's dispatch skeleton test expected 404 for an **unauthenticated** unknown-handler EXECUTE, but §6.5 authenticates before resolving → correct status is 401. All four now green; details in `SPEC-FINDINGS-LOG.md` F31.)*

---

## 1. Primary status table

> **How to read this section.** The **table** is the live state, and as of the 2026-08-21 full
> census it spans **one pin**: every row is a `c1b0708` measurement on the **755**-check set, with
> the M2 rows re-measured after their 2026-08-22 fixes. Nothing is carried forward from `de8f807`.
> *(This note previously described a two-pin split — 5 fresh M1 rows against 40 stale `de8f807`
> ones. That was accurate for the few hours between the M1 fix and the full census, and was left
> standing after the census closed it. Corrected 2026-08-22.)* The
> **dated `>` note blocks** that follow are a
> *build log* — each records what a peer's arrival established at the pin current on that date,
> and the figures in them (`682·0F @ cc1970f`, `665 @ e8524ed`, …) are **historical, not claims
> about this tree**. Where a note and the table disagree, the table wins. §1a covers the one case
> where a table row needs more than a number.

> **New peer — asm-x86_64 (2026-07-13, hand-written).** The lowest-level substrate probe: a
> **hand-authored x86-64 assembly** peer (GAS/AT&T), not `/entity-rosetta`-generated — the
> ultimate "can the wire+authority interior be built in the barest language" stress test.
> Transport + the envelope/data-map CBOR + the entire dispatch/authority interior are hand-written
> asm; entity codec + Ed25519/SHA + peer-id are **FFI** via `libentitycore_codec`. Measured
> **natively at `cc1970f`** → **682·0F (Result: PASS**, 583P/3W/0F/96S, deterministic), matching
> the reference `entity-peer` on every check it passes. Notable: it implements the full write-op
> surface (tree put/get/CAS/listing/delete, register/unregister, configure, revoke), genuine §5.5
> K-of-N multisig accept, §6.2 dispatch-entity normalization, AND **§7a.2a concurrent reentrant
> dispatch-outbound** — the last via a single-threaded fork + request/response frame router +
> `pending_tab` demux (no threads/epoll; the reentry is one-socket, validator-as-B). The 3 WARNs
> are benign (`r3_connection_flood` matches the reference's WARN). **Cohort counts reconciled at
> the 2026-07-14 branch merge — headline was 33 gate-green peers then** (this row included; **40 now** — see the top Cohort line). Per-peer detail:
> `protocol-generator/asm-x86_64/status/`. (Honesty: FFI-hybrid, oracle-pinned `--profile core`,
> cohort-pinned to one author's vectors — not full-profile, not independent convergence.)
>
> > **L2 update (2026-07-15) — native canonical codec.** The peer's **canonical ECF codec is now
> > hand-written x86-64 asm** (`src/codec.s`): the shortest-float ladder, integer/length
> > minimization, definite-length + recursive tag-reject, length-then-lex key sort, `ec_content_hash`,
> > and peer-id `format`/`parse` (native base58 + LEB128) — only **Ed25519 + SHA-256 remain FFI**
> > (the L2 boundary). Cross-checked differentially against the 3-way-locked corpus (`make diff` →
> > 71 corpus + 4 synthetic, 0 FAIL) and integrated into the live peer: `run-s4.sh --profile core`
> > → **682·0F (Result: PASS**, 583P/3W/0F/96S) @ `cc1970f`, **identical pass set to L1** — only the
> > codec *provider* changed (FFI→native). Symbol-verified (`nm bin/host`): codec symbols `T` (ours),
> > `ec_sha256`/`ec_ed25519_*` `U` (FFI). Parse accept-path (oracle-invisible) covered by
> > `make parse-test` (11·0F). Detail: `status/PHASE-L2.md`. **The asm probe's discovery arc is
> > complete at L2** — L3 (hand-written asm crypto) is **deferred indefinitely** (per-ISA, high-risk
> > crypto boundary, ~zero discovery value; crypto stays linked-compiled — ISA-MAP point 5). The one
> > remaining optional item — a **RISC-V L1** port — is now **DONE (2026-07-16, `riscv64`)**: a
> > first-class-riscv64 distro (Debian trixie) sysroot under `qemu-riscv64-static` confirmed the
> > earlier "block" was a Fedora-secondary-arch packaging gap, not a riscv problem. See its note below.

> **New peer — asm-arm64 (2026-07-15), the first ISA port.** The x86-64 asm peer transliterated
> to **aarch64** (GAS native ARM syntax) — the first port off the hand-written asm template, and
> the test of the ISA-MAP Axis-A thesis: *with the codec/crypto/peer-id behind the FFI, is the
> protocol interior a mechanical register/syscall swap?* Answer: **yes, end-to-end.** All 75
> dispatch functions + the 4 shell modules ported by the codified register/ABI/syscall map
> (`rdi..r9`→`x0..x5`, cursor `r15`→`x24`, `svc #0`, `bswap`→`rev`, logical-immediate workaround,
> `push/pop`→`stp/ldp` frames) with **zero protocol-logic change**. Runs under
> `qemu-aarch64-static`; the native Go oracle runs beside it. Codec `.so` **cross-built for
> aarch64** (FFI×ISA cost: cross-libsodium via `--forcearch`). Measured `--profile core` at
> `cc1970f` → **682·0F (Result: PASS**, 583P/3W/0F/96S) — **byte-identical to the x86-64 sibling's
> verdict**, same 3 benign WARNs; §7a `validate_echo_dispatch` + concurrency 5/5 + §5.5 multisig
> accept all pass. Substrate findings: `fork`→`clone(SIGCHLD)` (no `fork` in the aarch64 generic
> table; A-ARM64-001), cross-sysroot shape (A-ARM64-002), and one porting-discipline bug —
> per-function store-helper length-register ABI (A-ARM64-003). Per-peer detail:
> `protocol-generator/asm-arm64/status/`. (Honesty: **corroboration, not independent
> convergence** — shares the x86-64 peer's generation lineage + FFIs the same codec; the real
> signal is the substrate mechanics. FFI-hybrid, oracle-pinned `--profile core`, cohort-pinned.)

> **New peer — riscv64 (2026-07-16), the third ISA (second port).** The asm peer transliterated
> to **riscv64** (GAS, RV64GC) — ported off **`asm-arm64`**, NOT x86-64, because aarch64 and riscv64
> share the kernel's *generic* syscall table (so arm64 pre-adapted every generic-table quirk). All
> 75 dispatch functions + the 4 shell modules ported by the codified aarch64→riscv64 map
> (`x0-x5`→`a0-a5`, cursor `x24`→`s6`, `svc`→`ecall` nr-in-a7, `rev`→hand-rolled `bswap*`, flag-less
> fused compare-branches, `stp/ldp`→`addi sp`+`sd/ld`) with **zero protocol-logic change** — the
> dispatch port ran as a **9-way parallel fan-out** along function boundaries. Runs under
> `qemu-riscv64-static`; the native Go oracle runs beside it. Codec `.so` **cross-built for riscv64**
> against a **Debian trixie riscv64 sysroot** (the FFI×ISA cost — riscv64 is a Fedora *secondary*
> arch with no forcearch path, so glibc+libsodium come from Debian's first-class riscv64 port,
> assembled from `.debs` with no foreign-arch execution / no host binfmt; A-RISCV-002, retiring the
> "BLOCKED" finding). Measured `--profile core` at `cc1970f` → **682·0F (Result: PASS**, 583P/3W/0F/96S)
> — **byte-identical to the x86-64/arm64 siblings**, same 3 benign WARNs; §7a `validate_echo_dispatch`
> + concurrency 5/5 + §5.5 multisig 11/11 accept all pass. Landed **0-FAIL on the first full run** —
> the A-ARM64-003 inter-function seam bug did NOT recur, because the arm64→riscv64 map is a clean
> **bijection** (no register-pressure divergence; A-RISCV-004). Other findings: hand-rolled byte-swap
> (no base-ISA `rev8`; A-RISCV-001), Debian libsodium 1.0.18 vs fedora 1.0.22 (A-RISCV-003). Per-peer
> detail: `protocol-generator/riscv64/status/`. (Honesty: **corroboration, not independent
> convergence** — shares the x86-64/arm64 generation lineage + FFIs the same codec. FFI-hybrid,
> oracle-pinned `--profile core`, cohort-pinned.)

> **New peer — wasm-wat (2026-07-15), the interpreted-substrate probe.** The peer is **hand-authored
> WebAssembly text** (`host.wat` transport + poll loop, `wire.wat`/`dispatch.wat` envelope + §5.2 +
> handlers); the Rust codec is compiled to `wasm32-wasip1` and **wasm-merged** as the seam
> (canonical CBOR + Ed25519/SHA). Measured under WasmEdge 0.17 → **682·0F (Result: PASS**, 291P/294W/
> 0F/97S @ `cc1970f`), **full §7a `--validate` parity, no `-allow-skip`** — including the
> **reentrant `dispatch-outbound` dialer** (t1_2 M=8 concurrent + `validate_echo_dispatch`), authored
> as a **same-connection** §6.11 reentry (outbound echo rides the inbound fd; a `pending[echo_rid →
> dispatch_rid]` table on one socket, no client dialer/threads). **The crypto execution mode is
> load-bearing:** WasmEdge's interpreter runs one Ed25519 verify at ~9 ms so §6.11 T2.1 times out;
> `--enable-jit` (~84 µs, 109×) is the working lever and part of this peer's conformance contract.
> AOT is inert on 0.17 (the `wasmedge compile` artifact runs without engaging its native code — t2_1
> FAILs at 22.9 s, confirmed 2026-07-15). Multisig accept-path + `--name` keypair load deferred
> (local-env). Detail: `protocol-generator/wasm-wat/status/`; findings F33/F34/F35 + execution-mode
> analysis in `research/stewardship/HANDOFF-TO-ARCH-2026-07-15-*.md`. (Honesty: seam-hybrid,
> oracle-pinned `--profile core`, cohort-pinned to one author's vectors — not independent convergence.)

> **New peer — rust-wasm (2026-07-15), the COMPILED-wasm sibling of wasm-wat.** The generated Rust
> peer's library (`../rust`) cross-compiled **unmodified** to `wasm32-wasip1` (LLVM), behind a
> 336-line single-threaded `poll_oneoff` transport seam (`src/main.rs`) — the whole ~4,000-line
> interior (codec, §5 authz, §6 dispatch, §9.5 floor, ed25519-dalek + sha2) compiles with **zero
> source changes**; `Peer::dispatch` is byte-identical to native, the seam ports the same single-fd
> §7a reentry-demux as wasm-wat/asm. Measured under WasmEdge 0.17.1 `--run-mode=jit` → **682·0F
> (Result: PASS**, 291P/294W/0F/97S @ `cc1970f`), **full §7a `--validate` parity, no `-allow-skip`** —
> byte-for-byte the same P/W/F/S as wasm-wat, same runtime. Same-runtime codegen head-to-head vs the
> hand-authored WAT peer: compiled Rust is **−29% module size** (242 KB vs 340 KB) and **−28% JIT
> warmup**, at a fraction of the authoring cost (reuse a whole peer + one host file); hand-authored WAT
> is **~1.8× faster per request** (10k sustained-load) — the abstraction-tax vs hand-tuned-loop
> trade. The decisive control: **the same Rust peer as native ELF vs wasm runs within ~1%** — portable
> compute is nearly free; the per-substrate cost is the transport-ABI seam. Full analysis:
> `research/evaluations/wasm-codegen-comparison.md`; folded into SUBSTRATE-TAKEAWAYS §4. Two transport
> lessons bit as on wasm-wat: **single-send framing** (Nagle/delayed-ACK churn stall) + **JIT crypto
> execution mode**. Multisig accept-path + `--name` keypair deferred (local-env), as wasm-wat. (Honesty:
> shares the native Rust peer's generation lineage AND crypto crates — NOT independent convergence; the
> independent datapoints are the unmodified-interior-cross-compiles result + the codegen comparison.)

> **New peer — rust-wasm-wasmtime (2026-07-15), the wasmtime-AOT production sibling.** The SAME
> `rust-wasm` `wasm32-wasip1` module, run under **wasmtime** and precompiled to native Cranelift
> code (`wasmtime compile` → `.cwasm`, run `--allow-precompiled`) — the compile-once-run-native
> production story WasmEdge 0.17's **inert** AOT couldn't give. Deliberately wasip1 (not wasip2):
> `wasmtime compile` is WASI-version-agnostic, so this isolates ONE variable (runtime + exec-mode)
> against the WasmEdge column; wasip2 would add a second (a different socket ABI) and cost the
> no-rustup rule (fedora ships no wasip2 std) — a deferred forward-ABI probe. Interior byte-identical
> to rust-wasm; only the socket seam changed — WasmEdge self-bind (`sock_open/bind/listen`) → a
> **host-preopened listener** (`-S tcplisten`) + standard wasip1 `sock_accept`/`poll_oneoff` (the
> `wasi` crate); framing + §7a reentry pump port verbatim. Measured running the AOT `.cwasm` →
> **682·0F (Result: PASS**, 291P/294W/0F/97S @ `cc1970f`), **full §7a `--validate` parity, no
> `-allow-skip`** — byte-for-byte the same P/W/F/S as rust-wasm/wasm-wat, §6.11 t2_1/t2_2 churn
> passing at native speed (the "experimental" `-S tcplisten` held). **AOT warmup ~5.7 ms** (native
> engages) vs WasmEdge JIT's ~3 s — but honestly the big win is WasmEdge→wasmtime (Cranelift JIT is
> already ~ms); AOT removes the residual per-boot compile AND yields a deploy-time native artifact.
> Sizes: `.wasm` 242 KB (portable) / `.cwasm` 904 KB (native, **wasmtime-46.0.1-pinned** — a
> deploy-time recompile artifact, not portable across wasmtime versions). wasmtime v46.0.1 is a
> **checksum-pinned upstream release** (not in fedora; S11). Full analysis:
> `research/evaluations/wasm-codegen-comparison.md` (third column); SUBSTRATE-TAKEAWAYS §4. (Honesty:
> shares rust-wasm's generation lineage + crypto crates — cohort-consistent, NOT independent
> convergence; the independent datapoint is the AOT-native-engages + warmup result.)

> **New peers — Crystal + Odin (2026-07-12, provisional).** Two T3 corroboration /
> generator-robustness peers added this session, both **native-codec** (the LANDSCAPE "ffi"
> predictions were overturned: Crystal binds libsodium directly for Ed25519; Odin's crypto is
> **native pure-Odin `core:crypto`**), both measured **natively at `cc1970f`** → **682·0F**
> (`--profile core`, 292P/294W/96S). Crystal is the **Ruby-overfit check** (compiled/typed/
> fixed-width/CSP-fiber Ruby-like); Odin is the **no-exceptions / no-GC / no-package-manager**
> systems probe. **Reconciled at the 2026-07-14 branch merge** (A-CRY-006 / A-ODIN-005): the
> Julia + Nim parallel branch merged with this one, and the headline cohort count reached **33
> gate-green peers** at that 2026-07-14 merge (Crystal + Odin + asm-x86_64 folded into the alien/mainstream sweep; **40 now** — see the top Cohort line). No spec finding surfaced (well is dry); the
> only net-new code was a shared NUL-byte path check and a Crystal graceful-shutdown hardening.

> **New peers — Oz/Mozart + Io (2026-07-15).** Two paradigm probes, each closing one open
> substrate axis, both **NATIVE-transport + FFI-hybrid-crypto** and both **`682·0F Result: PASS`
> @ `cc1970f`** (`--profile core`, incl. origination-core 3/3 + a genuine 2-of-3 multisig
> accept-path unit). **Oz / Mozart** (285P/301W/0F/96S) is the **4th §7b structural-concurrency
> shape — dataflow variables**: the §6.11 handler-outbound demux collapses to one single-assignment
> dataflow variable per pending request (reader routes frames, never blocks on dispatch — no
> correlation map, no locks; A-OZ-006). Installs from the 2018 Mozart 2.0.1 RPM (no source build);
> crypto/CBOR seam is the `entity-codec-daemon` `Open.pipe` co-process (RPM ships zero headers →
> native-functor FFI out; the Rexx `ecnet` precedent). **Io** (291P/295W/0F/96S) is the **pure
> prototype-based object model** — §6.6 handler resolution rendered as Io's own delegation (a
> `DispatchNode` proto network where longest-prefix resolution *is* the proto-chain lookup);
> native Socket + an in-process `EntityCodec` C addon, built on the permanently-frozen
> `2026.04.20-native-final` tag (upstream master pivoted to WASM). Io's S4 initially FAILed
> `concurrency` t2_1/t2_2 and was misdiagnosed as a single-threaded throughput ceiling; the Oz
> sibling passing the same checks with *slower* co-process crypto ruled that out — bisection found
> two fixable bugs (A-IO-025 per-request `try`-coroutine leak; A-IO-026 blocking send stalling the
> single event loop under slow readers), and the ceiling claim was **retracted** → clean 0-FAIL,
> t2_1 0/10000 dropped. Honesty: both FFI-hybrid, oracle-pinned `--profile core`, cohort-pinned to
> one author's vectors — not full-profile, not independent convergence. Per-peer detail:
> `protocol-generator/{oz,io}/status/`.

> **New peers — SQL + Datalog (2026-07-16), the authority-as-query frontier probes — CLOSING the
> declarative-query/logic corner.** Two *spec-discovery* probes (not substrate probes) built in parallel
> S1→S5, both **NATIVE-transport-via-host + FFI-hybrid-codec** and both **`682·0F Result: PASS` @
> `cc1970f`** (SQL 291P/295W/0F/96S; Datalog 292P/294W/0F/96S), origination-core `dispatch_outbound_reentry`
> 3/3, genuine live 2-of-3 multisig accept, 71/71 wire corpus. The whole point is the **authored authority
> interior**: the §5.2 verify ladder, §5.5 delegation chain-walk, §3.6 K-of-N, and §6.6 resolution are
> authored *in the query/logic language* (SQL: recursive CTE + `HAVING count DISTINCT` + `ORDER BY length
> DESC`; Datalog: recursive Ascent rules to least fixpoint + counting aggregate + stratified negation),
> with a thin host (C / Rust) owning only what the substrate genuinely can't do (sockets/CBOR/crypto/store).
> The **wrapper-guard held through S4** on both — completing the S4 handler surface added **zero** imperative
> allow/deny; the verdict never left the authored interior. **Finding (co-equal with the gate):** authority
> IS a query, the protocol around it is a state machine — everything pure-function-of-the-projected-facts
> fits (often more legibly than the prose), everything stateful-sequential leaks to the host. Two spec-shaped
> results routed to arch: **F40** (§3.6 scope matching is typed — id dims literal, path dims canonicalized —
> surfaced by SQL as a real ALLOW bug) and **F41** (the §5/§6.6 decision surface is a monotone deductive
> system → an authority-as-derivation appendix makes fail-closed + the §5.5a within-grant conjunction
> *structural invariants*). Honesty: both seam-hybrid, cohort-consistent (shared C-ABI codec lineage) NOT
> independent convergence (ADR-0012), probe-tier — genuine gate-green peers, not visual/illustrative (no ‡).
> Synthesis: `research/evaluations/authority-as-query.md`; arch routing:
> `research/stewardship/HANDOFF-TO-ARCH-2026-07-16-authority-as-query.md`; per-peer:
> `protocol-generator/{sql,datalog}/status/`.

| Peer | Maint.⁴ | Spec | Oracle commit | `--profile core`² | Codec | Crypto floor (Ed25519 + SHA-256) | Ed448 / SHA-384 agility | Publish |
|------|:----:|:----:|---------------|:----------------:|-------|----------------------------------|-------------------------|---------|
| **OCaml** | **M1** | v0.8.0 | `c1b0708` | 755 · **0F** — 312P/337W/0F/106S ⁵ | native hand-rolled | native — mirage-crypto-ec + digestif | **FFI-hybrid** (opt-in `entitycore_agility`) | opam, `0.1.0-pre` |
| **Swift** | **M1** | v0.8.0 | `c1b0708` | 755 · **0F** — 312P/337W/0F/106S ⁵ | native hand-rolled | native — swift-crypto | deferred (→ FFI when scoped) | SPM, `0.1.0-pre` |
| **Haskell** | **M1** | v0.8.0 | `c1b0708` | 755 · **0F** — 312P/337W/0F/106S ⁵ | native hand-rolled | native — crypton | **native** — crypton (Ed448) | Cabal, `0.1.0-pre` |
| **Go** (clean-room) | **M1** | v0.8.0 | `c1b0708` | 755 · **0F** — 312P/337W/0F/106S ⁵ | native hand-rolled | native — stdlib `crypto/ed25519` | deferred (→ FFI when scoped) | Go module, `0.1.0-pre` |
| **Lean** | **M1** | v0.8.0 | `c1b0708` | 755 · **0F** — 312P/337W/0F/106S ⁵ | **pure-Lean proven core** + FFI crypto | **FFI** — C-ABI `ec_ed25519_*` | FFI (deferred) | Lake, `0.1.0-pre` |
| **C#** | M2 | v0.8.0 | `c1b0708` | **755 · 0F** — 313P/336W/0F/106S ✅ *(was an INVALID MEASUREMENT at 698/755 with 9 starved categories; fixed 2026-08-22 — §1c. Run time 18m20s → **7.2s**.)* | native (Cbor Ctap2 + handroll) | native — NSec | managed — BouncyCastle | NuGet, `0.1.0-pre` |
| **TypeScript** | M2 | v0.8.0 | `c1b0708` | **755 · 0F** — 312P/337W/0F/106S ✅ *(was 84F = 3 real + 81 cascade; fixed 2026-08-22 — §1b.)* | native (cborg + handroll) | native — @noble | managed — @noble | npm, `0.1.0-pre` |
| **Java** | M2 | v0.8.0 | `c1b0708` | **755 · 0F** — 312P/337W/0F/106S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — JDK SunEC | JDK / BouncyCastle | Maven, `0.1.0-pre` |
| **Kotlin** | M2 | v0.8.0 | `c1b0708` | **755 · 0F** — 312P/337W/0F/106S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — JDK SunEC | deferred (→ JDK SunEC / BouncyCastle) | Gradle→Maven Central, `0.1.0-pre` |
| **Elixir** | M2 | v0.8.0 | `c1b0708` | **755 · 0F** — 312P/337W/0F/106S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — OTP `:crypto` | **native** — OTP `:crypto` | Hex, `0.1.0-pre` |
| **Common Lisp** | M2 | v0.8.0 | `c1b0708` | **755 · 0F** — 311P/338W/0F/106S ✅ *(was 3F; CAP fix 2026-08-22. One WARN off the cohort: `concurrency/t1_1_concurrent_demux` reports no parallel speedup under load — the check names itself informational, **not** a §6.11 violation.)* | native hand-rolled | native — ironclad (pure-Lisp) | **native** — ironclad (pure-Lisp) | ASDF/Quicklisp, `0.1.0` |
| **Rust** (clean-room) | M2 | v0.8.0 | `c1b0708` | **755 · 0F** — 312P/337W/0F/106S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — ed25519-dalek + sha2 | deferred (→ FFI when scoped) | crates.io, `0.1.0-pre` |
| **Python** (clean-room) | M2 | v0.8.0 | `c1b0708` | **755 · 0F** — 312P/337W/0F/106S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — `cryptography` (OpenSSL) | **native** — `cryptography` (Ed448) | PyPI, `0.1.0` |
| **Zig** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | native (std-only) | native — `std.crypto` | deferred | source, `0.1.0-pre` |
| **C** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | native hand-rolled | native — libsodium | deferred (libsodium has no Ed448) | `make dist` + pkg-config |
| **C++** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | native hand-rolled | native — libsodium | deferred (libsodium has no Ed448) | CMake pkg + vcpkg + conan, `0.1.0-pre` |
| **Ada** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 310P/336W/3F/106S | native hand-rolled | native — libsodium (C binding) | deferred (libsodium has no Ed448) | Alire (optional), `0.1.0-pre` |
| **Ruby** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | native hand-rolled | native — stdlib `openssl` | **native** — stdlib `openssl` | RubyGems, `0.1.0.pre` |
| **Crystal** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | native hand-rolled | native — libsodium (direct `lib`/`fun` C binding) | deferred (libsodium has no Ed448; → FFI) | source, `0.1.0-pre` |
| **Odin** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | native hand-rolled | **native — pure-Odin `core:crypto`** (Ed25519 + SHA-2, FFI-free) | deferred (`core:crypto` has no Ed448; → FFI-hybrid) | source (`make dist`), `0.1.0-pre` |
| **Prolog** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | **FFI** (C-ABI) | **FFI** — C-ABI (library(crypto) has no Ed25519) | FFI | SWI pack, `0.1.0` |
| **PHP** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | native hand-rolled | native — ext-sodium (libsodium) | deferred (ext-sodium has no Ed448; → FFI) | Composer, `0.1.0-pre` |
| **Dart** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | native hand-rolled | native — cryptography_plus (pure-Dart) | deferred (→ FFI when scoped) | pub.dev, `0.1.0-pre` |
| **COBOL** | M3 | v0.8.0 | `c1b0708` | 755 · **30F** — 279P/335W/30F/111S | **FFI-hybrid** (COBOL value-codec + C-ABI) | **FFI** — `libentitycore_codec` (libsodium) | deferred (libsodium has no Ed448) | `make dist`, `0.1.0-pre` |
| **Tcl** | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | **FFI-hybrid** (pure-Tcl canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` (C-shim, libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | git + `pkgIndex.tcl`, `0.1.0-pre` |
| **Rexx** | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 308P/338W/3F/106S | **FFI-hybrid** (pure-Rexx **decimal-model** canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via the `ecnet` co-process daemon (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Fortran** | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | **FFI-hybrid** (pure-Fortran **signed-carrier uint64** canonical CBOR value codec + C-ABI) | **FFI** — `libentitycore_codec` bound direct via `iso_c_binding`, no C wrapper (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Forth** | probe | v0.8.0 | `c1b0708` | 755 · **4F** — 308P/337W/4F/106S | **FFI-hybrid** (pure-Forth **native-float-bits** canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via in-process `libcc` `c-function` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Smalltalk** | probe | v0.8.0 | `c1b0708` | 755 · **4F** — 308P/337W/4F/106S | **FFI-hybrid** (pure-Smalltalk canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via in-process UFFI `ffiCall:module:` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | git + Metacello/Tonel, `0.1.0-pre` |
| **APL** | probe | v0.8.0 | `de8f807` (not run) | not measured @ `de8f807` — upstream-blocked, see §3 | **FFI-hybrid** (pure-APL **array value-model** canonical CBOR codec + C-ABI) | **FFI** — `libentitycore_codec` via a GNU APL `⎕FX` native fn (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git source), `0.1.0-pre` |
| **asm-x86_64** | probe | v0.8.0 | `c1b0708` | ⚠ **INVALID MEASUREMENT**³ — ran **714 of the pinned 755** checks; 7 categor(ies) `budget_exhausted`. Not a score; quarantined. | **native (L2)** hand-written x86-64 asm — envelope/data-map CBOR **+ canonical ECF codec** (shortest-float ladder, key-sort, `ec_content_hash`, peer-id format/parse); only crypto is FFI | **FFI** — Ed25519 + SHA-256 via `libentitycore_codec` (libsodium); the canonical codec is native asm (L2 boundary) | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make host`), `0.1.0-pre` |
| **asm-arm64** | probe | v0.8.0 | `c1b0708` | ⚠ **INVALID MEASUREMENT**³ — ran **714 of the pinned 755** checks; 7 categor(ies) `budget_exhausted`. Not a score; quarantined. | **native (L1)** aarch64 GAS transliteration of the x86-64 peer — envelope/data-map CBOR + dispatch interior in hand-written asm; canonical codec + crypto via `libentitycore_codec` (cross-built for aarch64); run under `qemu-aarch64-static` | **FFI** — Ed25519 + SHA-256 via `libentitycore_codec` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make host`), `0.1.0-pre`|
| **riscv64** | probe | v0.8.0 | `c1b0708` | ⚠ **INVALID MEASUREMENT**³ — ran **714 of the pinned 755** checks; 7 categor(ies) `budget_exhausted`. Not a score; quarantined. | **native (L1)** RV64GC GAS port off the arm64 template via the shared generic syscall table; canonical codec + crypto via `libentitycore_codec` (cross-built for riscv64); run under `qemu-riscv64-static` | **FFI** — Ed25519 + SHA-256 via `libentitycore_codec` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make host`), `0.1.0-pre`|
| **wasm-wat** | probe | v0.8.0 | `c1b0708` | 755 · **2F** — 304P/339W/2F/110S | **seam-hybrid** (hand-authored WAT peer + wire codec; Rust codec compiled to `wasm32-wasip1`, wasm-merged as the seam) | **seam** — `entitycore_codec.wasm` (Rust→wasm, Ed25519 + SHA-256) | deferred (→ codec seam `ec_ed448_*`) | source (`make peer`), `0.1.0-pre` |
| **rust-wasm** | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 306P/337W/3F/109S | **native (inherited)** — the `../rust` peer's hand-rolled ECF codec cross-compiled UNMODIFIED to `wasm32-wasip1`; only a 336-line `poll_oneoff` transport seam is wasm-specific | **native** — ed25519-dalek + sha2 (compile to wasm cleanly, no seam) | deferred (→ codec seam `ec_ed448_*`) | source (`make peer`), `0.1.0-pre` |
| **rust-wasm-wasmtime** | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 306P/337W/3F/109S | **native (inherited)** — the SAME `rust-wasm` `wasm32-wasip1` module, run under **wasmtime AOT** (`wasmtime compile` → `.cwasm`); only the socket seam differs (host-preopened `-S tcplisten` + standard wasip1 `sock_accept`/`poll_oneoff`, the `wasi` crate) | **native** — ed25519-dalek + sha2 (compile to wasm cleanly, no seam) | deferred (→ codec seam `ec_ed448_*`) | source (`make aot`), `0.1.0-pre` |
| **Julia** | M3 | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | **native** hand-rolled (**multiple-dispatch** canonical CBOR) | **native** — system libsodium via `ccall` + `SHA` stdlib (Ed25519 + SHA-256; native-audited-lib tier, NOT the C-ABI) | deferred (→ opt-in FFI, C-ABI `ec_ed448_*`; libsodium has no Ed448) | Pkg (Project.toml + git), `0.1.0-pre` |
| **Nim** | M3 | v0.8.0 | `c1b0708` | 755 · **4F** — 308P/337W/4F/106S | **native** hand-rolled (**compile-time macro/template** canonical CBOR) | **native** — libsodium via `{.importc.}` C interop (Ed25519 + SHA-256) | deferred (libsodium has no Ed448) | nimble (git-indexed), `0.1.0-pre` |
| **Oz / Mozart** | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 302P/344W/3F/106S | **FFI-hybrid** (pure-Oz canonical CBOR value codec + C-ABI; bignum ints, IEEE floats as exact bit-patterns) | **FFI** — `libentitycore_codec` via the `entity-codec-daemon` `Open.pipe` co-process (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist`, `0.1.0-pre` |
| **Io** | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 308P/338W/3F/106S | **FFI-hybrid** (pure-Io canonical CBOR + C-ABI; `EcBig` uint64 carrier for the double number model) | **FFI** — `libentitycore_codec` via the in-process `EntityCodec` C addon (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist`, `0.1.0-pre` |
| **SQL** (authority-as-query) | probe | v0.8.0 | `c1b0708` | 755 · **2F** — 306P/340W/2F/107S | **seam-hybrid** — §5.2 ladder / §5.5 chain-walk (recursive CTE) / §3.6 K-of-N (`HAVING count DISTINCT`) / §6.6 (`ORDER BY length DESC`) **authored as real SQL** (`src/sql/`); thin C host owns sockets/CBOR/crypto/store over the C-ABI | **FFI** — `libentitycore_codec` (libsodium); crypto callable *from* SQL via `sqlite3_create_function` | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make dist`), `0.1.0-pre` |
| **Datalog** (authority-as-query) | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 306P/339W/3F/107S | **seam-hybrid** — §5.5 delegation as recursive **Ascent rules** to least fixpoint (SecPAL/Binder shape), §5.2 verdict as a derived `allow` fact, K-of-N counting aggregate, §6.6 stratified negation; pure-Rust host asserts `verified_signer` facts over the C-ABI | **FFI** — `libentitycore_codec` (libsodium); Ascent never touches a byte | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`cargo build --release`), `0.1.0-pre` |
| **Node-RED**‡ | exploratory | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | **interop** (delegates the TS peer's canonical CBOR + §6.5 engine) | **interop** — TS peer `@noble` (Ed25519 + SHA-256) | deferred (→ TS `@noble` seam) | not a peer (illustrative) |
| **TurboWarp**‡ | exploratory | v0.8.0 | `c1b0708` | 755 · **3F** — 308P/338W/3F/106S | **ALL FIVE handler bodies (§4 connect / echo / §6.3 tree / §6.2 handlers / §6.2 capability) + §6.5 dispatch + §5.2 verify AUTHORED in Scratch** — a dispatch spine routing to one `define dispatch-<handler>` custom block each; only socket/CBOR/crypto/store via the `ecutils` seam | **seam** — bundled `@noble` (Ed25519 + SHA-256) | deferred (→ bundled `@noble`) | not a peer (illustrative; real-VM confirmation pending) |
| **Pure Data**‡ | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 307P/339W/3F/106S | **§6.5 dispatch spine + §5.2 verify ladder + §4.6 auth ladder + §6.6 walk AUTHORED on the canvas** (pattern-first spine, one named unit per handler); bytes/CBOR/crypto/store/**TCP transport** in the `[ecodec]` C external (stock `[netreceive]` broadcasts replies — A-PD-002) | **FFI** — `libentitycore_codec` (libsodium) via `[ecodec]` | deferred (→ FFI, C-ABI `ec_ed448_*`) | not packaged (visual-paradigm probe on the real Pd runtime) |
| **Unison** | probe | v0.8.0 | `c1b0708` | 755 · **3F** — 309P/337W/3F/106S | **native** hand-rolled canonical ECF on **UCM runtime builtins — ZERO third-party dependencies** (CBOR/base58/LEB128 hand-rolled; `Float.toRepresentation` gives raw IEEE bits for the shortest-float ladder) | **native** — builtin `crypto.Ed25519.sign/verify.impl` + `crypto.hashBytes Sha2_256`; **key derivation HAND-WRITTEN in pure Unison** (GF(2²⁵⁵−19) base-2¹⁶ limb arithmetic + twisted-Edwards scalar mult — UCM ships sign/verify but NO keygen, A-UN-009) | deferred — **no C-FFI hatch** (managed runtime; Ed448/SHA-384 are not builtins, so the `libentitycore_codec` path other peers used is *structurally* unavailable) | Unison Share deferred, `0.1.0-pre` |

‡ **Node-RED (#31) + TurboWarp (#32) are exploratory visual-paradigm probes — NOT real, deployable peers, and distinct from the alien-substrate *language* probes (Tcl/Rexx/Forth/…) which are full gate-green peers.** **Pure Data (#33) is the third visual probe (reactive-patch, the paradigm's lone open representative) and the exception on measurement: it runs on the REAL Pd runtime over REAL TCP and clears the full core gate (682·0F Result: PASS @ `cc1970f`, genuine 2-of-3 multisig accept + origination 3/3) — a real conformant peer by the gate's standard, kept in the probe class because its purpose is paradigm-visualization (cohort-consistent lineage, shared C-ABI codec, ADR-0012).** They exist to answer "can the protocol be *authored in* a visual paradigm?" and to serve as **readable references for those communities** (a Node-RED or Scratch author can study the dispatch logic in their own idiom), **not** as something you would deploy. Node-RED delegates the entire §6.5 engine to the TS peer (a flow-graph wrapper); TurboWarp authors the dispatch + all handler bodies as Scratch blocks but delegates crypto to a bundled `@noble` seam, runs sandboxed (no raw TCP → oracle-reachable only via a WS↔TCP bridge, the browser-Rust/WASM pattern), and is measured by a faithful **block-interpreter** of the real `project.json` pending a real-TurboWarp-VM run. Neither is independent convergence (shared TS/`@noble` lineage, ADR-0012). Full synthesis of what the substrate sweep taught — **what translates, what needs a seam, what doesn't** — is in `research/SUBSTRATE-TAKEAWAYS.md`.

> **Update 2026-07-15 — Pure Data (#33) close-out: the first visual-paradigm probe to clear the FULL core gate.** `validate-peer --profile core` @ `cc1970f`: **682 · 287P/299W/0F/96S — Result: PASS**, every remaining skip a §9.0 extension carve-out (0 fail-counting), measured **natively on the real Pd runtime over real TCP** (no interpreter harness, no bridge). Genuine **2-of-3 multisig accept-path** (§3.6/§5.5 M3/M4/M6 K-of-N verification in the chain walk, persistent `EC_NAME` identity) + **origination-core `dispatch_outbound_reentry` 3/3** over real two-peer TCP (`run-origination-core.sh`). Authored on the canvas: the §6.5 **pattern-first dispatch spine** (one named unit per handler, per-handler op-switch), the §5.2 verify ladder, the §4.6 auth ladder, and the §6.6 longest-prefix walk; `[ecodec]` (a Pd C external on the C-ABI codec) owns bytes/CBOR/crypto/store **and the TCP transport** — stock `[netreceive]` broadcasts every reply to all sockets with no per-connection id (A-PD-002, proven at Pd source level), so transport is a legitimate seam on this substrate. The §6.11 reentry on a single-threaded canvas is a **bounded synchronous send+wait on the one inbound fd** (non-response frames hand back to the connection's assembler). Cohort-consistent (shared C-ABI codec + generation lineage), not independent convergence (ADR-0012). Per-peer detail: `protocol-generator/pd/status/`; survey verdict updated in `research/evaluations/visual-paradigms.md`.

> **Update 2026-07-13 — both peers reworked to author the protocol IN the paradigm, not wrap it (supersedes the "both delegate the §6.5 engine / both 249·2F" description below).** Node-RED's §6.5 is now the visible **16-node flow-graph** (still 249·2F — leaf crypto delegated + the throughput boundary). **TurboWarp was rebuilt, then completed:** the §6.5 dispatch, the full §5.2 verify sequence, and **ALL FIVE handler bodies** (§4 connect / echo / §6.3 tree / §6.2 handlers / §6.2 capability) are now authored as **Scratch blocks** (502 blocks) — reorganized from one 400-block tower into a short **dispatch spine + one `define dispatch-<handler>` custom-block procedure per handler** for legibility — with only the socket / canonical-CBOR / Ed25519-SHA / chain-verdict / token-mint / seed-cap / store mechanics behind the `ecutils` **seam** (deliberately no `dispatch` block). The **§6.6 handler resolution is authored as the actual tree WALK** (a `repeat until` that walks the dispatch path longest-prefix-first for the matching `system/handler` registration == `HandlerRegistry#resolve`) — not a hardcoded pattern list; the per-prefix store lookup + path slice are the only seam bits, and the final pattern→body match is just body-selection (Scratch can't call a procedure by dynamic name; resolved-but-un-authored handlers delegate). Measured **291 P / 294 W / 0 F / 97 S — Result: PASS @ `cc1970f`**, **solid 5/5 full-marathon runs** including both §6.11 robustness tests (`t2_1_sustained_load` + `t2_2_connection_churn`), via the headless **block-interpreter harness** (`turbowarp/src/harness/run-blocks.mjs`, which runs the *real* `project.json` block graph against the oracle). **The earlier flakiness was a harness-scheduling bug, now fixed** (not the old `A-TW-throughput` label, and not the connect authoring): the interpreter drained the inbound queue in one serial burst without yielding, so under §6.11 connection *churn* (t2_2) responses didn't flush before the oracle tore connections down → dropped requests → a downstream cascade. Yielding to the event loop between hats (`await setImmediate` — the cooperative per-tick model real Scratch already uses) resolved it; verified by reverting connect to delegated (which *also* failed t2_2 → proved the serial drain, not the authoring, was the root). A real-TurboWarp-VM run is the remaining confirmation. Still cohort-consistent (shared bundled `@noble` + generation lineage), not independent convergence (ADR-0012). Consolidated survey + when-to-stop verdict: `research/evaluations/visual-paradigms.md`. See `docs/status/HANDOFF-2026-07-13-turbowarp-closeout.md`.

The historical description below (both 249·2F, both delegating the §6.5 engine) is retained for the Node-RED throughput finding. Both delegate codec/crypto to the TS peer (Node-RED require()'d, TurboWarp esbuild-bundled), so a green result would be cohort-consistent, not independent (ADR-0012). `validate-peer --profile core` @ `cc1970f` for BOTH: **249 P / 293 W / 2 F / 101 S** — all correctness categories green (connectivity 22/22, type_system 108P, multisig 11 w/ genuine 2-of-3 accept-path, security 28, capability 12, §6.11 concurrency *correctness* t1_2/t1_3). The **2 identical FAILs are §6.11 sustained-load/churn robustness** (`t2_1`/`t2_2`) — a documented **throughput boundary** (`A-NR-throughput` / `A-TW-throughput`): they **pass standalone** and fail only under the full ~640-test marathon. That the LEAN TurboWarp harness hits the SAME boundary as Node-RED shows it is **engine-level** (the shared delegated §6.5 engine's full-suite sustained-load behavior on pure-JS crypto), not a per-runtime artifact — not a correctness defect, not memory-bound. Per "no green → no publish," unpublished. Value is visualization + generator-robustness, not a conformance claim. See `protocol-generator/{node-red,turbowarp}/`. The peer is authored as a Node-RED *flow-graph* (§6.6 dispatch ↔ wire routing); codec/crypto/§6.5-engine are delegated (interop) to the TypeScript peer, so a green result would be cohort-consistent, not independent (ADR-0012). `validate-peer --profile core` @ `cc1970f`: **249 P / 293 W / 2 F / 101 S** — **all correctness categories green** (connectivity 22/22, type_system 108P, multisig 11 w/ genuine 2-of-3 accept-path, security 28, capability 12, §6.11 concurrency *correctness* t1_2/t1_3). The **2 FAILs are §6.11 sustained-load/churn robustness** (`t2_1`/`t2_2`) — a documented **Node-RED-substrate throughput boundary** (`A-NR-throughput`): they **pass standalone** and fail only under the full ~640-test marathon (event-loop saturation + visual-runtime per-request overhead on pure-JS crypto), not a correctness defect, not memory-bound. Per "no green → no publish," unpublished. Value is visualization + generator-robustness, not a conformance claim. See `protocol-generator/node-red/`.
² **Every `--profile core` cell is a fresh measurement at oracle `c1b0708` (2026-08-21)** — `total · NF — P/W/F/S`, from one centralized `tools/run-cohort-census.sh` run over all 45 measurable peers. Nothing in this column is carried forward from an earlier pin: `755 ≠ 740`, so a `de8f807` figure is not comparable to one here even when the F-count matches. The **three** peers that did not execute the full 755 are quarantined in §1a rather than listed with a score. *(Four, until `csharp` was fixed 2026-08-22 — §1c.)*

⁴ **`Maint.` is the MAINTENANCE tier — how often this peer is re-measured, nothing else.** `M1` lockstep · `M2` priority catch-up · `M3` on-demand · `probe` paradigm probe · `exploratory` not a deployable peer. Defined per-peer in **`tools/peer-tiers.tsv`** (the roster) and explained in **§4**; current per-tier state is `tools/tier-status.py`. **These are NOT `research/LANDSCAPE.md`'s tiers 1–5**, which classify the *language landscape* ("what is worth building") rather than re-measurement cadence — the two were previously both written as bare `1`/`2`/`3` and were routinely confused, which is why these carry the `M` prefix. **A maintenance tier never affects whether a peer may be published**; it affects only how promptly it is re-measured after an oracle re-pin.

³ **`⚠ INVALID MEASUREMENT`** — this peer did not execute the same checks as the rest of the table, so **its P/W/F/S cannot be compared to any other row** and is not a verdict. The cause is always the same: the oracle's **global** `-timeout` expired mid-suite, after which whole categories are never run and are recorded at severity `SKIP` — the same severity as a deliberate `--profile core` extension carve-out — so `summary` reads as a near-clean run. Treat the numbers as a floor and read **§1a**.

**Every peer in this table is required to execute the identical check set** (`755` checks at `c1b0708`, digest `95edd774…`, pinned as `core_executed_check_set_digest` in `tools/oracle-pin.env`). This is **enforced, not assumed**: `tools/check-set-gate.py` validates every report in a census against that pin and hard-fails on any deviation or any `budget_exhausted` category, and `tools/run-cohort-census.sh` runs it automatically and exits non-zero when a census is not comparable. **This census: 41 of 45 conforming** — the 4 that deviated are in §1a, and the gate is what found them.

**Crypto-availability tiers** (the per-ecosystem story an adopter most needs): `native` = ships with runtime/stdlib or an in-language audited lib, no FFI; `managed` = a managed-code crypto package on the language's package manager; `FFI-hybrid` = native floor, Ed448 via `libentitycore_codec`; `FFI` = whole crypto surface via C-ABI; `deferred` = Ed25519+SHA-256 floor only, Ed448 not yet wired.


⁵ **Tier M1 — fixed this session, and the reference for everyone else.** These five went `3F/2F/83F` → **`0F`** at `c1b0708`. Three defect classes, all in the banner above and ratcheted in `AGENTS.md`: §5.6's MIN_DEFINED mint ceiling (absent in every peer, not merely wrong), CAP-6a's absent-vs-unrepresentable fail-open, and §6.3's missing `400 non_canonical_ecf` rejection status. `swift` needed a fourth — §5.5a frame over-scoping — which was the actual cause of its capability failures rather than a symptom. `lean`'s 83F was **2 real + 81 cascade** from one §6.3 defect; fixing it returned it to 0F, which is what confirmed the diagnosis. **These five diffs — plus M2's eight, landed 2026-08-22 — are the reference fix for the remaining 32** (§3): author it once from the spec, propagate, do not rediscover it 32 times. *(This footnote read "the reference fix for the other 40" before the M2 pass.)*

---

## 1a. INVALID MEASUREMENTS — three peers, and why they are not scores

**Status at `c1b0708`: `asm-x86_64` · `asm-arm64` · `riscv64` (714/755).
All three have `budget_exhausted` categories. None of the three is listed with a P/W/F/S anywhere in
§1, because a run measured on a different set of checks is not a worse score — it is not a score.**

`tools/check-set-gate.py` reports **42/45 conforming** and exits non-zero on exactly these three;
`tools/run-cohort-census.sh` does the same. That is the gate working as designed — **a non-zero
exit from the cohort gate is the expected, documented state today, not a regression**, and it is
attributable in full to this section.

**`csharp` was the fourth until 2026-08-22 — it is now FIXED and fully comparable.** It was a clean
`740 · 0F` at `de8f807`, then came back at 698 of 755 checks with 9 starved categories at this pin.
**Root-caused 2026-08-22: it was `typescript`'s §6.3 defect in its hang-form — see §1c.** Same 3 real
FAILs at the same indices, same cascade onset, but the peer dropped the frame and left the connection
open instead of closing, so each downstream check waited out a timeout (CAP-6a alone: 120 s) until the
global budget expired. Fixing the missing `400 non_canonical_ecf` restored both a valid measurement
and 0F in one change: **`755 · 0F — 313P/336W/0F/106S`, run time 18 m 20 s → 7.2 s.** Nothing had
regressed. *(This paragraph read "it has not been root-caused" until 2026-08-22, and "one fix should
restore both" until that fix was measured.)*

**The asm/ISA trio — what the "1 FAIL" was actually hiding.** Traced and measured 2026-08-17, still
unfixed, and the reason this section exists:

`asm-x86_64`, `asm-arm64` and `riscv64` each report `699 · 1F` in §1. That single visible FAIL
(`concurrency/t2_2_connection_churn`) is **not** the whole state, and the "peer-latency flake"
label this matrix used until 2026-08-17 was wrong in kind. What the census actually measured:

**1. One hung check starves seven whole categories, including a core one.** `t2_2_connection_churn`
does not fail fast — it hangs and burns **599 s of the oracle's 600 s global `-timeout`** (the whole
rest of the suite runs in ~0 ms). The oracle then records seven categories as
`budget_exhausted`, and its human output says so loudly — `!! WHOLE CATEGORIES NEVER RAN … this is
coverage loss, not a slow peer`. **The JSON summary does not**: the starved categories land in
`skipped`, so a reader of `summary` alone sees `1 failed` and a slightly high skip count. Starved:
`authz`, `crypto_agility`, `format_agility`, `negotiation`, `peer_canonicalization`,
**`resource_bounds`** (a *core* gate category), `universal_address_space`.

**2. Running the starved categories directly surfaces 2 more real core FAILs.** Driven one category
at a time so `concurrency` cannot eat the budget (`-category <name>`, `asm-x86_64`):

| Category | Result |
|---|---|
| **`resource_bounds`** | **FAIL 2/3** — `r1_payload_over_limit` (oversize frame closes the connection, spec-allowed, but the peer does not recover on the post-oversize probe) and `r3_connection_flood` (**admitted all 256 connections with no refusal** — no §4.10(c) admission cap — **and then fell over on the serve probe**) |
| `authz` | PASS (4 WARN) |
| `crypto_agility` · `format_agility` · `negotiation` · `peer_canonicalization` · `universal_address_space` | PASS, 0 FAIL |

So the honest count is **3 core FAILs** (`t2_2_connection_churn`, `r1_payload_over_limit`,
`r3_connection_flood`) — and all three are **one failure family**: the peer stops serving under
connection pressure.

**3. What the failure is — and what it is not.** Measured directly rather than inferred from the
accept-loop source:

- **Not qemu, not emulation.** `asm-x86_64` runs natively and fails identically to the two emulated ports.
- **Not a full-marathon-only flake.** `-category concurrency` alone reproduces it.
- **Not deterministic.** It hits cycle 29 of 100 in the full run and cycle 7 standalone — a random
  draw, so the previously-recorded "cycle 29" was never a meaningful constant.
- **Not resource exhaustion.** Sampled once per second across a full run: parent fds flat at 4,
  RSS flat at 1792 KB, live children steady at 3–7. Nothing grows. 60 rounds of bare TCP
  connect/close produce **zero** accumulation, so the accept/fork/reap path itself is sound.
- **What it is:** a subset of forked children **block forever in `read(2)` on their connection fd**
  (`/proc/<pid>/syscall` → syscall 0 on fd 4, `wchan=wait_woken`, state `S`, unchanged 8 s later).
  Those children never time out and never exit; the oracle's request on such a connection times out
  as `peer refused or hung`. Two contributing defects are visible in the same dump: **no idle/read
  deadline on a served connection**, and **the listening socket is leaked into every child**
  (all stuck children share fd 3 → the same socket inode as the parent's listen fd).

**Root cause is characterised, not fully traced** — the specific path on which a child blocks
instead of completing or closing has not been isolated to an instruction. Flagged at the same
standard as A-OZ-008 / A-IO-025 (report what is measured, do not over-invest ahead of a fix
session). The fix shape is known from the cohort: a per-connection read deadline plus the
**§4.10(c) connection-admission cap** that `r3_connection_flood` says outright is missing — the
same pairing Rexx landed as A-RX-014.

**4. Separately: the asm trio's higher raw PASS count is an artifact, not better conformance.**
Their `545P/42W` next to the cohort's `307P/327W` does **not** mean they pass more. **283
`type_system` checks that WARN for every other peer PASS for these three**, because
`src/typestore.s` publishes ~200 type entries — including whole **standard-extension** vocabularies
(`system/type/compute/*`, `content/*`, `clock/*`, `continuation/*`). The oracle treats those as
*matched-if-present*, so publishing them converts WARN→PASS. This is **not** an oracle violation,
but it **is** a deviation from this repo's own standing rule for core peers — *"scope to core +
operational + the type-system bootstrap only; a core peer never pre-publishes extension
vocabularies"* (`AGENTS.md`). Only these three peers do it (`grep -rl 'compute/apply'` over
`protocol-generator/*/src/` hits `asm-*` and `riscv64` and nothing else). **Do not read the asm
trio's P count as comparable to the rest of the table.**

Full trace, probe scripts and raw output: `research/stewardship/SESSION-2026-08-17-asm-budget-starvation.md`.

---

---

---

## 1b. `typescript`'s 84F was 3 real FAILs and 81 cascade — the same defect `lean` had — **FIXED 2026-08-22**

> **Resolved.** `typescript` is now **`755 · 0F — 312P/337W/0F/106S`**. This section is retained
> because the *diagnosis* is the reusable part: the 84 was never a measure of how bad the peer was,
> and reading it that way would have sent the fix in the wrong direction. The analysis below is
> as-measured before the fix.

**Do not read 84 as "typescript is the worst peer in the cohort." It was a 3F peer with one
connection-killing bug**, and the bug was `lean`'s, already fixed and verified there.

Measured, not inferred. `typescript`'s failure sequence is byte-for-byte the shape `lean` had before
its fix: the first FAIL of all 755 is `capability/configure_empty_grants_withdrawal` (**idx 558**),
followed immediately by `request_mint_temporal_ceiling` (559) and `request_ttl_zero_and_overflow`
(560) — those three, and only those three, are real. The last check before the first transport error
is `capability/ingest_rejects_unrepresentable_expiry` (a WARN whose own message reports a
**transport-drop** rather than the §5.2 `capability_denied` disposition), and from **idx 563** onward
every category fails on a dead connection — `tree_operations` 20, `security` 29, `multisig` 12,
`authz` 10, `universal_address_space` 7, `peer_canonicalization` 3.

*(This paragraph named idx 559 / `request_mint_temporal_ceiling` as the first FAIL until 2026-08-22.
Off by one check: 558 is `configure_empty_grants_withdrawal`. The real-FAIL count of 3 and the idx-563
cascade onset were both correct; only the identity of the first was wrong.)*

That is §6.3's missing rejection status (banner item 1): an undecodable frame is refused by dropping
or closing instead of answering `400 non_canonical_ecf`, and on a peer that closes, the refusal takes
the whole connection with it. **`lean` went 83F → 0F on exactly this fix**, and its 81 cascade
vanished — which is what turned the diagnosis from plausible into confirmed.

**CONFIRMED 2026-08-22 — the prediction held exactly.** `typescript` is now
**`755 · 0F — 312P/337W/0F/106S`**, byte-identical to the M1 five, and the run fell from a cascading
84F to a clean PASS in 33.9 s. All 81 cascade FAILs vanished with the one §6.3 change; the 3 real
FAILs took the §5.6 ceiling + CAP-2 fix. No transport error at idx 563 any more.

---

## 1c. `csharp`'s INVALID measurement was the SAME defect as `typescript`'s — ROOT-CAUSED **and FIXED** 2026-08-22

> **Resolved.** Both peers are now `755 · 0F` (`csharp` 313P/336W, `typescript` 312P/337W). Retained
> because the *differential* is the reusable part: it is how a starved run gets attributed to a known
> defect instead of being filed as a harness problem. Analysis below is as-measured before the fix.

**`csharp` was not an unexplained new failure. It was `typescript`'s §6.3 defect with the other
failure mode: `typescript` *closes* on an undecodable frame, `csharp` *hangs*.** That single
difference is what turned an 84F score into a starved, unscoreable run — and it meant one fix
addressed both the FAILs and the INVALID status, which is exactly what happened.

This supersedes the "not root-caused" note carried in §1a and §3 since 2026-08-21.

**The evidence, measured from the census reports, not inferred:**

| | `typescript` | `csharp` | `go`/`lean` (fixed) |
|---|---|---|---|
| First FAIL | idx **558** `configure_empty_grants_withdrawal` | idx **558**, same check | — |
| Real FAILs | 3, at idx 558/559/560 | **3, at idx 558/559/560 — identical** | 0 |
| First transport error | idx **563** | idx **563** — identical | — |
| CAP-6a check `elapsed_ms` | **5 ms** | **120 060 ms** | 1 ms |
| Cascade error text | fast close | `read response: i/o timeout` | — |
| Total run | **2 733 ms** | **1 100 556 ms** (18 m 20 s) | ~2 s |
| Outcome | 84F, full 755 measured | 52F, **9 categories never ran** → INVALID | `755 · 0F` |

**The mechanism.** Both peers reject an undecodable frame without answering `400
non_canonical_ecf` (§6.3, banner item 1). `typescript` closes the connection, so every later
check fails *instantly* — 81 cascade FAILs, but the suite still completes and the measurement
stays valid. `csharp` instead **drops the frame and leaves the connection open**, so the oracle
blocks until its own timeout on every subsequent request. The CAP-6a check alone burns **120 s**
(six field×shape variants × a 20 s block) — that is AGENTS.md's documented symptom (a), *"the
sender blocks until its own timeout, so a refusal is indistinguishable from a dead peer."*
`security` then burns 600 s and `tree_operations` 380 s, the 10-minute global budget expires, and
`authz` · `concurrency` · `crypto_agility` · `format_agility` · `multisig` · `negotiation` ·
`peer_canonicalization` · `resource_bounds` · `universal_address_space` never run.

**So the starvation is a symptom, not an independent problem.** `csharp` was a clean `740 · 0F`
at `de8f807` because CAP-6a did not exist as a check then — the drop-form defect was always
present and simply had nothing to expose it. Nothing regressed.

**CONFIRMED 2026-08-22 — and the timing is the proof.** `csharp` is now
**`755 · 0F — 313P/336W/0F/106S`**, a fully comparable measurement (`check-set-gate.py` PASS, zero
`budget_exhausted`). The whole run went from **1 100 556 ms (18 m 20 s) to 7 198 ms** — a ~150×
collapse from one change to the read loop. That is the diagnosis proving itself: if the starvation
had been latency, slowness, or a resource problem, answering `400 non_canonical_ecf` instead of
falling silent would not have touched it. Nine categories that had never run now run.
The precise mechanism, confirmed in the source: `csharp` did not merely drop the frame — it `break`ed
out of the read loop **without closing the socket**, so the oracle's every later write went to a
socket nobody was reading. Functionally identical to a hang, and a shape worth recognising on its
own: *a peer that stops reading but stays connected is indistinguishable from a slow peer.*

**Generalizable, and the reason this got its own section:** *a hang and a close are the same
`§6.3` bug, but they present as two completely different failure classes* — one as a large FAIL
count on a valid measurement, the other as a quarantined INVALID with a *small* FAIL count. The
diagnostic that unified them is cheap and should be run first on any starved peer: **compare the
first-FAIL index and the first-transport-error index against a known peer with the same defect.**
Here they matched exactly (558 / 563), which is what turned "csharp is a mystery" into "csharp is
typescript."

## 2. Capability & parity table

Feature parity is **not** uniform — the 5 T2 peers (C, Ada, Ruby, Prolog, Go) were built on a separate track and folded in later, so some normalization is still outstanding. This table makes the gaps visible; the catch-up items are in §3.

| Peer | Tier | Persistent identity CLI | `--validate` (§7a) | Genuine §3.6 K-of-N multisig¹ | Concurrency (§7b) | Idiom / discovery axis |
|------|:----:|------------------------|:------------------:|:------------------------------:|-------------------|------------------------|
| OCaml | 1 | `--name` | ✅ | ✅ genuine + selftest | OS-threads + mutex | strict-ML / result |
| Swift | 1 | `--name` (+`--owner-identity`, `--seed-policy`) | ✅ | ✅ genuine + test | actor-isolation (structural) | ARC / **grapheme-string** |
| Haskell | 1 | `--name` | ✅ | ✅ genuine + test | **STM (structural)** + GHC RTS | lazy / pure / monadic |
| Go | 1 | `--name` + `-seed` (Go-idiom single-dash flags) | ✅ (`-validate`) | ✅ genuine + test — **was frame-only, FIXED 2026-07-12** (accept-path PASS) | goroutines + mutex | static / clean-room |
| Lean | 1 | (host shell) | ✅ | ✅ genuine + **proven** (`multiSigRootOk_quorum`) | pure core (no shared store) | dependent-type / **proof** |
| C# | 2 | `--name` | ✅ | ✅ genuine (reference impl) | threads + lock | OO / exceptions |
| TypeScript | 2 | `--name` | ✅ | ✅ genuine (reference impl) | event-loop + promise-mutex | structural JS / bigint |
| Java | 2 | `--name` | ✅ | ✅ genuine + test | threads + lock | JVM / OO |
| Kotlin | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** | coroutines + concurrent-collections (atomic-per-key) | JVM / **sealed-Result + coroutines** |
| Elixir | 2 | `--name` | ✅ | ✅ genuine + test | actor-isolation (structural) | BEAM actor |
| Common Lisp | 2 | `--name` | ✅ | ✅ genuine + test | raw threads + manual | CLOS multiple-dispatch |
| Zig | 3 | `--name` | ✅ | ✅ genuine + test | threads + mutex (raced before fix) | no-GC / comptime |
| C | 3 | `--name` + `--seed` (**added 2026-07-12**) | ✅ | ✅ genuine — **was frame-only, FIXED 2026-07-12** (accept-path PASS) | **raw pthreads** (A-C-009; A-C-011 churn flake) | **manual malloc/free** |
| Ada | 3 | `--name` + `--seed` (**added 2026-07-12**) | ✅ | ✅ genuine — **was frame-only, FIXED 2026-07-12** (accept-path PASS; exposed A-ADA-014) | **protected objects (structural)** | safety-critical / contracts |
| Ruby | 3 | `--name` + `--seed` | ✅ | ✅ genuine + test — **was frame-only, FIXED 2026-07-12** (accept-path PASS) | GVL (released on IO) + mutex | dynamic / duck-typed |
| Crystal | 3 | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + in-image unit | **CSP fibers + Channels, single OS thread (structural store-safety, no mutex; graceful SIGTERM — A-CRY-011, 20/20 crash-free)** | **compiled/typed Ruby-like / fixed-width int / libsodium `lib`/`fun`** |
| Odin | 3 | `--name` | ✅ | ✅ **genuine + accept-path** (multisig K-of-N Allow + M3/M4/M6 deny flips) + 53-type byte-diff drift target | **raw OS threads + `sync.Mutex` (manual §4.8; A-ODIN-009 store carries pinned allocator)** | **data-oriented / no-GC `context` alloc / no-exceptions `or_return` / native pure-Odin crypto** |
| Prolog | 3 | `--name` (real load, **fixed 2026-07-12**) | ✅ | ✅ genuine (`verify_multisig_root/4`; accept-path PASS) | OS-threads + clause-DB RMW | **logic / SLD-resolution** |
| Rust (clean-room) | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** (oracle `33f35fd`) | std::thread + RwLock — **compile-enforced** | static / Result / `#![forbid(unsafe)]` |
| Python (clean-room) | 2 | `--name` | ✅ | ✅ genuine + accept-path **ran** (oracle `33f35fd`) | threads + explicit Lock (GIL-aware) | dynamic / duck-typed |
| PHP | 3 | `--name` | ✅ | ✅ genuine + accept-path **ran** | **single-thread `stream_select` event loop (structural)** | dynamic / **event-loop store-safety** |
| Dart | 3 | `--name` | ✅ | ✅ genuine + accept-path **ran** | event-loop confinement per isolate (structural) | **sealed-Result + Future / BigInt-web** |
| COBOL | 3 | `--name` | ✅ | present (11/0 pass) — ✅verify genuine | **single-threaded `poll()` loop + §6.11 reentry pump** | **FFI-hybrid / GnuCOBOL PIC records / COMP-3** |
| Tcl | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread `chan event`/`vwait` event loop (structural)** | **EIAS / everything-is-a-string / event-loop** |
| Rexx | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread select-pump over the `ecnet` co-process daemon (structural)** | **native-decimal number model / EIAS byte-string / RC-flag errors** |
| Fortran | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread select-loop over the linked C net-shim (structural)** | **fixed-width signed-only integer / IEEE-native / iso_c_binding-direct** |
| Forth | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread select-pump, IN-PROCESS sockets + crypto (no co-process; structural)** | **stack-machine / typeless cells / RPN — no native records** |
| Smalltalk | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + 4/4 in-image unit | **single green-process event loop on one OS thread, IN-PROCESS Sockets + UFFI crypto (no co-process; structural)** | **pure-object / live-image / message-passing — polymorphic `encodeOn:` double-dispatch** |
| APL | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **single-thread `⎕FIO` select-pump (structural) + §6.11 reentry pump** | **array / value model / `⎕FIO`-native sockets / `→`-branch tradfns** |
| asm-x86_64 | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) | **fork-per-connection (blocking) + §7a.2a reentry demux via request/response frame router + `pending_tab` (structural)** | **hand-written x86-64 asm (GAS/AT&T) — the lowest-level substrate; FFI codec/crypto** |
| wasm-wat | probe | hardcoded conformance seed (`--name` deferred) | ✅ **echo + reentrant dispatch-outbound dialer** | deferred (local-env; needs `--name` keypair) | **single-thread `poll_oneoff` over non-blocking sockets + §7a.2a SAME-connection reentry demux via `pending` table; JIT crypto-execution-mode load-bearing (§6.11)** | **hand-authored WebAssembly text (WAT) — interpreted-substrate / crypto-execution-mode probe** |
| rust-wasm | probe | hardcoded conformance seed (`--name` deferred) | ✅ **echo + reentrant dispatch-outbound dialer** | deferred (local-env; needs `--name` keypair) | **single-thread `poll_oneoff` + §7a.2a SAME-connection reentry demux via single-threaded reentrant pump; single-send framing (Nagle fix) + JIT crypto-execution-mode load-bearing (§6.11)** | **Rust compiled to `wasm32-wasip1` — the COMPILED-wasm codegen sibling of wasm-wat (unmodified interior + 336-line transport seam)** |
| Julia | 3 | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + 8/8 unit | **single-thread Task scheduler (cooperative, structural) + §6.11 Channel reentry** | **native multiple-dispatch codec / UInt64+BigInt hybrid numeric / JIT** |
| Nim | 3 | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted`) + 4/4 unit | **single-thread asyncdispatch event loop (structural) + §6.11 pending-table reentry** | **compiles-to-C / ARC-ORC deterministic GC / compile-time-macro codec / fixed-width uint64** |
| Unison | probe | `--name` | ✅ | ✅ **genuine + accept-path ran** (`valid_2of3_peer_signed_accepted` — a hard FAIL before K-of-N landed, so the category is NOT vacuously green here); supplementary peer-side unit authored but **UNVERIFIED** | **abilities (algebraic effects) over IO — `fork` green threads + a single `MVar` store (`take → pure fn → put` serializes every mutation through one cell; actor-like BY CONSTRUCTION) + per-request `Promise` §6.11 demux** | **content-addressed codebase / headless `ucm transcript` build / fixed-width 64-bit Nat+Int / NO C FFI — pure-Unison Ed25519 keygen** |
¹ "Genuine" = real §3.6 M3 (structure) + M4 (distinct-signer threshold) + M6 (local ∈ signers) with a positive accept-path test, per the multisig cohort closeout. The original 10-peer cohort was verified genuine + accept-path-GREEN against oracle `33f35fd`. **The later-folded peers were re-verified 2026-07-12 by making the oracle's `valid_2of3_peer_signed_accepted` accept-path RUN (provision the peer keypair + boot `--name conformance`) — and 4 of 5 were FRAME-ONLY: Ruby/Go/C/Ada rejected a valid co-signed 2-of-3 (a masked defect, since the reject-dominated `multisig` category passes vacuously for a fail-closed peer). All four were fixed (genuine M3/M4/M6, accept-path PASS @ `cc1970f`); Prolog + COBOL were already genuine. See the 2026-07-12 finding note in `research/stewardship/`.** (The accept-path FAIL *does* gate — a SKIP is auto-allowlisted, a FAIL is not — so this was a real 0-FAIL risk once exercised.)

**Standard host CLI surface** (the cohort convention): `--name NAME` (load Ed25519 identity from `~/.entity/peers/NAME/keypair`) · `--port N` · `--validate` (bootstrap §7a `system/validate/*` conformance handlers, OFF by default) · `--debug-open-grants` (deprecated; degenerate `default→*` seed policy) · `--help`. Go uses the same surface with Go-idiom single-dash flags. C/Ada currently expose identity via `-seed` only.

---

## 3. Maintenance state & catch-up backlog

**Standing maintenance loop (the steady state):** when a spec amendment lands and Go ships the corresponding `validate-peer` update, re-vendor the oracle, re-run **M1** immediately and converge to 0-FAIL, then catch up M2/M3 as capacity allows. *(This paragraph said "Tier-1/Tier-2/Tier-3" until 2026-08-21 — the exact bare-numeral spelling §4 warns is routinely confused with `research/LANDSCAPE.md`'s selection tiers. Corrected to the `M` prefix.)* **As of 2026-08-22 the loop has completed its first two stages: the oracle is re-vendored, M1 converged 5/5 (2026-08-21), and M2 converged 8/8 (2026-08-22). It is now at step three — M3 and the probes catching up** — see §4. *(This read "mid-cycle and stalled at step two … M1 has not converged" while that was true, on 2026-08-21.)* This is the engine of spec refinement now — not new languages (see the fifteen-peer architecture milestone review, §5).

| Item | Scope | Priority | Notes |
|------|-------|----------|-------|
| ~~**Oracle normalization**~~ ✅ DONE | whole cohort | — | **CLOSED.** All 17 peers re-run on one oracle `entity-core-go @e8524ed` (go HEAD) → uniform **665·0F**. Procedure + the when/why rule now live in `research/diagnostics/oracle-vendoring-policy.md`. (The 649-vs-653 phantom-build lesson is captured there as provenance hygiene: build once into repo-root, never per-peer.) |
| ~~**run-s4 oracle-path defaults**~~ ✅ DONE | C, Ada, Ruby, Prolog (+ Rust, Python) | — | **CLOSED.** All `run-s4.sh` + `run-origination-core.sh` defaults normalized to the repo-root `/work/output/s4-oracles/…` convention; they now run with no `ORACLE` override. (Lean keeps `/repo/output/…` by its distinct `-v "$PWD":/repo` mount convention — correct as-is.) |
| ~~**Re-normalize cohort onto public-HEAD oracle**~~ ✅ DONE | whole cohort | — | **CLOSED (2026-07-10).** The public `entity-core-go` mirror rewrote history — the pinned `e8524ed` no longer resolves. Re-pinned `tools/oracle-pin.env` (+ `protocol-generator/cpp/tools/oracle-pin.env`) to the reproducible public HEAD `cc1970f`, and **hardened the core-gate anchor**: `oracle-bootstrap.sh` now fingerprints the *normalized category set + 53-type floor* (`core_gate_fingerprint = 8261a03…`), comment/format-invariant, instead of the raw `profile.go` sha256 — so the V8 comment reword that flipped `e09a865`→`74e04e3` no longer false-alarms "core gate moved" (regression-tested: comment reword → fingerprint unchanged; category drop → fingerprint moves). The `cc1970f` core gate is thereby **provably** the gate the cohort converged against, so every peer's `--profile core` 0-FAIL carries. Cohort table + reading note re-normalized to `cc1970f`. *Optional remaining (non-gating):* a fresh full-suite re-run of the 21 non-COBOL peers on `cc1970f` to re-measure their extension-inflated `665` totals natively (COBOL already runs natively at `cc1970f`); deferred, as core is the gate and it carries. |
| ~~**Scorecard label fix** `62044c5 → b30a589`~~ ✅ DONE | provenance | — | **CLOSED (2026-07-12).** A-C-008 / A-ADA-013: `62044c5` was off-by-one; `b30a589` is the true v7.75 baseline where `resource_bounds` activates under `--profile core` (clean `62044c5` auto-skips it → 574·0F·90S, not the recorded 576·0F·89S). Corrected in-repo across the 9 v7.75-re-run peer reports that paired `576·0F·89S` with `62044c5` (common-lisp, csharp, elixir, haskell, java, ocaml, swift, typescript, zig); C/Ada already carried `b30a589`. Remaining `62044c5` mentions tree-wide are accurate history (the clean-subset evidence runs) and left intact. |
| ~~**CLI normalization** (`--name`)~~ ✅ DONE | C, Ada, Ruby, Go, Prolog | — | **CLOSED (2026-07-12).** The audit found the deviation was wider than "C/Ada lack `--name`": **neither Go nor Ruby actually had `--name`** (only `--seed`; the matrix had overclaimed it), and **Prolog's `--name` was a fake** (parsed then ignored, seed hardcoded). Standardized all five on the canonical convention (OCaml/Swift/Haskell/COBOL): default seed `0x11×32`; `--name NAME` loads the seed from `~/.entity/peers/NAME/keypair`. Go/Ada default seed normalized `0x01`→`0x11`. Each `run-s4.sh` provisions the conformance keypair + boots `--name conformance`. |
| ~~**Verify genuine multisig** on later-folded peers~~ ✅ DONE | C, Ada, Ruby, Prolog, Go, COBOL | — | **CLOSED (2026-07-12) — with a real finding.** Making the accept-path RUN exposed **4 of 5 as FRAME-ONLY** (Ruby/Go/C/Ada rejected a valid co-signed 2-of-3 — a masked conformance defect the reject-dominated `multisig` category hid). All four fixed with genuine §3.6 M3/M4/M6 (`multisig_root_ok`, modeled on the genuine Prolog peer) → accept-path PASS @ `cc1970f`; Ruby/Go carry in-repo unit tests, C/Ada guard via the now-genuine S4 accept-path. Prolog + COBOL were already genuine. The Ada fix additionally uncovered **A-ADA-014** (a latent §PR-8 fixed-length-String crash). Finding note in `research/stewardship/`. |
| **Capability mint temporal ceiling** (§5.6 / §6.2) — **FIXED in M1+M2 (13 peers), owed to 32** | 32 peers (M1's 5 + M2's 8 are done) | **Highest — it is the entire gap between the cohort and 0-FAIL** | **The fix exists, is verified, and just needs propagating.** §5.6's MIN_DEFINED construction was ABSENT in every peer (`mintToken` set no `expires_at` at all); implemented in `go`/`haskell`/`lean`/`ocaml`/`swift` and all five went to 0F. **The rules, from `spec-data/v0.8.2/ENTITY-CORE-PROTOCOL.md` §5.6:** `expires_at = MIN` over the **DEFINED** terms of `{parent.expires_at, caller_capability.expires_at, created_at + policy_entry.ttl_ms, created_at + request.ttl_ms}` — the first two ABSOLUTE, the last two DURATIONS converted against a **once-sampled** `created_at`; `ttl_ms == 0` is **defined** and yields `created_at` (do NOT special-case it — letting it fall out of the arithmetic is what stops it collapsing into the "no bound" spelling); an overflowing term is **dropped**, never wrapped or saturated; and an over-long request from a bounded caller **mints `200` with the clamped value — rejecting it is non-conformant.** Reference diffs: commits `e979e6c` (go), `58d190c` (ocaml), `8f790f6` (haskell), `cf2717c` (lean), `ded3e07` (swift). |
| **CAP-6a ingest fail-OPEN** (§6.2 / §5.2) | fixed in all 13 M1+M2 peers; unmeasured beyond them. **Present in 3 of 5 M1 peers and in ALL 6 of the remaining M2 peers** — assume it is present until measured | **Highest — security** | A received capability whose `expires_at`/`not_before`/`created_at` is not `uint64`-representable is malformed and MUST be refused via the §5.2 `capability_denied` disposition. `go`/`haskell`/`ocaml` **honored it and returned 200**. Mechanism, identical in five type systems: the idiomatic accessor (`Uint`/`uint_field`/`uintField`/`uintAt`) answers "nothing" for BOTH an absent field and a present non-uint one, so the expiry check is silently skipped. **The representability check must run BEFORE the range check it protects.** |
| **§6.3 rejection status missing** — the cascade source — **FIXED in all 13 M1+M2 peers; unmeasured in the other 32** | fixed in M1's 5 and M2's 8 (`typescript` §1b, `csharp` §1c); unmeasured elsewhere — **assume present until measured** | **High — one change, up to −81 FAILs per affected peer, and it can also un-starve an INVALID run** | §6.3: *"Rejection returns `400 non_canonical_ecf`"*. **Not optional even when a peer is already at 0F:** `rust` and `common-lisp` both reached 0F while still scoring CAP-6a **WARN**, because the `>2^64` half of that check can only arrive as a major-type-6 tag and is therefore rejected at decode — it needs the §6.3 answer to be *scored* as a refusal at all. Every M1 peer rejected an undecodable frame and then said nothing — `continue`, a logged skip, `break`/close, or a `none` that ended the read loop. §4.9(c) deliver-or-signal says the same. On a peer that closes, ONE bad frame kills the connection and every later check fails on it. **`lean` 83F → 0F and `typescript`'s 81 cascade are both this.** Fix shape: keep the strict decoder byte-unchanged, add a salvage decode used ONLY to recover `request_id`, answer 400, keep serving — the frame stays rejected, so the `tag_reject` wire-conformance vectors keep their meaning. |
| **§5.5a frame over-scoping** | `swift` (fixed); not seen in M2's eight; **worth grepping the remaining 32** | Medium | §5.5a's per-link granter frames scope the **RESOURCE dimension only**. swift passed them to all four dimensions of `grantSubset` and defaulted `peers` to them — identical to correct whenever child and parent share a granter, and fatal the moment a **delegated** cap arrives. **Enforcement grep:** in each peer, only the resources comparison may receive the granter frames. |
| ~~**`csharp` INVALID MEASUREMENT**~~ ✅ **DONE (2026-08-22)** | `csharp` | — | **CLOSED.** Was 698 of 755 checks with 9 `budget_exhausted` categories. **Never a distinct defect: it was `typescript`'s §6.3 missing-rejection-status in the hang-form** (drop + hold the connection open, rather than close), so every downstream check waited out a timeout — CAP-6a alone burned 120 s of the 10-minute budget — and the tail never ran. Identical 3 real FAILs at identical indices (558/559/560) and identical cascade onset (563) to `typescript`; that one comparison is what turned it from "new at this pin, not root-caused" into "it is `typescript`". **§1c** has the full differential. The §6.3 fix restored a valid 755-check run *and* 0F together: `755 · 0F — 313P/336W/0F/106S`, 18 m 20 s → 7.2 s. `-timeout` was never raised. |
| **Connection-pressure defect** (3 core FAILs each) | asm-x86_64, asm-arm64, riscv64 | **High** — it is the only thing between these three and a 0-FAIL gate, and it suppresses coverage | `t2_2_connection_churn` + `r1_payload_over_limit` + `r3_connection_flood`, one failure family: forked children block forever in `read(2)` with no idle deadline, and there is no §4.10(c) connection-admission cap. Characterised + measured 2026-08-17 (**§1a**); root cause not isolated to an instruction. Fix shape known from the cohort (A-RX-014 pairing). Three ISAs of hand-written asm — its own session. |
| **Extension type-vocabulary over-publication** | asm-x86_64, asm-arm64, riscv64 | Medium — cosmetic to the gate, material to the matrix's comparability | `src/typestore.s` publishes ~200 types incl. COMPUTE/CONTENT/CLOCK/CONTINUATION extension vocabularies, against `AGENTS.md`'s "a core peer never pre-publishes extension vocabularies". Converts 283 `type_system` WARNs to PASSes, so these three read `545P/42W` vs the cohort's `307P/327W` — **a higher pass count from a scope violation, not better conformance** (**§1a**). Enforcement grep: `grep -rl 'system/type/compute/apply' protocol-generator/*/src/` should be empty. |
| ~~**Per-peer `status/CONFORMANCE-REPORT` records one pin behind**~~ ✅ **DONE (2026-08-22)** for the 13 publishable peers | 13 done · 32 remain (they are behind on the *fix*, not just the record) | — | **CLOSED for everything this repo currently publishes.** Found in the release sweep: every tracked `status/CONFORMANCE-REPORT.json` was at the retired `de8f807` **740**-check set or older (38 at 740, 4 at 682, 1 at 645, `io` unreadable); **none at 755**. The `.md` siblings were worse — several led with `cc1970f`/`b30a589`-era banners quoting `552`/`576` totals from oracle `cb54f5b`. So a clone showed each peer's own report contradicting its §1 row. **Never a wrong number in §1** (census-backed) and **not caused by the M1/M2 passes** — the cause was structural: `run-cohort-census.sh` deliberately never writes tracked reports and `output/` is gitignored, so no driver could refresh them. **Fixed three ways:** (a) `run-cohort-census.sh --to-status` adds the missing destination to the *same* dispatch table (explicit opt-in, never the default); (b) all 13 publishable peers **re-measured** against the pinned oracle — each reproduced its published number exactly, 13/13 comparable; (c) `tools/check-set-gate.py --tracked`, now run by `make lint`, gates the committed reports so this cannot silently return. The 32 unfixed peers are reported by the gate but do not fail it — disclosed debt, and they rejoin the gated set as the CAP fix reaches them. **Refreshing a tracked report is a MEASUREMENT — never hand-copy a census JSON onto one.** |
| **`authz_peers_target_from_uri`** — WARN on every peer | all | Low — inconclusive by design | A single standalone peer cannot resolve `target_peer` against a synthetic foreign URI; needs a real two-peer harness to exercise. Not attempted since it was found 2026-08-16. |
| **RT-13b Class M** — own ≥2-writer concurrency test | 18 peers (`ada c cobol common-lisp cpp csharp haskell java julia kotlin lean ocaml odin prolog python ruby unison zig`) | Medium | Unchanged since 2026-07-28, re-confirmed 2026-08-13. Its own session's work. |
| **Ed448 agility** for deferred peers | Swift, Zig, C, Ada, Go | Demand-driven | Floor (Ed25519+SHA-256) ships; Ed448 via the OCaml FFI-hybrid pattern or native lib when an adopter needs it. |
| **Publish** (registry uploads) | all | Demand-driven | All parked at `0.1.0-pre`; per-ecosystem publish is an operator step gated on a community pull. |

---

## 4. Maintenance tiers — the workflow contract (ACTIVE)

**Status: active, and enforced by tooling.** From 2026-08-17 an oracle re-pin does **not** mean a
45-peer census. It means: re-run **M1**, converge it to 0-FAIL, and the re-pin is landed. Lower
tiers catch up behind it, and their lag is *tracked in the open* rather than being either hidden or
treated as an emergency.

This existed as prose before and drifted — §4 named 17 peers while the cohort had grown to 46, so
"re-run Tier-1" had no unambiguous meaning and every re-pin became a full census anyway. It is now
a data file plus two commands.

> **These are MAINTENANCE tiers — re-measurement cadence only.** They are not
> `research/LANDSCAPE.md`'s tiers 1–5, which classify the *language landscape* and answer "what is
> worth building". Both used to be written as bare `1`/`2`/`3`; the `M` prefix exists so they can
> never be confused again. **A maintenance tier never decides whether a peer may be published** —
> "no green report → no publish" is unchanged and applies to every peer regardless of tier.

### The contract

| Tier | Peers | Cadence | Gates a re-pin? |
|---|---:|---|:---:|
| **M1** — lockstep | 5 | Re-run on **every** oracle re-pin, before the re-pin is considered landed | **Yes** |
| **M2** — priority catch-up | 8 | Re-run once M1 has converged | No |
| **M3** — on-demand | 13 | Spare capacity · before a release · on an adopter request | No |
| **probe** — paradigm probe | 18 | When its own axis is touched, or before a release | No |
| **exploratory** — not a deployable peer | 2 | Never gates anything (§1 ‡) | No |

**M1 is `go` · `haskell` · `lean` · `ocaml` · `swift`** — chosen for spec-discovery capability and
axis coverage, not popularity: OCaml is the proven headline finder (A-OC-007), Haskell brings the
STM substrate and the cleanest record, Swift is the sharpest string/grapheme instrument, Go is the
clean-room generator-independence check, and **Lean is the proof vector — the only formal-methods
discovery channel we have**, kept in M1 deliberately despite higher upkeep.

*M1 is a default, not a cage.* Pull any peer up temporarily when an amendment touches its axis — a
memory-model change → add `c`; a numeric-model change → add `rexx` or `fortran`; a capability/authority
change → add `sql` or `datalog`, which author that surface in the query language and read it most sharply.

*Standing open question, carried forward:* `rust` and `python` sit in **M2**, and that placement is
**provisional** — a steward may promote them to M1 alongside the clean-room `go` peer as same-language
generator-independence checks against the hand-written siblings `entity-core-{rust,py}`. Not done yet;
it would take M1 from 5 peers to 7.

### Where the assignment lives

**`tools/peer-tiers.tsv`** is the single canonical home — all 46 peers, one tier each, plus the
oracle pin each peer's current verdict was measured at. The §1 `Maint.` column mirrors it. Nothing
else defines a tier.

### The two commands

```
tools/tier-status.py                      # where every peer stands, per tier
tools/tier-status.py --full               # + every peer's P/W/F/S
tools/tier-status.py --gate               # exit non-zero unless M1 is current AND 0-FAIL

tools/run-cohort-census.sh --tier M1      # the lockstep gate — 5 peers
tools/run-cohort-census.sh --tier M1,M2   # after M1 converges
tools/run-cohort-census.sh --stale        # only peers behind the current pin
tools/run-cohort-census.sh                # everything (pre-release)
```

A tier run gates **only the peers it ran** — otherwise `--tier M1` would exit non-zero because of a
probe nobody re-ran, and the exit code would stop meaning anything.

### Current state — 2026-08-22 @ `c1b0708` (post-M1-fix, post-full-census, post-M2-fix)

| Tier | Current & 0-FAIL | State |
|---|:---:|---|
| **M1** | **5 / 5** | **Fixed 2026-08-21 — the re-pin is LANDED.** `tools/tier-status.py --gate` exits 0 |
| **M2** | **8 / 8** | **Fixed 2026-08-22.** `typescript` 84F → 0F and `csharp` INVALID → 0F were the *same* §6.3 defect in its two presentations (§1b/§1c); the other 6 took the same CAP fix |
| **M3** | 0 / 13 | Re-measured. 11 at 3F · `nim` 4F · `cobol` 30F (CAP trio + its standing 27) |
| **probe** | 0 / 18 | Re-measured. 13 at 2–4F · `asm-x86_64` `asm-arm64` `riscv64` INVALID (§1a) · `apl` unmeasurable |
| **exploratory** | 0 / 2 | Re-measured. Both 3F. Never gates (§1 ‡) |

**Every tier is current on the pin — nothing is stale.** What the lower tiers carry is a *peer*
debt, not a measurement debt, and it is one debt: **25 of the 29 scored unfixed peers fail nothing
but the new CAP checks** — 23 at exactly 3F with a byte-identical P/W/F/S, 2 at 2F. That is the §5.6
mint ceiling, absent everywhere, measured across the cohort. *(Before the M2 pass this read "31 of
the 40 unfixed"; the count moved, the finding did not.)*

**This is the tier policy paying for itself in both directions.** Running M1 first (5 peers) found
the entire gating delta and produced a verified fix; running the full 45 afterwards is what
established that the gap is *uniform* rather than 40 separate problems — and it caught two things
M1 alone could not: `typescript`'s cascade and `csharp`'s invalid measurement, which the M2 pass then
proved were one defect, not two. **Tiering governs the cadence between releases; a release still runs
everything, and this one did.**

**What M2 added that M1 could not have taught.** Thirteen languages took the same ~200-line fix over
the same five places, unchanged — and that invariance is the evidence the spec reading is right, not
merely that the tests pass. But two lessons only appeared past the M1 sample: **CAP-6a's fail-open has
two mechanisms, not one** (null-collapse *and* an arithmetic fail-open that involves no null at all,
so the grep that catches one misses the other — `AGENTS.md` carries both), and **§6.3 is not optional
even at 0F** (`rust`, `common-lisp`). Pattern-matching off M1 alone would have missed both.

### Why this is on now

The cohort is at 46 peers while the spec is still in flux — arch `cb5df2c` landed four §6.2
capability rulings the same week, and `entity-core-go` implemented two of them within a day. Running
45 peers per change is not affordable at that rate and produces nothing M1 wouldn't have caught: the
discovery well has been dry on the current wire surface since ~15 peers (§5), so peers 16–46 are
corroboration and generator-robustness, not new findings. **M1 is where a real regression shows up
first; the rest is breadth, and breadth can lag by design as long as the lag is visible.**

*Deliberately unchanged:* the release gate. Before a release, run everything (`run-cohort-census.sh`
with no arguments) — tiering governs the cadence *between* releases, not what a release claims.

---

*Companion evidence: the per-peer `protocol-generator/<lang>/status/` records (CONFORMANCE-REPORT, ARCHITECTURE-REVIEW, SPEC-AMBIGUITY-LOG) and the cross-language findings register `research/stewardship/SPEC-FINDINGS-LOG.md`.*
