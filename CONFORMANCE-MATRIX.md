# entity-core-keystone — Conformance & Status Matrix

**The transparency contract for adopters.** Before you pull a generated peer, check its row here. A peer being a spec-version behind, or lacking Ed448 agility, or carrying a known gap, is a **documented, tracked state** — not a surprise. "This peer doesn't do X yet" lives here, in the open, with a tier that tells you when it'll be caught up.

**Cohort:** **46 peers in the tree · 46 measured · all 46 at ONE pin — the 778-check set `7aa6f3de…` · **46 of the 46 at 0-FAIL** (2026-09-08).** Every number in §1 is a fresh measurement at that pin — nothing is carried forward. **The pin is a content digest, not a commit** — see [The pin](#the-pin--content-anchored-and-why-there-is-no-commit-here) for the full anchor set and how to reproduce a number without access to our `dev` branch.
>
> **The set moved 758 → 778 on 2026-09-08 (oracle `c34abcae…` → `7aa6f3de…`, spec snapshot `v0.8.2.3` → `v0.8.2.11`) and the two sets are NOT comparable.** The 20 new checks are §4.7's connect-error table (0.8.2.4/0.8.2.6) plus §3.3's 404/501 code rows (0.8.2.7). **Every one of the 46 peers needed work for them and every one is green**: at the moment the candidate check set was first run across the roster, **1 of 46 passed** (`go`). All 46 tracked reports below were re-measured at the new pin — not carried forward, not copied. A control re-measurement at the RETIRED pin taken immediately before the flip moved **3 of 34 868 severities** across all 46 reports, all three the same `concurrency/t1_1_concurrent_demux` timing ratio, two against and one for; none was banked.
>
> **The earlier movement, kept because the reason still applies:** the set moved 756 → 758 on 2026-09-03 and those two are likewise not comparable. The census now passes `-reference-peer`, which runs `origination/{dispatch_outbound_reentry,reference_connect,reference_ready}` in place of a single `origination: skipped` placeholder. It had never been passed, which is why a separate origination harness existed on 31 peers and was absent on 15; those 15 gained the checks here. The delta is exactly +3 and −1 and nothing else, verified by diffing the sorted check-name sets. Never diff a row across this boundary.

| | Peers |
|---|---|
| **0-FAIL @ the 778-check pin** (46) | `go` `haskell` `lean` `ocaml` `swift` (**tier M1**, 5/5) · `common-lisp` `csharp` `elixir` `java` `kotlin` `python` `rust` `typescript` (**tier M2**, 8/8) · `ada` `c` `cobol` `cpp` `crystal` `dart` `julia` `nim` `odin` `php` `prolog` `ruby` `zig` (**tier M3**, 13/13) · `apl` `asm-arm64` `asm-x86_64` `datalog` `forth` `fortran` `io` `oz` `pd` `rexx` `riscv64` `rust-wasm` `rust-wasm-wasmtime` `smalltalk` `sql` `tcl` `unison` `wasm-wat` (**probe**, 18/18) · `node-red` `turbowarp` (**exploratory**, 2/2) |
| **Not measured** | *(none)* |

*The `Larger`, `INVALID MEASUREMENT` and `Not measured` rows are gone because the peers in them are gone, not because the categories were retired. `cobol` was 30F; the asm/ISA trio were quarantined starved runs; `apl` was carried as unmeasurable. **None of the three turned out to be what it was filed as** — see the 2026-08-30 blocks below, §1a and §1d.*

*This table has now been wrong twice in the same shape. It was one pin behind between 2026-08-28 and 2026-08-29 — reading `0-FAIL (13)` with 23 fixed peers filed under `3F`, four lines below a headline that already said 39. It then read `45 of 45 · 1 unmeasurable` for one day while the 46th was measurable and had simply not been run. The per-peer rows in §1 were correct throughout; the summary above them was not, both times. **A summary table is a second copy of a number and rots on its own schedule** — and the second occurrence landed in the very commit that wrote the first one down.*

**The headline is one sentence: every peer in the cohort passes `--profile core` at 0-FAIL — 46 of 46, with no exclusions and no unmeasured row.** `--profile core` gained three `capability` checks at the 2026-08-21 re-pin and every unfixed peer failed exactly those three; that uniformity was the finding, and it held all the way through. The fix shape did not vary across **thirty-seven** languages — the same five places every time (capability mint, codec salvage decode, wire `400`, read loop, policy lookup) — and that invariance is the evidence the spec reading is right, not merely that the tests pass.

**What that sentence does NOT say, and the distinction is the whole point of this document.** These 46 peers share a generation lineage and pass one author's vectors at one pinned check set: **cohort-consistent, not independent convergence** ([ADR-0012]). The three ISA peers are one design ported twice on top of that. And several of the defects closed on 2026-08-30 had been *passing* checks for months for reasons unrelated to what those checks test — a green row is evidence about the wire, not a proof about the peer.

**No row now carries a disclosed gap behind its 0-FAIL verdict. The last one — `cobol`'s
payload capacity — closed 2026-09-04, and both entries below are kept because how each was
found is worth more than the fact that neither is open.**

> **This sentence said "one row" while two more carried an undisclosed gap, and the correction is the more useful half.** `rust-wasm` and `rust-wasm-wasmtime` published **109** skips against the cohort's 106, in rows that printed the figure honestly beside prose asserting only one such row existed. The three extra were *not* `--profile core` carve-outs: they were the `multisig` accept-path checks (`valid_2of3_peer_signed_accepted`, `below_threshold_rejected`, `below_threshold_denied_write`), skipping with *"accept-path requires the peer's on-disk key (M6 root-at-local): peer keypair not found"* — an **unconfigured surface**, and a skip counts as a FAIL ([ADR-0012]). Cause: these were the only **2 of 46** harnesses that never provisioned `~/.entity/peers/<name>/keypair`; the peers' identity is compiled in, but the *validator* reads that file to co-sign AS the peer. Provisioned 2026-09-03 and re-measured: both are now **313P/337W/0F/106S**, six previously-unexercised checks now running and passing. **The find was mechanical and is worth repeating on every re-pin: ask of every tracked report which skips are NOT explained by a declared carve-out.** A per-peer skip count that differs from the cohort's is either a disclosure or a defect, and nothing was checking which.

**CLOSED 2026-09-04 — `cobol` carries no extra skip. It is at `758 · 317P/336W/0F/105S`, the
cohort's modal row exactly**, and against a peer on that row it differs by two offsetting
checks that were the same before this change (`authz_scope_exceeds_1` PASS where that peer
WARNs, `r3_connection_flood` WARN where it PASSes — both pre-existing, neither touched here).

The gap was `concurrency/t1_3_no_head_of_line`, which stages a **264 109-byte** frame — measured
on this peer's own oversize branch, not taken from the vector's "256 KiB" prose — against a
65535-byte frame cap that refused it with a correlated `413 payload_too_large`. **The finding
that produced stands and is not retired by the fix**: that bound was spec-legal (§4.10(a)
requires only that the maximum be **finite**, and the core protocol "places no restriction on
entity size"), so a conformant peer could not be fully *measured*, and raising our cap does not
change that for the next implementer. It stays routed as
`protocol-generator/shared/findings/conformance-payload-capacity-floor.md`.

**What the capacity actually cost, because the previous attempt is why it had been left open.**
Raising the buffers alone was measured in 2026-09-02 as unaffordable — a 512 KiB map-value slot
cost ~34 MB per call per nesting level and took the `concurrency` category from 15.5 s to 9 m
50 s. That number was a property of the DATA STRUCTURE, not of the capacity: `cbor-canon` is
recursive, its LOCAL-STORAGE is allocated and initialized per invocation, and it buffered every
map value into a fixed per-pair slot. It no longer buffers values at all — each pair records its
canonicalized key and the input offset its value starts at, and the values are canonicalized
straight into the output in sorted-key order. Per call, per level: **2.13 MB → 65.8 KB**. The
store made the same move for the same reason, from 1024 fixed slots to one arena addressed by
offset. With both, the frame capacity is 512 KiB and the suite is **FASTER than it was at 64 KiB**
— 47.9 s → 13–15.7 s, 7 of 7 runs.

**Two severities moved and one of them is the reversal of a trade this document published.**
`t1_3` SKIP → PASS, and `t1_1_concurrent_demux` **WARN → PASS** — the same check the 2026-09-02
note below records going PASS → WARN when the buffers grew. It returns because the peer got fast
enough that the oracle's sequential baseline falls under its 50 ms floor and the speedup signal is
suppressed. Verified per-check: **exactly 2 of 758 severities moved**, 7 of 7 runs identical, no
`budget_exhausted`, executed check-set digest equal to the pin.

**Footprint, measured rather than estimated, because that is what the capacity is bought with.**
Idle virtual 79 MB → 229 MB (the 320 admission slots at the new frame cap are most of it); RSS
after one full suite 100 MB, after five 240 MB, against a 4 GB container cap
(`protocol-generator/shared/diagnostics/cobol-footprint-probe.sh`). **A pre-existing
address-space leak was found while measuring this, and it was not introduced by this change** —
bisected against `HEAD` rather than assumed: **23.3 MB per suite before, 22.3 MB after**. It tracked
requests, not connections (~1 KB per dispatched request). It was not `cobol`'s: the mechanism was in
`libentitycore_codec`, which this peer links, and **it is fixed — the peer's virtual size is now flat
from the first suite onward, against +22.7 MB per suite before.** §3.

> *Two corrections to what this paragraph used to say, both found by measuring rather than re-reading.* **(1)** From 2026-08-30 it claimed both extra skips were refused with `413`. That was true of the 16 KiB one only. The 264 KB probe exceeds the FRAME cap and never reached any COBOL code: `netshim.c` drained the body and answered **nothing** — a §4.9(c) silent drop billed to the caller's deadline, which is why the check read as `i/o timeout` and was filed as a capacity skip. §4.10(a) makes the `413` a MUST; added 2026-09-02. **(2)** The 8192-byte per-entity ceiling was raised to 32 KiB the same day, which took `t1_4_frame_write_atomicity` **SKIP → PASS** and the skip count 108 → 107. **Say the other direction too: `t1_1_concurrent_demux` went PASS → WARN** (stable, 4 of 4 runs against 3 of 3 PASS before), because the larger canonicaliser buffers slowed the peer enough that its concurrent/sequential ratio no longer clears the 0.70 threshold. The oracle calls that WARN *"not a §6.11 violation — informational … for runtimes that do not physically parallelize"*, which describes this single-threaded poll peer accurately, so the row is a real gain traded against a more honest label. Verified per-check: **exactly 2 of 756 severities moved.** The ceiling stops at 32 KiB and not higher because `cbor-canon` is recursive with a 64-entry LOCAL-STORAGE pair table, so a 512 KiB value slot costs ~34 MB per call per nesting level — measured: sustained load dropped 7454 of 10000 requests and the category went 15.5 s → 9 m 50 s.

**The ISA trio's type-registry over-publication is CLOSED (2026-08-30).** It was the second disclosed gap here, and for as long as it stood the three peers read `594-595P/53-55W` against the cohort-standard `312P/337W`. `src/typestore.s` is now filtered to the 53-name core floor, and the three rows read `312-313P/336-337W` — **the pass count FELL by 282 and that is the fix, not a regression.** Those 282 `type_system` checks are matched-if-present, so publishing extension vocabularies had been converting WARNs into PASSes; the higher number was the scope violation. All three stayed `755 · 0F` and the change touched nothing outside `type_system` (verified per-check, before against after, on each peer). `asm-x86_64` reads one PASS above the other two for the unrelated reason in ⁹. Detail: ⁹ and §3.

**One skip is disclosed at the 778-check pin, on ALL 46 peers, and the reference peer has it
too — `connectivity/connect_ping_before_hello`.** §5.1 `ping` is a NETWORK-extension operation
that a core peer does not serve, so the row this check asserts (an *implemented* operation
arriving in a forbidden state → `409 connection_sequence_error`) is not drivable against one —
which the check says in its own message, and which §3.3's satisfaction mode (0.8.2.7) makes
explicit: *a check MUST NOT be pinned to a row it cannot reach.* What is missing is only the
§9.0 profile carve-out marker, so the oracle counts the skip against its FAIL gate and ends
`Result: FAIL (un-allowlisted skips)` while reporting `{"failed": 0}` in JSON. **This is an
upstream gate defect, not a cohort gap, and `entity-core-go`'s own peer produces it byte for
byte** — which is how it was located: the reference peer was checked first. Routed as **F59**;
allowlisted by name in `tools/skip-provenance-gate.py`, and removing those 46 entries is part of
closing it. It has one operational consequence worth stating plainly: the oracle **exits
non-zero**, so the five harnesses that propagate that exit code deliberately (`io`, `pd`,
`python`, `ruby`, `sql`) return 1 on a fully green run. They have not been made to swallow it.

**The ISA trio's `handler_not_found_on_unregistered_path` skip is CLOSED (2026-09-08), and a
skip counts as a failure here rather than a carve-out.** `asm-x86_64`, `asm-arm64` and `riscv64`
dispatch by OPERATION rather than by a §6.6 tree walk, so an unregistered path and an
unregistered *operation* were the same answer — `501 unsupported_operation` — and the oracle read
that as a peer registering a catch-all and SKIPped §3.3's 404 row under its 0.8.2.8
total-handler exception. Legal, and it left 43 of 46 peers passing a row three could not reach.
All three now carry `uri_handler_known`, a predicate over the handler set they already publish
as `system/handler/*` interface entities, and answer `404 handler_not_found` for a path no
handler governs — ahead of the 501/403 pair, per §6.5's resolution-first order. Each moved
`334P/336W/0F/108S → 335P/336W/0F/107S`: one skip fewer, one pass more, still `0F`, and onto the
cohort-standard row.

**The one disclosed skip is CLOSED (2026-09-07), and it was never about the payload.** `asm-x86_64`
carried `316P/336W/0F/106S` — one skip above the cohort — because
`concurrency/t1_3_no_head_of_line` could not stage its 256 KiB payload: the peer's §6.3 `put`
admission refused the oracle's staging entity with `400 hash_mismatch`. It now reads
**`317P/336W/0F/105S`** and the check PASSes; the allowlist entry is deleted, as its own doc requires.

**Two defects, and the first one is why the disclosure said "not root-caused."** The diagnosis
recorded here cited a standalone call to `libentitycore_codec.so` returning the sender's hash for
exactly those bytes. That was true, and it tested a **different function than the peer runs.**
`asm-x86_64` links `codec.o` *before* `-lentitycore_codec`, so its own native `ec_content_hash`
(`src/codec.s`) wins over the `.so`'s — the Makefile says so in a comment — and that native one
built the ECF into a fixed **64 KiB `ecf_scratch`** while the peer accepts frames to **16 MiB**.
Measured: rc=0 up to a 65 503-byte value, **rc=−2 `EC_OUT_OF_SPACE` from 66 005 up, with the output
buffer left UNWRITTEN.** Second defect: `admit_put` never checked that return code, so it compared
the carried hash against an untouched `.bss` buffer and reported `hash_mismatch` — **a peer capacity
limit stated as an accusation about the submitter's bytes.**

Both fixed. `ecf_scratch` is now sized against the input it can legally receive (`MAX_FRAME`, the
same 16 MiB as the request buffer the entity arrives in), and the ladder distinguishes `−3` (a
decode fault, genuinely step 1 → `invalid_request`) from `−2` (a capacity limit → `413
payload_too_large`, the §4.10(a) disposition this peer already uses for the frame cap) — never
`hash_mismatch`. The native codec was differentialled against the `.so` across the old boundary
before the number was believed: **14 sizes, 0 to 4 MiB, byte-identical, 0 divergent**, with the
compare-against-itself case asserted rather than assumed. Verified per-check: **exactly 1 of 758
severities moved**, and it is `t1_3` SKIP → PASS.

**✅ RESOLVED UPSTREAM — kept because the shape of the disclosure is the reusable part, and because it outlived its own cause by nine days on this page.** §4.7's status table used to **contradict itself** about an `authenticate` arriving before any `hello`: row 6 said `401 invalid_nonce` (restating §4.6 step 1, with the citation), row 10 said `400 connection_sequence_error`, and **no check exercised the input**, so a 0-FAIL verdict said nothing about it. Architecture folded the question: `ENTITY-CORE-PROTOCOL` now pins the pre-hello case to **`401 invalid_nonce`** and states outright that it is *not* the out-of-order row (0.8.2.8), the oracle grew `connectivity/connect_prehello_authenticate`, and **all 46 peers PASS it** at the current pin — verified per-check across the committed reports, not inferred. The disclosure below is the 2026-08-30 measurement that fed the ruling.

**Re-measured on the wire 2026-09-09, and the split is empirically gone: 46 of 46 answer `401 invalid_nonce`**, positive control `200` on every peer. That is the independent probe agreeing with `connect_prehello_authenticate` peer-for-peer, which is the condition this repo set for retiring a probe rather than keeping a second source of truth — so `tools/p47-run.sh` is deleted and `tools/p47-probe/` is retired. The six divergent peers moved at `5a53b75c` (the 0.8.2.3 sweep, 2026-09-01) and `prolog`'s third answer with them. **`csharp` is measured for the first time and closes the one open row** (FM-1k): it answers `401 invalid_nonce`, and its pre-sweep source answered `400 connection_sequence_error` — a one-line diff in that same sweep — so `entity-core-formalization`'s source read of it was right about the source they read, and their census stands at **35 of 35 resolved peers with zero disagreements**.

The 2026-08-30 measurement, kept as the record that fed the ruling — 45 of 46 peers, `csharp` then unbuildable offline: **38 answer `401 invalid_nonce`, 6 answer `400 connection_sequence_error`, `prolog` answers `401 authentication_failed`.** The split was **not** 38 implementations endorsing one reading — asked the same `authenticate` *after* a hello, only those 6 gave a different answer. The other 39 gave the same answer either way, i.e. they never modelled the pre-hello case at all and reached row 6's status as a by-product of the nonce check. Cohort weight was much weaker than 38–6 made it look, and an argument from it had to carry that caveat. **That caveat is the durable half and it survives the closure**: the ruling went the way the fall-through majority happened to point, and it went there on the text, not on the tally. Raised by `entity-core-formalization`; the normative question was architecture's **and has been answered — row 6 won**, so the 6 divergent peers were swept and the check now gates it. Full census, method, and the three probe defects the controls caught: [`prehello-authenticate-wire-census.md`](protocol-generator/shared/findings/prehello-authenticate-wire-census.md).

**A CORE MUST was unmet behind SEVEN of these green rows, and our half of it is now CLOSED (2026-09-09, F62).** §6.6's `resolve_handler` walks path prefixes for a `system/handler` entity, and its pseudocode ends *"Implementations MAY use a pre-built dispatch index for performance. The index **MUST** produce equivalent results to the tree walk."* Measured: `asm-arm64` `asm-x86_64` `cobol` `forth` `fortran` `riscv64` `smalltalk` answered **`404 handler_not_found`** when dispatched at a pattern where a `system/handler` entity **provably exists** — the oracle's own `core_register_handler_at_path` registers there, asserts the entity's type, and PASSes on all 46. The other 39 resolved, and **12 of them answered `501`**, which is what proves resolution succeeded and separates this from the §6.13(a) evaluator question. **`core_register_*` is nine checks that prove every WRITE and never dispatch at the pattern they just proved exists**; the two neighbours that look like they would are pointed at `system/tree` (a bootstrap handler) and at a built-in. **This corrects our own census finding**, which called all three host-seam failure shapes non-conformance: true of the other two, false here. **All seven now answer `501 no_handler_body`, every negative control is still 404, and exactly `0 of 778` severities moved on every peer** — which is what a MUST with no check looks like in numbers. It was **three** repairs, not the two the finding predicted: `smalltalk` had the container and the walk with only the wire path unwired; `cobol`, `fortran` and `forth` were **already walking the entity tree**, and their 404 came from the body-selection rung *below* resolution (`forth` additionally kept two key spaces for one fact, so its walk had nothing to be equivalent to); only the ISA trio needed a walk built, and theirs is consulted after the native index so an empty store behaves exactly as before. **What is still owed is the gate**, and deliberately not six per-peer unit tests: one Kind C independent check for §6.6 index/walk equivalence covers all 46 peers and retroactively gates `smalltalk`. Until it exists the evidence is `tools/host-seam-probe`, which measures and does not gate. Routed as **F62** — the vector ask is arch's and remains open; full chain in [`handler-resolution-index-equivalence.md`](protocol-generator/shared/findings/handler-resolution-index-equivalence.md).

**And one gap is cohort-wide rather than per-row:** `r3_connection_flood` WARNs on **42 of 46** peers — only `asm-x86_64`, `asm-arm64`, `riscv64` and `pd` self-bound admission — because §4.10(c)'s connection-admission cap is a SHOULD that most peers delegate to the supervisor. It never gates. It is named here because until 2026-08-30 it was disclosed only as something two ISA peers owed a third, which had it exactly backwards (§3). *(It was 44 WARN / 2 PASS earlier that day; `asm-arm64` and `riscv64` received the port and moved to PASS, which is why all three ISA rows now read `313P/336W`.)*

**Three peers in the count were never broken.** `rust-wasm`, `rust-wasm-wasmtime` and `node-red` were reported at 3F against build artifacts older than the sibling source they compile — they had inherited their parents' 2026-08-22 fix and nothing had re-measured them (§3). *(Pre-2026-08-28 this paragraph read "32 peers remain unfixed … 25 of those 29 fail nothing but those checks"; correct when written, closed by the propagation pass.)*

**Reading a row.** Each `--profile core` cell is `total · NF — P/W/F/S`, measured at the oracle's **default 10-minute global `-timeout`**. The **`NF` figure is the gate**; the `total` is extension-inflated and non-gating (it moves between oracle builds without any verdict changing). A skip counts as a failure unless it is an explicit `--profile core` extension carve-out. Per [ADR-0012] these peers are **cohort-consistent, not independent convergence** — they share a generation lineage and, for the FFI-hybrid peers, one codec `.so`; a cohort of generated peers all passing one author's vectors is not 40 independent confirmations.

### The pin — content-anchored, and why there is no commit here

**Every number in this document is anchored by a digest of the oracle's own content. None is anchored by a commit hash, and that is deliberate** — [ADR-0012] Amendment 1 (2026-08-23): *"a published conformance number is anchored by a CONTENT DIGEST of the oracle's check set … a commit SHA is a non-normative convenience and, where given, MUST be reachable from the published branch."*

| Anchor | Value | What it identifies |
|---|---|---|
| **`core_executed_check_set_digest`** | **`7aa6f3de…`** | The **778 checks a `--profile core -reference-peer <addr>` run actually executed.** This is the per-row anchor: the Oracle-pin column in §1 carries it, and `tools/check-set-gate.py` refuses to place two peers in the same column unless both reports carry it. |
| `core_gate_fingerprint` | `8261a033…` | The normalized category set + 53-type floor — *which categories run*. Comment- and format-invariant. |
| `check_set_digest` | `866ef058…` | The sorted set of check names the oracle **source** declares (non-test files only) — *what those categories assert*. |
| spec snapshot | `v0.8.2.11` — `ENTITY-CORE-PROTOCOL.md` `c97e1860…`, `ENTITY-CBOR-ENCODING.md` `433e094e…`, `ENTITY-NATIVE-TYPE-SYSTEM.md` `043fc80d…` | The normative text the peers were generated against, SHA-256-pinned per file in that snapshot's `MANIFEST.md`. |

Full values, provenance, and the movement history of each: `tools/oracle-pin.env`.

**Why not a commit.** [ADR-0027] authors every published commit **fresh at the release boundary**, so public `master` is a *different history* from `dev` — not a rewrite, just two lines that were never the same line. A `dev` SHA has therefore never resolved for a public reader and never will. Measured 2026-08-23: `entity-core-go`'s public `master` HEAD is `cc1970f` (the v0.8.0 release) and its `dev` is **514 commits** past it, so **the oracle this cohort was measured on exists on no public branch under any name.** There is no publicly-resolvable commit to cite that would not also be a *different oracle* from the one that produced these numbers.

This is not hypothetical and it is not new. The figures in this file's historical note blocks include `665·0F @ e8524ed` — and `e8524ed` stopped resolving anywhere on 2026-07-10 when go's mirror rewrote history. What carried the verdict across that death was the fingerprint, already recorded beside the dead commit in `tools/oracle-pin.env`:

> `retired_ref_4 = e8524ed  (unreproducible after mirror history rewrite; same fingerprint)`

**The commit died; the content anchor did not.** Publishing the anchor rather than the commit is that lesson applied ahead of the next occurrence instead of after it.

**Reproducing a number with no access to our `dev`.** Clone `entity-core-go` at whatever ref carries the same oracle content — after the release that is a commit on public `master` with a hash we have never seen and do not need to know. Run `tools/oracle-bootstrap.sh`: it prints `core_gate_fingerprint` and `check_set_digest` for whatever it built and requires **both** to match `tools/oracle-pin.env` before it will call the oracle current. If both match, it is the same gate — then run the cohort and compare each report's `core_executed_check_set_digest` (`tools/check-set-gate.py`). Identity by content was always the mechanism the tooling used; until 2026-08-23 only the documentation still led with the SHA.

**Honest limit, stated rather than implied.** Until `entity-core-go` publishes a `master` carrying this oracle, an outside reader can *verify* an oracle they have but cannot *obtain* the one these numbers were produced on. That is go's release to make, not something a digest fixes, and it is disclosed here rather than papered over. Where a `dev` commit still appears below — in the dated build-log note blocks and the closed-items ledger — it is **internal provenance for us, not a citation for the reader**, and those figures are already marked historical.

**Spec surface:** Entity Core **v0.8.2.11** is the pinned snapshot (`protocol-generator/shared/spec-data/v0.8.2.11/`, SHA-256-pinned per file in that snapshot’s `MANIFEST.md`) — but **no peer has been regenerated against it yet.** Every peer below was generated against **v0.8.0**, has taken each amendment as a targeted fix since, and is measured at the 778-check pin `7aa6f3de…` (all 46 of them; there is no unmeasured row). That gap is deliberate and tracked: the oracle is what gates the wire, and a snapshot reaching a peer is a regeneration question with its own cadence. *(A prior revision of this paragraph named a consequence that does not survive checking: it said **`pd` still carries F37's pre-rename `system/identity/peer-id` in 3 files**. Re-measured 2026-08-30: it is **2 files with one live code site** — `src/ecodec/ecodec.c:2399`, plus comments and its own ambiguity log — and it is **not pre-rename debt**. `pd` registers the type under BOTH names deliberately, because `ENTITY-NATIVE-TYPE-SYSTEM.md` v0.8.0 itself names it two ways and both are live `type_ref`s in one spec version; the peer's `A-PD-012` says so and escalates it as **F33**, awaiting arch's choice of canonical name. Registering both is the more spec-complete reading, not a gap. `pd` is tier M3 and 0-FAIL.)* Standard extensions are out of scope — every peer below is a *core* peer. The core wire contract is byte-unchanged across the V7→V8 cutover (see that dir's `MANIFEST.md`). The oracle's core category set + type floor (`cmd/internal/validate/profile.go`) is what gates `--profile core`; its committed anchors — `core_gate_fingerprint` **and** `check_set_digest` — are in `tools/oracle-pin.env`. **Both must match for a verdict to carry forward**: the fingerprint alone tracks *which categories run*, never *what they assert* (established at the `af8a582` cutover, where four hard-FAIL vectors landed inside existing core categories under a byte-identical fingerprint).

**Conformance gate:** `validate-peer --profile core` — the extension-free categories (`connectivity`, `encoding`, `type_system`, `origination`, `resource_bounds`, `concurrency`, + the §10.1 register / §7a conformance-handler gates).

**Where §1's numbers come from, and what is *not* in the repo — read this before citing a cell.** Every `--profile core` figure in §1 is generated from the centralized census, `output/scratch/census/<peer>.json`. **`output/` is gitignored, so those artifacts are not committed** — the numbers are *reproducible from the pin* (`tools/oracle-bootstrap.sh` rebuilds the oracle at `tools/oracle-pin.env`'s `ref`; `tools/run-cohort-census.sh` re-runs the cohort), not *archived in the tree*.

**The committed per-peer records agree with §1 for every peer we publish.** All **46** publishable peers' `protocol-generator/<lang>/status/CONFORMANCE-REPORT.{md,json}` are at the pinned 778-check set and each reproduced its §1 row exactly; `make lint` runs `tools/check-set-gate.py --tracked`, which fails if a peer published as 0-FAIL carries a committed report from an older check set. **Nothing is behind the pin: 46 of 46 at the pinned set, 0 stale.** *(This paragraph itself said "All 45 … at the pinned 755-check set" and "One peer's committed report is behind the pin — `apl`, at the retired 682-check set" until 2026-09-09, three pin flips after both stopped being true. §1's rows were correct throughout, which is why nothing caught it — `coherence-gate` check 6 exists because of this line and found it on its first run.)* *(Through 2026-08-29 the behind-the-pin count read "the remaining 6": `cobol` and `wasm-wat` at 740, the asm/ISA trio at 682, `apl` unmeasurable. All were behind on the FIX, not the paperwork. Until 2026-08-22 it was true of all 45 including the publishable ones: a clone showed each peer's own report contradicting its row here. §1 was never wrong; nothing gated those files.)* **§1 remains authoritative for the cohort; a peer's `status/` report is that peer's own last measurement.** Refresh one with `tools/run-cohort-census.sh --to-status <peer>` — it is a **measurement**, never a copy of the census JSON.

*The previous header block — the accreted `cc1970f`-era cohort paragraph — is archived verbatim at `docs/archive/CONFORMANCE-MATRIX-header-pre-de8f807.md`. Do not cite figures from it.*

> ## ✅ CURRENT (2026-08-21 · extended 2026-08-22) — re-pinned to the 755-check oracle + spec `v0.8.2`; **M1 and M2 both fixed, re-pin LANDED**
>
> **Read this before pulling any peer. It supersedes the 2026-08-17 banner below.** Both anchors were re-pinned on 2026-08-21: the spec snapshot to **`v0.8.2`** (SHA-256-pinned per file in its `MANIFEST.md`) and the oracle to the **755-check set `95edd774…`** (`entity-core-go` HEAD at the time; see [The pin](#the-pin--content-anchored-and-why-there-is-no-commit-here)). Tier **M1 was re-run, came back 0 of 5, was fixed, and is now 5/5 at `755 · 0F — 312P/337W/0F/106S`** — identical across all five. `tools/tier-status.py --gate` exits 0. **The full 45-peer census then ran**, so every row in §1 is a fresh measurement at that pin.
>
> **Extension, 2026-08-28 — the propagation is complete: 39 of 45 peers are publishable, up from 13.** Tier M3 is 12/13 (only `cobol`), the probes are 13/18, and the six that remain are named in the headline above — none of them is the CAP feature. Two peers turned out to be carrying more than the CAP trio, and both were found the same way: **fixing a wrong denial made the FAIL count go UP, and the new FAILs were the truth.** `sql` went 2F → 7F → 0F (a §5.5a handlers over-scoping had been standing in for a missing chain-attenuation rung AND a missing §6.2 mint-bound); `datalog` the same shape via an `entity://` URI-parsing defect. `nim` was the only peer that already HAD a §5.6 ceiling, and having a wrong one was worse than having none. All three lessons are ratcheted in `AGENTS.md`.
>
> **Extension, 2026-08-22 — tier M2 is now 8/8 and 13 of 45 peers are publishable.** `typescript` (84F → 0F) and `csharp` (INVALID → 0F) turned out to be the **same** §6.3 defect in its two presentations (§1b/§1c), not two problems; `rust` `python` `java` `kotlin` `elixir` `common-lisp` then took the same CAP fix and all landed 0F. **The fix shape did not change once across thirteen languages** — ~200 lines over 5–6 files, the same five places — and that invariance is the evidence the spec reading is right, not just that the tests pass. Two lessons appeared only past the M1 sample and are ratcheted in `AGENTS.md`: **CAP-6a's fail-open has two mechanisms** (null-collapse, and an arithmetic fail-open involving no null at all — one grep does not catch both), and **§6.3 is not optional even when a peer is already at 0F** (`rust`, `common-lisp` were 0F while still scoring CAP-6a WARN).
>
> **What moved in the gate, attributed BY CATEGORY** (never by commit message): 18 declared checks added between the two pins (`8537d875… → 95edd774…`); each resolved to its declaring file, that file's category *constant* read, and the constant tested against `coreProfileCategories`. **5 gate `--profile core`, all `catCapability`** — CAP-5 `request_mint_temporal_ceiling`, CAP-6 `request_ttl_zero_and_overflow`, CAP-6a `ingest_rejects_unrepresentable_expiry`, CAP-2/3 `configure_empty_grants_withdrawal`, CAP-7 `configure_rejects_base58_partial_prefix`. The other 13 are extension-only. `core_gate_fingerprint` stayed byte-identical (`8261a033…`) for the **fourth** consecutive time in this shape.
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
> (Note: the reference oracle's own citation for this rule, `"V7 §6.6"`, is stale under the de-versioned v0.8.0 spec — the rule is actually at §6.2. Filed to arch as `v7-section-citation-drift.md`; every keystone peer fix below uses the corrected `§6.2` citation, not the stale one.)
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
> `protocol-generator/shared/findings/fceb61f-cohort-remeasurement.md`, itself
> successor to `protocol-generator/shared/findings/af8a582-cohort-remeasurement.md`).

> **⛔ Superseded — "Reading the conformance numbers" (the `cc1970f` carry-forward note).** This note asserted that every peer's gate verdict was certified at `cc1970f` and that the `665` totals carried forward unchanged. **Both halves are withdrawn.** The carry-forward argument rested on the core-gate fingerprint alone, which tracks *which categories run* and not *what they assert* — disproven at the `af8a582` cutover, where four hard-FAIL vectors landed inside existing core categories under a byte-identical fingerprint. The cohort has since been re-measured at `af8a582` → `fceb61f` → `de8f807`. **Current numbers are the §1 table and footnote ²; the header's "Reading a row" replaces this note.** Kept as a marker so a reader who remembers this paragraph learns it was retired, not moved.

> **Wire-conformance corpus — F29/F30 re-vendor (2026-07-12).** The ECF codec corpus (the *lower-bar* `wire-conformance` axis, distinct from the `validate-peer --profile core` gate above) advanced **69 → 71 vectors**: arch added F29's `nested.5`/`nested.6` (array-of-maps ≥24/≥256-byte inner-text head boundary) and regenerated F30's `tag_reject.1/2/3/5` (now canonical-except-the-mt6-tag, genuinely gating the §6.3 tag scanner). Vendored from `entity-core-protocol` @ `be54baf` as `9695b1f1…` (supersedes `41d68d2d…`), artifact decode-verified per the F16 lesson (71 vectors, all canonical bytes matched `.diag`, nested pins exact). **Cohort codec re-run: 71/71 (0 FAIL) across all 27 codec peers** (cobol: 70 pass / 1 documented C-ABI carve-out skip on `content_hash.4`; go independently tallied 66 encode_equal + 5 decode_reject). **F29 + F30 CLOSED** (`SPEC-FINDINGS-LOG.md`). This **closes the alien-substrate discovery sweep** (Tcl/Rexx/Fortran/Forth/Smalltalk/APL): F29/F30 were the last corpus asks it produced; the spec-discovery well is dry on the current wire surface — steady state is re-running this cohort against each amendment, not adding language #N. *(**F31 CLOSED** the same day: 4 peers (elixir/csharp/cobol/typescript) had a peer-layer unit test fail while codec-green + S4-conformant. Bisected to two **stale-test** causes, both test-side — no handler/peer code was wrong: (A) the §7a dispatch-outbound reentry tests sent the `value` field as a bare scalar instead of the `{value:X}` echo-shape entity-data map the §7a.1 contract requires (per the Go oracle + the passing kotlin test); (B) cobol's dispatch skeleton test expected 404 for an **unauthenticated** unknown-handler EXECUTE, but §6.5 authenticates before resolving → correct status is 401. All four now green; details in `SPEC-FINDINGS-LOG.md` F31.)*

---

## 1. Primary status table

> **How to read this section.** The **table** is the live state, and as of the 2026-08-21 full
> census it spans **one pin**: every row is a fresh measurement on the **755**-check set `95edd774…`, with
> the M2 rows re-measured after their 2026-08-22 fixes. Nothing is carried forward from the retired
> 740-check pin.
> *(This note previously described a two-pin split — 5 fresh M1 rows against 40 stale 740-check
> ones. That was accurate for the few hours between the M1 fix and the full census, and was left
> standing after the census closed it. Corrected 2026-08-22.)* The
> **dated `>` note blocks** that follow are a
> *build log* — each records what a peer's arrival established at the pin current on that date,
> and the figures in them (`682·0F @ cc1970f`, `665 @ e8524ed`, …) are **historical, not claims
> about this tree**. Where a note and the table disagree, the table wins. §1a covers the one case
> where a table row needs more than a number.
>
> **The commit hashes in those note blocks do not resolve, and several never will.** They are
> `entity-core-go` `dev` SHAs, kept as *our* provenance trail; `e8524ed` in particular died in a
> 2026-07-10 mirror history rewrite and exists nowhere. Do not try to resolve one, and do not
> cite one — **every live claim in this file is anchored by a content digest instead**
> ([The pin](#the-pin--content-anchored-and-why-there-is-no-commit-here)). The note blocks are
> left as written rather than back-edited, because a build log that gets rewritten stops being
> evidence of anything.

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
> analysis in `protocol-generator/shared/findings/concurrency-latency-floor-and-cap-sig-coverage.md`
> and `protocol-generator/shared/findings/wasm-dialer-parity-F35-and-execution-mode.md`. (Honesty: seam-hybrid,
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
> `protocol-generator/shared/evaluations/wasm-codegen-comparison.md`; folded into SUBSTRATE-TAKEAWAYS §4. Two transport
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
> `protocol-generator/shared/evaluations/wasm-codegen-comparison.md` (third column); SUBSTRATE-TAKEAWAYS §4. (Honesty:
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
> Synthesis: `protocol-generator/shared/evaluations/authority-as-query.md`; arch routing:
> `protocol-generator/shared/findings/authority-as-query.md`; per-peer:
> `protocol-generator/{sql,datalog}/status/`.

| Peer | Maint.⁴ | Spec | Oracle pin⁶ | `--profile core`² | Codec | Crypto floor (Ed25519 + SHA-256) | Ed448 / SHA-384 agility | Publish |
|------|:----:|:----:|---------------|:----------------:|-------|----------------------------------|-------------------------|---------|
| **OCaml** | **M1** | v0.8.0 | `7aa6f3de…` | 778 · **0F** — 335P/336W/0F/107S ⁵ | native hand-rolled | native — mirage-crypto-ec + digestif | **FFI-hybrid** (opt-in `entitycore_agility`) | opam, `0.1.0-pre` |
| **Swift** | **M1** | v0.8.0 | `7aa6f3de…` | 778 · **0F** — 335P/336W/0F/107S ⁵ | native hand-rolled | native — swift-crypto | deferred (→ FFI when scoped) | SPM, `0.1.0-pre` |
| **Haskell** | **M1** | v0.8.0 | `7aa6f3de…` | 778 · **0F** — 335P/336W/0F/107S ⁵ | native hand-rolled | native — crypton | **native** — crypton (Ed448) | Cabal, `0.1.0-pre` |
| **Go** (clean-room) | **M1** | v0.8.0 | `7aa6f3de…` | 778 · **0F** — 335P/336W/0F/107S ⁵ | native hand-rolled | native — stdlib `crypto/ed25519` | deferred (→ FFI when scoped) | Go module, `0.1.0-pre` |
| **Lean** | **M1** | v0.8.0 | `7aa6f3de…` | 778 · **0F** — 335P/336W/0F/107S ⁵ | **pure-Lean proven core** + FFI crypto | **FFI** — C-ABI `ec_ed25519_*` | FFI (deferred) | Lake, `0.1.0-pre` |
| **C#** | M2 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 336P/335W/0F/107S ✅ *(was an INVALID MEASUREMENT at 698/755 with 9 starved categories; fixed 2026-08-22 — §1c. Run time 18m20s → **7.2s**.)* | native (Cbor Ctap2 + handroll) | native — NSec | managed — BouncyCastle | NuGet, `0.1.0-pre` |
| **TypeScript** | M2 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 84F = 3 real + 81 cascade; fixed 2026-08-22 — §1b. The one WARN off the 336P row is `concurrency/t1_1_concurrent_demux`, the timing-ratio check — see footnote ¹¹.)* | native (cborg + handroll) | native — @noble | managed — @noble | npm, `0.1.0-pre` |
| **Java** | M2 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — JDK SunEC | JDK / BouncyCastle | Maven, `0.1.0-pre` |
| **Kotlin** | M2 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — JDK SunEC | deferred (→ JDK SunEC / BouncyCastle) | Gradle→Maven Central, `0.1.0-pre` |
| **Elixir** | M2 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — OTP `:crypto` | **native** — OTP `:crypto` | Hex, `0.1.0-pre` |
| **Common Lisp** | M2 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ *(was 3F; CAP fix 2026-08-22. One WARN off the cohort: `concurrency/t1_1_concurrent_demux` reports no parallel speedup under load — the check names itself informational, **not** a §6.11 violation.)* | native hand-rolled | native — ironclad (pure-Lisp) | **native** — ironclad (pure-Lisp) | ASDF/Quicklisp, `0.1.0` |
| **Rust** (clean-room) | M2 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — ed25519-dalek + sha2 | deferred (→ FFI when scoped) | crates.io, `0.1.0-pre` |
| **Python** (clean-room) | M2 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-22)* | native hand-rolled | native — `cryptography` (OpenSSL) | **native** — `cryptography` (Ed448) | PyPI, `0.1.0` |
| **Zig** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 336P/335W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28. 314P/336W until 2026-09-02: `r3_connection_flood` WARN→PASS on a §4.10(c) admission bound — see §3, and note the peer carries a measured intermittent abort)* | native (std-only) | native — `std.crypto` | deferred | source, `0.1.0-pre` |
| **C** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | native hand-rolled | native — libsodium | deferred (libsodium has no Ed448) | `make dist` + pkg-config |
| **C++** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | native hand-rolled | native — libsodium | deferred (libsodium has no Ed448) | CMake pkg + vcpkg + conan, `0.1.0-pre` |
| **Ada** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 336P/335W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | native hand-rolled | native — libsodium (C binding) | deferred (libsodium has no Ed448) | Alire (optional), `0.1.0-pre` |
| **Ruby** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | native hand-rolled | native — stdlib `openssl` | **native** — stdlib `openssl` | RubyGems, `0.1.0.pre` |
| **Crystal** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | native hand-rolled | native — libsodium (direct `lib`/`fun` C binding) | deferred (libsodium has no Ed448; → FFI) | source, `0.1.0-pre` |
| **Odin** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | native hand-rolled | **native — pure-Odin `core:crypto`** (Ed25519 + SHA-2, FFI-free) | deferred (`core:crypto` has no Ed448; → FFI-hybrid) | source (`make dist`), `0.1.0-pre` |
| **Prolog** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | **FFI** (C-ABI) | **FFI** — C-ABI (library(crypto) has no Ed25519) | FFI | SWI pack, `0.1.0` |
| **PHP** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | native hand-rolled | native — ext-sodium (libsodium) | deferred (ext-sodium has no Ed448; → FFI) | Composer, `0.1.0-pre` |
| **Dart** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28. The extra WARN against the modal row is `concurrency/t1_1_concurrent_demux`, the timing-ratio check — see footnote ¹¹.)* | native hand-rolled | native — cryptography_plus (pure-Dart) | deferred (→ FFI when scoped) | pub.dev, `0.1.0-pre` |
| **COBOL** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 30F: 24 were a cascade behind one unchecked `MOVE` of wire data into a fixed field, which glibc's fortify check turned into a process kill. §3. Carried one extra skip until 2026-09-04 — `t1_3`, a 264 KB frame against a 64 KiB cap — and now sits on the cohort's modal row; the capacity became affordable only after `cbor-canon` stopped buffering map values, 2.13 MB → 65.8 KB per call per level.)* ⁸ | **FFI-hybrid** (COBOL value-codec + C-ABI) | **FFI** — `libentitycore_codec` (libsodium) | deferred (libsodium has no Ed448) | `make dist`, `0.1.0-pre` |
| **Tcl** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | **FFI-hybrid** (pure-Tcl canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` (C-shim, libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | git + `pkgIndex.tcl`, `0.1.0-pre` |
| **Rexx** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | **FFI-hybrid** (pure-Rexx **decimal-model** canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via the `ecnet` co-process daemon (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Fortran** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | **FFI-hybrid** (pure-Fortran **signed-carrier uint64** canonical CBOR value codec + C-ABI) | **FFI** — `libentitycore_codec` bound direct via `iso_c_binding`, no C wrapper (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Forth** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ *(was 4F; CAP trio + CAP-2 withdrawal form)* | **FFI-hybrid** (pure-Forth **native-float-bits** canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via in-process `libcc` `c-function` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git + tarball), `0.1.0-pre` |
| **Smalltalk** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ *(was 4F; CAP trio + CAP-2 withdrawal form. 2026-09-14: CAP-6a WARN→PASS — its 3 transport-drop variants now answer §6.3's status, F79.)* | **FFI-hybrid** (pure-Smalltalk canonical CBOR + C-ABI) | **FFI** — `libentitycore_codec` via in-process UFFI `ffiCall:module:` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | git + Metacello/Tonel, `0.1.0-pre` |
| **APL** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ ¹⁰ *(carried as "not measured — upstream-blocked" until 2026-08-30, on a toolchain claim that was false; 8 real FAILs then closed in one session — §1d)* | **FFI-hybrid** (pure-APL **array value-model** canonical CBOR codec + C-ABI) | **FFI** — `libentitycore_codec` via a GNU APL `⎕FX` native fn (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist` (git source), `0.1.0-pre` |
| **asm-x86_64** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ ⁹ *(the disclosed `t1_3_no_head_of_line` skip is CLOSED — a 64 KiB ECF scratch in the peer's own native codec, not the payload; see §1. Was an INVALID MEASUREMENT — §1a; that cause was a §4.9(c) silent drop, not connection pressure.)* | **native (L2)** hand-written x86-64 asm — envelope/data-map CBOR **+ canonical ECF codec** (shortest-float ladder, key-sort, `ec_content_hash`, peer-id format/parse); only crypto is FFI | **FFI** — Ed25519 + SHA-256 via `libentitycore_codec` (libsodium); the canonical codec is native asm (L2 boundary) | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make host`), `0.1.0-pre` |
| **asm-arm64** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ ⁹ *(was an INVALID MEASUREMENT — §1a; the cause was a §4.9(c) silent drop, not connection pressure.)* | **native (L1)** aarch64 GAS transliteration of the x86-64 peer — envelope/data-map CBOR + dispatch interior in hand-written asm; canonical codec + crypto via `libentitycore_codec` (cross-built for aarch64); run under `qemu-aarch64-static` | **FFI** — Ed25519 + SHA-256 via `libentitycore_codec` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make host`), `0.1.0-pre`|
| **riscv64** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ ⁹ *(was an INVALID MEASUREMENT — §1a; the cause was a §4.9(c) silent drop, not connection pressure.)* | **native (L1)** RV64GC GAS port off the arm64 template via the shared generic syscall table; canonical codec + crypto via `libentitycore_codec` (cross-built for riscv64); run under `qemu-riscv64-static` | **FFI** — Ed25519 + SHA-256 via `libentitycore_codec` (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make host`), `0.1.0-pre`|
| **wasm-wat** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ ⁷ | **seam-hybrid** (hand-authored WAT peer + wire codec; Rust codec compiled to `wasm32-wasip1`, wasm-merged as the seam) | **seam** — `entitycore_codec.wasm` (Rust→wasm, Ed25519 + SHA-256) | deferred (→ codec seam `ec_ed448_*`) | source (`make peer`), `0.1.0-pre` |
| **rust-wasm** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(census read 3F against a `peer.wasm` seven days older than the `../rust` source it compiles; already fixed by inheritance — §3. 2026-09-14: CAP-6a WARN→PASS — the §6.3 answer does NOT come by inheritance, because this seam reimplements the read loop, F79.)* | **native (inherited)** — the `../rust` peer's hand-rolled ECF codec cross-compiled UNMODIFIED to `wasm32-wasip1`; only a 336-line `poll_oneoff` transport seam is wasm-specific | **native** — ed25519-dalek + sha2 (compile to wasm cleanly, no seam) | deferred (→ codec seam `ec_ed448_*`) | source (`make peer`), `0.1.0-pre` |
| **rust-wasm-wasmtime** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(as `rust-wasm` — stale artifact, already fixed by inheritance — §3. 2026-09-14: CAP-6a WARN→PASS, F79.)* | **native (inherited)** — the SAME `rust-wasm` `wasm32-wasip1` module, run under **wasmtime AOT** (`wasmtime compile` → `.cwasm`); only the socket seam differs (host-preopened `-S tcplisten` + standard wasip1 `sock_accept`/`poll_oneoff`, the `wasi` crate) | **native** — ed25519-dalek + sha2 (compile to wasm cleanly, no seam) | deferred (→ codec seam `ec_ed448_*`) | source (`make aot`), `0.1.0-pre` |
| **Julia** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | **native** hand-rolled (**multiple-dispatch** canonical CBOR) | **native** — system libsodium via `ccall` + `SHA` stdlib (Ed25519 + SHA-256; native-audited-lib tier, NOT the C-ABI) | deferred (→ opt-in FFI, C-ABI `ec_ed448_*`; libsodium has no Ed448) | Pkg (Project.toml + git), `0.1.0-pre` |
| **Nim** | M3 | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 336P/335W/0F/107S ✅ *(was 4F. Its §5.6 ceiling already existed and was wrong three ways — §3. `handshake_nonce_single_use` WARN→PASS 2026-09-07: routing the connect handler in ANY connection state, per §4.7 row 10, made a dead RT-6 arm live — a replayed authenticate now answers the pinned 401 invalid_nonce instead of reaching the generic 401 missing_author.)* | **native** hand-rolled (**compile-time macro/template** canonical CBOR) | **native** — libsodium via `{.importc.}` C interop (Ed25519 + SHA-256) | deferred (libsodium has no Ed448) | nimble (git-indexed), `0.1.0-pre` |
| **Oz / Mozart** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 328P/343W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | **FFI-hybrid** (pure-Oz canonical CBOR value codec + C-ABI; bignum ints, IEEE floats as exact bit-patterns) | **FFI** — `libentitycore_codec` via the `entity-codec-daemon` `Open.pipe` co-process (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist`, `0.1.0-pre` |
| **Io** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 334P/337W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28. Went **28F on 2026-09-03** when the `-reference-peer` fold first ran the §6.11 origination check, and back to 0F the same day once the cause was found — see §1e. The FAIL was real and the fix is structural, not a re-run: **pre-fix 3 of 6** full-suite runs failed, **post-fix 0 of 12**.)* | **FFI-hybrid** (pure-Io canonical CBOR + C-ABI; `EcBig` uint64 carrier for the double number model) | **FFI** — `libentitycore_codec` via the in-process `EntityCodec` C addon (libsodium) | deferred (→ FFI, C-ABI `ec_ed448_*`) | `make dist`, `0.1.0-pre` |
| **SQL** (authority-as-query) | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 2F. NOT a plain CAP fix: the §5.5a handlers over-scoping that caused it was also masking a missing chain-attenuation rung and a missing §6.2 mint-bound — §3.)* | **seam-hybrid** — §5.2 ladder / §5.5 chain-walk (recursive CTE) / §3.6 K-of-N (`HAVING count DISTINCT`) / §6.6 (`ORDER BY length DESC`) **authored as real SQL** (`src/sql/`); thin C host owns sockets/CBOR/crypto/store over the C-ABI | **FFI** — `libentitycore_codec` (libsodium); crypto callable *from* SQL via `sqlite3_create_function` | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`make dist`), `0.1.0-pre` |
| **Datalog** (authority-as-query) | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 336P/335W/0F/107S ✅ *(was 3F. Like `sql`, the fix exposed a missing §5.5a frame isolation the earlier wrong denial had been answering — §3. 2026-09-14: CAP-6a WARN→PASS — its read loop dropped a refused frame instead of answering it, F79.)* | **seam-hybrid** — §5.5 delegation as recursive **Ascent rules** to least fixpoint (SecPAL/Binder shape), §5.2 verdict as a derived `allow` fact, K-of-N counting aggregate, §6.6 stratified negation; pure-Rust host asserts `verified_signer` facts over the C-ABI | **FFI** — `libentitycore_codec` (libsodium); Ascent never touches a byte | deferred (→ FFI, C-ABI `ec_ed448_*`) | source (`cargo build --release`), `0.1.0-pre` |
| **Node-RED**‡ | exploratory | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(census read 3F against a stale `dist/`; already fixed by inheritance from `typescript` — §3. 2026-09-14: CAP-6a WARN→PASS — the flow collapsed a strict-decode refusal into its drop node, F79.)* | **interop** (delegates the TS peer's canonical CBOR + §6.5 engine) | **interop** — TS peer `@noble` (Ed25519 + SHA-256) | deferred (→ TS `@noble` seam) | not a peer (illustrative) |
| **TurboWarp**‡ | exploratory | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-29 — the ordinary fix shape, the 37th language it has not varied in. `capability/ingest_rejects_unrepresentable_expiry` WARN → **PASS** on 2026-09-16: the 0.8.2.25 §4.11 work made this peer answer a CODED frame where it had dropped the connection, and CAP-6a scores a transport-drop refusal as WARN precisely because a drop is a refusal but not the §5.2 disposition. **This is the only real check the whole 46-peer 0.8.2.25 sweep moved at this pin** — 3 of 35 788 severities moved across all 46 reports and the other two were the footnote-¹⁰ timing ratio.)* | **ALL FIVE handler bodies (§4 connect / echo / §6.3 tree / §6.2 handlers / §6.2 capability) + §6.5 dispatch + §5.2 verify AUTHORED in Scratch** — a dispatch spine routing to one `define dispatch-<handler>` custom block each; only socket/CBOR/crypto/store via the `ecutils` seam | **seam** — bundled `@noble` (Ed25519 + SHA-256) | deferred (→ bundled `@noble`) | not a peer (illustrative; real-VM confirmation pending) |
| **Pure Data**‡ | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 332P/339W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | **§6.5 dispatch spine + §5.2 verify ladder + §4.6 auth ladder + §6.6 walk AUTHORED on the canvas** (pattern-first spine, one named unit per handler); bytes/CBOR/crypto/store/**TCP transport** in the `[ecodec]` C external (stock `[netreceive]` broadcasts replies — A-PD-002) | **FFI** — `libentitycore_codec` (libsodium) via `[ecodec]` | deferred (→ FFI, C-ABI `ec_ed448_*`) | not packaged (visual-paradigm probe on the real Pd runtime) |
| **Unison** | probe | v0.8.0 | `7aa6f3de…` | **778 · 0F** — 335P/336W/0F/107S ✅ *(was 3F; CAP fix 2026-08-28)* | **native** hand-rolled canonical ECF on **UCM runtime builtins — ZERO third-party dependencies** (CBOR/base58/LEB128 hand-rolled; `Float.toRepresentation` gives raw IEEE bits for the shortest-float ladder) | **native** — builtin `crypto.Ed25519.sign/verify.impl` + `crypto.hashBytes Sha2_256`; **key derivation HAND-WRITTEN in pure Unison** (GF(2²⁵⁵−19) base-2¹⁶ limb arithmetic + twisted-Edwards scalar mult — UCM ships sign/verify but NO keygen, A-UN-009) | deferred — **no C-FFI hatch** (managed runtime; Ed448/SHA-384 are not builtins, so the `libentitycore_codec` path other peers used is *structurally* unavailable) | Unison Share deferred, `0.1.0-pre` |

‡ **Node-RED (#31) + TurboWarp (#32) are exploratory visual-paradigm probes — NOT real, deployable peers, and distinct from the alien-substrate *language* probes (Tcl/Rexx/Forth/…) which are full gate-green peers.** **Pure Data (#33) is the third visual probe (reactive-patch, the paradigm's lone open representative) and the exception on measurement: it runs on the REAL Pd runtime over REAL TCP and clears the full core gate (682·0F Result: PASS @ `cc1970f`, genuine 2-of-3 multisig accept + origination 3/3) — a real conformant peer by the gate's standard, kept in the probe class because its purpose is paradigm-visualization (cohort-consistent lineage, shared C-ABI codec, ADR-0012).** They exist to answer "can the protocol be *authored in* a visual paradigm?" and to serve as **readable references for those communities** (a Node-RED or Scratch author can study the dispatch logic in their own idiom), **not** as something you would deploy. Node-RED delegates the entire §6.5 engine to the TS peer (a flow-graph wrapper); TurboWarp authors the dispatch + all handler bodies as Scratch blocks but delegates crypto to a bundled `@noble` seam, runs sandboxed (no raw TCP → oracle-reachable only via a WS↔TCP bridge, the browser-Rust/WASM pattern), and is measured by a faithful **block-interpreter** of the real `project.json` pending a real-TurboWarp-VM run. Neither is independent convergence (shared TS/`@noble` lineage, ADR-0012). Full synthesis of what the substrate sweep taught — **what translates, what needs a seam, what doesn't** — is in `research/SUBSTRATE-TAKEAWAYS.md`.

> **Update 2026-07-15 — Pure Data (#33) close-out: the first visual-paradigm probe to clear the FULL core gate.** `validate-peer --profile core` @ `cc1970f`: **682 · 287P/299W/0F/96S — Result: PASS**, every remaining skip a §9.0 extension carve-out (0 fail-counting), measured **natively on the real Pd runtime over real TCP** (no interpreter harness, no bridge). Genuine **2-of-3 multisig accept-path** (§3.6/§5.5 M3/M4/M6 K-of-N verification in the chain walk, persistent `EC_NAME` identity) + **origination-core `dispatch_outbound_reentry` 3/3** over real two-peer TCP (`run-origination-core.sh`). Authored on the canvas: the §6.5 **pattern-first dispatch spine** (one named unit per handler, per-handler op-switch), the §5.2 verify ladder, the §4.6 auth ladder, and the §6.6 longest-prefix walk; `[ecodec]` (a Pd C external on the C-ABI codec) owns bytes/CBOR/crypto/store **and the TCP transport** — stock `[netreceive]` broadcasts every reply to all sockets with no per-connection id (A-PD-002, proven at Pd source level), so transport is a legitimate seam on this substrate. The §6.11 reentry on a single-threaded canvas is a **bounded synchronous send+wait on the one inbound fd** (non-response frames hand back to the connection's assembler). Cohort-consistent (shared C-ABI codec + generation lineage), not independent convergence (ADR-0012). Per-peer detail: `protocol-generator/pd/status/`; survey verdict updated in `protocol-generator/shared/evaluations/visual-paradigms.md`.

> **Update 2026-07-13 — both peers reworked to author the protocol IN the paradigm, not wrap it (supersedes the "both delegate the §6.5 engine / both 249·2F" description below).** Node-RED's §6.5 is now the visible **16-node flow-graph** (still 249·2F — leaf crypto delegated + the throughput boundary). **TurboWarp was rebuilt, then completed:** the §6.5 dispatch, the full §5.2 verify sequence, and **ALL FIVE handler bodies** (§4 connect / echo / §6.3 tree / §6.2 handlers / §6.2 capability) are now authored as **Scratch blocks** (502 blocks) — reorganized from one 400-block tower into a short **dispatch spine + one `define dispatch-<handler>` custom-block procedure per handler** for legibility — with only the socket / canonical-CBOR / Ed25519-SHA / chain-verdict / token-mint / seed-cap / store mechanics behind the `ecutils` **seam** (deliberately no `dispatch` block). The **§6.6 handler resolution is authored as the actual tree WALK** (a `repeat until` that walks the dispatch path longest-prefix-first for the matching `system/handler` registration == `HandlerRegistry#resolve`) — not a hardcoded pattern list; the per-prefix store lookup + path slice are the only seam bits, and the final pattern→body match is just body-selection (Scratch can't call a procedure by dynamic name; resolved-but-un-authored handlers delegate). Measured **291 P / 294 W / 0 F / 97 S — Result: PASS @ `cc1970f`**, **solid 5/5 full-marathon runs** including both §6.11 robustness tests (`t2_1_sustained_load` + `t2_2_connection_churn`), via the headless **block-interpreter harness** (`turbowarp/src/harness/run-blocks.mjs`, which runs the *real* `project.json` block graph against the oracle). **The earlier flakiness was a harness-scheduling bug, now fixed** (not the old `A-TW-throughput` label, and not the connect authoring): the interpreter drained the inbound queue in one serial burst without yielding, so under §6.11 connection *churn* (t2_2) responses didn't flush before the oracle tore connections down → dropped requests → a downstream cascade. Yielding to the event loop between hats (`await setImmediate` — the cooperative per-tick model real Scratch already uses) resolved it; verified by reverting connect to delegated (which *also* failed t2_2 → proved the serial drain, not the authoring, was the root). A real-TurboWarp-VM run is the remaining confirmation. Still cohort-consistent (shared bundled `@noble` + generation lineage), not independent convergence (ADR-0012). Consolidated survey + when-to-stop verdict: `protocol-generator/shared/evaluations/visual-paradigms.md`. See `docs/status/HANDOFF-2026-07-13-turbowarp-closeout.md`.

The historical description below (both 249·2F, both delegating the §6.5 engine) is retained for the Node-RED throughput finding. Both delegate codec/crypto to the TS peer (Node-RED require()'d, TurboWarp esbuild-bundled), so a green result would be cohort-consistent, not independent (ADR-0012). `validate-peer --profile core` @ `cc1970f` for BOTH: **249 P / 293 W / 2 F / 101 S** — all correctness categories green (connectivity 22/22, type_system 108P, multisig 11 w/ genuine 2-of-3 accept-path, security 28, capability 12, §6.11 concurrency *correctness* t1_2/t1_3). The **2 identical FAILs are §6.11 sustained-load/churn robustness** (`t2_1`/`t2_2`) — a documented **throughput boundary** (`A-NR-throughput` / `A-TW-throughput`): they **pass standalone** and fail only under the full ~640-test marathon. That the LEAN TurboWarp harness hits the SAME boundary as Node-RED shows it is **engine-level** (the shared delegated §6.5 engine's full-suite sustained-load behavior on pure-JS crypto), not a per-runtime artifact — not a correctness defect, not memory-bound. Per "no green → no publish," unpublished. Value is visualization + generator-robustness, not a conformance claim. See `protocol-generator/{node-red,turbowarp}/`. The peer is authored as a Node-RED *flow-graph* (§6.6 dispatch ↔ wire routing); codec/crypto/§6.5-engine are delegated (interop) to the TypeScript peer, so a green result would be cohort-consistent, not independent (ADR-0012). `validate-peer --profile core` @ `cc1970f`: **249 P / 293 W / 2 F / 101 S** — **all correctness categories green** (connectivity 22/22, type_system 108P, multisig 11 w/ genuine 2-of-3 accept-path, security 28, capability 12, §6.11 concurrency *correctness* t1_2/t1_3). The **2 FAILs are §6.11 sustained-load/churn robustness** (`t2_1`/`t2_2`) — a documented **Node-RED-substrate throughput boundary** (`A-NR-throughput`): they **pass standalone** and fail only under the full ~640-test marathon (event-loop saturation + visual-runtime per-request overhead on pure-JS crypto), not a correctness defect, not memory-bound. Per "no green → no publish," unpublished. Value is visualization + generator-robustness, not a conformance claim. See `protocol-generator/node-red/`.
² **Every `--profile core` cell is a fresh measurement at the 778-check pin `7aa6f3de…` (2026-09-08)** — `total · NF — P/W/F/S`, from the centralized `tools/run-cohort-census.sh` over all 46 peers. Nothing in this column is carried forward from an earlier pin: `778 ≠ 758 ≠ 756 ≠ 755 ≠ 740`, so a figure from any retired pin is not comparable to one here even when the F-count matches. **As of 2026-08-30 every measured peer executed the full 755 and no row is quarantined** — the peers that did not are in §1a, which is now a retraction rather than a live quarantine. *(Four peers were quarantined at the 2026-08-21 census: `csharp`, fixed 2026-08-22 — §1c; and the ISA trio, fixed 2026-08-30 — §1a.)*

⁴ **`Maint.` is the MAINTENANCE tier — how often this peer is re-measured, nothing else.** `M1` lockstep · `M2` priority catch-up · `M3` on-demand · `probe` paradigm probe · `exploratory` not a deployable peer. Defined per-peer in **`tools/peer-tiers.tsv`** (the roster) and explained in **§4**; current per-tier state is `tools/tier-status.py`. **These are NOT `research/LANDSCAPE.md`'s tiers 1–5**, which classify the *language landscape* ("what is worth building") rather than re-measurement cadence — the two were previously both written as bare `1`/`2`/`3` and were routinely confused, which is why these carry the `M` prefix. **A maintenance tier never affects whether a peer may be published**; it affects only how promptly it is re-measured after an oracle re-pin.

³ **`⚠ INVALID MEASUREMENT`** — *no row carries this marker as of 2026-08-30; the definition is kept because §1a's historical record uses it and because the next starved run will need it.* This peer did not execute the same checks as the rest of the table, so **its P/W/F/S cannot be compared to any other row** and is not a verdict. The cause is always the same: the oracle's **global** `-timeout` expired mid-suite, after which whole categories are never run and are recorded at severity `SKIP` — the same severity as a deliberate `--profile core` extension carve-out — so `summary` reads as a near-clean run. Treat the numbers as a floor and read **§1a**.

**Every peer in this table is required to execute the identical check set** (`778` checks, digest `7aa6f3de…`, pinned as `core_executed_check_set_digest` in `tools/oracle-pin.env`). This is **enforced, not assumed**: `tools/check-set-gate.py` validates every report in a census against that pin and hard-fails on any deviation or any `budget_exhausted` category, and `tools/run-cohort-census.sh` runs it automatically and exits non-zero when a census is not comparable. **This census: 46 of 46 conforming**, and `tools/check-set-gate.py --tracked` reads the same over the committed reports. *(It read 41 of 45 until 2026-08-30; the 4 that deviated are in §1a, and the gate is what found them. The 46th, `apl`, was not a deviation — it was excluded from the census entirely, which no gate could see. §1d.)*

**Crypto-availability tiers** (the per-ecosystem story an adopter most needs): `native` = ships with runtime/stdlib or an in-language audited lib, no FFI; `managed` = a managed-code crypto package on the language's package manager; `FFI-hybrid` = native floor, Ed448 via `libentitycore_codec`; `FFI` = whole crypto surface via C-ABI; `deferred` = Ed25519+SHA-256 floor only, Ed448 not yet wired.


⁷ **`wasm-wat` is `755 · 0F` as of 2026-08-29 — and on the way there its FAIL count went UP twice, both times because a measurement got more honest.** Kept because the sequence is the evidence, not the endpoint. Until 2026-08-29 this was the only peer in the cohort whose `run-s4.sh` never provisioned `~/.entity/peers/conformance/keypair`, so four checks could not build their fixtures and SKIPped — reading as substrate limits rather than a missing setup file. Provisioning it (the peer hardcodes that same seed already) resolved three and converted the fourth into a real FAIL: it refused a valid 2-of-3 multisig capability it had co-signed, because `$verify_cap` hard-refused a map-valued `granter`. Tracing the remaining `capability` refusals then showed they were never the §5.6 ceiling — the peer had **no §5.5 delegation chain at all**, so a delegated cap was refused two gates before the mint was reached. **`304P/339W/2F/110S` → `306P/339W/3F/107S` → `312P/337W/0F/106S`**: four fewer skips, then the chain walk (`ef7affe`) and §3.6 K-of-N quorum roots (`905ce0f`). Never read the 2F→3F step as a regression — nothing about the peer changed at it. This peer then became the reference port for the same missing chain in all three ISA peers.

⁶ **`Oracle pin` is a content digest, not a commit.** `7aa6f3de…` is `core_executed_check_set_digest` — the sha256 over the sorted `<category>/<name>` list a `--profile core -reference-peer <addr>` run **actually executed**, 778 checks. Two rows may share this column only if both reports carry that exact digest; `tools/check-set-gate.py` enforces it, and a peer that deviates is an *invalid measurement*, not a low score (§1a). A commit hash is deliberately absent: published commits are authored fresh at the release boundary, so a `dev` SHA resolves for nobody outside this tree — see [The pin](#the-pin--content-anchored-and-why-there-is-no-commit-here) for the full anchor set, the reproduction recipe, and the one limit that a digest does not fix. The retired pins, where they appear below, are the 758-check set `c34abcae…`, the 756-check set `d30c3dd0…`, the 755-check set `95edd774…` and the 740-check set `8537d875…`. **This footnote itself carried `d30c3dd0…`/756 as the current pin until 2026-09-09, three flips after it stopped being current** — `tools/coherence-gate.py` is scoped to §1's rows and the 46 per-peer banners, so prose outside those two surfaces can go stale with every gate green. That is the same blind spot §4's dated table hit, and it is the reason the pin now appears in exactly one authoritative place (`tools/oracle-pin.env`) with everything else naming it rather than restating it.

⁸ **`cobol`'s 30F was 24 cascade + 5 real + 1, and the cascade came from a memory-safety defect.** `tree-handler`'s put path copied the wire entity into a fixed 8192-byte field with no size test; a 16 KiB `tree.put` — the oracle's own `t1_4` staging payload — overflowed it and glibc's `_FORTIFY_SOURCE` **terminated the peer**, so every check after that point reported connection-refused. Two more copies of the same shape were reachable from the wire (`store-put`/`store-bind` into a 4096-byte slot, `cap-resolve` into an 8192-byte one). All three are now bounded *before* the copy and answer a status. With the peer alive, five real defects surfaced: no §5.6 mint ceiling, a `created_at` that was a compile-time constant, a CAP-6a fail-open, and the F40 id-scope pair — which failed in **both** directions at once (an operations include of `/{local}/get` authorized the bare `get`, an exclude of `/*/get` denied it) because an id-scope dimension was being canonicalized. **Skips WERE 108 against the cohort's 106** — disclosed rather than worked around at the time: two concurrency probes stage 256 KiB and 16 KiB payloads that this peer's then-65535-byte frame cap and 8192-byte per-entity ceiling could not accept. **That is closed: 108 → 107 on 2026-09-02 (the 16 KiB one) and 107 → the cohort's 105 on 2026-09-04 (the 264 KB one), and the peer is on the modal row — see §1.** Its harness now passes `--validate` by default as every other peer's does; without it four concurrency checks SKIPped rather than ran. *(That default is worth one more line, because it was only half true for a year: `run-s4.sh` defaults `VALIDATE=1`, and the capped launcher beside it — `run-s4-host.sh`, the entry point this peer's own header documents for a human — forwarded `VALIDATE=${VALIDATE:-0}` as an EXPLICIT `-e`, which always beats the callee's default. So the documented by-hand invocation measured `312P/337W/0F/109S` and printed `Result: FAIL` while the census, which never sets the variable, measured the committed row. Nothing was wrong with the peer or the census; the two entry points disagreed, and only the one nobody automated was wrong. Fixed 2026-09-04.)*

⁹ **The type-registry over-publication is CLOSED (2026-08-30) — and the fix made the pass count FALL by 282, which is the whole point.** This footnote used to read *"the ISA trio's `594-595P/53-55W` is NOT better conformance than the cohort's `312P/337W`"*, and it was right: `src/typestore.s` published ~200 type entries including whole standard-extension vocabularies (`compute/*`, `system/registry/*`, `clock/*`, `continuation/*`, `relay/*`, `query/*`, …), the oracle scores those *matched-if-present*, and publishing them converted 282 `type_system` WARNs into PASSes. The store is now filtered to the 53-name core floor and the rows read `313P/336W` (`asm-x86_64`) and `312P/337W` (`asm-arm64`, `riscv64`), all three still `755 · 0F`.

**The number to hold onto is that a *correct* fix here LOWERS a published pass count**, which is the exact shape a reviewer reverts by reflex. Verified per-check on each peer, before against after: **exactly 282 checks changed, every one of them `type_system`, every one PASS→WARN, and nothing outside that category moved.** The enforcement grep `AGENTS.md` names — `grep -rl 'system/type/compute/apply' protocol-generator/*/src/` — now returns nothing.

Two things were found in the doing, both worth more than the fix. **The scope filter belongs in the generator, not the harvest.** These peers have no data model to reflect a registry over, so `typestore.s` is harvested byte-exact from the *reference* peer — which is a FULL peer and serves the extension vocabularies. The harvest is left intact (it is evidence of what the reference peer serves) and `gen-typestore.py` now carries `CORE_FLOOR` as a **keep-list, not a drop-list**: a drop-list fails open, publishing any vocabulary a future harvest adds, while a missing floor type fails closed as a hard `type_system` FAIL on the next run. **And `riscv64`'s `reference/typestore/` had never been committed** — 0 files tracked, not gitignored, simply absent — so its generator could not run from a clean clone and `src/typestore.s` was an artifact with no in-tree input. That is the `forth` `bin/peer.fs` shape one level up, and it is why all three now regenerate byte-identically from their own committed harvest.

One disclosed gap remains for these rows: all three are **corroboration, not independent convergence** — one hand-written design ported twice.

~~Second, `asm-arm64` and `riscv64` WARN on `r3_connection_flood` where `asm-x86_64` PASSes~~ — **ported 2026-08-30; all three now PASS and all three read `313P/336W`.** The sentence is kept because the correction attached to it is the durable part. It used to stop at that clause, which reads as an ISA-pair parity gap and is **backwards**: measured across all 46 committed reports, `r3_connection_flood` was **44 WARN with only `asm-x86_64` and `pd` passing** (now **42 WARN / 4 PASS**). The two ISA peers were exactly where the rest of the cohort is; `asm-x86_64` was the outlier *ahead* of it. Every other peer carries the same WARN with the same message — *"admitted all 256 connections without refusal and kept serving — no self-imposed bound, so admission is delegated externally."* Disclosing it as something those two rows owed, while 42 rows owing the identical thing said nothing, was a misattribution in the pessimistic direction, and this file's rule against unfair-looking-*good* cuts both ways. **The real state is unchanged by the port: a cohort-wide unimplemented SHOULD, now with four peers ahead of it, tracked in §3.** Porting it was ISA parity, not catch-up.

What went across were `asm-x86_64`'s four `host.s`/`dispatch.s` hardenings: the child closes the **inherited listen fd**, a **30 s socket idle deadline** on a served connection (a socket-level deadline on a connection one child owns exclusively — deliberately NOT the §6.11(c) per-request deadline, which §6.11 forbids implementing as a connection-wide primitive), the **§4.10(c) admission bound** at 64 with refusal by close, and the **§4.10(a) oversize path** answering `413` immediately instead of draining the declared body first. **The admission counter must be reaped twice** — once before the blocking `accept4` and again after it returns — or every child that exits while the parent is parked still counts as live and the bound presents as a dead peer. **On RISC-V the bound is a value comparison, not a compare-then-branch-on-flag**, since the ISA has no condition-flags register; that is the same restatement §5.6 rule 3's overflow test needed. Exactly one check moved on each peer (`r3_connection_flood` WARN→PASS), verified per-check before against after.

¹¹ **`concurrency/t1_1_concurrent_demux` is a TIMING RATIO, and it oscillates — read a row carrying it as a measurement of this host, not of the peer.** The check compares an N=16 concurrent batch against a sequential baseline and WARNs when it sees no parallel speedup; the oracle's own text calls that *"not a §6.11 violation — informational … for runtimes that do not physically parallelize"*, and **it is a WARN, never a FAIL, so it does not affect any `0F` verdict in this table.** `dart` and `typescript` carry it as of the 2026-09-16 refresh, and both moved PASS → WARN in that refresh while **nothing else about either peer changed** — verified per-check: across all 46 tracked reports, 3 of 35 788 severities moved, and these are two of the three. Its instability is long-recorded rather than newly noticed: it has been the *only* severity to move across four separate whole-cohort control re-measurements (3 of 34 868 on 2026-09-08, 2 of 34 868 on 2026-09-04, 1 of 758 twice), in **both** directions, and on those occasions the sample was deliberately not banked because it was a single observation against a stable tracked row. It is banked here because this refresh re-measured every peer as the closing act of the 0.8.2.25 sweep, and **a published row must equal the report it was published from** — editing the prose back to the prettier number is the one thing this table may not do. Also recorded as a genuine trade on `cobol` (footnote ⁸): raising its canonicaliser buffers took `t1_4` SKIP → PASS and this check PASS → WARN, 4 of 4 runs against 3 of 3 before.

¹⁰ **`apl` was never unmeasurable — see §1d.** Its image had built successfully on 2026-08-28; nobody ran the peer against it. One harness invocation on 2026-08-30 produced a valid 755-check measurement in 109 s, and the 8 FAILs it exposed were closed the same session. Seven of the eight were cohort defect classes this peer had sat out because the label kept it out of every propagation pass.

⁵ **Tier M1 — fixed this session, and the reference for everyone else.** These five went `3F/2F/83F` → **`0F`** at the then-current 755-check pin. Three defect classes, all in the banner above and ratcheted in `AGENTS.md`: §5.6's MIN_DEFINED mint ceiling (absent in every peer, not merely wrong), CAP-6a's absent-vs-unrepresentable fail-open, and §6.3's missing `400 non_canonical_ecf` rejection status. `swift` needed a fourth — §5.5a frame over-scoping — which was the actual cause of its capability failures rather than a symptom. `lean`'s 83F was **2 real + 81 cascade** from one §6.3 defect; fixing it returned it to 0F, which is what confirmed the diagnosis. **These five diffs — plus M2's eight, landed 2026-08-22 — are the reference fix for the remaining 32** (§3): author it once from the spec, propagate, do not rediscover it 32 times. *(This footnote read "the reference fix for the other 40" before the M2 pass.)*

---

## 1a. INVALID MEASUREMENTS — closed 2026-08-30, and the diagnosis was wrong

> ## ✅ CLOSED (2026-08-30) — **all three ISA peers are `755 · 0F`, and "the connection-pressure family" never existed**
>
> `asm-x86_64` **`755 · 0F — 595P/54W/0F/106S` in 1.4 s**, against `549P/53W/1F/111S` in 599 947 ms.
> `asm-arm64` and `riscv64` **`755 · 0F — 594P/55W/0F/106S`**, severity-identical to each other on
> all 755 checks. `tools/check-set-gate.py` reports 45/45 conforming and exits 0.
>
> **The cause was a §4.9(c) silent drop, not resource pressure.** The op-routing ladder compares an
> operation's LENGTH before its bytes. `ping` collides with `echo` at length 4; the byte compare
> failed and the branch returned **without writing any frame** — not `501`, not `400`, nothing.
> `hello` (5) and `authenticate` (12) had the same hole. Every connection-churn cycle ends with a
> `ping`, so **every cycle cost the caller its full 20 s read deadline**;
> `t2_2_connection_churn` reached cycle 29 of 100, consumed the entire 10-minute budget, and starved
> nine categories including three core ones. `concurrency` went from 599 s to **1.1 s, 6/6**.
>
> **Everything §1a says below about accumulation, stuck children and a "connection-pressure family"
> is retracted as a diagnosis.** The measurements were real and are left in place: the 2026-08-17
> stuck-children dump was accurate, the 2026-08-29 re-measurement that showed a *completely healthy
> peer at the moment of failure* was accurate, and the three defects fixed on 2026-08-29 were real
> defects. None of them was the cause. **A §4.9(c) drop is billed entirely to the CALLER's timeout,
> so it presents as the peer being slow or under-resourced rather than wrong** — which is why five
> separate investigations of the peer's health found nothing and why the label survived for months.
> The diagnostic that closed it asks the opposite question: set a flag in the frame WRITER, clear it
> at the top of dispatch, and print which operation *returned without having written*.
>
> `r1_payload_over_limit` and `r3_connection_flood` — filed here as the same "family" — were never
> separate: both ran and passed the moment the budget was no longer being eaten.
>
> **The trio also gained the full §5.5 delegation chain, §5.6 attenuation, §5.5a framing, §3.6 K-of-N
> and the §6.2 mint ceiling** in the same pass, ported from `wasm-wat`. The CAP-5/CAP-6 failures they
> carried were never the mint: both checks present a *delegated* capability and were refused two
> gates earlier by a fail-closed root-trust placeholder.
>
> **What is NOT closed: §1a.4 below.** The trio still over-publishes extension type vocabularies,
> which is the entire reason they read `594-595P/53-55W` against the cohort-standard `312P/337W`.
> A 0-FAIL row does not retire that finding.

*Everything from here to the end of §1a is the historical record of the wrong diagnosis, kept
verbatim because the measurements in it are sound and only the conclusion was not. Do not cite it as
current state.*

**Status at the 755-check pin, 2026-08-21 to 2026-08-30: `asm-x86_64` · `asm-arm64` · `riscv64` (714/755).
All three had `budget_exhausted` categories. None of the three was listed with a P/W/F/S anywhere in
§1, because a run measured on a different set of checks is not a worse score — it is not a score.**

`tools/check-set-gate.py` reported **42/45 conforming** and exited non-zero on exactly these three;
`tools/run-cohort-census.sh` did the same. That was the gate working as designed — **a non-zero
exit from the cohort gate was the expected, documented state, not a regression** — and it was
attributable in full to this section.

**`csharp` was the fourth until 2026-08-22 — it is now FIXED and fully comparable.** It was a clean
`740 · 0F` at the retired 740-check pin, then came back at 698 of 755 checks with 9 starved categories at this pin.
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

**5. Update 2026-08-29 — the three defects above are FIXED in `asm-x86_64`, and the family did
not move. That is itself the finding.** The child now closes the inherited listen fd, carries a
30 s socket-level idle deadline, and the peer bounds admission at 64 connections and refuses the
rest by close (§4.10(c) names close as an allowed refusal). A fourth defect not listed above was
found by re-reading §4.10(a) rather than the check: the oversize path **drained the entire
declared body** — up to the 4 GiB a 32-bit length header can name — before answering, which is
precisely the "fully buffering" that section forbids; it now answers `413` and closes, and the
oracle's verdict moved from *"connection terminated without a 413 frame"* to *"413
payload_too_large frame returned (spec-preferred: coded frame + close)"*. `r3` moved from
*"admitted all 256 without refusal"* to *"admitted 63/256 and refused the rest (self-bounded)"*.
**No check flipped**, `t2_2_connection_churn` still consumes the whole 10-minute budget, and the
peer remains an INVALID MEASUREMENT.
**What that rules out is worth more than what it fixed.** Sampled every 3 s through a full churn
run, the peer is *completely healthy at the moment of failure*: parent flat in `accept4`, parent
fds flat at 4, 2–4 live children, zombies reaped promptly, nothing accumulating anywhere. The
stuck-children mechanism this section identified in August is **gone**, and the check fails
anyway. So the remaining cause is **not accumulation**, and the 2026-08-17 characterisation —
correct about what it measured — was not the whole cause. The surviving symptom is narrow and
identical in all three checks: a `tree.get` on a *fresh* connection whose **write** times out,
while the peer is demonstrably accepting.

**Root cause is characterised, not fully traced** — the specific path on which a child blocks
instead of completing or closing has not been isolated to an instruction. Flagged at the same
standard as A-OZ-008 / A-IO-025 (report what is measured, do not over-invest ahead of a fix
session). The fix shape is known from the cohort: a per-connection read deadline plus the
**§4.10(c) connection-admission cap** that `r3_connection_flood` says outright is missing — the
same pairing Rexx landed as A-RX-014.

**4.** ~~**Separately: the asm trio's higher raw PASS count is an artifact, not better conformance.**~~ ✅ **CLOSED 2026-08-30 — see footnote ⁹ for the fix and the current numbers.** The finding below was correct and is kept verbatim; only its numbers are of their pin (`545P/42W` vs `307P/327W`, later `594-595P/53-55W` vs `312P/337W`). `typestore.s` is now filtered to the 53-name core floor, the enforcement grep returns nothing, and the three rows read `312-313P/336-337W` at `755 · 0F`. **The fix LOWERED the pass count by 282 — that is the correct direction.**
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
at the retired 740-check pin because CAP-6a did not exist as a check then — the drop-form defect was always
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

## 1d. `apl` was never unmeasurable — the exclusion outlived its reason by three days

> ## ✅ CLOSED (2026-08-30) — **`755 · 0F — 311P/338W/0F/106S`, digest `95edd774…`, 109 s, zero starved categories**
>
> Measured twice by two destinations of the same tool — the peer's own harness and
> `run-cohort-census.sh` — agreeing byte-for-byte on all five summary figures.
> `tools/check-set-gate.py --tracked` now reads **46 / 46 at the pinned set**.

**The claim that stood for three days was: *"UNMEASURABLE — upstream-blocked (1.9→2.0 cool-down); excluded from census by standing policy."* Three things in that sentence were false, and each was checkable in under a minute.**

1. **"GNU deleted `apl-1.9.tar.gz`."** It did not. GNU reorganized the flat `gnu/apl/` directory into per-version subdirectories when 2.0 shipped. `https://ftp.gnu.org/gnu/apl/apl-1.9/apl-1.9.tar.gz` answers **HTTP 200**, and the directory beside it also holds the `.sig` and the Debian source. The 2026-08-27 investigation checked six mirrors and `ftp.gnu.org`, found the *flat* path 404 on every one, and concluded deletion — but every mirror carries the same reorganization, so six agreeing sources were six copies of one observation. **A path change and a deletion are indistinguishable from a single URL, and mirrors do not make that sample independent.**
2. **"The image is unbuildable."** It was force-bumped to APL 2.0 on 2026-08-27 and **built successfully on 2026-08-28** — the image was in local storage the whole time, and `apl --version` runs. Whatever justified the label stopped being true the day after it was written.
3. **"Excluded from census by standing policy."** `tools/run-cohort-census.sh` hard-coded `apl) echo "SKIP: ... blocked" ; rc=125`. So the one peer nobody could measure was also the one peer the census would not attempt — the exclusion made itself permanent by removing the only thing that could have falsified it.

**The 8 FAILs, and what they say about the cost.** Seven of eight were defect classes already closed elsewhere in the cohort; `apl` missed them because the label kept it out of every propagation pass:

| FAIL | Class | Closed for the rest of the cohort |
|---|---|---|
| `core_register_reserved_refused` + `_publishes_nothing` | §6.2 reserved-pattern register guard | 2026-08-17 — **44 of 45 peers, `apl` the sole omission** |
| `request_mint_temporal_ceiling` (CAP-5) | §5.6 MIN_DEFINED ceiling | 36 languages, 2026-08-21 → 08-28 |
| `request_ttl_zero_and_overflow` (CAP-6) | same | same |
| `ingest_rejects_unrepresentable_expiry` (CAP-6a) | null-collapse fail-open | same |
| `f40_id_scope_exclude_literal` + `_include_no_overgrant` | id-scope over-canonicalization | `cobol`, 2026-08-30 |
| `handshake_nonce_single_use` | RT-6 `wrong-status` (`409` for `401`) | genuinely new to this peer |

**Two of the fixes are worth their own note.**

**The F40 pair reproduced `cobol`'s two-defects-holding-each-other-up shape exactly.** `CapMatchesScope` canonicalized both the value and the patterns for `handlers`, `operations` and `peers` — all three ID-scope, all three literal per §5.2/F40 — so an operations include of `/{local}/get` authorized the bare `get` while an exclude of `/*/get` denied it: overgranting and over-denying in one run. Removing the canonicalization alone takes every CAP check to `403`, because the handlers dimension was separately being compared as the **absolute resolved path** (`/{peer}/system/capability`) against grants that name handlers relatively. Neither defect is visible while the other stands.

**CAP-6a needed the §6.3 answer to score at all, and `apl` already had the 400 branch — unreachable.** The peer reached 0-FAIL with CAP-6a still WARN: *"3 capability_denied, 3 transport-drop."* `OnFrame` had a correct `400 non_canonical_ecf` response ready, but the `WirePeek` that recovers the `request_id` used the **strict** decoder, so a tagged frame returned `ok=0` two lines earlier and the frame was dropped on the floor. The fix is the cohort-standard salvage decode — strict decoder byte-unchanged, salvage used only to recover the id — and it moved CAP-6a to PASS on all six variants and cut the run from 149 s to 89 s, because the dropped frames had been billing the caller a full timeout each. **A refusal that exists but cannot be reached is a §4.9(c) silent drop**, and this is the third time in three days that shape has been the finding.

**The generalizable rule, and it is about the exclusion rather than the peer: an exclusion is a claim with an expiry date, and it must be wired to the thing that justifies it or deleted.** This one asserted a fact about an upstream server, was never re-checked, survived the repair of its own cause, and was enforced by the tool that would have disproved it. It also silently converted the published headline from a measurement into an assumption — `45 of 45 measurable` reads as complete and was one unrun command away from `46 of 46`. **Enforcement:** `tools/run-cohort-census.sh` no longer carries any per-peer exclusion, and `roster_peers()` no longer filters the roster — every peer in `tools/peer-tiers.tsv` is measured, so a peer can only leave the census by leaving the roster, where `tier-status.py` reports it.

---

## 1e. `c` was published 0-FAIL while carrying a remotely-triggerable use-after-free

> ## ✅ CLOSED (2026-09-02) — **`756 · 0F — 314P/336W/0F/106S`, digest `d30c3dd0…`**
>
> Rate measured on full `--profile core` runs, not asserted: **baseline 1 of 10 aborted ·
> after the fix 0 of 20.** Against a ~10% base rate, 20 clean runs is roughly 88%
> confidence — real, and not the same thing as proof.

**This row exists because the honest statement is uncomfortable: for as long as this peer has been published at 0-FAIL, roughly one run in ten could abort the process with heap corruption, and every green run was a true green.** A conformance suite that passes 756 checks says nothing about a race it never opens.

**What it was.** `reader_loop` dispatches each inbound EXECUTE on a **detached** thread whose job borrows `conn` and `io`, both of which live inside the connection's `serve_state`. The reader returns the moment the client closes, and `serve_reaper` joined **only the reader** before freeing that state — so a dispatch still in flight read and wrote freed memory. Because `ec_io_free()` also `close()`s the descriptor, a late write could land on an fd **already recycled by a later `accept()`**, which is a cross-connection write rather than a lost response. Symptom: `free(): chunks in smallbin corrupted`, `t2_2_connection_churn` failing mid-cycle, then 26 downstream checks reporting connection-refused — **1 real FAIL and 26 cascade**, the standing first-FAIL-in-run-order diagnostic.

**How it surfaced, which is the reusable part.** It did not surface from reading the code, and four things had to be true at once for it to be seen at all. `run-s4.sh` writes the peer's stderr to a path **inside a `--rm` container**, so the evidence was destroyed on every run — the same defect that hid `zig`'s abort through four investigations. The 2026-09-02 sweep put a post-run `cat` of that file into all 46 harnesses; **the very first full-cohort census after it landed printed the corruption message.** Before that, the peer's failures were indistinguishable from "the peer is slow" or "external load."

**Two measurement lessons, both about being wrong before being right.**

1. **`-category concurrency` alone reproduces NOTHING — 0 of 20 on the unfixed binary.** Heap corruption is layout-sensitive; the crash needs the full suite, ~680 checks deep, with the store populated. The standing advice to *drive a starved category directly* is right for **coverage** and wrong for a **race**: an isolated category is a different heap. Had the category run been treated as the measurement, this would have been closed as unreproducible.
2. **`ec_session_close` carried the identical defect** on the client side — join the reader, free `io` + `conn`, never wait for a §6.13(b) reentry dispatch. Not the path the corruption was measured on, and fixed in the same change rather than left for the next census.

**The rule, now ratified rather than a candidate** (second occurrence, different language, different allocator, after `zig`): **a detached worker must not outlive the state it borrows**, and the ordering is the entire fix — reserve **before** the spawn (the worker can finish before `pthread_create` returns), release **last** in the worker (the owner may free everything the instant the count reaches zero), and **drain before the owner frees**.

---

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

**Standing maintenance loop (the steady state):** when a spec amendment lands and Go ships the corresponding `validate-peer` update, re-vendor the oracle, re-run **M1** immediately and converge to 0-FAIL, then catch up M2/M3 as capacity allows. *(This paragraph said "Tier-1/Tier-2/Tier-3" until 2026-08-21 — the exact bare-numeral spelling §4 warns is routinely confused with `research/LANDSCAPE.md`'s selection tiers. Corrected to the `M` prefix.)* **As of 2026-08-30 the loop has run to completion for this re-pin and the cohort is closed: the oracle is re-vendored, M1 converged 5/5 (2026-08-21), M2 8/8 (2026-08-22), M3 + the probes closed the propagation on 2026-08-28, `turbowarp` took exploratory to 2/2 on 2026-08-29, and the last five — `cobol`, the ISA trio and `apl` — landed 2026-08-30. All 46 peers are at 0-FAIL, with no exclusions.** What is left below is **not conformance debt**: it is one cohort-wide unimplemented SHOULD, one withdrawn exculpation that needs measuring, and standing demand-driven work. *(This sentence also named "one open scope violation behind a green row (type-registry over-publication)" until 2026-08-30, when the ISA trio's `typestore.s` was filtered to the core floor — closed, and the pass count fell by 282 in the process.)* *(This read "40 of 45 … five independent defects in five peers" until 2026-08-30, then "45 of 45 … one unmeasured peer" for part of that day — see §1d. Before that, "mid-cycle and stalled at step two … M1 has not converged", which was true on 2026-08-21.)* This is the engine of spec refinement now — not new languages: the discovery well has been dry on the current wire surface since ~15 peers, per [`synthesis-reconciliation.md`](protocol-generator/shared/syntheses/synthesis-reconciliation.md). *(This sentence and the one in §4 cited "§5" of this file until 2026-08-30. There is no §5 — the section was folded out at some point and two published cross-references outlived it, resolving to nothing for any reader. Found by hand-walking the tree, which is the only thing that asks this question. **A gate now covers part of what the walk was catching**: `tools/coherence-gate.py`, in `make lint`, checks all 46 §1 rows and all 46 per-peer prose banners against the committed reports, so a published number cannot silently disagree with the report it is published from. It does **not** catch the `§5` defect that motivated half of it — there is no way to tell "§5 of this file" from "§5 of the spec", and this file cites the spec at §5–§7b 24 times, correctly. The walk stays mandatory.)*

| Item | Scope | Priority | Notes |
|------|-------|----------|-------|
| ~~**Oracle normalization**~~ ✅ DONE | whole cohort | — | **CLOSED.** All 17 peers re-run on one oracle `entity-core-go @e8524ed` (go HEAD) → uniform **665·0F**. Procedure + the when/why rule now live in `research/diagnostics/oracle-vendoring-policy.md`. (The 649-vs-653 phantom-build lesson is captured there as provenance hygiene: build once into repo-root, never per-peer.) |
| ~~**run-s4 oracle-path defaults**~~ ✅ DONE | C, Ada, Ruby, Prolog (+ Rust, Python) | — | **CLOSED.** All `run-s4.sh` + `run-origination-core.sh` defaults normalized to the repo-root `/work/output/s4-oracles/…` convention; they now run with no `ORACLE` override. (Lean keeps `/repo/output/…` by its distinct `-v "$PWD":/repo` mount convention — correct as-is.) |
| ~~**Re-normalize cohort onto public-HEAD oracle**~~ ✅ DONE | whole cohort | — | **CLOSED (2026-07-10).** The public `entity-core-go` mirror rewrote history — the pinned `e8524ed` no longer resolves. Re-pinned `tools/oracle-pin.env` (+ `protocol-generator/cpp/tools/oracle-pin.env`) to the reproducible public HEAD `cc1970f`, and **hardened the core-gate anchor**: `oracle-bootstrap.sh` now fingerprints the *normalized category set + 53-type floor* (`core_gate_fingerprint = 8261a03…`), comment/format-invariant, instead of the raw `profile.go` sha256 — so the V8 comment reword that flipped `e09a865`→`74e04e3` no longer false-alarms "core gate moved" (regression-tested: comment reword → fingerprint unchanged; category drop → fingerprint moves). The `cc1970f` core gate is thereby **provably** the gate the cohort converged against, so every peer's `--profile core` 0-FAIL carries. Cohort table + reading note re-normalized to `cc1970f`. *Optional remaining (non-gating):* a fresh full-suite re-run of the 21 non-COBOL peers on `cc1970f` to re-measure their extension-inflated `665` totals natively (COBOL already runs natively at `cc1970f`); deferred, as core is the gate and it carries. |
| ~~**Scorecard label fix** `62044c5 → b30a589`~~ ✅ DONE | provenance | — | **CLOSED (2026-07-12).** A-C-008 / A-ADA-013: `62044c5` was off-by-one; `b30a589` is the true v7.75 baseline where `resource_bounds` activates under `--profile core` (clean `62044c5` auto-skips it → 574·0F·90S, not the recorded 576·0F·89S). Corrected in-repo across the 9 v7.75-re-run peer reports that paired `576·0F·89S` with `62044c5` (common-lisp, csharp, elixir, haskell, java, ocaml, swift, typescript, zig); C/Ada already carried `b30a589`. Remaining `62044c5` mentions tree-wide are accurate history (the clean-subset evidence runs) and left intact. |
| ~~**CLI normalization** (`--name`)~~ ✅ DONE | C, Ada, Ruby, Go, Prolog | — | **CLOSED (2026-07-12).** The audit found the deviation was wider than "C/Ada lack `--name`": **neither Go nor Ruby actually had `--name`** (only `--seed`; the matrix had overclaimed it), and **Prolog's `--name` was a fake** (parsed then ignored, seed hardcoded). Standardized all five on the canonical convention (OCaml/Swift/Haskell/COBOL): default seed `0x11×32`; `--name NAME` loads the seed from `~/.entity/peers/NAME/keypair`. Go/Ada default seed normalized `0x01`→`0x11`. Each `run-s4.sh` provisions the conformance keypair + boots `--name conformance`. |
| ~~**Verify genuine multisig** on later-folded peers~~ ✅ DONE | C, Ada, Ruby, Prolog, Go, COBOL | — | **CLOSED (2026-07-12) — with a real finding.** Making the accept-path RUN exposed **4 of 5 as FRAME-ONLY** (Ruby/Go/C/Ada rejected a valid co-signed 2-of-3 — a masked conformance defect the reject-dominated `multisig` category hid). All four fixed with genuine §3.6 M3/M4/M6 (`multisig_root_ok`, modeled on the genuine Prolog peer) → accept-path PASS @ `cc1970f`; Ruby/Go carry in-repo unit tests, C/Ada guard via the now-genuine S4 accept-path. Prolog + COBOL were already genuine. The Ada fix additionally uncovered **A-ADA-014** (a latent §PR-8 fixed-length-String crash). Finding note in `research/stewardship/`. |
| ~~**Capability mint temporal ceiling** (§5.6 / §6.2)~~ ✅ **DONE (2026-08-28)** — all 36 fixable peers | 0 remain (`cobol` carries it inside its 30F; the asm trio's runs are INVALID) | — | **The fix exists, is verified, and just needs propagating.** §5.6's MIN_DEFINED construction was ABSENT in every peer (`mintToken` set no `expires_at` at all); implemented in `go`/`haskell`/`lean`/`ocaml`/`swift` and all five went to 0F. **The rules, from `spec-data/v0.8.2/ENTITY-CORE-PROTOCOL.md` §5.6:** `expires_at = MIN` over the **DEFINED** terms of `{parent.expires_at, caller_capability.expires_at, created_at + policy_entry.ttl_ms, created_at + request.ttl_ms}` — the first two ABSOLUTE, the last two DURATIONS converted against a **once-sampled** `created_at`; `ttl_ms == 0` is **defined** and yields `created_at` (do NOT special-case it — letting it fall out of the arithmetic is what stops it collapsing into the "no bound" spelling); an overflowing term is **dropped**, never wrapped or saturated; and an over-long request from a bounded caller **mints `200` with the clamped value — rejecting it is non-conformant.** Reference diffs: commits `e979e6c` (go), `58d190c` (ocaml), `8f790f6` (haskell), `cf2717c` (lean), `ded3e07` (swift). |
| ~~**CAP-6a ingest fail-OPEN** (§6.2 / §5.2)~~ ✅ **DONE (2026-08-28)** | 0 remain. Measured present in **every** peer that had not been fixed | — | A received capability whose `expires_at`/`not_before`/`created_at` is not `uint64`-representable is malformed and MUST be refused via the §5.2 `capability_denied` disposition. `go`/`haskell`/`ocaml` **honored it and returned 200**. Mechanism, identical in five type systems: the idiomatic accessor (`Uint`/`uint_field`/`uintField`/`uintAt`) answers "nothing" for BOTH an absent field and a present non-uint one, so the expiry check is silently skipped. **The representability check must run BEFORE the range check it protects.** |
| ~~**§6.3 rejection status missing**~~ ✅ **DONE (2026-08-28)** — the cascade source | 0 remain. `fortran` never had it (its `wire_peek` already answered a rejected frame with 400 — the salvage idea arrived there independently and earlier) | — | §6.3: *"Rejection returns `400 non_canonical_ecf`"*. **Not optional even when a peer is already at 0F:** `rust` and `common-lisp` both reached 0F while still scoring CAP-6a **WARN**, because the `>2^64` half of that check can only arrive as a major-type-6 tag and is therefore rejected at decode — it needs the §6.3 answer to be *scored* as a refusal at all. Every M1 peer rejected an undecodable frame and then said nothing — `continue`, a logged skip, `break`/close, or a `none` that ended the read loop. §4.9(c) deliver-or-signal says the same. On a peer that closes, ONE bad frame kills the connection and every later check fails on it. **`lean` 83F → 0F and `typescript`'s 81 cascade are both this.** Fix shape: keep the strict decoder byte-unchanged, add a salvage decode used ONLY to recover `request_id`, answer 400, keep serving — the frame stays rejected, so the `tag_reject` wire-conformance vectors keep their meaning. |
| ~~**§5.5a frame over-scoping**~~ ✅ **RATIFIED + SWEPT (2026-08-28)** | `swift`, `sql` (over-applied); `datalog` (under-applied — frames missing entirely from chain attenuation). Enforcement grep run across the whole remaining cohort: clean | — | §5.5a's per-link granter frames scope the **RESOURCE dimension only**. swift passed them to all four dimensions of `grantSubset` and defaulted `peers` to them — identical to correct whenever child and parent share a granter, and fatal the moment a **delegated** cap arrives. **Enforcement grep:** in each peer, only the resources comparison may receive the granter frames. |
| ~~**`csharp` INVALID MEASUREMENT**~~ ✅ **DONE (2026-08-22)** | `csharp` | — | **CLOSED.** Was 698 of 755 checks with 9 `budget_exhausted` categories. **Never a distinct defect: it was `typescript`'s §6.3 missing-rejection-status in the hang-form** (drop + hold the connection open, rather than close), so every downstream check waited out a timeout — CAP-6a alone burned 120 s of the 10-minute budget — and the tail never ran. Identical 3 real FAILs at identical indices (558/559/560) and identical cascade onset (563) to `typescript`; that one comparison is what turned it from "new at this pin, not root-caused" into "it is `typescript`". **§1c** has the full differential. The §6.3 fix restored a valid 755-check run *and* 0F together: `755 · 0F — 313P/336W/0F/106S`, 18 m 20 s → 7.2 s. `-timeout` was never raised. |
| ~~**`wasm-wat` — §5.5 delegation chains are ABSENT, and the 2F was hiding it**~~ ✅ **DONE (2026-08-29)** | 1 peer | — | **CLOSED at `755 · 0F — 312P/337W/0F/106S`.** The chain walk landed at `ef7affe` and §3.6 K-of-N quorum roots at `905ce0f`; the peer then became the reference port for the identical gap in all three ISA peers. Two lessons ratcheted in `AGENTS.md`: §5.5a has a **third** surface (the dispatch boundary, where the cap's patterns frame against their granter and the request target against the local peer), and **fixing one surface converts the next surface's vacuous pass into a true FAIL** — `captok_form_dispatch_minted_pl_presented_xpeer` was passing only because the peer refused every foreign-granted cap outright. Also: a **K-of-N root has no granter frame**, and the local peer is the correct one rather than a fallback (§3.6 M6 already requires it to have signed). The scoping history below is kept as the record of an estimate that was wrong. **The estimate below was wrong and is corrected in place because it was an estimate, not a measurement.** It read: *"the mint is a literal `(call $w_map (i64.const 4))` with fixed memory offsets, so adding `expires_at` is an arity + data-segment edit rather than a code edit … neither is hard."* Measured 2026-08-29 by tracing the actual refusal: **`wasm-wat` implements no capability chain at all.** `$verify_cap` requires `granter == this peer` (root-trust, depth-1 only) and `$serve_delegate` answers `501` to any request carrying a `parent`. All three outstanding `capability` results present a **delegated** cap — instrumented at the refusing gate, the presented `granter` is the caller's identity hash rather than this peer's, and `parent` is present on **4 of 4** refused tokens. So CAP-5 and CAP-6 never reach the mint at all; they are refused two gates earlier, and the §5.6 ceiling they are named for is not what fails. This is the `sql`/`datalog` shape at a larger scale — **a blanket wrong denial standing in for an entire unimplemented feature** — and it stayed invisible because the peer scored a respectable 2F. Real scope: §5.5 chain collection + per-link signature/grantee/temporal/attenuation validation, §3.6 K-of-N quorum roots, the §5.6 ceiling, and CAP-6a representability — in hand-authored WAT. Its own session. |
| **`wasm-wat` was never provisioned the conformance keypair** ✅ **DONE (2026-08-29)** — and it hid a sixth defect | 1 peer | — | Every other peer's `run-s4.sh` writes `~/.entity/peers/conformance/keypair` so the validator can co-sign **as** the peer; `wasm-wat`'s never did, and four checks SKIPped for want of a fixture rather than for any substrate reason. Provisioning it (the peer already hardcodes that same seed in `src/host.wat`) resolved three of the four and turned the fourth into a FAIL: **`multisig/valid_2of3_peer_signed_accepted` — the peer refuses a valid 2-of-3 it co-signed**, because `$verify_cap` hard-refuses a map-valued `granter` with the comment `;; multisig — deferred`. The two `below_threshold_*` probes now PASS **for the wrong reason** (it rejects every multi-granter cap). **This is the 2026-07-12 frame-only multisig finding recurring in the one peer that could not be measured for it** — the reject-dominated category hid it then, a missing setup file hid it now. `wasm-wat` 2F → 3F; the FAIL is a disclosure, not a regression. |
| ~~**`turbowarp` CAP-2/3**~~ ✅ **DONE (2026-08-29)** | 1 peer | — | **CLOSED at `755 · 0F — 311P/338W/0F/106S`.** The ordinary CAP fix shape, unvaried — the 37th language it has not varied in. Still the block-interpreter probe (§1 ‡), still not a deployable peer, and it never gated anything. |
| ~~**Stale build artifacts read as peer FAILs**~~ ✅ **DONE (2026-08-28)** | `rust-wasm`, `rust-wasm-wasmtime`, `node-red` | — | All three were reported at 3F and **all three were already correct**. They are thin seams over `../rust` (a path dep) and the `typescript` engine, both fixed 2026-08-22 — but `out/peer.wasm` was dated 2026-08-17, seven days older than the source it compiles, and `run-cohort-census.sh` hardcodes `NOBUILD=1` for the wasm peers while `node-red`'s harness rebuilds `dist/` only when `index.js` is MISSING, never when it is merely stale. Forced rebuild → 0F on all three, first try. **This is the standing stale-artifact rule firing on a plain sibling-crate fix rather than on a worktree merge**: `stat -c %Y` the artifact against `git log -1 --format=%cI` the source it derives from. Compounding it, `tier-status.py` was applying `output/scratch/reverify/` unconditionally, so three 2026-08-17 reports at the retired 740-check pin outranked the fresh census indefinitely — the identical defect `check-set-gate.py` was fixed for on 2026-08-22 and its sibling never checked. Overlay now applies only when newer. |
| ~~**§5.5 DELEGATION CHAINS ARE ABSENT in all four hand-authored peers**~~ ✅ **DONE (2026-08-30)** | `asm-x86_64` `asm-arm64` `riscv64` `wasm-wat` | — | **CLOSED — all four are `755 · 0F`.** `wasm-wat` first (2026-08-29), then ported to the three ISAs (`f3acd7f`, `abfddad`, `8636506`); `asm-arm64` was green on the first run and `riscv64` is severity-identical to it on all 755 checks. **One thing did not port mechanically:** §5.6 rule 3's overflow test reads the carry flag after `add`/`adds` on x86-64 and aarch64, and **RISC-V has no condition-flags register** — the wrap has to be detected as *the sum is less than either operand*. Getting that wrong compiles clean and silently saturates instead of dropping the term, which is the exact CAP-6 defect the rule exists to prevent; ratcheted in `AGENTS.md` as **a rule expressed in terms of a CPU flag is not portable — restate it as a value comparison before porting it.** Landing the chain also made a §4.9(c) hole reachable: four early-outs in the newly-reachable `request` path fell off the end of the function answering nothing. The original finding is kept below because it is the "wrong denial standing in for a missing check" archetype. Found 2026-08-29 by tracing why CAP-5/CAP-6 refuse. Each of these peers requires a presented capability's `granter` to be **this peer** and refuses anything else. `asm`'s source says so outright: *"until the delegation-chain walk exists, fail closed: granter ≠ our identity_hash → 403. (Closes forged_root_capability and the chain-\* reject probes, which all require denial.)"* — the stand-in was deliberate and documented; what was never noticed is what it buys. **Every chain vector these peers pass is reject-direction** — `chain_no_delegation_denied`, `chain_max_delegation_ttl_denied`, `chain_per_link_temporal_denied`, `chain_mid_link_expiry_denied`, `chain_parent_exclude_drop_denied`, all three `authz_attenuation_foreign_granter_*`, `chain_content_hash_substitution` — and a peer that refuses every chain answers all of them correctly for a reason unrelated to what they test. The `security` category has no accept-direction chain vector, so nothing catches it there; the only checks that do are CAP-5/CAP-6 (which present a delegated cap and therefore never reach the mint) and CAP-6a (whose control is a chain, so it SKIPs). **This is "conformance-green can be vacuous" and "a wrong denial standing in for a missing check" arriving together**, and it is not a coincidence that it is exactly the four peers written by hand: chain walking is the most laborious part of §5.5 to hand-author, so it is the part that got deferred, in assembly and in WAT alike. Scope: chain collection + per-link signature/grantee/temporal/attenuation/caveat validation + a root-granter test, in three ISAs and one WAT peer. |
| ~~**Connection-pressure defect**~~ ⛔ **RETRACTED (2026-08-30) — this defect never existed** | asm-x86_64, asm-arm64, riscv64 | — | **The row above described `t2_2_connection_churn` + `r1_payload_over_limit` + `r3_connection_flood` as "one failure family: forked children block forever in `read(2)` with no idle deadline, and there is no §4.10(c) connection-admission cap." That diagnosis was wrong and stood from 2026-08-17 across four investigations.** The cause was a **§4.9(c) silent drop**: the op ladder compares an operation's LENGTH before its bytes, `ping` collides with `echo` at 4, and the failed byte compare jumped to the function epilogue writing no frame at all. Every churn cycle ends with a `ping`, so every cycle burned the caller's full 20 s read deadline — `concurrency` 599 s → **1.1 s, 6/6**. `r1`/`r3` were never a family member: both ran and passed the moment the budget stopped being eaten. **A §4.9(c) drop is billed entirely to the CALLER's timeout, so it presents as the peer being slow or under-resourced rather than wrong** — every health check anyone ran was answering *"is the peer unhealthy"*, and the peer was fine. Full retraction and the diagnostic that closed it: **§1a**. |
| ~~**Extension type-vocabulary over-publication**~~ ✅ **DONE (2026-08-30)** | asm-x86_64, asm-arm64, riscv64 | — | **CLOSED — all three are `755 · 0F` at `313P/336W` / `312P/337W` / `312P/337W`, and the fix LOWERED the pass count by 282.** `src/typestore.s` published ~200 types incl. COMPUTE/CONTENT/CLOCK/CONTINUATION vocabularies, against `AGENTS.md`'s *"a core peer never pre-publishes extension vocabularies"*; the oracle scores those matched-if-present, so it had been converting 282 `type_system` WARNs into PASSes — **a higher pass count from a scope violation, not better conformance.** The store is now filtered to the 53-name core floor, corroborated exact against 8 other peers (rust python haskell ocaml swift java c typescript all publish the byte-identical 53). Verified per-check before/after on each peer: exactly 282 changed, all `type_system`, all PASS→WARN, nothing else moved. Enforcement grep `grep -rl 'system/type/compute/apply' protocol-generator/*/src/` now returns nothing. **Two things surfaced in the doing:** the filter belongs in `gen-typestore.py` as a fail-closed **keep-list** (the harvest comes from the FULL reference peer and stays intact as evidence; a drop-list would fail open on the next harvest), and **`riscv64`'s `reference/typestore/` had never been committed** — its generator could not run from a clean clone. All three now regenerate byte-identically from their own committed input. Detail: ⁹. |
| ~~**`zig` intermittent process ABORT in detached-thread teardown**~~ ✅ **MECHANISM REMOVED (2026-09-02) — and read the measurement caveat, because the count does not prove it** | `zig` | Medium — a clean run is a real 0-FAIL; an aborted run is an INVALID MEASUREMENT, not a low score | **The fix is structural: the peer no longer detaches any thread.** Both sites now own their handles — `host.zig` holds a 64-slot table where the admission bound and the thread lifetime are ONE mechanism (a slot frees only when its thread is JOINED), and `transport.zig` keeps an owned list of §4.8 dispatch threads, replacing an in-flight counter plus a `std.Thread.yield()` spin. `grep -c 'detach()' protocol-generator/zig/src/*.zig` returns 0 outside comments, which is the enforcement point. The panic arm (`entryFn`'s `.completed => unreachable` at `std/Thread.zig:1377`) is reachable only through the detached path, where `freeAndExit` munmaps the thread's own `Instance` mapping from inside the dying thread and a concurrent `spawn()` can be handed the address before the kernel's `CLONE_CHILD_CLEARTID` write lands in it; joining frees the mapping from the OWNER, after the kernel is done. **What is NOT claimed: that the abort rate was measured down.** It was recorded at 5 of 60 runs (8%) on 2026-09-02 morning and **would not reproduce at all that afternoon** — 0 of 130 sequential `--profile core` runs on the unchanged source at `--cpus=4`, uncapped (32 cores), and with 12 CPU burners oversubscribing the container, plus 0 of 100 `-category concurrency` runs. An instrument with a 0/130 baseline cannot demonstrate a fix, and 100 clean post-fix runs would be the same 0 either way; **saying so is the point.** The mechanism is nonetheless live and current: an intermediate variant carrying ONLY the `host.zig` half — i.e. still detaching the dispatch threads — reproduced the identical `Thread.zig:1377` panic, 1 abort in 100 runs, which also locates the abort at the **transport** site rather than the accept loop. **What IS measured, with power, is a second defect the same change removed:** `concurrency/t2_2_connection_churn` intermittently stalled for **20.6 s** against its usual 1.2 s — one churn cycle waiting out the oracle's request deadline. Unfixed **7 of 100**; `host.zig`-only **10 of 100** (unchanged, so it is not the accept loop); both halves **0 of 100**. That isolates it to replacing `awaitInflight()`'s yield-spin with a real `join()`: a reader busy-waiting on 4 cores can starve the very dispatch thread it is waiting for, where a futex wait cannot. Peer re-measured at `756 · 315P/335W/0F/106S`, `run-origination-core.sh` `Result: PASS`. |
| ~~**`cpp` retained one FILE DESCRIPTOR per connection, for the process lifetime**~~ ✅ **DONE (2026-09-02)** | `cpp` | Medium — no published number moves, and the peer would exhaust descriptors mid-suite under a conventional `ulimit` | **Found by asking the `zig` question of its siblings the same day, and it is the accumulation class rather than the lifetime one.** `Listener::Impl::conns` was **push_back-only** — no `erase` anywhere in the file — so a finished connection's `shared_ptr<Io>` was retained forever, and `~Io` is what calls `::close(fd_)` while `close_io()` only `shutdown()`s. The struct's own comment said *"keep its Io + Connection + reader thread alive until reaped"*; nothing reaped. **Measured on the running peer, not argued from the source: 4 fds idle → 1419 after one `--profile core` suite → 2834 after two**, linear and unbounded, and remotely triggerable by anyone who can open a connection. It has never failed a run because the toolchain container's soft limit is **524288**; under the conventional 1024 the peer would run out partway through a single suite and `accept()` would begin failing with `EMFILE`. Fixed with the same reap shape as `zig`'s accept loop — a `done` flag the reader sets LAST, and an erase in the accept loop that joins the reader before dropping the `shared_ptr`s; detached §4.8 dispatch threads hold their own copies, so the refcount keeps the fd alive exactly as long as it is in use. After: **4 → 7 → 6**, flat. Re-measured at `756 · 314P/336W/0F/106S`, unchanged. **The generalisable half: a comment that names a lifecycle step is not evidence the step exists, and the cheapest check is to count the resource at two points in time rather than read the code that manages it.** |
| ~~**Per-peer `status/CONFORMANCE-REPORT` records one pin behind**~~ ✅ **DONE — 46 of 46, completed 2026-08-30** | 0 remain. `apl` was the last, at the retired 682-check set, and it was behind because it was excluded from the census rather than because it could not be measured (§1d) | — | **CLOSED for everything this repo currently publishes.** Found in the release sweep: every tracked `status/CONFORMANCE-REPORT.json` was at the retired `de8f807` **740**-check set or older (38 at 740, 4 at 682, 1 at 645, `io` unreadable); **none at 755**. The `.md` siblings were worse — several led with `cc1970f`/`b30a589`-era banners quoting `552`/`576` totals from oracle `cb54f5b`. So a clone showed each peer's own report contradicting its §1 row. **Never a wrong number in §1** (census-backed) and **not caused by the M1/M2 passes** — the cause was structural: `run-cohort-census.sh` deliberately never writes tracked reports and `output/` is gitignored, so no driver could refresh them. **Fixed three ways:** (a) `run-cohort-census.sh --to-status` adds the missing destination to the *same* dispatch table (explicit opt-in, never the default); (b) all 13 publishable peers **re-measured** against the pinned oracle — each reproduced its published number exactly, 13/13 comparable; (c) `tools/check-set-gate.py --tracked`, now run by `make lint`, gates the committed reports so this cannot silently return. The 32 unfixed peers are reported by the gate but do not fail it — disclosed debt, and they rejoin the gated set as the CAP fix reaches them. **Refreshing a tracked report is a MEASUREMENT — never hand-copy a census JSON onto one.** |
| ~~**`authz_peers_target_from_uri`** — a **SPEC AMBIGUITY** that splits the cohort 40/6~~ ⛔ **RETIRED (2026-09-01) — the check no longer exists, and the ambiguity was never one** | was 40 WARN · 6 PASS; now 46 of 46 PASS its replacement | — | **CLOSED, and the correction runs the other way from the last one.** This row said *"Which behaviour is conformant is NOT settled by the spec, and that is the finding"*, and argued from the `peers` default's dead weight that **the 6 were right**. **§1.4 had settled it, in the snapshot the finding cites in its own header.** `ENTITY-CORE-PROTOCOL.md` line 300, byte-identical in `v0.8.2` and `v0.8.2.3`: *"the path MUST target the local peer's namespace. If the peer ID does not match the local peer, the peer MUST reject with status 400 (`invalid_request`)."* So the **majority** reading was right, and **both** groups had the disposition wrong — the 40 answered `404 handler_not_found` (`go` among them), the 6 answered `403`/`200`, the spec says **400 `invalid_request`**. What 0.8.2.2/0.8.2.3 added is the code NAME plus the explicit prohibition on both wrong dispositions (§3.3, §6.2, §6.5 step 3); the underlying MUST predates this finding. **The check itself was deleted rather than re-pointed** — its PASS branch required the foreign-namespace resolution §6.5 step 3 forbids, so it rewarded the defect; `strings validate-peer` finds 0 occurrences at the current pin. Its replacement is `authz/dispatch_inbound_foreign_namespace_refused`, and **all six former-PASS peers needed the new gate** (`forth` `smalltalk` in the 0.8.2.3 sweep; `pd` `asm-x86_64` `asm-arm64` `riscv64` on 2026-09-01) — not a coincidence, since passing required exactly the forbidden behaviour. A seventh, `wasm-wat`, WARNed here and still needed it: it refused, but by resolving locally and then failing authz, so **a WARN never meant safe**. Correction and the search-vocabulary lesson: [`protocol-generator/shared/findings/peers-dimension-reachability.md`](protocol-generator/shared/findings/peers-dimension-reachability.md). |
| ~~**§4.7 pre-hello `authenticate` — the spec contradicts itself and the cohort splits**~~ ✅ **CLOSED — architecture folded it; row 6 won and the oracle now gates it** | 46 | **Resolved.** `connect_prehello_authenticate` PASSes on 46 of 46 at the current pin | §4.7 row 6 says `401 invalid_nonce`, row 10 says `400 connection_sequence_error`, for the same input. Measured on the wire 2026-08-30: **38 / 6 / 1** (`prolog` answers `401 authentication_failed`; `csharp` unbuildable offline). Raised by `entity-core-formalization` (`ROUTING-2026-08-30-PREHELLO-AUTHENTICATE`), whose source census this **confirms exactly** — 0 disagreements across the 34 peers they resolved — and whose 11 unresolved peers this resolves. **The sequencing ask is real and cheap to honour: land the ruling BEFORE the v0.8.2 regeneration** or the ~6-peer sweep gets done twice. Do NOT resolve it by reading the oracle's Go source. Detail: [`prehello-authenticate-wire-census.md`](protocol-generator/shared/findings/prehello-authenticate-wire-census.md). |
| ~~**§4.7's connect-error table and its address-before-authentication row are unimplemented cohort-wide**~~ ✅ **DONE (2026-09-08) — landed, and DELIBERATELY NOT VISIBLE IN ANY ROW ABOVE** | 46 of 46 | Medium — a normative MUST-emit contract; clients key error handling off `result.data.code`, so a collapsed code selects the wrong remedy | **CLOSED at 46 of 46, and the honest framing is that no published number moves.** §4.7's table (0.8.2.4/0.8.2.6) gained checks in the CANDIDATE check set (`entity-core-go` `78db4a9`, 778 executed) and has none at the pin, so the work is invisible here until the re-pin: every peer is `778 · 0F` against the candidate and every committed report is unchanged at `c34abcae…`. **Re-measured at the pinned oracle after the change: 3 of 34 868 severities moved across all 46 tracked reports, all three the same documented `t1_1_concurrent_demux` timing ratio, two against and one for — none banked.** The rows implemented: `incompatible_protocol` / absent-or-empty `protocols` → `400 invalid_request` / unknown CONNECT operation in any state → `400 invalid_request` / second `hello` half-open → `409 connection_sequence_error` / second `hello` established → `409 connection_already_established` / `authenticate` peer_id ≠ `hello` peer_id → `401 identity_mismatch` / unregistered local path → `404 handler_not_found` / **pre-establishment EXECUTE naming a FOREIGN namespace → `400 invalid_request` (F57)**. **The last of those is the one to read carefully:** four INDEPENDENT implementations (`entity-core-{go,rust,py}` and our own `go` peer) answered `401` before we changed ours, against a table that names the status, the code and its own reason in one paragraph with §1.4 supplying the MUST. We implemented the spec, we are not treating our reading as settled, and the vector ask is routed (F57) with the reversal cost stated — 25 peers × a three-line hoist. |
| **`r3_connection_flood` — §4.10(c) connection-admission bound is unimplemented cohort-wide** | 42 of 46 | Low — §4.10(c) is a **SHOULD**, so it WARNs and never gates | Only `asm-x86_64`, `asm-arm64`, `riscv64` and `pd` PASS; every other peer answers *"admitted all 256 connections without refusal and kept serving — no self-imposed bound, so admission is delegated externally (systemd / proxy / OS fd limit)"*. **Raised as its own row on 2026-08-30 because it had been disclosed only in footnote ⁹ as something `asm-arm64`/`riscv64` owed `asm-x86_64`** — which is backwards: those two were with the cohort and `asm-x86_64` was ahead of it. Delegating admission to the supervisor is a legitimate posture for a SHOULD; what was not legitimate was naming two rows for it while 42 identical rows said nothing. **The two ISA peers took the port later the same day (44/2 → 42/4), for ISA parity rather than catch-up** — the four `host.s`/`dispatch.s` hardenings in ⁹. That does not move the cohort finding, which is what this row is about. Fix shape now exists in four peers if an adopter asks. |
| ~~**`libentitycore_codec` leaks an `ec_value` tree on EVERY encode — the "process exits" assumption is false for every peer that links it**~~ ✅ **DONE (2026-09-04)** | the FFI-consuming tier | — | **CLOSED, and the fix is verified by the whole cohort: 46/46 conforming, all comparable, and exactly 2 of 34 868 severities differ from the committed reports — both `t1_1_concurrent_demux`, the documented timing-ratio flake, neither a FAIL.** Found 2026-09-04 while measuring `cobol`'s capacity work and BISECTED rather than assumed: `cobol` grew 23.3 MB of address space per `--profile core` suite at `HEAD` and 22.3 MB after the capacity change, so it was neither new nor worsened by that work. It tracked REQUESTS, not connections — measured with `protocol-generator/shared/diagnostics/cobol-ffi-encode-leak-probe.sh`, which drives a connection-heavy category and a request-heavy one against separate fresh peers: `connectivity` 80 kB per run against `type_system` 419 kB over ~449 requests, i.e. **~1 KB per dispatched request**. **The mechanism was stated in the library's own source:** `src/ecf.c` — *"the harness + ABI calls are short-lived; we malloc value nodes and never free the tree (process exits)"*. True of the conformance harness it was developed against, false of every long-running peer that links it. `ec_encode_ecf` and `cc_content_hash` are called per request and each built an `ec_value` map that was never released; `ec_envelope_find_signature_for` leaked one tree **per included entity** with both its `continue`s skipping any free; the decoder leaked its partial tree on every malformed input, which is remotely triggerable by bad bytes alone. **The comment also named the fix — *"a v2 arena (`ec_arena_*`) replaces this for the long-running peer decode path"* — and that arena is a stub** (`malloc(1)`), honestly documented as unnecessary because decode borrows spans. The deferral was resolved on the DECODE path and left the sentence appearing to cover ENCODE, which it never did: **the standing "a deferral comment is a conformance claim with no gate on it" rule, in shared code.** Fixed with a recursive `ev_free` plus a release at every entry point that builds a tree, on every exit path including the error ones; child arrays are now zero-allocated so a partially built tree is walkable. **The ownership rule moved into the C-ABI header** (`ffi-generator/c-abi/spec/`), where a consumer reads it — a library whose correctness depends on its caller being short-lived has made that a term of its ABI. Rust already satisfied it. **Measured after: `cobol`'s virtual size is FLAT from the first suite through the fifth (235 132 kB, unchanged), against +22.7 MB per suite before.** *(And the fix first appeared to do nothing — `cp -a` restoring the saved tree after a HEAD bisect build preserved an mtime OLDER than the objects built in between, so cmake recompiled nothing and reported success. Ratcheted in `AGENTS.md`.)* Sibling drift found and closed in the same pass: the impl's shipped `entitycore_codec.h` had lost the `ec_ed25519_seed_to_pubkey` declaration the spec header carries, so a consumer could not call a symbol the library exports; the two are byte-identical again, as the README has always claimed. |
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

### Current state — 2026-09-08 @ the 778-check pin `7aa6f3de…` (cohort closed, 46/46)

**Every tier is current and 0-FAIL at the pin above**, confirmed by `tools/tier-status.py`. The
`State` column below records when each tier was **first** brought to 0-FAIL — at the retired
755-check pin `95edd774…` — because that closure is the evidence for how the debt was distributed,
and back-dating it would destroy that. Each tier has since been **re-measured at every re-pin**
(755 → 756 → 758 → 778); the current numbers are §1's, not this table's.

| Tier | Current & 0-FAIL | First closed (755-check pin `95edd774…`) |
|---|:---:|---|
| **M1** | **5 / 5** | **Fixed 2026-08-21 — the re-pin is LANDED.** `tools/tier-status.py --gate` exits 0 |
| **M2** | **8 / 8** | **Fixed 2026-08-22.** `typescript` 84F → 0F and `csharp` INVALID → 0F were the *same* §6.3 defect in its two presentations (§1b/§1c); the other 6 took the same CAP fix |
| **M3** | **13 / 13** | **Complete 2026-08-30.** `cobol` was the last, and its 30F was 24 cascade + 5 real + 1 — not the standing "liveness cascade" it was filed as |
| **probe** | **18 / 18** | **Complete 2026-08-30.** 11 peers fixed 2026-08-28; `wasm-wat` 08-29; then the ISA trio (INVALID → 0F, §1a) and `apl` (never unmeasurable, §1d) |
| **exploratory** | **2 / 2** | `node-red` 0F (it was never broken — stale `dist/`, §3). `turbowarp` 0F since 2026-08-29. Never gates (§1 ‡) |

**Every tier is current on the pin, nothing is stale, and the cohort is closed at 46 of 46.**
What the lower tiers carried was one debt (§5.6's MIN_DEFINED mint ceiling, absent everywhere), and
propagating it took the cohort from 13 publishable to 41. The rest were *different* problems, not
one: `cobol`'s memory-safety cascade, the ISA trio's §4.9(c) silent drop, two hand-authored
substrates missing §5.5 chains, and one peer excluded from measurement by a stale claim. *(This
table read `probe 13/18 · exploratory 1/2` and the paragraph read "41 of 45 … six different
problems" until 2026-08-30 — stale in the same commit that closed the work it described. Before
that, "25 of the 29 scored unfixed peers fail nothing but the new CAP checks"; that finding was
right and is now history.)*

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
discovery well has been dry on the current wire surface since ~15 peers ([`synthesis-reconciliation.md`](protocol-generator/shared/syntheses/synthesis-reconciliation.md)), so peers 16–46 are
corroboration and generator-robustness, not new findings. **M1 is where a real regression shows up
first; the rest is breadth, and breadth can lag by design as long as the lag is visible.**

*Deliberately unchanged:* the release gate. Before a release, run everything (`run-cohort-census.sh`
with no arguments) — tiering governs the cadence *between* releases, not what a release claims.

---

*Companion evidence: the per-peer `protocol-generator/<lang>/status/` records (CONFORMANCE-REPORT, ARCHITECTURE-REVIEW, SPEC-AMBIGUITY-LOG) and the cross-language findings register `research/stewardship/SPEC-FINDINGS-LOG.md`.*
