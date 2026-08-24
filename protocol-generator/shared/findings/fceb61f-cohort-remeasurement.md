# HANDOFF TO ARCH — 2026-07-28 — the cohort re-measured at `entity-core-go` `fceb61f`

**Companion / successor to:** `af8a582-cohort-remeasurement.md`. Arch's
response (verbal, 2026-07-28) implemented the two oracle items that handoff's §7 asked for — F40
control Row A + the A→B differential, and an RT-6 class split — at `entity-core-go` `fceb61f`
("feat(0.8.1 validator): F40 control Row A + RT-6 class split (oracle handoff items #1/#2)"). This
is that re-measurement: **45 of 46 peers** (`apl` still blocked, unchanged from last time), dual-
anchored on the new F40 differential + the RT-6 ladder, plus RT-13b Part-B progress.

**Reproduce:** `tools/run-cohort-census.sh` (new this session — no cohort-wide driver existed
before; every prior sweep was hand-driven peer by peer). `python3 protocol-generator/shared/diagnostics/f40-scope-typing-differential.py
output/scratch/census` and `python3 protocol-generator/shared/diagnostics/rt6-class-census.py
output/scratch/census` produce the two attribution tables below directly from
the measured reports — no hand transcription.

---

## 0. Headline

- **Gate unchanged: 6 PASS** (`go` `python` `rust` `rust-wasm` `rust-wasm-wasmtime` `nim`), same set
  as `af8a582`. `nim` still passes with an RT-6 WARN; `rust-wasm`/`rust-wasm-wasmtime` are still thin
  transport seams over the `rust` crate — independent-green count is still **4**.
- **F40 attribution resolves exactly the confound the af8a582 handoff flagged.** With the control
  row, only **2 peers** (`forth`, `smalltalk`) have a real, attributable canonicalization defect —
  down from the af8a582 census's naive "8 FAIL the exclude row." The other 6 were false positives:
  **4 are `WARN:unrelated-deny`** (`datalog`, `sql`, `swift`, `wasm-wat` — their baseline already
  denies for a reason unrelated to id-scope typing, exactly the `swift` counterexample the af8a582
  handoff's §3 caveat predicted), **1 is `unattributable`** (`cobol` — its liveness crash kills the
  connection mid-probe, so neither row got a real answer), and the previously-uncounted **6 are
  `not-measured`** (budget_exhausted, see §3).
- **RT-6 six-class ladder, measured**: 5 PASS, 2 WARN (wrong code), 7 FAIL `replay-accepted` (genuine
  2xx accept — same 7 peers as `af8a582`: `asm-arm64` `asm-x86_64` `pd` `prolog` `riscv64` `sql`
  `wasm-wat`), 31 FAIL `wrong-status`. **Zero peers landed in a distinct "post-delivery silent
  close" class this run** — see §2 for why, and for the one open item this surfaces for arch.
- **A methodology note that belongs in this handoff, not buried in a diff**: this run enforced a
  **uniform 60s oracle-default timeout across the whole cohort** (my driver's explicit
  `-profile core -json-out <path>` args override each harness's own default substitution, which is
  all-or-nothing — it silently drops a harness's bumped `-timeout` too). I caught and corrected two
  real casualties of this (`oz`, `rexx` — restored to their historical 10m budget once I noticed
  their totals had dropped to 679/681), verified the fix reproduces their historical FAIL count, and
  fixed the driver so a future run passes the historical budget for all nine inflated-timeout
  harnesses (`tools/run-cohort-census.sh`) rather than relying on a human to notice.

---

## 1. F40 attribution — the full 45-peer table

| Verdict | n | Peers |
|---|---|---|
| **`conformant`** | 34 | `ada` `c` `common-lisp` `cpp` `crystal` `csharp` `dart` `elixir` `fortran` `go` `haskell` `io` `java` `julia` `kotlin` `lean` `nim` `node-red` `ocaml` `odin` `oz` `pd` `php` `prolog` `python` `rexx` `ruby` `rust` `rust-wasm` `rust-wasm-wasmtime` `tcl` `typescript` `unison` `zig` |
| **`FAIL:canonicalization`** | 2 | `forth`, `smalltalk` — both fail `f40_id_scope_exclude_literal` with `(ALLOW,DENY)`; `forth` ALSO fails `f40_id_scope_include_no_overgrant` (the one real double-failure) |
| **`WARN:unrelated-deny`** | 4 | `datalog`, `sql`, `swift`, `wasm-wat` — `(DENY,DENY)`, baseline itself denies, exonerated per the A→B rubric |
| **`not-measured`** | 4 | `asm-arm64`, `asm-x86_64`, `riscv64` (genuine, §3), `turbowarp` (unrelated to timeout — an inherent gap in this exploratory probe) |
| **`unattributable`** | 1 | `cobol` — Row A probe itself hit `broken pipe` (the standing liveness crash killed the connection mid-check) |

`sql` and `swift` are the two peers named explicitly in the af8a582 handoff's §3 caveat (`swift`'s
matcher is demonstrably kind-branched, so its exclude-row 403 could never have been a canonicalization
defect) — both now read exactly as that caveat predicted, from measurement rather than an inference
about `swift`'s source. This is the confound closing cleanly; no further action needed on either.

**`forth` and `smalltalk` are the two real, attributable F40 defects left in the cohort** — a fix is
the same shape as every other converted peer (branch the id-scope matcher on dimension kind).

---

## 2. RT-6 six-class ladder — the full 45-peer table

| Class | n | Peers |
|---|---|---|
| **1 — PASS** (401 invalid_nonce) | 5 | `go` `python` `rust` `rust-wasm` `rust-wasm-wasmtime` |
| **2 — WARN** (401, different code) | 2 | `nim` (`missing_author`), `turbowarp` |
| **3 — FAIL `replay-accepted`** (genuine 2xx accept) | 7 | `asm-arm64` `asm-x86_64` `pd` `prolog` `riscv64` `sql` `wasm-wat` |
| **5 — FAIL `wrong-status`** (non-401 rejection) | 31 | everyone else — see the full table in `output/scratch/census/` per-peer JSON; the majority are `409 connection_already_established`, matching the af8a582 census |
| **4 — FAIL `no-rejection-proof`** (post-delivery close) | 0 | — |
| **6 — WARN** (pre-delivery write-fail) | 0 | — |

Classes 4 and 6 are both empty this run — worth flagging precisely rather than reading as "the
close-without-response behaviour disappeared." Checked directly: the three peers that were in the
af8a582 census's "connection closed, no response" bucket (`csharp`, `node-red`, `typescript`) are
now `wrong-status` with **`status=0, code=""`** — e.g. csharp's message: *"rejected with status 0
code=\"\" (e.g. 409 state-conflict)"*. That is the oracle's generic non-401 `default:` branch, not
the explicit read-error branch that produces the "CLOSE emitting nothing" wording (which is what my
census script's class-3/class-4 disambiguation looks for — see `protocol-generator/shared/diagnostics/rt6-class-census.py`'s docstring).
So on this build, a `status2==0, code==""` decode outcome is reaching the switch's default case
rather than the dedicated close-handling branch — i.e. `readFrame` is *not* returning an error for
these three peers, but whatever it decodes yields zero-value status/code. **This is worth arch's
attention as its own small question**: is a decoded-but-fieldless response frame supposed to fall
through to `wrong-status`, or should it be attributed the same as an explicit close? Right now it's
scored WARN-safe-adjacent (`wrong-status`, "wrong-but-safe") rather than the more cautious
`no-rejection-proof` framing arch's ruling described for a silent close — and it's not visible
without reading `details.rt6_class` + the message text together, which is why keystone's own
`protocol-generator/shared/diagnostics/rt6-class-census.py` disambiguates on message wording rather than trusting the label alone (per
oracle-pin.env's note on the still-pending upstream rename).

---

## 3. Budget_exhausted — genuine vs. self-inflicted (both closed out this pass)

Same interaction as the af8a582 handoff's §4a (`concurrency/t2_2_connection_churn` eating the 60s
global budget before `authz` runs, so F40 gets `SKIP skipped` instead of a verdict) — **still present
and still genuine** on `asm-arm64`, `asm-x86_64`, `riscv64` (679 total, 105 skipped, unchanged shape
from `af8a582`). This is a peer-latency issue on those three, not something this pass touches.

`turbowarp`'s reduced total (681, matching `af8a582` exactly) is unrelated to timeout — it's an
inherent category gap in that exploratory, non-deployable probe.

**`oz` and `rexx` were NOT genuine budget_exhausted casualties — they were an artifact of my own
driver**, caught and fixed within this session (not left in the numbers above): my cohort-census
script always passes explicit `-profile core -json-out <path>` args, which — because each
harness's own default-args substitution is all-or-nothing (`if [ "$#" -eq 0 ]`) — silently discarded
`oz`'s and `rexx`'s historical 10-minute `-timeout` bump along with it, dropping them to the 60s
oracle default and starving `authz` exactly like the three genuine cases. Caught by comparing totals
against the af8a582 baseline (both had been full `719`-check peers before), re-ran both with their
historical budget explicitly restored, confirmed both return to a full `719`-check, single-FAIL
result. **`tools/run-cohort-census.sh` is fixed** so a future run passes the correct historical
budget for all nine of AGENTS.md's disclosed inflated-timeout harnesses (`apl` excluded/blocked,
`io` 15m, `forth`/`oz`/`rexx`/`smalltalk` 10m, `dart`/`fortran` 5m, `prolog` 180s — `prolog`'s bump
was already unconditional in its own script and was never at risk).

No action requested on this section — it is keystone's own driver bug, disclosed and fixed, not a
peer or oracle finding. Flagged so the board isn't surprised by why `oz`/`rexx` don't show
`not-measured` here despite being on the historically-inflated list.

---

## 4. RT-13b Part-B (§4.1 write-concurrency classes) — progress this session

Full detail lives in `protocol-generator/shared/diagnostics/rt13-write-concurrency-classes.md` (updated this
session); summary for the board:

- **The two named holds are resolved** (`zig`, `common-lisp`) — both were a partial-grep false
  negative from the predecessor pass, not a real gap. Both have a real, resolvable write-mutex
  (`transport.zig:42` / `Io.writeFramed`; `peer-transport.lisp:21` / `write-framed`), verified by an
  exhaustive call-site search showing no bypass. Both move to Class M with their cited symbols.
- **The two named caveats are closed** (`oz`, `io`) — both Class S, with the queue/buffer that
  serializes concurrent logical writers named and verified from source (`oz`'s per-connection
  `Writer` port; `io`'s `Conn.wbuf` + `_flushWrites`, distinguished from the unrelated `Session`
  client object at the one other write call site).
- **Class R (`go`, `rust`) is done and independently verified non-vacuous.** Both now have a
  deterministic ≥2-writer test asserting frame-boundary integrity (not demux timing) —
  `protocol-generator/go/src/peer/transport_concurrency_test.go` (`go test -race`) and
  `protocol-generator/rust/src/peer/transport/tests.rs` (`cargo test`, run inside `rust-toolchain`
  since the crate's MSRV 1.96 exceeds host rustc 1.94.1). Both were confirmed to actually catch a
  regression: temporarily bypassing each peer's write-mutex reproduced the exact corruption
  signature (an undecodable/torn frame) the test is designed to catch, before the bypass was
  reverted. Both still owe CI wiring under a detector (`-race` / TSan / Miri) — noted, not a
  source-level gap.
- **Still open**: every Class M peer's own ≥2-writer test (18 peers: `c` `cpp` `ada` `odin` `zig`
  `cobol` `common-lisp` `prolog` `ocaml` `julia` `lean` `haskell` `unison` `java` `kotlin` `csharp`
  `ruby` `python`), and the RT-13a storage-layer artifact on the manual-memory peers (`c` already
  done via `A-C-009`; the rest owe the same shape). This is next-session work — the `go`/`rust`
  tests are the template.

---

## 5. Open asks carried forward unchanged (not re-litigated here)

F49 (§5.2 `matches_scope` pseudocode scope-kind parameter), F50 (`scope_subset` §5.5a ruling), and
the id-scope wildcard-syntax ask (`sql`'s `GLOB`) are all still open per the af8a582 handoff's §7 —
nothing in this pass changes their status. Flagging only the one *new* small ask from §2 above
(the `status=0` decode-outcome routing question).

---

## 6. The measured table

45 of 46 peers (`apl` still blocked — unchanged, §8 of the af8a582 handoff). Oracle: `entity-core-go`
`fceb61f` (`tools/oracle-pin.env`; `core_gate_fingerprint` byte-identical to `af8a582`,
`check_set_digest` moved — one check added, one rewritten in place).

| Peer | Gate | total | P | W | F | S | RT-6 class | F40 |
|---|---|---|---|---|---|---|---|---|
| `ada` | FAIL | 719 | 297 | 321 | 1 | 100 | wrong-status | conformant |
| `asm-arm64` | FAIL | 679 | 542 | 30 | 2 | 105 | replay-accepted | not-measured |
| `asm-x86_64` | FAIL | 679 | 542 | 30 | 2 | 105 | replay-accepted | not-measured |
| `c` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `cobol` | FAIL | 719 | 266 | 321 | 27 | 105 | wrong-status | unattributable |
| `common-lisp` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `cpp` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `crystal` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `csharp` | FAIL | 719 | 297 | 321 | 1 | 100 | wrong-status | conformant |
| `dart` | FAIL | 719 | 295 | 323 | 1 | 100 | wrong-status | conformant |
| `datalog` | FAIL | 719 | 294 | 324 | 1 | 100 | wrong-status | WARN:unrelated-deny |
| `elixir` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `forth` | FAIL | 719 | 293 | 323 | 3 | 100 | wrong-status | FAIL:canonicalization |
| `fortran` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `go` | **PASS** | 719 | 297 | 322 | 0 | 100 | pass | conformant |
| `haskell` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `io` | FAIL | 719 | 295 | 323 | 1 | 100 | wrong-status | conformant |
| `java` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `julia` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `kotlin` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `lean` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `nim` | **PASS** | 719 | 297 | 322 | 0 | 100 | warn-wrong-code | conformant |
| `node-red` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `ocaml` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `odin` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `oz` | FAIL | 719 | 289 | 329 | 1 | 100 | wrong-status | conformant |
| `pd` | FAIL | 719 | 292 | 326 | 1 | 100 | replay-accepted | conformant |
| `php` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `prolog` | FAIL | 719 | 295 | 323 | 1 | 100 | replay-accepted | conformant |
| `python` | **PASS** | 719 | 297 | 322 | 0 | 100 | pass | conformant |
| `rexx` | FAIL | 719 | 295 | 323 | 1 | 100 | wrong-status | conformant |
| `riscv64` | FAIL | 679 | 542 | 30 | 2 | 105 | replay-accepted | not-measured |
| `ruby` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `rust` | **PASS** | 719 | 297 | 322 | 0 | 100 | pass | conformant |
| `rust-wasm` | **PASS** | 719 | 296 | 322 | 0 | 101 | pass | conformant |
| `rust-wasm-wasmtime` | **PASS** | 719 | 296 | 322 | 0 | 101 | pass | conformant |
| `smalltalk` | FAIL | 719 | 294 | 323 | 2 | 100 | wrong-status | FAIL:canonicalization |
| `sql` | FAIL | 719 | 293 | 325 | 1 | 100 | replay-accepted | WARN:unrelated-deny |
| `swift` | FAIL | 719 | 293 | 325 | 1 | 100 | wrong-status | WARN:unrelated-deny |
| `tcl` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `turbowarp` | FAIL | 681 | 252 | 322 | 3 | 104 | warn-wrong-code | not-measured |
| `typescript` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `unison` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |
| `wasm-wat` | FAIL | 719 | 293 | 324 | 1 | 101 | replay-accepted | WARN:unrelated-deny |
| `zig` | FAIL | 719 | 296 | 322 | 1 | 100 | wrong-status | conformant |

Every row was produced inside that peer's own pinned `containers/<toolchain>/` image under podman,
`--network=none` (network-on cases — `csharp`/`turbowarp` — per their documented cache-restore
need), via `tools/run-cohort-census.sh`. Reproduce the two attribution columns directly:
`python3 protocol-generator/shared/diagnostics/f40-scope-typing-differential.py output/scratch/census` and
`python3 protocol-generator/shared/diagnostics/rt6-class-census.py output/scratch/census`.

---

## 7. What blocked the run (keystone's own defects, disclosed per the standing convention)

- **A shared-`:Z`-mount race under concurrency** — discovered and avoided, not fixed: running
  multiple containers concurrently against the same bind-mounted repo root produces spurious
  failures (proved directly: `go`+`c`+`python`+`sql` run in parallel corrupted; serial, clean).
  `tools/run-cohort-census.sh` runs strictly serially as a result, documented in its own header so a
  future editor doesn't "optimize" it back into a race.
- **The oz/rexx self-inflicted timeout drop**, §3 — caught and fixed in the driver.
- **`datalog`/`forth` hit a transient SELinux/permission error** writing their JSON report mid-batch
  (`open ...census/<peer>.json: permission denied`), root cause not fully isolated (not reproduced
  on a standalone re-run of just those two peers with nothing else active) — recorded as a live
  concern for whoever runs this driver next, not silently retried without note.
- **`rust-wasm`/`rust-wasm-wasmtime` need `NOBUILD=1`** in a `--network=none` re-run without a warm
  vendor mirror — their `Makefile` fetches `wasmedge_wasi_socket`/`wasi` from crates.io on a clean
  build, which a sealed-offline run can never satisfy. Both already had a `NOBUILD`-eligible
  `out/peer.*` staged from a prior session; the driver now passes `NOBUILD=1` for both. **This is
  provisional, not a real fix** — a future clean-room rebuild of either toolchain image will need a
  real vendored `wasi`/`wasmedge_wasi_socket` mirror the same way the main `rust` peer already has
  one (`output/vendor`), or it will fail exactly the way this run's first attempt did.

`apl` remains unmeasurable (§8 of the af8a582 handoff, unchanged — still needs a human decision on
the 1.9→2.0 cool-down override).
