# The §4.7 pre-hello `authenticate` divergence, measured on the wire

**Date:** 2026-08-30
**Repo:** `entity-core-keystone`
**Responds to:** `entity-core-formalization` `ROUTING-2026-08-30-PREHELLO-AUTHENTICATE`
**Status:** ~~measurement complete; the normative question is architecture's and is untouched
here.~~ → **CLOSED 2026-09-09. The question was ruled the day after this was written, the cohort
converged, and the probe is superseded by a conformance vector.**

---

## CLOSED — re-measured 2026-09-09: the split is gone, 46 of 46

**Everything below this section is the 2026-08-30 measurement and is kept verbatim as the record
of a cohort that no longer exists.** Read the table below as history; this section is the current
disposition.

| | 2026-08-30 | 2026-09-09 |
|---|---|---|
| `401 invalid_nonce` | 38 | **46** |
| `400 connection_sequence_error` | 6 | 0 |
| `401 authentication_failed` | 1 (`prolog`) | 0 |
| not measured | 1 (`csharp`) | 0 |

**Nothing drifted. The spec answered, and the cohort was swept.** The sequence is worth stating
in order, because "a published measurement went stale" and "a measurement was superseded by the
ruling it asked for" look identical from the table alone:

1. **2026-08-30** — arch *proposed* a ruling (`entity-core-protocol` `804876e`, *"§4.7 answers one
   input twice — eight sites, five wire behaviours, and the ruling"*). This document was written
   the same day, against a vendored `v0.8.2` that predates it, and correctly said the normative
   question was open. It was.
2. **2026-08-31** — arch *folded* it: **0.8.2.1, FM-1** (`76dbd87`). A pre-hello `authenticate` is
   **401 `invalid_nonce`**; §4.7's out-of-order row explicitly stops naming it. Our own vendored
   `v0.8.2.11` carries the ruling in four places — §4.2 (line 1666), §4.7 row 10's *"**Not** a
   pre-hello `authenticate`"* (1910), the paragraph at 1925, and the §9.0 conformance bullet
   (4259) whose wording is *"never `connection_sequence_error`"*.
3. **2026-09-01** — vendored at `v0.8.2.3` and swept: `5a53b75c`, *"sweep(0.8.2.3): PD-1 and FM-1
   across the cohort"*. That commit is what moved the six.
4. **2026-09-09** — re-measured all 46 on the wire. Uniform `401 invalid_nonce`, positive control
   `200` on every peer, and `sequence_distinguished` now false on 45 of 46.

**`csharp` is measured, and it is a corroboration rather than a correction.** It answers **`401
invalid_nonce`**, trusted, which is *not* the `400 connection_sequence_error` formalization read
from its source — because they read it before the sweep. `git show 5a53b75c` on that file is a
one-line diff: `400 connection_sequence_error` → `401 invalid_nonce`, same message string. So
their source census stands at **35 of 35 resolved peers with zero disagreements**, and the one
row that looked like it might break the streak is the sweep, not a miss. Closes **FM-1k**.

**`prolog` was the one genuine third answer and it is gone too** — `401 authentication_failed` →
`401 invalid_nonce`. It is also now the *only* peer left that is sequence-distinguished, and in
the opposite direction from 2026-08-30: it answers `invalid_nonce` pre-hello and
`authentication_failed` *after* a hello with a wrong nonce. That post-hello answer is a separate
question this probe was never pointed at and is not asserted here.

### The probe is retired, on this document's own terms

The closing section below pre-committed to it: *"If architecture rules, the ruling belongs in
`validate-peer` as a vector — at which point this probe should be deleted, not kept as a second
source of truth."* Architecture ruled, and the vector exists: **`connect_prehello_authenticate`**
is in the pinned oracle (`78db4a9`, `probePreHelloAuthenticate`) and is **PASS on all 46**
committed reports, read per-check rather than inferred from the category. The independent probe
and the gate now agree peer-for-peer, which is the condition for retiring the probe rather than
the reason to keep it.

**`tools/p47-run.sh` is deleted; `tools/p47-probe/` is kept, retired, and is no longer a
maintained instrument.** The wrapper is deleted rather than fixed because *what it did* was the
hazard: it installed the probe **over** `output/s4-oracles/validate-peer`, a binary
`entity-system-generator` invokes **by path from its own tree**. That is gone, and it did not
need to exist by 2026-09-06 — the eight harnesses that silently dropped an `ORACLE` override were
fixed at source that day, which is the entire justification the wrapper's header gives for
swapping. **Measured today rather than assumed:** the whole roster ran through the plain
`--probe` route and **46 of 46 produced probe-shaped output**, with `forth` (self-relaunching),
`prolog` (a hand-written census branch) and `smalltalk` driven first as the two failure classes
the swap existed for. A control on `prolog` through *both* routes returned the same answer, so
the route is not the variable in the table above.

*(Two defects in the wrapper surfaced while establishing that, and both are the standing
never-executed-guard class. Its documented per-peer form — `p47-run.sh go swift`, printed in the
Reproducing section below — **had never worked**: `--probe` takes an optional NAME, so the first
peer name was consumed as the probe name and the census refused with `no probe BINARY at
output/s4-oracles/<peer>`. Only the no-args form had ever been run. And its holder guard is
start-only, which is adequate for a two-minute single-peer run and not for the ~90-minute roster
run this closure needed.)*

---

## What was asked

Formalization reported that **§4.7's own status table contradicts itself**. Row 6 reads
*"Nonce mismatch / absent / pre-hello (§4.6 step 1) | `invalid_nonce` | 401"* — §4.6 step 1
restated inside the table, with the citation. Row 10, four rows later in the same table, says
`400 connection_sequence_error`. Both describe an `authenticate` arriving before any `hello`.

They censused the 46-peer cohort **by reading source**, found a multi-way split, and said so
plainly: *"Not measured on the wire — no probe exists to measure it with."*

This is that measurement. `validate-peer` has no vector for this input, which is the reason the
divergence shipped unnoticed; asking the running peer is keystone's job, and *"a source grep is
not a conformance census"* is a standing rule here precisely because it has been wrong in both
directions before.

## Result — 45 of 46 peers, measured

| Answer to a pre-hello `authenticate` | Sequence-distinguished? | n | Peers |
|---|---|---|---|
| **`401 invalid_nonce`** | **no** | **38** | `ada` `apl` `asm-arm64` `asm-x86_64` `c` `cobol` `common-lisp` `cpp` `crystal` `dart` `datalog` `elixir` `forth` `fortran` `go` `haskell` `io` `java` `julia` `kotlin` `lean` `ocaml` `odin` `oz` `pd` `php` `python` `rexx` `riscv64` `ruby` `rust` `rust-wasm` `rust-wasm-wasmtime` `smalltalk` `tcl` `unison` `wasm-wat` `zig` |
| **`400 connection_sequence_error`** | **yes** | **6** | `nim` `node-red` `sql` `swift` `turbowarp` `typescript` |
| **`401 authentication_failed`** | no | 1 | `prolog` |
| *not measured* | — | 1 | `csharp` |

`csharp` could not be built offline in this environment (`NU1101: Unable to find package
Microsoft.NETCore.App.Host.fedora.43-x64`). That is a pre-existing toolchain gap, not a probe
limitation, and it is the one row where formalization's source read (`400
connection_sequence_error`) stands unverified.

### Their source census was right everywhere it committed to an answer

**Zero disagreements across all 34 peers they resolved from source.** Every peer they placed in
the 401 group measures 401 `invalid_nonce`; every peer they placed in the 400 group measures 400
`connection_sequence_error`. This is worth recording as loudly as a correction would be: the
standing rule to re-verify a routed claim is about *calibration*, not distrust, and here the
routed claim held under measurement.

### The eleven they could not resolve, now resolved

`asm-arm64` `asm-x86_64` `dart` `pd` `riscv64` `ruby` `rust-wasm` `rust-wasm-wasmtime`
`wasm-wat` → **401 `invalid_nonce`** · `node-red` → **400 `connection_sequence_error`** ·
`prolog` → **401 `authentication_failed`**.

`prolog` is a genuine third answer on the status/code axis. Formalization predicted it would
"probably land on 401 by accident of control flow" — half right: the *status* is 401, the *code*
is `authentication_failed`, not `invalid_nonce`. A peer with no explicit pre-hello guard falls
through to a later check, and which check it lands on is not predictable from the absence of a
guard.

## The finding a source read could not produce: most of the majority is not taking a position

Every peer was also asked the **same `authenticate` after a valid `hello` on the same
connection**, with the same (deliberately wrong) nonce. That control separates two very
different things a `401 invalid_nonce` can mean:

- **Sequence-distinguished (6 peers).** A different answer pre-hello than post-hello. These peers
  model "no hello yet" as its own state and have genuinely taken §4.7 row 10's position.
- **Not sequence-distinguished (39 peers).** The *same* answer either way. These peers do not
  model the pre-hello case at all — they reach the nonce comparison, find no issued nonce to
  match, and answer `invalid_nonce` for the same reason they would answer it for any wrong nonce.

**So the 38–6 split is not 38 implementations endorsing row 6 against 6 endorsing row 10.** It is
6 implementations that reasoned about connection sequence and 38 that never had to, because
folding the case into the nonce check produces row 6's answer for free. Row 6 is *cheaper*, and
on this evidence its majority is a by-product of that rather than a considered reading. An
argument from cohort weight should not be made from this table without that caveat.

That distinction is invisible to source reading in the general case — it requires knowing which
branch a given peer would reach for two different inputs — and it is the substantive thing this
measurement adds.

## Method, and what would make it untrustworthy

`tools/p47-probe/` (a static Go binary, run through each peer's own `run-s4.sh` harness via
`tools/p47-run.sh`). Three exchanges per peer, each detailed below because each one exists to
kill a specific way this number could be wrong.

1. **Control — a `hello` on a fresh connection, which must answer `200`.** Without it, a probe
   bug is indistinguishable from a peer's answer. This is not hypothetical: it caught **three
   separate probe defects**, each of which would have produced a confident, wrong finding.
2. **Measurement — an `authenticate` on a fresh connection, no `hello`.**
3. **Sequenced control — `hello` then the same `authenticate`, one connection.**

Every map is emitted in canonical length-then-lex key order, and every entity carries a **real**
`content_hash` (`0x00 || SHA-256(ECF({type, data}))`). The `authenticate` carries a **valid
identity** derived from the cohort-standard conformance seed (`0x11`×32) — the derived `peer_id`
is self-checked against the known value `2KHoAk7A5Jmhy…`. **Only the nonce is deliberately
wrong**, because that is the input under test.

### The three probe defects the controls caught

Recorded because each is a way a wire census can be confidently wrong, and none of them would
have been visible in the output:

- **Placeholder `content_hash`.** 33 zero bytes. §1.8 is validate-before-trust, so peers recompute
  and reject a mismatch — and `go` reports that rejection as **`400 non_canonical_ecf`**, which is
  a bare 400 and reads exactly like row 10. The frame was structurally perfect; only the control
  said otherwise.
- **`key_type` sent as the numeric §1.5 registry code.** The wire field is **text** (`"ed25519"`).
  Four peers answered `400 unsupported_key_type`, which looked like a *fifth behaviour class*
  concentrated suspiciously in the hand-authored group. The **sequenced control** killed it: `go`
  gave the same 400 once a hello had preceded, proving the status was about the params and not
  the sequence. A probe without that control would have published a new finding about
  `asm-x86_64`, `asm-arm64`, `riscv64` and `wasm-wat` that does not exist.
- **A hello with no `nonce` field.** Accepted by 38 peers, rejected by the three
  TypeScript-family peers whose hello schema requires it — with `400 connection_sequence_error`,
  i.e. **the exact status and code under measurement**. Those three would have been recorded as
  row-10 peers on the strength of a malformed control frame.

The pattern across all three: **a wrong probe fails in the direction of the answer you are
looking for.** Two of the three produced a plausible bare `400`, and the third invented a class.

## What this does and does not settle

It settles **what the cohort does**. It settles nothing about **what is correct** — §4.7
contradicts itself, and that is architecture's to rule on. Nothing here should be read as
advocating a reading.

Two things follow for whoever does rule:

- **The cheap-answer caveat above.** Cohort weight is 38–6 on the surface and much weaker once
  "did this peer decide anything?" is asked.
- **`entity-core-go` answers `409`** (per formalization's read of the ground-up tree), a status in
  neither clause. Note this is the *ground-up* `entity-core-go`, not the generated `go` peer in
  this cohort, which measures `401 invalid_nonce` — the two are different implementations and
  should not be conflated when counting.

## Reproducing

**The gate is the reproduction now.** `connect_prehello_authenticate` runs in every
`--profile core` census; there is nothing to drive separately:

```
tools/run-cohort-census.sh                       # the gated answer, all 46
```

The retired probe still runs, through the ordinary census route and **without touching the shared
validator**:

```
tools/run-cohort-census.sh --probe p47-probe             # all peers -> output/scratch/p47-probe/
tools/run-cohort-census.sh --probe p47-probe go swift    # named peers
```

~~`tools/p47-run.sh` installs the probe at the path every harness defaults to…~~ **Deleted
2026-09-09** — see the closing section at the top. The env-override route it was written to work
around was fixed at source on 2026-09-06, and the swap it used instead was a write over a binary
a sibling repo invokes by path.

**This probe was deliberately not in the conformance suite.** The correct answer was undecided,
so there was nothing to gate on. ~~If architecture rules, the ruling belongs in `validate-peer` as
a vector — at which point this probe should be deleted, not kept as a second source of truth.~~
**It ruled; the vector exists; the probe is retired on exactly those terms.**
