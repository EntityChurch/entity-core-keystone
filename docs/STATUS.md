# entity-core-keystone — status

_Updated: 2026-08-30 · oracle pin: the 755-check set `95edd774…` · spec snapshot `v0.8.2`_

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

**46 peers in the tree · 46 measured · all 46 at one pin — the 755-check set
`95edd774…` (2026-08-21).** The pin is a content digest, not a commit; `CONFORMANCE-MATRIX.md`
§"The pin" carries the full anchor set and why. Nothing is carried forward from an earlier pin.

| State | Count | Peers |
|---|---:|---|
| **0-FAIL** — publishable | **46** | M1 5/5 · M2 8/8 · M3 13/13 · probe 18/18 · exploratory 2/2 |
| Not measured | 0 | — |

**The headline is one sentence: every peer in the cohort is at 0-FAIL, with no exclusions and no
unmeasured row.** `--profile core` gained three `capability` checks
at the 2026-08-21 re-pin; every unfixed peer failed exactly those three, and that uniformity
held all the way through the cohort.

**Read the 46 as a statement about the wire, not about the peers.** They share a generation
lineage and pass one author's vectors at one pinned check set: **cohort-consistent, not
independent convergence**. Three of the four defects closed on 2026-08-30 had been *passing*
checks for months for reasons unrelated to what those checks test — and one of the four peers
was quarantined that whole time under a diagnosis that turned out to be wrong. Two rows carry a
disclosed gap behind a green verdict (the ISA trio's type-registry over-publication; `cobol`'s
two unreachable concurrency payloads); both are named in `CONFORMANCE-MATRIX.md` §1a and its
footnotes rather than left to be discovered.

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

**Publication rule is unchanged: "no green report → no publish."** Today it withholds nothing —
all forty-six peers have a green report. Per [ADR-0012] they are **cohort-consistent, not independent
convergence** — they share a generation lineage and, for the FFI-hybrid peers, one codec `.so`.

## What's next

1. **`authz_peers_target_from_uri`** — WARNs on 39 of 46 peers, and the "inconclusive by design,
   needs a two-peer harness" label it carried since 2026-08-16 is **withdrawn**. Six peers PASS it
   with a real three-row verdict, so a standalone peer can decide it; `go` WARNs because all three
   rows return `404 handler_not_found` — unrouted, not undecidable. Read a PASS peer against `go`
   and find out whether the 39 share one defect.
2. **The ISA trio's type-registry over-publication** (`CONFORMANCE-MATRIX.md` §1a.4). `typestore.s`
   publishes ~200 entries including whole standard-extension vocabularies, which the oracle scores
   *matched-if-present* — so 283 `type_system` checks that WARN for every other peer PASS for these
   three. That is the whole reason they read `594-595P/53-55W` against the cohort-standard
   `312P/337W`. **Their reaching 0-FAIL did not retire this**; if anything it makes it easier to
   miss, because no FAIL count draws the eye there any more.
3. **Port `asm-x86_64`'s four `host.s` hardenings to `asm-arm64` and `riscv64`** — the inherited
   listen fd, the idle read deadline, the §4.10(c) admission bound and the §4.10(a) oversize path.
   Worth doing for ISA parity, but **not** because those two rows are behind the cohort: measured
   2026-08-30, `r3_connection_flood` WARNs on **44 of 46 peers** and only `asm-x86_64` and `pd`
   self-bound admission. §4.10(c) is a SHOULD that most peers delegate to the supervisor, so this
   never gates — and describing it as something two ISA peers owe a third had it backwards.
4. **`cobol`'s 8192-byte per-entity ceiling**, if a peer that can hold larger entities is wanted.
   Two concurrency probes stage 256 KiB and 16 KiB payloads; the first cannot fit its 65535-byte
   frame cap at all, and the second is refused with `413`. Raising the ceiling means raising every
   reader's buffer in lockstep — the store hands `lk-len` bytes back to a caller's fixed buffer —
   and missing one reintroduces exactly the overflow class that was just closed.
5. **Regenerate the cohort against the `v0.8.2` spec snapshot.** Every peer in the tree was
   generated against `v0.8.0`; the snapshot has been pinned since 2026-08-21 and no peer has moved
   to it. Tracked, not overlooked.
6. **Package-registry publish** and **Ed448/SHA-384 agility** stay demand-driven.

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
representability and §3.6 K-of-N all landed together; the row is now the cohort-standard
312P/337W/0F/106S. Two of the mistakes along the way were found only by measuring: framing the
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
| Per-peer conformance, tiers, catch-up backlog | `CONFORMANCE-MATRIX.md` |
| What the substrates taught us | `research/SUBSTRATE-TAKEAWAYS.md` |
| What 46 implementations found wrong with the spec | `protocol-generator/shared/findings/` |
| Session records / in-flight escalations | `research/stewardship/`, `docs/status/` |
| Oracle + spec pin provenance | `tools/oracle-pin.env` |
| Maintenance tier roster | `tools/peer-tiers.tsv` |
