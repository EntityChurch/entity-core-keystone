# entity-core-keystone — status

_Updated: 2026-08-29 · oracle pin: the 755-check set `95edd774…` · spec snapshot `v0.8.2`_

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

**46 peers in the tree · 45 measured · all 45 measured at one pin — the 755-check set
`95edd774…` (2026-08-21).** The pin is a content digest, not a commit; `CONFORMANCE-MATRIX.md`
§"The pin" carries the full anchor set and why. Nothing is carried forward from an earlier pin.

| State | Count | Peers |
|---|---:|---|
| **0-FAIL** — publishable | **39** | M1 5/5 · M2 8/8 · M3 12/13 · probe 13/18 · exploratory 1/2 |
| Standing defect + the CAP trio | 1 | `cobol` (30F = 3 + its standing 27) |
| CAP gap, propagation not reached | 2 | `wasm-wat` (2F) · `turbowarp` (3F, never gates) |
| **INVALID MEASUREMENT** — not scores | 3 | `asm-x86_64` · `asm-arm64` · `riscv64` |
| Not measured | 1 | `apl` — upstream-blocked |

**The headline is one sentence: the CAP propagation is complete, and what remains is six
separate problems rather than one.** `--profile core` gained three `capability` checks at the
2026-08-21 re-pin; every unfixed peer failed exactly those three, and that uniformity held all
the way through the cohort. None of the six peers still outstanding is failing on the mint
ceiling — say it that way, because "6 peers still fail" invites the reader to assume a shared
debt that is not there.

**The fix shape did not vary across thirty-six languages** — roughly 200 lines over five or six
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

**Publication rule is unchanged: "no green report → no publish."** Today that means those
thirty-nine peers, and only those. Per [ADR-0012] they are **cohort-consistent, not independent
convergence** — they share a generation lineage and, for the FFI-hybrid peers, one codec `.so`.

## What's next

1. **`wasm-wat` 2F** — diagnosed, not started. The mint is a literal call with hand-placed WAT
   memory offsets, so adding `expires_at` is an arity + data-segment edit rather than a code
   edit, and the §6.3 salvage wants a second decoder entry point in the same style.
2. **`turbowarp` 3F** — the block-interpreter probe. Never gates; the CAP trio in Scratch blocks.
3. **The asm/ISA trio's connection-pressure family** (§1a) — three ISAs of hand-written assembly,
   one failure family: children block forever in `read(2)` with no idle deadline and there is no
   §4.10(c) connection-admission cap. It is also why the cohort-wide mode of
   `tools/check-set-gate.py` exits non-zero: those runs starved, so they are quarantined rather
   than scored. (`--tracked`, the mode `make lint` runs, gates the publishable set and passes.)
4. **`cobol`'s standing 27-FAIL liveness cascade** — a separate investigation.
5. **`apl`** — upstream-blocked and unmeasured. GNU deleted the pinned 1.9 tarball when 2.0
   shipped; the toolchain bump is its own piece of work.
6. **Package-registry publish** and **Ed448/SHA-384 agility** stay demand-driven.

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
all 39 publishable peers carry a committed report at the pinned check set; the remaining 6 stay
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
