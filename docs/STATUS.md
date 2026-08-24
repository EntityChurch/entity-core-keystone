# entity-core-keystone — status

_Updated: 2026-08-23 · oracle pin: the 755-check set `95edd774…` · spec snapshot `v0.8.2`_

> **`CONFORMANCE-MATRIX.md` is authoritative for every per-peer number.** This file is a
> short orientation note, deliberately kept thin. When the two disagree, the matrix wins —
> a dated status narrative is exactly the artifact that goes stale first, and the previous
> revision of this file did — it sat six weeks and three oracle re-pins behind, still
> advertising a "uniformly conformant" 28-peer cohort. It is archived internally rather than
> corrected, because a status snapshot that gets back-edited stops being evidence of anything.

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
§“The pin” carries the full anchor set and why.
Nothing is carried forward from an earlier pin.

| State | Count | Peers |
|---|---:|---|
| **0-FAIL** — publishable | **13** | `go` `haskell` `lean` `ocaml` `swift` (**M1**, 5/5) · `common-lisp` `csharp` `elixir` `java` `kotlin` `python` `rust` `typescript` (**M2**, 8/8) |
| CAP gap only (2F–4F) | 28 | the rest of the measured cohort |
| CAP gap + a standing defect | 1 | `cobol` (30F = 3 + its standing 27) |
| **INVALID MEASUREMENT** — not scores | 3 | `asm-x86_64` · `asm-arm64` · `riscv64` |
| Not measured | 1 | `apl` — upstream-blocked |

The CAP-gap row splits 23 at 3F · 2 at 2F · 3 at 4F (`forth` `nim` `smalltalk`, one further
`capability` check each). `CONFORMANCE-MATRIX.md` §1 is the row-by-row source.

**The headline is one sentence:** `--profile core` gained three `capability` checks at this
pin, and every peer that has not been fixed fails exactly those. This is **one unimplemented
spec feature (§5.6's MIN_DEFINED mint ceiling) measured across the cohort, not dozens of
regressions.** The thirteen fixed peers show the fixed state and their diffs are the reference for
the rest (`CONFORMANCE-MATRIX.md` §3).

**Recent work (2026-08-22) — tiers M1 and M2 are both complete.** `typescript` went 84F → 0F and
`csharp` went from an unscoreable starved run to `755 · 0F` in 7.2 s (from 18 m 20 s) — both were the
*same* defect, §6.3's missing `400 non_canonical_ecf` rejection status, in its two presentations
(§1b/§1c). The remaining six M2 peers — `rust` `python` `java` `kotlin` `elixir` `common-lisp` —
then took the same CAP fix and all landed 0F. Eight languages, one fix shape, no new defect classes:
that repetition is itself the evidence the spec reading is right.

**Publication rule is unchanged: "no green report → no publish."** Today that means those thirteen
peers, and only those.

Per [ADR-0012] these peers are **cohort-consistent, not independent convergence** — they
share a generation lineage and, for the FFI-hybrid peers, one codec `.so`.

## What's next

1. **Propagate the CAP fix to the remaining 32 peers** (tier M3, the probes, `node-red`/wasm).
   Rules and thirteen reference commits are in `CONFORMANCE-MATRIX.md` §3; the fix shape is uniform
   (~200 lines over 5–6 files) and has now held across **thirteen** languages unchanged.
2. **The asm/ISA trio's connection-pressure family** — its own session (§1a). It is also why the
   cohort-wide mode of `tools/check-set-gate.py` exits non-zero: their runs starved, so they are
   not comparable and are quarantined rather than scored. (`--tracked`, the mode `make lint` runs,
   gates only the publishable set and passes.)
3. **`cobol`'s standing 27-FAIL liveness cascade** — a separate investigation.
4. **Package-registry publish** and **Ed448/SHA-384 agility** stay demand-driven.

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
published number exactly) and `make lint` now runs `check-set-gate.py --tracked`. The 32 unfixed
peers' reports stay behind by design — they owe the *fix*, not the paperwork.

## Where the detail lives

| Question | Doc |
|---|---|
| Per-peer conformance, tiers, catch-up backlog | `CONFORMANCE-MATRIX.md` |
| What the substrates taught us | `research/SUBSTRATE-TAKEAWAYS.md` |
| What 46 implementations found wrong with the spec | `protocol-generator/shared/findings/` |
| Session records / in-flight escalations | `research/stewardship/`, `docs/status/` |
| Oracle + spec pin provenance | `tools/oracle-pin.env` |
| Maintenance tier roster | `tools/peer-tiers.tsv` |
