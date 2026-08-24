# entity-core-keystone — status

_Updated: 2026-08-22 · oracle pin `entity-core-go @ c1b0708` · spec snapshot `v0.8.2`_

> **`CONFORMANCE-MATRIX.md` is authoritative for every per-peer number.** This file is a
> short orientation note, deliberately kept thin. When the two disagree, the matrix wins —
> a dated status narrative is exactly the artifact that goes stale first, and the previous
> revision of this file did (archived at
> `docs/archive/STATUS-2026-07-12-28-peer-cc1970f.md`, six weeks and three oracle re-pins
> behind, still advertising a "uniformly conformant" 28-peer cohort).

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

**46 peers in the tree · 45 measured · all 45 measured at one pin (`c1b0708`, 2026-08-21).**
Nothing is carried forward from an earlier pin.

| State | Count | Peers |
|---|---:|---|
| **0-FAIL** — publishable | **13** | `go` `haskell` `lean` `ocaml` `swift` (**M1**, 5/5) · `common-lisp` `csharp` `elixir` `java` `kotlin` `python` `rust` `typescript` (**M2**, 8/8) |
| CAP gap only (2F–4F) | 28 | the rest of the measured cohort |
| CAP gap + a standing defect | 1 | `cobol` (30F = 3 + its standing 27) |
| **INVALID MEASUREMENT** — not scores | 3 | `asm-x86_64` · `asm-arm64` · `riscv64` |
| Not measured | 1 | `apl` — upstream-blocked |

**The headline is one sentence:** `--profile core` gained three `capability` checks at this
pin, and every peer that has not been fixed fails exactly those. This is **one unimplemented
spec feature (§5.6's MIN_DEFINED mint ceiling) measured across the cohort, not dozens of
regressions.** The seven fixed peers show the fixed state and their diffs are the reference for
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
2. **Refresh the 13 publishable peers' `status/CONFORMANCE-REPORT.{md,json}`.** Found 2026-08-22:
   every tracked per-peer report is one pin behind (740-check set or older; none at 755), because the
   census deliberately never writes them and `output/` is gitignored. A **transparency** gap, not a
   conformance one — §1's numbers are census-backed and correct — but a fresh clone shows each peer's
   own report disagreeing with its row. Matrix §3.
3. **The asm/ISA trio's connection-pressure family** — its own session (§1a). Also what makes
   `tools/check-set-gate.py` exit non-zero cohort-wide today (42/45 comparable, by design).
4. **`cobol`'s standing 27-FAIL liveness cascade** — a separate investigation.
5. **Package-registry publish** and **Ed448/SHA-384 agility** stay demand-driven.

## Where the detail lives

| Question | Doc |
|---|---|
| Per-peer conformance, tiers, catch-up backlog | `CONFORMANCE-MATRIX.md` |
| What the substrates taught us | `research/SUBSTRATE-TAKEAWAYS.md` |
| Session records / handoffs | `research/stewardship/` |
| Oracle + spec pin provenance | `tools/oracle-pin.env` |
| Maintenance tier roster | `tools/peer-tiers.tsv` |
