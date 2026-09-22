# `arc-probe` — the `0.8.2.12 → 0.8.2.23` wire census · **Kind A (probe)**

## Status: ACTIVE

Kind and obligations: `docs/VERIFICATION-ARCHITECTURE.md`. A probe measures; it does not judge, it
does not gate, and it never appears in a published conformance number. It always exits 0.

## The surface

Twelve spec revisions landed against a cohort pinned at spec snapshot `v0.8.2.11`, almost all of
them in the §5 scope algebra and its consumers, and none had been measured. This is the instrument
that measures them. Six families, each chosen because it is (a) a behaviour a revision in this arc
introduced or changed, (b) reachable from a core peer's wire surface, and (c) separable from its
neighbours by a control.

| family | surface | revision |
|---|---|---|
| **A** | §3.3 / §5.4 effective-targets ladder | 0.8.2.20, 0.8.2.21 |
| **B** | §1.8 / §3.1 resolution integrity (the `included`-key forgery) | 0.8.2.23 |
| **C** | §5.2 / §5.6 scope typing supplied by the call site | 0.8.2.22 |
| **E** | §5.2 grant `exclude` — the unmatchable sentinel, and whether excludes are read at all | 0.8.2.21 |
| **F** | §1.4 / §5.2 Dimension 4 `peers`, **inbound half only** | 0.8.2.2 |
| **G** | §6.3 `check_path_permission` + the listing filter | 0.8.2.20/.21/.22 |

**F and G exist because of the cell census and they are its falsifier.**
`protocol-generator/shared/findings/scope-algebra-cell-census.md` enumerates the algebra as 146
decision cells with 37 vectors and names four structural zeros, then predicts in writing that the
next finding lands in L2, `peers`, or an exclude arm. Those two families drive the two zeros that
nothing had ever driven. Result: **`peers` largely clean (F85), `check_path_permission` the largest
finding of the arc (F84)** — three of four zeros yielded, which is recorded as a partial
falsification rather than a clean sweep.

## Controls — the reason any of this is publishable

Every family has a **positive control**, and the families whose finding is an ACCEPTANCE (B, E)
also carry an **antecedent**: an input that MUST be refused for a reason other than the one under
test. Without it a refusal in the measurement arm is unfalsifiable, which is the objection this
seat filed against another repo's deny-only check and then had to answer for its own (F70).

A family whose control failed is **VOID**, not "owed" — unmeasured is its own state, and folding it
into a defect count would make a peer whose control failed look like a peer with a bug. Voiding
happens over the assembled report rather than in the per-row grader, because **a row cannot see its
siblings**: five peers refuse every `system/capability:request`, so their 403 on a mistyped-scope
row would otherwise read as the only peers in the cohort enforcing the clause.

Two control lessons are baked in and are worth reading before adding a family:

- **A sentinel-shaped check needs a matchable-value control beside it.** `E1`'s exclude is
  UNMATCHABLE, so a peer that never reads grant excludes answers it exactly as one that reads them
  and finds the sentinel carves out nothing. `E2` excludes the very target requested. That control
  is what found **F83**.
- **An antecedent must establish the FIELD, not the status.** `G1` proves the narrow capability
  genuinely refuses `qB`; without it, a 200 in `G2` is equally explained by a grant wider than we
  think.

## Running it

```
tools/build-probes.sh arc-probe          # build into output/s4-oracles/
tools/arc-probe/run.sh python            # one peer
tools/arc-probe/run.sh go java sql       # several
tools/arc-probe/run-mint-floor.sh sql    # the peers that refuse `request` under the §6.9a floor
```

**The launch configuration is part of the measurement and there are two of them.** `run.sh` takes
the peer's OWN harness and removes exactly `--debug-open-grants` and nothing else: under the
degenerate `default → *` seed policy nothing is outside the caller's grant, so an authorization
probe has nothing to measure. `run-mint-floor.sh` keeps the flag, for the eight peers that refuse
`system/capability:request` under the discovery floor — its header states which families may be
read out of it (**E, F and G**, whose subject is a capability the probe MINTS) and **which row
changes meaning** (`F2` is refused at MINT under the floor and on USE under open grants; two
different gates, graded separately, never pooled).

Reports land in `output/scratch/arc/` and `output/scratch/arc-mint-floor/` (gitignored).

## Reading a report — three rules

1. **`trusted: false` suppresses everything.** It means the probe could not complete an ordinary
   in-grant request, so every row is a probe-side fault and not a reading about the peer.
2. **Never read the directory as a cohort picture without checking the reports are from one run.**
   Classify by ARTIFACT — does the report contain the families you are counting — not by mtime. A
   roster run that dies partway leaves the previous run's files in place, well-formed, carrying no
   run identity. That happened while building family F and the content check is what caught it.
3. **`not_driven` is published in every report and is part of the result.** A count with no stated
   surface grows while its coverage does not. Notably NOT driven: §6.8's handler/caller authority
   intersection, PD-2's outbound sub-dispatch (so **a green family F is not a green `peers`
   dimension**), and `turbowarp`, which no family reaches.

## Retirement condition

Stated so it is not left to judgement: **a family retires when the oracle ships a vector on its
surface.** The findings this probe produced (F78–F85) each ask for exactly that, and `F73` asks for
the cell table to become the shared artifact that decides when a fold is done. When
`check_path_permission` and Dimension 4 carry checks in the executed set, families F and G have
nothing left to say and should be deleted rather than kept as a second source of truth.
