# Syntheses — the cross-cutting analysis, including the case against our own claims

Eight documents that sit above any single peer. Where
[`../findings/`](../findings/README.md) carries *what we found wrong with the spec*, these
carry *what the whole exercise means* — and, in the largest of them, *why you should not
believe us*.

They were written as a deliberate sequence over four days in July 2026, and they argue with
each other on purpose.

## Read in this order

| | |
|---|---|
| 1. [`synthesis-reconciliation.md`](synthesis-reconciliation.md) | **Start here — this is the front door.** The converged, honest view: the builder's retrospective and the adversarial review reconciled into one picture, with the disagreements named rather than smoothed. |
| 2. [`red-team-critical-review.md`](red-team-critical-review.md) | **The prosecution, 954 lines.** A five-dimension adversarial review of entity-core: spec minimality, security and design, the extension boundary, a full mine of all 427 `A-*` implementation entries, and compute as the central paradigm. Net result: **zero novel in-core defects**, one already-filed bug (F37) — which is a claim that only means anything because the document spends its length trying to find more. |
| 3. [`implementation-history-review.md`](implementation-history-review.md) | The fourth attack dimension, by paradigm — adversarial method, run against the build history rather than the spec. |
| 4. [`compute-paradigm-and-meta-review.md`](compute-paradigm-and-meta-review.md) | **The review of the review.** Third-order: takes the red team's treatment of compute apart, closes three lineage blind spots, and corrects two framing errors *this analysis itself* made on its first pass. |

## The convergence thread

Where entity-core sits relative to work that already exists — the check against inventing a
solved problem.

| | |
|---|---|
| [`convergence-map.md`](convergence-map.md) | Seven research traditions across six entity subsystems, each run through the same comparison. |
| [`convergence-synthesis.md`](convergence-synthesis.md) | The capstone: the map turned into decision-grade takeaways for architecture, with the divergence analysis — where we are *not* the same as the thing we resemble. |
| [`substrate-theory-alignment.md`](substrate-theory-alignment.md) | The keystone survey aligned against an academic six-primitive substrate analysis (`{E,I,T,M,X,P}`), in that team's own terminology. Records agreement *and* mismatch. |
| [`substrate-minimality-and-the-machine-boundary.md`](substrate-minimality-and-the-machine-boundary.md) | How much substrate the system actually needs — the interface between entity computation and the physical host, prompted by an observed host failure. |

## Why these are here and not under `research/`

Same reason as the findings, and the same mechanism. The release keep-list drops undeclared
**prose** under a doc-root prefix, and `research/` is such a prefix — so a dated filename under
it strips, however durable the document. These eight were doing exactly that: stripping at
release while three of them were cited from the published surface, including from a published
finding.

Moving them out, under undated names, is the fix that needs no keep-list entry and no
maintenance. Each document's date is in its own `**Date:**` header, which is where a date
belongs — provenance, not an identifier.

They are a **point-in-time analysis** and are not revised as the cohort moves; the current
per-peer numbers are in [`CONFORMANCE-MATRIX.md`](../../../CONFORMANCE-MATRIX.md), which is
authoritative and wins on any disagreement.
