# Spec findings — what implementing entity-core 46 times found wrong with entity-core

These are the conclusions of the builds. Every one was surfaced by generating a real,
conformance-measured peer onto a substrate that stressed some axis the last one didn't —
a bignum integer model, a single-threaded canvas, a language with no key derivation, a
query engine instead of a program — and then failing, or passing for the wrong reason.

**Generating peers is the means; spec refinement is the end.** This directory is the end.
`CONFORMANCE-MATRIX.md` reports how the cohort scored; these say what the scoring taught.

## How to read one

Each file is addressed **to architecture**, which is why most of them open
`# HANDOFF-TO-ARCH`. That heading is kept deliberately: it says who the document is for,
what it is asking, and that keystone does not get to change the spec — it can only find
things and route them. Every finding names its ask, and the register below carries the
disposition. **Only architecture closes a finding.**

The live register — status, ownership, and what actually happened to each ask — is
[`research/stewardship/SPEC-FINDINGS-LOG.md`](../../../research/stewardship/SPEC-FINDINGS-LOG.md).
It stays where it is on purpose: it is a working index that changes as dispositions
change, and the findings themselves do not.

## The findings

| Finding | What it says |
|---|---|
| [`F32-auth-class-status.md`](F32-auth-class-status.md) | §4.2/§4.4 body text contradicts §5.2a on auth-class status codes |
| [`F37-peer-id-naming-appendix-b.md`](F37-peer-id-naming-appendix-b.md) | The peer-identity type has two live names (`system/identity/peer-id` vs `system/peer-id`), and Appendix B is systemically stale against the primary definitions |
| [`F38-mint-timestamp-precision.md`](F38-mint-timestamp-precision.md) | Mint-timestamp precision is a **correctness** parameter on a content-addressed protocol: second-truncated `created_at` makes same-second re-mints hash-identical |
| [`F40-asymmetry-audit.md`](F40-asymmetry-audit.md) | The typed-scope asymmetry audit arch asked for, with vector input |
| [`authority-as-query.md`](authority-as-query.md) | **F40/F41** — §3.6 matching is *typed*, and the §5/§6.6 authority interior is a monotone deductive system, so fail-closed could be a structural invariant instead of prose |
| [`asm-018-signature-construction.md`](asm-018-signature-construction.md) | **F36** — two different constructions share the word "signature" (ECF-bytes vs `content_hash`), with no pointer between them |
| [`concurrency-latency-floor-and-cap-sig-coverage.md`](concurrency-latency-floor-and-cap-sig-coverage.md) | **F33/F34** — §6.11 T2.1 imports a de-facto absolute throughput floor into a spec that says it is not a performance bar; and no vector tampers a *capability* signature |
| [`wasm-dialer-parity-F35-and-execution-mode.md`](wasm-dialer-parity-F35-and-execution-mode.md) | **F35** — the §7a reentry-echo skips §5.2 entirely, so outbound authorization is untested |
| [`peers-grant-dimension-oracle-gap.md`](peers-grant-dimension-oracle-gap.md) | The §5.2 `peers` grant dimension had **zero** oracle coverage — a MUST-gate nothing checked |
| [`frame-only-multisig-cohort.md`](frame-only-multisig-cohort.md) | Frame-only §3.6 multisig in 4 of 5 peers — a rejection-only category let them all pass without implementing K-of-N |
| [`budget-exhaustion-reporting.md`](budget-exhaustion-reporting.md) | `validate-peer` reports "never ran" and "deliberately not run" identically in JSON, so a starved run reads as a clean one |
| [`v7-section-citation-drift.md`](v7-section-citation-drift.md) | A stale "V7 §6.6" citation in the reference oracle, wire-observable |
| [`0.8.1-ratify-preconditions.md`](0.8.1-ratify-preconditions.md) | The 0.8.1 behavioral delta, its ratify preconditions, and one normative overreach |
| [`AGGREGATE-F32-F41.md`](AGGREGATE-F32-F41.md) | Aggregate digest of the open spec surface, F32 through F41 |
| [`critical-review-outputs.md`](critical-review-outputs.md) | Net-new items from the red-team critical review of our own claims |
| [`convergence-and-substrate-review.md`](convergence-and-substrate-review.md) | The paradigm / cross-tradition convergence thread |
| [`unison-peer-findings.md`](unison-peer-findings.md) | Two spec findings + one oracle-fact correction from the Unison peer — including a runtime that ships sign/verify but no key derivation |
| [`P1-closed-and-the-public-ref-does-not-exist.md`](P1-closed-and-the-public-ref-does-not-exist.md) | Content-digest anchoring landed, and the oracle we measure on exists on no public branch under any name |
| [`repin-done-cap-vectors-caught-a-cohort-wide-gap.md`](repin-done-cap-vectors-caught-a-cohort-wide-gap.md) | Arch's new CAP vectors caught a gap in **every** peer, including a fail-open — §5.6's mint ceiling had never been implemented anywhere |

### Cohort measurements routed to arch

Full re-measurements of the cohort against a specific oracle, sent as evidence rather than
as an ask.

| | |
|---|---|
| [`af8a582-cohort-remeasurement.md`](af8a582-cohort-remeasurement.md) | The cohort at `entity-core-go` `af8a582` |
| [`fceb61f-cohort-remeasurement.md`](fceb61f-cohort-remeasurement.md) | The cohort at `entity-core-go` `fceb61f` |
| [`bucket-B-cohort-application.md`](bucket-B-cohort-application.md) | Bucket-B applied to the cohort: two findings that move the gate |
| [`cb5df2c-corroboration.md`](cb5df2c-corroboration.md) | Corroborating arch's `cb5df2c`, with one strengthening datum and one coordination question |

### Closed — [`archive/`](archive/)

Kept for provenance, each with a RESOLVED banner naming what closed it.

| | |
|---|---|
| [`archive/F29-corpus-coverage-gap.md`](archive/F29-corpus-coverage-gap.md) | The ECF corpus had no array-of-maps vector with a ≥24-byte inner string — so a codec could be 69/69-green carrying a latent encoder bug. Closed by arch adding `nested.5`/`nested.6`. |
| [`archive/F30-tag-reject-corpus.md`](archive/F30-tag-reject-corpus.md) | Four of five `tag_reject` vectors carried no CBOR tag at all — they rejected on trailing data, so the §6.3 tag scanner was effectively untested. Closed by arch regenerating them. |

## Why these live under `protocol-generator/shared/`

They sat in `research/stewardship/` until 2026-08-23 and were **not published** — the index
that names them shipped and the evidence behind it did not, which is close to the worst
arrangement available. Two mechanical walls made a simple re-declaration the wrong fix:
the release keep-list matches top-level prefixes, so anything under `research/` needs a
per-file entry forever, while `protocol-generator/**` publishes with none; and the tree
hygiene linter files any *dated-named* document as an ephemeral snapshot, which these were.

So they moved and lost their dates — the date is preserved in each document's own header,
where it belongs as provenance rather than as an identifier. They sit beside the generator
work that produced them.
