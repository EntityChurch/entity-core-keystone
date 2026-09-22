# protocol-generator/shared/spec-data/v0.8.2.25/

**Verbatim snapshot of the authoritative normative spec files** — byte-for-byte copies of `entity-core-protocol/specs/{ENTITY-CORE-PROTOCOL,ENTITY-CBOR-ENCODING,ENTITY-NATIVE-TYPE-SYSTEM}.md`, not paraphrased tables. The snapshot pins generation inputs to a spec version for reproducibility per `(spec-version, lang, profile)` (S8), so generators can be re-run + version-stamped as the spec moves.

- **Authoring authority:** architecture only. Operators do NOT write spec-data. This snapshot is a mechanical copy — no editorial content is ours.
- **No paraphrase:** spec-data MUST literal-quote the spec wording; paraphrase is a bug.
- **Immutable:** once stamped, a `<version>/` directory is never edited in place. Amendments get a new directory — which is what this one is.
- **Integrity:** see `MANIFEST.md` for the SHA-256 of each file. **The digests are the only anchor here** — this snapshot is vendored from an *unreleased* line (`0.8.2.25` is not on published `master`, which is still `0.8.2`), so there is no released artifact to check a filename or a tag against. The source commit is recorded as an internal build coordinate and is not citable in anything published.
- **Version:** Entity Core Protocol **0.8.2.25**. **The type system is BYTE-IDENTICAL to `v0.8.2.11`** (`043fc80d…` at both pins) — it has not moved in fourteen revisions. Read the digest, not the version string.
- **Directory is named `v0.8.2.25`, not `v0.8.3`** — the fourth component is an arch-managed in-flight signal that lets core text move without cutting a release; the operator strips it and names the number at the cut.
- **What's new vs v0.8.2.11:** fourteen amendments (`0.8.2.12`–`0.8.2.25`), **559 / 7 / 0** changed lines respectively. The headline for this cohort is **§4.11, the pre-admission refusal** — arch's `CQ-34`/`CQ-35` ruling, which folded `entity-system-conformance`'s 34-peer measurement and `entity-core-go`'s three-seat measurement into one invariant: a peer refusing a frame pre-admission MUST put a coded `EXECUTE_RESPONSE` on the wire, and **a silent drop and a bare close are DISTINCT non-conformances that must be scored separately.** The arc also carries the §5 scope-algebra revisions (`.16` typed `scope_subset`, `.20`/`.22` the never-match sentinel and its control-flow obligation, `.23`/`.24` the authority table and the pre-admission consolidation).
- **Conformance scaffolding + generator defaults** are in `GUIDE-CONFORMANCE.md` + the generator menu — **not in this snapshot**.
- **`EXTENSION-TREE.md` is deliberately NOT vendored** and is still load-bearing *by reference*: §6.3's ladder cites its Appendix A for the `put` error codes. Read it in the sibling.

**Targets:** all peers from here forward. Supersedes `v0.8.2.11`, `v0.8.2.3`, `v0.8.2` and `v0.8.0` for new work; all are kept in place as point-in-time pins.

> ⛔ **CONSUMED BEFORE IT WAS VENDORED — the inverse of every prior snapshot's caveat, and it is a
> defect rather than a milestone.** `v0.8.2.11` shipped with a "vendored, NOT yet consumed" note. This
> one is the other way round: **33 of 46 peers were taken to `0.8.2.25` across six sweep tranches on
> 2026-09-14/15, before this directory existed**, implemented from architecture's routed packets rather
> than from a pin in this tree. The rules are the landed rules and several were re-derived from the
> spec text during the sweep, so this is a **provenance** defect and not a known correctness one —
> but a packet is not a pin, and nobody can re-run a review round. **Owed: re-derive the sweep's rules
> against this text.** See `MANIFEST.md`.
>
> **The oracle re-pin is deliberately NOT landed with this vendor**, unchanged policy: the spec
> snapshot is what peers are **written against**, the oracle pin is what they are **measured
> against**, and nothing requires the two to move together. The pin remains `78db4a9`
> (executed set `7aa6f3de…`, 778 checks), and a known blocker is recorded in `AGENTS.md` — at the
> candidate oracle one skip counts as FAIL, which makes the documented entry point exit non-zero on a
> 0-FAIL peer, observed live on `io` on 2026-09-15.
