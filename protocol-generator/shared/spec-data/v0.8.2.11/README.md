# protocol-generator/shared/spec-data/v0.8.2.11/

**Verbatim snapshot of the authoritative normative spec files** — byte-for-byte copies of `entity-core-protocol/specs/{ENTITY-CORE-PROTOCOL,ENTITY-CBOR-ENCODING,ENTITY-NATIVE-TYPE-SYSTEM}.md`, not paraphrased tables. The snapshot pins generation inputs to a spec version for reproducibility per `(spec-version, lang, profile)` (S8), so generators can be re-run + version-stamped as the spec moves.

- **Authoring authority:** architecture only. Operators do NOT write spec-data. This snapshot was taken under explicit arch authorization (`ROUTING-2026-09-06-d`, the CONSOLIDATED packet) and is a mechanical copy — no editorial content is ours.
- **No paraphrase:** spec-data MUST literal-quote the spec wording; paraphrase is a bug.
- **Immutable:** once stamped, a `<version>/` directory is never edited in place. Amendments get a new directory — which is what this one is.
- **Integrity:** see `MANIFEST.md` for the SHA-256 of each file. **The digests are the only anchor here** — this snapshot is vendored from an *unreleased* line (`0.8.2.11` is not on published `master`, which is still `0.8.2`), so there is no released artifact to check a filename or a tag against. The source commit is recorded as an internal build coordinate and is not citable in anything published.
- **Version:** Entity Core Protocol **0.8.2.11**, CBOR **1.6**. The type system stays **4.2.1** — label unmoved, bytes moved, and *its* change is a predicate for the protocol's newest rule. Read the digest, not the version string.
- **Directory is named `v0.8.2.11`, not `v0.8.3`** — the fourth component is an arch-managed in-flight signal that lets core text move without cutting a release; the operator strips it and names the number at the cut.
- **What's new vs v0.8.2.3:** **eight** amendments (`0.8.2.4`–`0.8.2.11`), 113 / 11 / 17 changed lines respectively. Seven are about what a peer **emits** — the §4.7 connect surface reconciled (FM-2), the pre-establishment EXECUTE, §3.3's default-code slots and their force, the 501/500 code sets, the half-open state, and entity fidelity raised SHOULD → MUST in its own canonical home. **The eighth is different in kind:** §6.3's `put` admission ladder is the **first ACCEPT-side rule of the arc**, and an accept-side rule partitions a cohort during adoption rather than merely diverging its error strings.
- **Conformance scaffolding + generator defaults** (the §7a `system/validate/*` test-handlers, the §7b concurrency gate, the §4.10 `resource_bounds` probe, store concurrency-safety, the recommended bound defaults, TCP_NODELAY, no-blocking-syscall-on-cooperative-pool) are in `GUIDE-CONFORMANCE.md` + the generator menu — **not in this snapshot**.
- **`EXTENSION-TREE.md` v4.5 is deliberately NOT vendored** and is still load-bearing *by reference*: §6.3's ladder cites its Appendix A for the `put` error codes. Read it in the sibling.

**Targets:** all peers from here forward. Supersedes `v0.8.2.3`, `v0.8.2` and `v0.8.0` for new work; all are kept in place as point-in-time pins.

> **Vendored, NOT yet consumed.** No peer has been regenerated against this snapshot; all 46 remain
> written against `v0.8.2.3` and measured at the `f313028` oracle. That is a tracked gap.
> **The oracle re-pin is deliberately held back from this vendor** — the spec snapshot is what the
> peers are written against, the oracle pin is what they are measured against, and nothing requires
> the two to land together. `entity-core-go` was actively editing the `put` surface on the day this
> was taken. See `MANIFEST.md` "Status in this repo".
