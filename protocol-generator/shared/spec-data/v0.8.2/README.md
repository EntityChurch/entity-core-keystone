# protocol-generator/shared/spec-data/v0.8.2/

**Verbatim snapshot of the authoritative normative spec files** — byte-for-byte copies of `entity-core-protocol/specs/{ENTITY-CORE-PROTOCOL,ENTITY-CBOR-ENCODING,ENTITY-NATIVE-TYPE-SYSTEM}.md`, not paraphrased tables. The snapshot pins generation inputs to a spec version for reproducibility per `(spec-version, lang, profile)` (S8), so generators can be re-run + version-stamped as the spec moves.

- **Authoring authority:** architecture only. Operators do NOT write spec-data. This snapshot was taken under explicit arch authorization (`ROUTING-2026-08-21-l` §1, re-verified by `-m` §1) and is a mechanical copy — no editorial content is ours.
- **No paraphrase:** spec-data MUST literal-quote the spec wording; paraphrase is a bug.
- **Immutable:** once stamped, a `<version>/` directory is never edited in place. Amendments get a new directory.
- **Integrity:** see `MANIFEST.md` for SHA-256 of each file + source-commit provenance (`entity-core-protocol` `106834c`, resolvable).
- **Version:** Entity Core Protocol **0.8.2**. CBOR stays **1.5** and the type system stays **4.2.1** — both version labels are unmoved from `v0.8.0`, though their bytes changed (29 / 40 lines).
- **Directory is named `v0.8.2`, not `v0.8.0.1`** — the fourth component is an arch-managed in-flight signal, stripped at release. `0.8.2` is the operator's release number.
- **What's new vs v0.8.0:** the 0.8.1 amendment set (F37 `system/peer-id`, F40 id-scope grammar, RT-6 401, continuation TTL 8×), the hash-width lock, §3.13 `reason`/`last_error`/`failing_since`, the CAP-1…CAP-7 capability cluster + CAP-6a ingest, the three-valued dispatch authority, and the version cut. 197 / 29 / 40 changed lines respectively — measured in this tree, matching arch's independent count.
- **Conformance scaffolding + generator defaults** (the §7a `system/validate/*` test-handlers, the §7b concurrency gate, the §4.10 `resource_bounds` probe, store concurrency-safety, the recommended bound defaults, TCP_NODELAY, no-blocking-syscall-on-cooperative-pool) are in `GUIDE-CONFORMANCE.md` + the generator menu — **not in this snapshot**. The guide is **now pinned by hash** in `MANIFEST.md`; it is `Status: Draft`, and a peer generated against it should say so.

**Targets:** all peers generated from here forward; new peers derive spec-first against this. Supersedes `v0.8.0` for new work.

> **Not yet consumed.** As of the release this snapshot was pinned for, **no peer has been regenerated against it** — the M1 re-run measured `v0.8.0`-generated peers against the `c1b0708` oracle. The one known consequence is `pd`'s F37 debt (`system/identity/peer-id` → `system/peer-id`, three files); `pd` is tier M3 and out of that release's scope. See `MANIFEST.md` "Status in this repo" and `CONFORMANCE-MATRIX.md`.
