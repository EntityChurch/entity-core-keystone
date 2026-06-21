# protocol-generator/shared/spec-data/v0.8.0/

**Verbatim snapshot of the authoritative normative spec files** — byte-for-byte copies of `entity-core-architecture/V8/entity-core-protocol/specs/{ENTITY-CORE-PROTOCOL,ENTITY-CBOR-ENCODING,ENTITY-NATIVE-TYPE-SYSTEM}.md`, not paraphrased tables. The snapshot pins generation inputs to a spec version for reproducibility per `(spec-version, lang, profile)` (S8), so generators can be re-run + version-stamped as the spec moves.

- **Authoring authority:** architecture only. Operators do NOT write spec-data.
- **No paraphrase:** spec-data MUST literal-quote the spec wording; paraphrase is a bug.
- **Integrity:** see `MANIFEST.md` for SHA-256 of each file + source-commit provenance.
- **Version:** Entity Core Protocol **0.8.0** (V8). The prior line was 0.7.77 (V7). The V8 cutover is the version stamp; the folded V7-line increments (0.7.76 verdict-determinism, 0.7.77 naming normalization) are recorded under their V7 labels in the spec's change history.
- **⚠ File renamed:** the core protocol spec is now `ENTITY-CORE-PROTOCOL.md` (de-versioned). It was `ENTITY-CORE-PROTOCOL-V7.md` in v7.75 and earlier. Tooling that opens the file by basename updates it when re-targeting this snapshot.
- **What's new vs v7.75:** 0.7.76 (capability-verdict timestamp sampled once per verdict — §5.10 Layer-1 input) + 0.7.77 (identifier-naming normalization — kebab namespaces / snake data-keys; mostly extension-side type-paths; **core wire byte-unchanged**) + the V8 cutover (version 0.8.0) + release-prep (file rename, cross-ref normalization to `.md`, and stripping of dev-process dates + unpublished-doc references so the published specs read clean). CBOR (1.5) + type-system (4.2.1) normative content is unchanged since v7.75; only their cross-refs/dates changed.
- **Source tree changed:** this snapshot is vendored from the **V8 published surface** (`V8/entity-core-protocol/specs/`), not the legacy `docs/architecture/v7.0-core-revision/...` tree that fed v7.75 and earlier.
- **CBOR conformance fixtures** live in `test-vectors/` (siblings, not nested here); the normative codec contract is `ENTITY-CBOR-ENCODING.md` Appendix E.
- **Conformance scaffolding + generator defaults** (the §7a `system/validate/*` test-handlers, the §7b concurrency gate, the §4.10 `resource_bounds` probe, store concurrency-safety, the recommended bound defaults, TCP_NODELAY, no-blocking-syscall-on-cooperative-pool) are in `GUIDE-CONFORMANCE.md` + the generator menu — **not in this snapshot**.

**Targets:** all peers after the V8 release cutover; new peers derive spec-first against this. Supersedes v7.75 for new work. Existing peers re-target on next rebuild (no forced migration).
