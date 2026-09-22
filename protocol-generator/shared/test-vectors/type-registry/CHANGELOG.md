# Type-Registry Render Corpus — Changelog

**This file is the corpus's version.** The directory is named for what the corpus tests and the
artifacts carry no version stamp; what changed, when, why, and who re-blessed it lives here instead.

A citation names `(oracle pin, corpus-name, artifact sha256)`. The sha is the exact identifier;
this file is the narrative behind it.

---

## What this corpus is, and what it is NOT

**It is not an arch-authored canonical corpus, and the distinction is load-bearing.** The two
sibling corpora here — `ecf-conformance/` and `crypto-agility/` — are vendored byte-identical from
`entity-core-protocol`, which authors them. This one is **derived**: it is harvested from
`entity-core-go`'s `types.RegisterCoreTypes` plus the connect/tree handler types, i.e. the same
registry `validate-peer`'s `runTypeSystem` walks.

Its role is a **drift/diff target**, not a normative pin. A peer renders its own
`system/type/<name>` entities natively from its own data model and diffs each `content_hash`
against this set. That is the standing cohort rule — *render natively, don't ingest bytes* — and
this corpus exists to give the render something to be wrong against.

**Consequence for regeneration:** when the oracle re-pins, this corpus can go stale without
anything failing, because it is an input to code generation rather than a gate on it. Regenerate
from the Go oracle when `entity-core-go` moves; `protocol-generator/shared/tools/dump-type-registry/`
is the harvester.

**Consequence for scope:** the harvest is taken from a **full** peer, so it carries 150 types
including standard-extension vocabularies. A core peer publishes the 53-name core floor and no
more. **The scope filter belongs in each peer's `tools/gen-typedefs.py`, not in this harvest** —
the harvest is evidence of what the reference peer serves, and pruning it destroys that. See
`AGENTS.md` on the type-registry over-publication finding for why that filter is a keep-list and
never a drop-list.

---

## 2026-09-02 — de-versioned

**No vector value changed and the normative artifact did not move.**

| Artifact | sha256 | Note |
|---|---|---|
| `type-registry-vectors.cbor` | `7ae1021d0e58b704a2528ff346f09c6fd037f01766b73286b99f1ca56d9c6d48` | **Unchanged.** Measured on both sides of the rename; identical. **This is the number to cite** |
| `type-registry-vectors.diag` | `1b0ddf3a91cdeec3e085da195497904c32d775d49201940dbaf13ff09883a880` | was `2737f0259e8f775097e7b8809ea477808368bdb786f6f770c958bcc0101dbf28` — **two comment lines**, see below |
| `type-registry-shapes.json` | `15cc691705373e63198b4f6fd6a72d27ae46339f21ea67e35987c483ca481b29` | **Unchanged.** |

**150 types, unchanged.**

Renamed out of `test-vectors/v0.8.0/`, where it had been sitting undeclared: the directory's
`MANIFEST.md` documented the ECF and crypto-agility corpora and **never mentioned these three
files at all**. `GUIDE-CONFORMANCE.md` §5.1 (MUST, revised 2026-08-22) forbids a spec-revision
stamp or an artifact version in a corpus directory or artifact name; `v0.8.0/type-registry-vectors-v1`
carried both. The stem now names the same subject as its directory, as §5.1 requires.

The `.diag` moved because two lines of its header comment carried the old name — the title's
`— v1` and a self-reference to `type-registry-vectors-v1.cbor`. Both edits sit inside the file's
opening `/ … /` span; no `name`, `tree_path`, `content_hash` or `h'…'` value moved, and the
`.cbor` digest confirms the encoding did not change.

**Verified by decode, not by sha** (`GUIDE-CONFORMANCE.md` §3 rule 6): the `.cbor` parses to
exactly 150 entries with no trailing data, the name sequence is identical and identically ordered
to the `.diag`'s, `type-registry-shapes.json` holds the same 150 shapes, every `content_hash` is a
well-formed `ecf-sha256:` + 64 hex, and no field carries a `TBD`/`PENDING` placeholder.
