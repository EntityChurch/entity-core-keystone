# protocol-generator/shared/

**The language-agnostic inputs every peer is generated from.** Nothing here is language-specific (S4) — Go tags, C# attributes, Python decorators etc. live in each `protocol-generator/<lang>/`, never here.

If you came looking for "the spec" or "the test vectors," they are here. Exact paths below.

## The spec — `spec-data/<version>/`

**Current version: `v0.8.0` (V8).** A **verbatim, byte-for-byte, SHA-256-pinned** snapshot of the three authoritative normative specs, copied from the sibling `entity-core-architecture` repo. Architecture authors it; operators never edit it (S2). Each `<version>/` is immutable once stamped — amendments get a new sub-directory.

```
spec-data/v0.8.0/
├── ENTITY-CORE-PROTOCOL.md       ← the core protocol (was ENTITY-CORE-PROTOCOL-V7.md before V8)
├── ENTITY-CBOR-ENCODING.md       ← canonical CBOR / ECF wire format (Appendix E = codec contract)
├── ENTITY-NATIVE-TYPE-SYSTEM.md  ← native type system
├── MANIFEST.md                   ← SHA-256 of each file + source arch commit (provenance/integrity)
└── README.md                     ← what changed vs the prior snapshot, version notes, caveats
```

Source of truth: `entity-core-architecture/V8/entity-core-protocol/specs/`, pinned to the arch commit recorded in `MANIFEST.md`.

> **Not in the snapshot:** conformance *scaffolding* (the §7a `system/validate/*` handlers, §7b concurrency gate, §4.10 `resource_bounds` probe, recommended bound defaults) is **operator-carried** — it lives in arch's `GUIDE-CONFORMANCE.md` + the generator menu, not in these three files. See the snapshot `MANIFEST.md` for the full carve-out.

## The diagnostic / conformance vectors — `test-vectors/<corpus-name>/`

**A corpus is identified by its name, never by a version stamp** (`GUIDE-CONFORMANCE.md` §5.1, MUST).
One directory per corpus, named for what the corpus tests; artifacts carry no `-v1`; each corpus's
`CHANGELOG.md` *is* its version, because an integer in a filename only ever said "something moved"
and was never once incremented while the ECF corpus grew 69 → 71 vectors. A conformance citation
names `(spec-version, corpus-name, artifact sha256)`.

The `.diag` files are CBOR diagnostic notation (the human source-of-truth); the `.cbor` files are the
byte-pinned fixtures impls actually load.

```
test-vectors/
├── ecf-conformance/                   ← vendored, byte-identical to arch
│   ├── conformance-vectors.{cbor,diag}  ECF codec corpus (71 vectors: 66 encode + 5 reject)
│   └── CHANGELOG.md
├── crypto-agility/                    ← vendored, byte-identical to arch
│   ├── agility-vectors.{cbor,diag}      Ed448 / SHA-384 / key+hash matrix
│   ├── SEEDS.md                         seed-construction reference
│   ├── README.md                        vector inventory
│   └── CHANGELOG.md
└── type-registry/                     ← DERIVED here, not vendored
    ├── type-registry-vectors.{cbor,diag}  system/type/* render drift target (150 types)
    ├── type-registry-shapes.json          shape reference consumed by each peer's gen-typedefs
    └── CHANGELOG.md
```

**The third one is a different kind of thing and the distinction is load-bearing.** `ecf-conformance/`
and `crypto-agility/` are byte-identical copies of architecture's canonical fixtures — keystone does
**not** author canonical bytes (S5). `type-registry/` is **harvested** from the reference
implementation's registry: a drift/diff target a peer renders against, not a normative pin. It is
also harvested from a *full* peer, so it carries extension vocabularies a core peer must not publish
— the 53-name core-floor filter belongs in each peer's `tools/gen-typedefs.py`, never in the harvest.

## The rest of `shared/`

| Dir | What |
|---|---|
| `lifecycle/` | The S1–S5 phase prompt templates the `/entity-rosetta` skill loads (constants / per-phase layers). |
| `seed-policy/` | Keystone-owned identity→capability seed-policy convention (README + JSON schema + examples + CLI + generator template) — the §6.9a peer-authority bootstrap surface. |
| `tools/` | Shared cross-language tooling (e.g. `dump-type-registry/`). |

## Versioning

Spec-data and test-vectors are **co-versioned** with the spec and stamped immutably per `<version>/`. A new spec amendment lands as a new `<version>/` sub-directory; existing peers re-target on their next rebuild (no forced migration). The live spec version is also in the repo-root `VERSION` file and the top of the root `README.md`.
