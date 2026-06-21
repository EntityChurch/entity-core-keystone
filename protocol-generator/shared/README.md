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

## The diagnostic / conformance vectors — `test-vectors/<version>/`

**Current version: `v0.8.0`.** Byte-identical copies of architecture's canonical golden-vector fixtures (keystone does **not** author canonical bytes — S5). CI hash-checks them against the tables in the `MANIFEST.md`. The `.diag` files are CBOR diagnostic notation (the human source-of-truth); the `.cbor` files are the byte-pinned fixtures.

```
test-vectors/v0.8.0/
├── conformance-vectors-v1.{cbor,diag}   ← ECF codec corpus (71 vectors: 64 encode + 5 reject + 2 meta)
├── agility-vectors-v1.{cbor,diag}       ← crypto-agility corpus (Ed448 / SHA-384 / key+hash matrix)
├── agility-SEEDS.md                     ← seed-construction reference for the agility corpus
├── type-registry-vectors-v1.{cbor,diag} ← system/type/* registry shapes
├── type-registry-shapes.json            ← type-registry shape reference
└── MANIFEST.md                          ← SHA-256 of every fixture + arch source commit + inventory
```

## The rest of `shared/`

| Dir | What |
|---|---|
| `lifecycle/` | The S1–S5 phase prompt templates the `/entity-rosetta` skill loads (constants / per-phase layers). |
| `seed-policy/` | Keystone-owned identity→capability seed-policy convention (README + JSON schema + examples + CLI + generator template) — the §6.9a peer-authority bootstrap surface. |
| `tools/` | Shared cross-language tooling (e.g. `dump-type-registry/`). |

## Versioning

Spec-data and test-vectors are **co-versioned** with the spec and stamped immutably per `<version>/`. A new spec amendment lands as a new `<version>/` sub-directory; existing peers re-target on their next rebuild (no forced migration). The live spec version is also in the repo-root `VERSION` file and the top of the root `README.md`.
