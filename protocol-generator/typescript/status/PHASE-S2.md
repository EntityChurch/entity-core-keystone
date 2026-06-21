# entity-core-protocol-typescript — Phase S2 Summary

**Phase:** S2 — codec layer
**Outcome:** ✅ complete. Native codec, **69/69 byte-identical** first run (`CONFORMANCE-REPORT.md`).

## What was built

Peer #2's codec layer — and **the first peer with no native sibling reference**
(pure V7 spec → peer in an ecosystem with no prior Entity Core impl; the real S8
test). Browser-portable: the codec core imports nothing from `node:*` and pulls
nothing at runtime; only crypto pulls `@noble`.

```
protocol-generator/typescript/
├── package.json                    (ESM, "type":"module"; runtime deps = @noble ×2 only)
├── tsconfig.json                   (strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes + noImplicitOverride)
├── package-lock.json               (COMMITTED; npm ci authoritative — S11)
├── .gitignore                      (node_modules, dist)
├── src/
│   ├── errors.ts                   (EntityCoreError ⊃ EntityCodecError; protocol/transport branch → S3)
│   ├── index.ts                    (top-level barrel: codec + crypto)
│   ├── codec/                      ← PURE-JS, BROWSER-SAFE, ZERO node:* imports
│   │   ├── bytes.ts                (ByteWriter, hex, concat — Uint8Array everywhere, no Buffer)
│   │   ├── ecf-value.ts            (value model: bigint ints, Uint8Array, PreEncoded N4 splice)
│   │   ├── float.ts                (shortest-float Rule 4/4a; hand-rolled half-precision)
│   │   ├── canonical-cbor.ts       (hand-rolled canonical encode + strict decode)
│   │   ├── leb128.ts               (N1 varint, bigint-backed)
│   │   ├── base58.ts               (Bitcoin alphabet, hand-rolled)
│   │   ├── peer-id.ts              (format/parse)
│   │   ├── entity-codec.ts         (encodeEntity, contentHash, sign/verify, peer-id)
│   │   └── index.ts
│   └── crypto/                     ← the pluggable agility seam (IKeyAlgorithm analogue)
│       ├── provider.ts             (CryptoProvider / SignatureScheme / HashFunction interfaces)
│       ├── noble-provider.ts       (@noble default; Ed25519+Ed448 from one pkg; SHA-2)
│       └── index.ts                (defaultProvider + keyType/hashFormat registries)
└── test/
    ├── corpus.ts                   (locate + load the vendored fixture)
    ├── conformance-runner.ts       (category-branching harness, twin of C# ConformanceRunner)
    ├── run-conformance.ts          (standalone — prints the table, exit code = gate)
    ├── conformance.test.ts         (the S2 gate in node:test form)
    ├── f7-vectors.test.ts          (our own >i64max boundary vectors — the oracle can't see them)
    ├── codec-unit.test.ts          (N1–N3 / R3 / R4 / R5 unit surfaces)
    └── cborg-crosscheck.test.ts    (the A-005 spike: independent encoder corroboration)
```

`node --test` → **54 tests green** (corpus gate + F7 + units + cborg cross-check).

## Key decisions (full detail in SPEC-AMBIGUITY-LOG.md)

1. **Hand-rolled canonical CBOR core; cborg → dev cross-check (A-005).** The spike
   proved cborg agrees on structure/sort/minimal-int/bigint but structurally
   cannot encode integral-valued floats (JS `number` ambiguity). The value model
   must carry an explicit float node regardless; given that, the hand-roll is the
   byte-perfect, zero-runtime-dep, browser-portable path. **Runtime tree is now 2
   packages (both @noble, crypto only) — leaner than the S1 eval's projected 3.**
2. **`bigint` end-to-end (R1).** The integer surface never touches `number`. F7
   boundary vectors authored here (`2⁶³` past i64::MAX) — the oracle can't see
   that range; this is TS's single most important self-authored test surface.
3. **N4 verbatim splice.** Entity `data` rides through a `preEncoded` value node —
   never decode→re-encode on the hash path.
4. **R3 decode-side float minimality.** The strict decoder re-encodes each decoded
   float and rejects any non-shortest / non-canonical-NaN form (`400 non_canonical`).
5. **Crypto behind a pluggable provider seam.** `@noble` default (browser-safe);
   Ed448 + SHA-384/512 are registry entries in the SAME `@noble/curves`/`hashes`
   packages; `node:crypto` documented as the Node-only alt behind the same seam.
6. **Node 24 via SHA-256-pinned official tarball.** fedora:43 ships Node 22, not
   24 — took the Containerfile's documented fallback; pinned 24.15.0 (≥30d). (A-004)

## Standards honored

- **S1** containers: all builds/tests in `entity-core-keystone/node24`; pull-once
  then **`--network=none`** sealed-offline (the user's hard requirement). No host
  installs; `node_modules`/`dist` gitignored; lockfile committed.
- **S2** spec-data read verbatim (v7.72); not modified.
- **S5/no-doctoring**: the codec was authored spec-first and passed the fixture
  first try — no fixture ever touched.
- **S6** profile decided libs; the one deviation (cborg → hand-roll, A-005) is
  logged + escalated, not silent.
- **S7** lower bar met (69/69 byte-identical to the cross-blessed fixture).
- **S8** convergence: 4th independent impl to 69/69, first with no native sibling.
- **S11** all pins exact + ≥30 days old; lockfile committed; offline-sealed builds.

## Carried to S3 (peer)

- Flesh out the exception hierarchy (HelloFailed / Authentication / Transport /
  the `ProtocolErrorError`-stutter rename A-003) — S2 shipped only the codec branch.
- The **transport seam**: `src/transport/` behind a `Transport` interface, Node
  `node:net` impl now; browser (WebSocket / in-memory) added later without
  touching codec/peer. The codec core is already cleanly separable.
- The hash-format / key-type registries (`crypto/index`) are the agility dispatch
  point the entity layer (S3) builds `content_hash_format` / `key_type` handling on.
- R5 zero-hash sentinel decode (null/undefined/empty-bytes → zero-hash) at the
  entity hash-field layer — no S2 vector exercised it; confirm against v7.72 text.
- The codec exposes `encodeEntity` / `contentHash` / `sign` / `verify` / peer-id
  as the surface S3 builds connection / dispatch / capability validation on.
