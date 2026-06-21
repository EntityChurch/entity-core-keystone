# entity-core-protocol-csharp — Phase S2 Summary

**Phase:** S2 — codec layer
**Outcome:** ✅ complete. Native codec, 69/69 byte-identical (`CONFORMANCE-REPORT.md`).

## What was built

The first generated peer's codec layer — the keystone's first real
`/entity-rosetta` run. Native C#, `System.Formats.Cbor` + NSec, no FFI on the
critical path.

```
protocol-generator/csharp/
├── EntityCore.Protocol.sln
├── .gitignore                                  (bin/obj; lockfiles committed)
├── src/EntityCore.Protocol/
│   ├── EntityCore.Protocol.csproj              (net9.0, nullable, warnings-as-errors, lockfile)
│   ├── EntityCoreException.cs                  (base; full hierarchy lands in S3)
│   ├── EntityCodecException.cs
│   └── Codec/
│       ├── EcfValue.cs                         (canonical value model, N4 PreEncoded carrier)
│       ├── CanonicalCbor.cs                    (encode via Ctap2 + hand-rolled shortest-float; strict decode)
│       ├── Leb128.cs                           (N1 varint)
│       ├── Base58.cs                           (Bitcoin alphabet, hand-rolled)
│       ├── PeerId.cs                           (parsed-components record)
│       └── EntityCodec.cs                      (public API: EncodeEntity, ContentHash, peer-id, Sign/Verify)
└── test/
    ├── EntityCore.Protocol.Conformance/        (console harness — prints the table, exit code = gate)
    └── EntityCore.Protocol.Tests/              (xUnit: corpus fact + 23 unit tests = the `dotnet test` gate)
```

## Key decisions (full detail in SPEC-AMBIGUITY-LOG.md)

1. **Architecture:** `CborWriter(Ctap2Canonical)` does structure / map-sort /
   minimal-ints / definite-lengths; **shortest-float hand-rolled** and spliced via
   `WriteEncodedValue` (the one thing no .NET conformance mode does — R1). Maximizes
   profile-mandated library use; confines the hand-roll to the unavoidable. (A-001)
2. **F4 closed empirically:** spiked `Ctap2Canonical` against the `map_keys`
   vectors *before* editing the profile (verify-then-edit, S6). It reproduces
   length-then-lex byte-for-byte. Profile `canonical_mode` `Strict` → `Ctap2Canonical`.
3. **NSec pin corrected** `23.4.0` (never released stable) → `25.4.0`. (A-002)
4. **Base58 hand-rolled**, closing the profile gap. (A-003)

## Standards honored

- **S1** containers: all builds/tests in `entity-core-keystone/dotnet9`; no host
  installs. Outputs (`bin/obj`) gitignored; lockfiles committed.
- **S2** spec-data read verbatim; not modified.
- **S5** no doctored oracles: the codec was fixed to the fixture, never the
  reverse. (It passed first try — no fixes needed.)
- **S6** profile decided libs; the two profile corrections are logged + escalated,
  not silent.
- **S7** lower bar met (byte-identical to fixture + FFI).
- **S8** convergence: 3rd independent impl to 69/69.
- **S11** all NuGet pins exact + ≥30 days old (NSec 25.4.0, System.Formats.Cbor
  9.0.0, libsodium 1.0.20.1, test SDK 17.11.1, xunit 2.9.0 / runner 2.8.2);
  lockfiles committed.

## Carried to S3 (peer)

- Flesh out the exception hierarchy (HelloFailed / Authentication / Transport / …
  per profile) — S2 shipped only the codec branch.
- R5 zero-hash sentinel decode (null/undefined/empty-bytes → zero-hash) — no S2
  vector exercised it; confirm against 7.56 text in the peer's hash-field decode.
- The codec exposes `EncodeEntity` / `ContentHash` / `Sign` / peer-id as the
  surface S3 builds connection / dispatch / capability validation on.

## Verify-peer note (S4, later)

S4 needs the live `validate-peer` oracle (`entity-core-go/cmd/validate-peer`)
built + a running C# peer to point it at. Not reachable until S3 produces a
peer. The codec gate (this phase) is fixture-based and needs no live oracle.
