# Profile Rationale — TypeScript / Node.js (peer #2)

**Companion to:** `profile.toml`, `research/evaluations/typescript.md`

Audit trail for *why* each major choice in `profile.toml` was made. One paragraph per choice. The eval has the full risk analysis + sources; this is the decision record.

## Codec strategy: native, no FFI
JS has a mature deterministic CBOR library (`cborg`) and a pure-JS crypto family (`@noble/curves` + `@noble/hashes`) that spans Ed25519 + Ed448 + SHA-2 — both halves of the codec credible natively and **browser-portable** — so FFI is off the critical path. The FFI codec remains a byte-identity cross-check only. Matches the LANDSCAPE T1 "native" assignment.

## CBOR: `cborg` 5.1.1
Chosen over `cbor-x` and `microcbor` because cborg is **deterministic-first and strict-first** — exactly ECF's posture. Its defaults are unusually favorable: map keys sort **length-first then bytewise** (the CTAP2/ECF rule — better than C#'s `Strict` which didn't sort at all), smallest-float on encode, and **tags rejected by default** (conformance-invariant N2 nearly for free, where C# needed a hand-written recursive scanner). Zero transitive dependencies, Uint8Array-native, v5.1.1 clears the S11 30-day floor (~44 days). The residual canonical work — decode-side float-minimality, the BigInt integer surface, raw-byte fidelity — is ours regardless, per the S1 reality-check that *no* CBOR library gives ECF canonicality for free (true of ciborium, System.Formats.Cbor, cbor2 alike).

## Crypto: `@noble` (default — browser-portable), `node:crypto` (pluggable alternative) — A-001
**Operator ruling: lean browser-compatible** — when two options are otherwise close, don't pick the one that locks out the browser. That decides A-001 for **`@noble`**. `@noble/curves` 2.2.0 gives **both Ed25519 (floor) and Ed448 (the agility family) from one pure-JS package** — still the big simplification over C#, which needed NSec (libsodium) *and* BouncyCastle to span the seam — and `@noble/hashes` 2.2.0 (audited; March-2026 self-audit specifically covered ed25519/ed448) gives SHA-2. Pure-JS means the codec + crypto run unchanged in a browser/Deno/Bun bundle — the consumable-data-library use case (the TS analogue of C#'s Avalonia driver). The trade vs `node:crypto`: +2 runtime deps (cborg→3 total) — but both are zero-*transitive*, raw-byte-native (no DER ceremony, where node:crypto needs a shim — old R6), PGP-signed, and from paulmillr's supply-chain-hardened family. `node:crypto` (zero-dep, native, Node-only) stays documented as the alternative *behind the same pluggable agility seam* — so dropping browser support later swaps the provider without touching the protocol. The Node-only transport (`node:net`) stays at the peer layer; the codec core is kept separable so it lifts into a browser bundle untouched.

## Base58: hand-rolled
C# proved base58 is ~80 lines (Bitcoin alphabet, V7 §8.5) and it's pure-JS/browser-safe. Hand-rolling it keeps the runtime tree to **three packages — `cborg` + `@noble/curves` + `@noble/hashes`, all zero-*transitive*-dependency** — the minimal corner of the ecosystem, just not a single package now that browser-portability brings @noble in. `@scure/base` 2.0.0 (0-dep, *audited*, same paulmillr family) is the drop-in alternative if an audited impl is preferred over saving the dep; both defensible, leaning hand-roll for minimalism.

## Integer model: always-`bigint` — R1/F7
JS `number` is f64 and exact only to 2⁵³−1; the protocol carries u64/i64. The codec's integer surface is `bigint` end-to-end, and int/uint **always** decode to `bigint` (no silent `number` path that works in tests and corrupts in production above 2⁵³). This is the TS-defining correctness risk and it collides with open finding **F7** (the corpus has no `>i64max` probes, so the oracle can't catch a u64 bug) — hence our own vector set across the 2⁵³/2⁶³/2⁶⁴ boundaries is mandatory, independent of conformance.

## Runtime: Node 24 LTS
Node 20 (the original empty container stub) is EOL by mid-2026. Node 24 is the active LTS — well past the 30-day floor, security-supported for years, and ships the native Ed448 + raw-key support we rely on. Pinned by official tarball + SHA-256 in the Containerfile (S11).

## Module system: ESM-only
Modern Node default; also forced by `@scure/base` v2 (ESM-only) if that path is taken, and cleaner than dual ESM/CJS. CJS interop is deferred to S5 unless a consumer needs it.

## Error model: exceptions
JS idiom is `throw`. Mirrors C#'s exception hierarchy as `Error` subclasses (with the `Object.setPrototypeOf` constructor fix for reliable `instanceof`). One naming nit logged (A-003): the C# `ProtocolErrorException` maps awkwardly to `ProtocolErrorError` — likely renamed `WireProtocolError`.

## Test framework: `node:test`
Built-in since Node 18, stable in 20+. Zero test-runner dependencies — where C# pulled three NuGet test pins (Microsoft.NET.Test.Sdk, xunit, xunit.runner.visualstudio), TS pulls none. Aligns with dependency minimization (S6: don't pull vitest/jest without authorization).

## Container network policy: pull-once-then-offline
The user's hard supply-chain requirement, layered on S11. Dependencies are resolved + locked in a single network-on build step (`npm ci` against the committed `package-lock.json`, baked into the image); every dev-loop, build, unit-test, and conformance run thereafter executes with `--network=none` (or loopback/pod-only for S4), so nothing can fetch a transitive package mid-work. This is the concrete mitigation for the Node transitive-dependency-explosion concern — combined with the deliberately near-zero dependency tree, the attack surface is minimal *and* sealed.

## Open profile decisions (logged in SPEC-AMBIGUITY-LOG.md)
- **A-001 — RESOLVED** — crypto = `@noble` (lean browser-compatible; operator ruling). `node:crypto` documented as the Node-only alt behind the pluggable seam.
- **A-002** — npm package id: unscoped `entity-core-protocol-typescript` vs scoped `@entity-core/protocol` (S5).
- **A-003** — `ProtocolErrorError` naming.
- **A-004** — exact `typescript` + Node 24.x.y version pins, verified ≥30d at S2 install.
