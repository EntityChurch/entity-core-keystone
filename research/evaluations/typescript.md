# Evaluation — TypeScript / Node.js

**Author:** keystone operators (peer #2 S1 foundation pass)
**Purpose:** Ground the choices in `protocol-generator/typescript/profile.toml` with an audit trail, and de-risk the **native-first** codec decision against what the reference impls (Go/Rust/Python) and peer #1 (C#) actually had to do. TypeScript is **peer #2** — arch-blessed (commit `b49a844`, "TS for peer #2") and the long-documented landscape #2 pick.

> **Why TS is the right peer #2 (keystone-thesis note).** Every peer touched so far had a native safety net — Go/Rust/Python exist as hand-written references; C# could byte-check against the rust/c FFI codec. **TypeScript is the first peer with no sibling that already knows the answer** — pure spec → peer in an ecosystem we have zero native reference for. That is the actual test of "does the spec carry everything" (S8 convergence). It runs `--profile core` from day one (the headline v7.72 inheritance); no hand-maintained scoreboard.

## Codec strategy decision: **native-first** (no FFI)

TypeScript stays **native**. JS has a mature deterministic CBOR library (`cborg`) and a pure-JS crypto family (`@noble/curves` + `@noble/hashes`) that covers **Ed25519 (floor) + Ed448 (agility family) from one package** plus SHA-2 — all browser-portable. There is no reason to pay the FFI tax. The FFI codec stays a **byte-identity cross-check** target, not a critical-path dependency. (Node's built-in `node:crypto` *also* does Ed25519+Ed448 natively, zero-dep — the Node-only alternative behind the agility seam; see A-001. We lean `@noble` for browser portability.)

**Planning consequence:** TS native S2 validates byte-identical against `test-vectors/v0.8.0/` (= v7.72; the codec corpus is unchanged 7.71→7.72, confirmed by SHA-256 in `spec-data/v7.72/MANIFEST.md`) and the 53-type registry vectors. It does **not** block on the FFI crate.

### The supply-chain headline (your stated #1 concern — dependency minimization)

We deliberately picked the **zero-transitive-dependency corner** of the npm ecosystem. The full runtime tree is:

| Surface | Choice | Runtime deps it adds |
|---|---|---|
| CBOR | `cborg` (rvagg) | **0 transitive** |
| Ed25519 + Ed448 (agility seam) | **`@noble/curves`** (one pkg, both families) | **0 transitive** |
| SHA-256 (+384/512) | **`@noble/hashes`** (audited) | **0 transitive** |
| Base58 | **hand-rolled** (~80 lines, Bitcoin alphabet — as C# did) | **0** |
| TCP transport | `node:net` (built-in) | **0** |
| Test runner | `node:test` (built-in) | **0** |
| Build | `typescript` (dev-dep only) | dev-only |

→ **The mandatory runtime dependency tree is three packages — `cborg` + `@noble/curves` + `@noble/hashes` — all zero-*transitive*-dependency**, from the two most supply-chain-disciplined authors in JS (rvagg, paulmillr). Not one package (browser-portability via @noble brings two in — see the crypto decision), but still the minimal corner: no 500-package explosion, nothing transitively pulls `latest`. (`@scure/base` v2.0.0 — 0-dep, *audited*, same paulmillr family — is the drop-in alternative to hand-rolled base58.)

The container enforces this at the network layer (see "Build / container" below): deps are pulled **once** with the network open and the tree locked; every build/test/conformance run thereafter is **offline** so nothing can grab a transitive `minus-split` mid-build.

## Library audit

| Concern | Choice (profile) | Version (pin candidate) | Reference-impl analogue | Notes |
|---|---|---|---|---|
| CBOR | `cborg` | **5.1.1** (satisfies the ≥30-day supply-chain cool-down) | Go `fxamacker/cbor`; Py `cbor2`; Rust `ciborium`; C# `System.Formats.Cbor` | Deterministic-by-default. **Map ordering, tag-reject, float-encode are favorable** (below). Decode-side gaps + BigInt are ours (R1/R3). Zero-dep. |
| Ed25519 (floor) | **`@noble/curves`** | **2.2.0** (~2mo → S11-clean) | Go stdlib; Py `cryptography`; Rust `ed25519-dalek`; C# NSec | Pure-JS, **browser-portable**, raw 32-byte keys (no DER). |
| Ed448 (agility seam) | **`@noble/curves`** | **2.2.0** | C# needed a *separate* lib (BouncyCastle) | **Same package covers both families** — seam is one dep here. |
| SHA-256 (+384/512 agility) | **`@noble/hashes`** | **2.2.0** | stdlib everywhere | Audited (March-2026 self-audit covered ed25519/ed448). |
| Base58 | **hand-rolled** | — | Go `mr-tron/base58`; Py `base58`; Rust `bs58`; C# hand-rolled | Bitcoin alphabet (V7 §8.5). Dodges a dep. Alt: `@scure/base` 2.0.0 (0-dep, audited, ESM-only). |
| Varint / LEB128 | hand-rolled (inline) | — | inline everywhere | Small (N1, multikey varints). BigInt-backed (see R1). |
| TCP transport | `node:net` (built-in) | Node 24 LTS | — | Async; peer S3. |

### Crypto-provider decision (A-001, RESOLVED): `@noble` — lean browser-compatible

**Operator ruling: lean browser-compatible.** When two options are otherwise close, don't pick the one that locks out the browser. So crypto = **`@noble/curves` 2.2.0** (Ed25519 floor + **Ed448 agility family from one pure-JS package**) + **`@noble/hashes` 2.2.0** (SHA-2, audited; March-2026 self-audit covered ed25519/ed448), behind the crypto-agility seam (the C# `IKeyAlgorithm`-registry pattern). Pure-JS → the codec + crypto run unchanged in a **browser/Deno/Bun** bundle — the consumable-data-library use case (the TS analogue of C#'s Avalonia driver). Raw-byte API (no DER ceremony), PGP-signed, strictly pinned, zero transitive deps.

Trade vs the alternative (`node:crypto`, zero-dep, native, Node-only): browser-portability costs **+2 runtime deps** (cborg → 3 total) and gives up nothing material — @noble is the de-facto-standard JS crypto family. `node:crypto` stays documented as the alternative behind the *same pluggable seam*, so dropping browser support later swaps the provider without touching the protocol. The Node-only transport (`node:net`) stays at the peer layer (S3); the codec core is kept **separable from transport** so it lifts into a browser bundle untouched.

## Load-bearing risks for TS native ECF (verify empirically in S1/S2 against test-vectors)

### R1 — Integer surface is `BigInt`, NOT `number` *(HIGH — the TS-defining risk; the float-equivalent of C# R1)*
JS `number` is IEEE-754 f64: integers are exact only to **2⁵³−1** (`Number.MAX_SAFE_INTEGER`). The protocol carries **u64 / i64** (`primitive/uint`, `primitive/int`, hash lengths, `ttl_ms`, revision counters). A naïve `number`-based codec **silently corrupts** any value above 2⁵³. → **The codec's integer surface must be `bigint` end-to-end** (encode, decode, the value model, varint/LEB128). cborg helps: integers **within 64-bit range encode as CBOR major-type 0/1 with no tags** (correct ECF), and `allowBigInt` (default true) returns out-of-safe-range integers as `BigInt` on decode. But the encoder must be *handed* `bigint` (not `number`) for the >2⁵³ range, and we must decide the value-model contract (always-bigint for int/uint, vs bigint-only-when-needed — always-bigint is the safer, less-surprising rule).

> **R1 collides with open finding F7.** The conformance corpus tops out at `i64::MAX` with **no `[2⁶³, u64::MAX]` probes**. So the oracle **cannot** catch a TS u64 bug above i64::MAX — TS is the peer *most exposed* to this gap. **Mitigation: author our own codec unit-test vectors across `2⁵³−1`, `2⁵³`, `2⁶³−1`, `2⁶³`, `2⁶⁴−1`** (encode + round-trip), independent of the oracle. Push arch on F7 (add the corpus probes). This is the single most important TS-specific test surface. See memory `[[codec-review-heuristic]]`.

### R2 — Entity-data fidelity: hash over raw bytes, never re-encode *(HIGH — cross-impl hash agreement, conformance-invariant N4 / V7 §1.8)*
All three reference impls converged on this (Go `cbor.RawMessage` passthrough; Rust `ecf_for_hash(type, &[u8])`; Python stores raw + idempotency guard); C# `ComputeContentHash(type, ReadOnlySpan<byte> rawData)` embeds verbatim. cborg decodes to JS values by default, so a decode→re-encode round-trip is **not guaranteed byte-identical** (and must never be on the hash path). → The TS codec must keep entity `data` as a `Uint8Array` and **embed it verbatim** into the `{data, type}` hashable — author a `computeContentHash(type: string, rawData: Uint8Array)` that does not parse-and-reserialize. This likely means a thin custom encode path for the hashable wrapper rather than round-tripping through cborg's high-level API.

### R3 — Canonical conformance: cborg defaults are *favorable*, but decode-side minimality + map sort still need verification *(MEDIUM — N1/N2/N3; the "no library gives ECF canonicality free" reality check)*
cborg is the best-positioned CBOR lib surveyed, but per the S1 reality-check, ECF canonicality is still **ours to enforce/verify on top**:
- **Map key ordering** — cborg's **default is "length-first then bytewise"**, which **is** the CTAP2 / ECF rule (length-then-lexicographic). *Verify byte-exact against the `map_keys.*` vectors before trusting it* — the default looks right (better than C#'s `Strict`, which didn't sort at all), but confirm. (`rfc8949EncodeOptions` gives the pure-bytewise variant — do **not** use it; ECF is length-first.)
- **Float minimization** — cborg encodes smallest-possible 16/32/64 by default (good), **but explicitly cannot enforce smallest-float on *decode*.** → We add a **decode-side check that incoming floats are already minimal** (reject non-minimal per ECF Rule 4a) and confirm special values: NaN `F9 7E00`, −0 `F9 8000`, +Inf `F9 7C00`, −Inf `F9 FC00`. Lock with vectors at 1.0, 1.5, 32768.0 (`f97800`), 65504.0 (`f97bff`), NaN, ±Inf, ±0.
- **Minimal ints** — confirm cborg rejects non-minimal int encodings on decode (it focuses on strictness; verify).

### R4 — Tag rejection *(LOW — N2, mostly free)*
ECF rejects any CBOR major-type-6 tag in `data` (`ENTITY-CBOR-ENCODING` §6.3 → `400 non_canonical_ecf`). **cborg rejects tags by default** ("where a tag is encountered during decode, an error will be thrown" unless a `tags` decoder is supplied). → Largely free; C# needed a hand-written recursive scanner, TS gets it from the library default. Confirm the error surfaces as our `400 non_canonical_ecf`, and that we never register a `tags` handler on the ECF decode path.

### R5 — Zero-hash sentinels on decode *(MEDIUM — V7 §1.3 / `RULING-Q-OMITZERO-HASH-FIELD`)*
Optional hash fields must accept CBOR null (`0xF6`), undefined (`0xF7`), and empty byte string as zero-hash; reject other malformed lengths. TS hash-field decode must accept these. (Confirm the ruling is reflected in the v7.72 spec text during S2; carried green in C#.)

### R6 — raw-key handling *(LOW — resolved by the @noble choice)*
The protocol uses raw 32-byte Ed25519 / 57-byte Ed448 keys. **`@noble/curves` takes raw key bytes with zero ceremony** — no DER wrapping — so this is a non-issue under the chosen provider. (Was a risk only for the `node:crypto` alternative, which needs a ~10-line DER-prefix shim if its `'raw-private'`/`'raw-public'` import is fiddly on the target Node. Documented in case the provider is ever switched.)

## Build / container

- **Runtime:** **Node 24 LTS** (active LTS; maintenance 2026-10-20; EOL 2028-04-30 — well past the ≥30-day supply-chain floor and security-supported for years). *Node 20 is EOL by mid-2026 — the empty `containers/node20/` stub is retired in favor of `containers/node24/`.*
- **Build tool:** `npm` (with committed `package-lock.json`); `tsc` for compile. **`npm ci`** (not `npm install`) so the lockfile is authoritative and never silently drifts.
- **Test:** `node:test` (built-in) + `tsx`/`tsc` — zero test-runner deps.
- **Module system:** **ESM-only** (`"type": "module"`, `module: nodenext`, `target: es2022`). The modern default, and what the `@noble` 2.x family ships; also the right shape for a browser bundle. Dual ESM/CJS is deferred (S5) unless a consumer needs CJS.
- **TS strictness:** `tsconfig` `strict: true` + `noUncheckedIndexedAccess` + `exactOptionalPropertyTypes` — the analogue of C#'s `nullable enable` + `TreatWarningsAsErrors`.
- **Network-lockdown design (the user's hard requirement):** the `node24` Containerfile pulls + locks deps in **one network-on build step** (`npm ci` against the committed lockfile, baked into the image), then **every** dev-loop / build / unit-test run uses `--network=none`; the S4 conformance run uses loopback/pod networking to the oracle only, with **no registry egress**. Pin Node itself by official tarball + SHA-256 (S11). Detail in `containers/node24/Containerfile`.

## Open items feeding the profile / next session

1. **A-001 — RESOLVED:** crypto = `@noble` (lean browser-compatible; operator ruling). `node:crypto` documented as the Node-only alternative behind the seam.
2. **R1 / F7** — author the `>i64max` codec vector set ourselves (the oracle can't); push arch on F7. **Highest-priority TS test surface.**
3. Pin exact versions against the **≥30-day rule** at S2 install time (`npm view <pkg> time` in-container) and log any too-new in the ambiguity log — same draft-then-verify pattern that corrected C#'s NSec pin (A-002). Candidates: `cborg` 5.1.1 ✓, `@noble/curves` 2.2.0 ✓, `@noble/hashes` 2.2.0 ✓, `typescript` (latest stable 5.x — verify ≥30d), Node 24.x.y (pin exact NVR/SHA-256).
4. Confirm cborg's map-sort + minimal-int + tag-reject defaults byte-exact against `map_keys`/`float` vectors **before** committing the full S2 build (cheap spike; FFI is the documented fallback if it fails — it won't be needed).
5. Decide the value-model integer contract: **always-`bigint` for int/uint** (recommended — no silent `number` path) vs bigint-only-above-2⁵³.

## What TS inherits from peer #1's scars (carry forward)
- `--profile core` is a **machine verdict** from day one — no hand scoreboard.
- **Don't trust a ruling memo over the oracle** (F20): request-time auth-class sig failure → **401**.
- **Ship day-one better defaults:** `capability_revoked` on known revocation; control-byte/leading-slash path → 400; deletion-marker listing filter; canonical peer_id derivation; the universal (`/*/*`) debug grant for `--debug-open-grants`.
- **Prioritize F12** (authenticate nonce-echo / replay): implement the echo check even though §4.6 doesn't yet mandate it; push arch to make it explicit.
- **Reuse the dump→author→diff mechanical loop** for the 53-type registry + tree vectors (render reference to readable shape, author natively, diff byte-exact).

## Reference files (for idiom, not copying)
Go `entity-core-go/core/ecf/ecf.go`, `core/hash/hash.go` · Rust `entity-core-rust/core/ecf/src/encoder.rs` (float minimization) · Python `entity-core-py/.../utils/ecf.py` · **C# (peer #1, closest analogue)** `protocol-generator/csharp/src/EntityCore.Protocol/Codec/{CanonicalCbor,EcfValue,Ecf}.cs` + the type-registry + handler patterns (the cross-peer pattern menu, GUIDE-EXTENSION-DEVELOPMENT §4).

## Sources (S1 web survey)
- [cborg (rvagg) — GitHub](https://github.com/rvagg/cborg) · [cborg — npm](https://www.npmjs.com/package/cborg)
- [@noble/curves — GitHub](https://github.com/paulmillr/noble-curves) · [@noble/hashes — npm](https://www.npmjs.com/package/@noble/hashes)
- [@scure/base — GitHub](https://github.com/paulmillr/scure-base)
- [Node.js crypto — Ed25519/Ed448](https://nodejs.org/api/crypto.html) · [Node.js EOL schedule](https://endoflife.date/nodejs)
