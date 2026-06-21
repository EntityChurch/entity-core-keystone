# entity-core-protocol-haskell — Phase S1 Summary

**Peer:** #8 (Haskell) · **Spec basis:** v7.74 (`spec-data/v7.74/`, freshly stamped) ·
**Phase:** S1 (research + profile authoring + container provisioning) ·
**Status:** COMPLETE — no blocking ambiguity items.

Haskell is a **coverage / robustness** peer (the cohort is at diminishing spec-discovery
returns — the wire-touching axes integer/float/crypto/string are saturated; Swift's last
high-yield string bet converged null). Its value is the **biggest unrepresented idiom
family**: pure-functional, **lazy-by-default**, monadic-IO (OCaml is strict + impure ML —
genuinely different). Protocol meaning was read directly from `spec-data/v7.74/`; sibling
*profiles* consulted for structure only.

The four real probes: (1) idiomatic pure/monadic-IO translation; (2) **lazy-evaluation
correctness in a byte-exact codec** (the one place an *implementation* finding could
surface); (3) **native Ed448 via crypton** (a fresh crypto-availability data point); (4)
STM / green threads for §7b.

---

## What I researched

- **spec-data/v7.74 (directly, spec-first):** §1.5 Identity / peer_id canonical-form-per-
  key_type table (Ed25519 → `0x01 0x00 ‖ pubkey`, identity-multihash, the digest IS the raw
  32-byte pubkey); §7.3 signature computation + multicodec LEB128 varint framing; §7.4 peer_id
  derivation (`base58(varint(key_type) ‖ varint(hash_type) ‖ digest)`) — **now defers to §1.5**
  in the v7.74 body (E1 erratum); §8.1 key/hash-format tables; ENTITY-CBOR-ENCODING §2.1 (text
  length = UTF-8 bytes), §2.2 Rule 2 (map keys sorted by encoded length then lexicographic over
  encoded bytes), Rule 4 + special-value table (shortest float incl. f16), §6.3 (Option B —
  reject tags on receive). MANIFEST: v7.71→v7.74 CBOR byte-stable except the v7.73 E3 decode-side
  erratum (no wire change) → v0.8.0 corpus valid at v7.74.
- **GHC toolchain:** release history + dates (9.6.7 / 9.8.4 / 9.10.3); GHC.org Linux bindist
  distribution (per-distro fedora33 bindist + SHA256SUMS); fedora-on-fedora:43 glibc forward-compat.
- **Crypto:** crypton (the maintained fork of the deprecated cryptonite) module surface +
  release dates; **Ed448 availability — NATIVE in crypton** (`Crypto.PubKey.Ed448`); SHA-2.
- **Build system:** Cabal vs Stack; **Stackage LTS 23.27** (GHC 9.8.4,
  crypton 1.0.4) as the dated snapshot for the S11 transitive-closure pin.
- **CBOR / base58 / varint:** `cborg` (mature, deterministic-first) vs ECF canonical requirements;
  base58 + LEB128 not in crypton/base.
- **Test / error / concurrency / memory / naming idioms** per Haskell norms.

## Decisions + pinned versions (S11: each ≥30 days old)

| Surface | Decision | Pin | Age | S11 |
|---|---|---|---|---|
| Codec strategy | **native** (A-005, 8th confirm: own the canonical layer; crypto native) | — | — | — |
| CBOR | **hand-rolled** ECF (zero CBOR dep; `cborg` ≠ ECF-exact) | in-repo | — | — |
| Toolchain | GHC **9.8.4**, fedora33 bindist | `9.8.4` | ~18 mo | ✅ |
| Build driver | **cabal-install** | `3.14.2.0` | ~14 mo | ✅ |
| Dependency snapshot | **Stackage LTS 23.27** (the dated closure pin) | `lts-23.27` | ~11 mo | ✅ |
| Ed25519 + Ed448 + SHA-2 | **crypton** (native, audited C-backed) | `1.0.4` | ~14 mo | ✅ |
| **Ed448** | **NATIVE** (crypton — no defer, no FFI; agility in scope) | `1.0.4` | ~14 mo | ✅ (A-HS-007) |
| base58 / varint | hand-rolled | in-repo | — | — | — |
| Error model | pure **`Either CodecError a`**; IO exceptions edge-only | — | — | — | — |
| Memory/eval | GC'd + **LAZY-by-default**; strict-ByteString/Text + force-at-folds | — | — | — | — |
| Concurrency | **green threads + STM (TVar)** (S3; codec pure/sync) | — | — | — | — |
| Naming | Haskell (UpperCamelCase types/ctors/modules; lowerCamelCase funcs/fields) | — | — | — | — |
| Build / Test | **Cabal** / **hspec** (+ QuickCheck for the lazy-eval probe) | LTS-pinned | — | — | ✅ |
| Publishing | **Hackage** (`cabal sdist`/`cabal upload`) | — | — | — | — |
| License | **Apache-2.0** (S9 default; ecosystem is BSD-3-lean, not mandated) | — | — | — | — |

## Cabal vs Stack — chose Cabal + an LTS-derived freeze (the S11 win)

**Cabal** (cabal-install 3.14.2.0) with a committed **`cabal.project.freeze`**, but the
*dependency set* **derived from Stackage LTS 23.27**. Best of both: Cabal is the lower-level,
no-extra-tool build driver with an explicit reviewable exact-version lockfile, while a Stackage
LTS snapshot is a **single dated pin** fixing the *entire transitive closure* to a coherent,
build-tested set ≥30 days old by construction. This is the cleanest answer to the Swift
**A-SW-005** transitive-age trap: the snapshot's publish date IS the 30-day floor for the whole
closure — no per-transitive-dep manual age audit, no version range for a resolver to float into
the cool-down window.

## Container build result — PASS (built + spike-verified, not just authored)

Per the S1 task contract for this peer (GHC-on-Fedora is the long pole), the container was
BUILT and PROVEN this phase.

- `podman build … containers/ghc-toolchain/Containerfile` → **SUCCESS**.
- Verification fail-closed: GHC 9.8.4 fedora33 bindist **exact sha256** matched
  (`5f03d48f…f947`); cabal-install 3.14.2.0 fedora33 **exact sha256** matched (`8d211976…36d7`).
- `ghc --version` → `version 9.8.4`; `cabal --version` → `3.14.2.0` — the **fedora33** bindist
  runs on the **fedora:43** base (newer-glibc forward-compat confirmed empirically).
- **crypton spike PASS** (throwaway Cabal package, `crypton ==1.0.4`): `cabal run` compiled
  crypton + memory-0.18.0 + basement-0.0.16 from Hackage and ran:
  - `sha256("hello") = 2cf24dba…9824` ✅ (matches known digest)
  - SHA-384 (empty) → 48-byte digest ✅
  - Ed25519 (`Crypto.PubKey.Ed25519`): pubkey 32 B, sig 64 B, **verify = True** ✅
  - **Ed448 (`Crypto.PubKey.Ed448`): pubkey 57 B, sig 114 B, verify = True** ✅ — *native full
    agility incl. Ed448, the headline crypto data point (A-HS-007).*
- **Offline-after-resolve PASS:** the **compiled artifact** re-ran under `--network=none` green.
  NOTE (A-HS-005): a *cold-store* `cabal build` still consults the remote Hackage index, so
  `--network=none` on a cold store fails — the offline S2 loop pre-populates the store on the
  networked resolve, commits the freeze + a pinned `index-state`, then builds warm.
- In-container GHC-bundled versions confirmed coherent with LTS 23.27: base 4.19.2.0,
  **bytestring 0.12.1.0**, integer-gmp 1.1, ghc-bignum 1.3.

## Ambiguity-log entries opened (7, none blocking)

- **A-HS-001** — pure `Either CodecError a`; IO exceptions transport-edge-only. → operator (idiom).
- **A-HS-002** — lazy-eval / strictness discipline in a byte-exact codec → strict ByteString/Text +
  force-at-folds. → operator (**the headline impl-watch-item**; QuickCheck-backed at S2).
- **A-HS-003** — concurrency = green threads + STM (TVar); 3rd data-race-free store shape. → operator (S3).
- **A-HS-004** — hspec over tasty/HUnit. → operator (revisitable at S2).
- **A-HS-005** — cabal cold-store index lookup → warm-store + committed freeze is the offline path. → operator.
- **A-HS-006** — §7a/§7b conformance scaffolding is GUIDE-carried, not spec-data → pick up at S3/S4. → research.
- **A-HS-007** — Ed448 NATIVE (crypton) → first native-full-agility peer; agility corpus in scope. → research (crypto ledger).

## Spec-first observations (no NEW spec defects found at S1)

Reading v7.74 directly surfaced no new spec contradiction. The peer-id **§7.4-vs-§1.5 tension**
that OCaml (A-OC-007) / Zig (A-ZIG-001) / Swift (A-SW-008) flagged is **already reconciled in the
v7.74 §7.4 body** (the E1 erratum — §7.4 now defers to the §1.5 canonical-form table), so Haskell
corroborates the *reconciliation* (a 5th read landing on a consistent §7.4 → §1.5) rather than
re-surfacing it. The CBOR canonical rules read unambiguously. The Haskell-specific mapping
judgments (strict-vs-lazy bytes; `Text` byte-vs-code-point) are generation-discipline calls
(A-HS-002), not spec ambiguities — the spec is explicit that lengths/ordering are byte/UTF-8.

---

## S2 entry checklist

1. **Container:** `entity-core-keystone/ghc-toolchain:latest` — BUILT + verified. Dev loop:
   `podman run --rm -v $PWD:/work:Z -w /work/protocol-generator/haskell
   entity-core-keystone/ghc-toolchain:latest cabal test`.
2. **Codec strategy:** `native` — hand-rolled canonical ECF CBOR + crypton (Ed25519/Ed448/SHA-2).
   Zero CBOR/base58/varint deps; those are in-repo.
3. **First spike (the S2 gate, cheap insurance per PHASE-S1-PROFILE):** push the `map_keys` +
   `float` ECF test-vectors (v0.8.0 corpus) through the hand-rolled encoder BEFORE the full build —
   confirm length-then-lex map-key ordering (over encoded bytes), shortest-float incl. f16, and
   recursive major-type-6 tag rejection (§6.3 Option B). If the spike fails, `ffi` is the
   documented fallback (not expected). The crypto+toolchain spike already passed at S1.
4. **LAZY-EVAL discipline (A-HS-002 — carry into every codec line):** strict `Data.ByteString`
   on the wire path (never lazy ByteString); encoder via `Data.ByteString.Builder` forced to
   strict; `Data.Text` text strings with CBOR length = `encodeUtf8` byte count (never `Text`
   length); `BangPatterns`/`seq`/`$!`/`StrictData` + strict fields at every byte/length
   accumulation (map-key sort, byte-length fold, digest input, decode position); `deepseq`
   decoded structures at the API edge. Add **QuickCheck** round-trip + strictness properties.
5. **Error/idiom:** pure codec = `Either CodecError a` (no IO, no exceptions in the codec layer);
   `Control.Exception` only at the S3 transport edge. No `head`/`fromJust`/`!!` on wire data
   (`no_partial_on_wire`). `-Wall -Werror`.
6. **Deps to pin in the .cabal + commit cabal.project.freeze (derived from LTS 23.27):** crypton
   **1.0.4** (memory 0.18.0, basement 0.0.16 transitively), bytestring **0.12.1.0**, text (LTS
   pin), hspec (LTS pin). Commit the freeze + a pinned `index-state` (A-HS-005).
7. **Corpus:** v7.71 ECF test-vectors (valid at v7.74; CBOR byte-stable). **Agility
   (Ed448/SHA-384) corpus IS IN SCOPE** — Ed448 is native (A-HS-007), no A-SW-001-style gate;
   cross-check SHA-384 + the Ed448 key/peer_id/signature vectors.
8. **Oracle:** wire-conformance (pure codec) is the S2 ground truth — byte-identical to
   `entity-core-codec-ffi`. S2 is done when it says so (S5/S7).
9. **Offline (A-HS-005):** resolve+compile once with network on → commit freeze + warm store →
   thereafter `cabal build --offline`; the compiled artifact runs `--network=none`.
10. **NOT in S2:** §7a/§7b conformance scaffolding (S3/S4, GUIDE-carried — A-HS-006); the peer
    machinery (S3); green-threads/STM concurrency (S3, codec is pure/synchronous).
