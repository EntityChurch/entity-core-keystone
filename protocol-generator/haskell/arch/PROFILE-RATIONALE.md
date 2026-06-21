# entity-core-protocol-haskell — Profile Rationale

Audit trail for every major S1 profile choice. Haskell is **peer #8**, a
*genuinely-spec-first* peer derived from the freshly-stamped `spec-data/v7.74` snapshot
(read directly — protocol meaning was NOT cribbed from the C#/TS/OCaml/Zig/Elixir/CL/Swift
source; only sibling *profiles* were consulted for structure). Haskell is a
**coverage / robustness** peer, not a discovery bet: the cohort is at diminishing
spec-discovery returns (the wire-touching axes — integer width, float model, crypto
availability, string model — are saturated, and Swift's last high-yield string bet
converged null). Haskell's value is the **biggest unrepresented idiom family**:
pure-functional, **lazy-by-default**, monadic-IO. OCaml is strict + impure ML — genuinely
different. Where a value matches a prior peer it is by independent arrival; the idiom seams
deliberately differ.

## What this peer probes (the reason it is worth generating)

1. **Idiomatic pure / monadic-IO translation.** The generated code must read as Haskell a
   Haskeller would write — a pure codec returning `Either CodecError a`, an `IO` boundary
   only at the transport edge, typeclasses where they earn their keep — NOT transpiled
   OCaml. This is the idiom-fidelity test for a non-strict pure-functional target.
2. **Lazy-evaluation correctness in a byte-exact codec** — the one axis where an
   *implementation* finding (not a spec finding) can surface. See the [memory] rationale below.
3. **Native Ed448 via crypton** — a fresh crypto-availability data point (the headline; see below).
4. **STM / GHC green threads for §7b** — a 3rd data-race-free store shape.

## Pinned GHC version: 9.8.4

GHC moves on a roughly-semiannual major cadence (9.10, 9.12, 9.14 are all newer at
authoring), so the version is pinned exactly and the whole peer is designed against one
release. **9.8.4** (~18 months old) is
chosen over the newer lines because it is the GHC against which **Stackage LTS 23.27** is
built — pinning the compiler to the exact version the dependency snapshot targets makes the
whole closure coherent (crypton 1.0.4, bytestring 0.12.1.0, text, hspec all from one tested
set). It comfortably clears the S11 ≥30-day cool-down. The toolchain is the official GHC.org
**fedora33** bindist, verified by an exact sha256 pin (`5f03d48f…f947`) from
`downloads.haskell.org/ghc/9.8.4/SHA256SUMS`, fail-closed on mismatch, installed via the
bindist's `./configure && make install` to `/opt/ghc/9.8.4`. The fedora33 build runs on
`fedora:43`'s newer glibc (GHC's Linux bindist is built against an older glibc and is
forward-compatible) — **build-proven at S1**, not assumed (the Swift fedora39-on-43 pattern).

## Build system: Cabal + a freeze file derived from Stackage LTS 23.27 (the S11 win)

The Cabal-vs-Stack choice is decided in favor of **Cabal** (cabal-install 3.14.2.0,
~14 months old) with a committed **`cabal.project.freeze`** as the S11
lockfile — but the *dependency set* is **derived from Stackage LTS 23.27** (GHC 9.8.4,
~11 months old). This deliberately takes the best of both: Cabal is
the lower-level, more-universal, no-extra-tool build driver (and the freeze file is an
explicit, reviewable, exact-version lockfile), while **a Stackage LTS snapshot is itself a
single dated pin** that fixes the *entire transitive closure* to a coherent, build-tested set
that is ≥30 days old by construction. This is the **cleanest answer to the Swift A-SW-005
transitive-age trap**: with a snapshot-derived freeze, the snapshot's publication date IS the
30-day floor for the whole closure — there is no per-transitive-dependency manual age audit to
get wrong, and no version *range* left for a resolver to float into the cool-down window. The
freeze file is committed; re-pinning to a newer LTS is deliberate + reviewed, re-applying S11.

## Codec strategy: native (lighter than ffi — crypto is the audited crypton)

LANDSCAPE pencilled Haskell as native with `cborg` + `cryptonite`. The **A-005 pattern**
every prior native peer hit (7-for-7) confirms native but overturns the *library* half: a
faithful ECF codec must own the canonical layer — length-then-lexicographic map-key ordering
on the **encoded** key bytes (§2.2 Rule 2), shortest-float incl. f16 (§2.2 Rule 4 + the
special-value table), recursive major-type-6 tag rejection on decode (§6.3 Option B), full
uint64/nint range, raw-byte fidelity — regardless of any CBOR library underneath, so a library
buys almost nothing. **`cborg`** is the mature, "deterministic-first" Haskell CBOR library, but
it does NOT give ECF's exact guarantees: its determinism is RFC-8949-canonical-leaning, not
ECF-identical (the float ladder, the *exact* encoded-key-bytes map ordering, and §6.3's
recursive-tag-reject-on-decode are ECF policy, not a cborg switch). With **crypton** supplying
audited, C-backed Ed25519 + Ed448 + SHA-2 natively, `native` is the strictly lighter path (one
audited crypto dependency, no FFI boundary, no CBOR dependency). `ffi` remains the documented
fallback; the cheap codec spike (push `map_keys` + `float` vectors through the hand-rolled
encoder) runs at S2 start per PHASE-S1-PROFILE. Haskell is the **8th** A-005 confirmation.

## Crypto: crypton — and Haskell is the FIRST native-FULL-agility peer (incl. Ed448)

**`crypton`** (the maintained fork of the now-**deprecated `cryptonite`** — cryptonite's own
Hackage page declares it deprecated in favor of crypton + the cryptohash-\* family; crypton
is forked with the original author's permission and is the actively-maintained successor) is
the idiomatic Haskell crypto library. It supplies `Crypto.PubKey.Ed25519` (Ed25519, RFC-8032
deterministic), `Crypto.Hash` (`hashWith SHA256/SHA384/SHA512`), **and** — the headline —
`Crypto.PubKey.Ed448` (**Ed448, native**). Pinned exactly to **1.0.4** (~14 months
old; the version Stackage LTS 23.27 pins). **All of this was
build-proven at S1** (the spike below): `sha256("hello")` matched the known digest, SHA-384
returned 48 bytes, Ed25519 signed+verified (32B pubkey / 64B sig), and **Ed448 signed+verified
natively** (57B pubkey / 114B sig). This makes Haskell the **first peer with native full
crypto-agility including Ed448** — a distinct crypto-availability outcome from the cross-peer
ledger: OCaml hit the Ed448 native gap (A-OC-002 → hybrid FFI), Zig deferred it (A-ZIG-002),
Swift deferred it (A-SW-001), and Common Lisp had pure-Lisp Ed448 (ironclad). crypton sources
Ed448 from the *same* audited C-backed library as Ed25519 — no FFI, no separate dependency, no
defer. The crypto-agility higher bar is therefore **reachable in-band for this peer**, and the
profile's `[codec].ed448_library` records it as `native`, not deferred.

## SHA-256 + SHA-384/512: crypton Crypto.Hash

`hashWith SHA256` is the content_hash floor (`content_hash_format 0x00`); `SHA384`/`SHA512`
are present in the same library for agility hashing. Same dependency as Ed25519/Ed448 — no
separate pin. Validated at S1 (sha256("hello") == `2cf24dba…9824`; SHA-384 empty → 48 bytes).

## Base58 + varint: hand-rolled

Both are small and absent from crypton/base. Base58 (Bitcoin alphabet, encode + decode) for
`peer_id` (§7.4 `base58(varint(key_type) ‖ varint(hash_type) ‖ digest)`); multicodec-style
LEB128 varints for the §7.3 `key_type`/`hash_type`/format-code framing (single-byte ≤ 0x7F
today, varint shape for forward-compat). Hand-rolling matches the dependency-minimization stance.

## Error model: pure `Either CodecError a` (Haskell-native; IO exceptions only at the edge)

Haskell's idiomatic pure-error shape is **`Either e a`** threaded by `do`-notation in the
`Either` monad. The codec is a **pure, total function** returning `Either CodecError a` — an
error is a *value*, never a thrown exception, so there is nothing to `catch` in the codec
layer (this is a stronger purity guarantee than OCaml's `result`, where a decode-path
exception is caught at the boundary — Haskell's codec has no exception path at all). The error
*shape* converges with OCaml's `result` (an Either-like ADT — the error axis is low-yield and
shown idiom-neutral across the cohort), but it is arrived at independently as the Haskell idiom
and enforced differently (pure vs. exception-bounded). **`Control.Exception` / `throwIO` /
`bracket`** appear ONLY at the impure S3 transport boundary (sockets), never in pure code.
Protocol-status failures (400 non_canonical_ecf / 401 / 403) map a `CodecError`/verdict
constructor → status code at the module boundary. (A-HS-001.)

## Memory + evaluation: LAZY by default — the headline Haskell seam (and the one impl-finding bet)

Haskell is **lazy (non-strict) by default**: every binding is a thunk until forced. On the
surface Haskell is the 5th GC'd peer (GHC has a generational copying tracing GC), but the
*defining* memory seam — unique among all 8 peers — is **laziness**. In a byte-exact codec this
is a genuine hazard, and the reason peer #8's idiom family is worth generating: a
lazily-accumulated length or byte buffer can build a space-leaking thunk chain, and a non-forced
fold can defer evaluation in ways that (while pure) blow the stack or mis-time strictness.
The codec design stance **defeats laziness deliberately wherever bytes accumulate or determinism
matters**:

- Wire bytes are **strict `Data.ByteString`** in the hot path — NOT lazy `ByteString` (which
  chunks and defers). The encoder emits via a `Data.ByteString.Builder` and forces the result to
  a strict `ByteString`.
- Text strings are **`Data.Text`** (text ≥ 2.0 is UTF-8 internally); the CBOR text-string length
  is the **UTF-8 byte count** via `Data.Text.Encoding.encodeUtf8`, never `Text` length (code
  points) — the same byte-vs-unit discipline Swift hit on `String.utf8`, here on `Text`.
- **`BangPatterns` / `seq` / `$!` / strict data fields (`!Field`, `StrictData` pragma)** wherever
  bytes or lengths accumulate: the map-key length sort, the byte-length fold, the digest input,
  and the decode-position threading are all forced; no lazy thunk reaches the wire.
- Decoded structures are `deepseq`/`force`d at the API edge before they cross into long-lived
  store state, so no thunk retains a large input buffer.

**Where it bites (the S2 watch-item):** encoder accumulation, the map-key length sort, and
decode position threading are the three places a thunk leak / space leak or a mis-forced ordering
would surface in a byte-exact codec. This is the single place an *implementation* finding (as
opposed to a spec finding) could come out of this peer. **QuickCheck** round-trip + strictness
properties (encode∘decode == id; no value leaves a leaking thunk) are a strong fit and are
layered at S2 as robustness insurance. (A-HS-002.)

## Concurrency: GHC green threads + STM (a 3rd data-race-free store shape; not exercised by the codec)

Haskell's headline concurrency story is **GHC green threads** (`forkIO` — lightweight, M:N
scheduled onto OS capabilities) + **STM** (`Control.Concurrent.STM`, `TVar` — composable,
lock-free, transactional memory), with `MVar` as the simpler primitive and the **`async`**
library for structured concurrency (`withAsync`/`race`/`concurrently`). The codec (S2) is pure +
synchronous, so concurrency is **not exercised at S2**. At the peer (S3), the
§4.8/§6.11 inbound-concurrent-with-outbound requirement, the §6.13b handler outbound closure,
the §7a `dispatch-outbound` **reentry** surface, and the **§7b store-concurrency gate** fit STM
naturally: the live store is a `TVar` (or a small set of `TVar`s) mutated inside `atomically`,
which gives a **3rd data-race-free shape** after the Elixir actor (message-serialized) and the
Swift actor (await-serialized) — here it is *transactional* (composable, retry-based). One
`forkIO` green thread per connection; request_id↔continuation correlation via an `MVar`/`TVar`
demux map. Final shape decided at S3; idiom recorded now. (A-HS-003.)

## Naming: Haskell conventions

`UpperCamelCase` for types/data-constructors/typeclasses/modules; `lowerCamelCase` for
functions/values/record-fields/constants (Haskell uses `lowerCamelCase` for top-level CAF
constants — **not** SCREAMING_SNAKE). Hierarchical module names (`EntityCore.Codec.CBOR`,
`EntityCore.PeerId`), with the file path matching the module path (`src/EntityCore/Codec/CBOR.hs`)
per Cabal convention. Differs from every prior peer's exact convention; the correct Haskell idiom.

## Build / test / packaging: Cabal + hspec + Hackage

**Cabal** (`cabal build`/`cabal test`) is the build driver (rationale above, with the LTS-derived
freeze). Tests use **hspec** — the de-facto idiomatic standalone behavior-test framework (the
RSpec analog: `describe`/`it`), in the pinned LTS 23.27 set (clears S11 via the snapshot) — over
**tasty** (a test-tree framework hosting HUnit/QuickCheck/hspec providers) and bare HUnit;
recorded as A-HS-004, revisitable. The conformance harness is an hspec spec (or a `cabal run
conformance` executable) that loads the normative v7.71 ECF fixture and asserts byte-identity.
**QuickCheck** property tests are layered at S2 for the lazy-eval robustness probe.
Packaging targets **Hackage** (Haskell's central registry): `cabal sdist` → `cabal upload`.

## License: Apache-2.0 (S9 default)

The Haskell ecosystem is **BSD-3-leaning** (GHC and `base` are BSD-3) but does NOT mandate it.
The repo's Apache-2.0 default (explicit patent grant) stands — no S9-override case arises (BSD-3
preference is a lean, not a mandate, and Apache-2.0 is a strictly broader grant).

## Container: containers/ghc-toolchain/Containerfile — BUILT + spike-verified at S1

`fedora:43` base + the GHC.org **9.8.4 fedora33 bindist** (sha256-pinned, fail-closed,
`./configure && make install` to `/opt/ghc/9.8.4`) + the **cabal-install 3.14.2.0 fedora33**
tarball (sha256-pinned, fail-closed, to `/opt/cabal/bin`). Fedora ships no GHC 9.8.4, so the
official bindist is the route; pinning + sha256 verification mirrors the zig/swift pattern adapted
to GHC's `./configure`-bindist distribution. (`downloads.haskell.org` also publishes
`SHA256SUMS.sig` detached GPG signatures; the exact-sha256 pin is the primary gate, GPG is the
documented defense-in-depth follow-on.) Per the S1 task contract for this peer (GHC-on-Fedora is
the long pole), the container was **built and proven NOW**, not just authored:

- `podman build … containers/ghc-toolchain/Containerfile` → **SUCCESS**.
- `ghc --version` → `The Glorious Glasgow Haskell Compilation System, version 9.8.4` on the
  fedora:43 base (the fedora33 bindist runs on fedora:43's newer glibc — forward-compat confirmed
  empirically).
- `cabal --version` → `cabal-install version 3.14.2.0`.
- **crypton spike PASS** (throwaway Cabal package, `crypton ==1.0.4`): `cabal run` compiled
  crypton (+ memory-0.18.0, basement-0.0.16) from Hackage and ran:
  - `sha256("hello") = 2cf24dba…9824` ✅ (matches known digest)
  - SHA-384 (empty) → 48-byte digest ✅
  - Ed25519: 32-byte pubkey, 64-byte sig, **verify = True** ✅
  - **Ed448: 57-byte pubkey, 114-byte sig, verify = True** ✅ (native full agility)
- **Offline-after-resolve PASS:** the compiled artifact re-ran under `--network=none` green; the
  only networked step is the one-time Hackage resolve/compile. NOTE: `cabal build` on a *cold*
  store still consults the remote package index — the offline S2 loop pre-populates the store on
  the networked resolve, commits the freeze + a pinned `index-state`, then builds with a warm
  store; recorded as A-HS-005 (cabal-offline mechanics, not a blocker).

## Spec version: read v7.74, codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.74` (read directly, spec-first). The codec uses
the `test-vectors/v0.8.0` ECF corpus: `ENTITY-CBOR-ENCODING.md` is byte-stable across the
v7.71→v7.74 line except the v7.73 **E3** construct-vs-decode erratum paragraph (a decode-side
clarification, no wire change — confirmed in the v7.74 MANIFEST), so the v0.8.0 corpus is valid at
v7.74 (the same finding the OCaml/Zig/Swift peers SHA-verified). The **agility (Ed448/SHA-384)
corpus is IN SCOPE** for this peer — Ed448 is native, so there is no A-SW-001-style gate. The §7a
conformance handlers + §7b concurrency gate come from `GUIDE-CONFORMANCE.md` + the generator menu,
**not** spec-data (per the v7.74 MANIFEST note), picked up at S3/S4 (A-HS-006).

## Spec-first observations (no NEW spec defects found at S1)

Reading v7.74 directly for profile-relevant facts surfaced no new spec contradiction beyond the
already-ledgered ones. The §1.5 identity canonical-form table (Ed25519 → `0x01 0x00 ‖ pubkey`,
the digest IS the raw 32-byte public key — identity-multihash, v7.64/v7.65), the §7.3 varint
framing, and the §7.4 peer-id derivation read cleanly: §7.4's v7.74 body now explicitly **defers
to the §1.5 table** (the E1 erratum reconciliation), so the peer-id §7.4-vs-§1.5 tension that
OCaml/Zig/Swift surfaced (A-OC-007 / A-ZIG-001 / A-SW-008) is **reconciled in the v7.74 §7.4
text** — Haskell corroborates the *reconciliation* rather than re-surfacing the tension (a 5th
read landing on a now-consistent §7.4 → §1.5). The CBOR canonical rules (§2.2 length-then-lex map
ordering over encoded bytes, shortest-float incl. f16, §6.3 recursive tag-reject) read
unambiguously. The Haskell-specific mapping judgments — strict-vs-lazy byte handling (A-HS-002)
and `Text`-byte-vs-code-point (within A-HS-002) — are generation-discipline calls, not spec
ambiguities (the spec is explicit that lengths/ordering are byte/UTF-8-oriented).
