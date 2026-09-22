# entity-core-protocol-haskell — S2 Conformance Report

**Peer:** #8 (Haskell) · **Phase:** S2 (codec) ·
**Status (2026-09-02):** GREEN — **173 examples, 0 failures**, the whole suite
run offline from a clean tree. ECF corpus **71/71** byte-identical, crypto-agility
corpus native (Ed448 + SHA-384), type-registry 53/53, selftests + QuickCheck
properties pass.

Toolchain: GHC 9.8.4, cabal-install 3.14.2.0, crypton 1.0.4 (pinned), in the
`entity-core-keystone/ghc-toolchain:latest` container. Built `-Wall -Werror`
(`-f dev`). Self-contained gate (no live Go oracle at S2): the corpus carries its
own cross-blessed `canonical` bytes.

> ## Correction, 2026-09-02 — this report claimed a green it could not reproduce
>
> Everything below the correction dates from the original S2 run and is kept as
> the record of it. Three of its claims were false by the time anyone checked:
>
> - **"69/69"** and **"Codec corpus v7.71"** — the ECF corpus is **71 vectors**
>   and lives at `shared/test-vectors/ecf-conformance/` (the corpora were
>   de-versioned 2026-09-01; a version stamp in a corpus directory name is now
>   forbidden by `GUIDE-CONFORMANCE` §5.1). The pinned digest quoted below,
>   `41d68d2d…`, is **retired** — it is the 69-vector corpus from before F29/F30.
> - **"Offline … verified GREEN"** in §6 — **it was not runnable at all.** The
>   image vendored no Hackage closure; the dependency store lived in a gitignored
>   `.cabal-home` inside the working tree that had been warmed by hand on one
>   machine, and only ever for the LIBRARY deps. `cabal test --offline` died with
>   fourteen `refusing to download the package` lines (hspec, QuickCheck, HUnit,
>   …). A claim of reproducibility that nobody re-ran is not evidence of
>   anything, and this one had been false for long enough that no one could say
>   when it stopped being true. The closure now ships in the image, derived from
>   this peer's own `cabal.project.freeze`; §6 records the current recipe.
> - **§2's `hash-format-sha-384.2.rehash` row** — that vector was **inverted
>   upstream**. It no longer pins a SHA-384 `content_hash`; it asserts the
>   construction is **REFUSED**, because §4.5a item 1a pins `system/peer` to the
>   ECFv1-SHA-256 floor unconditionally. The old assertion passed by calling the
>   raw digest primitive, which is exactly the hand-built bypass the vector's
>   `verifier_requirement` forbids. See §2a.
>
> The peer's CODEC was never wrong about any of this — the one real FAIL that
> surfaced once the suite could run was the inverted vector, and it was a test
> asserting a retired pin, not a codec defect. What was wrong was the report.

## 1. ECF conformance corpus — 69/69 PASS

`cabal run conformance-exe` (and the hspec `conformance` suite):

| Category      | Pass/Total | Notes |
|---------------|-----------|-------|
| float         | 14/14 | Rule 4 f16/f32/f64 shortest ladder + Rule 4a specials (NaN/±Inf/±0) |
| int           | 14/14 | Minimal head form; boundaries through max-i64; nint -1..-256 |
| map_keys      | 6/6   | Length-then-lex sort over **encoded key bytes** (text + byte + mixed) |
| length        | 8/8   | Definite-length only; empty array/map/text/bytes; 23/24 boundaries |
| primitive     | 6/6   | `0xf4`/`0xf5`/`0xf6`; null/bool mixes; empty str/bytes |
| nested        | 4/4   | Deep maps; entity carrier `{type,data}`; hash-keyed included map |
| tag_reject    | 5/5   | **decode_reject** — tags 0/1/37/55799 + nested-in-included (N2) |
| content_hash  | 4/4   | `varint(fmt) ‖ SHA256(ECF{type,data})`; empty-entity pin; ≥0x80 varint |
| peer_id       | 3/3   | `Base58(varint(kt) ‖ varint(ht) ‖ digest)`; ≥0x80 key_type |
| signature     | 3/3   | Deterministic Ed25519 over the **ECF preimage** (corpus convention) |
| envelope      | 2/2   | `system/envelope` root+included; hash-keyed included map |
| **TOTAL**     | **69/69** | **64 encode_equal + 5 decode_reject** |

**Codec-logic fixes to reach 69/69: ZERO.** First successful build passed
69/69 (matching the prior 7 native peers). The only pre-green edits were GHC
mechanics: a missing `OverloadedStrings` pragma (Base58 alphabet literal) and
test-side `-Werror` hygiene (partial `let Right x = …` → `case`, one orphan
`Arbitrary` instance flagged `-Wno-orphans`, redundant imports). No spec/codec
semantics changed.

## 2. Crypto-agility corpus — native Ed448 + SHA-384 (the headline data point)

`AgilitySpec` against `agility-vectors.cbor` (v7.71). Codec-reachable
Phase-1 vectors, **7/7 PASS** — all native via crypton (no FFI, no defer):

| Vector | Native primitive | Result |
|--------|------------------|--------|
| `key-type-ed448.1.pubkey` | Ed448 seed → 57-byte pubkey | byte-equal |
| `key-type-ed448.2.peer_id` | Ed448 peer_id (key_type 0x02, SHA-256-form) | base58-equal |
| `key-type-ed448.3.system_peer_entity` | system/peer ECF + SHA-256 content_hash | byte-equal |
| `key-type-ed448.4.signature` | deterministic Ed448 sig (114 B) | byte-equal |
| `hash-format-sha-384.1` | inherited SHA-256 content_hash pin | byte-equal |
| `hash-format-sha-384.2.rehash` | ~~**SHA-384** content_hash (49 B = `0x01` + 48 B digest)~~ | **withdrawn — see §2a** |
| Ed448 peer-id payload cross-check | `[0x02,0x01] ‖ SHA256(pubkey)` structure | base58-equal |

Haskell is the **2nd peer to pass the agility corpus natively** (after Common
Lisp's pure-Lisp ironclad) and the **first from an audited C-backed library**
(crypton). The Phase-2 `matrix.*` cap-grant flows are protocol-surface
(S3/S4), out of codec scope; the 3 `varint`/`format-code` `decode_reject`
probes assert a §1.2 seed-table policy that lives at the peer/validate layer
(the codec's `contentHash` accepts any format code and defaults unknown codes
to SHA-256; rejection of unallocated codes is S4).

## 2a. `hash-format-sha-384.2` — the §2.4a negative half (2026-09-02)

The corpus vector this row used to pin was **inverted upstream**: it asserted that
re-hashing the fixture `system/peer` under `content_hash_format = 0x01` succeeds,
pinning `012e64bbde…3eef5a69`. `ENTITY-CORE-PROTOCOL` §4.5a **item 1a** pins the
`system/peer` identity entity to the ECFv1-SHA-256 floor **unconditionally** — on
every connection, whatever the active format, whatever the peer's home format —
so that construction cannot exist. The vector now asserts the **refusal**.

Upstream's own note on the retirement is the part worth carrying, because this
harness was the thing it describes: the old vector *"stayed green only because the
verifier hand-built the entity instead of routing through the constructor that
would have refused it. A fixture that exercises a forbidden construction and
passes by bypassing the code that forbids it certifies the opposite of the rule"*
(`GUIDE-CONFORMANCE` §2.4a). `AgilitySpec` called `contentHash 1` — the raw digest
primitive — which is precisely that bypass.

What landed:

| | |
|---|---|
| Peer | `EntityCore.ContentHash.authorContentHash` — the §4.5a **authoring** entry point, as distinct from the `contentHash` digest primitive. Refuses `system/peer` under any non-floor format with `PeerEntityNotAtFloor`. `Identity.identityOfSeed` routes through it, so the pin is a constraint the peer's own authoring path EXECUTES rather than a property it happens to have. |
| Test | Both halves, per §2.4a — the refusal observed **through that constructor**, plus the positive half asserting the floor form still authors to the pin named by the vector's own `floor_form` field. Guarded by an assertion that the vector's `kind` is still `construct_reject`, so a re-vendor that inverts it back fails loudly instead of quietly testing nothing. |
| Coverage | The suite now asserts the corpus's full **id set**. A harness that reads vectors by name silently ignores any it was not written for; the corpus can grow, the green count stays the same, and nothing says a new pin went unmeasured. |

Regression-tested by planting the defect: with the floor check removed,
`authorContentHash` produces the 49-byte SHA-384 form and the example fails with
*"authored a system/peer under content_hash_format 1 (§4.5a item 1a forbids it);
got 49 bytes"*.

## 3. Uncovered-range selftests (codec-review heuristic)

`SelftestSpec`, 22 examples, all PASS:

- **Word64 above Int64** (the overflow spot): `2^64-1` → `1b ffffffffffffffff`;
  `2^63` → `1b 8000000000000000`; decode returns `VUInt maxBound` (NOT clamped).
- **nint full range**: `-1` → `20`; `-2^64` → `3b ffffffffffffffff`; round-trips.
- **Minimal-int rejection**: `1800`, `1817` rejected `NonCanonicalEcf`.
- **Base58 leading-zero**: all-zero → `1111` and back; `0x00`-prefixed payload
  round-trips; non-alphabet char rejected `BadBase58`.
- **Ed25519**: deterministic (same input → same sig); verify accepts; tampered
  message → `False`.
- **Recursive tag rejection (N2)**: bare tag, tag-in-array, tag-in-map-value,
  self-describe `0xd9d9f7` — all `TagRejected`.
- **Duplicate/out-of-order keys**: rejected `DuplicateKey`/`NonCanonicalEcf`.
- **Empty containers (N3)**: empty map → `0xA0`, empty array → `0x80`.

## 4. QuickCheck robustness properties (A-HS-002 — the lazy-eval asset)

`PropertySpec`, 4 properties × 100 cases each, all PASS:

- **round-trip**: `decode . encode == Right v` (NaN-excluded for `==`).
- **determinism**: re-encoding is byte-stable (`encode v == encode v`).
- **strictness**: `encode (force v) == encode v` — forcing the value (deepseq)
  does not change the bytes; no output depends on thunk timing.
- **wire idempotence**: `encode . decode . encode` is stable.

## 5. N1–N4 invariant coverage

| Inv | What | Covering test |
|-----|------|---------------|
| N1 | LEB128 varint framing (not fixed byte) | `peer_id.3` + `content_hash.4` (synthetic ≥0x80 multi-byte); agility Ed448 peer_id |
| N2 | Recursive major-type-6 tag rejection on decode | `tag_reject.1–5` + 4 selftest depth cases (bare/array/map/self-describe) |
| N3 | Empty map = `0xA0` | `length.2` + empty-container selftests (map→`0xA0`, array→`0x80`) |
| N4 | Entity byte-fidelity | decoder returns a strict `VBytes` slice of the input for byte strings; map order preserved-then-canonicalized at encode; `envelope.*` + agility `system_peer_entity` byte-equal |

## 6. Reproduce

From the repo root, on the host:

```
protocol-generator/haskell/run-s2.sh
```

That is the whole recipe. It runs sealed-offline (`--network=none`) against the
dependency closure vendored in the image, needs no host state, and was verified
2026-09-02 from a genuinely clean tree — `.cabal-home` and `dist-newstyle` both
moved aside first, because "it works here" is not the question an adopter is
asking.

**What this replaced, and why the replacement is the point.** The recipe that
stood here named `-e HOME=…/.cabal-home` — a **gitignored directory inside the
working tree**. A clone does not have it. The claim that followed it, *"Offline
(warm store, after the one networked resolve): build + test + exe all stay GREEN
(verified)"*, could therefore only ever have been true on the machine that
authored it, and it was not even true there: the store had been warmed for the
library closure and never for the test-suite closure, so `cabal test --offline`
failed to resolve hspec, QuickCheck and HUnit. **An image nobody rebuilds from
scratch is not a recipe, it is a local accident** — the same rule this repo
already applies to RPM pins, met here in a language package manager.

`containers/ghc-toolchain/Containerfile` now seeds `/opt/cabal-home` at image
build time from this peer's **own** `cabal.project.freeze` with
`--enable-tests`, and then re-resolves `--offline` to prove the closure is
complete. An unsatisfiable lockfile fails the IMAGE BUILD, which is the right
place to find out. `--enable-tests` is the load-bearing flag: without it the
resolve covers the library only, the image looks complete, the peer builds, and
only the gate is missing its dependencies.

`cabal.project.freeze` remains the committed lockfile (crypton 1.0.4,
bytestring 0.12.1.0, text 2.1.1, hspec 2.11.17, QuickCheck 2.15.0.1) and is the
single source the image derives from — never a restatement of the pins in the
Containerfile, which is how two copies drift.
