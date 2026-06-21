# entity-core-protocol-haskell — S2 Conformance Report

**Peer:** #8 (Haskell) · **Phase:** S2 (codec) ·
**Spec basis:** v7.74 · **Codec corpus:** v7.71 (byte-stable at v7.74) ·
**Status:** GREEN — **69/69 byte-identical**, agility corpus native, all
selftests + QuickCheck properties pass.

Toolchain: GHC 9.8.4, cabal-install 3.14.2.0, crypton 1.0.4 (pinned), in the
`entity-core-keystone/ghc-toolchain:latest` container. Built `-Wall -Werror`.
Self-contained gate (no live Go oracle at S2): the corpus carries its own
3-way-cross-blessed `canonical` bytes. Corpus sha256 verified by decoding
(`41d68d2d…6a052`), not assumed.

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

`AgilitySpec` against `agility-vectors-v1.cbor` (v7.71). Codec-reachable
Phase-1 vectors, **7/7 PASS** — all native via crypton (no FFI, no defer):

| Vector | Native primitive | Result |
|--------|------------------|--------|
| `key-type-ed448.1.pubkey` | Ed448 seed → 57-byte pubkey | byte-equal |
| `key-type-ed448.2.peer_id` | Ed448 peer_id (key_type 0x02, SHA-256-form) | base58-equal |
| `key-type-ed448.3.system_peer_entity` | system/peer ECF + SHA-256 content_hash | byte-equal |
| `key-type-ed448.4.signature` | deterministic Ed448 sig (114 B) | byte-equal |
| `hash-format-sha-384.1` | inherited SHA-256 content_hash pin | byte-equal |
| `hash-format-sha-384.2.rehash` | **SHA-384** content_hash (49 B = `0x01` + 48 B digest) | byte-equal |
| Ed448 peer-id payload cross-check | `[0x02,0x01] ‖ SHA256(pubkey)` structure | base58-equal |

Haskell is the **2nd peer to pass the agility corpus natively** (after Common
Lisp's pure-Lisp ironclad) and the **first from an audited C-backed library**
(crypton). The Phase-2 `matrix.*` cap-grant flows are protocol-surface
(S3/S4), out of codec scope; the 3 `varint`/`format-code` `decode_reject`
probes assert a §1.2 seed-table policy that lives at the peer/validate layer
(the codec's `contentHash` accepts any format code and defaults unknown codes
to SHA-256; rejection of unallocated codes is S4).

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

```
podman run --rm -v $PWD:/work:Z \
  -e HOME=/work/protocol-generator/haskell/.cabal-home \
  -w /work/protocol-generator/haskell \
  entity-core-keystone/ghc-toolchain:latest \
  sh -c 'cabal test'
```

Offline (warm store, after the one networked resolve — A-HS-005): add
`--network=none` and `--offline`; build + test + exe all stay GREEN
(verified). `cabal.project.freeze` is committed (pins the full closure;
crypton 1.0.4, bytestring 0.12.1.0, text 2.1.1, hspec 2.11.17,
QuickCheck 2.15.0.1).
