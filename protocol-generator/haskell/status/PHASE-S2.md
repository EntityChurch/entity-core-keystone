# entity-core-protocol-haskell — Phase S2 Summary

**Peer:** #8 (Haskell) · **Phase:** S2 (codec + types) ·
**Spec basis:** v7.74 · **Codec corpus:** v7.71 · **Status:** COMPLETE — GREEN.

Native hand-rolled canonical ECF codec + crypton crypto. **69/69 byte-identical**
on the ECF conformance corpus, **first build**, with **ZERO codec-logic fixes**
(the 8th consecutive native-peer A-005 confirmation). Plus the native-Ed448 +
SHA-384 agility corpus (7/7, the headline crypto data point), 22 uncovered-range
selftests, and 4 QuickCheck robustness properties (the lazy-eval asset).

---

## Modules (`src/EntityCore/`)

| Module | Responsibility |
|--------|----------------|
| `Codec/Error.hs` | `CodecError` ADT (`NonCanonicalEcf`/`Truncated`/`TagRejected`/`DuplicateKey`/…); `NFData` |
| `Codec/Value.hs` | The ECF value model (`StrictData`); `VUInt`/`VNInt` carry **full Word64** range |
| `Codec/Varint.hs` | LEB128 multicodec varint encode/decode (N1); minimal-form enforced on decode |
| `Codec/Float.hs` | Shortest-form float ladder f16/f32/f64 (Rule 4/4a); round-trip-exactness check |
| `Codec/CBOR.hs` | Canonical ECF encode (Builder→strict force) + decode (canonical-enforcing, N2/N3) |
| `Codec.hs` | Public re-export surface |
| `ContentHash.hs` | `varint(fmt) ‖ HASH(ECF{type,data})`; SHA-256 floor + SHA-384/512 (crypton) |
| `Base58.hs` | Bitcoin-alphabet encode/decode, leading-zero-preserving byte long-division |
| `PeerId.hs` | `Base58(varint(kt)‖varint(ht)‖digest)` format/parse + `derivePeerId` (§1.5 table) |
| `Signature.hs` | Ed25519 (floor) + **native Ed448** (agility) sign/verify via crypton |

Test surface (`test/`): `Fixture.hs` (corpus loader + per-vector runner),
`ConformanceSpec.hs` (the 69-vector gate + sha256 pin check), `SelftestSpec.hs`
(uncovered ranges), `PropertySpec.hs` (QuickCheck), `AgilitySpec.hs` (Ed448 +
SHA-384). Standalone runner `app/Main.hs` (`cabal run conformance-exe`).

## Build fixes — Haskell/GHC mechanics ONLY (no codec-correctness fix)

The codec produced byte-identical output on the **first successful compile**.
Every pre-green edit was GHC/Cabal mechanics, not codec logic:

1. **`OverloadedStrings` pragma** on `Base58.hs` (the alphabet is a `ByteString`
   literal). — language mechanics.
2. **`memory` + `crypton`** added to the *test-suite* build-depends (the
   in-test SHA-256 pin re-derivation imports `Crypto.Hash`/`Data.ByteArray`). — deps.
3. **`-Werror=incomplete-uni-patterns`** tripped lazy `let Right pk = …` test
   bindings → rewrote as `case`. — `-Werror` hygiene, test-only.
4. **`-Wno-orphans`** on `PropertySpec` (the `Arbitrary Value` generator is an
   orphan by design — `Value` is in the library, the generator + its canonical
   constraints belong in the test). — test-only.
5. Redundant imports / unused local binds removed (`-Wall -Werror`). — hygiene.

Crypton initially resolved to **1.0.6** (the recent index-state floats to the
newest). Pinned **`crypton ==1.0.4`** (+ `memory ==0.18.0`, `basement ==0.0.16`)
via `cabal.project` `constraints` so the profile/S11 authority holds; recorded
exactly in the committed `cabal.project.freeze`.

## A-HS-002 — lazy-evaluation / strictness evidence (THE Haskell impl-finding surface)

The headline watch-item. Where laziness was defeated, and the **concrete
evidence** that it mattered (a probe, not precaution):

1. **UTF-8 byte-length vs code-point length (the wire-corrupting trap).** The
   CBOR text head MUST carry the UTF-8 *byte* count, computed via
   `Data.Text.Encoding.encodeUtf8` then `BS.length`. **Probe:** the string
   `"héllo☃"` has **6 code points but 9 UTF-8 bytes** (`é`=2, `☃`=3); the encoder
   emits the **9-byte** length. A naive `Data.Text.length` (the obvious call)
   would have emitted **6** → a silently corrupt wire form + wrong content_hash.
   This is the single most dangerous Haskell-idiom trap and it is enforced in
   `Codec/CBOR.hs` (`buildValue (VText t)`) + cross-checked by the probe.

2. **Strict encode accumulator.** `encode` builds a `Data.ByteString.Builder`
   and **forces it to a strict `ByteString`** (`BL.toStrict … |> bang-bind`).
   Lazy `ByteString` chunks would defer + retain the input through the fold; the
   strict force means no builder thunk escapes. A 5000-key map encodes + forces
   to 54725 bytes cleanly (probe).

3. **Map-key sort over FORCED encoded bytes.** `buildMap` bang-materialises each
   `(encodedKey, encodedValue)` pair *before* `sortBy`, with the sort key the
   forced `(length, bytes)`. If the encoded-key bytes were a thunk, the sort
   would still be correct (pure) but every comparison would re-force the same
   thunk and the encoder would retain the unencoded `Value` tree — a space leak.
   Forcing up front makes the sort O(n log n) over already-computed bytes.

4. **Strict decode cursor + strict fields.** The decoder threads its cursor as a
   strict `ByteString` slice, bang-binds each `(value, rest)` step, and every
   `Value` constructor is strict (`StrictData`), so a decoded structure does not
   retain the input buffer through a chain of thunks.

5. **QuickCheck `strictness` property:** `encode (force v) == encode v` over 100
   arbitrary values — proves no output byte depends on whether the value was
   forced (i.e. the codec output is thunk-timing-independent).

**Finding:** there is **no lazy-evaluation *correctness* hazard hiding in a naive
codec** here — the one genuine correctness trap a naive Haskeller WOULD hit is
the `Text.length`-vs-UTF-8-byte-count confusion (flagged loudly above), and that
is a *string-length* bug, not strictly a laziness bug. The remaining strictness
work is **space-leak / determinism hygiene**, not correctness: a fully-lazy
encoder would still produce the right bytes, but would leak the input tree and
re-force encoded keys during the sort. So A-HS-002 lands as **"strictness is a
performance + space-safety discipline, plus one UTF-8 string-length correctness
trap"** — no surprising lazy-eval *wrong-bytes* hazard. Reusable generator
guidance for any future lazy/non-strict language: (a) byte-length of text is
always `encodeUtf8`-bytes, never the language's string length; (b) force the
encode accumulator; (c) materialize map-sort keys strictly.

## N1–N4 coverage

- **N1** (LEB128 not fixed byte): real `varintEncode`/`varintDecode` primitives;
  all format-code/key-type/hash-type framing routes through them. Covered by
  `peer_id.3` + `content_hash.4` (synthetic ≥0x80 multi-byte) and the native
  Ed448 peer_id. Decode enforces minimal (no trailing-zero group).
- **N2** (recursive tag rejection): explicit major-type-6 branch in `decodeItem`
  that rejects at ANY depth (the recursion visits every nested item). `tag_reject.1–5`
  + 4 selftest depth cases.
- **N3** (empty map `0xA0`): the canonical encoder emits `buildHead 5 0` = `0xA0`
  for `VMap []`; `length.2` + selftests pin it (and `0x80` for empty array).
- **N4** (entity fidelity): byte strings decode to a strict `VBytes` slice of the
  input; the decoder preserves decoded map order (and rejects non-canonical
  order so a re-encode is byte-stable). `envelope.*` + agility `system_peer_entity`
  prove byte-equality through the carrier shape.

## Spec-first observations / new findings

**No new spec contradiction surfaced at S2.** Reading the v7.74 ECF + §1.5/§7.3/§7.4
rules directly, the codec rules are unambiguous and the peer-id §7.4→§1.5
reconciliation (the E1 erratum) holds — Haskell is a 6th independent read landing
consistently (corroboration, not discovery; expected for a coverage peer). The
Ed448 SHA-256-form peer_id construction (`derivePeerId 0x02` → hash_type 0x01,
digest = SHA-256(pubkey)) matched the agility corpus `canonical_base58` first try,
corroborating the §1.5 size-cutoff convention across an 8th impl.

One **operator-level note (not a spec finding):** the agility `varint`/`format-code`
`decode_reject` probes (codes 128/255/0x42 → `unsupported_content_hash_format`)
test a §1.2 seed-table *policy* that is correctly a **peer/validate-layer**
responsibility, not a codec one — the codec's `contentHash` faithfully encodes
the multi-byte varint prefix and computes the digest; *rejecting* an unallocated
code is an S4 surface. Recorded as A-HS-008 (informational).

## S5 packaging follow-ups (NOT S2 blockers)

`cabal check` flags the standard Hackage-publish items deferred to S5: `-Werror`
must become a dev-only manual flag for distribution (the profile sets
`warnings_as_errors=true` for the dev/test profile — correct for S2/S3/S4); add a
`category:` field; move `CHANGELOG.md` to `extra-doc-files`. None affect
conformance.

## S3 entry checklist

1. **Codec is DONE + frozen.** 69/69 byte-identical, agility native, freeze
   committed; offline build verified. The pure `Either CodecError a` surface is
   the foundation S3 builds the peer on (status codes map at the module boundary).
2. **Concurrency enters now (A-HS-003):** green threads (`forkIO`) + STM (`TVar`)
   for the live store; `async` for structured concurrency; request_id↔continuation
   demux via `MVar`/`TVar`. The codec stays pure/synchronous underneath.
3. **IO boundary:** `Control.Exception`/`bracket`/`throwIO` appear ONLY at the
   transport edge (sockets) — never in the codec (A-HS-001). `no_partial_on_wire`
   holds: no `head`/`fromJust`/`!!` on wire data.
4. **§6.13 live hooks (v7.74):** register/unregister, handler outbound closure,
   emit pathway — built at S3 against the dispatcher seam (NOT stubbed; a
   501-stub is non-conformant under v7.74 A1).
5. **§7a/§7b conformance scaffolding (A-HS-006):** the `system/validate/{echo,
   dispatch-outbound}` handlers (`--validate` opt-in, off by default) + the §7b
   store-concurrency gate come from GUIDE-CONFORMANCE + the generator menu at
   S3/S4 — STM store is the natural §7b fit.
6. **Agility higher bar is already reachable** (Ed448 native, proven at S2) — the
   S4 validate-peer agility categories are in scope without an FFI detour.
