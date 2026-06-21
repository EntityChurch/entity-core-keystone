# entity-core-protocol-swift — Phase S2 Summary

**Peer:** #7 (Swift) · **Spec basis:** v7.74 · **Codec corpus:** v7.71 (valid at
v7.74; ECF byte-stable) · **Phase:** S2 (codec layer) ·
**Status:** COMPLETE — `wire-conformance` **69/69 PASS, byte-identical**; zero
codec-logic fixes; no blocking ambiguity items.

The S2 gate (the conformance corpus) is the ground truth (S5/S7). Swift derived
the ECF rules **spec-first** from `spec-data/v7.74/ENTITY-CBOR-ENCODING.md` (§3–§9,
Appendix E) + `ENTITY-CORE-PROTOCOL-V7.md` (§1.5/§7.1–§7.4) — not cribbed from
sibling codec source. The Zig harness was consulted only for the language-agnostic
fixture-parsing mechanics (record shape: `id`/`kind`/`input`/`canonical`; the
content_hash/peer_id/signature category dispatch), never for encoder math.

---

## Modules built (`Sources/EntityCoreProtocol/`)

| File | Responsibility |
|---|---|
| `CBORValue.swift` | The value model (enum) the codec operates over. `uint`(UInt64) / `nint`(UInt64, stores `n` for `-1-n`) / `bytes` / `text` / `array` / `map` / `float` / `bool` / `null`. Value type, `Sendable`, hand-written `Equatable` (float by bit-pattern so NaN==NaN, −0≠0). No tag case (tags aren't ECF). |
| `CodecError.swift` | Typed `throws(CodecError)` error enum, one case per rejection condition (nonCanonicalECF, truncated, tagRejected, duplicateKey, trailingBytes, malformed, invalidUTF8, badSeed, unsupportedHashFormat, unsupportedKeyType, invalidBase58, limitExceeded). Maps to status codes at the S3 boundary. |
| `Varint.swift` | Multicodec LEB128 encode/decode (N1). Single primitive routes all format-code / key_type / hash_type framing; rejects non-minimal + overlong. |
| `CBOR.swift` | Canonical ECF encode + decode. Minimal-int heads; length-then-lex map-key sort **over encoded `[UInt8]`**; duplicate-key reject (encode+decode); shortest-float ladder (f16-exact / f32-exact / f64) + Rule 4a specials; recursive major-type-6 tag reject (N2); non-minimal/indefinite/trailing reject; UTF-8 validation; depth limit 64 (§10.2). |
| `Base58.swift` | Bitcoin-alphabet encode+decode, byte long-division (no bignum), leading-zero preserving. |
| `ContentHash.swift` | `varint(format_code) ‖ HASH(ECF{type,data})`; SHA-256 floor + SHA-384/512 wired (agility). §4.4 construction-vs-verification asymmetry honored. Lowercase-hex display helper (§9.3 step 4). |
| `Signing.swift` | Deterministic Ed25519 (swift-crypto `Curve25519.Signing`); sign / verify / pubkey-from-seed; `Data` bridge only at the crypto edge. |
| `PeerID.swift` | `Base58(varint(key_type)‖varint(hash_type)‖digest)` format+parse round-trip; `fromEd25519` (key_type 0x01, identity-multihash, digest = raw 32-byte pubkey per §1.5/§7.4). |
| `Entity.swift` | `Entity` value type + `DecodedEntity` retaining `originalBytes` for fidelity-safe forwarding (N4). |

`Package.swift` + committed `Package.resolved` pin **swift-crypto 3.14.0** and
**swift-asn1 1.7.0** by exact version (A-SW-005: explicit older pin holds the S11
30-day floor — SwiftPM would otherwise float swift-asn1 to 1.7.1, ~6 days old).
Resolve verified: `Package.resolved` shows asn1 `1.7.0` / crypto `3.14.0`.

---

## Build fixes (Swift-API-mechanics vs codec-correctness)

**Codec-correctness fixes: ZERO.** The codec passed 66/69 on its first
execution; all encoder/decoder byte-paths were byte-identical first try.

Swift-API-mechanics fixes only (none touched codec logic):
1. **Spike:** `String(format:"%02x",…)` needs Foundation — replaced the hex helper
   with an ASCII-byte table lookup (no Foundation in the codec core).
2. **Signing.swift:** moved `import struct Foundation.Data` to file-top (Swift
   requires imports at file scope).
3. **Harness (test-side, NOT codec):** the `signature` category signs over the ECF
   preimage of `{type,data}`, not the content_hash — the established cross-peer
   corpus convention (A-SW-007). This took signature 0/3 → 3/3. A harness-semantics
   correction, not a codec change.
4. **Entity.swift:** `guard case let .map` → `guard case .map` (no-binding pattern
   warning) — cosmetic.

Release build (`swift build -c release`) is **clean** (the lone remaining warning
is SwiftPM noting swift-asn1 isn't directly target-referenced — expected; it's the
A-SW-005 transitive pin held explicitly). Offline build under `--network=none`
after resolve: **green** (profile `offline_after_resolve = true` honored).

---

## The spike (S2-entry gate, run BEFORE the full build)

A minimal hand-rolled ECF encoder pushed the **map_keys + float** vectors through
first: **20/20 byte-identical**. This de-risked the two highest-risk paths up front
— the float shortest-form ladder (incl. f16 subnormal exactness + f32 fallback +
Rule 4a specials) and the length-then-lex map-key sort over encoded bytes. The
`native` strategy was confirmed; the `ffi` fallback was not needed (6-for-6 prior
native peers + Swift = 7-for-7).

---

## A-SW-002 — the String-model probe (the headline Swift finding)

Swift `String` is grapheme-counted and not `Int`-indexable. The codec treats
`String` strictly as a UTF-8 carrier. Concrete codec-line evidence:

- **Text-string length = `String.utf8.count`, never `String.count`.** `CBOR.swift`
  `encode(.text)`: `let utf8 = Array(s.utf8); encodeHead(major: 3, arg:
  UInt64(utf8.count) …)`. A naive Swift dev writing `arg: UInt64(s.count)` would
  emit the **grapheme** count — wrong for any non-ASCII text. Proof:
  `testTextLengthIsUTF8BytesNotGraphemes` — `"café".count == 4` but
  `.utf8.count == 5`, so the text head is `0x65` (len 5), not `0x64` (len 4).
- **Map-key lexicographic sort over ENCODED `[UInt8]`, never `String` ordering.**
  `CBOR.swift` `encodeMap`: each key is first ECF-encoded to `[UInt8]`, then the
  sort compares `keyBytes.count` then `lexicographicallyLess(a.keyBytes,
  b.keyBytes)` — pure byte comparison. A naive Swift dev sorting `pairs.sorted { $0
  < $1 }` on the `String` keys would get Unicode-canonical / locale-aware ordering,
  which diverges from the wire. Proof: `testMapKeySortIsOverEncodedBytes…`.
- **Lowercase-hex digest display** (§7.4 line 823 / §9.3 step 4) goes through a
  byte-table `Hex.encode`, no `String(format:)` / locale.
- **No force-unwrap on wire data** (`[idiom].no_force_unwrap_on_wire`): every
  decode path is a checked `throws`; `readByte`/`readBytes` bounds-check and throw
  `.truncated`; `String(bytes:encoding:.utf8)` failure throws `.invalidUTF8`.

This is the highest-value cross-peer payoff: it is **reusable generator guidance**
for any future grapheme-counted-string language. The spec itself is unambiguous
(lengths/ordering are byte/UTF-8-oriented) — A-SW-002 is a generation-discipline
finding, not a spec gap.

---

## NEW spec finding — A-SW-007 (§7.3-vs-Appendix-E signature-message contradiction)

Surfaced this phase (escalated to **arch**). §7.3 NORMATIVE pseudocode says the
signed message is `entity.content_hash` (the 33-byte hash). The **normative**
Appendix E `signature` vectors sign the **ECF encoding of `{type,data}`** (the hash
*preimage*) — different bytes. The corpus wins (S5); §7.3's prose should be
tightened. This is a **textual contradiction between two normative surfaces** —
not a new *behavioral* discovery (the cross-peer cohort already builds to the
corpus, per the FFI session notes), but Swift is the first peer to
surface the §7.3-vs-Appendix-E tension explicitly in its log. Low interop risk;
real spec-quality finding. See `SPEC-AMBIGUITY-LOG.md` A-SW-007.

---

## N1–N4 coverage

- **N1 (LEB128 varints, not fixed bytes):** `Varint.swift` is the single primitive;
  `ContentHash`/`PeerID` route all format-code/key_type/hash_type framing through
  it. Multi-byte path proven by `content_hash.4` (format_code 128) + `peer_id.3`
  (key_type 128) + `testVarintMultiByte`.
- **N2 (recursive tag reject):** `CBOR.Decoder.decodeItem` major-type 6 → `throw
  .tagRejected`, hit at any nesting depth (the decoder recurses through
  arrays/maps). Proven by `tag_reject.1–5` (incl. the deep `included`-data case) +
  `testTagNestedInArray/MapValue/DeeplyNested`.
- **N3 (empty-map = `0xA0`):** `encodeMap` with 0 pairs emits `A0`. Proven by
  `length.2` + `testEmptyContainersCanonical` + the `content_hash.1` empty-data
  floor.
- **N4 (entity byte-fidelity):** `DecodedEntity.originalBytes` retains the exact
  wire bytes; forwarding uses originals, never a re-encode. (The decode surface is
  in place; forward-path exercise is an S3 peer concern.)

---

## S3-entry checklist

1. **Codec is done + green.** 69/69 byte-identical + 25 uncovered-range selftests
   all pass; offline release build clean. The codec modules are the foundation S3
   builds the peer machinery on.
2. **Error→status mapping** lives at the S3 module boundary (CodecError case →
   400/401/403). The codec only *names* conditions; the peer maps them.
3. **Async/concurrency enters at S3** (codec is synchronous + pure). Per profile:
   `actor` for per-connection serialized state; `async/await` +
   `withCheckedThrowingContinuation` for request_id↔continuation demux (N7); the
   §4.8/§6.11 inbound-concurrent-with-outbound requirement (N6). Reference types
   (`class`/`actor`) appear here for shared-mutable identity (Peer/conn graph);
   audit for retain cycles (`[memory].retain_cycle_risk`).
4. **§7a/§7b conformance scaffolding** (A-SW-006) is GUIDE-carried, picked up at
   S3/S4 — the `system/validate/{echo,dispatch-outbound}` handlers behind a
   `--validate` opt-in (off by default), and the §7b store concurrency gate.
5. **v7.74 extensibility foundations** (register/outbound/emit/owner-cap, §6.13/
   §6.9a) + `shared/seed-policy/` are S3 work.
6. **N4 forward-path, N5 (`included` preservation), N6, N7, N8** are S3/S4 peer
   invariants — pin now, enforce at peer build.
7. **Ed448 deferred** (A-SW-001) — Ed25519/SHA-256 floor is native + complete;
   agility (Ed448 via hybrid FFI, SHA-384) is a later higher-bar slot.
8. **Oracle:** `validate-peer --profile core` is the S4 ground truth; build the Go
   oracle + reference peer from go HEAD in-container (GOWORK=off) at S4.
