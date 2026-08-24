# entity-core-protocol-unison — Phase S2 Summary

**Peer:** #43 (Unison, operator-directed) · **Spec basis:** v0.8.0 / V8 ·
**Phase:** S2 (codec) · **Status:** COMPLETE — `Result: PASS 71·0F`, gate green,
no blocking ambiguity items. Container-bound, headless, `--network=none`.

Native, **builtins-only** canonical ECF codec hand-rolled in pure Unison over the UCM
`Bytes`/`Nat`/`crypto` runtime builtins (zero third-party dependency; `@unison/base`
NOT adopted). Ground truth is the pinned v0.8.0 corpus (Go `wire-conformance` cannot
drive Unison in-process); the headless `ucm transcript` harness IS the wire-conformance
equivalent for this substrate.

---

## Spike result (the S2 gate de-risk, per PHASE-S1)

Two spikes ran first, both in-container under caps:

1. **map_keys + float ECF round-trips** (the two historically hardest canonical rules) —
   PASS. `float.14` (1.1→f64 `fb3ff199999999999a`), `float.1/.2` (±0→f16), `float.7`
   (NaN→`f97e00`), `float.12` (65503→f32 `fa477fdf00`), `map_keys.1/.2` (length-then-lex
   over encoded key bytes) all reproduce byte-identically via the hand-rolled encoder.
   `Float.toRepresentation 1.1 = 4607632778762754458 = 0x3ff199999999999a` (matches the
   vector) — the shortest-float ladder is built on the raw IEEE-754 bits, as S1 planned.
2. **Ed25519 pubkey derivation** (the real risk — see Findings) — PASS against RFC 8032
   §7.1 Test-1 (`d75a9801…511a`, exact).

No canonical rule proved un-expressible in Unison builtins.

## Conformance verdict

```
Result: PASS — 71·0F   (71 PASS / 0 WARN / 0 FAIL / 0 SKIP)
sha_ok=true (corpus 9695b1f1…f7c6dc re-derived + checked)
```

Full per-category breakdown in `status/CONFORMANCE-REPORT.md`. Harness:
`transcripts/conformance.md` → golden `transcripts/conformance.output.md`
(`"PASS 71/71  sha_ok=true  vectors=71"`, `failIds = []`). Agility (Ed448/SHA-384)
honestly scoped OUT (A-UN-001) — not faked, not counted.

## N1–N4 + fixed-width coverage (each with a covering test)

Direct units in `transcripts/selftest.md` → `selftest.output.md` (all PASS), plus the
corpus vectors that exercise the same surfaces:

| Invariant | Baked in | Covering test |
|---|---|---|
| **N1** varint LEB128, not fixed byte | `varintEncode`/`varintDecode` (Codec.u); all format-code/key-type framing routes through it | `varint 128→8001`, `300→ac02`, `127→7f`; corpus `content_hash.4`, `peer_id.3` |
| **N2** recursive major-type-6 tag reject | `decodeItem` rejects major 6 at every recursion (arrays, map values, `included`) | `d9d9f7a0`, `81c001`, `a1616bc001`; corpus `tag_reject.1–5` |
| **N3** empty map == `0xA0` | `buildHead 5 0`; empty array == `0x80` | `encode (VMap []) == a0`, `encode (VArray []) == 80`; corpus `length.2`, `content_hash.1` |
| **N4** entity fidelity | decode→encode byte-identical for canonical input; `VBytes` verbatim | entity + bytes round-trip units; whole-corpus round-trip (S3 peer forwards original wire bytes) |
| **Fixed-width [2⁶³,2⁶⁴-1]** (A-UN-003) | `Nat` carries major-0 full range; nint magnitude rides as the wire arg in `VNInt` (Int too narrow) | `2⁶³→1b8000…`, `2⁶⁴-1→1bffff…`, nint `-2⁶⁴→3bffffffffffffffff` |

## What was built (`src/*.u`, builtins-only)

- **`Codec.u`** — `Value`/`CodecError` ADTs; canonical `encode` (map-key length-then-lex
  over encoded bytes, minimal int head, shortest f16/f32/f64 ladder incl. Rule 4a, definite
  lengths, `0xA0`/`0x80` empties); tag-rejecting/order-enforcing/minimal-enforcing `decode`;
  `varintEncode`/`varintDecode` (N1); shared prelude helpers.
- **`Protocol.u`** — `ecfOfEntity`, `contentHash` (`varint(fmt)‖SHA256(ECF)`), hand-rolled
  `base58Encode` (Bitcoin alphabet, leading-zero-preserving), `formatPeerId`/`derivePeerId`
  (§1.5 canonical form, A-UN-008).
- **`Ed25519.u`** — pure-Unison Ed25519 **key derivation** (GF(2²⁵⁵-19) field arithmetic in
  base-2¹⁶ `Nat` limbs + twisted-Edwards scalar mult + point compression) feeding the native
  `crypto.Ed25519.sign.impl`/`verify.impl` builtins (A-UN-009).
- **`Corpus.u`** — the v0.8.0 corpus embedded as base16 (verified mirror; sha-checked at run).
- **`transcripts/{build,conformance,selftest}.md`** — headless build + gate + invariant units.

## Findings / escalations

- **A-UN-009 (new)** — Ed25519 pubkey derivation is neither a UCM builtin nor an
  `@unison/base` primitive; the S1 "base has a wrapper" assumption was wrong. Resolved by
  in-band pure-Unison keygen (validated vs RFC 8032). Sharpens the no-C-FFI crypto-spectrum
  datum → research crypto ledger. NOT a spec finding.
- **No new spec defect** at S2 (expected — dry wire surface; coverage/generator-robustness
  peer). The canonical rules read unambiguously and reproduce byte-exact.
- **A-UN-001** agility defer holds (scoped OUT, honest SKIP; not gating).
- **Generator-robustness datum reinforced:** the whole codec builds + gates via headless
  `ucm transcript` on the content-addressed codebase, fully `--network=none` — no per-build
  pull, no file→compile→link loop.

## Unison-idiom notes (for the generator ratchet)

- **No `Nat` `-` operator** (unsigned): truncating subtraction is `Nat.drop`; `Nat.sub` →
  `Int`. `Nat.and`/`or`/`shiftLeft`/`shiftRight`/`pow` are builtins (used for bit surgery).
- **Qualified operators can't be prefix** (`Bytes.++ a b` / `Text.++ a b` fail): use infix
  or a named wrapper (`bappend`). Matches use newline-separated cases, not `|`. Multi-stmt
  lambdas must be extracted to named helpers.
- **`builtins.mergeio` first** in every transcript stanza-set; `Nat`/`Bytes`/etc. are not in
  scope otherwise. `load src/X.u` then `add` composes cross-file (deps must be added first).
- **Fixed-width discipline is load-bearing**, not cosmetic: field elements are 16×2¹⁶ limbs
  precisely because there is no 128-bit product; base-2¹⁶ keeps every partial product < 2⁶⁴.

## Not in S2 (deferred to later phases)

S3 peer machinery (abilities/fork concurrency, transport, dispatch, store), §7a validate
handlers, §7b store-concurrency gate, Ed448/SHA-384 agility (deferred, A-UN-001), Unison
Share packaging (S5).
