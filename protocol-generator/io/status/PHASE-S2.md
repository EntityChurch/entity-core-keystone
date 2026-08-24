# entity-core-protocol-io — Phase S2 summary (COMPLETE)

**Phase:** S2 (codec)
**Date:** 2026-07-15
**Status:** ✅ COMPLETE — **wire corpus 71/71 byte-identical, 0 fail.**

## What was built

The **EntityCodec Io addon** (`src/entitycodec/IoEntityCodec.c` +
`IoEntityCodecInit.c` + `io/A0_EntityCodec.io`), compiled exactly like the
hand-built Socket addon (the S1-proven pattern) and installed at
`~/.eerie/base/addons/EntityCodec`. Two halves per the profile's
`ffi-addon-hybrid` strategy:

1. **Canonical CBOR (ECF)** — hand-rolled encoder + strict-canonical decoder in
   the addon C, operating directly on Io values: minimal-head (Rule 1),
   length-then-lex map-key sort (Rule 2), definite lengths (Rule 3),
   shortest-float ladder incl. f16 + canonical NaN/±0/±Inf (Rules 4/4a),
   dup-key reject (Rule 5), recursive major-type-6 tag reject (N2), full-consume,
   UTF-8 validation. N1 (LEB128 varint framing) and N3 (`0xA0` empty map) covered.
2. **Crypto / content-hash / peer-id** — delegated to `libentitycore_codec`
   (the C-ABI): `ec_sha256/384`, `ec_ed25519_{seed_to_pubkey,sign,verify}`,
   `ec_content_hash(_with_format)`, `ec_peerid_{format,parse}`. Provenance
   (`ec_impl_info`): `c 0.1.0 / ecf-c-abi 1.1 / libsodium 1.0.22 / …`.

## Value model (A-IO-001 resolved)

The explicit CBOR value model (`EcMap`/`EcBytes`/`EcBig`/`EcFloat`/`EcNull`)
answers the double-typed-number trap: `Number` always means an exact integer
(|x| ≤ 2^53); ints beyond ride `EcBig` (sign + 8-byte magnitude), self-tested on
the **uint64 tower** (`int.*` corpus incl. 2^63−1, 2^63, 2^64−1) — all pass via
EcBig, no fixed-width fold. Byte-vs-text is explicit (`EcBytes` never inferred
from a Sequence). Two Io-specific quirks surfaced and were fixed:
- **-0.0** (float.2): Io's Number cache folds −0.0 → +0.0, so the sign of zero
  rides an explicit `negZero` slot on EcFloat across the seam.
- **SIOSYMBOL vs IOSYMBOL** in the addon init glue (IoState vs IoObject arg).

## Gate

```
./run-s2.sh   # container-bound, --network=none → make smoke && make s2
corpus: 71 vectors loaded (decoder survived the fixture — E.3)
category            P    F
float             14   0     int            14   0     length            8   0
map_keys           6   0     primitive       6   0     nested            6   0
tag_reject         5   0     content_hash    4   0     peer_id           3   0
signature          3   0     envelope        2   0
TOTAL: 71 pass / 0 fail / 71 vectors → S2 GATE: PASS
```

Plus `test/typecheck.io` — the §9.5 **53-type floor renders byte-identical to the
oracle's type-registry vectors (53/53, 0 drift)** — render-from-model, verified
before S4.

## Exit criteria — MET

Wire-conformance byte-identical (71/71); the decoder loads the fixture (E.3);
codec module compiles clean; type floor 0-drift. → S3.

## Findings

No spec-precision finding at S2 — the ECF spec is precise enough to oblige the
explicit Io value model with no leak into ad-hoc convention (the double-trap and
byte-vs-text seams resolve into the wrapper model, A-IO-001/006/009). Corroborates
the fixed-width-class lesson on a NEW combination (double-typed dynamic language).
