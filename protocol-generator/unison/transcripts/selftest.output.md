# entity-core-protocol-unison — pinned-invariant self-tests (N1–N4 + fixed-width)

Direct unit coverage for the pinned conformance invariants, complementing the
corpus gate (`conformance.md`). Each `>` watch prints its own PASS/FAIL so the
invariant is legible in the diffable output.

``` ucm
scratch/main> builtins.mergeio

  Done.

scratch/main> load src/Codec.u

  Loading changes detected in src/Codec.u.

  + type CodecError
  + type Value

  + atOr0               : [Nat] -> Nat -> Nat
  + bappend             : Bytes -> Bytes -> Bytes
  + buildHead           : Nat -> Nat -> Bytes
  + buildMap            : [(Value, Value)] -> Bytes
  + byteAt              : Bytes -> Nat -> Nat
  + bytesToText         : Bytes -> Text
  + concatBytes         : [Bytes] -> Bytes
  + decode              : Bytes -> Either CodecError Value
  + decodeArray         : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + decodeItem          : Bytes
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + decodeMap           : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + decodeSimpleOrFloat : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + doubleToF32Cand     : Nat -> Nat
  + doubleToHalfCand    : Nat -> Nat
  + encode              : Value -> Bytes
  + encodeFloatBits     : Nat -> Bytes
  + f32ToF64bits        : Nat -> Nat
  + foldl               : (b ->{g} a ->{g} b)
                          -> b
                          -> [a]
                          ->{g} b
  + fst2                : (a, b) -> a
  + halfToF64bits       : Nat -> Nat
  + highBit             : Nat -> Nat -> Nat
  + insertBy            : (a ->{g1} a ->{g} Boolean)
                          -> a
                          -> [a]
                          ->{g, g1} [a]
  + keyLt               : Bytes -> Bytes -> Boolean
  + lexLt               : Bytes
                          -> Bytes
                          -> Nat
                          -> Nat
                          -> Boolean
  + mapRight            : Either e a
                          -> (a ->{g} b)
                          ->{g} Either e b
  + maxN                : Nat -> Nat -> Nat
  + orderCheck          : Optional Bytes
                          -> Bytes
                          -> Either CodecError ()
  + rangeTo             : Nat -> Nat -> [Nat]
  + readArg             : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Nat, Nat)
  + readBE              : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Nat, Nat)
  + snd2                : (a, b) -> b
  + sortBy              : (a ->{g1} a ->{g} Boolean)
                          -> [a]
                          ->{g, g1} [a]
  + takeBytes           : Bytes
                          -> Nat
                          -> Nat
                          -> Either CodecError (Value, Nat)
  + varintDecode        : Bytes
                          -> Nat
                          -> Either CodecError (Nat, Nat)
  + varintEncode        : Nat -> Bytes

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Protocol.u

  Loading changes detected in src/Protocol.u.

  + b58AddByte        : [Nat] -> Nat -> [Nat]
  + base58Alphabet    : [Nat]
  + base58Encode      : Bytes -> Text
  + canonicalHashType : Nat -> Nat
  + contentHash       : Nat -> Text -> Value -> Bytes
  + countLeadingZeros : [Nat] -> Nat
  + derivePeerId      : Nat -> Bytes -> Text
  + ecfOfEntity       : Text -> Value -> Bytes
  + entityContentHash : Text -> Value -> Bytes
  + formatPeerId      : Nat -> Nat -> Bytes -> Text
  + reverseL          : [a] -> [a]

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.

scratch/main> load src/Ed25519.u

  Loading changes detected in src/Ed25519.u.

  + type Pt

  + addLimbs      : [Nat] -> [Nat] -> [Nat]
  + addPt         : Pt -> Pt -> Pt
  + base16limb    : Nat
  + basePt        : Pt
  + bitAtLimbs    : [Nat] -> Nat -> Nat
  + bitOfBytes    : Bytes -> Nat -> Nat
  + bxConst       : [Nat]
  + byConst       : [Nat]
  + clearLow3     : Nat -> Nat
  + compress      : Pt -> Bytes
  + csubP         : [Nat] -> [Nat]
  + d2Const       : [Nat]
  + dConst        : [Nat]
  + ed25519Pub    : Bytes -> Bytes
  + ed25519Sign   : Bytes -> Bytes -> Bytes
  + ed25519Verify : Bytes -> Bytes -> Bytes -> Boolean
  + fadd          : [Nat] -> [Nat] -> [Nat]
  + feByteAt      : [Nat] -> Nat -> Nat
  + feOne         : [Nat]
  + feToBytesLE   : [Nat] -> Bytes
  + feZero        : [Nat]
  + finv          : [Nat] -> [Nat]
  + fmul          : [Nat] -> [Nat] -> [Nat]
  + fold38        : [Nat] -> [Nat]
  + fsqr          : [Nat] -> [Nat]
  + fsub          : [Nat] -> [Nat] -> [Nat]
  + geLimb        : [Nat] -> [Nat] -> Boolean
  + idPt          : Pt
  + mulCols       : [Nat] -> [Nat] -> [Nat]
  + normalize     : [Nat] -> [Nat]
  + pad16         : [Nat] -> [Nat]
  + pConst        : [Nat]
  + pExp          : [Nat]
  + Pt.pt         : Pt -> [Nat]
  + Pt.pt.modify  : ([Nat] ->{g} [Nat]) -> Pt ->{g} Pt
  + Pt.pt.set     : [Nat] -> Pt -> Pt
  + Pt.px         : Pt -> [Nat]
  + Pt.px.modify  : ([Nat] ->{g} [Nat]) -> Pt ->{g} Pt
  + Pt.px.set     : [Nat] -> Pt -> Pt
  + Pt.py         : Pt -> [Nat]
  + Pt.py.modify  : ([Nat] ->{g} [Nat]) -> Pt ->{g} Pt
  + Pt.py.set     : [Nat] -> Pt -> Pt
  + Pt.pz         : Pt -> [Nat]
  + Pt.pz.modify  : ([Nat] ->{g} [Nat]) -> Pt ->{g} Pt
  + Pt.pz.set     : [Nat] -> Pt -> Pt
  + reduceP       : [Nat] -> [Nat]
  + scaleLimbs    : Nat -> [Nat] -> [Nat]
  + setHigh       : Nat -> Nat
  + smul          : Bytes -> Pt
  + subLimbs      : [Nat] -> [Nat] -> [Nat]

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.
```

``` unison
hx : Bytes -> Text
hx b = bytesToText (Bytes.toBase16 b)

fromHx : Text -> Bytes
fromHx h = match Bytes.fromBase16 (Text.toUtf8 h) with
  Right b -> b
  Left _ -> Bytes.empty

chk : Text -> Boolean -> Text
chk label ok = (if ok then "PASS " else "FAIL ") Text.++ label

rejects : Text -> Boolean
rejects h = match decode (fromHx h) with
  Left _ -> true
  Right _ -> false

roundtrips : Text -> Boolean
roundtrips h = match decode (fromHx h) with
  Right v -> (hx (encode v)) == h
  Left _ -> false

-- N1 — varint framing is real LEB128, not a fixed byte (codes >= 0x80 extend).
> chk "N1 varint 128 -> 8001" ((hx (varintEncode 128)) == "8001")
> chk "N1 varint 300 -> ac02" ((hx (varintEncode 300)) == "ac02")
> chk "N1 varint 127 -> 7f (1 byte)" ((hx (varintEncode 127)) == "7f")

-- N2 — recursive major-type-6 tag rejection at ANY depth (not just top level).
> chk "N2 tag top-level 55799" (rejects "d9d9f7a0")
> chk "N2 tag inside array elem" (rejects "81c001")
> chk "N2 tag nested in map value" (rejects "a1616bc001")

-- N3 — empty map pins to the single byte 0xA0 (and empty array to 0x80).
> chk "N3 empty map == a0" ((hx (encode (VMap []))) == "a0")
> chk "N3 empty array == 80" ((hx (encode (VArray []))) == "80")

-- N4 — entity fidelity: decode->encode is byte-identical for canonical input
--      (no lossy re-serialization); byte strings forwarded verbatim.
> chk "N4 fidelity: entity round-trips" (roundtrips "a26464617461a261610161626374776f647479706567746573742f7631")
> chk "N4 fidelity: bytes verbatim" (roundtrips "44deadbeef")

-- Fixed-width self-test [2^63, 2^64-1] (A-UN-003): the high-bit-set uint64 head
-- form, and the largest nint magnitude (-2^64) that Int cannot hold but VNInt's
-- Nat argument carries.
> chk "FW uint 2^63 head" ((hx (encode (VUInt 9223372036854775808))) == "1b8000000000000000")
> chk "FW uint 2^64-1 head" ((hx (encode (VUInt 18446744073709551615))) == "1bffffffffffffffff")
> chk "FW uint 2^64-1 round-trip" (roundtrips "1bffffffffffffffff")
> chk "FW nint -2^64 (max magnitude)" ((hx (encode (VNInt 18446744073709551615))) == "3bffffffffffffffff")
> chk "FW nint -2^64 round-trip" (roundtrips "3bffffffffffffffff")
```

``` ucm :added-by-ucm
  Loading changes detected in scratch.u.

  + chk        : Text -> Boolean -> Text
  + fromHx     : Text -> Bytes
  + hx         : Bytes -> Text
  + rejects    : Text -> Boolean
  + roundtrips : Text -> Boolean

  Run `update` to apply these changes to your codebase.

    23 | > chk "N1 varint 128 -> 8001" ((hx (varintEncode 128)) == "8001")
           ⧩
           "PASS N1 varint 128 -> 8001"

    24 | > chk "N1 varint 300 -> ac02" ((hx (varintEncode 300)) == "ac02")
           ⧩
           "PASS N1 varint 300 -> ac02"

    25 | > chk "N1 varint 127 -> 7f (1 byte)" ((hx (varintEncode 127)) == "7f")
           ⧩
           "PASS N1 varint 127 -> 7f (1 byte)"

    28 | > chk "N2 tag top-level 55799" (rejects "d9d9f7a0")
           ⧩
           "PASS N2 tag top-level 55799"

    29 | > chk "N2 tag inside array elem" (rejects "81c001")
           ⧩
           "PASS N2 tag inside array elem"

    30 | > chk "N2 tag nested in map value" (rejects "a1616bc001")
           ⧩
           "PASS N2 tag nested in map value"

    33 | > chk "N3 empty map == a0" ((hx (encode (VMap []))) == "a0")
           ⧩
           "PASS N3 empty map == a0"

    34 | > chk "N3 empty array == 80" ((hx (encode (VArray []))) == "80")
           ⧩
           "PASS N3 empty array == 80"

    38 | > chk "N4 fidelity: entity round-trips" (roundtrips "a26464617461a261610161626374776f647479706567746573742f7631")
           ⧩
           "PASS N4 fidelity: entity round-trips"

    39 | > chk "N4 fidelity: bytes verbatim" (roundtrips "44deadbeef")
           ⧩
           "PASS N4 fidelity: bytes verbatim"

    44 | > chk "FW uint 2^63 head" ((hx (encode (VUInt 9223372036854775808))) == "1b8000000000000000")
           ⧩
           "PASS FW uint 2^63 head"

    45 | > chk "FW uint 2^64-1 head" ((hx (encode (VUInt 18446744073709551615))) == "1bffffffffffffffff")
           ⧩
           "PASS FW uint 2^64-1 head"

    46 | > chk "FW uint 2^64-1 round-trip" (roundtrips "1bffffffffffffffff")
           ⧩
           "PASS FW uint 2^64-1 round-trip"

    47 | > chk "FW nint -2^64 (max magnitude)" ((hx (encode (VNInt 18446744073709551615))) == "3bffffffffffffffff")
           ⧩
           "PASS FW nint -2^64 (max magnitude)"

    48 | > chk "FW nint -2^64 round-trip" (roundtrips "3bffffffffffffffff")
           ⧩
           "PASS FW nint -2^64 round-trip"
```
