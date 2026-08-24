# entity-core-protocol-unison — ECF conformance harness (S2 gate)

Headless byte-identity harness over the pinned **v0.8.0** ECF corpus (71 vectors).
Loads `src/*.u` + the embedded corpus, then asserts, per vector:

  - `encode_equal` — `encode`/construct the `input` produces byte-identical `canonical`;
  - `decode_reject` — the decoder REJECTS the `canonical` wire bytes.

The corpus is decoded with OUR decoder (a load-time decoder smoke test) and its
SHA-256 re-derived and checked against the MANIFEST pin (drift fails loudly).
Ground truth is the shared fixture; this run is the `wire-conformance` equivalent
for a substrate the Go oracle cannot drive directly. Agility (Ed448/SHA-384) is
scoped OUT (A-UN-001).

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

scratch/main> load src/Corpus.u

  Loading changes detected in src/Corpus.u.

  + corpusBase16 : Text
  + corpusSha    : Text

  Run `update` to apply these changes to your codebase.

scratch/main> add

  Done.
```

``` unison
tcat : Text -> Text -> Text
tcat a b = a Text.++ b

notB : Boolean -> Boolean
notB b = if b then false else true

mapGet : Text -> [(Value, Value)] -> Optional Value
mapGet k kvs = match kvs with
  [] -> None
  pair +: rest -> if (fst2 pair) == VText k then Some (snd2 pair) else mapGet k rest

optText : Optional Value -> Text
optText o = match o with
  Some (VText t) -> t
  _ -> ""

optNat : Optional Value -> Nat
optNat o = match o with
  Some (VUInt n) -> n
  _ -> 0

optBytes : Optional Value -> Bytes
optBytes o = match o with
  Some (VBytes b) -> b
  _ -> Bytes.empty

optVal : Optional Value -> Value
optVal o = match o with
  Some v -> v
  None -> VNull

startsWith : Text -> Text -> Boolean
startsWith pre s =
  pb = Text.toUtf8 pre
  sb = Text.toUtf8 s
  if (Bytes.size sb) >= (Bytes.size pb) then (Bytes.take (Bytes.size pb) sb) == pb else false

produce : Text -> Value -> Bytes
produce vid input =
  if startsWith "content_hash." vid then
    match input with
      VMap kvs -> contentHash (optNat (mapGet "format_code" kvs)) (optText (mapGet "type" kvs)) (optVal (mapGet "data" kvs))
      _ -> Bytes.empty
  else if startsWith "peer_id." vid then
    match input with
      VMap kvs -> encode (VText (formatPeerId (optNat (mapGet "key_type" kvs)) (optNat (mapGet "hash_type" kvs)) (optBytes (mapGet "digest" kvs))))
      _ -> Bytes.empty
  else if startsWith "signature." vid then
    match input with
      VMap kvs ->
        seed = optBytes (mapGet "seed" kvs)
        match mapGet "entity" kvs with
          Some (VMap ekvs) -> ed25519Sign seed (ecfOfEntity (optText (mapGet "type" ekvs)) (optVal (mapGet "data" ekvs)))
          _ -> Bytes.empty
      _ -> Bytes.empty
  else encode input

runOne : Value -> Boolean
runOne v = match v with
  VMap kvs ->
    kind = optText (mapGet "kind" kvs)
    canon = optBytes (mapGet "canonical" kvs)
    if kind == "decode_reject" then
      match decode canon with
        Left _ -> true
        Right _ -> false
    else (produce (optText (mapGet "id" kvs)) (optVal (mapGet "input" kvs))) == canon
  _ -> false

vecId : Value -> Text
vecId v = match v with
  VMap kvs -> optText (mapGet "id" kvs)
  _ -> "?"

corpusBytes : Bytes
corpusBytes = match Bytes.fromBase16 (Text.toUtf8 corpusBase16) with
  Right b -> b
  Left _ -> Bytes.empty

vectors : [Value]
vectors = match decode corpusBytes with
  Right (VArray xs) -> xs
  _ -> []

results : [(Text, Boolean)]
results = List.map (v -> (vecId v, runOne v)) vectors

countPass : Nat
countPass = foldl (acc r -> if snd2 r then acc + 1 else acc) 0 results

failIds : [Text]
failIds = foldl (acc r -> if snd2 r then acc else acc :+ (fst2 r)) [] results

shaHex : Text
shaHex = bytesToText (Bytes.toBase16 (crypto.hashBytes crypto.HashAlgorithm.Sha2_256 corpusBytes))

summary : Text
summary =
  tcat (tcat (tcat (tcat "PASS " (Nat.toText countPass)) "/") (Nat.toText (List.size vectors)))
       (tcat (tcat "  sha_ok=" (if shaHex == corpusSha then "true" else "false"))
             (tcat "  vectors=" (Nat.toText (List.size vectors))))

> summary
> failIds
```

``` ucm :added-by-ucm
  Loading changes detected in scratch.u.

  + corpusBytes : Bytes
  + countPass   : Nat
  + failIds     : [Text]
  + mapGet      : Text -> [(Value, Value)] -> Optional Value
  + notB        : Boolean -> Boolean
  + optBytes    : Optional Value -> Bytes
  + optNat      : Optional Value -> Nat
  + optText     : Optional Value -> Text
  + optVal      : Optional Value -> Value
  + produce     : Text -> Value -> Bytes
  + results     : [(Text, Boolean)]
  + runOne      : Value -> Boolean
  + shaHex      : Text
  + startsWith  : Text -> Text -> Boolean
  + summary     : Text
  + tcat        : Text -> Text -> Text
  + vecId       : Value -> Text
  + vectors     : [Value]

  Run `update` to apply these changes to your codebase.

    103 | > summary
            ⧩
            "PASS 71/71  sha_ok=true  vectors=71"

    104 | > failIds
            ⧩
            []
```
