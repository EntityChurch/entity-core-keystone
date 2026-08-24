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

```ucm
scratch/main> builtins.mergeio
scratch/main> load src/Codec.u
scratch/main> add
scratch/main> load src/Protocol.u
scratch/main> add
scratch/main> load src/Ed25519.u
scratch/main> add
scratch/main> load src/Corpus.u
scratch/main> add
```

```unison
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
