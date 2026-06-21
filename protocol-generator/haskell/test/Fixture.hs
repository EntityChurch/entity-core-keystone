{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Conformance-fixture loader + per-vector runner.
--
-- Loads @conformance-vectors-v1.cbor@ (the canonical-ECF-encoded corpus the Go ×
-- Rust × Python oracles cross-blessed) with OUR OWN decoder — the fixture is
-- pure ECF (no tags), so a green load is itself a smoke test of the decoder.
-- Each vector is a map @{id, description, kind, input?, canonical}@. For
-- @encode_equal@ we re-produce the canonical bytes per category and compare; for
-- @decode_reject@ we feed @canonical@ to the decoder and assert rejection.
--
-- This module reads ONLY the fixture-parsing mechanics from the corpus shape
-- (per the cohort convention) — never codec logic from a sibling.
module Fixture
  ( Vector (..)
  , loadVectors
  , runVector
  , vectorCategory
  ) where

import qualified Data.ByteString as BS
import Data.List (find)
import qualified Data.Text as T
import Data.Text (Text)
import qualified Data.Text as Text

import EntityCore.Codec.CBOR (decode, encode)
import EntityCore.Codec.Value (Value (..))
import EntityCore.ContentHash (contentHash, ecfOfEntity)
import EntityCore.PeerId (PeerIdParts (..), formatPeerId)
import EntityCore.Signature (ed25519Sign)

-- | One conformance vector, decoded from the corpus.
data Vector = Vector
  { vId :: !Text
  , vKind :: !Text
  , vInput :: !(Maybe Value)
  , vCanonical :: !BS.ByteString
  }
  deriving (Show)

-- | Category prefix (text before the first dot in the id).
vectorCategory :: Vector -> Text
vectorCategory v = Text.takeWhile (/= '.') (vId v)

-- | Load + parse the corpus file. The top level is a CBOR array of vector maps.
loadVectors :: FilePath -> IO (Either String [Vector])
loadVectors path = do
  raw <- BS.readFile path
  case decode raw of
    Left e -> pure (Left ("fixture decode failed: " ++ show e))
    Right (VArray items) -> pure (traverse parseVector items)
    Right other -> pure (Left ("fixture root not an array: " ++ take 60 (show other)))

parseVector :: Value -> Either String Vector
parseVector (VMap kvs) = do
  vid <- textField "id"
  vkind <- textField "kind"
  canon <- bytesField "canonical"
  let !minput = lookupField "input"
  Right (Vector vid vkind minput canon)
  where
    lookupField name = snd <$> find (\(k, _) -> k == VText name) kvs
    textField name = case lookupField name of
      Just (VText t) -> Right t
      _ -> Left ("vector missing text field " ++ T.unpack name)
    bytesField name = case lookupField name of
      Just (VBytes b) -> Right b
      _ -> Left ("vector missing bytes field " ++ T.unpack name)
parseVector other = Left ("vector not a map: " ++ take 60 (show other))

-- | Field accessor over a decoded map.
mget :: Text -> [(Value, Value)] -> Maybe Value
mget name kvs = snd <$> find (\(k, _) -> k == VText name) kvs

-- | Run one vector, returning @Right ()@ on pass or @Left reason@ on failure.
runVector :: Vector -> Either String ()
runVector v
  | vKind v == "decode_reject" =
      case decode (vCanonical v) of
        Left _ -> Right ()
        Right _ -> Left "decoder ACCEPTED a decode_reject vector"
  | otherwise = do
      produced <- produce v
      if produced == vCanonical v
        then Right ()
        else Left ("byte mismatch\n    want " ++ hex (vCanonical v) ++ "\n    got  " ++ hex produced)

-- | Produce the canonical bytes for an @encode_equal@ vector per its category.
produce :: Vector -> Either String BS.ByteString
produce v =
  let cat = vectorCategory v
   in case vInput v of
        Nothing -> Left "encode_equal vector has no input"
        Just input -> case cat of
          "content_hash" -> produceContentHash input
          "peer_id" -> producePeerId input
          "signature" -> produceSignature input
          -- float / int / map_keys / length / primitive / nested / envelope:
          -- re-encode the decoded input value canonically.
          _ -> Right (encode input)

produceContentHash :: Value -> Either String BS.ByteString
produceContentHash (VMap kvs) = do
  typ <- need "type" >>= asText
  let dataV = maybe VNull id (mget "data" kvs)
      fmtCode = case mget "format_code" kvs of
        Just (VUInt n) -> toInteger n
        _ -> 0
  either (Left . show) Right (contentHash fmtCode typ dataV)
  where
    need name = maybe (Left ("content_hash input missing " ++ T.unpack name)) Right (mget name kvs)
    asText (VText t) = Right t
    asText _ = Left "content_hash type not text"
produceContentHash _ = Left "content_hash input not a map"

producePeerId :: Value -> Either String BS.ByteString
producePeerId (VMap kvs) = do
  kt <- need "key_type" >>= asUInt
  ht <- need "hash_type" >>= asUInt
  digest <- need "digest" >>= asBytes
  let !pid = formatPeerId (PeerIdParts kt ht digest)
  -- canonical bytes are the ECF encoding of the peer-id text string.
  Right (encode (VText (decodeAsciiText pid)))
  where
    need name = maybe (Left ("peer_id input missing " ++ T.unpack name)) Right (mget name kvs)
    asUInt (VUInt n) = Right (toInteger n)
    asUInt _ = Left "peer_id component not a uint"
    asBytes (VBytes b) = Right b
    asBytes _ = Left "peer_id digest not bytes"
producePeerId _ = Left "peer_id input not a map"

produceSignature :: Value -> Either String BS.ByteString
produceSignature (VMap kvs) = do
  seed <- need "seed" >>= asBytes
  entity <- need "entity"
  (typ, dataV) <- entityParts entity
  -- The corpus signs over the ECF preimage (ECF{type,data}), NOT content_hash.
  let !msg = ecfOfEntity typ dataV
  either (Left . show) Right (ed25519Sign seed msg)
  where
    need name = maybe (Left ("signature input missing " ++ T.unpack name)) Right (mget name kvs)
    asBytes (VBytes b) = Right b
    asBytes _ = Left "signature seed not bytes"
    entityParts (VMap ekvs) = do
      typ <- maybe (Left "entity missing type") Right (mget "type" ekvs)
      let dataV = maybe VNull id (mget "data" ekvs)
      case typ of
        VText t -> Right (t, dataV)
        _ -> Left "entity type not text"
    entityParts _ = Left "signature entity not a map"
produceSignature _ = Left "signature input not a map"

-- | Interpret an ASCII 'BS.ByteString' (a Base58 peer id) as 'Text'.
decodeAsciiText :: BS.ByteString -> Text
decodeAsciiText = T.pack . map (toEnum . fromIntegral) . BS.unpack

hex :: BS.ByteString -> String
hex = concatMap (\b -> let s = showHexByte b in s) . BS.unpack
  where
    showHexByte b =
      let hi = b `div` 16
          lo = b `mod` 16
       in [hexDigit hi, hexDigit lo]
    hexDigit n
      | n < 10 = toEnum (fromEnum '0' + fromIntegral n)
      | otherwise = toEnum (fromEnum 'a' + fromIntegral n - 10)
