{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StrictData #-}

-- | The materialized entity @{type, data, content_hash}@ (V7 §1.1, §3.4) and the
-- protocol envelope (§3.1). Sits directly on the S2 codec: 'entityHash' is
-- @varint(0x00) ‖ SHA-256(ECF{type,data})@ (the §9.1 floor) and entities
-- serialize through 'EntityCore.Codec.encode'.
--
-- Spec-first note: an entity's content_hash covers only @{type, data}@ (§1.1);
-- the wire form additionally carries @content_hash@ as a field so entities are
-- self-describing across serialization (§3.1). The two forms are kept distinct —
-- 'makeEntity' never hashes the content_hash field.
--
-- Strict-fields discipline (A-HS-002): 'Entity' / 'Envelope' fields are strict
-- ('StrictData'); a decoded entity does not retain the input buffer through a
-- thunk chain. The wire bytes themselves are strict 'BS.ByteString'.
module EntityCore.Model
  ( Entity (..)
  , makeEntity
  , Envelope (..)
    -- * Field accessors (data is a CBOR map)
  , mapGet
  , field
  , textField
  , bytesField
  , uintField
  , entityField
    -- * Wire form
  , entityToCbor
  , entityOfCbor
  , envelopeToCbor
  , envelopeOfCbor
  , includedGet
    -- * Misc
  , hexOf
  ) where

import Control.DeepSeq (NFData (..))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word64)
import Numeric (showHex)

import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.Value (Value (..))
import EntityCore.ContentHash (entityContentHash)

-- | A materialized entity. @entHash@ is the 33-byte content_hash (format byte
-- @0x00@ + 32-byte SHA-256 digest) under the ecfv1-sha256 floor.
data Entity = Entity
  { entType :: Text
  , entData :: Value
  , entHash :: ByteString
  }
  deriving (Eq, Show)

instance NFData Entity where
  rnf (Entity t d h) = rnf t `seq` rnf d `seq` rnf h

-- | Construct a materialized entity, computing its content_hash under the
-- ecfv1-sha256 floor (format_code 0).
makeEntity :: Text -> Value -> Entity
makeEntity !typ !dataV =
  let !h = entityContentHash typ dataV
   in Entity typ dataV h

-- ── CBOR field helpers (data is a Map) ───────────────────────────────────────

-- | Look up @key@ in a CBOR map value.
mapGet :: Value -> Text -> Maybe Value
mapGet (VMap kvs) key =
  foldr (\(k, v) acc -> case k of VText t | t == key -> Just v; _ -> acc) Nothing kvs
mapGet _ _ = Nothing

-- | Look up a field in the entity's @data@ map.
field :: Entity -> Text -> Maybe Value
field e = mapGet (entData e)

textField :: Entity -> Text -> Maybe Text
textField e key = case field e key of Just (VText s) -> Just s; _ -> Nothing

bytesField :: Entity -> Text -> Maybe ByteString
bytesField e key = case field e key of Just (VBytes s) -> Just s; _ -> Nothing

uintField :: Entity -> Text -> Maybe Word64
uintField e key = case field e key of Just (VUInt n) -> Just n; _ -> Nothing

-- | Decode a nested @value@ at @key@ as an entity (recomputing + validating its
-- hash). 'Nothing' if the field is absent or not a well-formed entity map.
entityField :: Entity -> Text -> Maybe Entity
entityField e key = case field e key of
  Just v -> either (const Nothing) Just (entityOfCbor v)
  Nothing -> Nothing

-- ── wire form: entity carries its content_hash ───────────────────────────────

entityToCbor :: Entity -> Value
entityToCbor e =
  VMap
    [ (VText "type", VText (entType e))
    , (VText "data", entData e)
    , (VText "content_hash", VBytes (entHash e))
    ]

-- | Parse a wire entity, recomputing the hash from @{type,data}@ and validating
-- it against the carried content_hash per entity fidelity (§1.8). Returns the
-- recomputed-canonical entity (we trust our hash, not the wire bytes —
-- §5.2 validate-before-trust).
entityOfCbor :: Value -> Either CodecError Entity
entityOfCbor c = do
  typ <- case mapGet c "type" of
    Just (VText s) -> Right s
    _ -> Left (Unsupported "entity: missing/invalid type")
  dataV <- case mapGet c "data" of
    Just d -> Right d
    Nothing -> Left (Unsupported "entity: missing data")
  let !e = makeEntity typ dataV
  case mapGet c "content_hash" of
    Just (VBytes h) | h /= entHash e -> Left (NonCanonicalEcf "entity: content_hash mismatch (§1.8 fidelity)")
    _ -> Right e

-- ── envelope (§3.1) ──────────────────────────────────────────────────────────

-- | A protocol envelope: a root entity plus the @included@ set keyed by content
-- hash. The included set MUST survive every dispatch surface, request and result
-- side (N5).
data Envelope = Envelope
  { envRoot :: Entity
  , envIncluded :: [(ByteString, Entity)] -- ^ key = entity content_hash bytes
  }
  deriving (Eq, Show)

instance NFData Envelope where
  rnf (Envelope r inc) = rnf r `seq` rnf inc

includedGet :: Envelope -> ByteString -> Maybe Entity
includedGet env h = lookup h (envIncluded env)

envelopeToCbor :: Envelope -> Value
envelopeToCbor env =
  let inc = map (\(k, e) -> (VBytes k, entityToCbor e)) (envIncluded env)
   in VMap
        [ (VText "root", entityToCbor (envRoot env))
        , (VText "included", VMap inc)
        ]

envelopeOfCbor :: Value -> Either CodecError Envelope
envelopeOfCbor c = do
  root <- case mapGet c "root" of
    Just r -> entityOfCbor r
    Nothing -> Left (Unsupported "envelope: missing root")
  included <- case mapGet c "included" of
    Just (VMap kvs) -> mapM parseIncluded kvs
    Nothing -> Right []
    Just _ -> Left (Unsupported "envelope: included not a map")
  Right (Envelope root included)
  where
    parseIncluded (VBytes h, v) = do
      e <- entityOfCbor v
      -- §3.1: included content_hash MUST match the map key.
      if h /= entHash e
        then Left (NonCanonicalEcf "envelope: included key != entity content_hash")
        else Right (h, e)
    parseIncluded _ = Left (Unsupported "envelope: included key not a byte string")

-- | Lowercase hex of a byte string (path keys; §3.5 invariant pointer).
hexOf :: ByteString -> Text
hexOf = T.pack . concatMap byteHex . BS.unpack
  where
    byteHex w = let s = showHex w "" in if length s == 1 then '0' : s else s
