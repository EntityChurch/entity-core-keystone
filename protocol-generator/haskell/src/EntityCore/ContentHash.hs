{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | content_hash construction (V7 §1.2 / §7.3).
--
-- @content_hash = varint(format_code) ‖ HASH(ECF{type, data})@
--
-- The hash input (the preimage) is the canonical ECF encoding of the two-field
-- entity map @{"type": <type>, "data": <data>}@ — NOT the @{type,data}@ pair in
-- some other order; the canonical encoder sorts the keys (@"data"@ before
-- @"type"@: both 4-char, lex @data@ < @type@). The leading varint binds the hash
-- to its digest function:
--
--   * @0x00@ → SHA-256 (the §9.1 floor);
--   * @0x01@ → SHA-384 (agility);
--   * a synthetic ≥ 0x80 code exercises the multi-byte varint prefix
--     (@content_hash.4@): the digest is still SHA-256 but the prefix is 2 bytes.
module EntityCore.ContentHash
  ( contentHash
  , entityContentHash
  , ecfOfEntity
  ) where

import Crypto.Hash (Digest, SHA256, SHA384, SHA512, hash)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Data.Text (Text)

import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.CBOR (encode)
import EntityCore.Codec.Value (Value (..))
import EntityCore.Codec.Varint (varintEncode)

-- | Canonical ECF bytes of the entity carrier @{type, data}@ — the content_hash
-- preimage AND the message the corpus @signature.*@ vectors sign over.
ecfOfEntity :: Text -> Value -> BS.ByteString
ecfOfEntity typ dataV =
  encode (VMap [(VText "type", VText typ), (VText "data", dataV)])

-- | Compute the content_hash for an entity under a given format code.
-- @0x00@/@0x01@ select SHA-256/SHA-384; @0x02@ → SHA-512; otherwise the digest
-- defaults to SHA-256 (the synthetic ≥ 0x80 forward-compat case — the corpus
-- vector pins SHA-256 under a 2-byte varint prefix). Returns a 'CodecError' for
-- an unrepresentable (negative) code.
contentHash :: Integer -> Text -> Value -> Either CodecError BS.ByteString
contentHash fmtCode typ dataV
  | fmtCode < 0 = Left (UnsupportedHashFormat fmtCode)
  | otherwise =
      let !preimage = ecfOfEntity typ dataV
          !digest = digestFor fmtCode preimage
          !prefix = varintEncode fmtCode
       in Right (prefix <> digest)

-- | The content_hash under the ecfv1-sha256 floor (format_code @0x00@): the
-- total form 'makeEntity' uses (no error case — SHA-256 over @ECF{type,data}@,
-- 33 bytes). The peer's hot path; equals @contentHash 0@'s @Right@.
entityContentHash :: Text -> Value -> BS.ByteString
entityContentHash typ dataV =
  let !preimage = ecfOfEntity typ dataV
      !digest = BA.convert (hash preimage :: Digest SHA256)
   in BS.cons 0x00 digest

-- | Pick the digest by format code. The agility codes (@0x01@ SHA-384,
-- @0x02@ SHA-512) are reachable since crypton ships them natively; any other
-- code (including the synthetic ≥ 0x80 forward-compat probe) uses SHA-256.
digestFor :: Integer -> BS.ByteString -> BS.ByteString
digestFor 1 bs = BA.convert (hash bs :: Digest SHA384)
digestFor 2 bs = BA.convert (hash bs :: Digest SHA512)
digestFor _ bs = BA.convert (hash bs :: Digest SHA256)
