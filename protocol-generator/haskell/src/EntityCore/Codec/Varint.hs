{-# LANGUAGE BangPatterns #-}

-- | Multicodec-style LEB128 varints (V7 §7.3, NORMATIVE) — invariant N1.
--
-- ALL format-code / key-type / hash-type framing routes through these real
-- LEB128 primitives, NOT a fixed byte. Currently allocated codes (< 0x80)
-- encode as a single byte, byte-identical to a fixed-width field; codes ≥ 0x80
-- extend to 2+ bytes (continuation bit set on every byte but the last). The
-- @peer_id.3@ / @content_hash.4@ corpus vectors exercise the synthetic ≥ 0x80
-- code, proving the primitive (N1's covering vectors).
--
-- Strictness (A-HS-002): the encode accumulator and decode shift/position are
-- bang-forced so no thunk chain builds while walking continuation bytes.
module EntityCore.Codec.Varint
  ( varintEncode
  , varintDecode
  ) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString as BS
import Data.Word (Word8)

import EntityCore.Codec.Error (CodecError (..))

-- | Encode a non-negative 'Integer' as a multicodec-style LEB128 varint
-- (low 7 bits per byte, little-endian groups, continuation bit @0x80@ on all
-- but the final byte).
varintEncode :: Integer -> BS.ByteString
varintEncode n0
  | n0 < 0 = error "varintEncode: negative input (caller bug)"
  | otherwise = BS.pack (go n0)
  where
    go :: Integer -> [Word8]
    go n =
      let !low = fromIntegral (n .&. 0x7f) :: Word8
          !rest = n `shiftR` 7
       in if rest == 0
            then [low]
            else (low .|. 0x80) : go rest

-- | Decode a multicodec-style LEB128 varint from the front of a strict
-- 'BS.ByteString'. Returns the decoded value and the remaining bytes, or a
-- 'CodecError' on truncation. Rejects a non-minimal trailing zero
-- continuation group (a @0x80@ final-group would be non-canonical).
varintDecode :: BS.ByteString -> Either CodecError (Integer, BS.ByteString)
varintDecode = go 0 0
  where
    go :: Int -> Integer -> BS.ByteString -> Either CodecError (Integer, BS.ByteString)
    go !shift !acc bs = case BS.uncons bs of
      Nothing -> Left (Truncated "varint: ran out of bytes")
      Just (b, rest) ->
        let !acc' = acc .|. (fromIntegral (b .&. 0x7f) `shiftL` shift)
         in if b .&. 0x80 /= 0
              then go (shift + 7) acc' rest
              else
                -- Final byte. A 0x00 final byte after a continuation group is a
                -- non-minimal (canonical-violating) encoding.
                if shift > 0 && b == 0x00
                  then Left (NonCanonicalEcf "varint: non-minimal trailing group")
                  else Right (acc', rest)
