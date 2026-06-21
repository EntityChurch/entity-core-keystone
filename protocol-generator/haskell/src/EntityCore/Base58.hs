{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Base58 (Bitcoin alphabet) encode / decode, leading-zero preserving.
--
-- Done as byte long-division (the cohort convention) rather than going through
-- a bignum library directly — although Haskell's 'Integer' IS bignum, the
-- explicit base-256 → base-58 long-division form matches the other peers and
-- keeps the leading-zero handling explicit (each leading 0x00 input byte maps to
-- one leading @'1'@ output character, and vice versa on decode).
module EntityCore.Base58
  ( base58Encode
  , base58Decode
  ) where

import qualified Data.ByteString as BS
import Data.Word (Word8)

import EntityCore.Codec.Error (CodecError (..))

alphabet :: BS.ByteString
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

-- | Index of a Base58 character, or Nothing if outside the alphabet.
charIndex :: Word8 -> Maybe Int
charIndex c = BS.elemIndex c alphabet

-- | Encode bytes to a Base58 'BS.ByteString' (ASCII). Leading 0x00 bytes become
-- leading @'1'@ characters.
base58Encode :: BS.ByteString -> BS.ByteString
base58Encode input =
  let !zeros = BS.length (BS.takeWhile (== 0) input)
      !digits = toBase58Digits (BS.unpack (BS.drop zeros input))
      !leading = BS.replicate zeros (BS.head alphabet) -- '1'
      !body = BS.pack (map (\d -> BS.index alphabet d) digits)
   in leading <> body
  where
    -- base-256 → base-58 long division, big-endian. Accumulate base-58 digits
    -- most-significant first.
    toBase58Digits :: [Word8] -> [Int]
    toBase58Digits = foldl step []
      where
        step :: [Int] -> Word8 -> [Int]
        step acc byte =
          let !carried = goCarry (fromIntegral byte) (reverse acc)
           in reverse carried
        -- Multiply the current digit list (least-significant first) by 256 and
        -- add the new byte, propagating carry; return least-significant first.
        goCarry :: Int -> [Int] -> [Int]
        goCarry !carry [] = emit carry
        goCarry !carry (d : ds) =
          let !acc = d * 256 + carry
              !digit = acc `mod` 58
              !c = acc `div` 58
           in digit : goCarry c ds
        emit 0 = []
        emit n = (n `mod` 58) : emit (n `div` 58)

-- | Decode a Base58 'BS.ByteString' back to bytes. Leading @'1'@ characters
-- become leading 0x00 bytes. Fails on any character outside the alphabet.
base58Decode :: BS.ByteString -> Either CodecError BS.ByteString
base58Decode input = do
  let !zeros = BS.length (BS.takeWhile (== BS.head alphabet) input) -- '1'
      !body = BS.drop zeros input
  idxs <- mapM indexOrFail (BS.unpack body)
  let !bytes = toBytes idxs
      !leading = BS.replicate zeros 0
  Right (leading <> bytes)
  where
    indexOrFail :: Word8 -> Either CodecError Int
    indexOrFail c = case charIndex c of
      Just i -> Right i
      Nothing -> Left (BadBase58 ("char 0x" ++ show c ++ " not in Base58 alphabet"))
    -- base-58 → base-256 long division (big-endian input digits).
    toBytes :: [Int] -> BS.ByteString
    toBytes = BS.pack . foldl step []
      where
        step :: [Word8] -> Int -> [Word8]
        step acc digit =
          let !carried = goCarry digit (reverse acc)
           in reverse carried
        goCarry :: Int -> [Word8] -> [Word8]
        goCarry !carry [] = emit carry
        goCarry !carry (b : bs) =
          let !acc = fromIntegral b * 58 + carry
              !byte = fromIntegral (acc `mod` 256)
              !c = acc `div` 256
           in byte : goCarry c bs
        emit 0 = []
        emit n = fromIntegral (n `mod` 256) : emit (n `div` 256)
