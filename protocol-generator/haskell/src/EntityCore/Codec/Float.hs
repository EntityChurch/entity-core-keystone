{-# LANGUAGE BangPatterns #-}

-- | Shortest-form float encoding (ENTITY-CBOR-ENCODING §2.2 Rule 4 + Rule 4a).
--
-- A 'Double' is encoded in the SHORTEST IEEE-754 width that preserves its value
-- exactly: try float16 (@0xF9@), then float32 (@0xFA@), else float64 (@0xFB@).
-- "Preserves value" = the narrowed bits decode back to a value that is
-- bit-identical to the original 'Double' (so -0.0 stays -0.0; NaN/±Inf take
-- their float16 forms per Rule 4a). The decoder reads any width but the encoder
-- only ever emits the shortest.
--
-- Strictness (A-HS-002): every intermediate (the half/single bit patterns, the
-- mantissa/exponent extracts) is bang-forced — no thunk reaches the byte
-- builder. This module is the S2 spike's float half.
module EntityCore.Codec.Float
  ( encodeFloatShortest
  , decodeFloat16
  , decodeFloat32
  , decodeFloat64
  , word16ToHalf
  ) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.), testBit)
import qualified Data.ByteString as BS
import GHC.Float (castDoubleToWord64, castWord64ToDouble, castFloatToWord32, castWord32ToFloat)
import Data.Word (Word8, Word16, Word32, Word64)

-- | Encode a 'Double' in the shortest CBOR float width that preserves it.
encodeFloatShortest :: Double -> BS.ByteString
encodeFloatShortest d =
  case tryHalf d of
    Just !h -> BS.pack (0xf9 : be16 h)
    Nothing ->
      case trySingle d of
        Just !s -> BS.pack (0xfa : be32 s)
        Nothing -> BS.pack (0xfb : be64 (castDoubleToWord64 d))

-- | If @d@ is exactly representable as a float16, the 16-bit pattern.
-- Round-trips through the half decoder and compares the raw 64-bit bit pattern
-- (so -0.0 ≠ 0.0, and the canonical quiet-NaN 0x7e00 is the chosen NaN form).
tryHalf :: Double -> Maybe Word16
tryHalf d =
  let !h = doubleToHalf d
      !back = word16ToHalf h
   in if castDoubleToWord64 back == castDoubleToWord64 d then Just h else Nothing

-- | If @d@ is exactly representable as a float32, the 32-bit pattern.
trySingle :: Double -> Maybe Word32
trySingle d =
  let !f = realToFrac d :: Float
      !w = castFloatToWord32 f
      !back = realToFrac (castWord32ToFloat w) :: Double
   in if castDoubleToWord64 back == castDoubleToWord64 d then Just w else Nothing

-- | Convert a 'Double' to a candidate float16 bit pattern (IEEE-754 round to
-- nearest, ties to even). Only trusted after 'tryHalf' confirms a round-trip;
-- the conversion itself never rejects — it produces the nearest half, which
-- 'tryHalf' then accepts only if exact.
doubleToHalf :: Double -> Word16
doubleToHalf d =
  let !bits = castDoubleToWord64 d
      !sign = fromIntegral ((bits `shiftR` 48) .&. 0x8000) :: Word16
      !expo = fromIntegral ((bits `shiftR` 52) .&. 0x7ff) :: Int -- biased 11-bit
      !mant = bits .&. 0xfffffffffffff -- 52-bit
   in if expo == 0x7ff
        then -- Inf / NaN
          if mant == 0
            then sign .|. 0x7c00 -- ±Inf
            else sign .|. 0x7e00 -- canonical quiet NaN (Rule 4a)
        else
          let !unbiased = expo - 1023
           in if unbiased > 15
                then sign .|. 0x7c00 -- overflow → Inf (won't pass tryHalf for finite d)
                else
                  if unbiased < -24
                    then sign -- underflow → ±0
                    else
                      if unbiased < -14
                        then -- subnormal half
                          let !shiftAmt = (-14 - unbiased) -- 1..10
                              !mant23 = (mant .|. 0x10000000000000) `shiftR` (42 + shiftAmt)
                           in sign .|. fromIntegral (mant23 .&. 0x3ff)
                        else -- normal half
                          let !he = unbiased + 15 -- 1..30
                              !hm = fromIntegral (mant `shiftR` 42) :: Word16 -- top 10 bits
                           in sign .|. (fromIntegral he `shiftL` 10) .|. (hm .&. 0x3ff)

-- | Decode a 16-bit half-precision pattern to a 'Double' (exact).
word16ToHalf :: Word16 -> Double
word16ToHalf h =
  let !sign = if testBit h 15 then negate else id
      !expo = fromIntegral ((h `shiftR` 10) .&. 0x1f) :: Int
      !mant = fromIntegral (h .&. 0x3ff) :: Int
   in case expo of
        0 ->
          if mant == 0
            then sign 0.0
            else sign (fromIntegral mant * (2 ** (-24)))
        31 ->
          if mant == 0
            then sign (1 / 0) -- ±Inf
            else castWord64ToDouble (signNaN sign 0x7ff8000000000000)
        _ -> sign (fromIntegral (mant + 1024) * (2 ** fromIntegral (expo - 25)))
  where
    -- Reconstruct a quiet NaN double bit pattern, honoring the sign function.
    signNaN f base = if f (1.0 :: Double) < 0 then base .|. 0x8000000000000000 else base

-- | Read a 32-bit float pattern as a 'Double'.
decodeFloat32 :: Word32 -> Double
decodeFloat32 = realToFrac . castWord32ToFloat

-- | Read a 64-bit float pattern as a 'Double'.
decodeFloat64 :: Word64 -> Double
decodeFloat64 = castWord64ToDouble

-- | Read a 16-bit half-precision pattern as a 'Double' (alias for the decoder).
decodeFloat16 :: Word16 -> Double
decodeFloat16 = word16ToHalf

-- Big-endian byte splits.
be16 :: Word16 -> [Word8]
be16 w = [fromIntegral (w `shiftR` 8), fromIntegral w]

be32 :: Word32 -> [Word8]
be32 w =
  [ fromIntegral (w `shiftR` 24)
  , fromIntegral (w `shiftR` 16)
  , fromIntegral (w `shiftR` 8)
  , fromIntegral w
  ]

be64 :: Word64 -> [Word8]
be64 w =
  [ fromIntegral (w `shiftR` 56)
  , fromIntegral (w `shiftR` 48)
  , fromIntegral (w `shiftR` 40)
  , fromIntegral (w `shiftR` 32)
  , fromIntegral (w `shiftR` 24)
  , fromIntegral (w `shiftR` 16)
  , fromIntegral (w `shiftR` 8)
  , fromIntegral w
  ]
