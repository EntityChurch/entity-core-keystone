{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Wire framing (§1.6) and the two message builders (§3.2 EXECUTE, §3.3
-- EXECUTE_RESPONSE). Frame := @[4-byte BE length][CBOR payload]@; the payload is
-- a CBOR-encoded @system/protocol/envelope@ (§3.1).
--
-- Pure layer only: the @encode@/@decode@ of frame ↔ envelope. The blocking
-- socket read/write of a full frame lives in 'EntityCore.Transport' (the IO
-- edge); these helpers stay total ('Either CodecError'), no exceptions
-- (A-HS-001). Frame length is explicit 4-byte big-endian ('explicit_endianness').
module EntityCore.Wire
  ( maxFrame
  , frameHeader
  , parseFrameLength
  , envelopeOfFrame
  , frameOfEnvelope
  , makeResponse
  , makeExecute
  , errorResult
  , emptyParams
  ) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)

import EntityCore.Codec.CBOR (decode, encode)
import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.Value (Value (..))
import EntityCore.Model

-- | §1.6 SHOULD bound — 16 MiB.
maxFrame :: Int
maxFrame = 16 * 1024 * 1024

-- | Build the 4-byte big-endian length header for a payload.
frameHeader :: Int -> ByteString
frameHeader len =
  BS.pack
    [ fromIntegral (len `shiftR` 24) .&. 0xff
    , fromIntegral (len `shiftR` 16) .&. 0xff
    , fromIntegral (len `shiftR` 8) .&. 0xff
    , fromIntegral len .&. 0xff
    ]

-- | Parse a 4-byte big-endian length header.
parseFrameLength :: ByteString -> Int
parseFrameLength hdr =
  let b i = fromIntegral (BS.index hdr i) :: Int
   in (b 0 `shiftL` 24) .|. (b 1 `shiftL` 16) .|. (b 2 `shiftL` 8) .|. b 3

-- ── envelope <-> frame ────────────────────────────────────────────────────────

envelopeOfFrame :: ByteString -> Either CodecError Envelope
envelopeOfFrame payload = decode payload >>= envelopeOfCbor

frameOfEnvelope :: Envelope -> ByteString
frameOfEnvelope env =
  let !payload = encode (envelopeToCbor env)
   in frameHeader (BS.length payload) <> payload

-- ── EXECUTE_RESPONSE builder (§3.3) ───────────────────────────────────────────

makeResponse :: Text -> Int -> Entity -> Entity
makeResponse requestId status result =
  makeEntity
    "system/protocol/execute/response"
    ( VMap
        [ (VText "request_id", VText requestId)
        , (VText "status", VUInt (fromIntegral status))
        , (VText "result", entityToCbor result)
        ]
    )

-- ── EXECUTE builder (§3.2) — used by the §6.13(b) handler outbound seam ───────

makeExecute :: Text -> Text -> Text -> Entity -> Maybe Value -> ByteString -> ByteString -> Entity
makeExecute requestId uri operation params resource author capability =
  makeEntity
    "system/protocol/execute"
    ( VMap
        ( [ (VText "request_id", VText requestId)
          , (VText "uri", VText uri)
          , (VText "operation", VText operation)
          , (VText "params", entityToCbor params)
          , (VText "author", VBytes author)
          , (VText "capability", VBytes capability)
          ]
            ++ maybe [] (\r -> [(VText "resource", r)]) resource
        )
    )

-- | @system/protocol/error@ result entity (§3.3).
errorResult :: Maybe Text -> Text -> Entity
errorResult message code =
  makeEntity
    "system/protocol/error"
    (VMap ((VText "code", VText code) : maybe [] (\m -> [(VText "message", VText m)]) message))

-- | Empty-params shape (§3.2): @primitive/any@ whose data is the canonical empty
-- map (the @0xA0@ encoding, N3).
emptyParams :: Entity
emptyParams = makeEntity "primitive/any" (VMap [])
