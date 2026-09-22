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
  , salvageRequestId
    -- * §4.11 pre-admission refusals (0.8.2.25)
  , FramingRefusal (..)
  , preAdmissionRefusal
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

import EntityCore.Codec.CBOR (decode, decodeAllowTags, encode)
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

-- | Recover ONLY the @request_id@ from a frame the strict decoder rejected, so
-- the rejection can be delivered as a correlated @400 non_canonical_ecf@
-- response (§6.3) instead of silence.
--
-- The frame stays rejected. Nothing else is read out of it: no entity is built,
-- nothing is stored, and the offending tag is discarded rather than interpreted.
-- The envelope and entity-wrapper shapes are fixed maps with no legal tag
-- position (§6.3), so a frame whose only defect is a tag inside some entity's
-- @data@ still has a structurally sound root -- exactly the case this recovers.
-- 'Nothing' when even the request_id is unreachable, leaving the frame
-- unattributable and silence the only remaining option.
salvageRequestId :: ByteString -> Maybe Text
salvageRequestId payload = case decodeAllowTags payload of
  Left _ -> Nothing
  Right v -> do
    root <- mapGet v "root"
    dat <- mapGet root "data"
    rid <- mapGet dat "request_id"
    case rid of
      VText t -> Just t
      _ -> Nothing

-- | §4.11's pre-admission refusal causes (0.8.2.25) that arise BELOW the decoder —
-- at the framing layer, where there is no 'CodecError' to carry them because no
-- CBOR was ever parsed. 'preAdmissionRefusal' maps both these and 'CodecError' onto
-- one (status, code) table so the classification lives in one place.
data FramingRefusal
  = -- | §4.10(a) / N14: the declared envelope exceeds the configured maximum.
    -- Reported BEFORE the body is buffered, so nothing is spent on it.
    FrameTooLarge
  | -- | A length prefix declaring N bytes followed by fewer — §4.11's framing arm.
    -- DISTINCT from EOF: a clean close is not a refusal of anything and there is
    -- nobody left to answer.
    FrameTruncated
  deriving (Eq, Show)

-- | The (status, code) §4.11 assigns a pre-admission refusal's CAUSE (0.8.2.25).
--
-- "A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on
-- the wire [MUST] — correlated by @request_id@ where the id is available, and
-- otherwise as a best-effort coded frame carrying no correlation." §4.9(c)'s
-- deliver-or-signal rule is scoped to "every request the peer ADMITS" and therefore
-- reaches none of these, which is why §4.11 exists.
--
-- THE FRAME OBLIGATION BELONGS TO THE CLASS; THE CODE BELONGS TO THE CAUSE [MUST].
-- A single code for the whole class answers an honest caller under the wrong reason
-- and sends them to the wrong layer.
--
-- @
-- connect-auth proof-of-possession    401 authentication_failed  (the connect
--                                                                 handler's, not here)
-- envelope over the configured max     413 payload_too_large      (§4.10(a), N14)
-- resolution integrity (mis-keyed)     400 hash_mismatch          (§5.2a, §1.8)
-- framing \/ never becomes an Envelope  400 invalid_request        (§4.7, §4.11)
-- root neither EXECUTE nor RESPONSE    400 invalid_request        (§3.3, N12\/N17 —
--                                                                 in dispatch, not here)
-- @
--
-- The CBOR tag-policy arm keeps @non_canonical_ecf@ and that is deliberate. §4.11
-- rules that code non-conformant "on the framing arm" and gives its reason in the
-- same sentence: @ENTITY-CBOR-ENCODING@ §5.4 "defines that code for CBOR
-- tag-policy violations specifically", which that document still MUSTs at decode
-- time. §6.3 disjoins the two by CAUSE — a tag in a DATA-FIELD position is the
-- policy violation; bytes that never become an Envelope are the framing arm — so
-- there is no conflict of MUSTs to reconcile, and this branch keeps the behaviour
-- the @tag_reject@ vectors were written against.
preAdmissionRefusal :: Either FramingRefusal CodecError -> (Int, Text)
preAdmissionRefusal (Left FrameTooLarge) = (413, "payload_too_large")
preAdmissionRefusal (Left FrameTruncated) = (400, "invalid_request")
preAdmissionRefusal (Right e) = case e of
  HashMismatch _ -> (400, "hash_mismatch")
  TagRejected _ -> (400, "non_canonical_ecf")
  _ -> (400, "invalid_request")

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

-- The @capability@ hash is 'Maybe' because §1.4's PD-2 AMBIENT arm carries no
-- credential at all: the sub-dispatch is authorized by the executing handler's own
-- grant and there is nothing to name. An empty 'ByteString' would NOT do — that is
-- a present field holding a hash that resolves to nothing, which §5.2 reads as an
-- unresolvable capability rather than as its absence.
makeExecute :: Text -> Text -> Text -> Entity -> Maybe Value -> ByteString -> Maybe ByteString -> Entity
makeExecute requestId uri operation params resource author capability =
  makeEntity
    "system/protocol/execute"
    ( VMap
        ( [ (VText "request_id", VText requestId)
          , (VText "uri", VText uri)
          , (VText "operation", VText operation)
          , (VText "params", entityToCbor params)
          , (VText "author", VBytes author)
          ]
            ++ maybe [] (\c -> [(VText "capability", VBytes c)]) capability
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
