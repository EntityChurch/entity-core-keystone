{-# LANGUAGE StrictData #-}
{-# LANGUAGE DeriveGeneric #-}

-- | The ECF value model the encoder / decoder operate over (A-HS-002).
--
-- Every field is STRICT (@StrictData@ pragma) — no lazy thunk reaches the wire.
-- Integers carry the FULL CBOR range: major-type-0 unsigned as a 'Word64'
-- (0 .. 2^64-1) and major-type-1 negative as a 'Word64' /argument/
-- (the wire value is @-1 - arg@, so @arg = 0@ is -1 and @arg = 2^64-1@ is
-- -2^64) — we do NOT clamp to 'Int' / 'Int64' (the codec-review uncovered-range
-- trap). Text strings are 'Data.Text.Text' (UTF-8-internal); the CBOR length is
-- the UTF-8 BYTE count, computed at encode time via @encodeUtf8@, never the
-- 'Data.Text.length' code-point count.
module EntityCore.Codec.Value
  ( Value (..)
  ) where

import Control.DeepSeq (NFData)
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Word (Word64)
import GHC.Generics (Generic)

-- | A decoded ECF value. Map entries are kept as an association list in their
-- decoded order; the encoder re-sorts them canonically (length-then-lex over
-- encoded key bytes), and the decoder enforces that received maps already
-- satisfy the canonical order + have no duplicate keys.
data Value
  = -- | Major type 0. Full unsigned 64-bit (0 .. 2^64-1).
    VUInt Word64
  | -- | Major type 1. Carries the on-wire /argument/; the represented value is
    -- @-1 - toInteger arg@. @VNInt 0@ is -1; @VNInt maxBound@ is -2^64.
    VNInt Word64
  | -- | Major type 2 (byte string), forwarded verbatim.
    VBytes ByteString
  | -- | Major type 3 (text string), UTF-8 on the wire.
    VText Text
  | -- | Major type 4 (definite-length array).
    VArray [Value]
  | -- | Major type 5 (definite-length map). Entries in decoded order.
    VMap [(Value, Value)]
  | -- | Major type 7 float (encoded shortest-form: f16/f32/f64). The model
    -- carries the 'Double'; the encoder picks the shortest IEEE-754 width that
    -- round-trips it (Rule 4 / Rule 4a).
    VFloat Double
  | -- | @0xF4@.
    VBool Bool
  | -- | @0xF6@.
    VNull
  deriving (Eq, Show, Generic)

instance NFData Value
