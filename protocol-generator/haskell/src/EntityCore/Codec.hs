-- | Public codec surface re-export. The codec is a total PURE function:
-- @'encode' :: 'Value' -> 'BS.ByteString'@ and
-- @'decode' :: 'BS.ByteString' -> 'Either' 'CodecError' 'Value'@. No IO, no
-- exceptions in this layer (A-HS-001).
module EntityCore.Codec
  ( -- * Value model
    Value (..)
    -- * Error model
  , CodecError (..)
    -- * Canonical ECF
  , encode
  , decode
    -- * Varints (N1)
  , varintEncode
  , varintDecode
  ) where

import EntityCore.Codec.CBOR (decode, encode)
import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.Value (Value (..))
import EntityCore.Codec.Varint (varintDecode, varintEncode)
