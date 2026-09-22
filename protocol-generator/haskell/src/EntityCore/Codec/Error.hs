{-# LANGUAGE DeriveGeneric #-}

-- | Codec error model (A-HS-001).
--
-- The pure codec is a total function returning @'Either' 'CodecError' a@:
-- decode/encode failures are /values/ (constructors of 'CodecError'), never
-- thrown exceptions. There is no IO and no exception path in the codec layer;
-- @Control.Exception@ appears only at the S3 transport boundary. Each
-- constructor maps to a protocol status code at the module boundary (S3):
-- 'NonCanonicalEcf' → 400, etc.
module EntityCore.Codec.Error
  ( CodecError (..)
  ) where

import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

-- | Every way the pure codec can reject input. @deriving Eq, Show@ for test
-- assertions; @NFData@ so decoded results can be forced at the API edge.
data CodecError
  = -- | Major-type-6 tag on the wire, indefinite length, non-minimal int /
    -- non-shortest float, duplicate map key, or any other canonical-form
    -- violation. Maps to protocol status @400 non_canonical_ecf@.
    NonCanonicalEcf !String
  | -- | Input ended before a complete item was decoded.
    Truncated !String
  | -- | A CBOR major-type-6 (tag) item was found in a @data@ region (N2).
    TagRejected !String
  | -- | Two equal keys in a map (canonical maps forbid duplicates).
    DuplicateKey !String
  | -- | Trailing bytes after a complete top-level item.
    TrailingBytes !String
  | -- | A reserved / unrecognised CBOR additional-information value, or an
    -- unsupported simple value.
    Unsupported !String
  | -- | Bad cryptographic seed / key / signature length.
    BadCrypto !String
  | -- | Unsupported key_type for peer-id / signature construction.
    UnsupportedKeyType !Integer
  | -- | Unsupported content-hash format code.
    UnsupportedHashFormat !Integer
  | -- | §4.5a item 1a: a @system\/peer@ identity entity was authored under a
    -- @content_hash_format@ other than the ECFv1-SHA-256 floor (@0x00@). The
    -- identity entity is pinned to the floor unconditionally — on every
    -- connection, whatever the active format, whatever the peer's home format —
    -- so a non-floor form is a construction the protocol does not admit. Carries
    -- the offending format code.
    PeerEntityNotAtFloor !Integer
  | -- | Base58 decode hit a character outside the Bitcoin alphabet.
    BadBase58 !String
  deriving (Eq, Show, Generic)

instance NFData CodecError
