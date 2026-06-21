{-# LANGUAGE BangPatterns #-}

-- | peer_id derivation + format/parse (V7 §1.5 / §7.4).
--
-- @peer_id = Base58( varint(key_type) ‖ varint(hash_type) ‖ digest )@
--
-- §7.4 defers to the §1.5 canonical-form-per-key_type table for @hash_type@ +
-- digest construction (the v7.74 E1 erratum — the peer-id §7.4/§1.5 tension the
-- OCaml/Zig/Swift peers flagged is already reconciled here):
--
--   * Ed25519 (@key_type 0x01@) → @hash_type 0x00@ (identity-multihash); the
--     digest IS the raw 32-byte public key (v7.64+).
--   * Ed448 (@0x02@), ML-DSA, etc. → @hash_type 0x01@ (SHA-256-form); the digest
--     is @SHA-256(canonical_pubkey_encoding)@.
--
-- 'formatPeerId' takes the abstract @(key_type, hash_type, digest)@ components
-- (the corpus @peer_id.*@ form). 'derivePeerId' takes a public key + key_type
-- and computes the canonical @hash_type@/digest first (the protocol + agility
-- path).
module EntityCore.PeerId
  ( PeerIdParts (..)
  , formatPeerId
  , parsePeerId
  , derivePeerId
  , canonicalHashType
  ) where

import Crypto.Hash (Digest, SHA256, hash)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS

import EntityCore.Base58 (base58Decode, base58Encode)
import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.Varint (varintDecode, varintEncode)

-- | The abstract components of a peer id.
data PeerIdParts = PeerIdParts
  { pidKeyType :: !Integer
  , pidHashType :: !Integer
  , pidDigest :: !BS.ByteString
  }
  deriving (Eq, Show)

-- | Format the components to a Base58 peer-id 'BS.ByteString' (ASCII).
formatPeerId :: PeerIdParts -> BS.ByteString
formatPeerId (PeerIdParts kt ht digest) =
  let !payload = varintEncode kt <> varintEncode ht <> digest
   in base58Encode payload

-- | Parse a Base58 peer-id back to its components (varint key_type, varint
-- hash_type, then the remaining bytes as the digest).
parsePeerId :: BS.ByteString -> Either CodecError PeerIdParts
parsePeerId b58 = do
  payload <- base58Decode b58
  (!kt, !r1) <- varintDecode payload
  (!ht, !digest) <- varintDecode r1
  Right (PeerIdParts kt ht digest)

-- | The canonical @hash_type@ for a @key_type@ (§1.5): Ed25519 → 0x00
-- identity-multihash; everything else → 0x01 SHA-256-form.
canonicalHashType :: Integer -> Integer
canonicalHashType 0x01 = 0x00
canonicalHashType _ = 0x01

-- | Derive a peer id from a public key + key_type, computing the canonical
-- @hash_type@ + digest per §1.5 (the protocol + agility path). Ed25519 uses the
-- raw pubkey as the digest; other keys hash it under SHA-256.
derivePeerId :: Integer -> BS.ByteString -> PeerIdParts
derivePeerId kt pubkey =
  let !ht = canonicalHashType kt
      !digest =
        if ht == 0x00
          then pubkey -- identity-multihash: digest IS the pubkey
          else BA.convert (hash pubkey :: Digest SHA256)
   in PeerIdParts kt ht digest
