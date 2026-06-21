{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Identity (L1) — a peer's keypair and the entities derived from it
-- (§1.5, §3.5, §7.3, §7.4). The peer's identity is a 32-byte Ed25519 seed;
-- everything else derives:
--
-- @
--   public_key    = Ed25519 pub of seed                       (32 bytes)
--   peer_id       = Base58(varint(1) ‖ varint(0) ‖ public_key)  (§1.5 identity-multihash)
--   peer entity   = system/peer { public_key, key_type }        (§3.5; v7.65 — NO
--                   peer_id in the hashable basis)
--   identity_hash = content_hash(peer entity)
-- @
--
-- Signing is over the full 33-byte content_hash (format byte + digest, §7.3), so
-- a signature is bound to the hash format.
--
-- §1.5/§7.4 reconciliation (the v7.74 E1 erratum, A-HS-NNN corroboration):
-- Ed25519 peer_id is identity-multihash form (key_type 0x01, hash_type 0x00,
-- digest = the raw public key). §7.4's older "NORMATIVE" SHA-256-form pseudocode
-- is superseded by the §1.5 table in v7.74; we follow §1.5 (derivePeerId).
module EntityCore.Identity
  ( Identity (..)
  , identityOfSeed
  , peerEntityOfPubkey
  , peerIdOfPubkey
  , signEntity
  , verifySignature
  , ed25519VerifyRaw
  ) where

import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE

import EntityCore.Codec.Value (Value (..))
import EntityCore.Model (Entity (..), bytesField, makeEntity)
import EntityCore.PeerId (derivePeerId, formatPeerId)
import qualified EntityCore.Signature as Sig

-- | A peer's local identity. All derived fields are precomputed at construction.
data Identity = Identity
  { idSeed :: ByteString -- ^ 32-byte Ed25519 seed
  , idPublicKey :: ByteString -- ^ 32 bytes
  , idPeerId :: Text -- ^ Base58 (ASCII)
  , idPeerEntity :: Entity
  , idIdentityHash :: ByteString -- ^ content_hash(peer entity), 33 bytes
  }

-- | The @system/peer@ entity for a public key (§3.5; v7.65 — no peer_id field in
-- the hashable basis).
peerEntityOfPubkey :: ByteString -> Entity
peerEntityOfPubkey publicKey =
  makeEntity
    "system/peer"
    (VMap [(VText "public_key", VBytes publicKey), (VText "key_type", VText "ed25519")])

-- | The Ed25519 canonical peer_id (identity-multihash, §1.5): key_type 0x01,
-- hash_type 0x00, digest = the raw public key.
peerIdOfPubkey :: ByteString -> Text
peerIdOfPubkey publicKey = TE.decodeUtf8 (formatPeerId (derivePeerId 0x01 publicKey))

-- | Build the local identity from a 32-byte seed. Errors only on a malformed
-- seed length (caught at host startup, not on the wire).
identityOfSeed :: ByteString -> Either String Identity
identityOfSeed seed = do
  publicKey <- either (Left . show) Right (Sig.ed25519PubkeyFromSeed seed)
  let peerEntity = peerEntityOfPubkey publicKey
  Right
    Identity
      { idSeed = seed
      , idPublicKey = publicKey
      , idPeerId = peerIdOfPubkey publicKey
      , idPeerEntity = peerEntity
      , idIdentityHash = entHash peerEntity
      }

-- | Sign an entity's content_hash; produce the @system/signature@ entity (§3.5):
-- target = signed entity hash, signer = our identity hash.
signEntity :: Identity -> Entity -> Entity
signEntity ident target =
  let !sigBytes = either (const "") id (Sig.ed25519Sign (idSeed ident) (entHash target))
   in makeEntity
        "system/signature"
        ( VMap
            [ (VText "target", VBytes (entHash target))
            , (VText "signer", VBytes (idIdentityHash ident))
            , (VText "algorithm", VText "ed25519")
            , (VText "signature", VBytes sigBytes)
            ]
        )

-- | Verify a @system/signature@ entity against the signer's @system/peer@ entity.
-- Reads public_key from the peer entity; the §5.2 signer-hash check is the
-- caller's responsibility.
verifySignature :: Entity -> Entity -> Bool
verifySignature signature signerPeer =
  case (bytesField signature "target", bytesField signature "signature", bytesField signerPeer "public_key") of
    (Just target, Just sigBytes, Just pub) ->
      either (const False) id (Sig.ed25519Verify pub target sigBytes)
    _ -> False

-- | Verify a raw Ed25519 signature over @msg@ under @pubkey@ (the §4.6
-- proof-of-possession check, where there is no @system/signature@ entity yet).
ed25519VerifyRaw :: ByteString -> ByteString -> ByteString -> Either String Bool
ed25519VerifyRaw pubkey msg sigBytes =
  either (Left . show) Right (Sig.ed25519Verify pubkey msg sigBytes)
