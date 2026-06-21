{-# LANGUAGE BangPatterns #-}

-- | Ed25519 + Ed448 signing / verification (V7 §7.3) via crypton — native.
--
-- Both algorithms are RFC-8032 deterministic (no RNG: a fixed seed + fixed
-- message gives a fixed signature). Ed25519 is the §9.1 floor (32-byte pubkey,
-- 64-byte signature); Ed448 is the crypto-agility higher bar (57-byte pubkey,
-- 114-byte signature) — NATIVE here via crypton, the headline data point: Haskell
-- is the first peer with native FULL agility incl. Ed448 (A-HS-007).
--
-- == What is signed
--
-- The PROTOCOL signing path (§7.3) signs over the @content_hash@ bytes. The
-- codec CORPUS @signature.*@ vectors, however, sign over the ECF preimage
-- (@ECF{type,data}@) — the locked-corpus convention (cf. Swift A-SW-007). Both
-- are just "sign these bytes"; this module signs whatever message it is given.
-- 'EntityCore.ContentHash.ecfOfEntity' produces the corpus message;
-- 'EntityCore.ContentHash.contentHash' produces the protocol message.
module EntityCore.Signature
  ( -- * Ed25519 (the §9.1 floor)
    ed25519PubkeyFromSeed
  , ed25519Sign
  , ed25519Verify
    -- * Ed448 (crypto-agility, native)
  , ed448PubkeyFromSeed
  , ed448Sign
  , ed448Verify
  ) where

import qualified Crypto.Error as CE
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS

import EntityCore.Codec.Error (CodecError (..))

-- ── Ed25519 ──────────────────────────────────────────────────────────────────

-- | Derive the 32-byte Ed25519 public key from a 32-byte seed.
ed25519PubkeyFromSeed :: BS.ByteString -> Either CodecError BS.ByteString
ed25519PubkeyFromSeed seed = do
  !sk <- secretKey25519 seed
  Right (BA.convert (Ed25519.toPublic sk))

-- | Deterministically sign @msg@ with the 32-byte seed, returning the 64-byte
-- signature.
ed25519Sign :: BS.ByteString -> BS.ByteString -> Either CodecError BS.ByteString
ed25519Sign seed msg = do
  !sk <- secretKey25519 seed
  let !pk = Ed25519.toPublic sk
      !sig = Ed25519.sign sk pk msg
  Right (BA.convert sig)

-- | Verify a 64-byte Ed25519 signature over @msg@ under a 32-byte public key.
ed25519Verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Either CodecError Bool
ed25519Verify pubkey msg sigBytes = do
  !pk <- mapCrypto "ed25519 pubkey" (Ed25519.publicKey pubkey)
  !sig <- mapCrypto "ed25519 sig" (Ed25519.signature sigBytes)
  Right (Ed25519.verify pk msg sig)

secretKey25519 :: BS.ByteString -> Either CodecError Ed25519.SecretKey
secretKey25519 seed
  | BS.length seed /= 32 = Left (BadCrypto "ed25519 seed must be 32 bytes")
  | otherwise = mapCrypto "ed25519 seed" (Ed25519.secretKey seed)

-- ── Ed448 (native agility) ───────────────────────────────────────────────────

-- | Derive the 57-byte Ed448 public key from a 57-byte seed.
ed448PubkeyFromSeed :: BS.ByteString -> Either CodecError BS.ByteString
ed448PubkeyFromSeed seed = do
  !sk <- secretKey448 seed
  Right (BA.convert (Ed448.toPublic sk))

-- | Deterministically sign @msg@ with the 57-byte seed, returning the 114-byte
-- signature.
ed448Sign :: BS.ByteString -> BS.ByteString -> Either CodecError BS.ByteString
ed448Sign seed msg = do
  !sk <- secretKey448 seed
  let !pk = Ed448.toPublic sk
      !sig = Ed448.sign sk pk msg
  Right (BA.convert sig)

-- | Verify a 114-byte Ed448 signature over @msg@ under a 57-byte public key.
ed448Verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Either CodecError Bool
ed448Verify pubkey msg sigBytes = do
  !pk <- mapCrypto "ed448 pubkey" (Ed448.publicKey pubkey)
  !sig <- mapCrypto "ed448 sig" (Ed448.signature sigBytes)
  Right (Ed448.verify pk msg sig)

secretKey448 :: BS.ByteString -> Either CodecError Ed448.SecretKey
secretKey448 seed
  | BS.length seed /= 57 = Left (BadCrypto "ed448 seed must be 57 bytes")
  | otherwise = mapCrypto "ed448 seed" (Ed448.secretKey seed)

-- ── crypton CryptoFailable → Either CodecError ───────────────────────────────

mapCrypto :: String -> CE.CryptoFailable a -> Either CodecError a
mapCrypto what = CE.onCryptoFailure (\e -> Left (BadCrypto (what ++ ": " ++ show e))) Right
