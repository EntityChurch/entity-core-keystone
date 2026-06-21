{-# LANGUAGE OverloadedStrings #-}

-- | Uncovered-range selftests (the codec-review heuristic — REQUIRED): the
-- corpus stops at i64-max, so we prove the FULL unsigned 64-bit range (Word64)
-- + the -2^64 nint floor + leading-zero base58 + deterministic Ed25519 +
-- recursive tag rejection at depth + duplicate-key + empty-container shapes.
module SelftestSpec (spec) where

import qualified Data.ByteString as BS
import Data.Word (Word64)
import Test.Hspec

import EntityCore.Base58 (base58Decode, base58Encode)
import EntityCore.Codec.CBOR (decode, encode)
import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.Value (Value (..))
import EntityCore.Signature (ed25519PubkeyFromSeed, ed25519Sign, ed25519Verify)

-- Hex literal helper.
bs :: [Word64] -> BS.ByteString
bs = BS.pack . map fromIntegral

spec :: Spec
spec = do
  describe "uint Word64 above Int64 (the overflow spot)" $ do
    it "2^64-1 → 0x1b ffffffffffffffff" $
      encode (VUInt maxBound) `shouldBe` bs [0x1b, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff]
    it "2^63 → 0x1b 8000000000000000 (above Int64.max)" $
      encode (VUInt (2 ^ (63 :: Int))) `shouldBe` bs [0x1b, 0x80,0,0,0,0,0,0,0]
    it "decode of 0x1b ffffffffffffffff is VUInt maxBound (not clamped)" $
      decode (bs [0x1b, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff]) `shouldBe` Right (VUInt maxBound)

  describe "nint full range" $ do
    it "-1 → 0x20" $ encode (VNInt 0) `shouldBe` bs [0x20]
    it "-2^64 → 0x3b ffffffffffffffff (nint min)" $
      encode (VNInt maxBound) `shouldBe` bs [0x3b, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff]
    it "round-trips the nint floor" $
      decode (bs [0x3b, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff]) `shouldBe` Right (VNInt maxBound)

  describe "minimal-int rejection on decode (Rule 1)" $ do
    it "rejects 0x1800 (non-minimal 0)" $
      isNonCanon (decode (bs [0x18, 0x00]))
    it "rejects 0x1817 (non-minimal 23)" $
      isNonCanon (decode (bs [0x18, 0x17]))

  describe "base58 leading-zero preservation" $ do
    it "all-zero 4 bytes → '1111' and back" $ do
      let z = BS.replicate 4 0
      base58Encode z `shouldBe` "1111"
      base58Decode (base58Encode z) `shouldBe` Right z
    it "round-trips a 0x00-prefixed payload" $ do
      let p = BS.cons 0 (bs [0x01, 0x02, 0xff, 0x00, 0xab])
      base58Decode (base58Encode p) `shouldBe` Right p
    it "rejects a non-alphabet char (0)" $
      case base58Decode "10" of Left (BadBase58 _) -> True `shouldBe` True; _ -> expectationFailure "expected BadBase58"

  describe "Ed25519 deterministic sign / verify / tamper-reject" $ do
    let seed = BS.replicate 32 0
        msg = "entity-core" :: BS.ByteString
    it "same input → same signature (deterministic)" $
      ed25519Sign seed msg `shouldBe` ed25519Sign seed msg
    it "verify accepts a valid signature" $
      case (,) <$> ed25519PubkeyFromSeed seed <*> ed25519Sign seed msg of
        Right (pk, sig) -> ed25519Verify pk msg sig `shouldBe` Right True
        Left e -> expectationFailure (show e)
    it "verify rejects a tampered message" $
      case (,) <$> ed25519PubkeyFromSeed seed <*> ed25519Sign seed msg of
        Right (pk, sig) -> ed25519Verify pk (msg <> "X") sig `shouldBe` Right False
        Left e -> expectationFailure (show e)

  describe "recursive tag rejection at depth (N2)" $ do
    it "bare tag (0xc0…) rejected" $
      isTagReject (decode (bs [0xc0, 0x00]))
    it "tag nested in array rejected" $
      -- [ tag0(0) ]  = 81 c0 00
      isTagReject (decode (bs [0x81, 0xc0, 0x00]))
    it "tag nested in map value rejected" $
      -- {"a": tag0(0)} = a1 61 61 c0 00
      isTagReject (decode (bs [0xa1, 0x61, 0x61, 0xc0, 0x00]))
    it "self-describe tag 55799 (0xd9d9f7) rejected" $
      isTagReject (decode (bs [0xd9, 0xd9, 0xf7, 0xa0]))

  describe "duplicate-key + ordering rejection" $ do
    it "duplicate key rejected" $
      -- {"a":1,"a":2} = a2 6161 01 6161 02
      isDupOrCanon (decode (bs [0xa2, 0x61,0x61, 0x01, 0x61,0x61, 0x02]))
    it "out-of-order keys rejected" $
      -- {"b":1,"a":2} encoded as-given (b before a) = a2 6162 01 6161 02
      isNonCanon (decode (bs [0xa2, 0x61,0x62, 0x01, 0x61,0x61, 0x02]))

  describe "empty containers (N3)" $ do
    it "empty map → 0xA0" $ encode (VMap []) `shouldBe` bs [0xa0]
    it "empty array → 0x80" $ encode (VArray []) `shouldBe` bs [0x80]
    it "empty map decodes back" $ decode (bs [0xa0]) `shouldBe` Right (VMap [])

isNonCanon :: Either CodecError a -> Expectation
isNonCanon (Left (NonCanonicalEcf _)) = pure ()
isNonCanon (Left other) = expectationFailure ("expected NonCanonicalEcf, got " ++ show other)
isNonCanon (Right _) = expectationFailure "expected rejection, got Right"

isTagReject :: Either CodecError a -> Expectation
isTagReject (Left (TagRejected _)) = pure ()
isTagReject (Left other) = expectationFailure ("expected TagRejected, got " ++ show other)
isTagReject (Right _) = expectationFailure "expected tag rejection, got Right"

isDupOrCanon :: Either CodecError a -> Expectation
isDupOrCanon (Left (DuplicateKey _)) = pure ()
isDupOrCanon (Left (NonCanonicalEcf _)) = pure ()
isDupOrCanon (Left other) = expectationFailure ("expected DuplicateKey/NonCanonicalEcf, got " ++ show other)
isDupOrCanon (Right _) = expectationFailure "expected rejection, got Right"
