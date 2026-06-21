{-# LANGUAGE OverloadedStrings #-}

-- | The 69/69 byte-identity conformance gate. Loads the locked v0.8.0 corpus and
-- asserts byte-identical encode (encode_equal) + correct rejection
-- (decode_reject) for every vector, grouped by category.
module ConformanceSpec (spec) where

import Control.Monad (forM_)
import Crypto.Hash (Digest, SHA256, hash)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Data.List (nub)
import qualified Data.Text as T
import Test.Hspec

import Fixture (Vector (..), loadVectors, runVector, vectorCategory)

corpusPath :: FilePath
corpusPath = "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"

-- The locked corpus sha256 (verify by decoding, do not assume).
corpusSha :: String
corpusSha = "41d68d2d717f84e195d46ec002fce6b8729742026256e72dc7a3a8b6c0c6a052"

spec :: Spec
spec = describe "ECF conformance corpus (v0.8.0, 69 vectors)" $ do
  result <- runIO (loadVectors corpusPath)
  rawBytes <- runIO (BS.readFile corpusPath)

  it "fixture sha256 matches the locked pin" $
    sha256Hex rawBytes `shouldBe` corpusSha

  case result of
    Left err -> it "loads the corpus" $ expectationFailure err
    Right vectors -> do
      it "decoded exactly 69 vectors" $
        length vectors `shouldBe` 69

      it "covers all 11 categories" $
        nub (map (T.unpack . vectorCategory) vectors)
          `shouldMatchList` [ "float", "int", "map_keys", "length", "primitive"
                            , "nested", "tag_reject", "content_hash", "peer_id"
                            , "signature", "envelope" ]

      forM_ categoryOrder $ \cat ->
        describe (T.unpack cat) $
          forM_ (filter ((== cat) . vectorCategory) vectors) $ \v ->
            it (T.unpack (vId v)) $
              case runVector v of
                Right () -> pure () :: Expectation
                Left reason -> expectationFailure reason

categoryOrder :: [T.Text]
categoryOrder =
  [ "float", "int", "map_keys", "length", "primitive", "nested"
  , "tag_reject", "content_hash", "peer_id", "signature", "envelope" ]

-- A tiny in-test SHA-256 hex via crypton (re-derive, do not trust the file name).
sha256Hex :: BS.ByteString -> String
sha256Hex bs = concatMap byteHex (BS.unpack digestBytes)
  where
    digestBytes = BA.convert (hash bs :: Digest SHA256) :: BS.ByteString
    byteHex b = [hd (b `div` 16), hd (b `mod` 16)]
    hd n | n < 10 = toEnum (fromEnum '0' + fromIntegral n)
         | otherwise = toEnum (fromEnum 'a' + fromIntegral n - 10)
