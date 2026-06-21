{-# LANGUAGE OverloadedStrings #-}

-- | A-HS-009 byte-diff: render all 53 §9.5 core types from the in-code model and
-- assert each entity's content_hash is byte-identical to the Go-rendered
-- @type-registry-vectors-v1.cbor@ set (the S8 drift target). The codec being
-- byte-green at S2 means the only residual risk is field-shape data, which this
-- per-type digest diff catches. Mirrors the Zig A-ZIG-008 test / TS
-- type-registry.test.ts.
module TypeRegistrySpec (spec) where

import Control.Monad (forM_)
import qualified Data.ByteString as BS
import Data.List (find)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Numeric (showHex)
import Test.Hspec

import EntityCore.Codec.CBOR (decode)
import EntityCore.Codec.Value (Value (..))
import EntityCore.Model (Entity (..), makeEntity)
import EntityCore.TypeDefs (TypeDef (..), allTypes, coreTypeCount, typeDefData)

vectorsPath :: FilePath
vectorsPath = "../shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor"

spec :: Spec
spec = describe "A-HS-009: §9.5 53-type registry render byte-diff" $ do
  raw <- runIO (BS.readFile vectorsPath)
  let parsed = do
        root <- either (Left . show) Right (decode raw)
        case root of
          VArray items -> traverse parseVector items
          _ -> Left "vector root not an array"
  case parsed of
    Left e -> it "loads the vector set" $ expectationFailure e
    Right rows -> do
      let want = Map.fromList rows
      it "rendered exactly 53 core types" $
        coreTypeCount `shouldBe` (53 :: Int)
      forM_ allTypes $ \td ->
        it (T.unpack (tdName td) ++ " content_hash byte-identical to the Go vector") $
          case Map.lookup (tdName td) want of
            Nothing -> expectationFailure ("type missing from vector set: " ++ T.unpack (tdName td))
            Just wantHex ->
              let e = makeEntity "system/type" (typeDefData td)
                  -- entHash = 0x00 format byte ‖ 32-byte SHA-256 digest; the
                  -- vector carries the bare digest after the "ecf-sha256:" prefix.
                  gotHex = hexOf (BS.drop 1 (entHash e))
               in gotHex `shouldBe` wantHex

-- | Parse one @{name, content_hash, ...}@ vector row → (name, digest-hex).
parseVector :: Value -> Either String (Text, Text)
parseVector (VMap kvs) = do
  name <- field "name"
  ch <- field "content_hash"
  case T.stripPrefix "ecf-sha256:" ch of
    Just d -> Right (name, d)
    Nothing -> Left ("content_hash without ecf-sha256 prefix: " ++ T.unpack ch)
  where
    field n = case snd <$> find (\(k, _) -> k == VText n) kvs of
      Just (VText t) -> Right t
      _ -> Left ("vector missing text field " ++ T.unpack n)
parseVector _ = Left "vector row not a map"

hexOf :: BS.ByteString -> Text
hexOf = T.pack . concatMap byteHex . BS.unpack
  where
    byteHex w = let s = showHex w "" in if length s == 1 then '0' : s else s
