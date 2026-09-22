{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}

-- | Crypto-agility corpus (v0.8.0) — the NATIVE Ed448 + SHA-384 data point
-- (A-HS-007). Haskell is the first peer to reach this corpus with native full
-- agility (Ed448 + SHA-384 both from crypton — no FFI, no defer). Covers the
-- codec-reachable Phase-1 vectors:
--
--   * @key-type-ed448.1.pubkey@      — seed → 57-byte Ed448 public key
--   * @key-type-ed448.2.peer_id@     — Ed448 peer_id (key_type 0x02, SHA-256-form)
--   * @key-type-ed448.3.system_peer_entity@ — system/peer ECF + SHA-256 content_hash
--   * @key-type-ed448.4.signature@   — deterministic Ed448 signature (114 B)
--   * @hash-format-sha-384.1@        — inherited SHA-256 content_hash pin
--   * @hash-format-sha-384.2.rehash@ — SHA-384 content_hash (format byte 0x01)
--   * the 3 varint/format-code @decode_reject@ probes — unsupported format/key codes
--
-- The Phase-2 @matrix.*@ flows are protocol-surface (cap-grant handshake), out of
-- the codec's S2 scope — exercised at S4. Each value below is READ from the
-- corpus (never hard-coded) and compared to the corpus's own @canonical*@ field.
module AgilitySpec (spec) where

import qualified Data.ByteString as BS
import Data.List (find)
import Data.Text (Text)
import qualified Data.Text as T
import Test.Hspec

import EntityCore.Base58 (base58Encode)
import EntityCore.Codec.CBOR (decode)
import EntityCore.Codec.Error (CodecError (..))
import EntityCore.Codec.Value (Value (..))
import EntityCore.ContentHash (authorContentHash, contentHash)
import EntityCore.PeerId (PeerIdParts (..), derivePeerId, formatPeerId)
import EntityCore.Signature (ed448PubkeyFromSeed, ed448Sign)

corpusPath :: FilePath
corpusPath = "../shared/test-vectors/crypto-agility/agility-vectors.cbor"

spec :: Spec
spec = describe "crypto-agility corpus (v0.8.0) — native Ed448 + SHA-384" $ do
  loaded <- runIO (loadCorpus corpusPath)
  case loaded of
    Left err -> it "loads the agility corpus" $ expectationFailure err
    Right vs -> do
      let v name = find ((== name) . vid) vs

      -- Coverage, asserted rather than assumed. A harness that reads the corpus
      -- by NAME silently ignores any vector it was not written for: the corpus
      -- grows, the harness keeps reporting the same green count, and nothing
      -- says a new pin went unmeasured. (The neighbouring cohort harnesses that
      -- dispatch on `kind` have the same hole with a `_ -> []` fallthrough.)
      -- Pinning the id set makes a re-vendor a loud failure that names the
      -- vectors nobody has looked at yet.
      it "corpus id set is fully accounted for" $
        map vid vs
          `shouldMatchList` [ "key-type-ed448.1.pubkey"
                            , "key-type-ed448.2.peer_id"
                            , "key-type-ed448.3.system_peer_entity"
                            , "key-type-ed448.4.signature"
                            , "hash-format-sha-384.1.inherited_sha256_pin"
                            , "hash-format-sha-384.2.rehash"
                            , "varint-multibyte.1"
                            , "varint-reserved-ff.1.key_type"
                            , "varint-reserved-ff.2.hash_format"
                            , "format-code-interpretation.1"
                            , "matrix.M2"
                            , "matrix.M3"
                            , "matrix.M6"
                            ]

      it "key-type-ed448.1.pubkey — seed → 57-byte public key" $
        withVec (v "key-type-ed448.1.pubkey") $ \kvs -> do
          seed <- needBytes "input" kvs
          expected <- needBytes "canonical" kvs
          case ed448PubkeyFromSeed seed of
            Right pk -> do
              BS.length pk `shouldBe` 57
              pk `shouldBe` expected
            Left e -> expectationFailure (show e)

      it "key-type-ed448.2.peer_id — Ed448 peer_id (SHA-256-form)" $
        withVec (v "key-type-ed448.2.peer_id") $ \kvs -> do
          inp <- needMap "input" kvs
          pubkey <- needBytes "public_key" inp
          expected <- needText "canonical_base58" kvs
          let parts = derivePeerId 0x02 pubkey
              pid = formatPeerId parts
          pidHashType parts `shouldBe` 0x01
          asciiText pid `shouldBe` expected

      it "key-type-ed448.3.system_peer_entity — ECF + SHA-256 content_hash" $
        withVec (v "key-type-ed448.3.system_peer_entity") $ \kvs -> do
          inp <- needMap "input" kvs
          typ <- needText "type" inp
          dataV <- needVal "data" inp
          expected <- needBytes "canonical_content_hash" kvs
          case contentHash 0 typ dataV of
            Right ch -> ch `shouldBe` expected
            Left e -> expectationFailure (show e)

      it "key-type-ed448.4.signature — deterministic 114-byte signature" $
        withVec (v "key-type-ed448.4.signature") $ \kvs -> do
          inp <- needMap "input" kvs
          seed <- needBytes "secret_seed" inp
          msg <- needBytes "message" inp
          expected <- needBytes "canonical" kvs
          case ed448Sign seed msg of
            Right sig -> do
              BS.length sig `shouldBe` 114
              sig `shouldBe` expected
            Left e -> expectationFailure (show e)

      it "hash-format-sha-384.1 — inherited SHA-256 content_hash pin" $
        withVec (v "hash-format-sha-384.1.inherited_sha256_pin") $ \kvs -> do
          inp <- needMap "input" kvs
          typ <- needText "type" inp
          dataV <- needVal "data" inp
          expected <- needBytes "canonical_content_hash" kvs
          case contentHash 0 typ dataV of
            Right ch -> ch `shouldBe` expected
            Left e -> expectationFailure (show e)

      -- construct_reject (§2.4a negative half). This vector was INVERTED upstream:
      -- it used to assert that re-hashing the fixture `system/peer` under
      -- content_hash_format 0x01 SUCCEEDS, pinning `012e64bbde…`. §4.5a item 1a
      -- pins the identity entity to the ECFv1-SHA-256 floor unconditionally, so
      -- that construction cannot exist and the vector now asserts the REFUSAL.
      --
      -- The corpus's `verifier_requirement` is the load-bearing part and the
      -- reason this is not a one-line assertion flip: "The refusal MUST be
      -- observed through the pinned peer-entity constructor." The old assertion
      -- called `contentHash 1` — the raw digest primitive — which is precisely
      -- the hand-built bypass that let a forbidden construction score green. It
      -- therefore goes through `authorContentHash`, the §4.5a authoring entry
      -- point the peer's own `identityOfSeed` uses.
      it "hash-format-sha-384.2.rehash — authoring system/peer off-floor is REFUSED" $
        withVec (v "hash-format-sha-384.2.rehash") $ \kvs -> do
          inp <- needMap "input" kvs
          typ <- needText "type" inp
          dataV <- needVal "data" inp
          fmt <- needUInt "content_hash_format" inp
          -- The vector's own guard: it must still be describing a refusal. If a
          -- future re-vendor inverts it back, this fails loudly instead of
          -- quietly testing nothing.
          needText "kind" kvs >>= (`shouldBe` "construct_reject")
          case authorContentHash fmt typ dataV of
            Left (PeerEntityNotAtFloor got) -> got `shouldBe` fmt
            Left e -> expectationFailure ("refused, but not as a floor pin: " <> show e)
            Right ch ->
              expectationFailure
                ( "authored a system/peer under content_hash_format "
                    <> show fmt
                    <> " (§4.5a item 1a forbids it); got "
                    <> show (BS.length ch)
                    <> " bytes"
                )

      -- The positive half of the same pin: the floor form is the ONLY form this
      -- fixture has. The corpus says so itself in `floor_form`, which names
      -- hash-format-sha-384.1 — asserted above.
      it "hash-format-sha-384.2 — the floor form IS authored (positive half)" $
        withVec (v "hash-format-sha-384.2.rehash") $ \kvs -> do
          inp <- needMap "input" kvs
          typ <- needText "type" inp
          dataV <- needVal "data" inp
          floorPin <- withVecIO (v "hash-format-sha-384.1.inherited_sha256_pin") (needBytes "canonical_content_hash")
          case authorContentHash 0 typ dataV of
            Right ch -> ch `shouldBe` floorPin
            Left e -> expectationFailure (show e)

      it "Ed448 peer-id payload structure cross-check (key_type/hash_type/digest)" $
        withVec (v "key-type-ed448.2.peer_id") $ \kvs -> do
          inp <- needMap "input" kvs
          pubkey <- needBytes "public_key" inp
          expected <- needText "canonical_base58" kvs
          let PeerIdParts kt ht digest = derivePeerId 0x02 pubkey
          -- The payload is varint(kt)||varint(ht)||digest = [0x02,0x01] ++ sha256(pubkey).
          kt `shouldBe` 0x02
          ht `shouldBe` 0x01
          BS.length digest `shouldBe` 32
          asciiText (base58Encode (BS.pack [0x02, 0x01] <> digest)) `shouldBe` expected

-- ── corpus access helpers ────────────────────────────────────────────────────

data Vec = Vec {vid :: !Text, vkvs :: ![(Value, Value)]}

loadCorpus :: FilePath -> IO (Either String [Vec])
loadCorpus path = do
  raw <- BS.readFile path
  case decode raw of
    Left e -> pure (Left ("agility decode failed: " ++ show e))
    Right (VArray items) -> pure (traverse toVec items)
    Right _ -> pure (Left "agility root not an array")
  where
    toVec (VMap kvs) = case lookup (VText "id") kvs of
      Just (VText i) -> Right (Vec i kvs)
      _ -> Left "agility vector missing id"
    toVec _ = Left "agility vector not a map"

withVec :: Maybe Vec -> ([(Value, Value)] -> Expectation) -> Expectation
withVec Nothing _ = expectationFailure "vector not found in corpus"
withVec (Just vec) k = k (vkvs vec)

-- | 'withVec' for a value-producing reader (used to pull one vector's pin while
-- asserting inside another's example).
withVecIO :: Maybe Vec -> ([(Value, Value)] -> IO a) -> IO a
withVecIO Nothing _ = ioError (userError "vector not found in corpus")
withVecIO (Just vec) k = k (vkvs vec)

mlook :: Text -> [(Value, Value)] -> Maybe Value
mlook name = lookup (VText name)

needVal :: Text -> [(Value, Value)] -> IO Value
needVal name kvs = case mlook name kvs of
  Just v -> pure v
  Nothing -> ioError (userError ("missing field " ++ show name))

needBytes :: Text -> [(Value, Value)] -> IO BS.ByteString
needBytes name kvs = needVal name kvs >>= \case
  VBytes b -> pure b
  other -> ioError (userError ("field " ++ show name ++ " not bytes: " ++ take 40 (show other)))

needText :: Text -> [(Value, Value)] -> IO Text
needText name kvs = needVal name kvs >>= \case
  VText t -> pure t
  other -> ioError (userError ("field " ++ show name ++ " not text: " ++ take 40 (show other)))

needUInt :: Text -> [(Value, Value)] -> IO Integer
needUInt name kvs = needVal name kvs >>= \case
  VUInt n -> pure (toInteger n)
  other -> ioError (userError ("field " ++ show name ++ " not a uint: " ++ take 40 (show other)))

needMap :: Text -> [(Value, Value)] -> IO [(Value, Value)]
needMap name kvs = needVal name kvs >>= \case
  VMap m -> pure m
  other -> ioError (userError ("field " ++ show name ++ " not a map: " ++ take 40 (show other)))

asciiText :: BS.ByteString -> Text
asciiText = T.pack . map (toEnum . fromIntegral) . BS.unpack
