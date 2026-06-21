{-# LANGUAGE ScopedTypeVariables #-}
-- The Arbitrary Value instance is an orphan by design: Value lives in the
-- library (no test deps there), the generator + its constraints live here.
{-# OPTIONS_GHC -Wno-orphans #-}

-- | QuickCheck robustness properties — the Haskell-idiom asset (A-HS-002).
--
--   * round-trip: @decode . encode == Right@ for arbitrary canonical values;
--   * determinism / strictness: re-encoding is byte-stable, and encoding a value
--     forced with @deepseq@ gives identical bytes to encoding the lazy value (no
--     output depends on a thunk being forced or not).
--
-- 'Arbitrary' generates only canonically-encodable values (sorted, dup-free
-- maps) — matching what the codec round-trips.
module PropertySpec (spec) where

import Control.DeepSeq (force)
import qualified Data.ByteString as BS
import Data.List (nubBy, sortBy)
import Data.Ord (comparing)
import qualified Data.Text as T
import Test.Hspec
import Test.Hspec.QuickCheck (prop)
import Test.QuickCheck

import EntityCore.Codec.CBOR (encode, decode)
import EntityCore.Codec.Value (Value (..))

-- Bound recursion depth so generation terminates.
genValue :: Int -> Gen Value
genValue 0 = oneof leaves
genValue d =
  frequency
    [ (6, oneof leaves)
    , (2, VArray <$> resize 4 (listOf (genValue (d - 1))))
    , (2, genMap d)
    ]
  where
    genMap dd = do
      pairs <- resize 4 (listOf ((,) <$> genKey <*> genValue (dd - 1)))
      pure (VMap (canonicalize pairs))

leaves :: [Gen Value]
leaves =
  [ VUInt <$> arbitrary
  , VNInt <$> arbitrary
  , VBytes . BS.pack <$> resize 8 (listOf arbitrary)
  , VText . T.pack <$> resize 8 (listOf (elements ['a' .. 'z']))
  , VFloat <$> genFloat
  , VBool <$> arbitrary
  , pure VNull
  ]

-- Floats that round-trip exactly: a mix of small ints-as-floats, halves, and
-- arbitrary doubles (all are exact under shortest-form by construction since the
-- model carries the Double and the encoder picks a width that preserves it).
genFloat :: Gen Double
genFloat = oneof
  [ fromIntegral <$> (arbitrary :: Gen Int)
  , elements [0.0, -0.0, 1.5, 0.5, 65504.0, -65504.0, 100000.0, 1.1, 3.14159]
  , arbitrary
  ]

-- Keys are text or bytes (the corpus key kinds).
genKey :: Gen Value
genKey = oneof
  [ VText . T.pack <$> resize 6 (listOf (elements ['a' .. 'z']))
  , VBytes . BS.pack <$> resize 6 (listOf arbitrary)
  ]

-- Make a key list canonical: dedup by key, then sort by (encoded length, bytes).
canonicalize :: [(Value, Value)] -> [(Value, Value)]
canonicalize =
  sortBy (comparing (encKeyLenBytes . fst)) . nubBy (\a b -> fst a == fst b)
  where
    encKeyLenBytes k = let e = encode k in (BS.length e, e)

instance Arbitrary Value where
  arbitrary = genValue 3
  shrink _ = []

spec :: Spec
spec = describe "codec robustness (QuickCheck)" $ do
  prop "round-trip: decode . encode == Right v" $ \(v :: Value) ->
    -- NaN compares unequal to itself, so exclude NaN-bearing values from the
    -- equality check (encode is still exercised on them by other props).
    not (hasNaN v) ==> decode (encode v) === Right v

  prop "determinism: re-encoding is byte-stable" $ \(v :: Value) ->
    encode v === encode v

  prop "strictness: forcing the value does not change its bytes" $ \(v :: Value) ->
    encode (force v) === encode v

  prop "round-trip is idempotent on the wire (encode . decode . encode)" $ \(v :: Value) ->
    case decode (encode v) of
      Right v' -> encode v' === encode v
      Left e -> counterexample (show e) False

hasNaN :: Value -> Bool
hasNaN (VFloat d) = isNaN d
hasNaN (VArray xs) = any hasNaN xs
hasNaN (VMap kvs) = any (\(k, val) -> hasNaN k || hasNaN val) kvs
hasNaN _ = False
