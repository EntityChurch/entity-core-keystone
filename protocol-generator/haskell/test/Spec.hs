module Main (main) where

import Test.Hspec

import qualified AgilitySpec
import qualified ConformanceSpec
import qualified MultiSigSpec
import qualified PropertySpec
import qualified SelftestSpec
import qualified TypeRegistrySpec

main :: IO ()
main = hspec $ do
  ConformanceSpec.spec
  SelftestSpec.spec
  MultiSigSpec.spec
  PropertySpec.spec
  AgilitySpec.spec
  TypeRegistrySpec.spec
