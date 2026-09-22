module Main (main) where

import Test.Hspec

import qualified AgilitySpec
import qualified ConformanceSpec
import qualified MultiSigSpec
import qualified PD2Spec
import qualified PropertySpec
import qualified ScopeAlgebraSpec
import qualified SelftestSpec
import qualified TypeRegistrySpec

main :: IO ()
main = hspec $ do
  ConformanceSpec.spec
  SelftestSpec.spec
  ScopeAlgebraSpec.spec
  MultiSigSpec.spec
  PD2Spec.spec
  PropertySpec.spec
  AgilitySpec.spec
  TypeRegistrySpec.spec
