{-# LANGUAGE OverloadedStrings #-}

-- | §3.6 M3 multi-signature K-of-N — the ACCEPT path the oracle CANNOT cover.
--
-- The validate-peer @multisig@ category is 100% rejection tests (each builds a
-- MALFORMED quorum and asserts a 403), which a fail-closed peer passes 10/10
-- /vacuously/ without genuine k-of-n logic. This is the direction the oracle does
-- not exercise: a real 2-of-3 root (one signer = the local peer) with a threshold
-- of valid signatures over the cap's content_hash MUST be ALLOWed — and each
-- M3/M4/M6 invariant flip MUST deny. We also confirm a single-sig root still
-- verifies identically (strict superset). Mirrors the OCaml selftest accept block.
module MultiSigSpec (spec) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)
import Test.Hspec

import EntityCore.Capability (Verdict (..), verifyCapabilityChain)
import EntityCore.Codec.Value (Value (..))
import EntityCore.Identity (Identity (..), identityOfSeed, signEntity)
import EntityCore.Model (Entity (..), makeEntity)

-- A deterministic identity from a single-byte seed.
mkIdent :: Word64 -> Identity
mkIdent b = case identityOfSeed (BS.replicate 32 (fromIntegral b)) of
  Right i -> i
  Left e -> error ("identityOfSeed: " ++ show e)

-- A multi-sig capability token: granter = {signers, threshold}, grantee = id1.
mkMultiCap :: [ByteString] -> Word64 -> Maybe ByteString -> Entity
mkMultiCap signers threshold parent =
  let granter =
        VMap
          [ (VText "signers", VArray (map VBytes signers))
          , (VText "threshold", VUInt threshold)
          ]
      fields =
        [ (VText "granter", granter)
        , (VText "grantee", VBytes granteeHash)
        , (VText "grants", VArray [])
        ]
          ++ maybe [] (\p -> [(VText "parent", VBytes p)]) parent
   in makeEntity "system/capability/token" (VMap fields)
  where
    granteeHash = idIdentityHash (mkIdent 1)

peerInc :: Identity -> (ByteString, Entity)
peerInc i = (idIdentityHash i, idPeerEntity i)

sigInc :: Entity -> (ByteString, Entity)
sigInc s = (entHash s, s)

-- nowMs = 0; the test caps carry no temporal bounds, so any clock allows.
allows :: Identity -> Entity -> [(ByteString, Entity)] -> Bool
allows local cap included =
  let resolve h = lookup h included
   in fst (verifyCapabilityChain (idPeerId local) 0 resolve included cap) == Allow

spec :: Spec
spec = describe "§3.6 M3 multi-signature K-of-N (accept path — oracle-uncovered)" $ do
  let id1 = mkIdent 1
      id2 = mkIdent 2
      id3 = mkIdent 3
      local = id1
      signers = [idIdentityHash id1, idIdentityHash id2, idIdentityHash id3]
      inc3 = [peerInc id1, peerInc id2, peerInc id3]
      cap = mkMultiCap signers 2 Nothing
      s1 = signEntity id1 cap
      s2 = signEntity id2 cap

  it "valid 2-of-3, local in quorum, 2 valid sigs → Allow" $
    allows local cap (inc3 ++ [sigInc s1, sigInc s2]) `shouldBe` True

  it "only 1 valid sig (< threshold) → Deny (M4)" $
    allows local cap (inc3 ++ [sigInc s1]) `shouldBe` False

  it "duplicate sig from same signer does not inflate the count → Deny (M4)" $
    -- two signature entities, but both from id1 → only one distinct signer
    allows local cap (inc3 ++ [sigInc s1, sigInc (signEntity id1 cap)]) `shouldBe` False

  it "local peer not among the signers → Deny (M6)" $ do
    let capNL = mkMultiCap [idIdentityHash id2, idIdentityHash id3] 2 Nothing
        n2 = signEntity id2 capNL
        n3 = signEntity id3 capNL
    allows local capNL ([peerInc id2, peerInc id3] ++ [sigInc n2, sigInc n3]) `shouldBe` False

  it "threshold = 1 (M3 structure) → Deny even with valid sigs (precedence)" $ do
    let capT1 = mkMultiCap signers 1 Nothing
    allows local capT1 (inc3 ++ [sigInc s1, sigInc s2]) `shouldBe` False

  it "duplicate signers (M3 structure) → Deny" $ do
    let capDup = mkMultiCap [idIdentityHash id1, idIdentityHash id1] 2 Nothing
        d1 = signEntity id1 capDup
    allows local capDup ([peerInc id1] ++ [sigInc d1]) `shouldBe` False

  it "n < 2 single-signer quorum (M3 structure) → Deny" $ do
    let capN1 = mkMultiCap [idIdentityHash id1] 2 Nothing
        n1 = signEntity id1 capN1
    allows local capN1 ([peerInc id1] ++ [sigInc n1]) `shouldBe` False

  it "multi-sig token off-root (has parent) → Deny (root-only)" $ do
    let capRooted = mkMultiCap signers 2 (Just (BS.replicate 33 0xaa))
    allows local capRooted (inc3 ++ [sigInc (signEntity id1 capRooted), sigInc (signEntity id2 capRooted)])
      `shouldBe` False

  it "single-sig root still verifies (strict superset)" $ do
    let ssCap =
          makeEntity
            "system/capability/token"
            ( VMap
                [ (VText "granter", VBytes (idIdentityHash id1))
                , (VText "grantee", VBytes (idIdentityHash id1))
                , (VText "grants", VArray [])
                ]
            )
        ssSig = signEntity id1 ssCap
    allows local ssCap ([peerInc id1, sigInc ssSig]) `shouldBe` True
