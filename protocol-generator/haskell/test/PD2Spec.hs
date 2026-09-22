{-# LANGUAGE OverloadedStrings #-}

-- | §1.4 PD-2 — the outbound sub-dispatch gate, and the ONE RULE THE WIRE CANNOT
-- MEASURE.
--
-- The oracle's @dispatch_outbound_multisig_root_refused@ check is GREEN on a peer
-- that has never implemented §1.4's multi-signature clause. Measured by planting
-- the guard out on both vanguards: the oracle's K-of-2 root is co-signed by the
-- target and a third party and NOT by the local peer, so §5.5's M6 (the local peer
-- MUST be a validated quorum member) refuses it first, for a reason that has
-- nothing to do with §1.4. The discriminating input is a quorum THE LOCAL PEER IS
-- A MEMBER OF, minted at the target, and nothing on the wire drives it.
--
-- So the green row is not evidence for that rule, and this module is. The
-- ANTECEDENT ASSERT is the load-bearing part: @quorumRootVerifiesLocally@ pins
-- that the very same quorum DOES verify in the local frame, so a refusal in the
-- foreign frame is attributable to §1.4 and not to a fixture that M6 was rejecting
-- anyway. Without it the control is INERT — which is how the first `go` version
-- shipped, and only planting caught it.
module PD2Spec (spec) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word64)
import Test.Hspec

import EntityCore.Capability
  ( Scope (..)
  , Verdict (..)
  , checkOutboundSubDispatch
  , grantPathFor
  , peerRelativeOf
  , targetMintedPeersRelaxation
  , verifyCapabilityChain
  , verifyCapabilityChainRootedAt
  )
import EntityCore.Codec.Value (Value (..))
import EntityCore.Identity (Identity (..), identityOfSeed, signEntity)
import EntityCore.Model (Entity (..), makeEntity)

mkIdent :: Word64 -> Identity
mkIdent b = case identityOfSeed (BS.replicate 32 (fromIntegral b)) of
  Right i -> i
  Left e -> error ("identityOfSeed: " ++ show e)

peerInc :: Identity -> (ByteString, Entity)
peerInc i = (idIdentityHash i, idPeerEntity i)

sigInc :: Entity -> (ByteString, Entity)
sigInc s = (entHash s, s)

-- | A single-signature token: @granter@ is one peer, @grantee@ another.
mkCap :: Identity -> Identity -> [Value] -> Entity
mkCap granter grantee grants =
  makeEntity
    "system/capability/token"
    ( VMap
        [ (VText "granter", VBytes (idIdentityHash granter))
        , (VText "grantee", VBytes (idIdentityHash grantee))
        , (VText "grants", VArray grants)
        ]
    )

-- | A §3.6 K-of-N quorum-rooted token.
mkMultiCap :: [ByteString] -> Word64 -> Identity -> [Value] -> Entity
mkMultiCap signers threshold grantee grants =
  makeEntity
    "system/capability/token"
    ( VMap
        [ ( VText "granter"
          , VMap
              [ (VText "signers", VArray (map VBytes signers))
              , (VText "threshold", VUInt threshold)
              ]
          )
        , (VText "grantee", VBytes (idIdentityHash grantee))
        , (VText "grants", VArray grants)
        ]
    )

-- | The narrow scaffold grant GUIDE-CONFORMANCE §7a.1 requires of
-- @dispatch-outbound@: it is the NARROWNESS that makes the confused-deputy
-- discriminator able to fire at all.
narrowGrant :: Value
narrowGrant =
  VMap
    [ (VText "handlers", VMap [(VText "include", VArray [VText "system/validate/echo"])])
    , (VText "operations", VMap [(VText "include", VArray [VText "echo"])])
    , (VText "resources", VMap [(VText "include", VArray [VText "system/handler/system/validate/echo"])])
    ]

echoResource :: Value
echoResource =
  VMap [(VText "targets", VArray [VText "system/handler/system/validate/echo"])]

never :: ByteString -> Bool
never _ = False

spec :: Spec
spec = describe "§1.4 PD-2 outbound sub-dispatch gate" $ do
  let local = mkIdent 1
      target = mkIdent 2
      third = mkIdent 3
      localPeer = idPeerId local
      targetPeer = idPeerId target
      handlerGrant = mkCap local local [narrowGrant]
      -- A credential MINTED BY THE TARGET naming the local peer as grantee: the
      -- ordinary reentry shape, "you may dispatch back to me".
      cred = mkCap target local [VMap []]
      credSig = signEntity target cred
      credInc = [peerInc target, peerInc local, sigInc credSig]
      resolve inc h = lookup h inc
      gate inc mcred op =
        checkOutboundSubDispatch
          localPeer targetPeer "system/validate/echo" op 0 never
          (resolve inc) inc handlerGrant echoResource mcred

  describe "§1.4: a MULTI-SIGNATURE root never relaxes Dimension 4" $ do
    -- The quorum the local peer IS a member of. The oracle cannot build this
    -- input; without it the refusal below would be M6's and not §1.4's.
    let signers = [idIdentityHash local, idIdentityHash target]
        msCap = mkMultiCap signers 2 local [VMap []]
        msInc =
          [peerInc local, peerInc target]
            ++ [sigInc (signEntity local msCap), sigInc (signEntity target msCap)]

    it "ANTECEDENT: the same quorum DOES verify in the LOCAL frame" $
      -- If this ever goes False the refusal below proves nothing: M6 would be
      -- rejecting the fixture and the §1.4 clause would never be reached.
      fst (verifyCapabilityChain localPeer 0 (resolve msInc) msInc msCap)
        `shouldBe` Allow

    it "the same quorum rooted at the TARGET is REFUSED (E3/F66)" $
      fst (verifyCapabilityChainRootedAt localPeer targetPeer 0 (resolve msInc) msInc msCap)
        `shouldBe` Deny

    it "and so relaxes nothing" $
      -- Projected through scIncl rather than compared as a Scope: adding a Show
      -- instance to a library type so a test can print it is a public API change
      -- made for the test's convenience, and the projection asserts the same fact.
      (scIncl <$> targetMintedPeersRelaxation localPeer targetPeer 0 never (resolve msInc) msInc msCap)
        `shouldBe` Nothing

    it "CONTRAST: a SINGLE-signature root minted by the target DOES relax" $
      -- The granter form is the only variable against the case above, which is
      -- what says the refusal is about the quorum and not about foreign rooting.
      (scIncl <$> targetMintedPeersRelaxation localPeer targetPeer 0 never (resolve credInc) credInc cred)
        `shouldBe` Just [targetPeer]

  describe "one gate and one exemption (§6.8 confused-deputy)" $ do
    it "COMPOSE: credential + a handler grant that covers -> allow" $
      gate credInc (Just cred) "echo" `shouldBe` True

    it "BYPASS: the SAME valid credential, an operation the handler grant does NOT cover -> refuse" $
      -- The only input that separates the two readings. Both obvious vectors
      -- agree under either one (sources agree -> allow, no source -> refuse).
      gate credInc (Just cred) "put" `shouldBe` False

    it "AMBIENT: no credential, foreign target, grant names no peers -> refuse" $
      -- §5.2's default for an absent `peers` scope is {include: [local]}.
      gate credInc Nothing "echo" `shouldBe` False

    it "a credential whose signature does not verify relaxes NOTHING (not an error)" $
      -- Dropping the cap signature from the bundle makes the chain unverifiable.
      gate [peerInc target, peerInc local] (Just cred) "echo" `shouldBe` False

    it "a credential granted to SOMEONE ELSE relaxes nothing" $ do
      let foreign' = mkCap target third [VMap []]
          inc = [peerInc target, peerInc third, sigInc (signEntity target foreign')]
      gate inc (Just foreign') "echo" `shouldBe` False

  describe "peerRelativeOf — §1.4's three spellings onto the one a grant matches" $ do
    let abs' = "/" <> localPeer <> "/system/validate/echo" :: Text
    it "peer-relative passes through" $
      peerRelativeOf "system/validate/echo" `shouldBe` "system/validate/echo"
    it "absolute loses the peer segment" $
      peerRelativeOf abs' `shouldBe` "system/validate/echo"
    it "schemed loses scheme and peer segment" $
      peerRelativeOf ("entity://" <> localPeer <> "/system/validate/echo")
        `shouldBe` "system/validate/echo"
    it "a NON-peer-id first segment is NOT stripped" $
      -- The standing `smalltalk`/`forth` defect: an unconditional strip turns
      -- system/protocol/connect into protocol/connect and every self-minted grant
      -- becomes unusable while the handshake stays green.
      peerRelativeOf "/system/protocol/connect" `shouldBe` "system/protocol/connect"

  describe "grantPathFor tolerates either spelling of the pattern" $ do
    let want = "/" <> localPeer <> "/system/capability/grants/system/validate/echo"
    it "peer-relative" $
      grantPathFor localPeer "system/validate/echo" `shouldBe` want
    it "absolute (what §6.6's tree walk answers) does not double the peer segment" $
      grantPathFor localPeer ("/" <> localPeer <> "/system/validate/echo") `shouldBe` want
