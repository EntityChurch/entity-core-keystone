{-# LANGUAGE OverloadedStrings #-}

-- | Capability system (L3) — the §5 verification core: pattern matching (§5.4),
-- request verification (§5.2 'verifyRequest' / 'checkPermission'),
-- delegation-chain verification (§5.5) + per-link granter frame (§5.5a / §PR-8),
-- and attenuation (§5.6).
--
-- Spec-first stance: derived from the §5 pseudocode directly. The Layer-1 verdict
-- is a bare 'Allow' / 'Deny' (§5.10 determinism); the dispatcher maps Deny → 403,
-- with the @unresolvable_grantee@ → 401 carve-out surfaced via 'ReqUnresolvable'.
--
-- == Verdict determinism (N8)
--
-- The verdict is a /pure/ function of the chain state. The store is captured as a
-- pure resolver ('Resolver' = @ByteString -> Maybe Entity@) closing over a content
-- snapshot ∪ the envelope @included@ set, plus a revocation-membership predicate;
-- given the same chain state, two peers produce the same verdict. There is no IO
-- in the verification path, so timing cannot perturb the verdict — only the
-- wall-clock @not_before@/@expires_at@ check reads a supplied @now_ms@.
module EntityCore.Capability
  ( Verdict (..)
  , ReqVerdict (..)
  , Resolver
  , verifyRequest
  , checkPermission
  , resolveGranterPeerId
  , grantsOfToken
  , parseGrant
  , grantSubset
  , Grant (..)
  , Scope (..)
    -- * §3.6 multi-signature granter (exposed for the accept-path unit test)
  , MultiGranter (..)
  , multiGranterOfEntity
  , isMultiSig
  , verifyMultiSigRoot
  , verifyCapabilityChain
    -- * path / pattern helpers (shared with the peer)
  , normalizeUri
  , canonicalize
  , matchesPattern
  , startsWith
  , isPeerId
  , parsePeerIdKt
  , extractPeer
  , firstSegment
  , findSignature
  ) where

import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe, mapMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word64)

import EntityCore.Codec.Value (Value (..))
import EntityCore.Identity (peerIdOfPubkey, verifySignature)
import EntityCore.Model
import qualified EntityCore.PeerId as PeerId

-- | Layer-1 (§5.10) verdict.
data Verdict = Allow | Deny
  deriving (Eq, Show)

-- | The §5.2 request verdict: a 3-way split so the dispatcher maps the §4.6 / F20
-- authentication-vs-authorization status boundary (authn → 401, authz → 403,
-- plus the §5.5 unresolvable-grantee 401 carve-out).
data ReqVerdict = ReqAllow | ReqAuthnFail | ReqAuthzDeny | ReqUnresolvable | ReqChainTooDeep
  deriving (Eq, Show)

-- | A pure entity resolver: included set ∪ content-store snapshot. (N8: the
-- verdict is a pure function of this.)
type Resolver = ByteString -> Maybe Entity

data Scope = Scope { scIncl :: [Text], scExcl :: [Text] }

data Grant = Grant
  { grHandlers :: Scope
  , grResources :: Scope
  , grOperations :: Scope
  , grPeers :: Maybe Scope
  }

-- ── parse helpers ─────────────────────────────────────────────────────────────

textList :: Value -> [Text]
textList (VArray l) = mapMaybe (\v -> case v of VText s -> Just s; _ -> Nothing) l
textList _ = []

parseScope :: Value -> Scope
parseScope c =
  Scope
    (maybe [] textList (mapGet c "include"))
    (maybe [] textList (mapGet c "exclude"))

parseGrant :: Value -> Grant
parseGrant c =
  let sc key = maybe (Scope [] []) parseScope (mapGet c key)
   in Grant (sc "handlers") (sc "resources") (sc "operations")
        (parseScope <$> mapGet c "peers")

grantsOfToken :: Entity -> [Grant]
grantsOfToken token = case field token "grants" of
  Just (VArray l) -> map parseGrant l
  _ -> []

-- ── §5.4 pattern matching ─────────────────────────────────────────────────────

startsWith :: Text -> Text -> Bool
startsWith prefix s = prefix `T.isPrefixOf` s

-- | URI normalization (§1.4): strip the @entity://@ scheme and prepend "/" to
-- produce an absolute path; peer-relative paths pass through to 'canonicalize'.
-- (The validator addresses ops as @entity://{peer}/...@ — Swift's headline fix.)
normalizeUri :: Text -> Text
normalizeUri uri
  | "entity://" `T.isPrefixOf` uri = "/" <> T.drop 9 uri
  | otherwise = uri

-- | Resolve peer-relative paths to absolute "/{local}/..." form. Throws (via the
-- caller's catch) on reserved directory-relative / ambiguous bare-wildcard paths.
canonicalize :: Text -> Text -> Text
canonicalize localPeer path
  | "./" `T.isPrefixOf` path || "../" `T.isPrefixOf` path =
      error "canonicalize: reserved directory-relative path"
  | "*/" `T.isPrefixOf` path = error "canonicalize: ambiguous bare peer wildcard"
  | "/" `T.isPrefixOf` path = path
  | otherwise = "/" <> localPeer <> "/" <> path

-- | Match a canonical (absolute) path against a canonical pattern.
matchesPattern :: Text -> Text -> Bool
matchesPattern path pattern
  | pattern == "*" = True
  | "/*/" `T.isPrefixOf` pattern =
      let remainder = T.drop 3 pattern
       in case T.findIndex (== '/') (T.drop 1 path) of
            Nothing -> False
            Just i -> matchesPattern (T.drop (i + 2) path) remainder
  | "/*" `T.isSuffixOf` pattern =
      let prefix = T.dropEnd 1 pattern -- keep trailing /
       in prefix `T.isPrefixOf` path
  | otherwise = path == pattern

matchesScope :: Text -> Text -> Scope -> Bool
matchesScope localPeer value s =
  let cv = canonicalize localPeer value
      covered pats = any (\p -> matchesPattern cv (canonicalize localPeer p)) pats
   in covered (scIncl s) && not (covered (scExcl s))

-- ── §5.2 check_permission ──────────────────────────────────────────────────────

firstSegment :: Text -> Text
firstSegment uri0 =
  let uri = if "/" `T.isPrefixOf` uri0 then T.drop 1 uri0 else uri0
   in case T.findIndex (== '/') uri of
        Just i -> T.take i uri
        Nothing -> uri

base58Alphabet :: Text
base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

isPeerId :: Text -> Bool
isPeerId seg =
  T.length seg >= 46 && T.all (\c -> T.elem c base58Alphabet) seg

-- | Parse the leading key_type varint from a Base58 peer_id (§4.6 hardening:
-- reject a claimed peer_id whose key_type byte is not Ed25519). 'Nothing' on a
-- malformed peer_id (treated as not-a-rejection by the caller).
parsePeerIdKt :: Text -> Maybe Integer
parsePeerIdKt pid = case PeerId.parsePeerId (TE.encodeUtf8 pid) of
  Right parts -> Just (PeerId.pidKeyType parts)
  Left _ -> Nothing

extractPeer :: Text -> Text -> Text
extractPeer localPeer uri =
  let first = firstSegment (normalizeUri uri)
   in if isPeerId first then first else localPeer

-- | §PR-8 frame discipline: the GRANT's resource patterns (@s.incl@/@s.excl@)
-- canonicalize against the GRANTER's peer_id (@granterPeer@), NOT the verifier's.
-- The request TARGET and caller-supplied EXCLUDE stay on the local frame (§5.4).
checkResourceScope :: Text -> Text -> Value -> Scope -> Bool
checkResourceScope localPeer granterPeer resource s =
  let targets = maybe [] textList (mapGet resource "targets")
      callerExcl = maybe [] textList (mapGet resource "exclude")
      coveredLocal pats v = any (\p -> matchesPattern v (canonicalize localPeer p)) pats
      coveredGrant pats v = any (\p -> matchesPattern v (canonicalize granterPeer p)) pats
   in not (null targets)
        && all
          ( \tgt ->
              let ct = canonicalize localPeer tgt
               in if coveredLocal callerExcl ct
                    then True
                    else
                      coveredGrant (scIncl s) ct
                        && not (coveredGrant (scExcl s) ct)
          )
          targets

-- | §PR-8: the frame for canonicalizing a cap's grant resource patterns is the
-- GRANTER's peer_id. Single-sig granter → derive peer_id from public_key;
-- multi-sig / unresolvable granter → 'Nothing' (caller falls back to local).
resolveGranterPeerId :: Resolver -> Entity -> Maybe Text
resolveGranterPeerId resolve cap =
  case bytesField cap "granter" of
    Nothing -> Nothing
    Just gh -> case resolve gh of
      Just g -> peerIdOfPubkey <$> bytesField g "public_key"
      Nothing -> Nothing

-- | Gate the wire request at the dispatch authorization boundary. @granterPeer@
-- is the §PR-8 frame for the cap's grant resource patterns; every other dimension
-- (operation, handler, target-peer scope) stays on the local frame.
checkPermission :: Text -> Text -> Entity -> Entity -> Text -> Verdict
checkPermission localPeer granterPeer exec token handlerPattern =
  let operation = fromMaybe "" (textField exec "operation")
      uri = fromMaybe "" (textField exec "uri")
      targetPeer = extractPeer localPeer uri
      resource = field exec "resource"
      grantOk g =
        matchesScope localPeer operation (grOperations g)
          && matchesScope localPeer handlerPattern (grHandlers g)
          && matchesScope localPeer targetPeer (fromMaybe (Scope [localPeer] []) (grPeers g))
          && case resource of
            Nothing -> True
            Just r -> checkResourceScope localPeer granterPeer r (grResources g)
   in if any grantOk (grantsOfToken token) then Allow else Deny

-- ── §3.6 M3 multi-signature granter ────────────────────────────────────────────
-- The capability @granter@ field is a union (§3.6): a single @system/hash@ (bytes,
-- single-sig — the existing behavior) OR a @{signers: [system/hash], threshold:
-- uint}@ descriptor (a map, multi-sig, ROOT-ONLY). A multi-sig root is verified by
-- 'verifyMultiSigRoot' — M3 structure first, then §5.5 M6 root-at-local + M4 k-of-n
-- quorum.

-- | A parsed multi-granter quorum descriptor: the signer identity hashes and the
-- k-of-n threshold.
data MultiGranter = MultiGranter
  { mgSigners :: [ByteString]
  , mgThreshold :: Word64
  }
  deriving (Eq, Show)

-- | Recognize a multi-sig granter: @granter@ is a CBOR map (not bytes) → parse
-- @signers@ (array of hash bytes) + @threshold@ (uint, defaulting to 0 = below the
-- M3 floor when absent/malformed). 'Nothing' for a single-sig (bytes) granter or a
-- missing granter.
multiGranterOfEntity :: Entity -> Maybe MultiGranter
multiGranterOfEntity cap = case field cap "granter" of
  Just g@(VMap _) ->
    let signers = case mapGet g "signers" of
          Just (VArray xs) -> mapMaybe (\v -> case v of VBytes b -> Just b; _ -> Nothing) xs
          _ -> []
        threshold = case mapGet g "threshold" of Just (VUInt t) -> t; _ -> 0
     in Just (MultiGranter signers threshold)
  _ -> Nothing

-- | True iff the capability carries a §3.6 multi-sig (map) granter.
isMultiSig :: Entity -> Bool
isMultiSig cap = case multiGranterOfEntity cap of Just _ -> True; Nothing -> False

-- | True iff the signer list contains a duplicate hash (M3: signers must be
-- distinct).
hasDuplicateSigners :: [ByteString] -> Bool
hasDuplicateSigners = go []
  where
    go _ [] = False
    go seen (s : rest) = s `elem` seen || go (s : seen) rest

-- | All @system/signature@ entities in the included set whose @target@ == the given
-- hash (the cap's content_hash, for M4).
signaturesTargeting :: ByteString -> [(ByteString, Entity)] -> [Entity]
signaturesTargeting target included =
  [ e
  | (_, e) <- included
  , entType e == "system/signature"
  , case bytesField e "target" of Just t -> t == target; Nothing -> False
  ]

-- | Verify a multi-signature ROOT capability (§3.6 M3 / §5.5 M4·M6). Returns True
-- (ALLOW) only if the quorum is well-formed AND a threshold of DISTINCT signers
-- signed the cap's content hash. Structural validation (M3) precedes signature
-- counting (§3.6 precedence 25): a malformed quorum is denied on its structure, not
-- on its signatures. Every path returns a 'Bool' → the dispatcher maps False to 403
-- @capability_denied@ (never a throw, never a diverge).
verifyMultiSigRoot :: Text -> Word64 -> Resolver -> [(ByteString, Entity)] -> Entity -> MultiGranter -> Bool
verifyMultiSigRoot localPeer nowMs resolve included cap mg =
  let signers = mgSigners mg
      n = length signers
      threshold = mgThreshold mg
      peerIdOf h = resolve h >>= \p -> peerIdOfPubkey <$> bytesField p "public_key"
      -- §3.6 M3 structure — root-only; a real quorum (n ≥ 2); a usable threshold
      -- (2 ≤ threshold ≤ n); distinct signers.
      structureOk =
        bytesField cap "parent" == Nothing
          && n >= 2
          && threshold >= 2
          && threshold <= fromIntegral n
          && not (hasDuplicateSigners signers)
      -- §5.5 M6 root-at-local — the local peer MUST be a quorum member.
      localInSigners = any (\s -> peerIdOf s == Just localPeer) signers
      -- temporal validity + grantee resolution (as for any root).
      temporalOk =
        (case uintField cap "not_before" of Just nb -> nowMs >= nb; Nothing -> True)
          && (case uintField cap "expires_at" of Just ex -> ex >= nowMs; Nothing -> True)
      granteeOk = case bytesField cap "grantee" of Just gh -> resolve gh /= Nothing; Nothing -> False
      -- §5.5 M4 k-of-n — count DISTINCT signers with a valid signature over the
      -- cap's content hash; ≥ threshold ⇒ quorum. A duplicate signature from the
      -- same signer does NOT inflate the count (we fold over the distinct signer
      -- list, recording each signer at most once).
      sigs = signaturesTargeting (entHash cap) included
      validSigners =
        foldl
          ( \acc s ->
              if s `elem` acc
                then acc
                else case resolve s of
                  Nothing -> acc
                  Just signerPeer ->
                    let signed =
                          any
                            ( \sgn ->
                                (case bytesField sgn "signer" of Just sg -> sg == s; Nothing -> False)
                                  && verifySignature sgn signerPeer
                            )
                            sigs
                     in if signed then s : acc else acc
          )
          []
          signers
      quorumOk = fromIntegral (length validSigners) >= threshold
   in structureOk && localInSigners && temporalOk && granteeOk && quorumOk

-- ── §5.5 / §5.6 chain verification + attenuation ───────────────────────────────

findSignature :: ByteString -> [(ByteString, Entity)] -> Maybe Entity
findSignature target included =
  let match (_, e) =
        entType e == "system/signature"
          && (case bytesField e "target" of Just t -> t == target; Nothing -> False)
   in lookupBy match included
  where
    lookupBy p = foldr (\x acc -> if p x then Just (snd x) else acc) Nothing

-- | §5.5a per-link granter frame. Multi-sig root (no @granter@) → local frame;
-- single-sig → derive from public_key; **preferred hard-fail** ('Nothing') on an
-- unresolvable granter or a resolved entity with no public_key (never a silent
-- fallback to local, which would re-admit the V1' bug class).
linkGranterPeer :: Resolver -> Text -> Entity -> Maybe Text
linkGranterPeer resolve localPeer cap =
  case bytesField cap "granter" of
    Nothing -> Just localPeer -- multi-sig root (M3) → local frame
    Just gh -> case resolve gh of
      Just g -> peerIdOfPubkey <$> bytesField g "public_key"
      Nothing -> Nothing -- unresolvable granter → deny

-- | §5.6: every child include covered by parent include; child inherits all
-- parent excludes. §5.5a: each side's patterns canonicalize against THAT side's
-- granter peer_id.
scopeSubset :: Text -> Text -> Scope -> Scope -> Bool
scopeSubset childPeer parentPeer child parent =
  all
    ( \cp ->
        let cc = canonicalize childPeer cp
         in any (\pp -> matchesPattern cc (canonicalize parentPeer pp)) (scIncl parent)
    )
    (scIncl child)
    && all
      ( \pe ->
          let cpe = canonicalize parentPeer pe
           in any (\ce -> matchesPattern cpe (canonicalize childPeer ce)) (scExcl child)
      )
      (scExcl parent)

-- | @childPeer@/@parentPeer@ are the §5.5a per-link granter frames applied to the
-- RESOURCE dimension only; handlers/operations/peers stay on @localPeer@.
grantSubset :: Text -> Text -> Text -> Grant -> Grant -> Bool
grantSubset localPeer childPeer parentPeer child parent =
  scopeSubset localPeer localPeer (grHandlers child) (grHandlers parent)
    && scopeSubset localPeer localPeer (grOperations child) (grOperations parent)
    && scopeSubset childPeer parentPeer (grResources child) (grResources parent)
    && let cp = fromMaybe (Scope [localPeer] []) (grPeers child)
           pp = fromMaybe (Scope [localPeer] []) (grPeers parent)
        in scopeSubset localPeer localPeer cp pp

isAttenuated :: Text -> Text -> Text -> Entity -> Entity -> Bool
isAttenuated localPeer childPeer parentPeer child parent =
  let cg = grantsOfToken child
      pg = grantsOfToken parent
      scopeOk = all (\c -> any (\p -> grantSubset localPeer childPeer parentPeer c p) pg) cg
      ttlOk = case (uintField parent "expires_at", uintField child "expires_at") of
        (Just _, Nothing) -> False -- child infinite, parent finite
        (Just pe, Just ce) -> ce <= pe
        (Nothing, _) -> True
   in scopeOk && ttlOk

-- | §5.7 delegation caveats — parent's caveats constrain its direct child.
checkDelegationCaveats :: Entity -> Entity -> Int -> Bool
checkDelegationCaveats parent child depth =
  case field parent "delegation_caveats" of
    Nothing -> True
    Just caveats ->
      let noDeleg = case mapGet caveats "no_delegation" of Just (VBool b) -> b; _ -> False
       in if noDeleg
            then False
            else
              let depthOk = case mapGet caveats "max_delegation_depth" of
                    Just (VUInt m) -> fromIntegral depth < m
                    _ -> True
                  ttlOk = case mapGet caveats "max_delegation_ttl" of
                    Just (VUInt maxttl) -> case (uintField child "expires_at", uintField child "created_at") of
                      (Just ex, Just cr) -> (ex - cr) <= maxttl
                      (Just _, Nothing) -> True
                      (Nothing, _) -> False
                    _ -> True
               in depthOk && ttlOk

-- | §5.5 walk to root via parent hashes. Left on too-deep / unreachable.
collectChain :: Resolver -> Entity -> Either Text [Entity]
collectChain resolve = go (0 :: Int) []
  where
    go depth acc current
      | depth > 64 = Left "ChainTooDeep"
      | otherwise =
          let acc' = current : acc
           in case bytesField current "parent" of
                Nothing -> Right (reverse acc') -- root reached
                Just ph -> case resolve ph of
                  Just parent -> go (depth + 1) acc' parent
                  Nothing -> Left "ChainUnreachable"

-- | §4.10(b) structural-bound pre-check: True if the authority chain rooted at
-- the capability exceeds the max depth (64). Walks parent pointers without
-- verifying signatures — depth is a purely structural property, gated BEFORE the
-- per-link authz walk so an over-deep chain is reported as 400 chain_depth_exceeded
-- (structural excess), distinct from a 403 capability_denied authz failure (arch
-- ruling, v7.75 §4.10(b)). An unreachable parent is NOT a depth problem — it
-- returns False here and is left for 'verifyCapabilityChain' to deny (403).
chainExceedsDepth :: Resolver -> Entity -> Bool
chainExceedsDepth resolve = go (0 :: Int)
  where
    go depth current
      | depth > 64 = True
      | otherwise = case bytesField current "parent" of
          Nothing -> False -- root reached within bound
          Just ph -> case resolve ph of
            Just parent -> go (depth + 1) parent
            Nothing -> False -- unreachable — not a depth problem

-- | §5.5 single-sig chain verification. Returns Allow/Deny, with the §5.5
-- unresolvable-grantee carve-out signalled by the 'Bool' (True = 401 carve-out).
verifyCapabilityChain :: Text -> Word64 -> Resolver -> [(ByteString, Entity)] -> Entity -> (Verdict, Bool)
verifyCapabilityChain localPeer nowMs resolve included capability =
  case collectChain resolve capability of
    Left _ -> (Deny, False)
    Right chain ->
      let root = last chain
          -- Root authority: a §3.6 M3 multi-sig root (root-only) must pass k-of-n
          -- quorum validation; a single-sig root must root at the local peer.
          rootOk = case multiGranterOfEntity root of
            Just mg -> verifyMultiSigRoot localPeer nowMs resolve included root mg
            Nothing -> case bytesField root "granter" of
              Just gh -> case resolve gh of
                Just g -> case bytesField g "public_key" of
                  Just pk -> peerIdOfPubkey pk == localPeer
                  Nothing -> False
                Nothing -> False
              Nothing -> False
       in if not rootOk
            then (Deny, False)
            else
              let n = length chain
                  step i current
                    -- §3.6 M3 multi-sig is ROOT-ONLY and is fully verified above
                    -- (structure, quorum signatures, temporal, grantee). At the root
                    -- (i == n-1) it contributes no additional per-link obligation; a
                    -- multi-sig token anywhere but the chain root is rejected.
                    | isMultiSig current = (False, i == n - 1)
                    | otherwise =
                    let sigOk = case bytesField current "granter" of
                          Just gh -> case (findSignature (entHash current) included, resolve gh) of
                            (Just sgn, Just granter) ->
                              let signerOk = case bytesField sgn "signer" of Just s -> s == gh; Nothing -> False
                               in signerOk && verifySignature sgn granter
                            _ -> False
                          Nothing -> False
                        granteeUnres = case bytesField current "grantee" of
                          Just gh -> resolve gh == Nothing
                          Nothing -> True
                        temporalOk =
                          (case uintField current "not_before" of Just nb -> nowMs >= nb; Nothing -> True)
                            && (case uintField current "expires_at" of Just ex -> ex >= nowMs; Nothing -> True)
                        linkOk
                          | i < n - 1 =
                              let parent = chain !! (i + 1)
                               in case (linkGranterPeer resolve localPeer current, linkGranterPeer resolve localPeer parent) of
                                    (Just childPeer, Just parentPeer) ->
                                      ( case (bytesField parent "grantee", bytesField current "granter") of
                                          (Just pg, Just cg) -> pg == cg
                                          _ -> False
                                      )
                                        && isAttenuated localPeer childPeer parentPeer current parent
                                        && checkDelegationCaveats parent current i
                                    _ -> False
                          | otherwise = True
                     in (granteeUnres, sigOk && temporalOk && linkOk)
                  results = zipWith step [0 ..] chain
                  -- §5.5: an unresolvable grantee anywhere raises the 401 carve-out,
                  -- which takes precedence over a plain Deny.
                  anyUnres = any fst results
                  allOk = all snd results
               in if anyUnres
                    then (Deny, True)
                    else if allOk then (Allow, False) else (Deny, False)

-- | §5.1 revocation marker check (caller supplies the membership predicate over
-- @system/capability/revocations/{hash_hex}@).
isRevoked :: (ByteString -> Bool) -> Resolver -> Entity -> Bool
isRevoked revoked resolve capability =
  let rootHash = case collectChain resolve capability of
        Right chain -> entHash (last chain)
        Left _ -> entHash capability
   in revoked (entHash capability) || revoked rootHash

-- | §5.2 request verification → 3-way verdict (the §4.6 / F20 status boundary).
-- @nowMs@ feeds the temporal check; @revoked@ is the revocation-membership
-- predicate (a pure snapshot of the revocations subtree).
verifyRequest :: Text -> Word64 -> (ByteString -> Bool) -> Resolver -> Envelope -> ReqVerdict
verifyRequest localPeer nowMs revoked resolve env =
  let exec = envRoot env
      included = envIncluded env
   in -- 2. signature / author — authentication class (→ 401).
      case findSignature (entHash exec) included of
        Nothing -> ReqAuthnFail
        Just sgn ->
          let authorH = bytesField exec "author"
              signerOk = case (bytesField sgn "signer", authorH) of (Just s, Just a) -> s == a; _ -> False
           in if not signerOk
                then ReqAuthnFail
                else case authorH >>= includedGet env of
                  Nothing -> ReqAuthnFail
                  Just author ->
                    if not (verifySignature sgn author)
                      then ReqAuthnFail
                      else -- 3. capability / chain — authorization class (→ 403).
                        case bytesField exec "capability" >>= includedGet env of
                          Nothing -> ReqAuthzDeny
                          Just capability
                            -- §4.10(b) resource bound: a chain exceeding max depth is
                            -- rejected as 400 chain_depth_exceeded (structural excess) BEFORE
                            -- the per-link authz walk — distinct from 403 capability_denied.
                            -- Arch v7.75 ruling: 400 lets the caller distinguish "shorten
                            -- your chain" from "you lack the capability".
                            | chainExceedsDepth resolve capability -> ReqChainTooDeep
                            | otherwise ->
                            case verifyCapabilityChain localPeer nowMs resolve included capability of
                              (_, True) -> ReqUnresolvable
                              (Deny, _) -> ReqAuthzDeny
                              (Allow, _) ->
                                let granteeOk = case (bytesField capability "grantee", authorH) of
                                      (Just g, Just a) -> g == a
                                      _ -> False
                                 in if not granteeOk
                                      then ReqAuthzDeny
                                      else if isRevoked revoked resolve capability then ReqAuthzDeny else ReqAllow
