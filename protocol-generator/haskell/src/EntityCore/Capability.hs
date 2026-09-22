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
    -- * §5.2 effective targets + §6.3 handler-level path check
  , effectiveTargets
  , checkPathPermission
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
  , ScopeKind (..)
  , matchesIdPattern
  , startsWith
  , isPeerId
  , parsePeerIdKt
  , extractPeer
  , firstSegment
  , findSignature
    -- * §5.6 temporal ceiling (CAP-5 / CAP-6) + §6.2 CAP-6a ingest
  , addTtl
  , minDefined
  , temporalFieldsRepresentable
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

-- ── §5.6 temporal ceiling (CAP-5 / CAP-6) ───────────────────────────────────

-- | Convert a DURATION term to an absolute timestamp, reporting 'Nothing' when
-- the term contributes no ceiling.
--
-- §5.6 rule 3: a term whose conversion overflows is treated as ABSENT, exactly
-- as a null term is. It MUST NOT wrap and MUST NOT saturate -- saturating encodes
-- differently from absence and manufactures @expires_at == 2^64-1@, a finite
-- bound no reader can distinguish from a deliberate one.
--
-- @ttl == 0@ is deliberately NOT special-cased: §5.6 rule 2 makes it a DEFINED
-- value yielding @created_at@ (expire immediately), and letting it fall out of
-- the arithmetic is what keeps it from ever collapsing into the absent /
-- \"no bound\" spelling.
addTtl :: Word64 -> Word64 -> Maybe Word64
addTtl createdAt ttl
  | sum' < createdAt = Nothing   -- wrapped => drop the term
  | otherwise = Just sum'
  where
    sum' = createdAt + ttl

-- | §5.6's MIN_DEFINED: the minimum over the DEFINED terms only, and 'Nothing'
-- when no term is defined (the token genuinely has no expiry).
--
-- Callers pass terms already shaped: absolute timestamps (@parent.expires_at@,
-- @caller_capability.expires_at@) enter directly; durations are converted with
-- 'addTtl' first. Mixing a duration in unconverted yields a near-epoch timestamp
-- and silently clamps every token to already-expired.
minDefined :: [Maybe Word64] -> Maybe Word64
minDefined terms = case [x | Just x <- terms] of
  [] -> Nothing
  xs -> Just (minimum xs)

-- ── §6.2 CAP-6a: unrepresentable temporal fields on INGEST ──────────────────

-- | True when every CAP-6a temporal field on a RECEIVED token is either ABSENT
-- (legal) or a 'VUInt'.
--
-- This is the reader-side half of CAP-6 and where a peer fails OPEN: 'uintField'
-- answers 'Nothing' for BOTH an absent field and a present non-uint one, so a
-- token carrying @expires_at: -1@ slipped past the expiry check and was honored.
-- §6.2 CAP-6a: such a token \"is malformed. A verifier MUST refuse it and MUST NOT
-- treat the unrepresentable field as absent.\"
temporalFieldsRepresentable :: Entity -> Bool
temporalFieldsRepresentable tok =
  all ok ["expires_at", "not_before", "created_at"]
  where
    ok k = case field tok k of
      Nothing -> True           -- absent is legal
      Just (VUInt _) -> True    -- representable
      Just _ -> False           -- present but undecodable as uint64

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

-- | The unmatchable value (0.8.2.20). Unreachable as a canonical path by
-- CONSTRUCTION: its first segment cannot be a peer_id, since 'isPeerId' requires
-- >= 46 Base58 characters and @-@ is outside the Base58 alphabet.
neverMatch :: Text
neverMatch = "/never-match"

-- | Resolve peer-relative paths to absolute "/{local}/..." form.
--
-- TOTAL (0.8.2.20): the return domain is "a canonical path OR 'neverMatch'". This
-- used to @error@, and the bottom was reachable from the wire — every normative
-- call site is a matcher with no error channel to consume one, so the exception
-- escaped the matcher, the resilience frame caught it, and @../x@ in a resource
-- exclude answered 500 (measured 2026-09-14). The diagnostic belongs at admission
-- (§6.5), which has a caller to answer.
canonicalize :: Text -> Text -> Text
canonicalize localPeer path
  | "./" `T.isPrefixOf` path || "../" `T.isPrefixOf` path = neverMatch
  | "*/" `T.isPrefixOf` path = neverMatch
  | "/" `T.isPrefixOf` path = path
  | otherwise = "/" <> localPeer <> "/" <> path

-- | Match a canonical (absolute) path against a canonical pattern.
matchesPattern :: Text -> Text -> Bool
matchesPattern path pattern
  -- 'neverMatch' never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
  -- rule rather than a property of the string: the guard below returns True for a
  -- bare "*", so safety must not rest on a value merely looking unmatchable.
  | path == neverMatch || pattern == neverMatch = False
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

-- | Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
-- call site — there is no default — so a new one cannot inherit the wrong matcher
-- silently, which is exactly the F40 defect.
data ScopeKind
  = -- | @operations@, @peers@ — @system\/capability\/id-scope@.
    IdScope
  | -- | @handlers@, @resources@ — @system\/capability\/path-scope@.
    PathScope
  deriving (Eq, Show)

-- | §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard
-- forms — bare @*@ and a trailing @\/*@ segment-prefix. None of the §5.4 path
-- transforms apply, so a pattern carrying path syntax is matched as a literal string:
-- a non-match, never a fault.
matchesIdPattern :: Text -> Text -> Bool
matchesIdPattern value pattern
  | pattern == "*" = True
  | "/*" `T.isSuffixOf` pattern = T.dropEnd 1 pattern `T.isPrefixOf` value
  | otherwise = value == pattern

-- | AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
-- fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
-- fail-OPEN in an exclude (carves out nothing -> the grant is SILENTLY WIDER than
-- its author wrote): same value, same matcher, opposite safety direction, so the
-- reading is chosen where the POSITION is known and 'matchesPattern' stays uniform
-- over its operands.
--
-- EVERY CALL SITE MUST GUARD IT ON PATH-SCOPE (0.8.2.24, N2/N3). This used to be
-- asked of every dimension — the comment here said so, "transcribing §5.2's loop
-- literally", and that was true of the loop as it then read. §5.2's exclude test
-- now sits INSIDE @if dimension_type == "system\/capability\/path-scope"@, and
-- §5.4 says the same from the other side: "a capability carrying an unmatchable
-- PATH-SCOPE pattern is INVALID ... It does NOT reach @operations@ or @peers@
-- [MUST]".
--
-- 'neverMatch' is a §5.4 PATH-canonicalization sentinel with no meaning on an
-- id-scope dimension, whose patterns are literal identifiers that §5.2's own
-- id-scope arm forbids putting through the §5.4 transforms. Asking it outside the
-- type dispatch ran an id pattern through those transforms purely to classify it
-- and then DENIED THE WHOLE DIMENSION on a property unrelated to whether the
-- exclude carves anything out: an @operations@ exclude of @*\/apply@ — an ordinary
-- namespaced operation name, a literal matching nothing under the id-scope grammar
-- — canonicalized to the sentinel and denied every operation. Over-denial, and
-- invisible on any well-formed grant.
excludeIsUnmatchable :: Text -> [Text] -> Bool
excludeIsUnmatchable frame = any (\p -> canonicalize frame p == neverMatch)

matchesScope :: Text -> Text -> Scope -> ScopeKind -> Bool
-- The guard is on the PATH-SCOPE arm only (0.8.2.24). The two id-scope dimensions
-- fall through to the literal matcher below unguarded, which is correct: under the
-- id-scope grammar every non-@*@ pattern is a literal, and a literal is never
-- structurally unmatchable, so there is nothing here for the sentinel to detect.
-- §5.4 says so outright and leaves the id-scope form of the carves-out-nothing
-- hazard deliberately open rather than minting a second sentinel for it — a scope
-- boundary, not an omission.
matchesScope localPeer _value s PathScope
  | excludeIsUnmatchable localPeer (scExcl s) = False   -- 0.8.2.21 — deny
matchesScope localPeer value s kind =
  let covered = case kind of
        IdScope -> \pats -> any (matchesIdPattern value) pats
        PathScope ->
          let cv = canonicalize localPeer value
           in \pats -> any (\p -> matchesPattern cv (canonicalize localPeer p)) pats
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
        -- An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before
        -- any target: the coverage test below is correct in isolation and is simply
        -- never reached on a sentinel, because matchesPattern answers False.
        && not (excludeIsUnmatchable granterPeer (scExcl s))
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
        matchesScope localPeer operation (grOperations g) IdScope
          && matchesScope localPeer handlerPattern (grHandlers g) PathScope
          && matchesScope localPeer targetPeer (fromMaybe (Scope [localPeer] []) (grPeers g)) IdScope
          && case resource of
            Nothing -> True
            Just r -> checkResourceScope localPeer granterPeer r (grResources g)
   in if any grantOk (grantsOfToken token) then Allow else Deny

-- ── §5.2 effective targets and §6.3 check_path_permission ─────────────────────

-- | §5.2's effective target list (0.8.2.20): the caller's own @resource.exclude@
-- removes entries from the request BEFORE anything else looks at it.
--
-- The survivors come back in the caller's OWN SPELLING, not canonicalized —
-- 0.8.2.21 is explicit that @effective_targets@ yields raw survivors, and the
-- distinction is load-bearing because the value flows on to the store lookup,
-- which canonicalizes for itself.
--
-- The 'Bool' says whether a @resource@ was present at all. An ABSENT resource and
-- a resource whose every target was excluded are different inputs to §3.3 — the
-- first is "no resource", the second is an empty effective list — and for a
-- resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with
-- different answers, not merely different inputs to one.
--
-- THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11):
-- "where an implementation projects @resource.targets@ onto the effective set
-- ahead of the handler, that projection MUST NOT be lossy about its own emptiness
-- — narrow when narrowing leaves something, and retain the raw pair when narrowing
-- would empty it." A function returning only a list cannot satisfy that:
-- collapsing @[qA] exclude [qA]@ to @[]@ deletes the two-empties discriminator
-- before any handler can read it, and the handler's refusal arm becomes dead code
-- that only a WIRE drive can detect.
--
-- A @targets@ key that is PRESENT but not an array reads as PRESENT-and-empty, not
-- as absent. Reading it as absent would answer it with the ABSENT case, which for
-- @get@ is the whole root listing — wider than the request, which is the answer
-- §3.3 forbids. (This is the one place the two vanguard peers diverged; corrected
-- toward the present reading.)
effectiveTargets :: Text -> Entity -> ([Text], Bool)
effectiveTargets localPeer exec =
  case field exec "resource" of
    Just r@(VMap _) -> case mapGet r "targets" of
      Nothing -> ([], False)
      Just targetsV ->
        let targets = textList targetsV
            callerExcl = maybe [] textList (mapGet r "exclude")
            -- The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's
            -- table rules it separately from the grant arm): 'canonicalize' answers
            -- 'neverMatch' and 'matchesPattern' then answers False, so the target
            -- simply survives. That asymmetry is 0.8.2.21's whole point and it is
            -- INHERITED from the primitives here rather than restated.
            dropped t =
              let ct = canonicalize localPeer t
               in any (\x -> matchesPattern ct (canonicalize localPeer x)) callerExcl
         in (filter (not . dropped) targets, True)
    _ -> ([], False)

-- | §6.3's handler-level path check.
--
-- IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the enforcement wherever the
-- subject is derived after dispatch, and the dispatch-level check can be made
-- VACUOUS by caller-controlled input: a caller who excludes the one target its
-- capability does not cover removes that target from 'checkPermission''s view
-- entirely, and a handler that then acts on it has authorized nothing.
--
-- THREE DIMENSIONS, NOT FOUR. @peers@ is not consulted here — the path is local by
-- construction at this point (§1.4's inbound rule refuses a foreign namespace at
-- §6.5 step 3, before any handler runs), and §6.3's signature names only
-- @handlers@, @operations@ and @resources@.
--
-- THE FRAME IS @local_peer_id@, NOT THE GRANTER, AND THAT IS THE SPEC'S OWN
-- SIGNATURE RATHER THAN A CHOICE. §6.3's block reads
-- @matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)@ —
-- there is no granter parameter to pass. §5.5a governs chain ATTENUATION, where
-- the subject is a pattern compared against a parent's pattern; this call site
-- compares a CONCRETE local path the handler is about to touch.
--
-- There is no caller-exclude set at this call site: the subject is a single
-- concrete path, and the caller's exclusions have already been applied in deriving
-- it. Every grant exclude covering the subject therefore denies — which
-- 'matchesScope' already implements, including 0.8.2.21's sentinel rule, so this
-- function is three calls to it and nothing else.
--
-- An empty @resources.include@ is a legal grant shape (§5.2: handlers that touch
-- no tree paths) and DENIES every path here, which is what that note says it
-- should: @any@ over an empty include list is False.
--
-- 'canonicalize' is total and may answer 'neverMatch', which matches no grant
-- (§5.4) — so a malformed path falls through to DENY rather than being matched
-- against anything.
checkPathPermission :: Text -> Text -> Text -> Entity -> Text -> Bool
checkPathPermission localPeer operation path token handlerPattern =
  let cp = canonicalize localPeer path
      grantOk g =
        matchesScope localPeer handlerPattern (grHandlers g) PathScope
          && matchesScope localPeer operation (grOperations g) IdScope
          && matchesScope localPeer cp (grResources g) PathScope
   in any grantOk (grantsOfToken token)

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
        temporalFieldsRepresentable cap   -- CAP-6a: see the chain-walk note below
          && (case uintField cap "not_before" of Just nb -> nowMs >= nb; Nothing -> True)
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
--
-- TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16). §3.6's grammar binds the scope
-- TYPE, not one function — "an implementation on the canonicalizing reading is
-- non-conformant and MUST adopt the literal matcher" — and F40's id-scope pin
-- therefore reaches here exactly as it reaches 'matchesScope', with delegation-chain
-- WIDENING named as the reason. This function used to canonicalize both operands on
-- every dimension, so an @operations@ or @peers@ pattern was put through the §5.4
-- path transforms purely to compare it: @entity-core-formalization@ measured 2 of 64
-- include pairs and 2 of 64 exclude pairs diverging (@\/tree\/get@ vs @*@,
-- @*\/apply@ vs @*@), FAIL-CLOSED, with a 16-pair control alphabet reporting zero —
-- which is why every hand-tried example missed it.
--
-- The kind is a parameter with NO DEFAULT and is named at every call site, for the
-- same reason 'matchesScope' takes one: a default is how the next dimension inherits
-- the wrong matcher silently, which is the original F40 defect.
--
-- The §5.4 sentinel needs no separate guard on either arm. On the path arm it is
-- inside 'matchesPattern', which refuses 'neverMatch' in EITHER operand, so every
-- path that reaches a match decision here is already guarded. On the id arm it does
-- not apply at all (0.8.2.24, N2/N3 — see 'excludeIsUnmatchable').
scopeSubset :: ScopeKind -> Text -> Text -> Scope -> Scope -> Bool
scopeSubset kind childPeer parentPeer child parent =
  all coveredByParentInclude (scIncl child)
    && all inheritedByChildExclude (scExcl parent)
  where
    coveredByParentInclude cp = case kind of
      IdScope -> any (matchesIdPattern cp) (scIncl parent)
      PathScope ->
        let cc = canonicalize childPeer cp
         in any (\pp -> matchesPattern cc (canonicalize parentPeer pp)) (scIncl parent)
    inheritedByChildExclude pe = case kind of
      IdScope -> any (matchesIdPattern pe) (scExcl child)
      PathScope ->
        let cpe = canonicalize parentPeer pe
         in any (\ce -> matchesPattern cpe (canonicalize childPeer ce)) (scExcl child)

-- | @childPeer@/@parentPeer@ are the §5.5a per-link granter frames applied to the
-- RESOURCE dimension only; handlers/operations/peers stay on @localPeer@. The scope
-- KIND is named per dimension alongside the frame: @handlers@/@resources@ are
-- path-scope, @operations@/@peers@ id-scope (§3.6, F40/F50).
grantSubset :: Text -> Text -> Text -> Grant -> Grant -> Bool
grantSubset localPeer childPeer parentPeer child parent =
  scopeSubset PathScope localPeer localPeer (grHandlers child) (grHandlers parent)
    && scopeSubset IdScope localPeer localPeer (grOperations child) (grOperations parent)
    && scopeSubset PathScope childPeer parentPeer (grResources child) (grResources parent)
    && let cp = fromMaybe (Scope [localPeer] []) (grPeers child)
           pp = fromMaybe (Scope [localPeer] []) (grPeers parent)
        in scopeSubset IdScope localPeer localPeer cp pp

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
                          -- CAP-6a FIRST: a present-but-unrepresentable temporal
                          -- field is malformed and MUST be refused. Must precede
                          -- the range checks below, which use uintField and so
                          -- cannot tell "absent" from "present but not a uint".
                          temporalFieldsRepresentable current
                            && (case uintField current "not_before" of Just nb -> nowMs >= nb; Nothing -> True)
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
