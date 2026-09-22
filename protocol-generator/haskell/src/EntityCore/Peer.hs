{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Peer assembly — bootstrap, the four MUST system handlers (§6.2: tree,
-- handler, capability, connect), the dispatch chain (§6.5), per-connection state,
-- the v7.74 live hooks (§6.13a register/unregister, §6.13b outbound closure,
-- §6.10 emit via 'EntityCore.Store'), the §6.9a Peer Authority Bootstrap, and the
-- §7a conformance test-handlers.
--
-- Spec-first: the handshake (§4.1/§4.6 three-check proof-of-possession), the
-- dispatch chain order (verify → resolve → check_permission → handler), and the
-- §4.4 / §6.9a initial-grant delivery are derived directly from V7. Transport
-- lives in 'EntityCore.Transport'; this module is the protocol brain — a function
-- from inbound envelope to outbound response envelope, plus a per-connection
-- state record. Store mutation runs in 'IO' (STM underneath, §7b-safe); the
-- pure capability verdict comes from 'EntityCore.Capability'.
module EntityCore.Peer
  ( Peer (..)
  , Conn (..)
  , createPeer
  , newConn
  , dispatch
  , internalErrorResponse
  , outboundDispatch
  ) where

import Control.Monad (forM_, guard, when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef
import Data.Maybe (catMaybes, fromMaybe, isJust, listToMaybe, mapMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word64)
import System.IO (IOMode (ReadMode), withBinaryFile)

import EntityCore.Capability
  ( ReqVerdict (..)
  , Verdict (..)
  , canonicalize
  , checkPermission
  , extractPeer
  , findSignature
  , grantsOfToken
  , isPeerId
  , normalizeUri
  , resolveGranterPeerId
  , verifyRequest
  )
import qualified EntityCore.Capability as Cap
import EntityCore.Codec.Value (Value (..))
import EntityCore.Codec.Varint (varintDecode)
import EntityCore.ContentHash (contentHash)
import EntityCore.Identity (Identity (..), ed25519VerifyRaw, identityOfSeed, peerEntityOfPubkey, peerIdOfPubkey, signEntity, verifySignature)
import EntityCore.Model
import EntityCore.PeerId (PeerIdParts (..), parsePeerId)
import EntityCore.SeedPolicy (SeedPolicy (..))
import EntityCore.Store (Store)
import qualified EntityCore.Store as Store
import qualified EntityCore.TypeDefs as TypeDefs
import EntityCore.Wire (emptyParams, errorResult, makeExecute, makeResponse)

-- ── peer + connection state ──────────────────────────────────────────────────

data Peer = Peer
  { peerIdentity :: Identity
  , peerStore :: Store
  , peerLocal :: Text
  , peerSeedPolicy :: SeedPolicy
  , peerConformance :: Bool -- ^ --validate: register the system/validate/* §7a handlers
  }

-- | Per-connection state (§4.2). Mutable handshake fields + the §6.13(b)
-- handler-facing outbound seam (set by the transport when the connection is
-- reentrant; 'Nothing' otherwise).
data Conn = Conn
  { connEstablished :: IORef Bool
  , connIssuedNonce :: IORef (Maybe ByteString)
  , connHelloPeerId :: IORef (Maybe Text)
  , connOutbound :: IORef (Maybe (Envelope -> IO (Maybe Envelope)))
  , connOutCounter :: IORef Int
  }

newConn :: IO Conn
newConn = Conn <$> newIORef False <*> newIORef Nothing <*> newIORef Nothing <*> newIORef Nothing <*> newIORef 0

-- | A handler outcome: status, result entity, any protocol entities to bundle.
data Outcome = Outcome
  { ocStatus :: Int
  , ocResult :: Entity
  , ocIncluded :: [(ByteString, Entity)]
  }

ok :: Entity -> Outcome
ok result = Outcome 200 result []

okI :: [(ByteString, Entity)] -> Entity -> Outcome
okI included result = Outcome 200 result included

errOc :: Int -> Text -> Outcome
errOc status code = Outcome status (errorResult Nothing code) []

errMsg :: Int -> Text -> Text -> Outcome
errMsg status code msg = Outcome status (errorResult (Just msg) code) []

nowMs :: IO Word64
nowMs = round . (* 1000) <$> getPOSIXTime

-- ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ──────────────────────────

randomBytes :: Int -> IO ByteString
randomBytes n =
  -- §4.6 SHOULD ≥32-byte CSPRNG. Read EXACTLY n bytes from /dev/urandom — NOT
  -- BS.readFile (which reads to EOF; on a character device that never ends and
  -- hangs the connect handler).
  withBinaryFile "/dev/urandom" ReadMode (`BS.hGet` n)

-- ── grant construction (§4.4 / §5.4) ─────────────────────────────────────────

scopeV :: [Text] -> [Text] -> Value
scopeV incl excl =
  VMap
    ( (VText "include", VArray (map VText incl))
        : [(VText "exclude", VArray (map VText excl)) | not (null excl)]
    )

grantV :: [Text] -> [Text] -> [Text] -> Maybe [Text] -> Value
grantV handlers resources operations peers =
  VMap
    ( [ (VText "handlers", scopeV handlers [])
      , (VText "resources", scopeV resources [])
      , (VText "operations", scopeV operations [])
      ]
        ++ maybe [] (\p -> [(VText "peers", scopeV p [])]) peers
    )

-- ── §6.9a seed policy ─────────────────────────────────────────────────────────

-- | The §4.4 discovery floor: every authenticated identity gets at least this.
discoveryFloor :: [Value]
discoveryFloor =
  [ grantV ["system/tree"] ["system/type/*", "system/handler/*"] ["get"] Nothing
  , grantV ["system/capability"] [] ["request"] Nothing
  ]

-- | A wide-open admin scope — the degenerate @default → *@ (= retired
-- @--debug-open-grants@).
openGrantsScope :: [Value]
openGrantsScope = [grantV ["*"] ["*", "/*/*"] ["*"] (Just ["*"])]

-- | Full owner authority over the local namespace @/{peer_id}/*@ (§6.9a).
ownerGrants :: Peer -> [Value]
ownerGrants p = [grantV ["*"] ["*"] ["*"] (Just [peerLocal p])]

-- | Raw grants from a seed-policy entry, handling both §6.9a.0 shapes: a cap
-- token (detached-signature — verify the sig at the §3.5 pointer first) or a
-- policy-entry (scope template).
seedEntryGrants :: Peer -> Entity -> IO [Value]
seedEntryGrants p e
  | entType e == "system/capability/token" = do
      let sigPath = "/" <> peerLocal p <> "/system/signature/" <> hexOf (entHash e)
      msgn <- Store.getAt (peerStore p) sigPath
      pure $ case msgn of
        Just sgn | verifySignature sgn (idPeerEntity (peerIdentity p)) -> grantsOf
        _ -> []
  | entType e == "system/capability/policy-entry" = pure grantsOf
  | otherwise = pure []
  where
    grantsOf = case field e "grants" of Just (VArray l) -> l; _ -> []

-- | §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 →
-- default), then UNION the matched scope with the §4.4 discovery floor (v7.62 §8).
deriveSeedGrants :: Peer -> Entity -> Text -> IO [Value]
deriveSeedGrants p remotePeer remotePeerId = do
  let base = "/" <> peerLocal p <> "/system/capability/policy/"
  mEntry <-
    firstJustM
      [ Store.getAt (peerStore p) (base <> hexOf (entHash remotePeer))
      , Store.getAt (peerStore p) (base <> remotePeerId)
      , Store.getAt (peerStore p) (base <> "default")
      ]
  policyGrants <- maybe (pure []) (seedEntryGrants p) mEntry
  pure $ if null policyGrants then discoveryFloor else discoveryFloor ++ policyGrants

firstJustM :: Monad m => [m (Maybe a)] -> m (Maybe a)
firstJustM [] = pure Nothing
firstJustM (m : ms) = m >>= \case Just x -> pure (Just x); Nothing -> firstJustM ms

-- | Mint a root capability token granted by us to @granteeHash@. Signs it,
-- returns @(token, signature)@.
mintToken :: Peer -> ByteString -> Maybe ByteString -> [Value] -> IO (Entity, Entity)
mintToken p granteeHash parent grants = do
  t <- nowMs
  pure (mintTokenAt p t granteeHash parent Nothing grants)

-- | 'mintToken' with @created_at@ supplied by the caller and §5.6's MIN_DEFINED
-- ceiling attached, so a computed @expires_at@ is guaranteed relative to the SAME
-- instant that lands in the token (§5.10 also wants the evaluation timestamp
-- sampled once per verdict rather than re-read per term).
--
-- @Nothing@ for the expiry means no term was defined and the token genuinely has
-- no expiry -- the ONLY "no bound" spelling. @Just v@ is emitted verbatim,
-- including @v == created_at@, which §5.6 rule 2 requires for @ttl_ms == 0@ and
-- which means "already expired at every observable instant", not "unbounded".
mintTokenAt :: Peer -> Word64 -> ByteString -> Maybe ByteString -> Maybe Word64 -> [Value] -> (Entity, Entity)
mintTokenAt p createdAt granteeHash parent expiresAt grants =
  let dat =
        VMap
          ( [ (VText "granter", VBytes (idIdentityHash (peerIdentity p)))
            , (VText "grantee", VBytes granteeHash)
            , (VText "grants", VArray grants)
            , (VText "created_at", VUInt createdAt)
            ]
              ++ maybe [] (\e -> [(VText "expires_at", VUInt e)]) expiresAt
              ++ maybe [] (\ph -> [(VText "parent", VBytes ph)]) parent
          )
      token = makeEntity "system/capability/token" dat
      sgn = signEntity (peerIdentity p) token
   in (token, sgn)

-- ── §6.13(b) handler-facing outbound dispatch ─────────────────────────────────

-- | Build, sign (as the local peer), and send an outbound EXECUTE through the
-- §6.11 reentry seam on the serving connection (@connOutbound@), returning the
-- correlated EXECUTE_RESPONSE envelope. Present on every peer even though no core
-- handler originates — a runtime-registered handler (§6.13a) may.
outboundDispatch ::
  Peer ->
  Conn ->
  Text -> -- uri
  Text -> -- operation
  Entity -> -- params
  Maybe Value -> -- resource
  Entity -> -- capability
  Entity -> -- granter peer
  Entity -> -- capability signature
  IO (Maybe Envelope)
outboundDispatch p conn uri operation params resource capability granterPeer capabilitySignature = do
  mSend <- readIORef (connOutbound conn)
  case mSend of
    Nothing -> pure Nothing -- no reentrant connection → seam unavailable
    Just send -> do
      modifyIORef' (connOutCounter conn) (+ 1)
      n <- readIORef (connOutCounter conn)
      let requestId = "out-" <> T.pack (show n)
          exec = makeExecute requestId uri operation params resource (idIdentityHash (peerIdentity p)) (entHash capability)
          execSig = signEntity (peerIdentity p) exec
          included =
            [ (entHash capability, capability)
            , (entHash granterPeer, granterPeer)
            , (idIdentityHash (peerIdentity p), idPeerEntity (peerIdentity p))
            , (entHash capabilitySignature, capabilitySignature)
            , (entHash execSig, execSig)
            ]
      send (Envelope exec included)

-- ── connect handler (§4.1, §4.6) ──────────────────────────────────────────────

connectHandler :: Peer -> Conn -> Entity -> [(ByteString, Entity)] -> IO Outcome
connectHandler p conn exec included = do
  let op = fromMaybe "" (textField exec "operation")
  established <- readIORef (connEstablished conn)
  case op of
    "hello"
      | established -> pure (errOc 409 "connection_already_established")
      | otherwise -> do
          -- §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on
          -- a HALF-OPEN connection (hello done, authenticate not yet) is an
          -- operation we implement arriving in a state that forbids it — the same
          -- class as connection_already_established above, taking the same 409.
          -- A half-open connection is NOT established, so the guard above cannot
          -- reach it; §4.7 names this gap explicitly because two adjacent rules
          -- each look like they cover it and neither does. We re-issued a nonce
          -- and answered 200.
          alreadyGreeted <- readIORef (connIssuedNonce conn)
          let params = entityField exec "params"
              strArray key = case params >>= (`field` key) of
                Just (VArray l) -> Just (mapMaybe (\case VText s -> Just s; _ -> Nothing) l)
                _ -> Nothing
              hashOk = maybe True (elem "ecfv1-sha256") (strArray "hash_formats")
              keyOk = maybe True (elem "ed25519") (strArray "key_types")
              initiatorPid = params >>= (`textField` "peer_id")
              -- §4.5 mutual verifiability, the direction that is NOT the array.
              -- key_types is an ACCEPT-SET; the initiator's OWN key_type is not in
              -- it — it rides in its peer_id — so a hello may advertise a perfectly
              -- good accept-set and still name an identity we cannot verify.
              -- Checking only the array leaves that MUST unenforced at hello, which
              -- is where §4.5 wants it (the "symmetric earliest-reject guarantee").
              -- An UNPARSEABLE peer_id is deliberately left alone: that is a
              -- malformed field, not a key_type we lack, and authenticate refuses it.
              initiatorKeyOk = case initiatorPid of
                Nothing -> True
                Just pid -> case parsePeerId (TE.encodeUtf8 pid) of
                  Right parts -> pidKeyType parts == 0x01
                  Left _ -> True
              -- §4.5 `protocols` — the one negotiated field Required with NO
              -- default, so there is no floor to fall back to, and its two failure
              -- modes carry different codes on purpose:
              --   absent or empty     -> 400 invalid_request       (a malformed hello)
              --   non-empty, disjoint -> 400 incompatible_protocol (we compared)
              -- "a caller that named no version cannot be told the comparison
              -- failed" — the remedies differ (send the field vs change the
              -- version) and §4.7 exists so the code selects the remedy. The
              -- vocabulary is §8.4's identifiers, today the single entity-core/1.0.
              protos = strArray "protocols"
              -- The refusal ladder as DATA rather than as nesting: first Just wins.
              -- ORDER IS OBSERVABLE AND §4.5 FIXES NONE, so it is stated here in one
              -- place instead of being implied by indentation. `protocols` is LAST,
              -- matching the reference peer, which refuses key_types first. Checking
              -- protocols first is equally spec-legal and makes AGILITY-UNKNOWN-1
              -- answer incompatible_protocol, because that probe's own hello carries
              -- protocols ["entity-core/v7"] — a spec-line name, not a §8.4
              -- identifier. Matching the reference's precedence is the interoperable
              -- choice; the probe's identifier is routed as F56.
              refusal =
                listToMaybe $
                  catMaybes
                    [ errOc 409 "connection_sequence_error" <$ guard (isJust alreadyGreeted)
                    , errOc 400 "incompatible_hash_format" <$ guard (not hashOk)
                    , errOc 400 "unsupported_key_type" <$ guard (not keyOk)
                    , errOc 400 "unsupported_key_type" <$ guard (not initiatorKeyOk)
                    , errMsg 400 "invalid_request" "hello: protocols absent or empty"
                        <$ guard (maybe True null protos)
                    , errOc 400 "incompatible_protocol"
                        <$ guard (notElem "entity-core/1.0" (fromMaybe [] protos))
                    ]
          case refusal of
            Just o -> pure o
            Nothing -> do
                  writeIORef (connHelloPeerId conn) initiatorPid
                  nonce <- randomBytes 32
                  writeIORef (connIssuedNonce conn) (Just nonce)
                  t <- nowMs
                  let hello =
                        makeEntity
                          "system/protocol/connect/hello"
                          ( VMap
                              [ (VText "peer_id", VText (peerLocal p))
                              , (VText "nonce", VBytes nonce)
                              , (VText "protocols", VArray [VText "entity-core/1.0"])
                              , (VText "timestamp", VUInt t)
                              , (VText "hash_formats", VArray [VText "ecfv1-sha256"])
                              , (VText "key_types", VArray [VText "ed25519"])
                              ]
                          )
                  pure (ok hello)
    "authenticate"
      -- RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
      -- single-use nonce. The anti-replay property is the MUST and the mechanism
      -- (established-state tracking) is impl-defined, but the STATUS is pinned to
      -- 401 invalid_nonce — a 409 state-conflict under-signals the replay.
      | established -> pure (errOc 401 "invalid_nonce")
      | otherwise -> do
          mIssued <- readIORef (connIssuedNonce conn)
          case mIssued of
            Nothing -> pure (errOc 401 "invalid_nonce") -- authenticate before hello
            Just issued -> case entityField exec "params" of
              Nothing -> pure (errOc 401 "authentication_failed")
              Just auth
                -- §4.6 hardening: reject an unsupported key_type (field, non-32-byte
                -- pubkey, or claimed peer_id's leading key_type byte).
                | badKeyType auth -> pure (errOc 400 "unsupported_key_type")
                | otherwise -> do
                    let pub = bytesField auth "public_key"
                        echoed = bytesField auth "nonce"
                        claimedPeer = textField auth "peer_id"
                    if echoed /= Just issued
                      then pure (errOc 401 "invalid_nonce")
                      else case pub of
                        Nothing -> pure (errOc 401 "authentication_failed")
                        Just publicKey ->
                          let sigOk = case findSignature (entHash auth) included of
                                Just sgn -> case bytesField sgn "signature" of
                                  Just sb -> either (const False) id (verifyPoP publicKey (entHash auth) sb)
                                  Nothing -> False
                                Nothing -> False
                           in if not sigOk
                                then pure (errOc 401 "authentication_failed")
                                else
                                  if claimedPeer /= Just (peerIdOfPubkey publicKey)
                                    then pure (errOc 401 "identity_mismatch")
                                    else do
                                      helloPid <- readIORef (connHelloPeerId conn)
                                      if helloPid /= Nothing && helloPid /= claimedPeer
                                        then pure (errOc 401 "identity_mismatch")
                                        else do
                                          -- success: mint the §4.4 / §6.9a initial cap from
                                          -- the declared seed policy (UNION discovery floor).
                                          let remotePeer = peerEntityOfPubkey publicKey
                                          grants <- deriveSeedGrants p remotePeer (fromMaybe "" claimedPeer)
                                          (token, sgn) <- mintToken p (entHash remotePeer) Nothing grants
                                          writeIORef (connEstablished conn) True
                                          let grantResult =
                                                makeEntity "system/capability/grant" (VMap [(VText "token", VBytes (entHash token))])
                                          pure $
                                            okI
                                              [ (entHash token, token)
                                              , (idIdentityHash (peerIdentity p), idPeerEntity (peerIdentity p))
                                              , (entHash sgn, sgn)
                                              ]
                                              grantResult
    -- §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
    -- 400 invalid_request, not the 501 every other handler answers. The table
    -- separates a STATE conflict from an UNKNOWN operation because they select
    -- different remedies — "an unknown connect operation is not out of order at
    -- all; it exists in no state", so reporting connection_sequence_error would
    -- point the caller at its ORDERING when the defect is its OPERATION NAME.
    -- Row 10 is scoped "in any state", so this arm covers pre-handshake AND
    -- established; the genuine sequence cases are refused above, with 409.
    --
    -- SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
    -- (§3.3's 501 row, §6.2 — unknown op on a registered handler -> 501
    -- unsupported_operation) is a different contract and is separately gated;
    -- moving the shared 501 would trade one green check for another.
    other -> pure (errMsg 400 "invalid_request" ("connect: unknown operation " <> other))
  where
    badKeyType auth =
      (textField auth "key_type" /= Nothing && textField auth "key_type" /= Just "ed25519")
        || maybe False (\pk -> BS.length pk /= 32) (bytesField auth "public_key")
        || case textField auth "peer_id" of
          Just pid -> case Cap.parsePeerIdKt pid of Just kt -> kt /= 0x01; Nothing -> False
          Nothing -> False

-- proof-of-possession verifies a raw Ed25519 signature over the message
verifyPoP :: ByteString -> ByteString -> ByteString -> Either String Bool
verifyPoP = ed25519VerifyRaw

-- ── tree handler (§6.3) ───────────────────────────────────────────────────────

resourceTarget :: Entity -> Maybe Text
resourceTarget exec = case field exec "resource" of
  Just r -> case mapGet r "targets" of
    Just (VArray (VText t : _)) -> Just t
    _ -> Nothing
  Nothing -> Nothing

-- | §1.4 / §5.4 path-flex validation before canonicalize.
pathFlexOk :: Text -> Bool
pathFlexOk target
  | T.elem '\0' target = False
  | otherwise =
      let segs0 = T.splitOn "/" target
          (absOk, body0) =
            if "/" `T.isPrefixOf` target
              then case segs0 of
                ("" : first : _) -> (isPeerId first, drop 1 segs0)
                _ -> (False, segs0)
              else (True, segs0)
       in absOk
            && let body = case reverse body0 of ("" : rest) -> reverse rest; _ -> body0
                in all (\s -> not (T.null s) && s /= "." && s /= "..") body

isDeletionMarker :: Peer -> ByteString -> IO Bool
isDeletionMarker p h = do
  me <- Store.getByHash (peerStore p) h
  pure $ case me of Just e -> entType e == "system/deletion-marker"; Nothing -> False

buildListing :: Peer -> Text -> IO Outcome
buildListing p path = do
  entries0 <- Store.listing (peerStore p) path
  entries <-
    filterM
      ( \(_, mh, hasChildren) -> case mh of
          Just h | not hasChildren -> not <$> isDeletionMarker p h
          _ -> pure True
      )
      entries0
  let entryMap =
        map
          ( \(seg, mh, hasChildren) ->
              ( VText seg
              , entityToCbor
                  ( makeEntity
                      "system/tree/listing-entry"
                      ( VMap
                          ( (VText "has_children", VBool hasChildren)
                              : maybe [] (\h -> [(VText "hash", VBytes h)]) mh
                          )
                      )
                  )
              )
          )
          entries
  pure $
    ok
      ( makeEntity
          "system/tree/listing"
          ( VMap
              [ (VText "path", VText path)
              , (VText "entries", VMap entryMap)
              , (VText "count", VUInt (fromIntegral (length entries)))
              , (VText "offset", VUInt 0)
              ]
          )
      )

filterM :: Monad m => (a -> m Bool) -> [a] -> m [a]
filterM _ [] = pure []
filterM f (x : xs) = do b <- f x; rest <- filterM f xs; pure (if b then x : rest else rest)

-- | §6.3's @put@ admission ladder (normative, 0.8.2.11).
--
-- @put@ is a RECEIPT path: the submitter authors the entity, the peer validates
-- what it received (§1.8 item 1) and MUST NOT author a submitted entity's
-- @content_hash@ on the submitter's behalf. Two ordered steps:
--
--   1. STRUCTURE — a map carrying a non-empty text @type@, a PRESENT @data@
--      (any CBOR value; null is a legal payload), and a @content_hash@ that is
--      a well-formed @system/hash@ whose total byte length matches its format
--      code (§1.2). Any failure → 400 @invalid_request@. A well-formed hash
--      naming a format code this peer cannot verify is the separate §1.2
--      ingest-dispatch case → 400 @unsupported_content_hash_format@.
--   2. HASH — carried @content_hash@ vs @content_hash({type, data})@.
--      Disagreement → 400 @hash_mismatch@.
--
-- Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
-- inputs are exactly what step 1 establishes, so a submission that is both
-- malformed and mis-hashed is step 1's and answers @invalid_request@.
--
-- Structural admission is not semantic validation: @data@ is never checked
-- against the type named by @type@.
admitPut :: Value -> Either Outcome Entity
admitPut v = do
  pairs <- case v of
    VMap ps -> Right ps
    _ -> refuse "invalid_request" "put: entity is not a map"
  let get k = lookup (VText k) pairs
  typ <- case get "type" of
    Just (VText t) | not (T.null t) -> Right t
    _ -> refuse "invalid_request" "put: entity.type absent, empty or not a text string"
  dataV <- case get "data" of
    Just d -> Right d
    Nothing -> refuse "invalid_request" "put: entity.data absent"
  carried <- case get "content_hash" of
    Just (VBytes b) -> Right b
    _ -> refuse "invalid_request" "put: entity.content_hash absent or not a byte string"
  (code, rest) <- case varintDecode carried of
    Right r -> Right r
    Left _ -> refuse "invalid_request" "put: entity.content_hash is not a well-formed system/hash"
  digestLen <- case hashDigestLen code of
    -- §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
    -- invalid_request: the shape is fine, the algorithm is what we lack.
    Nothing -> refuse "unsupported_content_hash_format" "put: unsupported content_hash_format"
    Just n -> Right n
  if BS.length rest /= digestLen
    then refuse "invalid_request" "put: content_hash length does not match its format code"
    else case contentHash code typ dataV of
      Right computed
        | computed == carried ->
            -- The carried hash IS the entity's address; recomputing it into the
            -- store would be the authoring arm §6.3 forbids.
            Right (Entity typ dataV carried)
      _ -> refuse "hash_mismatch" "put: content_hash does not match content_hash({type, data})"
  where
    refuse code msg = Left (errMsg 400 code msg)

-- | Digest byte length for a @content_hash_format@ code per the §1.2 seed
-- table, or 'Nothing' when this peer cannot verify that code. The total wire
-- length is this plus the varint prefix, which is not a constant of the code
-- (§7.3): codes ≥ 0x80 occupy more than one byte.
--
-- __@0x00@ and @0x01@ only.__ @0x02@ (ECFv1-SHA-512) is ALLOCATED by §1.5 with a
-- defined 64-byte digest, and this peer used to verify it — @crypton@ ships
-- SHA-512, so an allocated code with a known algorithm looked computable and
-- therefore verifiable. That reading is withdrawn. §1.5 marks @0x02@ /Reserved/,
-- and all three ground-up implementations (go, rust, py) read /Reserved/ as
-- not-implemented and refuse it.
--
-- __The justification is the three-way convergence, NOT the wire vector that
-- surfaced it.__ Aligning a peer to a vector is authoring against the oracle;
-- aligning it to three independently written implementations is not, and those
-- three ARE independent convergence in a way 46 peers from one generator are not.
-- §1.5's @Status@ column never states what it obliges — that gap is routed as F55,
-- and until it is answered the conservative reading is the interoperable one.
--
-- @0x01@ STAYS: the crypto-agility corpus exercises SHA-384 and S2 goes red
-- without it. And the asymmetry is deliberate — __name the codes a peer can
-- VERIFY, not the codes its construction path will serialise__: 'contentHash'
-- will still emit a prefix for an unimplemented code on the forward-compat
-- construction path (§4.7), and this is the ingest surface, which is the one that
-- decides interop.
hashDigestLen :: Integer -> Maybe Int
hashDigestLen 0x00 = Just 32
hashDigestLen 0x01 = Just 48
hashDigestLen _ = Nothing

treeHandler :: Peer -> Entity -> IO Outcome
treeHandler p exec = do
  let op = fromMaybe "" (textField exec "operation")
      tgt = resourceTarget exec
  case (op, tgt) of
    (o, Just target) | (o == "get" || o == "put") && not (pathFlexOk target) ->
      pure (errMsg 400 "invalid_path" target)
    ("get", Nothing) -> buildListing p ("/" <> peerLocal p <> "/")
    ("get", Just target)
      | T.null target || T.last target == '/' ->
          buildListing p (canonicalize (peerLocal p) target)
    ("get", Just target) -> do
      let path = canonicalize (peerLocal p) target
      me <- Store.getAt (peerStore p) path
      case me of
        Just e ->
          let mode = entityField exec "params" >>= (`textField` "mode")
           in if mode == Just "hash"
                then pure (ok (makeEntity "system/hash" (VBytes (entHash e))))
                else pure (ok e)
        Nothing -> pure (errMsg 404 "not_found" path)
    ("put", Just target) -> do
      let path = canonicalize (peerLocal p) target
          params = entityField exec "params"
          entity = params >>= (`field` "entity")
          expected = params >>= (`bytesField` "expected_hash")
      current <- Store.hashAt (peerStore p) path
      let zero33 = BS.replicate 33 0
          casOk = case expected of
            Nothing -> True
            Just h | h == zero33 -> current == Nothing
            Just h -> current == Just h
      if not casOk
        then pure (errMsg 409 "hash_mismatch" path)
        else case entity of
          Just raw -> case admitPut raw of
            Left refusal -> pure refusal
            Right e -> do
              Store.bind (peerStore p) path e
              pure (ok (makeEntity "system/hash" (VBytes (entHash e))))
          Nothing -> pure (errMsg 400 "unexpected_params" "put: missing entity")
    (_, Nothing) -> pure (errMsg 400 "ambiguous_resource" "tree: missing resource target")
    (other, _) -> pure (errMsg 501 "unsupported_operation" ("tree: " <> other))

-- ── capability handler (§6.2) ──────────────────────────────────────────────────

-- | Find a token entity by content hash in the local store. Used for the §5.6
-- @parent.expires_at@ term on the delegate path; an unresolvable parent simply
-- contributes no term (MIN_DEFINED is over DEFINED terms only).
resolveToken :: Peer -> ByteString -> IO (Maybe Entity)
resolveToken p h = Store.getByHash (peerStore p) h

isZeroHash :: ByteString -> Bool
isZeroHash = BS.all (== 0)

mintBounded :: Peer -> Maybe Entity -> [Value] -> Maybe Word64 -> ByteString -> Maybe ByteString -> IO Outcome
mintBounded p callerCap reqGrants reqTtlMs granteeHash parent = do
  let bounded = case callerCap of
        Nothing -> False
        Just cap ->
          let parentGrants = grantsOfToken cap
           in all
                ( \cg ->
                    let c = Cap.parseGrant cg
                     in any (\pg -> Cap.grantSubset (peerLocal p) (peerLocal p) (peerLocal p) c pg) parentGrants
                )
                reqGrants
  if not bounded
    then pure (errOc 403 "scope_exceeds_authority")
    else do
      -- §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE
      -- and convert the duration terms against that same instant.
      --
      -- Not an authorization decision: an over-long ttl_ms from a bounded caller
      -- MINTS a clamped token at 200 -- "rejecting it is non-conformant" (§5.6).
      -- The bound exists because `request` mints a ROOT token (parent: null), so
      -- §5.6's parent-child attenuation never reaches it.
      createdAt <- nowMs
      parentExpiry <- case parent of
        Nothing -> pure Nothing
        Just ph -> do
          mpe <- resolveToken p ph
          pure (mpe >>= \pe -> uintField pe "expires_at")
      let callerExpiry = callerCap >>= \c -> uintField c "expires_at"
          reqExpiry = reqTtlMs >>= Cap.addTtl createdAt
          expiresAt = Cap.minDefined [parentExpiry, callerExpiry, reqExpiry]
          (token, sgn) = mintTokenAt p createdAt granteeHash parent expiresAt reqGrants
      let grantResult = makeEntity "system/capability/grant" (VMap [(VText "token", VBytes (entHash token))])
      pure $
        okI
          [ (entHash token, token)
          , (idIdentityHash (peerIdentity p), idPeerEntity (peerIdentity p))
          , (entHash sgn, sgn)
          ]
          grantResult

reqGrantsOf :: Maybe Entity -> [Value]
reqGrantsOf params = case params >>= (`field` "grants") of Just (VArray l) -> l; _ -> []

-- | §5.6: @request.ttl_ms@ is a DURATION term. Absent => no term. A present but
-- non-uint value is likewise no term (and the frame carrying it is rejected at
-- decode by §6.3 long before here).
reqTtlOf :: Maybe Entity -> Maybe Word64
reqTtlOf params = params >>= \pe -> uintField pe "ttl_ms"

capabilityHandler :: Peer -> Entity -> Maybe Entity -> IO Outcome
capabilityHandler p exec callerCap = do
  let op = fromMaybe "" (textField exec "operation")
      params = entityField exec "params"
      author = bytesField exec "author"
  case op of
    "request" -> case author of
      Nothing -> pure (errOc 403 "capability_denied")
      Just granteeHash -> mintBounded p callerCap (reqGrantsOf params) (reqTtlOf params) granteeHash Nothing
    "delegate" -> case params >>= (`bytesField` "parent") of
      Nothing -> pure (errMsg 400 "unexpected_params" "delegate: parent required")
      Just ph | isZeroHash ph -> pure (errMsg 400 "unexpected_params" "delegate: zero parent")
      Just ph ->
        if author /= Just (idIdentityHash (peerIdentity p))
          then pure (errMsg 501 "unsupported_operation" "delegate: same-peer-only in v1")
          else case author of
            Nothing -> pure (errOc 403 "capability_denied")
            Just granteeHash -> mintBounded p callerCap (reqGrantsOf params) (reqTtlOf params) granteeHash (Just ph)
    "revoke" -> case params >>= (`bytesField` "token") of
      Nothing -> pure (errMsg 400 "unexpected_params" "revoke: missing token")
      Just tokenH | isZeroHash tokenH -> pure (errMsg 400 "unexpected_params" "revoke: zero token")
      Just tokenH -> do
        t <- nowMs
        let marker =
              makeEntity
                "system/capability/revocation"
                (VMap [(VText "token", VBytes tokenH), (VText "revoked_at", VUInt t)])
        Store.bind (peerStore p) ("/" <> peerLocal p <> "/system/capability/revocations/" <> hexOf tokenH) marker
        pure (ok emptyParams)
    "configure" -> case params >>= (`textField` "peer_pattern") of
      Nothing -> pure (errMsg 400 "unexpected_params" "configure: missing peer_pattern")
      Just pp ->
        let isHex = T.length pp == 66 && T.all (\c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) pp
         in if not (pp == "default" || isHex || isPeerId pp)
              then pure (errMsg 400 "invalid_peer_pattern" pp)
              else case params of
                Just prm -> do
                  Store.bind (peerStore p) ("/" <> peerLocal p <> "/system/capability/policy/" <> pp) prm
                  pure (ok emptyParams)
                Nothing -> pure (errOc 400 "unexpected_params")
    other -> pure (errMsg 501 "unsupported_operation" ("capability: " <> other))

-- ── handlers handler (§6.2 / §6.13(a)) — register/unregister ──────────────────

registerPattern :: Entity -> Either Outcome Text
registerPattern exec = case resourceTarget exec of
  Nothing -> Left (errMsg 400 "ambiguous_resource" "register/unregister require exactly one resource target")
  Just target ->
    let prefix = "system/handler/"
     in if not (prefix `T.isPrefixOf` target) || T.length target == T.length prefix
          then Left (errMsg 400 "invalid_resource" "resource target MUST be system/handler/{pattern}")
          else Right (T.drop (T.length prefix) target)

-- | §6.2: user-installed handlers MUST NOT register at system/* paths.
isReservedSystemPattern :: Text -> Bool
isReservedSystemPattern pattern = pattern == "system" || "system/" `T.isPrefixOf` pattern

-- | register (§6.13a / §6.2): the five normative writes. (1) manifest, (2) types,
-- (3) self-issued signed grant, (4) grant-signature at @system/signature/{hash}@
-- (§3.5 pointer), (5) interface index. A 501 stub is non-conformant under v7.74.
registerHandler :: Peer -> Entity -> IO Outcome
registerHandler p exec = case registerPattern exec of
  Left e -> pure e
  Right pattern
    | isReservedSystemPattern pattern ->
        pure (errMsg 403 "forbidden_pattern" ("§6.2: user-installed handlers MUST NOT register at system/* paths: " <> pattern))
  Right pattern -> case entityField exec "params" of
    Nothing -> pure (errMsg 400 "unexpected_params" "register: missing params")
    Just req
      | entType req /= "system/handler/register-request" ->
          pure (errMsg 400 "unexpected_params" ("register expects register-request, got " <> entType req))
      | otherwise -> do
          let manifest = fromMaybe (VMap []) (field req "manifest")
              name = case mapGet manifest "name" of Just (VText s) -> s; _ -> pattern
              operations = fromMaybe (VMap []) (mapGet manifest "operations")
              exprPath = case mapGet manifest "expression_path" of Just (VText s) -> Just s; _ -> Nothing
              internalScope = mapGet manifest "internal_scope"
              grantScope = case (field req "requested_scope", internalScope) of
                (Just (VArray l), _) -> l
                (_, Just (VArray l)) -> l
                _ -> []
              interfaceRel = "system/handler/" <> pattern
              absPath rel = "/" <> peerLocal p <> "/" <> rel
              handlerE =
                makeEntity
                  "system/handler"
                  ( VMap
                      ( (VText "interface", VText interfaceRel)
                          : maybe [] (\pp -> [(VText "expression_path", VText pp)]) exprPath
                          ++ maybe [] (\s -> [(VText "internal_scope", s)]) internalScope
                      )
                  )
          -- (1) manifest at the pattern path.
          Store.bind (peerStore p) (absPath pattern) handlerE
          -- (2) associated types at system/type/{type_name}.
          case field req "types" of
            Just (VMap kvs) ->
              forM_ kvs $ \case
                (VText tn, v) -> Store.bind (peerStore p) (absPath ("system/type/" <> tn)) (makeEntity "system/type" v)
                _ -> pure ()
            _ -> pure ()
          -- (3) self-issued signed grant + (4) grant-signature at the §3.5 pointer.
          (token, sgn) <- mintToken p (idIdentityHash (peerIdentity p)) Nothing grantScope
          Store.bind (peerStore p) (absPath ("system/capability/grants/" <> pattern)) token
          Store.bind (peerStore p) (absPath ("system/signature/" <> hexOf (entHash token))) sgn
          -- (5) interface index.
          let ifaceE =
                makeEntity
                  "system/handler/interface"
                  (VMap [(VText "pattern", VText pattern), (VText "name", VText name), (VText "operations", operations)])
          Store.bind (peerStore p) (absPath interfaceRel) ifaceE
          let result =
                makeEntity
                  "system/handler/register-result"
                  (VMap [(VText "pattern", VText pattern), (VText "grant", entData token)])
          pure (ok result)

-- | unregister (§6.2): reverse all five writes; grant-signature removed alongside
-- the grant (writer symmetry). Installed types left in place (A-OC-009).
unregisterHandler :: Peer -> Entity -> IO Outcome
unregisterHandler p exec = case registerPattern exec of
  Left e -> pure e
  Right pattern -> do
    let absPath rel = "/" <> peerLocal p <> "/" <> rel
    mg <- Store.getAt (peerStore p) (absPath ("system/capability/grants/" <> pattern))
    case mg of
      Just g -> do
        Store.unbind (peerStore p) (absPath ("system/signature/" <> hexOf (entHash g)))
        Store.unbind (peerStore p) (absPath ("system/capability/grants/" <> pattern))
      Nothing -> pure ()
    Store.unbind (peerStore p) (absPath pattern)
    Store.unbind (peerStore p) (absPath ("system/handler/" <> pattern))
    pure (ok emptyParams)

handlersHandler :: Peer -> Entity -> IO Outcome
handlersHandler p exec = case fromMaybe "" (textField exec "operation") of
  "register" -> registerHandler p exec
  "unregister" -> unregisterHandler p exec
  other -> pure (errMsg 501 "unsupported_operation" ("handler: " <> other))

-- | Entity-native dispatch (§6.13a): a dynamically-registered handler has no
-- in-process body; evaluate the body at its expression_path. The minimal
-- @compute/literal@ shape returns a @compute/result@ (the §10.1 round-trip);
-- richer bodies → 501. See A-HS-010.
entityNativeDispatch :: Peer -> Text -> IO Outcome
entityNativeDispatch p handlerPath = do
  mhe <- Store.getAt (peerStore p) handlerPath
  case mhe of
    Nothing -> pure (errMsg 404 "handler_not_found" handlerPath)
    Just he -> case textField he "expression_path" of
      Nothing -> pure (errMsg 501 "no_handler_body" handlerPath)
      Just exprPath -> do
        let absP = canonicalize (peerLocal p) exprPath
        mexpr <- Store.getAt (peerStore p) absP
        case mexpr of
          Nothing -> pure (errMsg 404 "expression_not_found" absP)
          Just expr
            | entType expr == "compute/literal" -> case field expr "value" of
                Just value ->
                  pure
                    ( ok
                        ( makeEntity
                            "compute/result"
                            (VMap [(VText "value", value), (VText "expression", VBytes (entHash expr))])
                        )
                    )
                Nothing -> pure (errMsg 400 "unexpected_params" "compute/literal missing value")
            | otherwise -> pure (errMsg 501 "unsupported_expression" (entType expr))

typesHandler :: Peer -> Entity -> IO Outcome
typesHandler _ exec =
  pure (errMsg 501 "unsupported_operation" ("type: " <> fromMaybe "" (textField exec "operation")))

-- ── §7a conformance test-handlers (system/validate namespace) ─────────────────
-- NOT core protocol — conformance scaffolding (GUIDE-CONFORMANCE §7a), present
-- only under the conformance opt-in (--validate), off by default.

-- | echo — return the params entity VERBATIM (no compute, no re-wrap; the
-- cohort-wide re-wrap bug is the non-conformant party).
echoHandler :: Peer -> Entity -> IO Outcome
echoHandler _ exec = case entityField exec "params" of
  Just prm -> pure (ok prm)
  Nothing -> pure (errMsg 400 "invalid_params" "echo requires a params entity")

-- | dispatch-outbound — originate exactly one outbound EXECUTE via §6.11 reentry
-- back to the caller, return the downstream response verbatim (generic relay).
dispatchOutboundHandler :: Peer -> Conn -> Entity -> IO Outcome
dispatchOutboundHandler p conn exec = case entityField exec "params" of
  Nothing -> pure (errMsg 400 "invalid_params" "dispatch-outbound requires a params entity")
  Just prm ->
    let target = fromMaybe "" (textField prm "target")
        operation = fromMaybe "" (textField prm "operation")
     in case (field prm "value", entityField prm "reentry_capability", entityField prm "reentry_granter", entityField prm "reentry_cap_signature") of
          (Just value, Just capability, Just granterPeer, Just capabilitySignature) -> do
            -- §7a.1: [value] IS the outbound params data — pass through, do NOT re-wrap.
            let inner = makeEntity "primitive/any" value
                resource = VMap [(VText "targets", VArray [VText ("system/handler/" <> target)])]
            menv <- outboundDispatch p conn target operation inner (Just resource) capability granterPeer capabilitySignature
            case menv of
              Nothing -> pure (errMsg 503 "no_outbound_seam" "no live §6.11 reentry connection")
              Just env ->
                let status = fromMaybe 0 (uintField (envRoot env) "status")
                    resultCbor = fromMaybe (VMap []) (field (envRoot env) "result")
                 in pure (ok (makeEntity "primitive/any" (VMap [(VText "status", VUInt status), (VText "result", resultCbor)])))
          _ -> pure (errMsg 400 "invalid_params" "dispatch-outbound requires value + reentry authority")

-- ── dispatcher-level signature ingestion (§6.5) ───────────────────────────────

ingestSignatures :: Peer -> Envelope -> IO ()
ingestSignatures p env =
  forM_ (envIncluded env) $ \(_, e) ->
    when (entType e == "system/signature") $ do
      Store.putEntity (peerStore p) e
      case bytesField e "signer" of
        Just signerH -> case includedGet env signerH of
          Just signerPeer -> do
            Store.putEntity (peerStore p) signerPeer
            case (bytesField e "target", bytesField signerPeer "public_key") of
              (Just target, Just pk) -> do
                let pid = peerIdOfPubkey pk
                Store.bind (peerStore p) ("/" <> pid <> "/system/signature/" <> hexOf target) e
              _ -> pure ()
          Nothing -> pure ()
        Nothing -> pure ()

-- ── handler resolution (§6.6) — backward tree-walk ────────────────────────────

resolveHandler :: Peer -> Text -> IO (Maybe (Text, Text))
resolveHandler p path = do
  let segs = T.splitOn "/" path
      n = length segs
      tryLen i
        | i < 1 = pure Nothing
        | otherwise = do
            let prefix = T.intercalate "/" (take i segs)
            me <- Store.getAt (peerStore p) prefix
            case me of
              Just e | entType e == "system/handler" -> pure (Just (prefix, T.drop (T.length prefix) path))
              _ -> tryLen (i - 1)
  tryLen n

stripLocal :: Peer -> Text -> Text
stripLocal p pattern =
  let prefix = "/" <> peerLocal p <> "/"
   in if prefix `T.isPrefixOf` pattern then T.drop (T.length prefix) pattern else pattern

-- ── dispatch chain (§6.5) ──────────────────────────────────────────────────────

internalErrorResponse :: Envelope -> Maybe Envelope
internalErrorResponse env =
  let requestId = fromMaybe "" (textField (envRoot env) "request_id")
   in Just (Envelope (makeResponse requestId 500 (errorResult Nothing "internal_error")) [])

-- | A pure snapshot resolver over included ∪ content store (N8). Build it once per
-- dispatch (after signature ingestion) so the capability verdict is a pure
-- function of a fixed chain state.
buildResolver :: Peer -> Envelope -> IO (ByteString -> Maybe Entity, ByteString -> Bool)
buildResolver p env = do
  contentSnapshot <- Store.snapshotContentFn (peerStore p)
  treeSnapshot <- Store.snapshotTreeMember (peerStore p)
  let included = envIncluded env
      resolve h = case lookup h included of Just e -> Just e; Nothing -> contentSnapshot h
      revoked h = treeSnapshot ("/" <> peerLocal p <> "/system/capability/revocations/" <> hexOf h)
  pure (resolve, revoked)

dispatch :: Peer -> Conn -> Envelope -> IO (Maybe Envelope)
dispatch p conn env = do
  let exec = envRoot env
  if entType exec /= "system/protocol/execute"
    then pure Nothing -- §3.3: server side ignores non-EXECUTE
    else do
      let requestId = fromMaybe "" (textField exec "request_id")
          uri = fromMaybe "" (textField exec "uri")
      outcome <-
        if uri == "system/protocol/connect"
          then connectHandler p conn exec (envIncluded env)
          else do
            ingestSignatures p env
            (resolve, revoked) <- buildResolver p env
            t <- nowMs
            -- §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate
            -- used to sit inside the ReqAllow arm, so a pre-establishment EXECUTE naming a
            -- FOREIGN namespace took the 401 an unauthenticated request takes. §4.7's own
            -- reason: "a 401 directs the caller to authenticate and retry, and for a
            -- foreign-namespace address that retry cannot succeed at any authentication
            -- state — so the 401 names a remedy that does not exist." §6.5 step 3 calls it
            -- "a gate, not an ordering preference" and §1.4 makes the downstream permission
            -- check unreachable here, so evaluating authentication first can only mislead.
            let addrPath = canonicalize (peerLocal p) (normalizeUri uri)
            if extractPeer (peerLocal p) addrPath /= peerLocal p
              then pure (errMsg 400 "invalid_request" "not local peer")
              else case verifyRequest (peerLocal p) t revoked resolve env of
              ReqUnresolvable -> pure (errOc 401 "unresolvable_grantee")
              ReqAuthnFail -> pure (errOc 401 "authentication_failed")
              ReqAuthzDeny -> pure (errOc 403 "capability_denied")
              ReqChainTooDeep -> pure (errOc 400 "chain_depth_exceeded")
              ReqAllow -> do
                -- (The §1.4 address gate that used to sit here has moved ABOVE the
                -- verdict — §4.7 0.8.2.6 orders it before authentication. Reaching this
                -- arm at all now means the path is local.)
                let path = addrPath
                do
                    mres <- resolveHandler p path
                    case mres of
                      Nothing -> pure (errMsg 404 "handler_not_found" path)
                      Just (pattern, _suffix) -> do
                        let callerCap = bytesField exec "capability" >>= includedGet env
                        case callerCap of
                          Nothing -> pure (errOc 403 "capability_denied")
                          Just cap -> do
                            let granterPeer = fromMaybe (peerLocal p) (resolveGranterPeerId resolve cap)
                            case checkPermission (peerLocal p) granterPeer exec cap pattern of
                              Deny -> pure (errOc 403 "capability_denied")
                              Allow -> case stripLocal p pattern of
                                "system/tree" -> treeHandler p exec
                                "system/capability" -> capabilityHandler p exec callerCap
                                "system/handler" -> handlersHandler p exec
                                "system/type" -> typesHandler p exec
                                "system/validate/echo" -> echoHandler p exec
                                "system/validate/dispatch-outbound" -> dispatchOutboundHandler p conn exec
                                _ -> entityNativeDispatch p pattern
      let response = makeResponse requestId (ocStatus outcome) (ocResult outcome)
      pure (Just (Envelope response (ocIncluded outcome)))

-- ── bootstrap (§6.9) ──────────────────────────────────────────────────────────

opSpec :: Maybe Text -> Maybe Text -> Value
opSpec inp out =
  VMap (f "input_type" inp ++ f "output_type" out)
  where
    f k = maybe [] (\s -> [(VText k, VText s)])

bootstrapHandlers :: [(Text, Text, [(Text, (Maybe Text, Maybe Text))])]
bootstrapHandlers =
  [ ("system/tree", "Tree", [("get", (Nothing, Nothing)), ("put", (Nothing, Nothing))])
  ,
    ( "system/handler"
    , "Handlers"
    ,
      [ ("register", (Just "system/handler/register-request", Just "system/handler/register-result"))
      , ("unregister", (Just "system/handler/unregister-request", Nothing))
      ]
    )
  , ("system/type", "Types", [("validate", (Just "system/type/validate-request", Just "system/type/validate-result"))])
  ,
    ( "system/capability"
    , "Capability"
    ,
      [ ("request", (Just "system/capability/request", Just "system/capability/grant"))
      , ("revoke", (Just "system/capability/revoke-request", Nothing))
      , ("configure", (Just "system/capability/policy-entry", Nothing))
      , ("delegate", (Just "system/capability/delegate-request", Just "system/capability/grant"))
      ]
    )
  , ("system/protocol/connect", "Connect", [("hello", (Nothing, Nothing)), ("authenticate", (Nothing, Nothing))])
  ]

-- | Install a handler's three bootstrap entities (manifest at pattern, interface
-- index, empty grant).
installBootstrapHandler :: Peer -> (Text, Text, [(Text, (Maybe Text, Maybe Text))]) -> IO ()
installBootstrapHandler p (pattern, name, ops) = do
  let operations = VMap (map (\(o, (i, ou)) -> (VText o, opSpec i ou)) ops)
      handlerE = makeEntity "system/handler" (VMap [(VText "interface", VText ("system/handler/" <> pattern))])
  Store.bind (peerStore p) ("/" <> peerLocal p <> "/" <> pattern) handlerE
  let interfaceE =
        makeEntity
          "system/handler/interface"
          (VMap [(VText "pattern", VText pattern), (VText "name", VText name), (VText "operations", operations)])
  Store.bind (peerStore p) ("/" <> peerLocal p <> "/system/handler/" <> pattern) interfaceE
  (token, _) <- mintToken p (idIdentityHash (peerIdentity p)) Nothing []
  Store.bind (peerStore p) ("/" <> peerLocal p <> "/system/capability/grants/" <> pattern) token

-- | Build a peer from a 32-byte seed + seed policy. Materializes the §6.9 core
-- handlers, the §9.5 type floor (seam), and the §6.9a Peer Authority Bootstrap
-- (owner cap + default seed-policy entry). The @--validate@ opt-in additionally
-- bootstraps the §7a conformance handlers.
createPeer :: ByteString -> SeedPolicy -> Bool -> IO Peer
createPeer seed seedPolicy conformance = do
  identity <- either error pure (identityOfSeed seed)
  store <- Store.newStore
  let localPeer = idPeerId identity
      p = Peer identity store localPeer seedPolicy conformance
  -- local identity entity in the store (root-granter resolution)
  Store.putEntity store (idPeerEntity identity)
  -- §9.5 type floor (render-from-model seam; minimal seed at S3, A-HS-009)
  TypeDefs.publish store localPeer
  -- §6.9 core handlers
  mapM_ (installBootstrapHandler p) bootstrapHandlers
  -- §6.9a Peer Authority Bootstrap (L0 write-set): owner cap (detached-sig shape)
  -- + default seed-policy entry. Read back by authenticate (dual-form lookup).
  let policyBase = "/" <> localPeer <> "/system/capability/policy/"
  (ownerToken, ownerSig) <- mintToken p (idIdentityHash identity) Nothing (ownerGrants p)
  Store.bind store (policyBase <> hexOf (idIdentityHash identity)) ownerToken
  Store.bind store ("/" <> localPeer <> "/system/signature/" <> hexOf (entHash ownerToken)) ownerSig
  let defaultGrants = case seedPolicy of
        SeedPolicyDebugOpen -> openGrantsScope
        _ -> discoveryFloor
      defaultEntry =
        makeEntity
          "system/capability/policy-entry"
          (VMap [(VText "peer_pattern", VText "default"), (VText "grants", VArray defaultGrants)])
  Store.bind store (policyBase <> "default") defaultEntry
  -- §7a conformance handlers — only under --validate (off by default → 404).
  when conformance $
    mapM_
      (installBootstrapHandler p)
      [ ("system/validate/echo", "validate-echo", [("echo", (Nothing, Nothing))])
      , ("system/validate/dispatch-outbound", "validate-dispatch-outbound", [("dispatch", (Nothing, Nothing))])
      ]
  pure p
