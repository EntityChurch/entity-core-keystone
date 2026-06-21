{-# LANGUAGE OverloadedStrings #-}

-- | S3 smoke runner — boots TWO Haskell peers over real loopback TCP and drives
-- the lifecycle scenario, all green:
--
--   1. §4.1 handshake (hello → authenticate; session + §4.4/§6.9a initial cap).
--   2. EXECUTE on an unregistered path → 404.
--   3. Authority-gated tree get → 200 (discovery-floor grant admits system/type/*).
--   4. capability request → 200 (mints a bounded child cap).
--   5. request_id demux (N7): N concurrent EXECUTEs each correlate to their reply.
--   6. Clean teardown (no hangs; STM/green-thread cleanup).
--   7. (--validate surface) register → dispatch round-trip + dispatch-outbound
--      reentry self-check (the §7a handlers, B-role on the same connection).
--
-- Green = the peer talks the wire correctly. The client side is built from the
-- library's own builders + codec (no fakes): it dials, runs its own dispatcher on
-- the bidirectional connection (so the §6.11 reentry leg works), signs as a real
-- second identity, and asserts statuses by request_id correlation.
module Main (main) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar
import Control.Monad (forM, forM_, unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.IORef
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.POSIX (getPOSIXTime)
import qualified Data.Word as Word
import Network.Socket
import System.Exit (exitFailure)
import System.IO (BufferMode (LineBuffering), hFlush, hSetBuffering, stdout)

import EntityCore.Codec.Value (Value (..))
import EntityCore.Identity (Identity (..), identityOfSeed, signEntity)
import EntityCore.Model
import EntityCore.Peer (createPeer)
import EntityCore.SeedPolicy (SeedPolicy (..))
import EntityCore.Transport (ConnIOHandle, acceptLoop, listenOn, runWithConn, sendOver)
import EntityCore.Wire (makeExecute)

-- ── test harness ──────────────────────────────────────────────────────────────

assertEq :: (Eq a, Show a) => Text -> a -> a -> IO Bool
assertEq label expected got
  | expected == got = do BC.putStrLn (BC.pack ("  ok   " ++ T.unpack label)); pure True
  | otherwise = do
      BC.putStrLn (BC.pack ("  FAIL " ++ T.unpack label ++ " — expected " ++ show expected ++ ", got " ++ show got))
      pure False

statusOf :: Maybe Envelope -> Int
statusOf Nothing = -1
statusOf (Just env) = maybe (-1) fromIntegral (uintField (envRoot env) "status")

-- ── client identity + envelope construction ──────────────────────────────────

data Client = Client
  { clIdent :: Identity
  , clHandle :: ConnIOHandle
  , clReqCtr :: IORef Int
  , clCap :: IORef (Maybe Entity) -- the §4.4 initial cap (the granted token)
  , clCapSig :: IORef (Maybe Entity) -- its signature
  , clGranter :: IORef (Maybe Entity) -- the server peer entity (granter)
  }

-- | Atomic request-id allocation: 'atomicModifyIORef'' so 16 concurrent senders
-- never collide on a request_id (a duplicate id would cross-wire the §6.11 demux
-- and hang a 'takeMVar' — the N7 trap, in the client this time).
nextReqId :: Client -> IO Text
nextReqId cl = do
  n <- atomicModifyIORef' (clReqCtr cl) (\x -> (x + 1, x + 1))
  pure ("req-" <> T.pack (show n))

-- | Send a self-authored EXECUTE (author + capability + signatures in included),
-- await its EXECUTE_RESPONSE by request_id.
sendAuthed :: Client -> Text -> Text -> Entity -> Maybe Value -> IO (Maybe Envelope)
sendAuthed cl uri operation params resource = do
  rid <- nextReqId cl
  mcap <- readIORef (clCap cl)
  mcapSig <- readIORef (clCapSig cl)
  mgranter <- readIORef (clGranter cl)
  let ident = clIdent cl
      capHash = maybe BS.empty entHash mcap
      exec = makeExecute rid uri operation params resource (idIdentityHash ident) capHash
      execSig = signEntity ident exec
      included =
        [ (idIdentityHash ident, idPeerEntity ident)
        , (entHash execSig, execSig)
        ]
          ++ maybe [] (\cap -> [(entHash cap, cap)]) mcap
          ++ maybe [] (\s -> [(entHash s, s)]) mcapSig
          ++ maybe [] (\g -> [(entHash g, g)]) mgranter
  sendOver (clHandle cl) (Envelope exec included)

-- ── handshake (§4.1 / §4.6) ───────────────────────────────────────────────────

handshake :: Client -> IO Bool
handshake cl = do
  let ident = clIdent cl
  -- hello (unauthenticated EXECUTE on system/protocol/connect)
  ridH <- nextReqId cl
  let helloParams = makeEntity "primitive/any" (VMap [(VText "peer_id", VText (idPeerId ident))])
      helloExec = makeExecute ridH "system/protocol/connect" "hello" helloParams Nothing (idIdentityHash ident) BS.empty
  helloResp <- sendOver (clHandle cl) (Envelope helloExec [(idIdentityHash ident, idPeerEntity ident)])
  okHello <- assertEq "handshake: hello → 200" 200 (statusOf helloResp)
  let nonce = case helloResp >>= resultEntityOf >>= (`bytesField` "nonce") of
        Just nn -> nn
        Nothing -> BS.empty
      serverPeerId = fromMaybe "" (helloResp >>= resultEntityOf >>= (`textField` "peer_id"))
  okPid <- assertEq "handshake: remote peer_id present" True (not (T.null serverPeerId))
  -- authenticate: params carry public_key + echoed nonce + claimed peer_id; the
  -- auth entity is signed (the §4.6 proof-of-possession).
  ridA <- nextReqId cl
  let authEntity =
        makeEntity
          "primitive/any"
          ( VMap
              [ (VText "public_key", VBytes (idPublicKey ident))
              , (VText "nonce", VBytes nonce)
              , (VText "peer_id", VText (idPeerId ident))
              ]
          )
      authSig = signEntity ident authEntity
      authExec = makeExecute ridA "system/protocol/connect" "authenticate" authEntity Nothing (idIdentityHash ident) BS.empty
      authIncluded =
        [ (idIdentityHash ident, idPeerEntity ident)
        , (entHash authSig, authSig)
        ]
  authResp <- sendOver (clHandle cl) (Envelope authExec authIncluded)
  okAuth <- assertEq "handshake: authenticate → 200" 200 (statusOf authResp)
  -- capture the granted cap + its signature + the granter (server) peer from the
  -- authenticate response's included set, for subsequent authed EXECUTEs.
  case authResp of
    Just env -> do
      let inc = envIncluded env
          tokenHash = resultEntityOf env >>= (`bytesField` "token")
          token = tokenHash >>= (`lookup` inc)
          tokSig = token >>= \t -> findSigFor (entHash t) inc
          granter = case [e | (_, e) <- inc, entType e == "system/peer"] of (e : _) -> Just e; _ -> Nothing
      writeIORef (clCap cl) token
      writeIORef (clCapSig cl) tokSig
      writeIORef (clGranter cl) granter
    Nothing -> pure ()
  pure (okHello && okPid && okAuth)
  where
    findSigFor h inc = case [e | (_, e) <- inc, entType e == "system/signature", bytesField e "target" == Just h] of
      (e : _) -> Just e
      _ -> Nothing

resultEntityOf :: Envelope -> Maybe Entity
resultEntityOf env = case field (envRoot env) "result" of
  Just v -> either (const Nothing) Just (entityOfCbor v)
  Nothing -> Nothing

-- ── the scenario ──────────────────────────────────────────────────────────────

main :: IO ()
main = withSocketsDo $ do
  hSetBuffering stdout LineBuffering
  BC.putStrLn "== entity-core-protocol-haskell S3 smoke =="
  -- Server peer (validate on, so the §7a surface is reachable).
  serverIdent <- either error pure (identityOfSeed (BC.replicate 32 '\x11'))
  -- Boot with the degenerate open seed policy (= --debug-open-grants) so an
  -- authenticated peer receives a wide cap — the smoke runner drives the
  -- grant-gated register + §7a dispatch-outbound surface end-to-end (exactly what
  -- the validate-peer harness does). The restricted §4.4 floor is exercised by
  -- the get/request steps above with the default policy in the dedicated tests.
  server <- createPeer (idSeed serverIdent) SeedPolicyDebugOpen True
  (lsock, port) <- listenOn 0
  _ <- forkIO (acceptLoop server lsock)
  threadDelay 100000

  -- Client peer identity (a distinct second peer).
  clientIdent <- either error pure (identityOfSeed (BC.replicate 32 '\x22'))
  -- The client also runs a Peer so its dispatcher can answer the reentrant
  -- dispatch-outbound leg (B-role on the same connection, §7a.2a). --validate so
  -- the client's own system/validate/echo is reachable for the reentry target.
  clientPeer <- createPeer (idSeed clientIdent) SeedPolicyStandard True

  -- Dial the server; get a bidirectional connection (the client's Peer serves
  -- reentrant EXECUTEs on it).
  addr : _ <- getAddrInfo (Just defaultHints {addrSocketType = Stream}) (Just "127.0.0.1") (Just (show port))
  csock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  connect csock (addrAddress addr)
  (_clientConn, handle) <- runWithConn clientPeer csock

  ctr <- newIORef 0
  capRef <- newIORef Nothing
  capSigRef <- newIORef Nothing
  granterRef <- newIORef Nothing
  let cl = Client clientIdent handle ctr capRef capSigRef granterRef

  results <- newIORef []
  let record b = modifyIORef' results (b :)

  -- 1. handshake
  handshake cl >>= record

  -- 2. EXECUTE on an unregistered path → 404
  let bogusParams = makeEntity "primitive/any" (VMap [])
      bogusRes = VMap [(VText "targets", VArray [VText "system/nonexistent/thing"])]
  r404 <- sendAuthed cl "system/nonexistent/thing" "get" bogusParams (Just bogusRes)
  assertEq "unregistered path → 404" 404 (statusOf r404) >>= record

  -- 3. authority-gated tree get → 200 (discovery floor admits system/type/*)
  let getParams = makeEntity "primitive/any" (VMap [])
      typeRes = VMap [(VText "targets", VArray [VText "system/type/primitive/any"])]
  rGet <- sendAuthed cl "system/tree" "get" getParams (Just typeRes)
  assertEq "authority-gated tree get → 200" 200 (statusOf rGet) >>= record

  -- 4. capability request → 200 (mints a bounded child cap, subset of ours)
  let reqGrants =
        VArray
          [ VMap
              [ (VText "handlers", VMap [(VText "include", VArray [VText "system/tree"])])
              , (VText "resources", VMap [(VText "include", VArray [VText "system/type/*"])])
              , (VText "operations", VMap [(VText "include", VArray [VText "get"])])
              ]
          ]
      capParams = makeEntity "primitive/any" (VMap [(VText "grants", reqGrants)])
  -- No resource target: capability:request is addressed by handler+operation, and
  -- the §4.4 floor grant for system/capability carries no resource scope, so a
  -- resource target would fail the §5.4 resource check (the floor admits the op,
  -- not a resource).
  rCap <- sendAuthed cl "system/capability" "request" capParams Nothing
  assertEq "capability request → 200" 200 (statusOf rCap) >>= record

  -- 5. request_id demux (N7): N concurrent EXECUTEs, each correlates to its reply
  let n = 16
  done <- newEmptyMVar
  forM_ [1 .. n] $ \_ -> forkIO $ do
    rr <- sendAuthed cl "system/tree" "get" getParams (Just typeRes)
    putMVar done (statusOf rr)
  statuses <- forM [1 .. n] $ \_ -> takeMVar done
  assertEq "request_id demux: N concurrent EXECUTEs all 200" (replicate n 200) statuses >>= record

  -- 7. §7a register → dispatch round-trip (the register *contract*: five writes)
  let regManifest = VMap [(VText "name", VText "smoke-handler"), (VText "operations", VMap [(VText "ping", VMap [])])]
      regReq = makeEntity "system/handler/register-request" (VMap [(VText "manifest", regManifest)])
      regRes = VMap [(VText "targets", VArray [VText "system/handler/smoke/test"])]
  rReg <- sendAuthed cl "system/handler" "register" regReq (Just regRes)
  assertEq "register → 200 (five writes)" 200 (statusOf rReg) >>= record

  -- 7b. dispatch-outbound reentry self-check (§7a.2a): the server originates an
  -- echo back to us (B-role) over the same connection. We pass our own cap as the
  -- reentry authority (the cap valid at the caller = us).
  mcap <- readIORef capRef
  mcapSig <- readIORef capSigRef
  case (mcap, mcapSig) of
    (Just _cap, Just _capSig) -> do
      -- Mint the REENTRY capability: granted by the CLIENT (us) to the SERVER, so
      -- the server is authorized to originate back to us over the connection
      -- (§7a.2a — the reentry direction can only be authorized by the caller). A
      -- wide-open grant over our namespace; signed by the client identity. This is
      -- the cap valid AT THE CALLER (us) — distinct from the server-granted cap we
      -- use for our own outbound EXECUTEs.
      now <- fmap (round . (* 1000)) getPOSIXTime
      let openGrant =
            VMap
              [ (VText "handlers", VMap [(VText "include", VArray [VText "*"])])
              , (VText "resources", VMap [(VText "include", VArray [VText "*", VText "/*/*"])])
              , (VText "operations", VMap [(VText "include", VArray [VText "*"])])
              , (VText "peers", VMap [(VText "include", VArray [VText "*"])])
              ]
          reentryCap =
            makeEntity
              "system/capability/token"
              ( VMap
                  [ (VText "granter", VBytes (idIdentityHash clientIdent))
                  , (VText "grantee", VBytes (idIdentityHash serverIdent))
                  , (VText "grants", VArray [openGrant])
                  , (VText "created_at", VUInt (now :: Word.Word64))
                  ]
              )
          reentryCapSig = signEntity clientIdent reentryCap
          echoInner = VText "reentry-ping"
          echoVal = VMap [(VText "value", echoInner)]
          dispParams =
            makeEntity
              "primitive/any"
              ( VMap
                  [ (VText "target", VText "system/validate/echo")
                  , (VText "operation", VText "echo")
                  , (VText "value", echoVal)
                  , (VText "reentry_capability", entityToCbor reentryCap)
                  , (VText "reentry_granter", entityToCbor (idPeerEntity clientIdent))
                  , (VText "reentry_cap_signature", entityToCbor reentryCapSig)
                  ]
              )
          dispRes = VMap [(VText "targets", VArray [VText "system/validate/dispatch-outbound"])]
      rDisp <- sendAuthed cl "system/validate/dispatch-outbound" "dispatch" dispParams (Just dispRes)
      okDispStatus <- assertEq "dispatch-outbound reentry → 200" 200 (statusOf rDisp)
      -- the relayed echo result.value must equal what we sent (value pass-through)
      let echoedBack = do
            env <- rDisp
            res <- resultEntityOf env
            innerResultV <- field res "result"
            inner <- either (const Nothing) Just (entityOfCbor innerResultV)
            field inner "value"
      okDispVal <- assertEq "dispatch-outbound reentry: echo value passthrough" (Just echoInner) echoedBack
      record (okDispStatus && okDispVal)
    _ -> do
      BC.putStrLn "  FAIL dispatch-outbound: no cap captured from authenticate"
      record False

  -- 6. teardown — close the client connection; the listener + green threads are
  -- reaped on process exit (closing lsock under a blocked accept races a
  -- threadWait, so we leave it to RTS shutdown).
  close csock
  threadDelay 50000

  rs <- readIORef results
  let passed = length (filter id rs)
      total = length rs
  BC.putStrLn (BC.pack ("== smoke: " ++ show passed ++ "/" ++ show total ++ " green =="))
  hFlush stdout
  unless (and rs) exitFailure
