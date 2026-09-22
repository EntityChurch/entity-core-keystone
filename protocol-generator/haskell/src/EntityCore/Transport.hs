{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Transport (L4) — TCP listener + per-connection serve loop via GHC green
-- threads ('forkIO') + STM (§1.6 framing, §4.8 inbound concurrency, §6.11
-- reentry).
--
-- == Concurrency model (A-HS-003 — the headline, a 3rd data-race-free shape)
--
-- One reader green thread per connection demuxes inbound frames (§6.11). An
-- EXECUTE_RESPONSE is routed to the awaiting outbound caller by @request_id@
-- through an STM-'TVar' pending map; an EXECUTE is dispatched on its OWN green
-- thread ('forkIO', §4.8) so a handler that originates an outbound EXECUTE
-- (§6.13b) and awaits its response does NOT block the reader. Writes (inbound
-- responses + outbound requests share the socket) are serialized by an 'MVar'
-- held only around the syscall.
--
-- The outbound await is the cleanest STM idiom in the codebase: the caller
-- 'retry's on an empty reply slot, and the reader 'writeTVar's the slot — no
-- condition variable, no manual signalling, no lost wakeup (STM blocks/wakes the
-- transaction automatically). Connection close fills every pending slot with
-- 'Nothing' so no waiter hangs.
--
-- == GHC RTS vs Swift's cooperative-pool trap (§7b)
--
-- Swift's structured-concurrency pool starved when blocking @read()@/@accept()@
-- ran on its bounded cooperative threads. GHC's @-threaded@ RTS sidesteps this:
-- the IO manager multiplexes blocking socket I/O over @epoll@, so a green thread
-- parked in 'recv' yields its capability to others — blocking reads do not starve
-- the scheduler. We additionally set @TCP_NODELAY@ (the Zig/Swift Nagle-churn
-- lesson) on every socket.
module EntityCore.Transport
  ( serveConnection
  , listenOn
  , acceptLoop
  , runWithConn
  , ConnIOHandle
  , sendOver
  ) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Exception (SomeException, try)
import Control.Monad (forever, void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.IORef (writeIORef)
import Data.Text (Text)
import Network.Socket
import Network.Socket.ByteString (recv, sendAll)
import System.Environment (lookupEnv)
import System.IO (hPutStrLn, stderr)
import System.IO.Unsafe (unsafePerformIO)

import EntityCore.Model (Entity (..), Envelope (..), textField)
import EntityCore.Peer (Conn (..), Peer, dispatch, internalErrorResponse, newConn)
import EntityCore.Wire (FramingRefusal (..), frameOfEnvelope, envelopeOfFrame, preAdmissionRefusal, salvageRequestId, makeResponse, errorResult, maxFrame, parseFrameLength)

-- | Per-connection IO state.
data ConnIO = ConnIO
  { ioSock :: Socket
  , ioWriteLock :: MVar ()
  , ioPending :: TVar (Map Text (TVar (Maybe (Maybe Envelope))))
  , ioClosed :: TVar Bool
  }

makeConnIO :: Socket -> IO ConnIO
makeConnIO sock = ConnIO sock <$> newMVar () <*> newTVarIO Map.empty <*> newTVarIO False

-- ── blocking framed read (the IO edge — exceptions live here, not in the codec) ──

-- | Read exactly @n@ bytes; 'Nothing' on EOF / closed socket.
recvExact :: Socket -> Int -> IO (Maybe ByteString)
recvExact sock n = go BS.empty
  where
    go acc
      | BS.length acc >= n = pure (Just acc)
      | otherwise = do
          chunk <- recv sock (n - BS.length acc)
          if BS.null chunk then pure Nothing else go (acc <> chunk)

-- | What one read of the socket produced (§1.6, §4.11).
--
-- THE THREE ARE NOT INTERCHANGEABLE AND THEY USED TO BE ONE 'Nothing'. An EOF is a
-- clean end of connection and is a refusal of nothing; an oversize prefix and a
-- truncated body are §4.11 PRE-ADMISSION REFUSALS, each owed a coded
-- EXECUTE_RESPONSE before the loop ends. Collapsing them meant this peer answered
-- an over-'maxFrame' envelope by returning straight out of the read loop with
-- nothing on the wire — §4.11's second named non-conformant behaviour, "closing
-- with no coded frame", which is indistinguishable from a network fault (§4.6) and
-- which on a multiplexed connection destroys unrelated ADMITTED requests.
data FrameRead
  = FrameOk ByteString
  | -- | Clean EOF / closed socket. Nothing to answer, nobody to answer to.
    FrameEof
  | -- | A §4.11 refusal: the coded frame goes out and THEN the loop ends.
    FrameRefused FramingRefusal

-- | Read one full frame (§1.6), keeping the three outcomes apart.
--
-- The oversize test is on the DECLARED length and runs BEFORE the body is read, as
-- §4.10(a) requires ("reject before fully buffering") — draining the declared body
-- to keep the stream framed IS the fully-buffering that section forbids, and a
-- sender declaring 4 GiB and sending 1 KiB would park the peer forever.
readFrame :: Socket -> IO FrameRead
readFrame sock = do
  mhdr <- recvExact sock 4
  case mhdr of
    Nothing -> pure FrameEof
    Just hdr ->
      let len = parseFrameLength hdr
       in if len < 0 || len > maxFrame
            then pure (FrameRefused FrameTooLarge)
            else do
              mbody <- recvExact sock len
              case mbody of
                -- A length prefix arrived and the body did not: the sender is gone
                -- mid-frame. §4.11's framing arm — a refusal, not an EOF.
                Nothing -> pure (FrameRefused FrameTruncated)
                Just body -> pure (FrameOk body)

-- | Serialized framed write (responses + outbound requests share the socket).
writeFramed :: ConnIO -> Envelope -> IO ()
writeFramed cio env =
  withMVar (ioWriteLock cio) $ \_ -> do
    r <- (try (sendAll (ioSock cio) (frameOfEnvelope env)) :: IO (Either SomeException ()))
    case r of
      Left e -> dbg ("writeFramed exc: " ++ show e)
      Right () -> pure ()

-- ── §6.11 demux ────────────────────────────────────────────────────────────────

-- | Route an inbound EXECUTE_RESPONSE to its awaiting outbound caller.
routeResponse :: ConnIO -> Envelope -> IO ()
routeResponse cio env = atomically $ do
  let requestId = fromMaybe "" (textField (envRoot env) "request_id")
  m <- readTVar (ioPending cio)
  case Map.lookup requestId m of
    Just slot -> writeTVar slot (Just (Just env))
    Nothing -> pure ()

-- | §6.13(b) outbound primitive: register a reply slot, send the request, then
-- 'retry' until the reader fills the slot (or the connection closes → 'Nothing').
-- The whole await is one composable STM transaction — no condition variable.
outbound :: ConnIO -> Envelope -> IO (Maybe Envelope)
outbound cio request = do
  let requestId = fromMaybe "" (textField (envRoot request) "request_id")
  slot <- newTVarIO Nothing
  atomically $ modifyTVar' (ioPending cio) (Map.insert requestId slot)
  writeFramed cio request
  result <- atomically $ do
    mres <- readTVar slot
    closed <- readTVar (ioClosed cio)
    case mres of
      Just v -> pure v
      Nothing -> if closed then pure Nothing else retry
  atomically $ modifyTVar' (ioPending cio) (Map.delete requestId)
  pure result

-- | Wake every pending outbound waiter on connection close.
closeConnIO :: ConnIO -> IO ()
closeConnIO cio = atomically $ do
  writeTVar (ioClosed cio) True
  m <- readTVar (ioPending cio)
  mapM_ (\slot -> writeTVar slot (Just Nothing)) (Map.elems m)

{-# NOINLINE dbgEnabled #-}
dbgEnabled :: Bool
dbgEnabled = unsafePerformIO (maybe False (const True) <$> lookupEnv "EC_DEBUG")

dbg :: String -> IO ()
dbg s = if dbgEnabled then hPutStrLn stderr ("[transport] " ++ s) else pure ()

-- ── reader loop (§6.11 demux + §4.8 concurrent dispatch) ──────────────────────

-- | Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a
-- frame refused BEFORE it became an admitted request.
--
-- An EMPTY @request_id@ IS the best-effort form, not a bug: §4.11 prescribes
-- exactly that where no id can be recovered ("otherwise a best-effort coded frame
-- carrying no correlation"). The alternative this replaced was silence — §4.11's
-- other named non-conformant behaviour, "the weaker of the two precisely because
-- nothing surfaces it".
refusePreAdmission :: ConnIO -> Text -> Int -> Text -> IO ()
refusePreAdmission cio requestId status code =
  writeFramed cio (Envelope (makeResponse requestId status (errorResult Nothing code)) [])

readLoop :: ConnIO -> (Envelope -> IO ()) -> IO ()
readLoop cio onExecute = loop
  where
    loop = do
      mpayload <- (try (readFrame (ioSock cio)) :: IO (Either SomeException FrameRead))
      case mpayload of
        Left e -> dbg ("readFrame exc: " ++ show e)
        Right FrameEof -> dbg "readFrame EOF"
        Right (FrameRefused fr) -> do
          -- §4.11: the coded frame goes out and THEN the loop ends. The stream is
          -- desynchronized on both arms — an oversize body was never drained, a
          -- truncated one never arrived — so closing is the only sound choice once
          -- the framing is lost, and §4.11 leaves that close to us. It is a choice
          -- made AFTER answering, never an alternative to answering. No id is
          -- recoverable here (the body was never read), so this is the best-effort
          -- uncorrelated form.
          let (status, code) = preAdmissionRefusal (Left fr)
          dbg ("framing refusal: " ++ show fr)
          refusePreAdmission cio "" status code
        Right (FrameOk payload) -> do
          case envelopeOfFrame payload of
            -- A COMPLETE frame the decoder refused. The framing is intact, so we
            -- answer and keep serving — this used to drop the frame, which rejected
            -- it (correct) and then said nothing (wrong): the sender blocked until
            -- its own §6.11(c) deadline and a refusal was indistinguishable from a
            -- dead peer.
            --
            -- THE CODE IS THE CAUSE'S (§4.11, §5.2a). Every cause answered
            -- @non_canonical_ecf@ until 0.8.2.24/.25 pinned them apart: a mis-keyed
            -- @included@ entry is @400 hash_mismatch@ (its encoding is canonical —
            -- what is false is the claim the key makes), a tag-policy violation
            -- keeps @non_canonical_ecf@, and everything else that never becomes an
            -- Envelope is @400 invalid_request@.
            --
            -- The frame is still REJECTED; only the request_id is salvaged, to
            -- correlate the response, and an unrecoverable id yields the
            -- uncorrelated best-effort frame rather than silence.
            Left e -> do
              dbg ("envelopeOfFrame FAIL: " ++ show e)
              let (status, code) = preAdmissionRefusal (Right e)
              refusePreAdmission cio (fromMaybe "" (salvageRequestId payload)) status code
              loop
            Right env -> do
              if entType (envRoot env) == "system/protocol/execute/response"
                then dbg ("recv RESPONSE rid=" ++ show (textField (envRoot env) "request_id")) >> routeResponse cio env
                else dbg ("recv EXECUTE rid=" ++ show (textField (envRoot env) "request_id")) >> void (forkIO (onExecute env))
              loop

-- | Serve one accepted connection. A fresh per-connection 'Conn' holds the
-- handshake state + the §6.13(b) outbound seam wired to this connection's IO.
serveConnection :: Peer -> Socket -> IO ()
serveConnection peer sock = do
  setSocketOption sock NoDelay 1
  cio <- makeConnIO sock
  conn <- newConn
  writeIORef (connOutbound conn) (Just (outbound cio))
  let onExecute env = do
        -- Per-request isolation: an exception on one adversarial request must NOT
        -- tear down the connection (§3.3 every EXECUTE receives a response).
        resp <- (try (dispatch peer conn env) :: IO (Either SomeException (Maybe Envelope)))
        let out = case resp of
              Right r -> r
              Left _ -> internalErrorResponse env
        case out of
          Just r -> writeFramed cio r
          Nothing -> pure ()
  readLoop cio onExecute
  closeConnIO cio
  void (try (close sock) :: IO (Either SomeException ()))

-- | Listen on 127.0.0.1:port (0 = auto). Returns the socket + the bound port.
listenOn :: Int -> IO (Socket, Int)
listenOn port = do
  addr : _ <- getAddrInfo (Just defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Stream}) (Just "127.0.0.1") (Just (show port))
  sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
  setSocketOption sock ReuseAddr 1
  bind sock (addrAddress addr)
  listen sock 64
  bound <- socketPort sock
  pure (sock, fromIntegral bound)

acceptLoop :: Peer -> Socket -> IO ()
acceptLoop peer sock = forever $ do
  (conn, _) <- accept sock
  void (forkIO (serveConnection peer conn))

-- | Run a single bidirectional connection's serve + dispatcher (used by the smoke
-- runner's client side: the dialing peer also serves reentrant EXECUTEs so the
-- §6.11 reentry surface works both directions). Returns the 'ConnIO' outbound
-- primitive so the caller can originate requests over the same connection.
runWithConn :: Peer -> Socket -> IO (Conn, ConnIOHandle)
runWithConn peer sock = do
  setSocketOption sock NoDelay 1
  cio <- makeConnIO sock
  conn <- newConn
  writeIORef (connOutbound conn) (Just (outbound cio))
  let onExecute env = do
        resp <- (try (dispatch peer conn env) :: IO (Either SomeException (Maybe Envelope)))
        let out = case resp of Right r -> r; Left _ -> internalErrorResponse env
        case out of Just r -> writeFramed cio r; Nothing -> pure ()
  _ <- forkIO $ do
    readLoop cio onExecute
    closeConnIO cio
  pure (conn, ConnIOHandle cio)

-- | Opaque handle exposing the outbound send over a 'runWithConn' connection.
newtype ConnIOHandle = ConnIOHandle ConnIO

-- | Send an EXECUTE envelope over a 'runWithConn' connection, awaiting the
-- correlated EXECUTE_RESPONSE by @request_id@ (§6.11 demux). Used by the smoke
-- client to originate requests on the same bidirectional connection.
sendOver :: ConnIOHandle -> Envelope -> IO (Maybe Envelope)
sendOver (ConnIOHandle cio) = outbound cio
