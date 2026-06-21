{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Storage — the two layers of §1.7, plus the §6.10 emit pathway.
--
-- @
--   Content Store: hash → entity   (immutable, content-addressed, dedup)
--   Entity Tree:   path → hash      (mutable location index)
-- @
--
-- == Concurrency model (A-HS-003, the §7b headline)
--
-- The store is a small set of 'TVar's mutated inside 'atomically'. STM
-- transactions are atomic + composable + lock-free, so the per-request
-- dispatch-thread store race that crashed the Zig peer (HashMap double-free) and
-- the Common Lisp peer (raced @gethash@ → 500s) is **structurally impossible**
-- here: two concurrent 'bind's serialize at the STM commit point with no manual
-- locking and no lost update. This is a /third/ data-race-free store shape after
-- the Elixir/Swift actor (message/await-serialized) — here /transactional/.
--
-- Emit-consumer effects ('IO' callbacks) MUST run /outside/ the transaction (STM
-- is pure): each mutator commits the state change in 'atomically', then runs the
-- consumer callbacks in 'IO'. The event payload is captured atomically so the
-- effect sees a consistent snapshot. Field names are the §6.10 normative
-- inventory; @event_type@ derives from the null-@new_hash@ rule only.
module EntityCore.Store
  ( Store
  , ContentStoreEvent (..)
  , TreeChangeEvent (..)
  , newStore
  , registerContentConsumer
  , registerTreeConsumer
  , putEntity
  , getByHash
  , bind
  , unbind
  , hashAt
  , getAt
  , listing
  , snapshotContentFn
  , snapshotTreeMember
  ) where

import Control.Concurrent.STM
import Control.Monad (forM_, when)
import Data.ByteString (ByteString)
import Data.List (sortOn)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T

import EntityCore.Model (Entity (..))

-- | Content-store event (§6.10 Store step): carries @(hash, entity)@ only — no
-- context.
data ContentStoreEvent = ContentStoreEvent
  { cseHash :: ByteString
  , cseEntity :: Entity
  }

-- | Tree-change event (§6.10 Bind step). @context@ is impl-defined (§6.8a); inert
-- in core, so not carried.
data TreeChangeEvent = TreeChangeEvent
  { tceEventType :: Text -- ^ "created" | "modified" | "deleted"
  , tcePath :: Text
  , tceNewHash :: Maybe ByteString
  , tcePreviousHash :: Maybe ByteString
  }

-- | The store. All four maps/lists live behind 'TVar's; mutators compose the
-- content-put and the tree-bind in a single transaction.
data Store = Store
  { stContent :: TVar (Map ByteString Entity) -- ^ content_hash → entity
  , stTree :: TVar (Map Text ByteString) -- ^ path → content_hash
  , stContentConsumers :: TVar [ContentStoreEvent -> IO ()]
  , stTreeConsumers :: TVar [TreeChangeEvent -> IO ()]
  }

newStore :: IO Store
newStore =
  Store <$> newTVarIO Map.empty <*> newTVarIO Map.empty <*> newTVarIO [] <*> newTVarIO []

-- | Register an emit consumer (§6.10 consumer-registration primitive). Reachable
-- any time, incl. post-bootstrap. Delivery is sync-inline (impl-defined §9.4).
registerContentConsumer :: Store -> (ContentStoreEvent -> IO ()) -> IO ()
registerContentConsumer st f = atomically (modifyTVar' (stContentConsumers st) (f :))

registerTreeConsumer :: Store -> (TreeChangeEvent -> IO ()) -> IO ()
registerTreeConsumer st f = atomically (modifyTVar' (stTreeConsumers st) (f :))

deriveEventType :: Maybe ByteString -> Maybe ByteString -> Text
deriveEventType previous newH = case (previous, newH) of
  (Nothing, _) -> "created"
  (_, Nothing) -> "deleted"
  _ -> "modified"

-- ── content store ────────────────────────────────────────────────────────────

-- | §6.10 Store step: fires a content-store event only when the entity is new to
-- the store (a re-put of an existing hash fires nothing). Atomic state change,
-- then effects in IO.
putEntity :: Store -> Entity -> IO ()
putEntity st e = do
  isNew <- atomically $ do
    m <- readTVar (stContent st)
    if Map.member (entHash e) m
      then pure False
      else do writeTVar (stContent st) (Map.insert (entHash e) e m); pure True
  when isNew $ do
    consumers <- readTVarIO (stContentConsumers st)
    forM_ consumers $ \f -> f (ContentStoreEvent (entHash e) e)

getByHash :: Store -> ByteString -> IO (Maybe Entity)
getByHash st h = Map.lookup h <$> readTVarIO (stContent st)

-- ── entity tree (location index) ─────────────────────────────────────────────

-- | §6.10 Bind step: runs Store then Bind in one transaction. A tree-change event
-- fires when the binding at the path changes (no event on a re-bind to the same
-- hash). A bind to a @system/deletion-marker@ fires "modified", NOT "deleted" —
-- classification keys on a null @new_hash@ only, never on entity type.
bind :: Store -> Text -> Entity -> IO ()
bind st path e = do
  (contentNew, previous, changed) <- atomically $ do
    cm <- readTVar (stContent st)
    let !cNew = not (Map.member (entHash e) cm)
    when cNew $ writeTVar (stContent st) (Map.insert (entHash e) e cm)
    tm <- readTVar (stTree st)
    let !prev = Map.lookup path tm
        !chg = prev /= Just (entHash e)
    writeTVar (stTree st) (Map.insert path (entHash e) tm)
    pure (cNew, prev, chg)
  when contentNew $ do
    cs <- readTVarIO (stContentConsumers st)
    forM_ cs $ \f -> f (ContentStoreEvent (entHash e) e)
  when changed $ do
    ts <- readTVarIO (stTreeConsumers st)
    forM_ ts $ \f ->
      f (TreeChangeEvent (deriveEventType previous (Just (entHash e))) path (Just (entHash e)) previous)

unbind :: Store -> Text -> IO ()
unbind st path = do
  previous <- atomically $ do
    tm <- readTVar (stTree st)
    let !prev = Map.lookup path tm
    writeTVar (stTree st) (Map.delete path tm)
    pure prev
  case previous of
    Nothing -> pure ()
    Just _ -> do
      ts <- readTVarIO (stTreeConsumers st)
      forM_ ts $ \f -> f (TreeChangeEvent "deleted" path Nothing previous)

hashAt :: Store -> Text -> IO (Maybe ByteString)
hashAt st path = Map.lookup path <$> readTVarIO (stTree st)

getAt :: Store -> Text -> IO (Maybe Entity)
getAt st path = do
  mh <- hashAt st path
  case mh of
    Just h -> getByHash st h
    Nothing -> pure Nothing

-- | A pure content resolver over a one-time atomic snapshot of the content store
-- (N8: the capability verdict is a pure function of a fixed chain state — captured
-- once per dispatch so timing cannot perturb the verdict).
snapshotContentFn :: Store -> IO (ByteString -> Maybe Entity)
snapshotContentFn st = do
  m <- readTVarIO (stContent st)
  pure (`Map.lookup` m)

-- | A pure path-membership predicate over a snapshot of the tree (the revocation
-- check: is @path@ bound?).
snapshotTreeMember :: Store -> IO (Text -> Bool)
snapshotTreeMember st = do
  m <- readTVarIO (stTree st)
  pure (`Map.member` m)

-- | One-level listing under @prefix@ (a path ending in "/"). Returns
-- @(segment, hash?, has_children)@ per @system/tree/listing-entry@ (§3.9). A
-- bound path contributes a hash; a path that is also a prefix of deeper paths
-- contributes @has_children@.
listing :: Store -> Text -> IO [(Text, Maybe ByteString, Bool)]
listing st prefix0 = do
  tm <- readTVarIO (stTree st)
  let prefix = if not (T.null prefix0) && T.last prefix0 == '/' then prefix0 else prefix0 <> "/"
      plen = T.length prefix
      step m path h
        | T.length path > plen && T.take plen path == prefix =
            let rest = T.drop plen path
             in case T.findIndex (== '/') rest of
                  Nothing -> note m rest (Just h) False -- direct child, bound
                  Just i -> note m (T.take i rest) Nothing True -- deeper child path
        | otherwise = m
      note m seg hOpt deeper =
        Map.insertWith mergeEntry seg (hOpt, deeper) m
      mergeEntry (hNew, dNew) (hOld, dOld) =
        (maybe hOld Just hNew, dOld || dNew)
      acc = Map.foldlWithKey' step Map.empty tm
  pure $ sortOn (\(s, _, _) -> s) [(seg, h, d) | (seg, (h, d)) <- Map.toList acc]
