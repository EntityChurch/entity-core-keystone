/-
  Storage — the two layers of §1.7 (Content Store: hash→entity, immutable;
  Entity Tree: path→hash, mutable), plus the §6.10 emit hooks.

  Concurrency (§7b): Lean's `IO.asTask .dedicated` gives TRUE OS-thread
  parallelism (no GIL), so the shared store MUST be guarded — `Std.Mutex` is the
  store-safety primitive (the OCaml-threads posture, 1a finding #3; actor/STM
  alternatives don't exist in Lean). Every op runs under the mutex. Emit
  consumers are snapshotted under the lock and fired AFTER unlock so a consumer
  that touches the store can't deadlock (core registers zero consumers, but the
  §6.10 hook is LIVE — reachable post-bootstrap, the §6.13(c) MUST).

  In-memory assoc-list impl (zero deps; conformance-scale ~100 entries). Paths
  are canonical absolute "/{peer_id}/rest" (§1.4); the peer canonicalizes first.
-/
import EntityCore.Model
import Std.Sync.Mutex
import Std.Data.HashMap

namespace EntityCore.Store

open EntityCore.Model

/-- Content-store event (§6.10 Store step): (hash, entity) only — no context. -/
structure ContentStoreEvent where
  hash : ByteArray
  entity : Entity

/-- Tree-change event (§6.10 Bind step). `eventType` ∈ {created,modified,deleted}
keys on a null `newHash` only (a bind to a deletion-marker is "modified"). -/
structure TreeChangeEvent where
  eventType : String
  path : String
  newHash : Option ByteArray
  previousHash : Option ByteArray

structure Data where
  content : Std.HashMap String Entity   -- hex(hash) → entity
  tree : Std.HashMap String ByteArray   -- path → bound hash bytes
  contentConsumers : List (ContentStoreEvent → IO Unit)
  treeConsumers : List (TreeChangeEvent → IO Unit)

structure Store where
  mutex : Std.Mutex Data

def create : IO Store := do
  let m ← Std.Mutex.new
    { content := (∅ : Std.HashMap String Entity), tree := (∅ : Std.HashMap String ByteArray),
      contentConsumers := [], treeConsumers := [] }
  pure { mutex := m }

-- ── emit consumer registration (§6.10) — reachable any time, incl. post-bootstrap ──
def registerContentConsumer (s : Store) (f : ContentStoreEvent → IO Unit) : IO Unit :=
  s.mutex.atomically (modify fun d => { d with contentConsumers := f :: d.contentConsumers })
def registerTreeConsumer (s : Store) (f : TreeChangeEvent → IO Unit) : IO Unit :=
  s.mutex.atomically (modify fun d => { d with treeConsumers := f :: d.treeConsumers })

def deriveEventType (previous new : Option ByteArray) : String :=
  match previous, new with
  | none, _ => "created"
  | _, none => "deleted"
  | _, _ => "modified"

-- ── content store ────────────────────────────────────────────────────────────

/-- §6.10 Store step: fires a content event only when the entity is new.
Uses `modifyGet` (not get-then-set) so the `HashMap` is uniquely referenced and
the insert is in-place O(1) — get-then-set keeps the old map shared, forcing an
O(n) copy per insert and an O(n²) sustained-load latency runaway (§6.11). -/
def putEntity (s : Store) (e : Entity) : IO Unit := do
  let toFire ← s.mutex.atomically (modifyGet fun d =>
    let key := hex e.hash
    if d.content.contains key then ([], d)
    else (d.contentConsumers.map (fun f => f { hash := e.hash, entity := e }),
          { d with content := d.content.insert key e }))
  for act in toFire do act

def getByHash (s : Store) (h : ByteArray) : IO (Option Entity) :=
  s.mutex.atomically do pure ((← get).content.get? (hex h))

-- ── entity tree (location index) ─────────────────────────────────────────────

/-- §6.10 Bind step: Store then Bind; fires a tree event when the binding changes. -/
def bind (s : Store) (path : String) (e : Entity) : IO Unit := do
  putEntity s e
  let toFire ← s.mutex.atomically (modifyGet fun d =>
    let previous := d.tree.get? path
    let changed := match previous with | none => true | some h => !(baEq h e.hash)
    let d' := { d with tree := d.tree.insert path e.hash }
    if changed then
      let ev : TreeChangeEvent :=
        { eventType := deriveEventType previous (some e.hash), path,
          newHash := some e.hash, previousHash := previous }
      (d.treeConsumers.map (fun f => f ev), d')
    else ([], d'))
  for act in toFire do act

def unbind (s : Store) (path : String) : IO Unit := do
  let toFire ← s.mutex.atomically (modifyGet fun d =>
    let previous := d.tree.get? path
    let d' := { d with tree := d.tree.erase path }
    match previous with
    | none => ([], d')
    | some _ =>
        let ev : TreeChangeEvent := { eventType := "deleted", path, newHash := none, previousHash := previous }
        (d.treeConsumers.map (fun f => f ev), d'))
  for act in toFire do act

def hashAt (s : Store) (path : String) : IO (Option ByteArray) :=
  s.mutex.atomically do pure ((← get).tree.get? path)

def getAt (s : Store) (path : String) : IO (Option Entity) := do
  match ← hashAt s path with
  | some h => getByHash s h
  | none => pure none

/-- Snapshot of the full tree (path × hash) for one-level listing (§3.9). -/
def treeSnapshot (s : Store) : IO (List (String × ByteArray)) :=
  s.mutex.atomically do pure (← get).tree.toList

end EntityCore.Store
