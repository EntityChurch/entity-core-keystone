/-
  Transport (L4) — TCP listener + per-connection serve loop over the FFI socket
  shim (§1.6 framing, §4.8 inbound concurrency, §6.11 reentry).

  Concurrency model (the §7b OS-thread posture): one reader runs per connection on
  a `.dedicated` thread (blocking recv never starves the compute pool). The reader
  demuxes inbound frames — an EXECUTE_RESPONSE is routed to its awaiting outbound
  caller by `request_id` (via an `IO.Promise`, the clean Lean alternative to the
  cohort's condition variables); an EXECUTE is dispatched on its OWN dedicated
  thread so a handler that originates an outbound EXECUTE (§6.13(b)) and awaits its
  response does NOT block the reader. Writes (responses + outbound requests share
  the fd) are serialized by a `Std.Mutex`. Shared store safety is the store's own
  mutex. The §6.13(b) handler-facing outbound seam is `outbound` below, wired to
  `conn.outbound` so a runtime-registered handler can reach it (§6.11 reentry).
-/
import EntityCore.Peer
import Std.Sync.Mutex

namespace EntityCore.Transport

open EntityCore.Model
open EntityCore.Peer (Peer Conn dispatch internalErrorResponse)

/-- Per-connection IO state: the fd, a write lock, and the reentry pending-map. -/
structure ConnIO where
  fd : UInt32
  writeMutex : Std.Mutex Unit
  pending : Std.Mutex (List (String × IO.Promise (Option Envelope)))
  closed : IO.Ref Bool

def ConnIO.new (fd : UInt32) : IO ConnIO := do
  pure { fd, writeMutex := ← Std.Mutex.new (),
         pending := ← Std.Mutex.new [], closed := ← IO.mkRef false }

/-- Serialized framed write (responses + outbound requests share the fd). -/
def writeFramed (cio : ConnIO) (env : Envelope) : IO Unit :=
  cio.writeMutex.atomically (EntityCore.Net.writeFrame cio.fd env)

/-- Route an inbound EXECUTE_RESPONSE to its awaiting outbound caller (§6.11). -/
def routeResponse (cio : ConnIO) (env : Envelope) : IO Unit := do
  let requestId := (textField env.root "request_id").getD ""
  let pendingList ← cio.pending.atomically get
  match pendingList.find? (·.1 == requestId) with
  | some (_, p) => p.resolve (some env)
  | none => pure ()

/-- §6.13(b) outbound primitive: send a request, await its correlated response
(blocks this dispatch thread; the reader routes the reply). `none` on close. -/
def outbound (cio : ConnIO) (request : Envelope) : IO (Option Envelope) := do
  let requestId := (textField request.root "request_id").getD ""
  let p ← IO.Promise.new
  cio.pending.atomically (modify (fun l => (requestId, p) :: l))
  writeFramed cio request
  let res ← IO.wait p.result?
  cio.pending.atomically (modify (fun l => l.filter (·.1 != requestId)))
  pure (res.getD none)

/-- Wake every pending outbound waiter on connection close. -/
def closeConn (cio : ConnIO) : IO Unit := do
  cio.closed.set true
  let pendingList ← cio.pending.atomically get
  for kp in pendingList do kp.2.resolve none

/-- Reader loop (§6.11 demux): RESPONSE → route; EXECUTE → dispatch on its own
dedicated thread (§4.8). Ends on connection close / malformed frame. -/
partial def readLoop (cio : ConnIO) (onExecute : Envelope → IO Unit) : IO Unit := do
  match ← EntityCore.Net.readFrame cio.fd with
  | none => pure ()
  | some env =>
    if env.root.typ == "system/protocol/execute/response" then
      routeResponse cio env
    else
      -- Dispatch on the shared task pool (reused threads), NOT a fresh .dedicated
      -- thread per request: per-request thread creation is an O(requests)
      -- sustained-load latency runaway (§6.11). The reader itself stays on its own
      -- dedicated thread (blocking recv off the pool) and routes any reentry
      -- response, so a pool worker blocked on an outbound await never deadlocks.
      let _ ← IO.asTask (onExecute env)
      pure ()
    readLoop cio onExecute

/-- Serve one accepted connection: wire the §6.13(b) outbound seam, then read. -/
def serveConnection (peer : Peer) (fd : UInt32) : IO Unit := do
  let cio ← ConnIO.new fd
  let conn ← Conn.new
  conn.outbound.set (some (fun req => outbound cio req))
  let onExecute (env : Envelope) : IO Unit := do
    -- Per-request isolation: an exception on one request must not tear the
    -- connection down (§3.3 every EXECUTE gets a response).
    let resp ← try dispatch peer conn env catch _ => pure (internalErrorResponse env)
    match resp with
    | some r => (try writeFramed cio r catch _ => pure ())
    | none => pure ()
  readLoop cio onExecute
  closeConn cio
  try EntityCore.Net.tcpClose fd catch _ => pure ()

/-- Accept connections forever, each served on its own dedicated thread. -/
partial def acceptLoop (peer : Peer) (lfd : UInt32) : IO Unit := do
  let cfd ← EntityCore.Net.tcpAccept lfd
  if cfd == EntityCore.Net.badfd then pure ()
  else
    let _ ← IO.asTask (serveConnection peer cfd) .dedicated
    acceptLoop peer lfd

end EntityCore.Transport
