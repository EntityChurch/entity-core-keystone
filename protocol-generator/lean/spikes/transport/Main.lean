/-
  Lean S1/1c spike — TRANSPORT.

  The handoff's flagged gate: does Lean have a usable socket story for the peer?
  This proves the three things S3 needs:
    1. TCP works over the FFI socket shim (real two-peer loopback echo).
    2. A blocking recv runs on a DEDICATED thread (IO.asTask .dedicated), so the
       compute pool is never starved — the §7b OCaml-threads posture, dodging the
       Swift cooperative-pool/blocking-syscall trap (1a finding #3).
    3. Shared state across threads is guarded by Std.Mutex (the §7b store-safety
       primitive: actor-isolation/STM alternatives don't exist in Lean, so the raw
       OS-thread runtime enforces store-safety with an explicit mutex).
-/

import Std.Sync.Mutex

@[extern "ec_tcp_listen"]  opaque tcpListen  (port : UInt16) : IO UInt32
@[extern "ec_tcp_accept"]  opaque tcpAccept  (fd : UInt32) : IO UInt32
@[extern "ec_tcp_connect"] opaque tcpConnect (port : UInt16) : IO UInt32
@[extern "ec_tcp_send"]    opaque tcpSend    (fd : UInt32) (data : @& ByteArray) : IO Unit
@[extern "ec_tcp_recv"]    opaque tcpRecv    (fd : UInt32) : IO ByteArray
@[extern "ec_tcp_close"]   opaque tcpClose   (fd : UInt32) : IO Unit

def badfd : UInt32 := 0xFFFFFFFF

/-- Server: accept one connection, echo one message, bump a shared counter. -/
def serve (port : UInt16) (hits : Std.Mutex Nat) : IO Unit := do
  let lfd ← tcpListen port
  if lfd == badfd then throw (IO.userError "listen failed")
  let cfd ← tcpAccept lfd          -- BLOCKS on the dedicated thread
  let msg ← tcpRecv cfd            -- BLOCKS
  tcpSend cfd msg                  -- echo
  hits.atomically (modify (· + 1)) -- shared state, mutex-guarded
  tcpClose cfd
  tcpClose lfd

def main : IO Unit := do
  let hits ← Std.Mutex.new (0 : Nat)
  let port : UInt16 := 38472

  -- server on a DEDICATED thread (blocking syscalls live here, off the pool)
  let srv ← IO.asTask (serve port hits) .dedicated

  IO.sleep 200  -- let the server bind+listen before we dial

  let fd ← tcpConnect port
  if fd == badfd then throw (IO.userError "connect failed")
  let payload := "ping from lean".toUTF8
  tcpSend fd payload
  let reply ← tcpRecv fd
  tcpClose fd

  -- join the server thread
  match ← IO.wait srv with
  | .ok _ => pure ()
  | .error e => throw e

  let count ← hits.atomically get

  IO.println s!"sent  bytes : {payload.size}"
  IO.println s!"echo  bytes : {reply.size}"
  IO.println s!"counter     : {count}  (Std.Mutex-guarded, set from the dedicated thread)"
  if reply == payload && count == 1 then
    IO.println "transport spike: GREEN (TCP echo over FFI + dedicated thread + Std.Mutex)"
  else
    IO.eprintln "transport spike: FAILED"
    IO.Process.exit 1
