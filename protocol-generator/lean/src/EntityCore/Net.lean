/-
  Network FFI bindings (§1.6 framing over the C socket shim) — the unproven IO
  shell. Blocking sockets; the transport runs the reader on a `.dedicated` thread
  (§7b). `tcpRecvExact` is frame-oriented: it returns exactly `n` bytes, or a
  short read (`size < n`) when the connection closes — the framer's close signal.
-/
import EntityCore.Wire

namespace EntityCore.Net

@[extern "ec_tcp_listen"]      opaque tcpListen (port : UInt16) : IO UInt32
@[extern "ec_tcp_bound_port"]  opaque tcpBoundPort (lfd : UInt32) : IO UInt16
@[extern "ec_tcp_accept"]      opaque tcpAccept (lfd : UInt32) : IO UInt32
@[extern "ec_tcp_connect"]     opaque tcpConnect (port : UInt16) : IO UInt32
@[extern "ec_tcp_send"]        opaque tcpSendRaw (fd : UInt32) (data : @& ByteArray) : IO Unit
@[extern "ec_tcp_recv_exact"]  opaque tcpRecvExact (fd : UInt32) (n : UInt32) : IO ByteArray
@[extern "ec_tcp_close"]       opaque tcpClose (fd : UInt32) : IO Unit

/-- Wall-clock epoch milliseconds (§4.6 timestamps / the verdict `now`). -/
@[extern "ec_now_ms"]          opaque nowMs (u : Unit) : IO UInt64
/-- CSPRNG bytes (§4.6 nonce). -/
@[extern "ec_random_bytes"]    opaque randomBytes (n : UInt32) : IO ByteArray

def badfd : UInt32 := 0xFFFFFFFF

/-- 4-byte big-endian length header. -/
def be32 (n : Nat) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat (n >>> 24 &&& 0xff), UInt8.ofNat (n >>> 16 &&& 0xff),
                 UInt8.ofNat (n >>> 8 &&& 0xff), UInt8.ofNat (n &&& 0xff)]

/-- Write a framed envelope: `[4-byte BE length][CBOR payload]`. -/
def writeFrame (fd : UInt32) (env : EntityCore.Model.Envelope) : IO Unit := do
  let payload := EntityCore.Wire.payloadOfEnvelope env
  tcpSendRaw fd (be32 payload.size ++ payload)

/-- Read one framed envelope; `none` on connection close or a malformed/oversized
frame (§3.3 — the caller ends the reader loop). -/
def readFrame (fd : UInt32) : IO (Option EntityCore.Model.Envelope) := do
  let hdr ← tcpRecvExact fd 4
  if hdr.size != 4 then pure none
  else
    let len := (hdr[0]!.toNat <<< 24) ||| (hdr[1]!.toNat <<< 16)
             ||| (hdr[2]!.toNat <<< 8) ||| hdr[3]!.toNat
    if len > EntityCore.Wire.maxFrame then pure none
    else
      let payload ← tcpRecvExact fd (UInt32.ofNat len)
      if payload.size != len then pure none
      else pure (EntityCore.Wire.envelopeOfPayload payload)

end EntityCore.Net
