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

/-- What one read of the socket produced (§1.6, §4.11).

THE THREE ARE NOT INTERCHANGEABLE AND THEY USED TO BE ONE `none`. An EOF is a clean
end of connection and is a refusal of nothing; an oversize prefix and a truncated
body are §4.11 PRE-ADMISSION REFUSALS, each owed a coded EXECUTE_RESPONSE before the
loop ends. Collapsing them meant this peer answered an over-`maxFrame` envelope by
ending the read loop with nothing on the wire — §4.11's second named non-conformant
behaviour, "closing with no coded frame", which is indistinguishable from a network
fault (§4.6) and which on a multiplexed connection destroys unrelated ADMITTED
requests. -/
inductive FrameRead where
  | payload (p : ByteArray)
  /-- Clean EOF / closed socket. Nothing to answer, nobody to answer to. -/
  | eof
  /-- A §4.11 refusal: the coded frame goes out and THEN the loop ends. -/
  | refused (cause : EntityCore.Wire.PreAdmission)

/-- Read one framed payload, keeping the three outcomes apart.

The oversize test is on the DECLARED length and runs BEFORE the body is read, as
§4.10(a) requires ("reject before fully buffering") — draining the declared body to
keep the stream framed IS the fully-buffering that section forbids, and a sender
declaring 4 GiB and sending 1 KiB would park the peer forever. -/
def readFrameResult (fd : UInt32) : IO FrameRead := do
  let hdr ← tcpRecvExact fd 4
  if hdr.size != 4 then pure .eof
  else
    let len := (hdr[0]!.toNat <<< 24) ||| (hdr[1]!.toNat <<< 16)
             ||| (hdr[2]!.toNat <<< 8) ||| hdr[3]!.toNat
    if len > EntityCore.Wire.maxFrame then pure (.refused .frameTooLarge)
    else
      let payload ← tcpRecvExact fd (UInt32.ofNat len)
      -- A length prefix arrived and the body did not: the sender is gone mid-frame.
      -- §4.11's framing arm — a refusal, not an EOF.
      if payload.size != len then pure (.refused .frameTruncated)
      else pure (.payload payload)

/-- Read one framed payload. `none` means the CONNECTION is finished (EOF, short
read, or an over-`maxFrame` length prefix per §4.10(a)); it does NOT mean the
frame was malformed.

That distinction is the whole point of this function. It used to decode inline and
collapse "connection closed" and "undecodable frame" into the same `none`, and
`readLoop`'s `none` branch ENDS the loop -- so a single malformed frame tore the
connection down and every subsequent request on it failed. Decoding is now the
caller's job, which lets it answer §6.3's mandated `400 non_canonical_ecf` and
keep serving. -/
def readFramePayload (fd : UInt32) : IO (Option ByteArray) := do
  match ← readFrameResult fd with
  | .payload p => pure (some p)
  | _ => pure none

/-- Read one framed envelope; `none` on connection close OR a malformed frame.
Retained for callers that do not need the distinction (the client/outbound side);
the server reader loop uses `readFramePayload` so it can tell them apart. -/
def readFrame (fd : UInt32) : IO (Option EntityCore.Model.Envelope) := do
  match ← readFramePayload fd with
  | none => pure none
  | some payload => pure (EntityCore.Wire.envelopeOfPayload payload)

end EntityCore.Net
