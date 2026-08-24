## Transport (L4) — TCP listener + dialer + per-connection reader loop, on Nim's
## stdlib `asyncdispatch`/`asyncnet` single-threaded cooperative event loop
## (profile [async], A-NIM-006).
##
## Concurrency model (why this satisfies §4.8 / §6.11 / §7b structurally):
##   - ONE event thread runs the whole peer, so the store (plain Table) has no
##     concurrent writer → §7b store-safety is by construction, no lock.
##   - The reader loop dispatches each inbound EXECUTE via `asyncCheck` (fire the
##     handler as its own event-loop task) and immediately loops to read the next
##     frame — so inbound processing does NOT block on a handler's outbound
##     dispatch (§4.8). A handler that reenters with an outbound EXECUTE (§6.11) is
##     just another loop turn; its reply arrives as a readable future.
##   - §6.11 demux: outbound EXECUTEs register a `Future[Envelope]` in a per-conn
##     `pending` table keyed by `request_id`; the reader completes the matching
##     future when the EXECUTE_RESPONSE arrives, IN ANY ORDER (§6.11(b)). No
##     cross-thread demux — a single loop, a plain Table.
##   - Writes are serialized by an async mutex so two concurrent `asyncCheck`
##     responses cannot interleave bytes on the shared socket if a send yields.
##
## Frame := [4-byte big-endian length][ECF envelope] (§1.6). Max inbound frame is
## bounded (§4.10(a) 16 MiB) — over-limit is rejected before the body is buffered.
##
## SPDX-License-Identifier: Apache-2.0

import std/[asyncdispatch, asyncnet, tables, deques, options]
import std/nativesockets
import ./ecf
import ./model
import ./wire
import ./identity
import ./peer

const MaxFrame* = 16 * 1024 * 1024   ## §4.10(a) recommended default (16 MiB)

# ── minimal async mutex (asyncdispatch ships none) ─────────────────────────────

type AsyncMutex = ref object
  locked: bool
  waiters: Deque[Future[void]]

proc newAsyncMutex(): AsyncMutex =
  AsyncMutex(waiters: initDeque[Future[void]]())

proc acquire(m: AsyncMutex): Future[void] =
  result = newFuture[void]("AsyncMutex.acquire")
  if not m.locked:
    m.locked = true
    result.complete()
  else:
    m.waiters.addLast(result)

proc release(m: AsyncMutex) =
  if m.waiters.len > 0:
    m.waiters.popFirst().complete()
  else:
    m.locked = false

# ── per-connection IO state ────────────────────────────────────────────────────

type
  Io* = ref object
    sock*: AsyncSocket
    writeMu: AsyncMutex
    pending*: Table[string, Future[Envelope]]   ## §6.11 request_id → awaiting caller
    closed*: bool

proc newIo*(sock: AsyncSocket): Io =
  Io(sock: sock, writeMu: newAsyncMutex(),
     pending: initTable[string, Future[Envelope]]())

proc setNoDelay*(sock: AsyncSocket) =
  ## §7b transport menu: disable Nagle on this request/response socket (small
  ## frames + delayed-ACK is the ~40ms/round-trip churn the Zig peer found).
  ## Best-effort — a failure just leaves Nagle on, not fatal. IPPROTO_TCP=6,
  ## TCP_NODELAY=1 on Linux (the fedora:43 container target).
  when defined(linux):
    const IpprotoTcp = 6
    const TcpNodelay = 1
    try:
      setSockOptInt(sock.getFd(), IpprotoTcp, TcpNodelay, 1)
    except CatchableError:
      discard

# ── framing ────────────────────────────────────────────────────────────────────

proc recvExactly(sock: AsyncSocket; n: int): Future[string] {.async.} =
  ## Read exactly `n` bytes; empty string signals a closed connection.
  var buf = newStringOfCap(n)
  while buf.len < n:
    let chunk = await sock.recv(n - buf.len)
    if chunk.len == 0: return ""   # peer closed
    buf.add chunk
  buf

type Frame = object
  closed: bool       ## clean connection close
  oversize: int      ## >0 → §4.10(a) over-limit; drain this many bytes then 413
  payload: seq[byte]

proc readFrame(sock: AsyncSocket): Future[Frame] {.async.} =
  ## Read one length-prefixed frame. §4.10(a): an over-limit frame is signalled
  ## (not read into memory) so the reader can drain + reply 413 and KEEP serving.
  let hdr = await recvExactly(sock, 4)
  if hdr.len == 0: return Frame(closed: true)
  let n = (uint32(byte hdr[0]) shl 24) or (uint32(byte hdr[1]) shl 16) or
          (uint32(byte hdr[2]) shl 8) or uint32(byte hdr[3])
  if int(n) > MaxFrame:
    return Frame(oversize: int(n))
  let body = await recvExactly(sock, int(n))
  if body.len < int(n): return Frame(closed: true)
  var payload = newSeq[byte](body.len)
  for i in 0 ..< body.len: payload[i] = byte(body[i])
  Frame(payload: payload)

proc drainBytes(sock: AsyncSocket; total: int) {.async.} =
  ## Consume + discard `total` bytes from the socket (§4.10(a) oversize drain), so
  ## the stream stays framed and the connection keeps serving after the 413.
  var remaining = total
  while remaining > 0:
    let chunk = await sock.recv(min(remaining, 65536))
    if chunk.len == 0: break         # peer closed mid-drain
    remaining -= chunk.len

proc writeFramed(io: Io; env: Envelope): Future[void] {.async.} =
  ## Serialized framed write (responses + outbound requests share the socket).
  let payload = encodeEnvelope(env)
  var frame = newString(4 + payload.len)
  let n = uint32(payload.len)
  frame[0] = char((n shr 24) and 0xff)
  frame[1] = char((n shr 16) and 0xff)
  frame[2] = char((n shr 8) and 0xff)
  frame[3] = char(n and 0xff)
  for i in 0 ..< payload.len: frame[4 + i] = char(payload[i])
  await io.writeMu.acquire()
  try:
    await io.sock.send(frame)
  finally:
    io.writeMu.release()

# ── §6.11 outbound demux ───────────────────────────────────────────────────────

proc outbound*(io: Io; requestId: string; req: Envelope): Future[Envelope] {.async.} =
  ## Send an EXECUTE and await its correlated EXECUTE_RESPONSE (§6.11).
  if io.closed: raise newException(IOError, "connection_broken")
  let fut = newFuture[Envelope]("outbound")
  io.pending[requestId] = fut
  await io.writeFramed(req)
  return await fut

proc routeResponse(io: Io; env: Envelope) =
  ## Complete the awaiting caller's future by request_id (§6.11(b), any order).
  let rid = env.root.textField("request_id").get("")
  if io.pending.hasKey(rid):
    let fut = io.pending[rid]
    io.pending.del(rid)
    fut.complete(env)
  # unmatched response: drop (nothing awaiting)

proc closeIo(io: Io) =
  ## Wake every pending waiter with connection_broken (§6.11 teardown).
  io.closed = true
  for rid, fut in io.pending:
    if not fut.finished: fut.fail(newException(IOError, "connection_broken"))
  io.pending.clear()

# ── reader loop (§4.8 + §6.11 demux) ───────────────────────────────────────────

proc dispatchAndRespond(p: Peer; conn: Conn; io: Io; env: Envelope) {.async.} =
  ## Dispatch one inbound EXECUTE as its own event-loop task and write the reply.
  ## The §6.11 reentry sender lets a handler (system/validate/dispatch-outbound)
  ## originate an outbound EXECUTE on THIS connection and await its response.
  let sender: OutboundSender =
    proc(reqId: string; e: Envelope): Future[Envelope] = io.outbound(reqId, e)
  let resp = await dispatch(p, conn, env, sender)
  if resp.isSome:
    try:
      await io.writeFramed(resp.get)
    except CatchableError:
      discard   # peer went away mid-write; reader loop will observe the close

proc readLoop*(p: Peer; conn: Conn; io: Io) {.async.} =
  ## Read frames until the connection closes. EXECUTE_RESPONSE → route to its
  ## awaiting caller; EXECUTE → dispatch on its own task (reader keeps reading).
  try:
    while true:
      let frame = await readFrame(io.sock)
      if frame.closed: break                         # clean close
      if frame.oversize > 0:
        # §4.10(a): drain the over-limit body, reply 413, KEEP serving.
        await drainBytes(io.sock, frame.oversize)
        let err = makeResponse("", 413'u64, errorResult("payload_too_large"))
        try: await io.writeFramed(Envelope(root: err, included: @[]))
        except CatchableError: break
        continue
      var env: Envelope
      try:
        env = envelopeOfFrame(frame.payload)
      except CatchableError:
        continue                                     # malformed → drop, keep reading
      if env.root.typ == ResponseType:
        io.routeResponse(env)
      elif env.root.typ == ExecuteType:
        asyncCheck dispatchAndRespond(p, conn, io, env)   # §4.8: do not block reader
      # §6.5 other root type → ignore (client-style; a strict responder closes)
  except CatchableError:
    discard
  io.closeIo()

# ── listener / dialer ──────────────────────────────────────────────────────────

proc listen*(port: Port): AsyncSocket =
  result = newAsyncSocket()
  result.setSockOpt(OptReuseAddr, true)
  result.bindAddr(port, "127.0.0.1")
  result.listen()

proc dial*(port: Port): Future[AsyncSocket] {.async.} =
  result = newAsyncSocket()
  await result.connect("127.0.0.1", port)
  setNoDelay(result)

# ── §4.1 initiator handshake + session ─────────────────────────────────────────

type Session* = ref object
  io*: Io
  local*: Peer
  conn*: Conn
  remotePeerId*: string
  capability*: Entity        ## the minted token the responder granted us
  granterPeer*: Entity       ## the responder's system/peer entity
  capSignature*: Entity      ## signature over the token
  reqCounter*: int

proc sendConnect(io: Io; conn: Conn; operation: string; params: Entity;
                 included: seq[Included]): Future[Envelope] {.async.} =
  ## A connect-path EXECUTE carries no author/capability (§4.2 pre-authorization).
  inc conn.outCounter
  let rid = "h-" & $conn.outCounter
  let exec = makeExecute(rid, ConnectUri, operation, params)
  let env = Envelope(root: exec, included: included)
  return await io.outbound(rid, env)

proc initiate*(local: Peer; io: Io; conn: Conn): Future[Session] {.async.} =
  ## §4.1 legs 1–2: hello → authenticate, returning an established Session. Leg 3
  ## (the reverse authenticate) is OPTIONAL + deferred (§4.1) — a client-style
  ## initiator completes via legs 1–2 alone.
  # 1. hello
  let r1 = await sendConnect(io, conn, "hello", emptyParams(), @[])
  if r1.root.uintField("status").get(0'u64) != 200:
    raise newException(IOError, "hello rejected")
  let remoteHello = r1.root.entityField("result").get
  let remotePeerId = remoteHello.textField("peer_id").get("")
  let remoteNonce = remoteHello.bytesField("nonce").get(@[])

  # 2. authenticate (§4.6 proof-of-possession)
  let auth = makeEntity("system/protocol/connect/authenticate", mapV(@[
    EcPair(key: textV("peer_id"), val: textV(local.identity.peerId)),
    EcPair(key: textV("public_key"), val: bytesV(local.identity.publicKey)),
    EcPair(key: textV("key_type"), val: textV("ed25519")),
    EcPair(key: textV("nonce"), val: bytesV(remoteNonce)),
  ]))
  let authSig = local.identity.signEntityHash(auth)
  let r2 = await sendConnect(io, conn, "authenticate", auth, @[
    (key: local.identity.identityHash, entity: local.identity.peerEntity),
    (key: authSig.hash, entity: authSig),
  ])
  if r2.root.uintField("status").get(0'u64) != 200:
    raise newException(IOError, "authenticate rejected")

  # extract the granted capability chain from the response's included map (§4.4)
  let grant = r2.root.entityField("result").get
  let tokenH = grant.bytesField("token").get(@[])
  let token = r2.includedGet(tokenH).get
  let granterH = token.bytesField("granter").get(@[])
  let granter = r2.includedGet(granterH).get
  var capSig: Entity
  for inc in r2.included:
    if inc.entity.typ == "system/signature":
      let t = inc.entity.bytesField("target")
      if t.isSome and t.get == token.hash: capSig = inc.entity
  return Session(io: io, local: local, conn: conn, remotePeerId: remotePeerId,
                 capability: token, granterPeer: granter, capSignature: capSig)

proc execute*(s: Session; uri, operation: string; params: Entity;
              resource = EcValue(nil)): Future[Envelope] {.async.} =
  ## Build, sign, and send an authenticated EXECUTE; await the correlated reply.
  ## The §5.8 chain (author peer, capability, granter peer, cap-sig, exec-sig) is
  ## carried in `included`.
  inc s.reqCounter
  let rid = "req-" & $s.reqCounter
  let exec = makeExecute(rid, uri, operation, params,
                         author = some(s.local.identity.identityHash),
                         capability = some(s.capability.hash),
                         resource = resource)
  let execSig = s.local.identity.signEntityHash(exec)
  let env = Envelope(root: exec, included: @[
    (key: s.local.identity.identityHash, entity: s.local.identity.peerEntity),
    (key: s.capability.hash, entity: s.capability),
    (key: s.granterPeer.hash, entity: s.granterPeer),
    (key: s.capSignature.hash, entity: s.capSignature),
    (key: execSig.hash, entity: execSig),
  ])
  return await s.io.outbound(rid, env)
