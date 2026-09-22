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
import ./errors      # TagRejected — §4.11's one arm that KEEPS non_canonical_ecf
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
  ## Read up to `n` bytes, looping until `n` are in hand or the peer closes. A SHORT
  ## result is returned as-is rather than collapsed to "": the caller needs to tell a
  ## close at a frame boundary (0 bytes read) from one MID-FRAME (1..n-1 read), because
  ## §4.11 owes a coded frame for the second and nothing at all for the first.
  var buf = newStringOfCap(n)
  while buf.len < n:
    let chunk = await sock.recv(n - buf.len)
    if chunk.len == 0: break        # peer closed
    buf.add chunk
  buf

type Frame = object
  closed: bool       ## clean connection close AT A FRAME BOUNDARY — owed nothing
  truncated: bool    ## §4.11 framing arm: the stream ended MID-FRAME — owed 400
  oversize: int      ## >0 → §4.10(a) over-limit; the DECLARED length, never read
  payload: seq[byte]

proc readFrame(sock: AsyncSocket): Future[Frame] {.async.} =
  ## Read one length-prefixed frame. §4.10(a): an over-limit frame is signalled at its
  ## LENGTH PREFIX and its body is never read -- "reject BEFORE fully buffering".
  ##
  ## THE TRUNCATED ARM IS SEPARATE FROM THE CLEAN CLOSE and that is §4.11's framing row:
  ## "un-parseable, truncated or non-canonical CBOR, or a length prefix that never
  ## completes" is a REFUSAL owed a coded frame, while a clean EOF at a frame boundary is
  ## an ordinary hangup owed nothing. Both surface as a short read, so the distinction
  ## can only be made where the frame boundary is known -- and getting it wrong the other
  ## way would answer 400 to every peer that simply hangs up. This peer collapsed both
  ## into `closed` and broke the loop silently.
  let hdr = await recvExactly(sock, 4)
  if hdr.len == 0: return Frame(closed: true)
  if hdr.len < 4: return Frame(truncated: true)     # a partial length prefix
  let n = (uint32(byte hdr[0]) shl 24) or (uint32(byte hdr[1]) shl 16) or
          (uint32(byte hdr[2]) shl 8) or uint32(byte hdr[3])
  if int(n) > MaxFrame:
    return Frame(oversize: int(n))
  # A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
  # refused there as bytes that never become an Envelope.
  let body = await recvExactly(sock, int(n))
  if body.len < int(n): return Frame(truncated: true)
  var payload = newSeq[byte](body.len)
  for i in 0 ..< body.len: payload[i] = byte(body[i])
  Frame(payload: payload)

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

proc preAdmissionRefusal*(e: ref Exception): tuple[status: uint64, code, message: string] =
  ## The `(status, code, message)` §4.11 assigns a pre-admission failure's CAUSE.
  ##
  ## "The frame obligation belongs to the class; the CODE belongs to the cause [MUST]" --
  ## a single code for the class would answer an honest caller under the wrong reason and
  ## send them to the wrong layer.
  ##
  ##   envelope over the configured maximum  413 payload_too_large  (§4.10(a), N14)
  ##   resolution integrity (mis-keyed inc.) 400 hash_mismatch      (§5.2a, §1.8)
  ##   framing / never becomes an Envelope   400 invalid_request    (§4.7, §4.11)
  ##   root is neither EXECUTE nor E_R       400 invalid_request    (§3.3, §4.11 -- in
  ##                                           peer.dispatch, not here)
  ##   connect-auth proof-of-possession      401 authentication_failed (the connect
  ##                                           handler's, not here)
  ##
  ## THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
  ## non-conformant "on the framing arm" and gives its reason in the same sentence:
  ## ENTITY-CBOR-ENCODING defines it for CBOR TAG-POLICY violations specifically, which
  ## that document still MUSTs at decode time (§6.3). The two rows are disjoint by CAUSE
  ## rather than in conflict. Everything else this decoder calls non-canonical (a
  ## non-minimal head, an indefinite length, mis-ordered keys) is genuinely
  ## "non-canonical CBOR that never becomes an Envelope".
  ##
  ## This peer answered `non_canonical_ecf` for EVERY decode-boundary cause until
  ## 0.8.2.24/.25 pinned them apart -- measured on the wire, arc-probe B1/B2. A mis-keyed
  ## `included` entry carries NO TAG: its encoding is canonical, what is false is the
  ## claim the KEY makes, and the remedy `non_canonical_ecf` selects (*re-encode*) sends
  ## an honest caller to the wrong layer.
  ##
  ## ORDER IS LOAD-BEARING: `TagRejected` is an `EcCodecError` and the model errors are
  ## `ModelError`s, so each specific arm is tested before anything that could subsume it.
  ##
  ## The messages are a FIXED TABLE, never the exception's own text: a wire-visible
  ## string stays ASCII (two peers in this cohort have been killed at runtime by a
  ## non-ASCII byte in an encoded string, on two unrelated compilers), and nothing here
  ## echoes attacker-supplied bytes back.
  if e of IncludedKeyMismatch or e of ContentHashMismatch:
    (400'u64, "hash_mismatch", "an entity was addressed by a hash that does not bind to it")
  elif e of TagRejected:
    (400'u64, "non_canonical_ecf", "CBOR tags are forbidden anywhere in an entity data field")
  else:
    (400'u64, "invalid_request", "frame did not decode into an envelope")

proc refusePreAdmission(io: Io; requestId: string;
                        refusal: tuple[status: uint64, code, message: string]) {.async.} =
  ## Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
  ## refused BEFORE it becomes an admitted request.
  ##
  ## "A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
  ## wire [MUST] -- correlated by `request_id` where the id is available, and otherwise
  ## as a best-effort coded frame carrying no correlation."
  ##
  ## §4.9(c)'s deliver-or-signal rule is scoped to "every request the peer ADMITS" and
  ## therefore reaches none of these, which is why §4.11 exists. BOTH of the
  ## non-conformant behaviours it names separately were present on this peer: DROPPING
  ## the frame (the un-salvageable decode arm and the non-EXECUTE root) and CLOSING with
  ## no coded frame (the truncated arm's bare `break`).
  ##
  ## AN EMPTY `request_id` IS THE BEST-EFFORT FORM, not a bug: it is what the section
  ## prescribes where no id can be recovered, and guessing one would correlate the
  ## refusal to somebody else's in-flight request.
  let err = errorResult(refusal.code, some(refusal.message))
  try:
    await io.writeFramed(Envelope(root: makeResponse(requestId, refusal.status, err),
                                  included: @[]))
  except CatchableError:
    discard   # a write failure here is a dead socket, not a protocol decision

proc readLoop*(p: Peer; conn: Conn; io: Io) {.async.} =
  ## Read frames until the connection closes. EXECUTE_RESPONSE → route to its
  ## awaiting caller; EXECUTE → dispatch on its own task (reader keeps reading);
  ## anything else → §4.11/§6.5 coded refusal, which peer.dispatch supplies.
  try:
    while true:
      let frame = await readFrame(io.sock)
      if frame.closed: break                         # clean close at a frame boundary
      if frame.truncated:
        # §4.11's framing arm. This used to arrive as `closed` and take a bare `break` --
        # "closing with no coded frame", indistinguishable from a network fault and, on a
        # multiplexed connection, fatal to unrelated ADMITTED requests. The stream is
        # desynchronized (the declared bytes never arrived), so the frame goes out and
        # THEN the connection closes: §4.11 makes the FRAME mandatory and leaves the close
        # to us, and closing is the only sound choice once the framing is lost.
        await refusePreAdmission(io, "", (400'u64, "invalid_request",
                                          "frame did not decode into an envelope"))
        break
      if frame.oversize > 0:
        # §4.10(a), mood raised SHOULD -> MUST at 0.8.2.25 (N14). The over-size condition
        # is detected at the length prefix with the connection intact and nothing spent,
        # so the permissive mood had nothing to license.
        #
        # THE DRAIN IS GONE, AND ITS REMOVAL IS THE FIX RATHER THAN A SIMPLIFICATION.
        # This arm used to consume `oversize` bytes before answering, to keep the stream
        # framed and carry on serving -- which reads as the more polite behaviour and is
        # exactly the "fully buffering" §4.10(a) forbids, one buffer at a time. A sender
        # that DECLARES 16 MiB + 1 and then sends nothing parked the reader forever and
        # NO 413 WAS EVER EMITTED: measured here, the oversize case answered nothing at
        # all until the client gave up. The frame goes out first and the connection then
        # closes, because the framing is unrecoverable once a body of unknown length is
        # outstanding -- §4.11 makes the frame mandatory and leaves the close to us.
        await refusePreAdmission(io, "", (413'u64, "payload_too_large",
                                          "inbound frame exceeds the configured maximum size"))
        break
      var env: Envelope
      var refusal = (status: 0'u64, code: "", message: "")
      try:
        env = envelopeOfFrame(frame.payload)
      except CatchableError:
        # A COMPLETE frame the decoder refused. The framing is intact, so we answer and
        # KEEP SERVING -- and the refusal MUST be a status rather than silence (§4.11;
        # §4.9(c) says the same from the other direction). This used to `continue`, which
        # rejected the frame (correct) and then dropped it on the floor (wrong): the
        # sender saw no response at all and blocked until its own timeout, so a refusal
        # was indistinguishable from a dead peer.
        #
        # The frame is still REJECTED -- only enough is salvaged to correlate the
        # response, and an unrecoverable id now takes §4.11's uncorrelated best-effort
        # form rather than the silence it used to take.
        refusal = preAdmissionRefusal(getCurrentException())
      if refusal.status != 0:
        await refusePreAdmission(io, salvageRequestId(frame.payload).get(""), refusal)
        continue                                     # keep reading
      if env.root.typ == ResponseType:
        io.routeResponse(env)
      else:
        # EXECUTE dispatches on its own task (§4.8: do not block the reader); any OTHER
        # root type reaches the same path, where peer.dispatch answers §6.5's rewritten
        # "Other type?" arm with 400 invalid_request (N12/N17). It used to be dropped
        # here without ever reaching dispatch.
        asyncCheck dispatchAndRespond(p, conn, io, env)
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
  #
  # §4.5 makes `protocols` Required with NO default, so a hello that omits it is a
  # MALFORMED hello and a conforming responder answers 400 invalid_request. This
  # dialer sent `emptyParams()` and it worked only because no peer enforced the
  # rule — the moment the responder side landed, the peer could not complete a
  # handshake with itself. THE ORACLE CANNOT SEE THIS: its origination check reuses
  # the INBOUND connection and never makes us dial.
  let helloParams = makeEntity("primitive/any", mapV(@[
    EcPair(key: textV("peer_id"), val: textV(local.localPeer)),
    EcPair(key: textV("protocols"), val: arrV(@[textV(ProtocolVersion)])),
    EcPair(key: textV("hash_formats"), val: arrV(@[textV("ecfv1-sha256")])),
    EcPair(key: textV("key_types"), val: arrV(@[textV("ed25519")])),
  ]))
  let r1 = await sendConnect(io, conn, "hello", helloParams, @[])
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
