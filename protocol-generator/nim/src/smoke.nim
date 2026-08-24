## S3 smoke runner — the phase exit gate. Two Nim peers talk over real loopback
## TCP through the full machinery, asserting the S3 contract:
##
##   1. Handshake BOTH DIRECTIONS — A dials B (hello + authenticate → session), and
##      B dials A (the symmetric direction). §4.1 legs 1–2 are the mandatory core;
##      leg 3 (reverse authenticate) is deferred (§4.1).
##   2. Unknown-handler EXECUTE on an AUTHENTICATED conn → 404 handler_not_found
##      (resolved-then-missed).
##   3. Unknown-handler EXECUTE on an UNAUTHENTICATED conn → 401 (F31: auth BEFORE
##      resolve; MUST NOT leak 404).
##   4. request_id demux — 8 concurrent in-flight EXECUTEs each correlate to their
##      own reply by request_id (§6.11(b)), no cross-delivery, no hang.
##
## Run (in-container): `nim c -r --mm:orc src/smoke.nim`. Exit 0 = all green.
##
## SPDX-License-Identifier: Apache-2.0

import std/[asyncdispatch, asyncnet, nativesockets, options]
import ./model
import ./wire
import ./peer
import ./transport

var passCount = 0
var failCount = 0

proc check(name: string; ok: bool) =
  if ok: inc passCount else: inc failCount
  echo "  [", (if ok: "PASS" else: "FAIL"), "] ", name

proc serveConnection(p: Peer; sock: AsyncSocket) {.async.} =
  setNoDelay(sock)
  let io = newIo(sock)
  let conn = Conn()
  await readLoop(p, conn, io)
  sock.close()

proc acceptLoop(p: Peer; server: AsyncSocket) {.async.} =
  while true:
    let client = await server.accept()
    asyncCheck serveConnection(p, client)

proc boundPort(server: AsyncSocket): Port =
  getLocalAddr(server.getFd(), AF_INET)[1]

proc openSession(local: Peer; remotePort: Port): Future[Session] {.async.} =
  ## Dial + start the reader loop + run the §4.1 handshake.
  let sock = await dial(remotePort)
  let io = newIo(sock)
  let conn = Conn()
  asyncCheck readLoop(local, conn, io)   # routes responses into pending futures
  return await initiate(local, io, conn)

proc runSmoke() {.async.} =
  var seedA = newSeq[byte](32)
  var seedB = newSeq[byte](32)
  for i in 0 ..< 32: seedA[i] = 0x01'u8
  for i in 0 ..< 32: seedB[i] = 0x02'u8
  let peerA = newPeer(seedA)
  let peerB = newPeer(seedB)

  let serverA = listen(Port(0))
  let serverB = listen(Port(0))
  asyncCheck acceptLoop(peerA, serverA)
  asyncCheck acceptLoop(peerB, serverB)
  let portA = boundPort(serverA)
  let portB = boundPort(serverB)

  # ── 1a. handshake: A → B (frames out and back) ─────────────────────────────
  echo "Handshake A -> B:"
  let sessAB = await openSession(peerA, portB)
  check("session established (initial capability granted)", sessAB.capability.hash.len == 33)
  check("remote peer_id matches responder B", sessAB.remotePeerId == peerB.localPeer)

  # ── 2. unknown handler on an AUTHENTICATED conn → 404 ──────────────────────
  echo "Dispatch (authenticated):"
  block:
    let uri = "/" & peerB.localPeer & "/does/not/exist"
    let resp = await sessAB.execute(uri, "noop", emptyParams())
    let status = resp.root.uintField("status").get(0'u64)
    check("unknown handler (authenticated) -> 404", status == 404)

  # ── 4. request_id demux — 8 concurrent in-flight EXECUTEs ──────────────────
  echo "Concurrency (request_id demux):"
  block:
    const N = 8
    # execute() assigns request_ids sequentially from reqCounter; called in a
    # synchronous loop the i-th future corresponds to id "req-(i+1)". All N are
    # fired before any is awaited → genuinely concurrent in-flight (§6.11).
    let base = sessAB.reqCounter
    var futs: seq[Future[Envelope]]
    for i in 0 ..< N:
      futs.add sessAB.execute("/" & peerB.localPeer & "/nope/" & $i, "noop", emptyParams())
    let replies = await all(futs)
    var correlated = 0
    for i in 0 ..< N:
      let rid = replies[i].root.textField("request_id").get("")
      let status = replies[i].root.uintField("status").get(0'u64)
      if rid == "req-" & $(base + i + 1) and status == 404: inc correlated
    check("8 interleaved requests each correlate by request_id -> " & $correlated & "/8",
          correlated == N)

  # ── 1b. handshake the OTHER direction: B → A ───────────────────────────────
  echo "Handshake B -> A (symmetric direction):"
  let sessBA = await openSession(peerB, portA)
  check("reverse session established (B dials A)", sessBA.capability.hash.len == 33)
  check("remote peer_id matches responder A", sessBA.remotePeerId == peerA.localPeer)

  # ── 3. F31: unknown handler on an UNAUTHENTICATED conn → 401 (NOT 404) ──────
  echo "F31 (auth-before-resolve):"
  block:
    let sock = await dial(portB)
    let io = newIo(sock)
    let conn = Conn()
    asyncCheck readLoop(peerA, conn, io)
    let rid = "unauth-1"
    let uri = "/" & peerB.localPeer & "/does/not/exist"
    let exec = makeExecute(rid, uri, "noop", emptyParams())   # NO author / capability
    let env = Envelope(root: exec, included: @[])
    let resp = await io.outbound(rid, env)
    let status = resp.root.uintField("status").get(0'u64)
    check("unknown handler (UNAUTHENTICATED) -> 401 (F31: not 404)", status == 401)
    sock.close()

proc main() =
  waitFor runSmoke()
  echo ""
  let allPass = failCount == 0
  echo "SMOKE: ", (if allPass: "PASS" else: "FAIL"),
       " (", passCount, " pass, ", failCount, " fail)"
  if not allPass: quit(1)

main()
