## entity-core-protocol-nim — standalone peer host (the S4 conformance target).
##
## Boots a single Peer listener on a TCP port and runs the asyncdispatch event
## loop forever, so an external oracle (entity-core-go `validate-peer`) can drive
## the live wire surface. Twin of the Zig `host` / C# `EntityCore.Protocol.Host`.
##
##   --port N               listen port (default 7777; 0 = auto-assign)
##   --name NAME            load a persistent Ed25519 identity from the standard
##                          on-disk location ~/.entity/peers/NAME/keypair (entity-
##                          core PEM: base64 of a 32-byte seed between BEGIN/END
##                          ENTITY PRIVATE KEY lines — the Go entity-peer / peer-
##                          manager convention). Without --name a random seed.
##   --validate             register the §7a system/validate/* conformance handlers
##                          (OFF by default; dispatch-outbound is a standing dialer).
##   --debug-open-grants    degenerate default→* seed policy (deprecated; debug only).
##
## Binds loopback (127.0.0.1); a single `LISTENING …` line goes to stdout once
## bound (a run-script waits for it).
##
## SPDX-License-Identifier: Apache-2.0

import std/[asyncdispatch, asyncnet, os, base64, strutils, nativesockets, sysrand]
import ./peer
import ./transport

proc serveConnection(p: Peer; sock: AsyncSocket) {.async.} =
  setNoDelay(sock)                       # §7b: low-latency request/response
  let io = newIo(sock)
  let conn = Conn()
  await readLoop(p, conn, io)            # blocks until the connection closes
  sock.close()

proc acceptLoop(p: Peer; server: AsyncSocket) {.async.} =
  while true:
    let client = await server.accept()   # §4.8: each conn served as its own task
    asyncCheck serveConnection(p, client)

proc loadSeedFromName(name: string): seq[byte] =
  ## Read the 32-byte seed from ~/.entity/peers/NAME/keypair (PEM: base64 body
  ## between BEGIN/END ENTITY PRIVATE KEY lines).
  let home = getEnv("HOME", "/root")
  let path = home / ".entity" / "peers" / name / "keypair"
  if not fileExists(path):
    stderr.writeLine("error: --name " & name & ": cannot read " & path)
    quit(2)
  var body = ""
  for raw in readFile(path).splitLines():
    let line = raw.strip()
    if line.len == 0 or line[0] == '-': continue
    body.add line
  let dec = decode(body)
  if dec.len != 32:
    stderr.writeLine("error: --name " & name & ": expected a 32-byte seed, got " & $dec.len)
    quit(2)
  result = newSeq[byte](32)
  for i in 0 ..< 32: result[i] = byte(dec[i])

proc main() =
  var
    port = 7777
    validate = false
    openGrants = false
    seed = newSeq[byte](32)
    haveName = false
  discard urandom(seed)                  # default random seed (overridden by --name)
  let params = commandLineParams()
  var idx = 0
  while idx < params.len:
    let arg = params[idx]
    case arg
    of "--port":
      inc idx
      if idx >= params.len: (stderr.writeLine("error: --port requires an integer"); quit(2))
      port = parseInt(params[idx])
    of "--name":
      inc idx
      if idx >= params.len: (stderr.writeLine("error: --name requires a value"); quit(2))
      seed = loadSeedFromName(params[idx]); haveName = true
    of "--validate": validate = true
    of "--debug-open-grants": openGrants = true
    of "-h", "--help":
      echo "usage: host [--port N] [--name NAME] [--validate] [--debug-open-grants]"
      return
    else:
      stderr.writeLine("error: unknown argument '" & arg & "'"); quit(2)
    inc idx
  discard haveName

  let p = newPeer(seed, validate = validate, openGrants = openGrants)
  let server = listen(Port(port))
  let bound = getLocalAddr(server.getFd(), AF_INET)
  echo "LISTENING 127.0.0.1:" & $bound[1] & " peer_id=" & p.localPeer &
       " validate=" & $validate & " open_grants=" & $openGrants
  asyncCheck acceptLoop(p, server)
  runForever()

main()
