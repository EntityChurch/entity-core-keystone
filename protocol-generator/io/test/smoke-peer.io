// S3 smoke — an in-process peer-dispatch walk over the REAL §4.1 handshake +
// §5.2/§6.5 dispatch chain: hello + authenticate to obtain a capability, then
// 404, a tree get on a floor type, and a system/capability:request round-trip.
//
// This drives `peer dispatch(conn, env)` directly (the same path the transport's
// _serviceFrame calls) rather than over an in-process socket pair: this frozen
// Io build runs an `obj @method` coroutine to completion before the spawning
// coroutine resumes (yield is a no-op when no other coro is queued), so two
// in-process socket loops cannot cooperatively interleave. The REAL-transport,
// separate-process path is validated by run-s4.sh (the Go validate-peer oracle
// over loopback TCP). Prints PASS/FAIL and exits.

EntityCodec
srcDir := Path with(File thisSourceFile parentDirectory parentDirectory path, "src")
loadSrc := method(name, Lobby doFile(Path with(srcDir, name)))
loadSrc("Ec.io"); loadSrc("Entity.io"); loadSrc("Envelope.io"); loadSrc("Identity.io")
loadSrc("Wire.io"); loadSrc("Store.io"); loadSrc("Capability.io"); loadSrc("CoreTypes.io")
loadSrc("Handlers.io"); loadSrc("Peer.io"); loadSrc("Transport.io")

fails := 0
check := method(name, ok,
    if(ok, ("ok   " .. name) println, fails = fails + 1; ("FAIL " .. name) println))

respIdent := Identity ofSeed(EntityCodec hexDecode("2222222222222222222222222222222222222222222222222222222222222222"))
respPeer := Peer createFromIdentity(respIdent, true, false)   // open grants for the smoke
respLocal := respPeer localPeer
initIdent := Identity ofSeed(EntityCodec hexDecode("3333333333333333333333333333333333333333333333333333333333333333"))

// a Map "conn" carrying the handshake state the dispatch path threads (no socket)
conn := Map clone atPut("established", false) atPut("issued_nonce", nil) \
    atPut("hello_peer_id", nil) atPut("out_counter", 0) atPut("outbound_transport", nil)

rid := 0
nextRid := method(rid = rid + 1; "req-" .. rid)
dispatchExec := method(exec, included,
    respPeer dispatch(conn, Envelope with(exec, if(included == nil, List clone, included))))

// ── §4.1 handshake: hello → authenticate → capability ──
hello := Entity with("system/protocol/connect/hello", EcMap with(
    "peer_id", initIdent peerId, "nonce", EcBytes with(EntityCodec randomBytes(32)),
    "protocols", list("entity-core/1.0" asSymbol), "timestamp", Capability nowMs,
    "hash_formats", list("ecfv1-sha256" asSymbol), "key_types", list("ed25519" asSymbol)))
r1 := dispatchExec(Wire makeExecute(nextRid, "system/protocol/connect", "hello", hello, nil, nil, nil), nil)
check("hello -> 200", Wire responseStatus(r1) == 200)
remoteHello := Wire responseResult(r1)
check("remote peer id matches responder", remoteHello text("peer_id") == respLocal)
remoteNonce := remoteHello bytes("nonce")

auth := Entity with("system/protocol/connect/authenticate", EcMap with(
    "peer_id", initIdent peerId, "public_key", EcBytes with(initIdent pub),
    "key_type", "ed25519", "nonce", EcBytes with(remoteNonce)))
r2 := dispatchExec(Wire makeExecute(nextRid, "system/protocol/connect", "authenticate", auth, nil, nil, nil),
    list(initIdent peerEntity, initIdent sign(auth)))
check("authenticate -> 200", Wire responseStatus(r2) == 200)
grant := Wire responseResult(r2)
token := if(grant != nil, r2 includedGet(grant bytes("token")), nil)
granterPeer := if(token != nil, r2 includedGet(token bytes("granter")), nil)
capSig := if(token != nil, Capability findSignature(token hash, r2 included), nil)
check("handshake yielded a capability", token != nil and(granterPeer != nil) and(capSig != nil))

// authenticated-EXECUTE helper (§3.2 + §5.2)
authExec := method(uri, op, params, resource,
    exec := Wire makeExecute(nextRid, uri, op, params, initIdent idHash, token hash, resource)
    dispatchExec(exec, list(token, granterPeer, initIdent peerEntity, capSig, initIdent sign(exec))))

r404 := authExec("local/nope/here", "get", Wire emptyParams, Wire resourceTarget("local/nope/here"))
check("404 handler_not_found", Wire responseStatus(r404) == 404)

rget := authExec("system/tree", "get", Entity with("system/tree/get-request", EcMap clone),
    Wire resourceTarget("system/type/primitive/string"))
check("tree get floor type -> 200", Wire responseStatus(rget) == 200)
gotType := Wire responseResult(rget)
check("tree get returned a system/type entity", gotType != nil and(gotType entityType == "system/type"))

reqEnt := Entity with("system/capability/request", EcMap with(
    "grants", list(Capability grant(list("system/tree" asSymbol),
                                    list("system/type/*" asSymbol),
                                    list("get" asSymbol), nil))))
rcap := authExec("system/capability", "request", reqEnt, nil)
check("capability:request -> 200", Wire responseStatus(rcap) == 200)
grantOut := Wire responseResult(rcap)
check("capability:request returned a grant", grantOut != nil and(grantOut entityType == "system/capability/grant"))

ra := authExec("system/tree", "get", Entity with("system/tree/get-request", EcMap clone),
    Wire resourceTarget("system/type/primitive/uint"))
rb := authExec("system/tree", "get", Entity with("system/tree/get-request", EcMap clone),
    Wire resourceTarget("system/type/primitive/bool"))
check("sequential gets both 200", Wire responseStatus(ra) == 200 and(Wire responseStatus(rb) == 200))

if(fails > 0, ("SMOKE-PEER FAIL (" .. fails .. ")") println; System exit(1))
"SMOKE-PEER OK: handshake + 404 + tree get + capability request (in-process dispatch)" println
System exit(0)
