// Throughput probe — measure steady-state peer dispatch req/s and whether
// per-request latency climbs across a long sequential run (accumulation) vs is
// flat-but-slow (genuine ceiling). Isolates DISPATCH cost from the transport by
// driving peer dispatch(conn, env) in-process on a pre-built authenticated
// tree.get envelope. (A-IO-023 reconciliation vs the Oz sibling.)

EntityCodec
srcDir := Path with(File thisSourceFile parentDirectory parentDirectory path, "src")
loadSrc := method(n, Lobby doFile(Path with(srcDir, n)))
loadSrc("Ec.io"); loadSrc("Entity.io"); loadSrc("Envelope.io"); loadSrc("Identity.io")
loadSrc("Wire.io"); loadSrc("Store.io"); loadSrc("Capability.io"); loadSrc("CoreTypes.io")
loadSrc("Handlers.io"); loadSrc("Peer.io"); loadSrc("Transport.io")

// responder peer with the open-grant seed
peer := Peer createFromIdentity(Identity ofSeed(EntityCodec hexDecode("2222222222222222222222222222222222222222222222222222222222222222")), true, true)
client := Identity ofSeed(EntityCodec hexDecode("3333333333333333333333333333333333333333333333333333333333333333"))

// a Map "conn" (no socket) — dispatch only touches conn state for the handshake
conn := Map clone atPut("established", false) atPut("issued_nonce", nil) atPut("hello_peer_id", nil) atPut("out_counter", 0) atPut("outbound_transport", nil)

rid := 0
nextRid := method(rid = rid + 1; "req-" .. rid)

// ── handshake in-process to obtain the client's initial capability ──
hello := Entity with("system/protocol/connect/hello", EcMap with(
    "peer_id", client peerId, "nonce", EcBytes with(EntityCodec randomBytes(32)),
    "protocols", list("entity-core/1.0" asSymbol), "timestamp", Capability nowMs,
    "hash_formats", list("ecfv1-sha256" asSymbol), "key_types", list("ed25519" asSymbol)))
r1 := peer dispatch(conn, Envelope with(Wire makeExecute(nextRid, "system/protocol/connect", "hello", hello, nil, nil, nil), List clone))
remoteNonce := (Wire responseResult(r1)) bytes("nonce")

auth := Entity with("system/protocol/connect/authenticate", EcMap with(
    "peer_id", client peerId, "public_key", EcBytes with(client pub),
    "key_type", "ed25519", "nonce", EcBytes with(remoteNonce)))
authSig := client sign(auth)
r2 := peer dispatch(conn, Envelope with(
    Wire makeExecute(nextRid, "system/protocol/connect", "authenticate", auth, nil, nil, nil),
    list(client peerEntity, authSig)))
grant := Wire responseResult(r2)
token := r2 includedGet(grant bytes("token"))
granterPeer := r2 includedGet(token bytes("granter"))
capSig := Capability findSignature(token hash, r2 included)
("handshake ok, cap=" .. (token != nil)) println

// ── build ONE authenticated tree.get envelope (reused each iteration) ──
buildReq := method(uri, res,
    getReq := Entity with("system/tree/get-request", EcMap clone)
    resource := Wire resourceTarget(res)
    exec := Wire makeExecute(nextRid, uri, "get", getReq, client idHash, token hash, resource)
    execSig := client sign(exec)
    Envelope with(exec, list(token, granterPeer, client peerEntity, capSig, execSig))
)

// the TRUE peer-side hot path is decode(frame bytes) + dispatch (the oracle
// builds+signs the request; that is client cost, not the peer's). Pre-build ONE
// request frame's bytes and measure decode+dispatch per method call.
reqFrameBytes := EntityCodec encode(buildReq("system/tree", "system/type/primitive/string") toWire)
nope404Bytes := EntityCodec encode(buildReq("local/nope/here", "local/nope/here") toWire)   // the CBOR payload (no length prefix)
mode := System getEnvironmentVariable("TP_MODE")       // "dispatch" | "decode" | else both
preEnv := Wire envelopeOfFrame(reqFrameBytes)
peerServe := method(bytes,
    if(mode == "dispatch", peer dispatch(conn, preEnv); return nil)
    if(mode == "decode", Wire envelopeOfFrame(bytes); return nil)
    if(mode == "verify",
        env := Wire envelopeOfFrame(bytes)
        Capability verifyRequest(peer localPeer, peer store, env)
        return nil)
    if(mode == "d404",
        env := Wire envelopeOfFrame(nope404Bytes)
        peer dispatch(conn, env)
        return nil)
    if(mode == "vr_resp",
        env := Wire envelopeOfFrame(bytes)
        Capability verifyRequest(peer localPeer, peer store, env)
        resp := Envelope with(Wire makeResponse(env root text("request_id"), 404, Wire errorResult("not_found", "x")), List clone)
        return nil)
    if(mode == "resolve",
        env := Wire envelopeOfFrame(bytes)
        p := Capability canonicalize(peer localPeer, Capability normalizeUri(env root text("uri")))
        peer store resolveHandlerPattern(p)
        return nil)
    env := Wire envelopeOfFrame(bytes)
    peer dispatch(conn, env)
    nil
)
warm := peer dispatch(conn, preEnv)
("warm status=" .. Wire responseStatus(warm)) println

// ── measure: N requests via a METHOD per iteration (drains the retain pool
// per call, exactly like the real peer's _serviceFrame → peer dispatch path;
// a bare for-loop body accumulates on the loop activation's pool — a test
// artifact, not the peer's behaviour) ──
N := 3000
t0 := Date clone now asNumber
bucketStart := t0
doCollect := System getEnvironmentVariable("TP_COLLECT") != nil
for(i, 1, N,
    peerServe(reqFrameBytes)
    if(doCollect and(i % 100 == 0), Collector collect)
    if(i % 500 == 0,
        now := Date clone now asNumber
        dt := now - bucketStart
        rate := (500 / dt) floor
        rss := File with("/proc/self/status") contents split("\n") select(containsSeq("VmRSS")) first
        cSize := peer store content size
        tSize := peer store tree size
        nNodes := peer store nodes size
        ("req " .. i .. "  rate=" .. rate .. " req/s  " .. rss .. "  store.content=" .. cSize .. " tree=" .. tSize .. " nodes=" .. nNodes) println
        bucketStart = now
    )
)
total := Date clone now asNumber - t0
("=== TOTAL " .. N .. " via-method in " .. (total * 1000) floor .. "ms = " .. (N / total) floor .. " req/s ===") println
