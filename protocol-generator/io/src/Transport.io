// entity-core-protocol-io — transport (L4): a SINGLE-COROUTINE non-blocking
// poll loop over the Socket addon's async primitives (asyncAccept /
// asyncStreamRead / asyncStreamWrite). This is the correct single-threaded
// event-peer model (the Pd/Scratch lesson made explicit): one loop services
// every connection cooperatively, so there is no per-connection blocking read
// and no coroutine yield-recursion (the A-IO-020 scheduler wedge that the
// Socket-addon's coroutine-per-connection model hits under the oracle's
// concurrent-connection probing).
//
// == §4.8 store-safety: STRUCTURAL — one coroutine, one frame dispatched to
// completion before the next is read; the store is never touched concurrently.
// == §4.9 resilience: a per-connection fault removes only that connection; the
// loop keeps serving. == §4.10(a): the 4-byte length prefix is checked against
// Wire maxFrame (16 MiB) before the body is buffered; over-limit closes the
// connection. == §6.11 reentry: a bounded synchronous send+wait on the SAME fd
// (non-response frames hand back to the connection's assembler).
// == Half-close (S1): a closed socket is dropped before any pending write; we
// never answer after peer-FIN.

Conn := Object clone do(
    new := method(sock,
        Map clone atPut("sock", sock) atPut("rbuf", Sequence clone) atPut("wbuf", Sequence clone asMutable) \
            atPut("established", false) atPut("issued_nonce", nil) \
            atPut("hello_peer_id", nil) atPut("out_counter", 0) atPut("idle", Date clone now asNumber) atPut("outbound_transport", nil)
    )
)

Transport := Object clone do(
    peer ::= nil
    listenSock ::= nil
    conns ::= nil
    port ::= 0

    with := method(p, Transport clone setPeer(p) setConns(List clone))

    dlog := method(s,
        if(System getEnvironmentVariable("PEER_DEBUG_500") != nil,
            f := File with("/tmp/conn.log") openForAppending; f write(s .. "\n"); f close))

    // Drain ALL complete frames from a conn's rbuf into a List of payloads,
    // trimming the consumed prefix ONCE at the end. Per-frame removeSlice on a
    // large buffer is O(n) → O(n²) over many frames (the T2.1 6-req/s wall — a
    // 5 MB pipelined rbuf shifting per frame); the cursor + single trim is O(n).
    // NON-RAISING (A-IO-025): an over-limit length prefix (§4.10(a)) sets
    // conn "overlimit" and stops draining — the caller closes the connection.
    // Non-raising so the poll loop needs NO per-pass `try` (Io's `try` clones a
    // Coroutine per call — the concurrency-throughput leak).
    drainFrames := method(conn,
        rbuf := conn at("rbuf")
        out := List clone
        pos := 0
        n := rbuf size
        loop(
            if(n - pos < 4, break)
            len := ((rbuf at(pos)) * 16777216) + ((rbuf at(pos + 1)) * 65536) + ((rbuf at(pos + 2)) * 256) + (rbuf at(pos + 3))
            if(len < 0 or(len > Wire maxFrame), conn atPut("overlimit", true); break)
            if(n - pos < 4 + len, break)
            out append(rbuf exSlice(pos + 4, pos + 4 + len))
            pos = pos + 4 + len
        )
        if(pos > 0, rbuf removeSlice(0, pos - 1))
        out
    )

    // service one inbound frame → write the response back on the connection.
    // NO per-frame `try` (A-IO-025): the whole decode→dispatch path is total
    // (non-raising) — envelopeOfFrame → nil on a malformed frame, dispatch → a
    // coded Outcome for every verdict — so a valid request never spawns a `try`
    // Coroutine (the concurrency-throughput leak). A genuinely-unexpected fault
    // is contained by the poll loop's one coarse guard, not a per-request try.
    _serviceFrame := method(conn, payload,
        dlog("[conn] frame " .. payload size .. "B")
        env := Wire envelopeOfFrame(payload)
        if(env == nil,
            // §6.3: "Rejection returns 400 non_canonical_ecf" — a rejected frame is owed
            // a STATUS, not silence. This used to `return`, which rejected the frame
            // (correct) and then dropped it on the floor (wrong): the sender saw no
            // response at all and blocked until its own timeout, violating §6.3's second
            // sentence and §4.9(c) deliver-or-signal. It also made a refusal
            // indistinguishable from a dead peer, and on a single-connection oracle run
            // it poisons every later request on the same connection.
            //
            // The frame is still REJECTED — only enough is salvaged to correlate the
            // response. If even the request_id is unrecoverable the frame is
            // unattributable and silence is the only option left.
            dlog("[conn] undecodable frame")
            rid := Wire salvageRequestId(payload)
            if(rid != nil,
                _sendFrame(conn, Envelope with(
                    Wire makeResponse(rid, 400, Wire errorResult("non_canonical_ecf", nil)))))
            return)
        resp := peer dispatch(conn, env)
        if(resp != nil, _sendFrame(conn, resp))
    )

    maxWbuf := 64 * 1024 * 1024      // per-conn outbound backpressure cap

    // Queue a frame for the connection and flush what the socket accepts NOW.
    // NON-BLOCKING (A-IO-026): a partial/would-block write leaves the remainder
    // buffered on the conn — it does NOT sleep-spin inside the send. A blocking
    // send stalls EVERY other connection on this single coroutine (cross-conn
    // head-of-line) → the T2.1 sustained-load i/o-timeout drops. Unwritten bytes
    // flush at the top of the next poll pass.
    _sendFrame := method(conn, env,
        conn at("wbuf") appendSeq(Wire frameOfEnvelope(env))
        _flushWrites(conn)
    )

    // write as much of the pending wbuf as the socket accepts right now; never
    // sleep. Returns false iff the connection should be dropped (closed, or the
    // un-drained backlog exceeded maxWbuf — a peer that stopped reading).
    _flushWrites := method(conn,
        wbuf := conn at("wbuf")
        if(wbuf size == 0, return true)
        sock := conn at("sock")
        if(sock isOpen not, return false)
        if(wbuf size > maxWbuf, sock close; return false)
        sock asyncStreamWrite(wbuf, 0, wbuf size)   // removes written bytes from wbuf
        true
    )

    // §6.11 reentry: write an outbound EXECUTE, then poll-read the SAME fd until
    // the correlated response arrives (dispatching a non-correlated inbound
    // EXECUTE that shows up meanwhile — behavioral presence). A bounded
    // synchronous send+wait on the ONE inbound fd (the Pd lesson); non-response
    // frames hand back to the connection's assembler.
    reentry := method(conn, reqEnv, rid,
        sock := conn at("sock")
        _sendFrame(conn, reqEnv)
        resp := nil
        deadline := Date clone now asNumber + 20
        loop(
            if(sock isOpen not, break)
            if(Date clone now asNumber > deadline, break)
            _flushWrites(conn)   // push the buffered outbound EXECUTE (+ any replies)
            sock asyncStreamRead(conn at("rbuf"), 262144)
            frames := drainFrames(conn)
            if(conn at("overlimit") == true, break)
            if(frames size == 0, System sleep(0.0005); continue)
            frames foreach(payload,
                fenv := Wire envelopeOfFrame(payload)
                if(fenv == nil, continue)
                if(fenv root entityType == "system/protocol/execute/response" and(fenv root text("request_id") == rid),
                    resp = fenv
                ,
                    // a non-correlated inbound EXECUTE (or other response) —
                    // hand back to the assembler by dispatching it now
                    if(fenv root entityType == "system/protocol/execute",
                        r2 := peer dispatch(conn, fenv)
                        if(r2 != nil, _sendFrame(conn, r2)))
                )
            )
            if(resp != nil, break)
        )
        resp
    )

    // bind + listen SYNCHRONOUSLY (no loop). Split out of `start` so a caller can
    // guarantee the socket is accepting BEFORE spawning an in-process initiator
    // coroutine (Io's `obj @method` runs the new coroutine up to its first yield
    // immediately — an initiator spawned before the bind would dial a dead port).
    bind := method(p,
        ls := Socket clone setHost("127.0.0.1") setPort(p)
        r := ls serverOpen
        if(r isError, Exception raise("serverOpen failed: " .. r message))
        setListenSock(ls)
        setPort(p)
        ls
    )

    // the accept + service loop (drives the scheduler for any peer coroutine).
    serve := method(
        addr := IPAddress clone
        ls := listenSock
        // _pollPass is a METHOD (not the loop body) so its retain pool drains on
        // every return — WITHOUT this, the poll loop is one long-lived activation
        // whose pool accumulates every request's frame/envelope objects → GC-mark
        // thrash → the T2.1 ~6-req/s collapse (A-IO-021, the same retain-stack
        // draining lesson as the codec, applied at the loop boundary).
        loop(
            if(_pollPass(ls, addr) not, System sleep(0.0005))
        )
    )

    start := method(p, bind(p); serve)

    _pollPass := method(ls, addr,
        busy := false
        // accept ALL pending connections this pass (churn — §4.9/T2.2)
        accepting := true
        while(accepting,
            c := ls asyncAccept(addr)
            if(c and(c isError not),
                conn := Conn new(c)
                conn atPut("outbound_transport", self)
                conns append(conn)
                busy = true
            ,
                accepting = false)
        )
        // service every connection; drain ALL available frames (throughput — T2.1).
        alive := List clone
        conns foreach(conn,
            sock := conn at("sock")
            if(sock isOpen not, continue)
            // drain pending outbound FIRST (backpressure, non-blocking) — a conn
            // whose peer stopped reading buffers here without stalling the loop
            if(_flushWrites(conn) not, continue)   // closed / over-cap → drop
            sock asyncStreamRead(conn at("rbuf"), 262144)
            if(sock isOpen not, continue)
            frames := drainFrames(conn)
            if(conn at("overlimit") == true, sock close; continue)   // §4.10(a) over-limit
            if(frames size > 0,
                busy = true
                conn atPut("idle", Date clone now asNumber)   // last-active wall-clock
                frames foreach(payload,
                    if(sock isOpen not, break)
                    _serviceFrame(conn, payload))
            ,
                // no inbound frame. A connection with buffered OUTPUT is still
                // active — keep it and keep the loop hot so its response flushes.
                if(conn at("wbuf") size > 0,
                    busy = true; conn atPut("idle", Date clone now asNumber)
                ,
                    // Reap only a connection idle for a WALL-CLOCK window (§4.9(b)
                    // — bound the poll list against a half-closed/abandoned socket
                    // that reads nil forever) — NEVER by poll-pass count, which
                    // reaps an active connection paused between requests (the
                    // A-IO-024 5-security-FAIL trap).
                    if((Date clone now asNumber) - conn at("idle") > 60, sock close)
                )
            )
            if(sock isOpen, alive append(conn))
        )
        setConns(alive)
        busy
    )
)

// ══════════════════════ initiator (dialer + §4.1 handshake) ══════════════════════
// A blocking-poll initiator for the S3 two-peer smoke / any A-role.
Session := Object clone do(
    ident ::= nil
    sock ::= nil
    rbuf ::= nil
    reqCounter ::= 0
    remotePeerId ::= nil
    capability ::= nil
    granterPeer ::= nil
    capSignature ::= nil

    dial := method(ident, host, port,
        s := self clone setIdent(ident) setRbuf(Sequence clone)
        sk := Socket clone setHost(host) setPort(port)
        deadline := Date clone now asNumber + 5
        connected := false
        while(Date clone now asNumber < deadline,
            r := sk connect
            if(r isError not, connected = true; break)
            System sleep(0.05)
        )
        if(connected not, Exception raise("dial: connect failed"))
        s setSock(sk)
        s handshake
        s
    )

    _nextRid := method(setReqCounter(reqCounter + 1); "req-" .. reqCounter)

    _takeOneFrame := method(
        if(rbuf size < 4, return nil)
        len := ((rbuf at(0)) * 16777216) + ((rbuf at(1)) * 65536) + ((rbuf at(2)) * 256) + (rbuf at(3))
        if(rbuf size < 4 + len, return nil)
        payload := rbuf exSlice(4, 4 + len)
        rbuf removeSlice(0, 4 + len - 1)
        payload
    )

    _readFrameBlocking := method(
        deadline := Date clone now asNumber + 30
        loop(
            payload := _takeOneFrame
            if(payload != nil, return payload)
            if(sock isOpen not, return nil)
            if(Date clone now asNumber > deadline, return nil)
            sock asyncStreamRead(rbuf, 65536)
            System sleep(0.0005)
        )
    )

    _send := method(reqEnv,
        out := Wire frameOfEnvelope(reqEnv) asMutable
        while(out size > 0, if(sock isOpen not, return nil); sock asyncStreamWrite(out, 0, out size); if(out size > 0, System sleep(0.0005)))
        payload := _readFrameBlocking
        if(payload == nil, return nil)
        Wire envelopeOfFrame(payload)
    )

    _authIncluded := method(exec,
        execSig := ident sign(exec)
        list(capability, granterPeer, ident peerEntity, capSignature, execSig)
    )

    execute := method(uri, operation, params, resource,
        exec := Wire makeExecute(_nextRid, uri, operation, params, ident idHash, capability hash, resource)
        _send(Envelope with(exec, _authIncluded(exec)))
    )

    _requireOk := method(env, step,
        if(env == nil, Exception raise(step .. " failed: no response"))
        if(Wire responseStatus(env) != 200,
            r := Wire responseResult(env)
            code := if(r != nil, r text("code"), "?")
            Exception raise(step .. " failed: " .. Wire responseStatus(env) .. " " .. code))
    )

    handshake := method(
        hello := Entity with("system/protocol/connect/hello", EcMap with(
            "peer_id", ident peerId, "nonce", EcBytes with(EntityCodec randomBytes(32)),
            "protocols", list("entity-core/1.0" asSymbol), "timestamp", Capability nowMs,
            "hash_formats", list("ecfv1-sha256" asSymbol), "key_types", list("ed25519" asSymbol)))
        r1 := _send(Envelope with(Wire makeExecute(_nextRid, "system/protocol/connect", "hello", hello, nil, nil, nil), List clone))
        _requireOk(r1, "hello")
        remoteHello := Wire responseResult(r1)
        setRemotePeerId(remoteHello text("peer_id"))
        remoteNonce := remoteHello bytes("nonce")
        if(remoteNonce == nil, Exception raise("hello: missing remote nonce"))
        auth := Entity with("system/protocol/connect/authenticate", EcMap with(
            "peer_id", ident peerId, "public_key", EcBytes with(ident pub),
            "key_type", "ed25519", "nonce", EcBytes with(remoteNonce)))
        authSig := ident sign(auth)
        r2 := _send(Envelope with(Wire makeExecute(_nextRid, "system/protocol/connect", "authenticate", auth, nil, nil, nil),
            list(ident peerEntity, authSig)))
        _requireOk(r2, "authenticate")
        grant := Wire responseResult(r2)
        tokenH := if(grant != nil, grant bytes("token"), nil)
        token := if(tokenH != nil, r2 includedGet(tokenH), nil)
        if(token == nil, Exception raise("authenticate grant omits the capability token"))
        granterH := token bytes("granter")
        gp := if(granterH != nil, r2 includedGet(granterH), nil)
        if(gp == nil, Exception raise("authenticate grant omits the granter identity"))
        capSig := Capability findSignature(token hash, r2 included)
        if(capSig == nil, Exception raise("authenticate grant omits the capability signature"))
        setCapability(token); setGranterPeer(gp); setCapSignature(capSig)
    )

    close := method(try(sock close))
)
