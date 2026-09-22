// entity-core-protocol-io — peer assembly: bootstrap (§6.9 / §6.9a), the MUST
// system handlers (§6.2), the §6.5 dispatch chain, §6.6 resolution (the
// prototype-network delegation walk in Store), and the §6.9a seed policy.
//
// The pure protocol brain: dispatch is a function from an inbound envelope to an
// outbound response envelope; transport lives in Transport.io. Each handler is a
// Handler clone; the runtime handler map (pattern -> instance) mirrors the
// dispatch-node network the store maintains for §6.6.

Peer := Object clone do(
    identity ::= nil
    store ::= nil
    localPeer ::= nil       // Base58 peer_id text
    openGrants ::= false
    conformance ::= false
    runtimeHandlers ::= nil // Map: pattern (no leading /peer) -> Handler instance

    idHash := method(identity idHash)
    abs := method(rel, "/" .. localPeer .. "/" .. rel)

    create := method(seed, open, conf,
        p := self clone
        p setIdentity(Identity ofSeed(seed))
        p setStore(Store clone)
        p setLocalPeer(p identity peerId)
        p setOpenGrants(if(open == nil, false, open))
        p setConformance(if(conf == nil, false, conf))
        p setRuntimeHandlers(Map clone)
        p bootstrap
        p
    )

    createFromIdentity := method(ident, open, conf,
        p := self clone
        p setIdentity(ident)
        p setStore(Store clone)
        p setLocalPeer(ident peerId)
        p setOpenGrants(if(open == nil, false, open))
        p setConformance(if(conf == nil, false, conf))
        p setRuntimeHandlers(Map clone)
        p bootstrap
        p
    )

    getHandler := method(pattern, runtimeHandlers at(pattern))
    registerRuntimeHandler := method(pattern,
        // entity-native / community handlers registered via §6.13(a): the tree
        // binding + dispatch-node already exist; a generic EntityNativeHandler
        // clone routes op dispatch through the stored expression (501 for the
        // core peer's stub-free surface).
        if(runtimeHandlers hasKey(pattern) not,
            h := EntityNativeHandler clone setPeer(self) setPattern(pattern)
            runtimeHandlers atPut(pattern, h))
        self
    )

    // ── grant construction (§4.4 / §5.4) ──
    _discoveryFloor := method(
        list(
            Capability grant(list("system/tree" asSymbol),
                             list("system/type/*" asSymbol, "system/handler/*" asSymbol),
                             list("get" asSymbol), nil),
            Capability grant(list("system/capability" asSymbol), list(), list("request" asSymbol), nil))
    )
    // A-PD-017: the open/debug seed needs resources ["*", "/*/*"] — bare star is
    // granter-local, never universal.
    _openGrantsScope := method(
        list(Capability grant(list("*" asSymbol),
                              list("*" asSymbol, "/*/*" asSymbol),
                              list("*" asSymbol),
                              list("*" asSymbol)))
    )
    _ownerGrants := method(
        list(Capability grant(list("*" asSymbol), list("*" asSymbol, "/*/*" asSymbol),
                              list("*" asSymbol), list(localPeer)))
    )

    // ── token mint (§4.4 / §6.9a). created_at in TRUE ms (A-PD-016). ──
    // mintTokenAt at the current instant with no §5.6 ceiling. Used by the paths that
    // mint a self-issued grant from local authority (bootstrap, handler registration,
    // the §4.4 handshake), where no MIN_DEFINED term is in play.
    mintToken := method(granteeHash, grants, parent,
        mintTokenAt(Capability nowMs, granteeHash, grants, parent, nil)
    )

    // Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
    //
    // expiresAt nil means no term was defined and the token genuinely has no expiry (the
    // ONLY "no bound" spelling). A non-nil value is emitted verbatim — including one
    // equal to createdAt, which §5.6 rule 2 requires for ttl_ms == 0 and which means
    // "already expired at every observable instant", not "unbounded".
    //
    // createdAt is supplied rather than sampled here so a computed expiry is guaranteed
    // to be relative to the SAME instant that lands in the token; sampling the clock
    // twice skews the two.
    mintTokenAt := method(createdAt, granteeHash, grants, parent, expiresAt,
        kv := EcMap with(
            "granter", EcBytes with(idHash),
            "grantee", EcBytes with(granteeHash),
            "grants", grants,
            "created_at", createdAt)
        if(expiresAt != nil, kv atPut("expires_at", expiresAt))
        if(parent != nil, kv atPut("parent", EcBytes with(parent)))
        token := Entity with("system/capability/token", kv)
        Map clone atPut("token", token) atPut("signature", identity sign(token))
    )

    capIncluded := method(minted,
        list(
            minted at("token"),
            identity peerEntity,
            minted at("signature"))
    )

    // ── §6.9a seed policy (authenticate-time derivation) ──
    _seedEntryGrants := method(e,
        t := e entityType
        if(t == "system/capability/token",
            sigPath := "/" .. localPeer .. "/system/signature/" .. e hashHex
            sgn := store getAt(sigPath)
            if(sgn != nil and(Identity verifySignature(sgn, identity peerEntity)),
                gl := e listField("grants")
                return if(gl == nil, List clone, gl))
            return List clone
        )
        if(t == "system/capability/policy-entry",
            gl := e listField("grants")
            return if(gl == nil, List clone, gl)
        )
        List clone
    )

    // dual-form lookup (hex -> Base58 -> default), UNION with the §4.4 floor.
    deriveSeedGrants := method(remotePeer, remotePeerId,
        base := "/" .. localPeer .. "/system/capability/policy/"
        entry := store getAt(base .. remotePeer hashHex)
        if(entry == nil, entry = store getAt(base .. remotePeerId))
        if(entry == nil, entry = store getAt(base .. "default"))
        floor := _discoveryFloor
        if(entry == nil, return floor)
        policy := _seedEntryGrants(entry)
        if(policy size == 0, return floor)
        floor appendSeq(policy)
    )

    // ── §6.13(b) handler-facing outbound dispatch (§6.11 reentry) ──
    // The transport wires conn "outbound_transport" to itself; the peer builds +
    // signs the outbound EXECUTE and hands it to the transport's reentry method,
    // which does the bounded synchronous send+wait on the SAME fd.
    outboundDispatch := method(conn, uri, operation, params, capability, granterPeer, capSig, resource,
        transport := conn at("outbound_transport")
        if(transport == nil, return nil)
        requestId := "out-" .. conn at("out_counter")
        conn atPut("out_counter", conn at("out_counter") + 1)
        exec := Wire makeExecute(requestId, uri, operation, params,
            idHash, capability hash, resource)
        execSig := identity sign(exec)
        included := list(capability, granterPeer, identity peerEntity, capSig, execSig)
        transport reentry(conn, Envelope with(exec, included), requestId)
    )

    // ── dispatcher-level signature ingestion (§6.5) ──
    // §6.5's narrow scope: bind signatures so a handler can find them by tree
    // lookup at the invariant-pointer path. The EXECUTE's OWN request signature
    // (target == the root EXECUTE hash) is consumed inline by verify_request and
    // is never looked up post-dispatch — binding one per request would grow the
    // store unboundedly under sustained load (thousands of live entities → GC
    // thrash → the later-category timeout wall, A-IO-022). Skip it; still ingest
    // cap / identity / handshake signatures that downstream verification finds.
    _ingestSignatures := method(env,
        execHash := env root hash
        env included foreach(e,
            if(e entityType != "system/signature", continue)
            target := e bytes("target")
            if(target != nil and(target == execHash), continue)   // transient request sig
            store putEntity(e)
            signerH := e bytes("signer")
            if(signerH == nil, continue)
            signerPeer := env includedGet(signerH)
            if(signerPeer == nil, continue)
            store putEntity(signerPeer)
            pk := signerPeer bytes("public_key")
            if(target != nil and(pk != nil),
                pid := Identity peerIdOfPubkey(pk)
                store bind("/" .. pid .. "/system/signature/" .. EntityCodec hexEncode(target), e))
        )
    )

    _stripLocal := method(pattern,
        prefix := "/" .. localPeer .. "/"
        if(pattern beginsWithSeq(prefix), pattern exSlice(prefix size), pattern)
    )

    // ── dispatch chain (§6.5) → EXECUTE_RESPONSE envelope, or nil for non-EXECUTE ──
    // NO per-request `try` (A-IO-025): the whole path is total — verifyRequest
    // returns verdicts, canonicalize/fromWire return sentinels — so a valid
    // request never spawns a `try` Coroutine (the concurrency-throughput leak).
    dispatch := method(conn, env,
        exec := env root
        if(exec entityType != "system/protocol/execute",
            // §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
            // invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare
            // close -- that is indistinguishable from a network fault."
            //
            // §3.3 read "the connection MUST be closed", assigning no code and
            // requiring no frame, and §9.1's floor row that MANDATED the bare close
            // was REPLACED at the same revision (N18). This peer did something weaker
            // still: it returned nil, the transport wrote NOTHING, and the connection
            // stayed open -- which is §4.11's OTHER non-conformant behaviour, the
            // silent drop, "the weaker of the two precisely because nothing surfaces
            // it". This is a PRE-ADMISSION refusal: the root is not an EXECUTE, so
            // nothing was ever admitted and §4.9(c) does not reach it.
            //
            // The request_id is read best-effort -- an arbitrary root type is under no
            // obligation to carry one, and §4.11 licenses the uncorrelated frame
            // exactly there. We do NOT close: on a multiplexed connection that would
            // cost every ADMITTED in-flight request its response, and §4.11 leaves the
            // close to us.
            r := Wire preAdmissionRefusal("non_execute_root")
            rid := exec text("request_id")
            return Envelope with(Wire makeResponse(if(rid == nil, "", rid), r at(0),
                Wire errorResult(r at(1), "root entity is neither EXECUTE nor EXECUTE_RESPONSE")))
        )
        requestId := exec text("request_id")
        outcome := _dispatchInner(conn, env, exec)
        Envelope with(Wire makeResponse(requestId, outcome status, outcome result), outcome included)
    )

    _dispatchInner := method(conn, env, exec,
        uri := exec text("uri")
        operation := exec text("operation")
        included := env included
        if(uri == "system/protocol/connect",
            h := runtimeHandlers at("system/protocol/connect")
            // handlerPattern is nil on the unauthenticated connect path, which has
            // no resolved handler entity (§6.3's check is fail-closed there by
            // construction -- there is no caller capability either).
            return h dispatch(operation, Map clone \
                atPut("exec", exec) atPut("conn", conn) atPut("included", included) \
                atPut("callerCap", nil) atPut("env", env) atPut("handlerPattern", nil))
        )
        // §1.4 a reserved (./ ../ */) or empty request path is a malformed request
        if(uri == nil or(Capability isReservedPath(Capability normalizeUri(uri))),
            return Outcome err(400, "non_canonical_ecf", nil))
        _ingestSignatures(env)
        // §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
        // sit below the §5.2 verdict, so a pre-establishment EXECUTE naming a FOREIGN namespace
        // took the 401 an unauthenticated request takes. §4.7's own reason: "a 401 directs the
        // caller to authenticate and retry, and for a foreign-namespace address that retry
        // cannot succeed at any authentication state — so the 401 names a remedy that does not
        // exist." §6.5 step 3 calls it "a gate, not an ordering preference".
        path := Capability canonicalize(localPeer, Capability normalizeUri(uri))
        if(Capability extractPeer(localPeer, path) != localPeer,
            return Outcome err(400, "invalid_request", "not local peer"))
        rv := Capability verifyRequest(localPeer, store, env)
        if(rv == "AUTHN_FAIL", return Outcome err(401, "authentication_failed", nil))
        if(rv == "UNRESOLVABLE_GRANTEE", return Outcome err(401, "unresolvable_grantee", nil))  // §5.2/PR-3 carve-out
        if(rv == "AUTHZ_DENY", return Outcome err(403, "capability_denied", nil))
        if(rv == "CHAIN_TOO_DEEP", return Outcome err(400, "chain_depth_exceeded", nil))
        // (The §1.4 address gate that used to sit here has moved ABOVE the verdict — §4.7
        // 0.8.2.6 orders it before authentication. Reaching this line means the path is local.)
        pattern := store resolveHandlerPattern(path)
        if(pattern == nil, return Outcome err(404, "handler_not_found", path))
        capH := exec bytes("capability")
        callerCap := if(capH != nil, env includedGet(capH), nil)
        if(callerCap == nil, return Outcome err(403, "capability_denied", nil))
        granterPeer := Capability resolveGranterPeerId(callerCap, included, store)
        if(granterPeer == nil, granterPeer = localPeer)
        if(Capability checkPermission(localPeer, granterPeer, exec, callerCap, pattern) == "DENY",
            return Outcome err(403, "capability_denied", nil))
        stripped := _stripLocal(pattern)
        h := runtimeHandlers at(stripped)
        if(h == nil, return Outcome err(404, "handler_not_found", pattern))
        // handlerPattern is CARRIED, never recomputed: §6.3's path check needs the
        // handler pattern and the caller's capability, and this dispatch-level check
        // has already computed both. Recomputing invites the two to drift, and §6.8 is
        // explicit that the authority is selected by who named the path. It is the
        // OWNING handler's pattern (§6.3, 0.8.2.23) -- for the tree handler owner and
        // runner coincide, so the distinction is not observable here, but the field is
        // named for the owner.
        h dispatch(operation, Map clone \
            atPut("exec", exec) atPut("conn", conn) atPut("included", included) \
            atPut("callerCap", callerCap) atPut("env", env) atPut("handlerPattern", pattern))
    )

    // ── bootstrap (§6.9) ──
    _bindHandlerEntities := method(pattern, name, ops,
        operations := EcMap clone
        ops foreach(op,
            spec := EcMap clone
            if(op at(1) != nil, spec atPut("input_type", op at(1)))
            if(op at(2) != nil, spec atPut("output_type", op at(2)))
            operations atPut((op at(0)) asSymbol, spec)
        )
        store bind(abs(pattern), Entity with("system/handler",
            EcMap with("interface", ("system/handler/" .. pattern) asSymbol)))
        store bind(abs("system/handler/" .. pattern), Entity with("system/handler/interface",
            EcMap with("pattern", pattern asSymbol, "name", name, "operations", operations)))
        minted := mintToken(idHash, List clone, nil)
        store bind(abs("system/capability/grants/" .. pattern), minted at("token"))
    )

    bootstrap := method(
        // local identity entity in the store (root-granter resolution)
        store putEntity(identity peerEntity)
        // publish the §9.5 core type floor
        CoreTypes publish(store, localPeer)

        // instantiate + register the MUST handler instances
        _install("system/tree", TreeHandler, "Tree",
            list(list("get", nil, nil), list("put", nil, nil)))
        _install("system/handler", HandlersHandler, "Handlers",
            list(list("register", "system/handler/register-request", "system/handler/register-result"),
                 list("unregister", "system/handler/unregister-request", nil)))
        _install("system/type", TypeHandler, "Types",
            list(list("validate", "system/type/validate-request", "system/type/validate-result")))
        _install("system/capability", CapabilityHandler, "Capability",
            list(list("request", "system/capability/request", "system/capability/grant"),
                 list("revoke", "system/capability/revoke-request", nil),
                 list("configure", "system/capability/policy-entry", nil),
                 list("delegate", "system/capability/delegate-request", "system/capability/grant")))
        _install("system/protocol/connect", ConnectHandler, "Connect",
            list(list("hello", nil, nil), list("authenticate", nil, nil)))

        // §6.9a Peer Authority Bootstrap: self-owner cap + default scope-template
        policyBase := "/" .. localPeer .. "/system/capability/policy/"
        owner := mintToken(idHash, _ownerGrants, nil)
        store bind(policyBase .. EntityCodec hexEncode(idHash), owner at("token"))
        store bind("/" .. localPeer .. "/system/signature/" .. (owner at("token")) hashHex, owner at("signature"))
        defaultGrants := if(openGrants, _openGrantsScope, _discoveryFloor)
        store bind(policyBase .. "default", Entity with("system/capability/policy-entry", EcMap with(
            "peer_pattern", "default", "grants", defaultGrants)))

        // §7a conformance handlers — only under --validate
        if(conformance,
            _install("system/validate/echo", EchoHandler, "validate-echo",
                list(list("echo", nil, nil)))
            _install("system/validate/dispatch-outbound", DispatchOutboundHandler, "validate-dispatch-outbound",
                list(list("dispatch", nil, nil)))
        )
        self
    )

    _install := method(pattern, proto, name, ops,
        runtimeHandlers atPut(pattern, proto clone setPeer(self))
        _bindHandlerEntities(pattern, name, ops)
        self
    )
)

// entity-native / community handler (§6.13(a)): the stored expression drives
// dispatch. The core peer ships no expressions, so this resolves compute/literal
// (the minimal entity-native body) and 501s the rest — the substrate is LIVE
// (register+dispatch round-trips), which is the §6.13(a) behavioral contract.
EntityNativeHandler := Handler clone do(
    pattern ::= nil
    dispatch := method(operation, ctx,
        store := peer store
        hp := peer abs(pattern)
        he := store getAt(hp)
        if(he == nil, return Outcome err(404, "handler_not_found", hp))
        exprPath := he text("expression_path")
        if(exprPath == nil, return Outcome err(501, "no_handler_body", hp))
        absExpr := Capability canonicalize(peer localPeer, exprPath)
        expr := store getAt(absExpr)
        if(expr == nil, return Outcome err(404, "expression_not_found", absExpr))
        if(expr entityType == "compute/literal",
            value := expr field("value")
            if(value == nil, return Outcome err(400, "unexpected_params", "compute/literal missing value"))
            return Outcome ok(Entity with("compute/result", EcMap with(
                "value", value, "expression", EcBytes with(expr hash))), nil)
        )
        Outcome err(501, "unsupported_expression", expr entityType)
    )
)
