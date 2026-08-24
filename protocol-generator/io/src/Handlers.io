// entity-core-protocol-io — the MUST system handlers (§6.2) + §7a conformance
// handlers, rendered in the PROTOTYPE PARADIGM (the probe's payoff):
//
// Handler is the base prototype carrying the "unknown operation -> 501" default.
// Each concrete handler is a CLONE overriding only its op_<operation> methods
// (differential inheritance — it stores only its diffs). Dispatching an
// operation is a MESSAGE SEND resolved against the clone (perform), but GUARDED
// by the declared-op set so inherited Object slots are never wire-reachable
// (A-IO-004/A-IO-007). ctx is a Map {exec, conn, included, callerCap, env}.

Handler := Object clone do(
    peer ::= nil
    ops := list()          // declared operation names (the §6.2 op set)

    // §6.2 dispatch: op must be declared, else 501; then op_<name>(ctx).
    dispatch := method(operation, ctx,
        if(ops contains(operation) not,
            return Outcome err(501, "unsupported_operation", operation))
        self perform("op_" .. operation, ctx)
    )

    // shared helpers
    ok := method(res, inc, Outcome ok(res, inc))
    fail := method(st, code, msg, Outcome err(st, code, msg))
    execOf := method(ctx, ctx at("exec"))
    paramsOf := method(ctx, (ctx at("exec")) entityField("params"))
)

// ── stateless path/resource helpers ──
HandlerUtil := Object clone do(
    execResourceTarget := method(exec,
        r := exec mapField("resource")
        if(r == nil, return nil)
        targets := List clone
        tv := r at("targets")
        if(tv != nil and(tv isKindOf(List)), tv foreach(x, if(x isKindOf(Sequence), targets append(x))))
        if(targets size == 0, nil, targets at(0))
    )

    // §1.4 path validity (no NUL, no empty/./.. segments; abs paths peer-rooted)
    pathFlexOk := method(target,
        if(target containsSeq((0 asCharacter) asString), return false)
        segs0 := target split("/")
        if(target beginsWithSeq("/"),
            if(segs0 size >= 2 and(segs0 at(0) == ""),
                absOk := Capability isPeerId(segs0 at(1))
                body := segs0 slice(1)
            ,
                absOk := false
                body := segs0
            )
        ,
            absOk := true
            body := segs0
        )
        if(absOk not, return false)
        if(body size > 0 and(body last == ""), body = body slice(0, body size - 1))
        good := true
        body foreach(seg, if(seg == "" or(seg == ".") or(seg == ".."), good = false; break))
        good
    )

    isZeroHash := method(seq,
        z := true
        seq foreach(b, if(b != 0, z = false; break))
        z
    )
)

// ══════════════════════ §4.1/§4.6 connect handler ══════════════════════
ConnectHandler := Handler clone do(
    ops := list("hello", "authenticate")

    _negotiationDisjoint := method(params, key, supported,
        if(params == nil, return false)
        v := params field(key)
        if(v == nil, return false)     // absent -> not disjoint
        if(v isKindOf(List) not, return false)
        declared := List clone
        v foreach(x, if(x isKindOf(Sequence), declared append(x asSymbol)))
        declared contains(supported asSymbol) not
    )

    op_hello := method(ctx,
        conn := ctx at("conn")
        exec := execOf(ctx)
        if(conn at("established") == true, return fail(409, "connection_already_established", nil))
        params := exec entityField("params")
        if(_negotiationDisjoint(params, "hash_formats", "ecfv1-sha256"), return fail(400, "incompatible_hash_format", nil))
        if(_negotiationDisjoint(params, "key_types", "ed25519"), return fail(400, "unsupported_key_type", nil))
        if(params != nil, conn atPut("hello_peer_id", params text("peer_id")))
        nonce := EntityCodec randomBytes(32)
        conn atPut("issued_nonce", nonce)
        ok(Entity with("system/protocol/connect/hello", EcMap with(
            "peer_id", peer localPeer,
            "nonce", EcBytes with(nonce),
            "protocols", list("entity-core/1.0" asSymbol),
            "timestamp", Capability nowMs,
            "hash_formats", list("ecfv1-sha256" asSymbol),
            "key_types", list("ed25519" asSymbol))), nil)
    )

    op_authenticate := method(ctx,
        conn := ctx at("conn")
        exec := execOf(ctx)
        included := ctx at("included")
        if(conn at("established") == true, return fail(409, "connection_already_established", nil))
        issuedNonce := conn at("issued_nonce")
        if(issuedNonce == nil, return fail(401, "invalid_nonce", nil))
        auth := exec entityField("params")
        if(auth == nil, return fail(401, "authentication_failed", nil))
        // §4.6 hardening: reject unsupported key_type / non-32-byte pubkey / non-ed25519 peer_id
        ktField := auth text("key_type")
        badKt := (ktField != nil and(ktField != "ed25519"))
        pub := auth bytes("public_key")
        if(badKt not and(pub != nil) and(pub size != 32), badKt = true)
        claimed := auth text("peer_id")
        if(badKt not and(claimed != nil),
            parsed := nil
            pe := try(parsed = EntityCodec peeridParse(claimed))   // try() returns nil/exc, NOT the value
            if(pe == nil and(parsed != nil) and(parsed at(0) != 1), badKt = true)
        )
        if(badKt, return fail(400, "unsupported_key_type", nil))
        // step 1: nonce echo
        echoed := auth bytes("nonce")
        if((echoed != nil and(echoed == issuedNonce)) not, return fail(401, "invalid_nonce", nil))
        if(pub == nil, return fail(401, "authentication_failed", nil))
        // step 2: proof of possession
        sgn := Capability findSignature(auth hash, included)
        sigOk := false
        if(sgn != nil,
            sb := sgn bytes("signature")
            if(sb != nil and(sb size == 64),
                sigOk = EntityCodec ed25519Verify(pub, auth hash, sb))
        )
        if(sigOk not, return fail(401, "authentication_failed", nil))
        // step 3: identity binding
        if(claimed != Identity peerIdOfPubkey(pub), return fail(401, "identity_mismatch", nil))
        helloPid := conn at("hello_peer_id")
        if(helloPid != nil and(helloPid != claimed), return fail(401, "identity_mismatch", nil))
        // success: mint the initial cap (§4.4 / §6.9a)
        remotePeer := Identity peerEntityOfPubkey(pub)
        grants := peer deriveSeedGrants(remotePeer, claimed)
        minted := peer mintToken(remotePeer hash, grants, nil)
        conn atPut("established", true)
        ok(Entity with("system/capability/grant", EcMap with(
            "token", EcBytes with((minted at("token")) hash))),
           peer capIncluded(minted))
    )
)

// ══════════════════════ §6.3 tree handler ══════════════════════
TreeHandler := Handler clone do(
    ops := list("get", "put")

    op_get := method(ctx,
        exec := execOf(ctx)
        local := peer localPeer
        store := peer store
        target := HandlerUtil execResourceTarget(exec)
        // §6.3: absent OR empty-string target → list the local peer's root.
        if(target == nil or(target == ""), return _listing("/" .. local .. "/"))
        // §1.4: a bare "/" is the universal tree root → list peer-id children.
        if(target == "/", return _listing("/"))
        if(HandlerUtil pathFlexOk(target) not, return fail(400, "invalid_path", target))
        // §6.3: trailing "/" → list entries under the prefix.
        if(target endsWithSeq("/"), return _listing(Capability canonicalize(local, target)))
        path := Capability canonicalize(local, target)
        e := store getAt(path)
        if(e == nil, return fail(404, "not_found", path))
        params := exec entityField("params")
        mode := if(params != nil, params text("mode"), nil)
        if(mode == "hash",
            return ok(Entity with("system/hash", EcMap with("hash", EcBytes with(e hash))), nil))
        ok(e, nil)
    )

    op_put := method(ctx,
        exec := execOf(ctx)
        local := peer localPeer
        store := peer store
        target := HandlerUtil execResourceTarget(exec)
        if(target == nil, return fail(400, "ambiguous_resource", "tree: missing resource target"))
        if(HandlerUtil pathFlexOk(target) not, return fail(400, "invalid_path", target))
        path := Capability canonicalize(local, target)
        params := exec entityField("params")
        entity := if(params != nil, params entityField("entity"), nil)
        expected := if(params != nil, params bytes("expected_hash"), nil)
        current := store hashAt(path)
        casOk := if(expected == nil,
            true
        ,
            if(HandlerUtil isZeroHash(expected),
                current == nil
            ,
                current != nil and(current == EntityCodec hexEncode(expected) asSymbol)
            )
        )
        if(casOk not, return fail(409, "hash_mismatch", path))
        if(entity == nil, return fail(400, "unexpected_params", "put: missing entity"))
        store bind(path, entity)
        ok(Entity with("system/hash", EcMap with("hash", EcBytes with(entity hash))), nil)
    )

    _listing := method(path,
        store := peer store
        rows := List clone
        store listing(path) foreach(row,
            hx := row at(1)
            hasChildren := row at(2)
            if(hx != nil and(hasChildren not) and(_isDeletionMarker(EntityCodec hexDecode(hx))), continue)
            rows append(row)
        )
        entries := EcMap clone
        rows foreach(row,
            seg := row at(0)
            hx := row at(1)
            hasChildren := row at(2)
            d := if(hx != nil,
                EcMap with("has_children", hasChildren, "hash", EcBytes with(EntityCodec hexDecode(hx))),
                EcMap with("has_children", hasChildren))
            le := Entity with("system/tree/listing-entry", d)
            entries atPut(seg asSymbol, le toWire)
        )
        ok(Entity with("system/tree/listing", EcMap with(
            "path", path asSymbol,
            "entries", entries,
            "count", rows size,
            "offset", 0)), nil)
    )

    _isDeletionMarker := method(hashSeq,
        e := peer store getByHash(hashSeq)
        e != nil and(e entityType == "system/deletion-marker")
    )
)

// ══════════════════════ §6.2/§6.13(a) handlers handler ══════════════════════
HandlersHandler := Handler clone do(
    ops := list("register", "unregister")

    _registerPattern := method(exec,
        target := HandlerUtil execResourceTarget(exec)
        if(target == nil, return nil)
        prefix := "system/handler/"
        if(target beginsWithSeq(prefix) not or(target size == prefix size), return nil)
        target exSlice(prefix size)
    )
    _patternError := method(exec,
        if(HandlerUtil execResourceTarget(exec) == nil,
            fail(400, "ambiguous_resource", "register/unregister require exactly one resource target")
        ,
            fail(400, "invalid_resource", "resource target MUST be system/handler/{pattern}"))
    )

    op_register := method(ctx,
        exec := execOf(ctx)
        store := peer store
        pattern := _registerPattern(exec)
        if(pattern == nil, return _patternError(exec))
        req := exec entityField("params")
        if(req == nil, return fail(400, "unexpected_params", "register: missing params"))
        if(req entityType != "system/handler/register-request",
            return fail(400, "unexpected_params", "register expects register-request, got " .. req entityType))
        manifest := req mapField("manifest")
        name := if(manifest != nil, (Entity with("x", manifest)) text("name"), nil)
        if(name == nil, name = pattern)
        operations := if(manifest != nil, (manifest at("operations")), nil)
        if(operations == nil, operations = EcMap clone)
        exprPath := if(manifest != nil, (Entity with("x", manifest)) text("expression_path"), nil)
        internalScope := if(manifest != nil, manifest at("internal_scope"), nil)
        grantScope := req listField("requested_scope")
        if(grantScope == nil and(internalScope != nil) and(internalScope isKindOf(List)), grantScope = internalScope)
        if(grantScope == nil, grantScope = List clone)
        interfaceRel := "system/handler/" .. pattern
        // (1) handler manifest at the pattern path
        hp := EcMap with("interface", interfaceRel asSymbol)
        if(exprPath != nil, hp atPut("expression_path", exprPath))
        if(internalScope != nil, hp atPut("internal_scope", internalScope))
        store bind(peer abs(pattern), Entity with("system/handler", hp))
        // (2) associated types
        types := req mapField("types")
        if(types != nil,
            types foreachEntry(tk, tv,
                if(tk isKindOf(Sequence),
                    td := if(tv hasSlot("ecKind") and(tv ecKind == "map"), tv, EcMap with("def", tv))
                    store bind(peer abs("system/type/" .. tk), Entity with("system/type", td))
                )
            )
        )
        // (3) self-issued signed handler grant + (4) grant-signature at §3.5
        minted := peer mintToken(peer idHash, grantScope, nil)
        store bind(peer abs("system/capability/grants/" .. pattern), minted at("token"))
        store bind(peer abs("system/signature/" .. (minted at("token")) hashHex), minted at("signature"))
        // (5) handler interface entity (discovery index)
        store bind(peer abs(interfaceRel), Entity with("system/handler/interface", EcMap with(
            "pattern", pattern asSymbol, "name", name, "operations", operations)))
        // wire the runtime handler slot so the paradigm dispatch reaches it
        peer registerRuntimeHandler(pattern)
        ok(Entity with("system/handler/register-result", EcMap with(
            "pattern", pattern asSymbol, "grant", (minted at("token")) data)), nil)
    )

    op_unregister := method(ctx,
        exec := execOf(ctx)
        store := peer store
        pattern := _registerPattern(exec)
        if(pattern == nil, return _patternError(exec))
        g := store getAt(peer abs("system/capability/grants/" .. pattern))
        if(g != nil,
            store unbind(peer abs("system/signature/" .. g hashHex))
            store unbind(peer abs("system/capability/grants/" .. pattern))
        )
        store unbind(peer abs(pattern))
        store unbind(peer abs("system/handler/" .. pattern))
        ok(Wire emptyParams, nil)
    )
)

// ══════════════════════ system/type:validate handler ══════════════════════
TypeHandler := Handler clone do(
    ops := list("validate")

    op_validate := method(ctx,
        store := peer store
        req := paramsOf(ctx)
        if(req == nil, return fail(400, "invalid_params", "validate requires a params entity"))
        subject := req entityField("entity")
        if(subject == nil, return fail(400, "unexpected_params", "validate-request missing entity"))
        typeName := req text("type_name")
        if(typeName == nil, typeName = subject entityType)
        typeDef := store getAt(peer abs("system/type/" .. typeName))
        if(typeDef == nil,
            return ok(Entity with("system/type/validate-result", EcMap with(
                "valid", false,
                "errors", list(("no registered type definition for " .. typeName) asSymbol))), nil))
        fields := typeDef mapField("fields")
        errors := List clone
        if(fields != nil,
            fields foreachEntry(fk, fv,
                if(fk isKindOf(Sequence),
                    optional := (fv hasSlot("ecKind")) and(fv ecKind == "map") and(fv at("optional") == true)
                    present := subject dataMap hasKey(fk)
                    if(optional not and(present not),
                        errors append(("missing required field: " .. fk) asSymbol))
                )
            )
        )
        valid := errors size == 0
        d := EcMap with("valid", valid)
        if(valid not, d atPut("errors", errors))
        ok(Entity with("system/type/validate-result", d), nil)
    )
)

// ══════════════════════ §6.2 capability handler ══════════════════════
CapabilityHandler := Handler clone do(
    ops := list("request", "delegate", "revoke", "configure")

    _reqGrants := method(params,
        if(params == nil, return List clone)
        gl := params listField("grants")
        if(gl == nil, List clone, gl)
    )

    op_request := method(ctx,
        params := paramsOf(ctx)
        author := (execOf(ctx)) bytes("author")
        if(author == nil, return fail(403, "capability_denied", nil))
        _mintBounded(ctx at("callerCap"), _reqGrants(params), author, nil)
    )

    op_delegate := method(ctx,
        params := paramsOf(ctx)
        author := (execOf(ctx)) bytes("author")
        ph := if(params != nil, params bytes("parent"), nil)
        if(ph == nil, return fail(400, "unexpected_params", "delegate: parent required"))
        if(HandlerUtil isZeroHash(ph), return fail(400, "unexpected_params", "delegate: zero parent"))
        if((author != nil and(peer idHash == author)) not,
            return fail(501, "unsupported_operation", "delegate: same-peer-only in v1"))
        _mintBounded(ctx at("callerCap"), _reqGrants(params), author, ph)
    )

    op_revoke := method(ctx,
        params := paramsOf(ctx)
        store := peer store
        tokenH := if(params != nil, params bytes("token"), nil)
        if(tokenH == nil, return fail(400, "unexpected_params", "revoke: missing token"))
        if(HandlerUtil isZeroHash(tokenH), return fail(400, "unexpected_params", "revoke: zero token"))
        marker := Entity with("system/capability/revocation", EcMap with(
            "token", EcBytes with(tokenH), "revoked_at", Capability nowMs))
        store bind("/" .. peer localPeer .. "/system/capability/revocations/" .. EntityCodec hexEncode(tokenH), marker)
        ok(Wire emptyParams, nil)
    )

    op_configure := method(ctx,
        params := paramsOf(ctx)
        store := peer store
        pp := if(params != nil, params text("peer_pattern"), nil)
        if(pp == nil, return fail(400, "unexpected_params", "configure: missing peer_pattern"))
        isHex := (pp size == 66) and(_isLowerHex(pp))
        if((pp == "default" or(isHex) or(Capability isPeerId(pp))) not,
            return fail(400, "invalid_peer_pattern", pp))
        store bind("/" .. peer localPeer .. "/system/capability/policy/" .. pp, params)
        ok(Wire emptyParams, nil)
    )

    _isLowerHex := method(s,
        ok := true
        s foreach(code,
            c := code asCharacter
            if(("0123456789abcdef" findSeq(c)) == nil, ok = false; break))
        ok
    )

    _mintBounded := method(callerCap, reqGrants, granteeHash, parent,
        local := peer localPeer
        bounded := false
        if(callerCap != nil,
            parentGrants := Capability grantsOfToken(callerCap)
            bounded = true
            reqGrants foreach(cgRaw,
                c := Capability parseGrant(cgRaw)
                covered := false
                parentGrants foreach(pg,
                    if(Capability grantSubset(local, local, local, c, pg), covered = true; break))
                if(covered not, bounded = false; break)
            )
        )
        if(bounded not, return fail(403, "scope_exceeds_authority", nil))
        minted := peer mintToken(granteeHash, reqGrants, parent)
        ok(Entity with("system/capability/grant", EcMap with(
            "token", EcBytes with((minted at("token")) hash))),
           peer capIncluded(minted))
    )
)

// ══════════════════════ §7a conformance handlers (--validate only) ══════════════════════
EchoHandler := Handler clone do(
    ops := list("echo")
    op_echo := method(ctx,
        p := paramsOf(ctx)
        if(p == nil, return fail(400, "invalid_params", "echo requires params"))
        ok(p, nil)
    )
)

DispatchOutboundHandler := Handler clone do(
    ops := list("dispatch")
    op_dispatch := method(ctx,
        p := paramsOf(ctx)
        if(p == nil, return fail(400, "invalid_params", "dispatch-outbound requires a params entity"))
        target := p text("target")
        op := p text("operation")
        value := p field("value")
        cap := p entityField("reentry_capability")
        granter := p entityField("reentry_granter")
        capSig := p entityField("reentry_cap_signature")
        if((value != nil and(cap != nil) and(granter != nil) and(capSig != nil)) not,
            return fail(400, "invalid_params", "dispatch-outbound requires value + reentry authority"))
        // §7a.1 generic relay: forward `value` VERBATIM as the downstream params data
        innerData := if(value hasSlot("ecKind") and(value ecKind == "map"), value, EcMap with("value", value))
        inner := Entity with("primitive/any", innerData)
        resource := EcMap with("targets", list(("system/handler/" .. target) asSymbol))
        resp := peer outboundDispatch(ctx at("conn"), target, op, inner, cap, granter, capSig, resource)
        if(resp == nil, return fail(503, "no_outbound_seam", "no live §6.11 reentry connection"))
        root := resp root
        status := root uint("status")
        if(status == nil, status = 0)
        resultCbor := root field("result")
        if(resultCbor == nil, resultCbor = EcMap clone)
        ok(Entity with("primitive/any", EcMap with("status", status, "result", resultCbor)), nil)
    )
)
