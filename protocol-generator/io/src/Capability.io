// entity-core-protocol-io — capability system (L3): the §5 verification core.
// Pattern matching (§5.4), request verification (§5.2), delegation-chain
// verification (§5.5), attenuation (§5.6), caveats (§5.7), revocation (§5.1),
// and genuine §3.6 M3 multi-signature K-of-N. Derived from the §5 pseudocode.
//
// Verdict is a symbol; verify_request is 4-way ALLOW/AUTHN_FAIL/AUTHZ_DENY/
// CHAIN_TOO_DEEP (folding §4.10(b)); the §5.5 unresolvable-grantee carve-out
// surfaces its own UNRESOLVABLE_GRANTEE. §PR-8/§5.5a: the RESOURCE dimension
// canonicalizes against the GRANTER's peer_id; other dimensions on the local
// frame. IoNumber is fine for thresholds/timestamps (all << 2^53).
//
// A Scope is a Map {incl <List>, excl <List>} of pattern text Sequences.
// A Grant is a Map {handlers,resources,operations Scope; peers Scope-or-nil}.

Capability := Object clone do(
    maxChainDepth := 64
    base58 := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    nowMs := method(EntityCodec nowMs floor)

    // ── §5.4 canonicalization + pattern matching ──
    normalizeUri := method(uri,
        if(uri beginsWithSeq("entity://"), "/" .. uri exSlice(9), uri)
    )

    // NON-RAISING (A-IO-025): a reserved/ambiguous path is returned UNCHANGED —
    // it cannot match any canonical "/{peer}/..." pattern, so it fails closed
    // without spawning a per-call `try` coroutine (Io's `try` clones a Coroutine
    // — the concurrency-throughput leak). `isReservedPath` gates the explicit
    // 400 at the request boundary (§1.4).
    isReservedPath := method(path,
        path beginsWithSeq("./") or(path beginsWithSeq("../")) or(path beginsWithSeq("*/"))
    )
    canonicalize := method(localPeer, path,
        if(isReservedPath(path), return path)
        if(path beginsWithSeq("/"), path, "/" .. localPeer .. "/" .. path)
    )

    matchesPattern := method(path, pattern,
        if(pattern == "*", return true)
        if(pattern beginsWithSeq("/*/"),
            remainder := pattern exSlice(3)
            if(path size == 0, return false)
            i := path findSeq("/", 1)
            if(i == nil, return false)
            return matchesPattern(path exSlice(i + 1), remainder)
        )
        if(pattern size >= 2 and(pattern endsWithSeq("/*")),
            return path beginsWithSeq(pattern exSlice(0, pattern size - 1))
        )
        path == pattern
    )

    _covered := method(frame, pats, cv,
        c := false
        pats foreach(p, if(matchesPattern(cv, canonicalize(frame, p)), c = true; break))
        c
    )

    matchesScope := method(localPeer, value, scope,
        cv := canonicalize(localPeer, value)
        _covered(localPeer, scope at("incl"), cv) and(_covered(localPeer, scope at("excl"), cv) not)
    )

    // ── scope / grant parse from an EcMap ──
    parseScope := method(m,
        if(m == nil, return Map clone atPut("incl", List clone) atPut("excl", List clone))
        incl := List clone
        excl := List clone
        iv := m at("include")
        if(iv != nil and(iv isKindOf(List)), iv foreach(x, if(x isKindOf(Sequence), incl append(x))))
        ev := m at("exclude")
        if(ev != nil and(ev isKindOf(List)), ev foreach(x, if(x isKindOf(Sequence), excl append(x))))
        Map clone atPut("incl", incl) atPut("excl", excl)
    )

    _ecmapField := method(m, key,
        v := m at(key)
        if(v != nil and(v hasSlot("ecKind")) and(v ecKind == "map"), v, nil)
    )

    parseGrant := method(m,
        peers := nil
        if(m at("peers") != nil, peers = parseScope(_ecmapField(m, "peers")))
        Map clone \
            atPut("handlers", parseScope(_ecmapField(m, "handlers"))) \
            atPut("resources", parseScope(_ecmapField(m, "resources"))) \
            atPut("operations", parseScope(_ecmapField(m, "operations"))) \
            atPut("peers", peers)
    )

    grantsOfToken := method(token,
        out := List clone
        gl := token listField("grants")
        if(gl != nil, gl foreach(g, if(g hasSlot("ecKind") and(g ecKind == "map"), out append(parseGrant(g)))))
        out
    )

    // build a grant EcMap (the §4.4 helper). peers nil -> omit dimension.
    grant := method(handlers, resources, operations, peers,
        g := EcMap with(
            "handlers", Ec scope(handlers),
            "resources", Ec scope(resources),
            "operations", Ec scope(operations))
        if(peers != nil, g atPut("peers", Ec scope(peers)))
        g
    )

    // ── §5.2 helpers ──
    firstSegment := method(uri,
        u := if(uri beginsWithSeq("/"), uri exSlice(1), uri)
        i := u findSeq("/")
        if(i == nil, u, u exSlice(0, i))
    )

    isPeerId := method(seg,
        if(seg size < 46, return false)
        ok := true
        seg foreach(code,
            if(base58 findSeq(code asCharacter) == nil, ok = false; break))
        ok
    )

    extractPeer := method(localPeer, uri,
        f := firstSegment(normalizeUri(uri))
        if(isPeerId(f), f, localPeer)
    )

    checkResourceScope := method(localPeer, granterPeer, resourceMap, scope,
        targets := List clone
        tv := resourceMap at("targets")
        if(tv != nil and(tv isKindOf(List)), tv foreach(x, if(x isKindOf(Sequence), targets append(x))))
        callerExcl := List clone
        ev := resourceMap at("exclude")
        if(ev != nil and(ev isKindOf(List)), ev foreach(x, if(x isKindOf(Sequence), callerExcl append(x))))
        if(targets size == 0, return false)
        good := true
        targets foreach(tgt,
            ct := canonicalize(localPeer, tgt)
            if(callerExcl size > 0 and(_covered(localPeer, callerExcl, ct)),
                nil
            ,
                if(_covered(granterPeer, scope at("incl"), ct) not, good = false; break)
                if(_covered(granterPeer, scope at("excl"), ct), good = false; break)
            )
        )
        good
    )

    // §PR-8: resolve the granter's peer_id (its resource frame), or nil.
    resolveGranterPeerId := method(cap, included, storeObj,
        gh := cap bytes("granter")
        if(gh == nil, return nil)     // multi-granter is a map, not bytes
        g := capResolve(included, storeObj, gh)
        if(g == nil, return nil)
        pk := g bytes("public_key")
        if(pk == nil, return nil)
        Identity peerIdOfPubkey(pk)
    )

    // ── §5.2 check_permission → ALLOW / DENY ──
    checkPermission := method(localPeer, granterPeer, exec, token, handlerPattern,
        operation := exec text("operation")
        uri := exec text("uri")
        targetPeer := extractPeer(localPeer, uri)
        resource := exec mapField("resource")
        verdict := "DENY"
        grantsOfToken(token) foreach(g,
            okg := matchesScope(localPeer, operation, g at("operations")) and(
                   matchesScope(localPeer, handlerPattern, g at("handlers")))
            if(okg,
                peers := g at("peers")
                if(peers == nil, peers = Map clone atPut("incl", list(localPeer)) atPut("excl", List clone))
                okg = matchesScope(localPeer, targetPeer, peers)
            )
            if(okg and(resource != nil),
                okg = checkResourceScope(localPeer, granterPeer, resource, g at("resources"))
            )
            if(okg, verdict = "ALLOW"; break)
        )
        verdict
    )

    // ── §5.5 chain resolution + verification ──
    capResolve := method(included, storeObj, hashSeq,
        included foreach(e, if(e hash == hashSeq, return e))
        storeObj getByHash(hashSeq)
    )

    findSignature := method(target, included,
        included foreach(e,
            if(e entityType == "system/signature" and(e bytes("target") == target) and(target != nil),
                return e))
        nil
    )

    signaturesTargeting := method(target, included,
        out := List clone
        included foreach(e,
            if(e entityType == "system/signature" and(e bytes("target") == target) and(target != nil),
                out append(e)))
        out
    )

    isMultisig := method(cap,
        g := cap field("granter")
        g != nil and(g hasSlot("ecKind")) and(g ecKind == "map")
    )

    multiGranterOf := method(cap,
        m := cap field("granter")
        if(m == nil or((m hasSlot("ecKind")) not) or(m ecKind != "map"), return nil)
        signers := List clone
        arr := m at("signers")
        if(arr != nil and(arr isKindOf(List)),
            arr foreach(s, if(s hasSlot("ecKind") and(s ecKind == "bytes"), signers append(s seq))))
        th := m at("threshold")
        Map clone atPut("signers", signers) atPut("threshold", if(th isKindOf(Number), th, 0))
    )

    _hasDupSigners := method(signers,
        n := signers size
        dup := false
        for(i, 0, n - 1, for(j, i + 1, n - 1,
            if(signers at(i) == signers at(j), dup = true)))
        dup
    )

    _peerIdOfSigner := method(included, storeObj, signerHash,
        p := capResolve(included, storeObj, signerHash)
        if(p == nil, return nil)
        pk := p bytes("public_key")
        if(pk == nil, return nil)
        Identity peerIdOfPubkey(pk)
    )

    _linkGranterPeer := method(included, storeObj, localPeer, cap,
        gh := cap bytes("granter")
        if(gh == nil, return localPeer)   // multi-sig root frame = local
        g := capResolve(included, storeObj, gh)
        if(g == nil, return nil)
        pk := g bytes("public_key")
        if(pk == nil, return nil)
        Identity peerIdOfPubkey(pk)
    )

    // §3.6 M3 / §5.5 M4·M6 multi-sig root validation → true/false
    verifyMultisigRoot := method(localPeer, included, storeObj, cap, mg,
        signers := mg at("signers")
        threshold := mg at("threshold")
        n := signers size
        if(cap bytes("parent") != nil, return false)     // root-only
        if(n < 2, return false)
        if(threshold < 2 or(threshold > n), return false)
        if(_hasDupSigners(signers), return false)
        localIn := false
        signers foreach(s, if(_peerIdOfSigner(included, storeObj, s) == localPeer, localIn = true; break))
        if(localIn not, return false)
        now := nowMs
        nb := cap uint("not_before")
        if(nb != nil and(now < nb), return false)
        ex := cap uint("expires_at")
        if(ex != nil and(ex < now), return false)
        grantee := cap bytes("grantee")
        if(grantee == nil or(capResolve(included, storeObj, grantee) == nil), return false)
        sigs := signaturesTargeting(cap hash, included)
        valid := List clone
        signers foreach(sh,
            if(valid contains(sh), continue)
            sp := capResolve(included, storeObj, sh)
            if(sp == nil, continue)
            sigs foreach(sgn,
                if(sgn bytes("signer") == sh and(Identity verifySignature(sgn, sp)),
                    valid append(sh); break)
            )
        )
        valid size >= threshold
    )

    // §5.6 scope subset (per-frame canonicalization, §5.5a)
    _scopeSubset := method(childPeer, parentPeer, child, parent,
        ok := true
        child at("incl") foreach(cp,
            cc := canonicalize(childPeer, cp)
            covered := false
            parent at("incl") foreach(pp, if(matchesPattern(cc, canonicalize(parentPeer, pp)), covered = true; break))
            if(covered not, ok = false; break)
        )
        if(ok,
            parent at("excl") foreach(pe,
                cpe := canonicalize(parentPeer, pe)
                covered := false
                child at("excl") foreach(ce, if(matchesPattern(cpe, canonicalize(childPeer, ce)), covered = true; break))
                if(covered not, ok = false; break)
            )
        )
        ok
    )

    grantSubset := method(localPeer, childPeer, parentPeer, child, parent,
        if(_scopeSubset(localPeer, localPeer, child at("handlers"), parent at("handlers")) not, return false)
        if(_scopeSubset(localPeer, localPeer, child at("operations"), parent at("operations")) not, return false)
        if(_scopeSubset(childPeer, parentPeer, child at("resources"), parent at("resources")) not, return false)
        cp := child at("peers"); if(cp == nil, cp = Map clone atPut("incl", list(localPeer)) atPut("excl", List clone))
        pp := parent at("peers"); if(pp == nil, pp = Map clone atPut("incl", list(localPeer)) atPut("excl", List clone))
        _scopeSubset(localPeer, localPeer, cp, pp)
    )

    _isAttenuated := method(localPeer, childPeer, parentPeer, childTok, parentTok,
        ok := true
        grantsOfToken(childTok) foreach(c,
            covered := false
            grantsOfToken(parentTok) foreach(p, if(grantSubset(localPeer, childPeer, parentPeer, c, p), covered = true; break))
            if(covered not, ok = false; break)
        )
        if(ok not, return false)
        pe := parentTok uint("expires_at")
        ce := childTok uint("expires_at")
        if(pe != nil and(ce == nil), return false)
        if(pe != nil, return ce <= pe)
        true
    )

    _checkCaveats := method(parentTok, childTok, depth,
        caveats := parentTok mapField("delegation_caveats")
        if(caveats == nil, return true)
        nd := caveats at("no_delegation")
        if(nd == true, return false)
        depthOk := true
        mdd := caveats at("max_delegation_depth")
        if(mdd != nil and(mdd isKindOf(Number)), depthOk = depth < mdd)
        ttlOk := true
        maxttl := caveats at("max_delegation_ttl")
        if(maxttl != nil and(maxttl isKindOf(Number)),
            ex := childTok uint("expires_at")
            cr := childTok uint("created_at")
            if(ex != nil and(cr != nil), ttlOk = (ex - cr) <= maxttl,
                if(ex != nil, ttlOk = true, ttlOk = false))
        )
        depthOk and(ttlOk)
    )

    // collect the parent chain -> list(chain-List, ok-bool)
    collectChain := method(cap, included, storeObj,
        acc := List clone
        current := cap
        depth := 0
        loop(
            if(depth > maxChainDepth, return list(nil, false))
            acc append(current)
            ph := current bytes("parent")
            if(ph == nil, return list(acc, true))
            parent := capResolve(included, storeObj, ph)
            if(parent == nil, return list(nil, false))
            current = parent
            depth = depth + 1
        )
    )

    // §4.10(b) structural pre-check: true iff chain exceeds max depth (no sig
    // verify; an unreachable parent is NOT a depth problem — left for the walk).
    chainExceedsDepth := method(cap, included, storeObj,
        current := cap
        depth := 0
        loop(
            if(depth > maxChainDepth, return true)
            ph := current bytes("parent")
            if(ph == nil, return false)
            parent := capResolve(included, storeObj, ph)
            if(parent == nil, return false)
            current = parent
            depth = depth + 1
        )
    )

    // §5.5 chain verification → "ALLOW"/"DENY"; may raise UNRESOLVABLE_GRANTEE.
    verifyCapabilityChain := method(localPeer, storeObj, cap, included,
        cr := collectChain(cap, included, storeObj)
        if(cr at(1) not, return "DENY")
        chain := cr at(0)
        root := chain last
        rootMg := multiGranterOf(root)
        rootOk := if(rootMg != nil,
            verifyMultisigRoot(localPeer, included, storeObj, root, rootMg)
        ,
            rgh := root bytes("granter")
            g := if(rgh != nil, capResolve(included, storeObj, rgh), nil)
            pk := if(g != nil, g bytes("public_key"), nil)
            pk != nil and(Identity peerIdOfPubkey(pk) == localPeer)
        )
        if(rootOk not, return "DENY")

        good := true
        n := chain size
        for(i, 0, n - 1,
            if(good not, break)
            current := chain at(i)
            if(isMultisig(current),
                if(i != n - 1, good = false)
                continue
            )
            // signature: signer == granter, verify against granter identity
            gh := current bytes("granter")
            if(gh != nil,
                sgn := findSignature(current hash, included)
                granter := capResolve(included, storeObj, gh)
                if(sgn != nil and(granter != nil),
                    signer := sgn bytes("signer")
                    if((signer != nil and(signer == gh) and(Identity verifySignature(sgn, granter))) not, good = false)
                ,
                    good = false
                )
            ,
                good = false
            )
            // grantee resolution → UNRESOLVABLE_GRANTEE carve-out (401, §5.2/PR-3).
            // Returned as a distinct verdict (not raised) — string-matching a raised
            // exception message across the addon boundary is fragile (was surfacing 500).
            geh := current bytes("grantee")
            if(geh == nil or(capResolve(included, storeObj, geh) == nil),
                return "UNRESOLVABLE")
            // temporal validity
            now := nowMs
            nb := current uint("not_before")
            if(nb != nil and(now < nb), good = false)
            ex := current uint("expires_at")
            if(ex != nil and(ex < now), good = false)
            // delegation link
            if(i < n - 1,
                parent := chain at(i + 1)
                childPeer := _linkGranterPeer(included, storeObj, localPeer, current)
                parentPeer := _linkGranterPeer(included, storeObj, localPeer, parent)
                if(childPeer == nil or(parentPeer == nil),
                    good = false
                ,
                    pg := parent bytes("grantee")
                    cg := current bytes("granter")
                    if((pg != nil and(cg != nil) and(pg == cg) and(
                        _isAttenuated(localPeer, childPeer, parentPeer, current, parent)) and(
                        _checkCaveats(parent, current, i))) not, good = false)
                )
            )
        )
        if(good, "ALLOW", "DENY")
    )

    _revokeMarker := method(localPeer, storeObj, hashSeq,
        storeObj getAt("/" .. localPeer .. "/system/capability/revocations/" .. EntityCodec hexEncode(hashSeq))
    )

    isRevoked := method(localPeer, storeObj, cap, included,
        cr := collectChain(cap, included, storeObj)
        rootHash := if(cr at(1), (cr at(0) last) hash, cap hash)
        (_revokeMarker(localPeer, storeObj, cap hash) != nil) or(_revokeMarker(localPeer, storeObj, rootHash) != nil)
    )

    // ── §5.2 verify_request (4-way) → ALLOW / AUTHN_FAIL / AUTHZ_DENY / CHAIN_TOO_DEEP ──
    verifyRequest := method(localPeer, storeObj, env,
        exec := env root
        included := env included
        // step 1: content hash integrity (§5.2). fromWire recomputes every
        // entity's true hash and flags hashOk=false when the wire CARRIED a
        // different content_hash (tamper) — non-raising (A-IO-025). A mismatch on
        // the root or any included entity → AUTHZ_DENY (no per-request `try`).
        if(exec hashOk not, return "AUTHZ_DENY")
        included foreach(e, if(e hashOk not, return "AUTHZ_DENY"))
        sgn := findSignature(exec hash, included)
        if(sgn == nil, return "AUTHN_FAIL")
        authorH := exec bytes("author")
        signer := sgn bytes("signer")
        if((signer != nil and(authorH != nil) and(signer == authorH)) not, return "AUTHN_FAIL")
        author := env includedGet(authorH)
        if(author == nil, return "AUTHN_FAIL")
        if(Identity verifySignature(sgn, author) not, return "AUTHN_FAIL")
        ch := exec bytes("capability")
        cap := if(ch != nil, env includedGet(ch), nil)
        if(cap == nil, return "AUTHZ_DENY")
        if(chainExceedsDepth(cap, included, storeObj), return "CHAIN_TOO_DEEP")
        cv := verifyCapabilityChain(localPeer, storeObj, cap, included)
        if(cv == "UNRESOLVABLE", return "UNRESOLVABLE_GRANTEE")
        if(cv == "DENY", return "AUTHZ_DENY")
        grantee := cap bytes("grantee")
        if((grantee != nil and(grantee == authorH)) not, return "AUTHZ_DENY")
        if(isRevoked(localPeer, storeObj, cap, included), return "AUTHZ_DENY")
        "ALLOW"
    )
)
