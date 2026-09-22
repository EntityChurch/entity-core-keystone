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

    // §6.2 CAP-6a: true iff every temporal field on a RECEIVED token is either absent
    // (legal) or representable as a uint64.
    //
    // This is the reader-side half of CAP-6 and it is where a peer fails OPEN. Io's
    // fail-open is the ARITHMETIC one, not the null-collapse one, and the distinction
    // matters because the grep that catches the other misses this: Entity uint is
    // `if(v != nil and(v isKindOf(Number)), v, nil)`, so it returns ANY Number, negative
    // included. The expiry check therefore did NOT skip — it RAN and returned the wrong
    // answer. For a negative not_before, `now < nb` is simply false and the capability
    // passed. No nil, no skip, nothing an Option-shaped audit would find.
    //
    // Io Numbers are IEEE doubles, so the >2^64 half is a range check against the wire's
    // uint64 domain rather than an overflow trap. A non-integral Number is likewise
    // unrepresentable and refused.
    //
    // An absent field stays legal and is NOT rejected here. Refusal must be the §5.2
    // capability_denied disposition, never a decode-layer drop or a transport close.
    temporalFieldsRepresentable := method(tok,
        list("expires_at", "not_before", "created_at") foreach(k,
            v := tok field(k)
            if(v == nil, continue)
            if(v isKindOf(Number) not, return false)
            if(v < 0, return false)
            if(v != (v floor), return false)
            if(v >= 18446744073709551616, return false))
        true
    )

    // §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative to
    // createdAt. Rule 3: a conversion that is not representable is treated as ABSENT
    // (nil) exactly as a null term is — it MUST NOT wrap and MUST NOT saturate to a
    // representable maximum, since saturation manufactures expires_at == 2^64-1, a
    // finite bound no reader can distinguish from a deliberate one.
    //
    // ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
    // yielding createdAt (expire immediately). The absent field is the only "no bound"
    // spelling, and falling out of the arithmetic is what keeps the two from collapsing.
    addTtl := method(createdAt, ttl,
        if(ttl isKindOf(Number) not, return nil)
        if(ttl < 0, return nil)
        sum := createdAt + ttl
        if(sum >= 18446744073709551616, return nil)
        sum
    )

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
    // The unmatchable value (0.8.2.20). Unreachable as a canonical path by
    // CONSTRUCTION: its first segment cannot be a peer_id, since a peer_id needs
    // >= 46 Base58 characters and "-" is outside the Base58 alphabet.
    NEVER_MATCH := "/never-match"

    // TOTAL (0.8.2.20): the return domain is "a canonical path OR NEVER_MATCH". The
    // reserved arm used to PASS THE INPUT THROUGH, which matched nothing -- the
    // desired outcome in an INCLUDE and the opposite of it in an EXCLUDE, so a grant
    // exclude carrying "../x" carved out nothing and the grant was silently wider
    // than its author wrote (measured on the wire 2026-09-14).
    canonicalize := method(localPeer, path,
        if(isReservedPath(path), return NEVER_MATCH)
        if(path beginsWithSeq("/"), path, "/" .. localPeer .. "/" .. path)
    )

    // AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
    // fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
    // fail-OPEN in an exclude (carves out nothing), so the reading is chosen where
    // the POSITION is known and matchesPattern stays uniform over its operands.
    //
    // ASK THIS ONLY OF A PATH-SCOPE DIMENSION (0.8.2.24, N2/N3). NEVER_MATCH is a
    // 5.4 PATH-canonicalization sentinel; an id-scope pattern is a literal
    // identifier that 5.2's own id-scope arm forbids putting through the 5.4
    // transforms. This guard used to sit OUTSIDE the type dispatch, transcribing
    // 5.2's loop as it read before that loop grew one -- which ran an id pattern
    // through those transforms purely to classify it and then DENIED THE WHOLE
    // DIMENSION on a property unrelated to whether the exclude carves anything out:
    // an `operations` exclude of a namespaced operation name such as the
    // apply-under-star form -- an ordinary literal that matches nothing under the
    // id-scope grammar -- canonicalized to the sentinel and denied every operation.
    // Over-denial, and invisible on any well-formed grant.
    //
    // 5.4 says outright that the rule "does NOT reach `operations` or `peers`
    // [MUST]", and it does not leave the id dimensions unprotected by oversight:
    // under the id-scope grammar every non-star pattern is a literal and a literal
    // is never structurally unmatchable, so there is nothing here for this sentinel
    // to detect. A scope boundary, not an omission.
    _excludeUnmatchable := method(frame, excl,
        r := false
        if(excl != nil, excl foreach(p, if(canonicalize(frame, p) == NEVER_MATCH, r = true; break)))
        r
    )

    matchesPattern := method(path, pattern,
        // NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a
        // matcher rule rather than a property of the string: the line below returns
        // true for a bare "*", so safety must not rest on a value merely looking
        // unmatchable.
        if(path == NEVER_MATCH or(pattern == NEVER_MATCH), return false)
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

    // §5.2 id-scope match (0.8.1, F40) — operations and peers. Literal comparison with
    // exactly two wildcard forms: bare "*" and a trailing slash-star segment-prefix.
    // None of the §5.4 path transforms apply, so a pattern carrying path syntax is
    // matched as a literal string: a non-match, never a fault.
    matchesIdPattern := method(value, pattern,
        if(pattern == "*", return true)
        if(pattern size >= 2 and pattern endsWithSeq("/*"),
            return value beginsWithSeq(pattern exSlice(0, pattern size - 1))
        )
        value == pattern
    )

    _coveredId := method(pats, value,
        c := false
        pats foreach(p, if(matchesIdPattern(value, p), c = true; break))
        c
    )

    // §5.2 typed scope match. `kind` is "id" (operations, peers) or "path" (handlers,
    // resources) and is given at every call site — there is no default, so a new one
    // cannot inherit the wrong matcher silently, which is exactly the F40 defect.
    matchesScope := method(localPeer, value, scope, kind,
        // SCOPED TO PATH-SCOPE (0.8.2.24). 5.2's exclude loop tests the sentinel
        // INSIDE `if dimension_type == "system/capability/path-scope"`, and 5.4
        // scopes its own invalid-capability rule the same way. `kind` already names
        // the dimension here, so the scoping costs one term and cannot be got wrong
        // by a new call site.
        if(kind == "path" and(_excludeUnmatchable(localPeer, scope at("excl"))), return false)  // 0.8.2.21
        if(kind == "id",
            return _coveredId(scope at("incl"), value) and(_coveredId(scope at("excl"), value) not)
        )
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
        // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before
        // any target: the coverage test below is correct in isolation and is simply
        // never reached on a sentinel, because matchesPattern answers false.
        //
        // UNGUARDED ON PURPOSE, unlike matchesScope's (0.8.2.24): `scope` here is
        // ALWAYS the RESOURCES dimension, which 5.2 fixes as path-scope, so the type
        // test that call site performs would be a constant here. The single-dimension
        // signature is what makes that checkable -- a granter frame reaching an
        // id-scope call site is the defect, and this method cannot be one.
        if(_excludeUnmatchable(granterPeer, scope at("excl")), return false)
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

    // ── §3.3 effective targets + §6.3 check_path_permission ──

    // §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude`
    // removes entries from `resource.targets` BEFORE anything else looks at the
    // request.
    //
    // Returns a Map with "had" (was a `resource` present at all) and "list" (the
    // survivors). THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST]
    // (0.8.2.25, N11): "where an implementation projects resource.targets onto the
    // effective set ahead of the handler, that projection MUST NOT be lossy about
    // its own emptiness -- narrow when narrowing leaves something, and retain the
    // raw pair when narrowing would empty it." A method returning only the List
    // cannot satisfy that: collapsing `[qA] exclude [qA]` to an empty List deletes
    // the two-empties discriminator before any handler can read it, and the
    // handler's refusal arm becomes dead code that only a WIRE drive can detect.
    //
    // The survivors are in the caller's OWN SPELLING, not canonicalized -- 0.8.2.21
    // is explicit that effective_targets yields raw survivors, and the distinction
    // is load-bearing because the value flows on to the store lookup, which
    // canonicalizes for itself.
    //
    // "Every seam that narrows is exempted alike, inbound-wire and in-process
    // sub-dispatch, or one request receives two different answers according to which
    // door it arrived through." This peer has exactly ONE narrowing seam -- this
    // method, called by the tree handler -- and §6.5's dispatch chain does not
    // project: _dispatchInner passes `exec` through untouched and checkPermission
    // reads `resource` for itself. So there is no second door to keep in step, and
    // adding a projection at dispatch would create one.
    //
    // A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list.
    // Reporting it absent would serve the WIDER absent-case answer to a request that
    // named a resource, which is N11's own defect one field over.
    //
    // The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it
    // separately from the grant arm) and that is INHERITED here rather than
    // restated: canonicalize answers the sentinel, matchesPattern then answers
    // false, and the target simply survives.
    effectiveTargets := method(localPeer, exec,
        out := List clone
        r := exec mapField("resource")
        if(r == nil, return Map clone atPut("had", false) atPut("list", out))
        tv := r at("targets")
        if(tv == nil, return Map clone atPut("had", false) atPut("list", out))
        targets := List clone
        if(tv isKindOf(List), tv foreach(x, if(x isKindOf(Sequence), targets append(x))))
        excl := List clone
        ev := r at("exclude")
        if(ev != nil and(ev isKindOf(List)), ev foreach(x, if(x isKindOf(Sequence), excl append(x))))
        targets foreach(t,
            ct := canonicalize(localPeer, t)
            dropped := false
            excl foreach(x, if(matchesPattern(ct, canonicalize(localPeer, x)), dropped = true; break))
            if(dropped not, out append(t))
        )
        Map clone atPut("had", true) atPut("list", out)
    )

    // §6.3's handler-level path check: may the caller access `path` AS A TREE PATH,
    // under `handlerPattern`, with `token`?
    //
    // IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever
    // the subject is derived after dispatch, and the dispatch-level check can be
    // made VACUOUS by caller-controlled input: a caller who excludes the one target
    // its capability does not cover removes that target from checkPermission's view
    // entirely, and a handler that then acts on it has authorized nothing.
    //
    // THREE DIMENSIONS, NOT FOUR. `peers` is not consulted -- the path is local by
    // construction at this point (§1.4's inbound rule refuses a foreign namespace at
    // §6.5 step 3, before any handler runs), and §6.3's signature names only
    // handlers, operations and resources.
    //
    // THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own
    // signature rather than a choice: §6.3's block reads
    // `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)`
    // -- there is no granter parameter to pass. §5.5a governs chain ATTENUATION,
    // where the subject is a pattern compared against a parent's pattern; this call
    // site compares a CONCRETE local path the handler is about to touch.
    //
    // Scope types: handlers -> path-scope, operations -> id-scope, resources ->
    // path-scope. An empty resources.include is a legal grant shape (§5.2: handlers
    // that touch no tree paths) and DENIES every path here, which is what that note
    // says it should. A malformed path canonicalizes to NEVER_MATCH, which matches
    // no grant, so it falls through to DENY rather than being matched against
    // anything.
    checkPathPermission := method(localPeer, operation, path, token, handlerPattern,
        allowed := false
        grantsOfToken(token) foreach(g,
            if(matchesScope(localPeer, handlerPattern, g at("handlers"), "path") not, continue)
            if(matchesScope(localPeer, operation, g at("operations"), "id") not, continue)
            if(matchesScope(localPeer, path, g at("resources"), "path") not, continue)
            allowed = true; break
        )
        allowed
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
            okg := matchesScope(localPeer, operation, g at("operations"), "id") and(
                   matchesScope(localPeer, handlerPattern, g at("handlers"), "path"))
            if(okg,
                peers := g at("peers")
                if(peers == nil, peers = Map clone atPut("incl", list(localPeer)) atPut("excl", List clone))
                okg = matchesScope(localPeer, targetPeer, peers, "id")
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

    // The two halves of the scope typing, split so each can be mutated
    // independently. Measured on the sibling `tcl` peer by planting: mutating the
    // MATCHER alone is INERT for the published K-7 witnesses, because for the
    // star-slash-apply form against a bare star the two matchers AGREE (both take
    // the bare-star arm) and the whole divergence comes from CANONICALIZATION
    // manufacturing the sentinel. The frame is the half that bites; the matcher half
    // needs a pair such as /a/get against the peer-wildcard form, which
    // canonicalizes to itself and is a PATTERN to one matcher and a literal to the
    // other.
    _ssFrame := method(kind, pattern, peerFrame,
        if(kind == "path", canonicalize(peerFrame, pattern), pattern)
    )
    _ssCovers := method(kind, pattern, value,
        if(kind == "path", matchesPattern(value, pattern), matchesIdPattern(value, pattern))
    )

    // §5.5a/§5.6 subset check: every child include must be covered by some parent
    // include, and every parent exclude must be inherited by some child exclude.
    //
    // TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; entity-core-formalization
    // K-7). §3.6's id-scope grammar binds the scope TYPE, not one function -- "An
    // implementation on the canonicalizing reading is non-conformant and MUST adopt
    // the literal matcher" -- so the rule F40 landed on matchesScope reaches here
    // too, with delegation-chain WIDENING named as the reason: on the canonicalizing
    // reading a bare id include reads as covered by a path-form parent pattern it
    // does not literally match, and a child grant comes out wider than its parent.
    // `lean`'s differential put it at 2 of 64 include pairs and 2 of 64 exclude
    // pairs, fail-closed, with a 16-pair control alphabet reporting 0 -- which is why
    // every hand-tried example missed it.
    //
    // `kind` has NO DEFAULT and is named at every call site, because a default is how
    // the next dimension inherits the wrong matcher silently -- the original F40
    // defect. The per-link granter frames are meaningless on the id arm (an id
    // pattern is never canonicalized) and are simply unread there.
    _scopeSubset := method(childPeer, parentPeer, child, parent, kind,
        ok := true
        child at("incl") foreach(cp,
            cc := _ssFrame(kind, cp, childPeer)
            covered := false
            parent at("incl") foreach(pp, if(_ssCovers(kind, _ssFrame(kind, pp, parentPeer), cc), covered = true; break))
            if(covered not, ok = false; break)
        )
        if(ok,
            parent at("excl") foreach(pe,
                cpe := _ssFrame(kind, pe, parentPeer)
                covered := false
                child at("excl") foreach(ce, if(_ssCovers(kind, _ssFrame(kind, ce, childPeer), cpe), covered = true; break))
                if(covered not, ok = false; break)
            )
        )
        ok
    )

    grantSubset := method(localPeer, childPeer, parentPeer, child, parent,
        // §5.5a: only the RESOURCE dimension uses the per-link granter frames; the
        // other dimensions stay on the local frame. The scope KIND is a property of
        // the DIMENSION and is named at every call site, never defaulted (F50 /
        // 0.8.2.16).
        if(_scopeSubset(localPeer, localPeer, child at("handlers"), parent at("handlers"), "path") not, return false)
        if(_scopeSubset(localPeer, localPeer, child at("operations"), parent at("operations"), "id") not, return false)
        if(_scopeSubset(childPeer, parentPeer, child at("resources"), parent at("resources"), "path") not, return false)
        cp := child at("peers"); if(cp == nil, cp = Map clone atPut("incl", list(localPeer)) atPut("excl", List clone))
        pp := parent at("peers"); if(pp == nil, pp = Map clone atPut("incl", list(localPeer)) atPut("excl", List clone))
        _scopeSubset(localPeer, localPeer, cp, pp, "id")
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
            // temporal validity.
            //
            // CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
            // created_at is MALFORMED and must be refused outright. This has to run
            // BEFORE the two range checks below, because those are what the ambiguity
            // defeats — see temporalFieldsRepresentable for the mechanism, which in Io
            // is the ARITHMETIC form rather than the null-collapse one.
            if(temporalFieldsRepresentable(current) not, good = false)
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
