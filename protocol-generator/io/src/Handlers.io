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

    // A §5.4 PATTERN rather than a concrete path. A resource-requiring operation
    // takes a concrete path (0.8.2.20); a trailing "/" is a LISTING request, not a
    // pattern -- only a star makes it one.
    patternPath := method(target, target containsSeq("*"))

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

    // §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
    // 400 invalid_request, not the 501 the base Handler answers. The table separates
    // a STATE conflict from an UNKNOWN operation because they select different
    // remedies — "an unknown connect operation is not out of order at all; it exists
    // in no state", so connection_sequence_error would point the caller at its
    // ORDERING when the defect is its OPERATION NAME. Row 10 is scoped "in any
    // state", so this covers pre-handshake AND established; the genuine sequence
    // cases are refused in op_hello/op_authenticate, with 409.
    //
    // SCOPED TO THIS CLONE DELIBERATELY, and differential inheritance is what scopes
    // it: overriding `dispatch` here leaves the base's §3.3 501 row (§6.2) — a
    // different contract, separately gated — untouched for every other handler. The
    // declared-op guard is mirrored rather than bypassed, so an inherited Object slot
    // is still never wire-reachable (A-IO-004/A-IO-007).
    dispatch := method(operation, ctx,
        if(ops contains(operation) not,
            return Outcome err(400, "invalid_request", "connect: unknown operation " .. operation))
        self perform("op_" .. operation, ctx)
    )

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
        // §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
        // HALF-OPEN connection (hello done, authenticate not yet) is an operation we
        // implement arriving in a state that forbids it — the same class as
        // connection_already_established above, taking the same 409. A half-open
        // connection is NOT established, so the guard above cannot reach it; §4.7
        // names this gap explicitly because two adjacent rules each look like they
        // cover it and neither does.
        if(conn at("issued_nonce") != nil, return fail(409, "connection_sequence_error", nil))
        params := exec entityField("params")
        if(_negotiationDisjoint(params, "hash_formats", "ecfv1-sha256"), return fail(400, "incompatible_hash_format", nil))
        if(_negotiationDisjoint(params, "key_types", "ed25519"), return fail(400, "unsupported_key_type", nil))
        // §4.5 mutual verifiability, the direction that is NOT the array. `key_types`
        // is an ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in
        // its `peer_id` — so a hello may advertise a perfectly good accept-set and
        // still name an identity we cannot verify. Checking only the array leaves that
        // MUST unenforced at hello, which is where §4.5 wants it; authenticate catches
        // it one leg later, which is conformant but non-canonical.
        //
        // An UNPARSEABLE peer_id is deliberately left alone: that is a malformed field,
        // not a key_type we lack, and authenticate already refuses it. `try()` returns
        // nil-or-exception and NOT the value, so the parse result is read out of the
        // assigned slot (A-IO: the same shape op_authenticate uses below).
        helloPid := if(params != nil, params text("peer_id"), nil)
        if(helloPid != nil,
            hparsed := nil
            hpe := try(hparsed = EntityCodec peeridParse(helloPid))
            if(hpe == nil and(hparsed != nil) and(hparsed at(0) != 1),
                return fail(400, "unsupported_key_type", nil))
        )
        // §4.5 `protocols` — the one negotiated field Required with NO default, so
        // there is no floor to fall back to, and its two failure modes carry different
        // codes on purpose (§4.5 table row / §4.7 row 1):
        //
        //   absent or empty     -> 400 invalid_request       (a malformed hello)
        //   non-empty, disjoint -> 400 incompatible_protocol (we compared)
        //
        // "a caller that named no version cannot be told the comparison failed" — the
        // remedies differ (send the field vs change the version) and §4.7 exists so the
        // code selects the remedy. The vocabulary is §8.4's protocol version
        // identifiers, today the single entity-core/1.0.
        //
        // ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
        // precedence between the three, so a hello disjoint in more than one dimension
        // may be refused on any of them — but the choice is OBSERVABLE, and the
        // reference peer refuses key_types first. Checking protocols first is equally
        // spec-legal and makes AGILITY-UNKNOWN-1 answer incompatible_protocol, because
        // that probe's own hello carries protocols ["entity-core/v7"] — a spec-line
        // name, not a §8.4 identifier (F56).
        protos := List clone
        if(params != nil,
            pv := params field("protocols")
            if(pv != nil and(pv isKindOf(List)),
                pv foreach(x, if(x isKindOf(Sequence), protos append(x asSymbol))))
        )
        if(protos size == 0,
            return fail(400, "invalid_request", "hello: protocols absent or empty"))
        if(protos contains("entity-core/1.0" asSymbol) not,
            return fail(400, "incompatible_protocol", nil))
        if(params != nil, conn atPut("hello_peer_id", helloPid))
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
        // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
        // single-use nonce — pinned to 401 invalid_nonce, not a 409 state-conflict
        // which under-signals the replay.
        if(conn at("established") == true, return fail(401, "invalid_nonce", nil))
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
        // §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
        // resource.targets: a handler that counts the effective list and then
        // indexes targets[0] has implemented the arithmetic completely and is still
        // reading a path no authorization covered.
        eff := Capability effectiveTargets(local, exec)
        if(eff at("had") not,
            // THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN
            // SPECIFICATION IS WHAT SAYS SO. §3.3's "an empty effective list IS the
            // absent case" is scoped "for an operation that REQUIRES a resource"
            // (0.8.2.24, N7); `get` does not. For a resource-OPTIONAL operation
            // 0.8.2.25 (N10) decides the present-but-empty case by whether the absent
            // case is WIDER than the request -- BROAD-RESULT refuses it,
            // OPTIONAL-FILTER answers it empty -- and requires the operation to
            // declare which it is.
            //
            // EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
            // resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
            // listing", self-excluded case "400 path_required". Both arms are pinned
            // by text; neither is this peer's choice.
            return _listing("/" .. local .. "/", ctx))
        effList := eff at("list")
        // `resource` PRESENT, every target carved out by the caller's own exclude.
        // Serving it the absent case "answers a request for one excluded path with a
        // listing of the tree" (EXTENSION-TREE §2.2a) -- the root listing is wider
        // than what was asked for, which is what BROAD-RESULT means.
        if(effList size == 0, return fail(400, "path_required", "tree: effective target list is empty"))
        if(effList size > 1, return fail(400, "ambiguous_resource", "tree: more than one effective target"))
        target := effList at(0)
        // §6.3: an empty-string target lists the local peer's root.
        if(target == "", return _listing("/" .. local .. "/", ctx))
        // §1.4: a bare "/" is the universal tree root → list peer-id children. It
        // sits ABOVE pathFlexOk deliberately: "/" has no peer segment, so the §1.4
        // absolute-path test refuses it, and this arm is what makes the universal
        // root reachable at all.
        if(target == "/", return _listing("/", ctx))
        if(HandlerUtil pathFlexOk(target) not, return fail(400, "invalid_path", target))
        // §6.3: trailing "/" → list entries under the prefix.
        if(target endsWithSeq("/"), return _listing(Capability canonicalize(local, target), ctx))
        if(HandlerUtil patternPath(target), return fail(400, "malformed_resource", target))
        path := Capability canonicalize(local, target)
        // §6.3: the handler MUST verify the CALLER's capability covers the path it is
        // about to read. Not a secondary check -- the dispatch-level check never saw
        // this path if the caller excluded it.
        callerCap := ctx at("callerCap")
        if(callerCap != nil and(
             Capability checkPathPermission(local, "get", path, callerCap, ctx at("handlerPattern")) not),
            return fail(403, "capability_denied", path))
        e := store getAt(path)
        if(e == nil, return fail(404, "not_found", path))
        params := exec entityField("params")
        mode := if(params != nil, params text("mode"), nil)
        if(mode == "hash",
            return ok(Entity with("system/hash", EcMap with("hash", EcBytes with(e hash))), nil))
        ok(e, nil)
    )

    // Digest byte length for a content_hash_format code per the §1.2 seed table,
    // or nil when this peer cannot VERIFY that code. The total wire length is
    // this plus the varint prefix, which is not a constant of the code (§7.3):
    // codes >= 0x80 occupy more than one byte.
    hashDigestLen := method(code,
        if(code == 0, return 32)
        if(code == 1, return 48)
        nil
    )

    // §6.3's `put` admission ladder (normative, 0.8.2.11).
    //
    // `put` is a RECEIPT path: the submitter authors the entity, the peer
    // validates what it received (§1.8 item 1) and MUST NOT author a submitted
    // entity's content_hash on the submitter's behalf. Two ordered steps:
    //
    //   1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data`
    //      (any CBOR value; null is a legal payload), and a `content_hash` that
    //      is a well-formed system/hash whose total byte length matches its
    //      format code (§1.2). Any failure -> 400 invalid_request. A well-formed
    //      hash naming a format code this peer cannot verify is the separate
    //      §1.2 ingest-dispatch case -> 400 unsupported_content_hash_format.
    //   2. HASH — carried content_hash vs contentHash({type, data}).
    //      Disagreement -> 400 hash_mismatch.
    //
    // Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step
    // 2's inputs are exactly what step 1 establishes, so a submission that is
    // both malformed and mis-hashed is step 1's and answers invalid_request.
    //
    // Structural admission is not semantic validation: `data` is never checked
    // against the type named by `type`.
    //
    // Returns list("admitted", entity) or list("refused", outcome).
    admitPut := method(v,
        refuse := block(code, msg, list("refused", fail(400, code, msg)))
        if(v == nil or((v hasSlot("ecKind")) not) or(v ecKind != "map"),
            return refuse call("invalid_request", "put: entity is not a map"))
        t := v at("type")
        if(t == nil or(t isKindOf(Sequence) not) or(t hasSlot("ecKind")) or(t size == 0),
            return refuse call("invalid_request",
                "put: entity.type absent, empty or not a text string"))
        // Presence, not truthiness: a CBOR null is a legal `data` payload, so the
        // map's own hasKey is the presence test rather than a nil check.
        if(v hasKey("data") not,
            return refuse call("invalid_request", "put: entity.data absent"))
        d := v at("data")
        ch := v at("content_hash")
        if(ch == nil or((ch hasSlot("ecKind")) not) or(ch ecKind != "bytes") or(ch seq size == 0),
            return refuse call("invalid_request",
                "put: entity.content_hash absent or not a byte string"))
        carried := ch seq
        // Leading multicodec LEB128 format-code varint (§7.3).
        code := 0
        shift := 0
        n := 0
        done := false
        while(n < carried size and(done not),
            b := carried at(n)
            // Explicit bit methods, not the `&`/`<<` operators: in Io `==` binds
            // TIGHTER than `&`, so `b & 0x80 == 0` parses as `b & (0x80 == 0)`.
            code = code + (b bitwiseAnd(127) * (2 ** shift))
            n = n + 1
            if(b bitwiseAnd(128) == 0, done = true, shift = shift + 7)
        )
        if(done not,
            return refuse call("invalid_request",
                "put: entity.content_hash is not a well-formed system/hash"))
        digestLen := hashDigestLen(code)
        // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
        // invalid_request: the shape is fine, the algorithm is what we lack.
        if(digestLen == nil,
            return refuse call("unsupported_content_hash_format",
                "put: unsupported content_hash_format"))
        if(carried size != n + digestLen,
            return refuse call("invalid_request",
                "put: content_hash length does not match its format code"))
        computed := EntityCodec contentHashWithFormat(t, EntityCodec encode(d), code)
        if(computed != carried,
            return refuse call("hash_mismatch",
                "put: content_hash does not match content_hash({type, data})"))
        // The carried hash IS the entity's address; recomputing it into the store
        // would be the authoring arm §6.3 forbids.
        list("admitted", Entity admitted(t, d, carried))
    )

    op_put := method(ctx,
        exec := execOf(ctx)
        local := peer localPeer
        store := peer store
        // Same ladder as op_get, with the two empties COLLAPSED rather than split:
        // EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's
        // "an empty effective list IS the absent case" applies in its unscoped form
        // and both empties answer path_required. That is the same table op_get's
        // branch cites, read one row down -- the field is per-operation and neither
        // answer is derivable from this handler's source.
        //
        // Note the code change 0.8.2.20 forced: this branch answered
        // ambiguous_resource for a MISSING target, which 0.8.2.20 names as the exact
        // inversion it forbids ("answering ambiguous_resource for an absent resource
        // inverts them"). The remedies differ -- *supply a resource* is not
        // *disambiguate your request* -- and the code selects.
        eff := Capability effectiveTargets(local, exec)
        effList := eff at("list")
        if(eff at("had") not or(effList size == 0),
            return fail(400, "path_required", "tree: put requires a resource target"))
        if(effList size > 1, return fail(400, "ambiguous_resource", "tree: more than one effective target"))
        target := effList at(0)
        if(HandlerUtil pathFlexOk(target) not, return fail(400, "invalid_path", target))
        if(HandlerUtil patternPath(target), return fail(400, "malformed_resource", target))
        path := Capability canonicalize(local, target)
        // §6.3 (see op_get): the CALLER's capability must cover the path this handler
        // is about to write, because the caller's own exclude can vacate the
        // dispatch-level check.
        callerCap := ctx at("callerCap")
        if(callerCap != nil and(
             Capability checkPathPermission(local, "put", path, callerCap, ctx at("handlerPattern")) not),
            return fail(403, "capability_denied", path))
        params := exec entityField("params")
        rawEntity := if(params != nil, params field("entity"), nil)
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
        if(rawEntity == nil, return fail(400, "unexpected_params", "put: missing entity"))
        admitted := admitPut(rawEntity)
        if(admitted at(0) == "refused", return admitted at(1))
        entity := admitted at(1)
        store bind(path, entity)
        ok(Entity with("system/hash", EcMap with("hash", EcBytes with(entity hash))), nil)
    )

    // §6.3's per-entry listing check for one child segment (0.8.2.21/.22).
    //
    // An unauthenticated context is the bootstrap/internal path and is NOT filtered:
    // the filter's subject is "the caller's verified capability", and where there is
    // none there is no caller to narrow. `ctx` is nil on internal call paths.
    _entryVisible := method(ctx, dir, seg,
        if(ctx == nil, return true)
        callerCap := ctx at("callerCap")
        if(callerCap == nil, return true)
        child := if(dir endsWithSeq("/"), dir, dir .. "/")
        Capability checkPathPermission(peer localPeer, "get", child .. seg, callerCap, ctx at("handlerPattern"))
    )

    // Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
    //
    // "When any handler returns a multi-entry result whose entries are tree paths,
    // each entry MUST be individually checked using check_path_permission. Entries
    // for which check_path_permission returns DENY MUST be omitted. The result's
    // `count` field MUST reflect the filtered entry count, not the source tree's
    // total count."
    //
    // This is the read path at its highest volume and it is the reason 0.8.2.21
    // refused to carve reads out of the caller-specified-path rule: an unfiltered
    // listing discloses the EXISTENCE of every binding under a prefix to a caller
    // whose capability covers none of them. `count` following the SOURCE total is
    // that disclosure by itself, which is why `rows` is the FILTERED list and the
    // count is taken from it.
    //
    // The DIRECTORY itself is deliberately NOT checked -- §6.3 makes each ENTRY the
    // subject, and testing the prefix would deny a listing to a caller whose grant
    // covers children but not the node above them, which is the ordinary shape of a
    // narrowed grant.
    _listing := method(path, ctx,
        store := peer store
        rows := List clone
        store listing(path) foreach(row,
            hx := row at(1)
            hasChildren := row at(2)
            if(hx != nil and(hasChildren not) and(_isDeletionMarker(EntityCodec hexDecode(hx))), continue)
            if(_entryVisible(ctx, path, row at(0)) not, continue)
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
    // §6.2: true iff pattern == "system" or pattern starts with "system/" -- user-installed
    // handlers MUST NOT register there.
    _isReservedPattern := method(pattern,
        pattern == "system" or(pattern beginsWithSeq("system/"))
    )

    op_register := method(ctx,
        exec := execOf(ctx)
        store := peer store
        pattern := _registerPattern(exec)
        if(pattern == nil, return _patternError(exec))
        // §6.2 wire message stays plain ASCII (A-OZ-008 precedent: a non-ASCII byte in a
        // wire-visible string tripped the codec's UTF-8 validation path on this run --
        // isolated live, see SPEC-AMBIGUITY-LOG; keep the § citation in source comments only).
        if(_isReservedPattern(pattern),
            return fail(403, "forbidden_pattern", "section 6.2: user-installed handlers MUST NOT register at system/* paths: " .. pattern))
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
        _mintBounded(ctx, ctx at("callerCap"), params, _reqGrants(params), author, nil)
    )

    op_delegate := method(ctx,
        params := paramsOf(ctx)
        author := (execOf(ctx)) bytes("author")
        ph := if(params != nil, params bytes("parent"), nil)
        if(ph == nil, return fail(400, "unexpected_params", "delegate: parent required"))
        if(HandlerUtil isZeroHash(ph), return fail(400, "unexpected_params", "delegate: zero parent"))
        if((author != nil and(peer idHash == author)) not,
            return fail(501, "unsupported_operation", "delegate: same-peer-only in v1"))
        _mintBounded(ctx, ctx at("callerCap"), params, _reqGrants(params), author, ph)
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

    _mintBounded := method(ctx, callerCap, params, reqGrants, granteeHash, parent,
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

        // §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
        // convert the duration term against that same instant.
        //
        // Note what this is NOT: an authorization decision. An over-long ttl_ms from a
        // bounded caller MINTS a clamped token and returns 200 — "rejecting it is
        // non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
        // (parent: null), so §5.6's parent-child attenuation never reaches it; without
        // this clamp, temporal attenuation is the one dimension a requester could escape,
        // and policy withdrawal would have no bounded latency.
        createdAt := Capability nowMs
        ceiling := nil
        foldMin := block(t, if(t != nil and(ceiling == nil or(t < ceiling)), ceiling = t))
        if(parent != nil,
            pt := Capability capResolve(ctx at("included"), peer store, parent)
            if(pt != nil, foldMin call(pt uint("expires_at"))))          // absolute
        if(callerCap != nil, foldMin call(callerCap uint("expires_at"))) // absolute
        if(params != nil,
            ttl := params uint("ttl_ms")
            if(ttl != nil, foldMin call(Capability addTtl(createdAt, ttl))))  // duration

        minted := peer mintTokenAt(createdAt, granteeHash, reqGrants, parent, ceiling)
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
        if(resp == nil, return fail(503, "no_outbound_seam", "no live section 6.11 reentry connection"))
        root := resp root
        status := root uint("status")
        if(status == nil, status = 0)
        resultCbor := root field("result")
        if(resultCbor == nil, resultCbor = EcMap clone)
        ok(Entity with("primitive/any", EcMap with("status", status, "result", resultCbor)), nil)
    )
)
