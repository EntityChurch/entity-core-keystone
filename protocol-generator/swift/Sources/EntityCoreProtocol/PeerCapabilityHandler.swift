// PeerCapabilityHandler.swift — capability + handlers handlers, §7a handlers.
//
// §6.2 capability handler (request/delegate/revoke/configure), §6.13a handlers
// handler (register/unregister — the FIVE normative writes; a 501-stub is
// NON-CONFORMANT), and GUIDE-CONFORMANCE §7a (echo / dispatch-outbound). Extension
// of `Peer`.

import Crypto

extension Peer {

    // MARK: - Handlers handler (§6.2 / §6.13a) — register / unregister

    func handlersHandler(operation: String, requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        switch operation {
        case "register":
            // §6.2: pattern from EXECUTE.resource.targets[0] (system/handler/{pattern}).
            guard let targets = ctx.resourceTarget?.targets, targets.count == 1, let first = targets.first else {
                return try errorResponse(requestID: requestID, status: 400, code: "ambiguous_resource")
            }
            // resource is "system/handler/{pattern}" → derive {pattern}.
            let pattern = patternFromHandlerResource(first)
            // §6.2: user-installed handlers MUST NOT register at system/* paths.
            if isReservedSystemPattern(pattern) {
                // ASCII-ONLY IN A WIRE-VISIBLE STRING (AGENTS.md, ratified on two
                // independent crashes). A `§` in an error `message` is CBOR-text-encoded
                // and sent; Oz's compiled string constant was corrupted by one and Io's
                // own UTF-8 validator rejected byte-correct UTF-8, killing the process
                // and cascading 104 FAILs. The citation stays, spelled "section", and
                // `§` stays in comments, which are never encoded.
                return try errorResponse(requestID: requestID, status: 403, code: "forbidden_pattern",
                    message: "section 6.2: user-installed handlers MUST NOT register at system/* paths: " + pattern)
            }
            // The five §6.13a writes (manifest, types, grant, grant-sig, interface).
            try await registerHandler(pattern: pattern)
            // register-result.
            let result = try Model.make(type: "system/handler/register-result", fields: [
                ("pattern", .text(pattern)), ("registered", .bool(true)),
            ])
            return try okResponse(requestID: requestID, result: result)

        case "unregister":
            guard let targets = ctx.resourceTarget?.targets, targets.count == 1, let first = targets.first else {
                return try errorResponse(requestID: requestID, status: 400, code: "ambiguous_resource")
            }
            let pattern = patternFromHandlerResource(first)
            try await unregisterHandler(pattern: pattern)
            let ok = try Model.emptyParams()
            return try okResponse(requestID: requestID, result: ok)

        default:
            return try errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")
        }
    }

    /// The five §6.13a/§6.2 normative writes for `register`.
    func registerHandler(pattern: String) async throws {
        let p = identity.peerID
        // 1. manifest at pattern path.
        let manifest = try Model.make(type: "system/handler", fields: [("interface", .text("system/handler/" + pattern))])
        await store.bind(path: "/" + p + "/" + pattern, manifest.entity)
        // 2. (types installed per register-request.types — none in the minimal core path.)
        // 3. grant at system/capability/grants/{pattern}.
        let grant = try Model.make(type: "system/capability/token", data: .textMap([
            ("grants", .array([])),
            ("granter", .bytes(identity.identityHash)),
            ("grantee", .bytes(identity.identityHash)),
            ("created_at", .uint(nowMillis())),
        ]))
        await store.bind(path: "/" + p + "/system/capability/grants/" + pattern, grant.entity)
        // 4. grant-signature at system/signature/{grant_hash} (§3.5 invariant pointer).
        let sig = try identity.signatureEntity(target: grant.hash)
        await store.bind(path: "/" + p + "/system/signature/" + Hex.encode(grant.hash), sig.entity)
        // 5. interface at system/handler/{pattern}.
        let iface = try Model.make(type: "system/handler/interface", fields: [
            ("pattern", .text(pattern)), ("name", .text(pattern)),
        ])
        await store.bind(path: "/" + p + "/system/handler/" + pattern, iface.entity)
    }

    /// `unregister` reverses all five writes (§6.2).
    func unregisterHandler(pattern: String) async throws {
        let p = identity.peerID
        // recover grant hash to unbind its signature.
        if let grant = await store.getAt(path: "/" + p + "/system/capability/grants/" + pattern), let gh = grant.contentHash {
            await store.unbind(path: "/" + p + "/system/signature/" + Hex.encode(gh))
        }
        await store.unbind(path: "/" + p + "/" + pattern)
        await store.unbind(path: "/" + p + "/system/capability/grants/" + pattern)
        await store.unbind(path: "/" + p + "/system/handler/" + pattern)
    }

    func patternFromHandlerResource(_ resource: String) -> String {
        // "system/handler/{pattern}" → "{pattern}"; tolerate a leading peer prefix.
        var s = resource
        if let r = s.range(of: "system/handler/") { s = String(s[r.upperBound...]) }
        return s
    }

    /// §6.2: user-installed handlers MUST NOT register at system/* paths.
    func isReservedSystemPattern(_ pattern: String) -> Bool {
        pattern == "system" || pattern.hasPrefix("system/")
    }

    // MARK: - Capability handler (§6.2)

    func capabilityHandler(operation: String, requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        switch operation {
        case "request":
            return try await capabilityRequest(requestID: requestID, ctx: ctx)
        case "delegate":
            // Delegate v1 is same-peer self-attenuation only; a remote caller → 501.
            return try errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")
        case "revoke":
            return try await capabilityRevoke(requestID: requestID, ctx: ctx)
        case "configure":
            return try await capabilityConfigure(requestID: requestID, ctx: ctx)
        default:
            return try errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")
        }
    }

    /// §6.2 request: mint a token bounded by the caller's authenticated cap (and
    /// the matched policy entry, if any). Subset-validation, not intersection.
    func capabilityRequest(requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        guard let p = params(ctx.execute), let requested = p.arrayAt("grants") else {
            return try errorResponse(requestID: requestID, status: 400, code: "bad_request")
        }
        guard let callerCap = ctx.callerCapability else {
            return try errorResponse(requestID: requestID, status: 403, code: "scope_exceeds_authority")
        }
        // Validate each requested grant is a subset of the caller's authenticated cap.
        let callerGrants = Capability.grants(of: callerCap)
        // §6.2 MINT-TIME subset check — the capability-handler surface, NOT the
        // §5.5 dispatch chain walk. Both sides stay on the LOCAL frame, matching
        // go and ocaml.
        //
        // This used to pass the caller cap's granter as `parentFrame`. For a
        // DELEGATED caller cap that frame is the caller's peer, and §5.5a
        // canonicalization makes a bare `*` granter-LOCAL — so the child's `["*"]`
        // became `/<thisPeer>/*` while the parent's identical `["*"]` became
        // `/<callerPeer>/*`, and a grant could not be a subset of ITSELF. Same
        // bare-star trap as A-PD-017, reached from the frame side rather than the
        // seed side.
        let requestedGrants = requested.map { Capability.GrantEntry.from($0) }
        for rg in requestedGrants {
            if !Capability.grantCoveredBy(rg, callerGrants, childFrame: localPeerID, parentFrame: localPeerID, localPeerID: localPeerID) {
                return try errorResponse(requestID: requestID, status: 403, code: "scope_exceeds_authority")
            }
        }
        // Mint the token with the requested grants, granted to the caller.
        guard let grantee = ctx.callerIdentityHash else {
            return try errorResponse(requestID: requestID, status: 403, code: "scope_exceeds_authority")
        }
        // §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). created_at is sampled
        // ONCE and the duration term converted against that same instant.
        //
        // Not an authorization decision: an over-long ttl_ms from a bounded caller
        // MINTS a clamped token at 200 -- "rejecting it is non-conformant" (§5.6).
        //
        // The previous line had no ceiling at all AND would TRAP on overflow --
        // Swift's `+` on UInt64 is checked, so an over-2^64 ttl_ms crashed the peer
        // instead of dropping the term as §5.6 rule 3 requires.
        let createdAt = nowMillis()
        let expiresAt = Capability.minDefined([
            callerCap.data.uintAt("expires_at"),               // absolute
            Capability.addTTL(createdAt, p.uintAt("ttl_ms")),  // duration -> absolute
        ])
        var tokenFields: [(String, CBORValue)] = [
            ("grants", .array(requested)),
            ("granter", .bytes(identity.identityHash)),
            ("grantee", .bytes(grantee)),
            ("created_at", .uint(createdAt)),
        ]
        if let e = expiresAt { tokenFields.append(("expires_at", .uint(e))) }
        let token = try Model.make(type: "system/capability/token", data: .textMap(tokenFields))
        let tokenSig = try identity.signatureEntity(target: token.hash)
        let grant = try Model.make(type: "system/capability/grant", fields: [("token", .bytes(token.hash))])
        pendingIncluded = [token, identity.peerEntity, tokenSig]
        return try okResponse(requestID: requestID, result: grant)
    }

    /// §6.2 revoke: write a revocation marker (and unbind a known storage path).
    func capabilityRevoke(requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        guard let p = params(ctx.execute), let token = p.bytesAt("token") else {
            return try errorResponse(requestID: requestID, status: 400, code: "unexpected_params")
        }
        // v7.62 §10: revoke-request.token MUST be non-zero (an all-zero hash is the
        // null/create-only sentinel, never a real cap hash).
        if token.allSatisfy({ $0 == 0 }) {
            return try errorResponse(requestID: requestID, status: 400, code: "unexpected_params")
        }
        let markerPath = "/" + localPeerID + "/system/capability/revocations/" + Hex.encode(token)
        let marker = try Model.make(type: "system/capability/revocation", fields: [
            ("token", .bytes(token)), ("revoked_at", .uint(nowMillis())),
        ])
        await store.bind(path: markerPath, marker.entity)
        let ok = try Model.emptyParams()
        return try okResponse(requestID: requestID, result: ok)
    }

    /// §6.2 configure: write a policy entry at system/capability/policy/{peer_pattern}.
    func capabilityConfigure(requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        guard let p = params(ctx.execute), let peerPattern = p.textAt("peer_pattern") else {
            return try errorResponse(requestID: requestID, status: 400, code: "unexpected_params")
        }
        // v7.62 §4: the peer_pattern is exact — `default`, a full identity-hash hex
        // (66 lowercase-hex chars: 1-byte format + 32-byte digest), or a full peer_id
        // (Base58). A partial-prefix form (e.g. `00abc*`) is explicitly rejected.
        let isFullHex = peerPattern.utf8.count == 66 && peerPattern.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66)
        }
        guard peerPattern == "default" || isFullHex || Capability.isPeerID(peerPattern) else {
            return try errorResponse(requestID: requestID, status: 400, code: "invalid_peer_pattern")
        }
        let entity = Entity(type: "system/capability/policy-entry", data: p,
                            contentHash: try? ContentHash.contentHash(type: "system/capability/policy-entry", data: p))
        await store.bind(path: "/" + localPeerID + "/system/capability/policy/" + peerPattern, entity)
        let ok = try Model.emptyParams()
        return try okResponse(requestID: requestID, result: ok)
    }

    // MARK: - §7a conformance handlers (GUIDE-CONFORMANCE §7a)

    /// `system/validate/echo` — proves §6.13a resolve→dispatch. Returns the params
    /// entity VERBATIM (`result.value == params.value`). NOTE the cohort bug: do
    /// NOT re-wrap the value as `{value: value}` — pass it THROUGH unchanged.
    func echoHandler(operation: String, requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        guard operation == "echo" else {
            return try errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")
        }
        // Return the params entity verbatim (the {value: X} entity, not a bare scalar).
        guard let pType = paramsType(ctx.execute), let pData = params(ctx.execute) else {
            let empty = try Model.emptyParams()
            return try okResponse(requestID: requestID, result: empty)
        }
        let result = try Model.make(type: pType, data: pData)
        return try okResponse(requestID: requestID, result: result)
    }

    /// `system/validate/dispatch-outbound` — proves §6.13b/§6.11: this peer
    /// ORIGINATES exactly one outbound EXECUTE back to the caller over the same
    /// inbound connection (reentry), awaits the response, and relays it VERBATIM.
    /// The relay MUST NOT re-wrap `value` (the §7b matrix pin). Cap-passing
    /// convention: in-band params (Go ruling (a)).
    func dispatchOutboundHandler(operation: String, requestID: String, ctx: HandlerContext) async throws -> BuiltEntity {
        guard operation == "dispatch" else {
            return try errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")
        }
        guard let outbound = ctx.outbound, let p = params(ctx.execute),
              let target = p.textAt("target"), let op = p.textAt("operation") else {
            return try errorResponse(requestID: requestID, status: 400, code: "invalid_params")
        }
        // §7a.2a in-band reentry authority (Go ruling (a)): the caller nested the
        // reentry cap + its granter peer + the cap signature as FULL materialized
        // entities directly under params (NOT hash references). The `value` field IS
        // the outbound params entity data — pass it THROUGH unchanged (re-wrapping as
        // `{value: value}` double-wraps → the echo's result.value returns a map; the
        // §7b t1_2 pin).
        // GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
        // single-granter case is an array of ONE. They were singular, which made
        // §1.4's multi-signature-root rule ungateable on the wire: driving it needs
        // two granter identities and two signatures, and a single-credential carrier
        // cannot express that input.
        //
        // TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one,
        // because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle
        // is what all 46 tracked reports are measured against and it sends the
        // SINGULAR names; a plural-only peer reads the triple as absent there, takes
        // the ambient arm and refuses — measured on the `go` vanguard as 2 of 778
        // severities moving PASS -> FAIL. Accepting both keeps the cohort 0-FAIL at
        // BOTH check sets. REMOVE THIS FALLBACK AT THE ORACLE RE-PIN, and not before:
        // the exit condition is that `tools/oracle-pin.env`'s `ref` names an oracle
        // whose dispatch-outbound probe sends the plural carriers.
        func entityList(_ key: String) -> [Entity]? {
            guard let arr = p.arrayAt(key) else { return nil }
            // An array whose members do not all decode is a MALFORMED carrier and is
            // nil, never a silently shorter list — the all-or-none test below would
            // otherwise read a partial credential as a complete one.
            var out: [Entity] = []
            for v in arr {
                guard let e = decodeEntity(v) else { return nil }
                out.append(e)
            }
            return out
        }
        let capEnt = decodeEntity(p.mapValue("reentry_capability"))
        let granterEnts = entityList("reentry_granters")
            ?? decodeEntity(p.mapValue("reentry_granter")).map { [$0] }
        let capSigEnts = entityList("reentry_cap_signatures")
            ?? decodeEntity(p.mapValue("reentry_cap_signature")).map { [$0] }
        guard let value = p.mapValue("value") else {
            return try errorResponse(requestID: requestID, status: 400, code: "invalid_params")
        }
        // The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED
        // arm, all three absent selects the AMBIENT arm, and a PARTIAL set is 400
        // invalid_params — a partial credential is malformed, not ambient. An empty
        // array is partial, not present: it carries no credential.
        let nPresent = [capEnt != nil, !(granterEnts ?? []).isEmpty, !(capSigEnts ?? []).isEmpty]
            .filter { $0 }.count
        guard nPresent == 0 || nPresent == 3 else {
            return try errorResponse(requestID: requestID, status: 400, code: "invalid_params")
        }
        let hasCred = nPresent == 3
        let cred = hasCred ? capEnt : nil
        let granters = hasCred ? (granterEnts ?? []) : []
        let capSigs = hasCred ? (capSigEnts ?? []) : []
        let outParams = try Model.primitiveAny(value)

        // §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer,
        // all four dimensions, on THIS handler's own grant — with a target-minted
        // credential relaxing Dimension 4 and nothing else. Consulting only the
        // presented credential here is the §6.8 confused-deputy bypass.
        guard try await authorizeOutboundSubDispatch(target: target, operation: op,
                                                     cred: cred, granters: granters,
                                                     capSigs: capSigs, ctx: ctx) else {
            // §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
            // transport- or gateway-class code would launder an authorization verdict
            // into a route fault, and the ambient and presented branches would then
            // disagree about what the same gate decided.
            return try errorResponse(requestID: requestID, status: 403, code: "capability_denied")
        }

        // We AUTHOR the reentry EXECUTE with our own key (author = us == grantee), sign
        // it, and bundle the reentry cap + its granter peers + our author identity + the
        // cap signatures + our exec signature into `included` (self-contained chain).
        //
        // The AMBIENT arm carries no credential, so the EXECUTE carries no `capability`
        // field and the bundle carries no cap, granter or cap-signature. An empty hash
        // would NOT do — that is a present field resolving to nothing, which §5.2 reads
        // as an unresolvable capability rather than as its absence.
        let outExec = try Wire.buildExecute(
            requestID: requestID + "-reentry", uri: target, operation: op, params: outParams,
            author: identity.identityHash, capability: hasCred ? capEnt?.contentHash : nil,
            resourceTargets: nil)
        let execSig = try identity.signatureEntity(target: outExec.hash)
        var execIncluded: [BuiltEntity] = []
        if hasCred, let c = capEnt {
            // Every granter and every signature goes into `included` because §5.5's
            // chain walk resolves them BY HASH out of that map — a granter left out is
            // a link the verifier cannot reach, which fails closed and reads as the
            // peer refusing the credential form rather than as a carrier we truncated.
            execIncluded.append(rebuild(c))
            execIncluded.append(contentsOf: granters.map { rebuild($0) })
            execIncluded.append(contentsOf: capSigs.map { rebuild($0) })
        }
        execIncluded.append(identity.peerEntity)
        execIncluded.append(execSig)

        // Originate over the inbound connection (§6.11 reentry). The transport
        // demuxes the EXECUTE_RESPONSE back to us by request_id.
        let outEnvBytes = try Wire.encodeEnvelope(root: outExec, included: execIncluded)
        let respEnv = try await outbound(outEnvBytes)
        // Relay the downstream result entity VERBATIM under `result` (no unwrapping).
        let downStatus = respEnv.root.data.uintAt("status") ?? 0
        let downResult = respEnv.root.data.mapValue("result") ?? .null
        let relay = try Model.make(type: "primitive/any", data: .textMap([
            ("status", .uint(downStatus)),
            ("result", downResult),
        ]))
        return try okResponse(requestID: requestID, result: relay)
    }

    /// §1.4's PD-2 gate, wired to this peer's store: resolve the executing handler's
    /// OWN grant, assemble the §7a.2a bundle, and run `checkOutboundSubDispatch`.
    ///
    /// The credential, its granters and its signatures arrive NESTED IN PARAMS
    /// (ratified shape (a), in-band), so they are NOT in `ctx.included` and a verifier
    /// handed that alone cannot resolve a single link — every credential then reads as
    /// invalid and the legitimate reentry is refused. The bundle merges them in, plus
    /// whatever the store already holds for the chain.
    func authorizeOutboundSubDispatch(
        target: String, operation: String, cred: Entity?, granters: [Entity],
        capSigs: [Entity], ctx: HandlerContext
    ) async throws -> Bool {
        let localPeerID = identity.peerID
        // §6.8: a handler with no valid grant does not run. Fail closed rather than
        // falling back to the credential, which is the substitution §6.8 forbids.
        // `ctx.pattern` is already PEER-RELATIVE (the dispatcher resolved it), and
        // `grantPath` tolerates either spelling regardless.
        guard let ownGrant = await store.getAt(
            path: Capability.grantPath(localPeerID: localPeerID, pattern: ctx.pattern)) else { return false }

        // §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends the
        // absolute form, so the URI names the target. Where the uri is PEER-RELATIVE
        // there is no peer in it and the §6.11 seam's destination is the CALLER — the
        // peer on the other end of the connection we reenter — so that is the fallback.
        // Without it Dimension 4 passes vacuously on the default {include: [local]} and
        // the exemption is never exercised.
        var targetPeerID = Capability.extractPeer(target, localPeerID: localPeerID)
        if targetPeerID == localPeerID, let callerHash = ctx.callerIdentityHash {
            // `??` is an autoclosure, which cannot carry an `await` — resolve the two
            // sources in sequence instead.
            var callerPeer = ctx.included[HashKey(callerHash)]
            if callerPeer == nil { callerPeer = await store.getByHash(callerHash) }
            if let cp = callerPeer, let pid = Capability.peerIDOf(cp) { targetPeerID = pid }
        }

        var bundle = ctx.included
        for e in ([cred].compactMap { $0 } + granters + capSigs) {
            if let h = e.contentHash { bundle[HashKey(h)] = e }
        }
        // Pull the chain's parents/granters/grantees out of the store too — the
        // credential may delegate from a token only the store holds.
        var frontier: [[UInt8]] = []
        if let c = cred { for k in ["parent", "granter", "grantee"] {
            if let h = c.data.bytesAt(k) { frontier.append(h) } } }
        var guardCount = 0
        while let h = frontier.popLast(), guardCount < 256 {
            guardCount += 1
            let key = HashKey(h)
            if bundle[key] == nil, let stored = await store.getByHash(h) {
                bundle[key] = stored
                for k in ["parent", "granter", "grantee"] {
                    if let nh = stored.data.bytesAt(k) { frontier.append(nh) }
                }
            }
        }
        let snapshot = bundle
        let resolver: Capability.Resolver = { h in snapshot[HashKey(h)] }
        // `target` arrives as any of §1.4's three spellings and the validator sends the
        // SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the resource
        // target want the PEER-RELATIVE path — §1.4's PD-2 block says so for Dimension
        // 1, and a resource target carrying a scheme is not a path at all.
        let relTarget = Capability.peerRelativeOf(target)
        let resource = Capability.ResourceTarget(
            targets: ["system/handler/" + relTarget], exclude: [])
        // Revocation is an async store read and the gate is sync, so it is resolved
        // HERE and handed in as an already-decided fact.
        var credRevoked = false
        if let c = cred, let ch = c.contentHash {
            credRevoked = await isRevoked(cap: c, capHash: ch, snapshot: snapshot)
        }
        return Capability.checkOutboundSubDispatch(
            localPeerID: localPeerID, targetPeerID: targetPeerID, handlerPattern: relTarget,
            operation: operation, handlerGrant: ownGrant, resource: resource, cred: cred,
            included: snapshot, now: nowMillis(), resolve: resolver,
            granterPeerID: { [self] c in granterPeerIDFrom(c, snapshot: snapshot) },
            isRevoked: { _ in credRevoked })
    }

    /// Rebuild a `BuiltEntity` (with wire bytes + content_hash) from an `Entity`
    /// decoded off the wire — re-renders through the codec so it can ride in
    /// `included`. The content_hash is recomputed (§7.1), not trusted from the wire.
    func rebuild(_ e: Entity) -> BuiltEntity {
        (try? Model.make(type: e.type, data: e.data)) ??
            BuiltEntity(entity: e, hash: e.contentHash ?? [], bytes: (try? e.encode()) ?? [])
    }
}
