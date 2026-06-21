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
        let granterFrame = (await granterPeerID(of: callerCap)) ?? localPeerID
        let requestedGrants = requested.map { Capability.GrantEntry.from($0) }
        for rg in requestedGrants {
            if !Capability.grantCoveredBy(rg, callerGrants, childFrame: localPeerID, parentFrame: granterFrame) {
                return try errorResponse(requestID: requestID, status: 403, code: "scope_exceeds_authority")
            }
        }
        // Mint the token with the requested grants, granted to the caller.
        guard let grantee = ctx.callerIdentityHash else {
            return try errorResponse(requestID: requestID, status: 403, code: "scope_exceeds_authority")
        }
        var tokenFields: [(String, CBORValue)] = [
            ("grants", .array(requested)),
            ("granter", .bytes(identity.identityHash)),
            ("grantee", .bytes(grantee)),
            ("created_at", .uint(nowMillis())),
        ]
        if let ttl = p.uintAt("ttl_ms") { tokenFields.append(("expires_at", .uint(nowMillis() + ttl))) }
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
        guard let value = p.mapValue("value"),
              let capEnt = decodeEntity(p.mapValue("reentry_capability")),
              let granterEnt = decodeEntity(p.mapValue("reentry_granter")),
              let capSigEnt = decodeEntity(p.mapValue("reentry_cap_signature")),
              let capHash = capEnt.contentHash else {
            return try errorResponse(requestID: requestID, status: 400, code: "invalid_params")
        }
        let outParams = try Model.primitiveAny(value)

        // We AUTHOR the reentry EXECUTE with our own key (author = us == grantee), sign
        // it, and bundle the reentry cap + its granter peer + our author identity + the
        // cap signature + our exec signature into `included` (self-contained chain).
        let outExec = try Wire.buildExecute(
            requestID: requestID + "-reentry", uri: target, operation: op, params: outParams,
            author: identity.identityHash, capability: capHash, resourceTargets: nil)
        let execSig = try identity.signatureEntity(target: outExec.hash)
        let execIncluded: [BuiltEntity] = [
            rebuild(capEnt), rebuild(granterEnt), identity.peerEntity, rebuild(capSigEnt), execSig,
        ]

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

    /// Rebuild a `BuiltEntity` (with wire bytes + content_hash) from an `Entity`
    /// decoded off the wire — re-renders through the codec so it can ride in
    /// `included`. The content_hash is recomputed (§7.1), not trusted from the wire.
    func rebuild(_ e: Entity) -> BuiltEntity {
        (try? Model.make(type: e.type, data: e.data)) ??
            BuiltEntity(entity: e, hash: e.contentHash ?? [], bytes: (try? e.encode()) ?? [])
    }
}
