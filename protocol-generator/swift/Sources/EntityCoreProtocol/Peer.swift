// Peer.swift — L1–L4 peer machinery: handlers, dispatch chain, bootstrap, §6.9a.
//
// CONCURRENCY MODEL (the Swift idiom probe). `Peer` is an `actor`: identity, the
// nonce table, and per-connection session state are actor-isolated. The `Store`
// is its own actor (§7b data-race-free). `async/await` carries all I/O; the
// transport (Transport.swift) drives `dispatch` and reentry. This actor/structured-
// concurrency model is genuinely distinct from all six prior peers (C# Tasks, TS
// event loop, OCaml/Zig threads+mutex, Elixir BEAM processes, CL conditions) — the
// store-race that bit Zig/CL is structurally impossible here (Store is an actor).
//
// Derived spec-first from §3–§6 of spec-data/v7.74. The dispatch chain (§6.5),
// resolution (§6.6), verify_request (§5.2), bootstrap (§6.9/§6.9a), the four MUST
// handlers (§6.2), register/unregister (§6.13a), emit (§6.10), and the §7a
// conformance handlers all live here; the capability algebra is in Capability.swift.

import Crypto
import struct Foundation.Data
#if canImport(Glibc)
import Glibc
#endif

/// Per-connection session state (§4.1/§4.2). Lives on the Peer actor.
final class Session: @unchecked Sendable {
    var helloReceived = false
    var established = false
    /// The nonce this peer issued in its hello response (§4.6 nonce-echo).
    var issuedNonce: [UInt8]?
    /// The remote's authenticated identity hash, set at authenticate.
    var remoteIdentityHash: [UInt8]?
    var remotePeerID: String?
    /// The remote's system/peer entity (ingested at authenticate).
    var remotePeerEntity: Entity?
}

/// The outbound-dispatch closure a handler uses to originate an EXECUTE over the
/// inbound connection (§6.13b reentry seam). Returns the EXECUTE_RESPONSE entity.
public typealias OutboundDispatch = @Sendable (_ executeEnvelopeBytes: [UInt8]) async throws -> Envelope

/// The handler execution context (§6.8). Implementation-defined representation;
/// carries what the spec mandates is available: the EXECUTE, the resolved handler
/// pattern + suffix, the resource target, caller identity/capability, the handler
/// grant, and the reentry outbound seam (§6.13b). `@unchecked Sendable`: only read
/// across the await boundary; the Peer actor owns mutation.
public final class HandlerContext: @unchecked Sendable {
    public let execute: Entity
    public let included: [HashKey: Entity]
    public let pattern: String
    public let suffix: String
    public let resourceTarget: Capability.ResourceTarget?
    public let callerIdentityHash: [UInt8]?
    public let callerCapability: Entity?
    /// §6.13b: originate an outbound EXECUTE back over the inbound connection.
    public let outbound: OutboundDispatch?

    init(execute: Entity, included: [HashKey: Entity], pattern: String, suffix: String,
         resourceTarget: Capability.ResourceTarget?, callerIdentityHash: [UInt8]?,
         callerCapability: Entity?, outbound: OutboundDispatch?) {
        self.execute = execute; self.included = included; self.pattern = pattern
        self.suffix = suffix; self.resourceTarget = resourceTarget
        self.callerIdentityHash = callerIdentityHash; self.callerCapability = callerCapability
        self.outbound = outbound
    }
}

public actor Peer {
    public let identity: Identity
    public let store: Store
    let seedPolicy: SeedPolicy
    let conformanceHandlers: Bool

    /// per-Session nonce-and-identity state; keyed by an opaque connection id.
    private var sessions: [Int: Session] = [:]

    /// Side-channel for a handler to attach result-side `included` entities (the
    /// minted token + granter peer + signature for authenticate/request). Set by a
    /// handler, read+cleared by `dispatch` into the DispatchResult (N5 result-side
    /// included preservation). Actor-isolated, so no race.
    var pendingIncluded: [BuiltEntity] = []

    public var localPeerID: String { identity.peerID }

    /// Construct a peer. `seedPolicy` drives §6.9a authority bootstrap (default:
    /// the conformant `standard()` policy). `conformanceHandlers` opt-in installs
    /// the §7a `system/validate/*` handlers (OFF by default — `dispatch-outbound`
    /// is a standing dialer never live in production).
    public init(seed: [UInt8], seedPolicy: SeedPolicy = .standard(), conformanceHandlers: Bool = false) async throws {
        self.identity = try Identity(seed: seed)
        self.store = Store()
        self.seedPolicy = seedPolicy
        self.conformanceHandlers = conformanceHandlers
        try await bootstrap()
    }

    // MARK: - Bootstrap (§6.9 + §6.9a)

    private func bootstrap() async throws {
        let p = identity.peerID
        // §6.9 step 2/3: publish core types at system/type/* (S3 seed; S4 full 53).
        try await TypeRegistry.publish(into: store, localPeerID: p)
        // Bind our own system/peer entity (identity surface).
        await store.bind(path: "/" + p + "/system/peer/" + Hex.encode(identity.identityHash), identity.peerEntity.entity)

        // §6.9 step 4-6: bootstrap handler manifests + interfaces + grants. Each
        // interface declares its §6.2 operation set (the handlers category matches
        // the required operations per pattern).
        let bootstrapHandlers: [(pattern: String, name: String, ops: [String])] = [
            ("system/tree", "Tree", ["get", "put"]),
            ("system/handler", "Handlers", ["register", "unregister"]),
            ("system/type", "Type", ["validate"]),
            ("system/capability", "Capability", ["request", "delegate", "revoke", "configure"]),
            ("system/protocol/connect", "Connect", ["hello", "authenticate"]),
        ]
        for h in bootstrapHandlers {
            try await installHandler(pattern: h.pattern, name: h.name, operations: h.ops)
        }

        // §6.9a peer-authority bootstrap: materialize the self-owner cap + policy
        // entries at L0 (detached-signature shape uniformly).
        try await materializeSeedPolicy()

        // §7a conformance scaffolding (opt-in, off by default).
        if conformanceHandlers {
            try await installHandler(pattern: "system/validate/echo", name: "system/validate/echo")
            try await installHandler(pattern: "system/validate/dispatch-outbound", name: "system/validate/dispatch-outbound")
        }
    }

    /// Install a handler at its pattern path: manifest (dispatch target), interface
    /// (discovery index), grant (authority), grant-signature (§3.5 invariant
    /// pointer). The five §6.2 writes (types are published separately at bootstrap).
    private func installHandler(pattern: String, name: String, operations: [String] = []) async throws {
        let p = identity.peerID
        // 1. manifest at the pattern path — type system/handler (dispatch target).
        let manifest = try Model.make(type: "system/handler", fields: [("interface", .text("system/handler/" + pattern))])
        await store.bind(path: "/" + p + "/" + pattern, manifest.entity)
        // 5. interface entity at system/handler/{pattern} (discovery index). The
        // `operations` map is the §6.2 operation set: key = op name, value = an
        // operation-spec data map (the oracle decodes the value as
        // HandlerOperationSpec, not a wrapped entity — bare empty map = no I/O types).
        let opPairs: [(key: CBORValue, value: CBORValue)] = operations.map { (.text($0), .map([])) }
        let iface = try Model.make(type: "system/handler/interface", fields: [
            ("pattern", .text(pattern)), ("name", .text(name)),
            ("operations", .map(opPairs)),
        ])
        await store.bind(path: "/" + p + "/system/handler/" + pattern, iface.entity)
        // 3. handler grant (self-issued: granter = grantee = local identity).
        let grant = try selfGrant(grants: [])
        await store.bind(path: "/" + p + "/system/capability/grants/" + pattern, grant.entity)
        // 4. grant-signature at system/signature/{grant_hash} (§3.5 / §6.2 convergence).
        let sig = try identity.signatureEntity(target: grant.hash)
        await store.bind(path: "/" + p + "/system/signature/" + Hex.encode(grant.hash), sig.entity)
    }

    /// A self-issued cap token (granter = grantee = local identity). §6.8 grant
    /// issuance contract: granter is local, signed by local key.
    private func selfGrant(grants: [CBORValue]) throws(CodecError) -> BuiltEntity {
        try Model.make(type: "system/capability/token", data: .textMap([
            ("grants", .array(grants)),
            ("granter", .bytes(identity.identityHash)),
            ("grantee", .bytes(identity.identityHash)),
            ("created_at", .uint(nowMillis())),
        ]))
    }

    /// §6.9a: write the self-owner cap (full scope over /{peer}/*) + the default
    /// (and named) policy entries at system/capability/policy/{key}, detached-sig.
    private func materializeSeedPolicy() async throws {
        let p = identity.peerID
        let selfHashHex = Hex.encode(identity.identityHash)
        // self-owner cap: root cap, full scope over the local namespace, grantee = self.
        let ownerGrant = SeedGrant(handlers: ["*"], resources: ["/" + p + "/*"], operations: ["*"]).toValue()
        let ownerCap = try selfGrant(grants: [ownerGrant])
        await store.bind(path: "/" + p + "/system/capability/policy/" + selfHashHex, ownerCap.entity)
        let ownerSig = try identity.signatureEntity(target: ownerCap.hash)
        await store.bind(path: "/" + p + "/system/signature/" + Hex.encode(ownerCap.hash), ownerSig.entity)

        // default + named entries as policy-entry caps (detached-sig token shape).
        for entry in seedPolicy.entries {
            let key = entry.grantee  // "default" | hex | base58; "self" handled above.
            if key == "self" { continue }
            let grantValues = entry.grants.map { $0.toValue() }
            let cap = try selfGrant(grants: grantValues)
            await store.bind(path: "/" + p + "/system/capability/policy/" + key, cap.entity)
            let sig = try identity.signatureEntity(target: cap.hash)
            await store.bind(path: "/" + p + "/system/signature/" + Hex.encode(cap.hash), sig.entity)
        }
    }

    // MARK: - Session lifecycle

    func session(_ id: Int) -> Session {
        if let s = sessions[id] { return s }
        let s = Session(); sessions[id] = s; return s
    }
    func dropSession(_ id: Int) { sessions.removeValue(forKey: id) }

    // MARK: - Dispatch chain (§6.5)

    /// The result of dispatching an inbound EXECUTE: the EXECUTE_RESPONSE entity
    /// plus any result-side `included` entities the handler attached (N5 — minted
    /// token + granter peer + signature for authenticate/request).
    public struct DispatchResult: Sendable {
        public let response: BuiltEntity
        public let included: [BuiltEntity]
    }

    /// Process an inbound envelope on connection `connID`. `outbound` is the §6.13b
    /// reentry closure (the transport supplies it so handlers can originate over the
    /// same connection). EXECUTE_RESPONSE roots are routed by the transport (demux),
    /// not here — this handles EXECUTE roots.
    public func dispatch(_ env: Envelope, connID: Int, outbound: OutboundDispatch?) async -> DispatchResult {
        pendingIncluded = []
        let response = await dispatchInner(env, connID: connID, outbound: outbound)
        let included = pendingIncluded
        pendingIncluded = []
        return DispatchResult(response: response, included: included)
    }

    private func dispatchInner(_ env: Envelope, connID: Int, outbound: OutboundDispatch?) async -> BuiltEntity {
        let root = env.root
        guard root.type == Wire.executeType else {
            // §3.3: not an EXECUTE here (EXECUTE_RESPONSE is demuxed by transport;
            // any other type → caller closes the connection).
            return (try? errorResponse(requestID: "", status: 400, code: "protocol_error")) ?? fallbackError()
        }
        let reqID = root.data.textAt("request_id") ?? ""
        let uri = root.data.textAt("uri") ?? ""
        let operation = root.data.textAt("operation") ?? ""
        let sess = session(connID)

        // Connection pre-authorization (§4.2): system/protocol/connect is the sole
        // pre-authorized path; no author/capability required.
        if isConnectPath(uri) && !sess.established {
            return await handleConnect(root: root, env: env, operation: operation, requestID: reqID, session: sess)
        }
        if isConnectPath(uri) && sess.established {
            return (try? errorResponse(requestID: reqID, status: 409, code: "connection_already_established")) ?? fallbackError()
        }

        // Any other path requires auth (§4.2): reject missing author/capability 403.
        // §5.2 verify_request.
        let verdict = await verifyRequest(env)
        switch verdict {
        case .authDeny:
            return (try? errorResponse(requestID: reqID, status: 401, code: "authentication_failed")) ?? fallbackError()
        case .unresolvableGrantee:
            return (try? errorResponse(requestID: reqID, status: 401, code: "unresolvable_grantee")) ?? fallbackError()
        case .authzDeny(let code):
            return (try? errorResponse(requestID: reqID, status: 403, code: code)) ?? fallbackError()
        case .chainTooDeep:
            return (try? errorResponse(requestID: reqID, status: 400, code: "chain_depth_exceeded")) ?? fallbackError()
        case .allow:
            break
        }

        // Ingest signatures from envelope.included (§6.5 dispatcher-level).
        await ingestSignatures(env)

        // Canonicalize URI; reject non-self peer (§1.4 inbound dispatch).
        let canonURI = Capability.canonicalize(uri, frame: localPeerID)
        let targetPeer = Capability.extractPeer(canonURI, localPeerID: localPeerID)
        if targetPeer != localPeerID {
            return (try? errorResponse(requestID: reqID, status: 400, code: "wrong_peer")) ?? fallbackError()
        }

        // Resolve handler (§6.6 longest-prefix tree walk).
        guard let resolved = await resolveHandler(canonURI) else {
            return (try? errorResponse(requestID: reqID, status: 404, code: "handler_not_found")) ?? fallbackError()
        }

        // check_permission (§5.2) — handler + operation + peer + resource. The
        // handler pattern is the relative form ("system/tree") used in grants.
        let caller = env.included(root.data.bytesAt("capability") ?? [])
        let resourceTarget = Capability.ResourceTarget.from(root.data.mapValue("resource"))
        let handlerPatternRel = patternRelative(resolved.pattern)
        if let cap = caller {
            let granterFrame = (await granterPeerID(of: cap)) ?? localPeerID
            let permitted = Capability.checkPermission(
                operation: operation, handlerPattern: handlerPatternRel, targetPeer: targetPeer,
                resourceTarget: resourceTarget, grants: Capability.grants(of: cap),
                localPeerID: localPeerID, granterFrame: granterFrame)
            if !permitted {
                return (try? errorResponse(requestID: reqID, status: 403, code: "capability_denied")) ?? fallbackError()
            }
        }

        // Build context + dispatch to the resolved handler body.
        let ctx = HandlerContext(
            execute: root, included: env.included, pattern: handlerPatternRel, suffix: resolved.suffix,
            resourceTarget: resourceTarget, callerIdentityHash: root.data.bytesAt("author"),
            callerCapability: caller, outbound: outbound)
        return await invokeHandler(pattern: handlerPatternRel, operation: operation, requestID: reqID, ctx: ctx)
    }

    // MARK: - verify_request (§5.2)

    func verifyRequest(_ env: Envelope) async -> Verdict {
        let execute = env.root
        // 1. content hash check.
        guard let claimedHash = execute.contentHash,
              let recomputed = try? Entity(type: execute.type, data: execute.data).computeContentHash(),
              recomputed.elementsEqual(claimedHash) else {
            return .authzDeny(code: "capability_denied")  // tampered envelope (§5.2 step 1)
        }
        // 2. signature (authentication-class).
        guard let author = execute.data.bytesAt("author") else { return .authDeny }
        guard let sig = Wire.findSignature(target: claimedHash, in: env.included) else { return .authDeny }
        guard let sigSigner = sig.data.bytesAt("signer"), sigSigner.elementsEqual(author) else { return .authDeny }
        // §5.2 authentication: the author identity MUST travel in `included` (§3.3 —
        // the caller proves who it is on the wire, not by store reference). Absent
        // from included → authentication-class failure (401), not a store fallback.
        guard let authorEntity = env.included(author) else { return .authDeny }
        guard Capability.verifySignature(sig, by: authorEntity) else { return .authDeny }

        // 3. capability (authorization-class).
        guard let capHash = execute.data.bytesAt("capability") else { return .authzDeny(code: "capability_denied") }
        let capOpt: Entity?
        if let inc = env.included(capHash) { capOpt = inc } else { capOpt = await store.getByHash(capHash) }
        guard let cap = capOpt else { return .authzDeny(code: "capability_denied") }
        // chain verification (§5.5). Build a merged resolver snapshot: envelope
        // `included` (carries the full chain per §5.8) plus any store-held identity
        // entities (our own peer entity, ingested remote peers). Pre-resolving into
        // a sync dict lets the §5.5 closures run without re-entering the Store actor.
        var snapshot: [HashKey: Entity] = env.included
        // Walk the chain collecting parent/granter/grantee hashes, fetching from
        // the store any not already in `included`.
        var frontier: [[UInt8]] = []
        func enqueue(_ e: Entity) {
            for k in ["parent", "granter", "grantee"] { if let h = e.data.bytesAt(k) { frontier.append(h) } }
        }
        enqueue(cap)
        var guardCount = 0
        while let h = frontier.popLast(), guardCount < 256 {
            guardCount += 1
            let key = HashKey(h)
            if snapshot[key] == nil, let stored = await store.getByHash(h) {
                snapshot[key] = stored
                enqueue(stored)
            } else if let e = snapshot[key] {
                enqueue(e)
            }
        }
        // Also resolve granter peer entities (for the §5.5a granter-frame) from store.
        let resolver: Capability.Resolver = { h in snapshot[HashKey(h)] }
        // §4.10(b) resource bound: a chain exceeding max depth is rejected as 400
        // chain_depth_exceeded (structural excess) BEFORE the per-link authz walk —
        // distinct from 403 capability_denied. Arch v7.75 ruling: 400 lets the caller
        // distinguish "shorten your chain" from "you lack the capability".
        if Capability.chainExceedsDepth(cap, resolve: resolver) { return .chainTooDeep }
        let chainVerdict = Capability.verifyChain(
            cap, included: env.included, localPeerID: localPeerID, now: nowMillis(),
            resolve: resolver, granterPeerID: { [self] c in granterPeerIDFrom(c, snapshot: snapshot) })
        // The chain's per-link unresolvable-grantee (§5.5, 401) MUST take precedence
        // over the §5.2 grantee==author mismatch (403, AUTHZ-GRANTEE-1) — so the chain
        // verdict is consumed BEFORE the request-level grantee==author check.
        guard chainVerdict == .allow else { return chainVerdict }
        // §5.2: the presented (leaf) cap's grantee MUST be the request author.
        guard let grantee = cap.data.bytesAt("grantee"), grantee.elementsEqual(author) else {
            return .authzDeny(code: "capability_denied")
        }
        // §5.1 is_revoked: a revocation marker at system/capability/revocations/{hash}
        // for the presented (leaf) cap OR its chain root → 403 capability_denied
        // (RULING-CLASS-C: the (403, capability_denied) member, our verifier has no
        // separate is_revoked sentinel string on the core floor).
        if await isRevoked(cap: cap, capHash: capHash, snapshot: snapshot) {
            return .authzDeny(code: "capability_denied")
        }
        return .allow
    }

    /// §5.1 revocation marker check: covers the presented (leaf) cap hash and the
    /// chain-root cap hash (revoking the root cascades to every delegated child).
    func isRevoked(cap: Entity, capHash: [UInt8], snapshot: [HashKey: Entity]) async -> Bool {
        // Walk parent links to the chain root.
        var rootHash = capHash
        var cur = cap
        var guardCount = 0
        while let parent = cur.data.bytesAt("parent"), guardCount < 256 {
            guardCount += 1
            guard let parentEntity = snapshot[HashKey(parent)] else { break }
            rootHash = parent
            cur = parentEntity
        }
        for h in [capHash, rootHash] {
            let path = "/" + localPeerID + "/system/capability/revocations/" + Hex.encode(h)
            if await store.isBound(path: path) { return true }
        }
        return false
    }

    /// granter peer_id from a snapshot dict (sync; for the §5.5 closures).
    nonisolated func granterPeerIDFrom(_ cap: Entity, snapshot: [HashKey: Entity]) -> String? {
        guard let granterHash = cap.data.bytesAt("granter") else { return nil }
        if granterHash.elementsEqual(identity.identityHash) { return identity.peerID }
        if let peer = snapshot[HashKey(granterHash)], let pk = peer.data.bytesAt("public_key") {
            return try? PeerID.fromEd25519(publicKey: pk).format()
        }
        return nil
    }

    // MARK: - Handler resolution (§6.6)

    struct Resolved { let pattern: String; let suffix: String }

    /// §6.6 longest-prefix tree walk: walk path segments down to 1, first
    /// system/handler entity is the longest-prefix match.
    func resolveHandler(_ path: String) async -> Resolved? {
        let segs = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        var i = segs.count
        while i >= 2 {  // segs[0] is "" (leading slash), segs[1] is peer
            let prefix = segs[0..<i].joined(separator: "/")
            if let e = await store.getAt(path: prefix), e.type == "system/handler" {
                let suffix = String(path.dropFirst(prefix.count))
                return Resolved(pattern: prefix, suffix: suffix)
            }
            i -= 1
        }
        return nil
    }

    // MARK: - Handler bodies

    func invokeHandler(pattern: String, operation: String, requestID: String, ctx: HandlerContext) async -> BuiltEntity {
        do {
            switch pattern {
            case "system/tree": return try await treeHandler(operation: operation, requestID: requestID, ctx: ctx)
            case "system/handler": return try await handlersHandler(operation: operation, requestID: requestID, ctx: ctx)
            case "system/capability": return try await capabilityHandler(operation: operation, requestID: requestID, ctx: ctx)
            case "system/type": return try await typeHandler(operation: operation, requestID: requestID, ctx: ctx)
            case "system/validate/echo": return try await echoHandler(operation: operation, requestID: requestID, ctx: ctx)
            case "system/validate/dispatch-outbound": return try await dispatchOutboundHandler(operation: operation, requestID: requestID, ctx: ctx)
            default:
                return try errorResponse(requestID: requestID, status: 501, code: "unsupported_operation")
            }
        } catch {
            return (try? errorResponse(requestID: requestID, status: 500, code: "internal_error")) ?? fallbackError()
        }
    }

    // MARK: helpers shared with handlers (in PeerHandlers.swift)

    func errorResponse(requestID: String, status: UInt64, code: String, message: String? = nil) throws(CodecError) -> BuiltEntity {
        let err = try Wire.errorEntity(code: code, message: message)
        return try Wire.buildResponse(requestID: requestID, status: status, result: err)
    }

    func okResponse(requestID: String, result: BuiltEntity) throws(CodecError) -> BuiltEntity {
        try Wire.buildResponse(requestID: requestID, status: 200, result: result)
    }

    func fallbackError() -> BuiltEntity {
        // Only reachable if codec encoding itself fails (it does not for these
        // fixed shapes). A non-throwing last resort so dispatch always returns.
        let e = Entity(type: "system/protocol/error", data: .textMap([("code", .text("internal_error"))]), contentHash: nil)
        return BuiltEntity(entity: e, hash: [], bytes: [])
    }

    func isConnectPath(_ uri: String) -> Bool {
        uri == "system/protocol/connect" || uri.hasSuffix("/system/protocol/connect")
    }

    /// Strip the /{peer}/ prefix from a canonical handler pattern to the relative
    /// form used in grants/scopes ("system/tree").
    func patternRelative(_ patternPath: String) -> String {
        // patternPath is /{peer}/rest — drop "/" + peer + "/".
        let trimmed = patternPath.hasPrefix("/") ? String(patternPath.dropFirst()) : patternPath
        if let slash = trimmed.firstIndex(of: "/") { return String(trimmed[trimmed.index(after: slash)...]) }
        return trimmed
    }

    // MARK: - Signature ingestion (§6.5 dispatcher-level)

    func ingestSignatures(_ env: Envelope) async {
        for (_, e) in env.included where e.type == "system/signature" {
            await store.putEntity(e)
            guard let signerHash = e.data.bytesAt("signer"), let target = e.data.bytesAt("target") else { continue }
            // recover signer peer_id; ingest its peer entity if present.
            let signerPeer = (await store.getByHash(signerHash)) ?? env.included(signerHash)
            guard let sp = signerPeer, let pk = sp.data.bytesAt("public_key") else { continue }
            await store.putEntity(sp)
            guard let peerID = try? PeerID.fromEd25519(publicKey: pk).format() else { continue }
            let path = "/" + peerID + "/system/signature/" + Hex.encode(target)
            if await store.hashAt(path: path) == nil {
                await store.bind(path: path, e)
            }
        }
    }

    // MARK: - granter-frame resolution (§5.5a)

    /// The granter peer_id of a cap, by resolving granter → system/peer → peer_id.
    /// Async path (uses the store).
    func granterPeerID(of cap: Entity) async -> String? {
        guard let granterHash = cap.data.bytesAt("granter") else { return nil }
        let peer = await store.getByHash(granterHash)
        guard let pk = peer?.data.bytesAt("public_key") else {
            // self-cap: granter is our own identity.
            if granterHash.elementsEqual(identity.identityHash) { return localPeerID }
            return nil
        }
        return try? PeerID.fromEd25519(publicKey: pk).format()
    }

}

/// Wall-clock milliseconds since the Unix epoch (§6.2 timestamp convention).
func nowMillis() -> UInt64 {
    var ts = timespec()
    clock_gettime(CLOCK_REALTIME, &ts)
    return UInt64(ts.tv_sec) * 1000 + UInt64(ts.tv_nsec) / 1_000_000
}
