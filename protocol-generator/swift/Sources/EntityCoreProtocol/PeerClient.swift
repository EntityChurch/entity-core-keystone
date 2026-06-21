// PeerClient.swift — the initiator side of a connection (§4.1 handshake + execute).
//
// A client-style initiator (§4.1 legs 1–2; client does not serve inbound — leg 3
// is reachability-gated and not sent). It dials, runs hello → authenticate, holds
// the session's initial capability (§4.4), and issues authenticated EXECUTEs. For
// the §6.13b reentry self-check the client ALSO runs a Connection reader so it can
// answer the target's reentrant EXECUTE (B-role on the same connection, §7a.2a).

import struct Foundation.Data

/// An established outbound session to a remote peer.
public final class PeerClient: @unchecked Sendable {
    public let identity: Identity
    public let connection: Connection
    private let socket: Socket
    /// Remote peer_id learned at hello.
    public private(set) var remotePeerID: String = ""
    /// The initial capability token hash delivered at authenticate (§4.4).
    public private(set) var capabilityHash: [UInt8]?
    /// The full included set from the authenticate response (token, granter, sig).
    public private(set) var capabilityIncluded: [HashKey: Entity] = [:]
    private var seq: UInt64 = 0
    private let seqLock = NSLockBox()

    /// Dial + handshake. `servePeer` (optional) makes this initiator ALSO answer
    /// inbound EXECUTEs on the connection (B-role for the §6.13b reentry self-check).
    public static func connect(to port: UInt16, identity: Identity, servePeer: Peer? = nil) async throws -> PeerClient {
        let socket = try Listener.dial(port: port)
        // The Connection's `peer` answers any inbound EXECUTE (reentry B-role). For a
        // pure client with no serve peer, supply `identity`'s own peer so an
        // unexpected inbound EXECUTE is handled rather than crashing; a client that
        // never receives one (legs 1–2) simply never uses it.
        let backingPeer: Peer
        if let sp = servePeer { backingPeer = sp } else { backingPeer = try await Peer(seed: identity.seed) }
        let conn = Connection(socket: socket, peer: backingPeer, connID: -1)
        let client = PeerClient(identity: identity, connection: conn, socket: socket)
        await conn.start()
        try await client.handshake()
        return client
    }

    init(identity: Identity, connection: Connection, socket: Socket) {
        self.identity = identity
        self.connection = connection
        self.socket = socket
    }

    func nextRequestID() -> String {
        seqLock.withLock { seq += 1; return "c-\(seq)" }
    }

    /// §4.1 legs 1–2: hello → authenticate.
    func handshake() async throws {
        // Leg 1: hello (EXECUTE on system/protocol/connect, no auth fields).
        let helloParams = try Model.make(type: "system/protocol/connect/hello", fields: [
            ("peer_id", .text(identity.peerID)),
            ("protocols", .array([.text("entity-core/1.0")])),
        ])
        let helloReqID = nextRequestID()
        let helloExec = try Wire.buildExecute(
            requestID: helloReqID, uri: "system/protocol/connect", operation: "hello", params: helloParams)
        let helloEnv = try Wire.encodeEnvelope(root: helloExec)
        let helloResp = try await connection.execute(helloEnv, requestID: helloReqID)
        let helloResult = helloResp.root.data.mapValue("result")?.mapValue("data")
        guard let nonce = helloResult?.bytesAt("nonce") else { throw SocketError.cannotConnect }
        remotePeerID = helloResult?.textAt("peer_id") ?? ""

        // Leg 2: authenticate. Build the authenticate entity, sign it, include the
        // peer + signature (§4.6).
        let authEntity = try Model.make(type: "system/protocol/connect/authenticate", fields: [
            ("peer_id", .text(identity.peerID)),
            ("public_key", .bytes(identity.publicKey)),
            ("key_type", .text("ed25519")),
            ("nonce", .bytes(nonce)),
        ])
        let sig = try identity.signatureEntity(target: authEntity.hash)
        let authReqID = nextRequestID()
        let authParams = try Model.make(type: "system/protocol/connect/authenticate", fields: [
            ("peer_id", .text(identity.peerID)),
            ("public_key", .bytes(identity.publicKey)),
            ("key_type", .text("ed25519")),
            ("nonce", .bytes(nonce)),
        ])
        let authExec = try Wire.buildExecute(
            requestID: authReqID, uri: "system/protocol/connect", operation: "authenticate", params: authParams)
        // included carries the signature over the authenticate entity + our peer.
        let authEnv = try Wire.encodeEnvelope(root: authExec, included: [sig, identity.peerEntity])
        let authResp = try await connection.execute(authEnv, requestID: authReqID)
        guard authResp.root.data.uintAt("status") == 200 else { throw SocketError.cannotConnect }
        // §4.4: result is system/capability/grant; token + granter + sig in included.
        capabilityHash = authResp.root.data.mapValue("result")?.mapValue("data")?.bytesAt("token")
        capabilityIncluded = authResp.included
    }

    /// Issue an authenticated EXECUTE. Builds + signs the EXECUTE, bundles author +
    /// capability + chain into `included`, awaits the response.
    public func execute(uri: String, operation: String, params: BuiltEntity,
                        resourceTargets: [String]? = nil, includeAuthority: Bool = true) async throws -> Envelope {
        let reqID = nextRequestID()
        let author = identity.identityHash
        let exec = try Wire.buildExecute(
            requestID: reqID, uri: uri, operation: operation, params: params,
            author: includeAuthority ? author : nil,
            capability: includeAuthority ? capabilityHash : nil,
            resourceTargets: resourceTargets)
        let sig = try identity.signatureEntity(target: exec.hash)
        var included: [BuiltEntity] = [sig, identity.peerEntity]
        if includeAuthority {
            // Bundle the capability chain (token + granter peer + token sig) from
            // the authenticate response's included (§5.8 full chain in included).
            for (_, e) in capabilityIncluded {
                included.append(BuiltEntity(entity: e, hash: e.contentHash ?? [], bytes: (try? e.encode()) ?? []))
            }
        }
        let env = try Wire.encodeEnvelope(root: exec, included: included)
        return try await connection.execute(env, requestID: reqID)
    }

    public func close() async { await connection.close() }
}
