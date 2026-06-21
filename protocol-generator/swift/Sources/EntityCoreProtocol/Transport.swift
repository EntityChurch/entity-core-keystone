// Transport.swift — L4: TCP listener/dialer + per-connection actor with reentrant
// demux (§6.11), inbound-concurrent-with-outbound (§4.8), request_id correlation
// (N7), and the §6.13b handler-outbound reentry seam.
//
// CONCURRENCY MODEL. Each connection is a `Connection` actor owning the pending-
// response table (request_id → continuation) and the outbound request_id counter.
// A single reader runs in a detached Task doing BLOCKING frame reads (on the
// concurrency pool, so it doesn't stall cooperative tasks):
//   - EXECUTE_RESPONSE → resume the awaiting continuation by request_id (§6.11(b)
//     out-of-order tolerant; N7 demux). NOT serialized on the reader.
//   - EXECUTE         → dispatch CONCURRENTLY on a child Task (§4.8 — inbound
//     processing never blocks on outbound, and the reader keeps reading). The
//     handler gets the §6.13b `outbound` closure that originates back over THIS
//     same connection (reentry) and awaits the correlated reply.
// Writes are serialized by the Socket's mutex. Per-request deadlines are at the
// request layer (§6.11(c)), not connection-wide. This actor/structured-concurrency
// model is distinct from all six prior peers (threads/event-loops/BEAM).

import struct Foundation.Data

/// A live connection: reader-demux + reentrant outbound. Bridges blocking socket
/// I/O to the async Peer actor.
public actor Connection {
    private let socket: Socket
    private let peer: Peer
    private let connID: Int
    private var nextRequestSeq: UInt64 = 0
    /// request_id → continuation awaiting an EXECUTE_RESPONSE (§6.11 demux).
    private var pending: [String: CheckedContinuation<Envelope, Error>] = [:]
    private var readerTask: Task<Void, Never>?
    private var closed = false
    /// Liveness flag readable WITHOUT entering the actor (for the server's churn
    /// prune). Set false once the reader loop has torn down.
    private let active = AtomicFlag(true)
    public nonisolated var readerActive: Bool { active.value }

    public init(socket: Socket, peer: Peer, connID: Int) {
        self.socket = socket
        self.peer = peer
        self.connID = connID
    }

    /// Start the reader loop. Returns immediately; the loop runs until EOF/close.
    public func start() {
        readerTask = Task { [weak self] in
            await self?.readLoop()
        }
    }

    /// Block until the reader loop finishes (used by the server-side serve task).
    public func wait() async {
        await readerTask?.value
    }

    private func readLoop() async {
        // Blocking reads happen on a detached task so the actor isn't pinned; each
        // frame is handed back onto the actor for demux.
        while !closed {
            // Blocking read on a DEDICATED OS thread (§7b): a blocking read parked on
            // the small cooperative pool starves accepts/other readers under churn
            // (t2_2 i/o-timeout). A fresh thread per read keeps the pool free.
            let frameOpt = await onBlockingThread { [socket] in
                socket.readFrame()
            }
            guard let frame = frameOpt else { break }   // EOF / connection broken
            guard let env = try? Wire.decodeEnvelope(frame) else { break } // §3.3 malformed → close
            await handleFrame(env)
        }
        await teardown()
    }

    private func handleFrame(_ env: Envelope) async {
        let rootType = env.root.type
        if rootType == Wire.responseType {
            // EXECUTE_RESPONSE → demux to the awaiting caller by request_id (N7).
            let reqID = env.root.data.textAt("request_id") ?? ""
            if let cont = pending.removeValue(forKey: reqID) {
                cont.resume(returning: env)
            }
            // (an unmatched response is dropped — no awaiter)
        } else if rootType == Wire.executeType {
            // EXECUTE → dispatch CONCURRENTLY (§4.8). The reader keeps reading; the
            // handler may originate outbound over this same connection (reentry).
            let connID = self.connID
            let outbound = self.makeOutbound()
            Task { [weak self, peer] in
                let result = await peer.dispatch(env, connID: connID, outbound: outbound)
                guard let self else { return }
                if let bytes = try? Wire.encodeEnvelope(root: result.response, included: result.included) {
                    await self.send(bytes)
                }
            }
        } else {
            // §3.3: any other root type is invalid → close the connection.
            await teardown()
        }
    }

    /// The §6.13b outbound-dispatch seam: send an EXECUTE over THIS connection and
    /// await the correlated EXECUTE_RESPONSE (reentry to the caller). The caller's
    /// request_id is taken from the EXECUTE envelope (the handler set it).
    private func makeOutbound() -> OutboundDispatch {
        return { [weak self] envBytes in
            guard let self else { throw SocketError.cannotConnect }
            return try await self.originate(envBytes)
        }
    }

    /// Originate an outbound EXECUTE (handler reentry) and await its response.
    func originate(_ envBytes: [UInt8]) async throws -> Envelope {
        // Decode to recover the request_id used for correlation.
        let env = try Wire.decodeEnvelope(envBytes)
        let reqID = env.root.data.textAt("request_id") ?? freshRequestID()
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Envelope, Error>) in
            if closed { cont.resume(throwing: SocketError.cannotConnect); return }
            pending[reqID] = cont
            if !socket.writeFrame(envBytes) {
                pending.removeValue(forKey: reqID)
                cont.resume(throwing: SocketError.cannotConnect)
            }
        }
    }

    /// Send an outbound EXECUTE and await the correlated EXECUTE_RESPONSE. Used by
    /// the client side (handshake + post-handshake requests). N7 demux.
    public func execute(_ envBytes: [UInt8], requestID: String) async throws -> Envelope {
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Envelope, Error>) in
            if closed { cont.resume(throwing: SocketError.cannotConnect); return }
            pending[requestID] = cont
            if !socket.writeFrame(envBytes) {
                pending.removeValue(forKey: requestID)
                cont.resume(throwing: SocketError.cannotConnect)
            }
        }
    }

    /// Serialized send of a response frame (no awaiter).
    func send(_ bytes: [UInt8]) async {
        _ = socket.writeFrame(bytes)
    }

    func freshRequestID() -> String {
        nextRequestSeq += 1
        return "req-\(connID)-\(nextRequestSeq)"
    }

    func teardown() async {
        if closed { return }
        closed = true
        active.value = false
        // Resolve all in-flight requests with a connection-broken error (§6.11
        // informative teardown contract) so callers aren't left hanging.
        for (_, cont) in pending { cont.resume(throwing: SocketError.cannotConnect) }
        pending.removeAll()
        socket.close()
        await peer.dropSession(connID)
    }

    public func close() async { await teardown() }
}

/// The server: accept loop, one Connection per inbound socket.
public actor Server {
    let listener: Listener
    let peer: Peer
    private var nextConnID = 0
    private var connections: [Connection] = []
    private var acceptTask: Task<Void, Never>?

    public var port: UInt16 { listener.port }

    public init(peer: Peer, port: UInt16) throws {
        self.peer = peer
        self.listener = try Listener(port: port)
    }

    /// Start accepting. Each accepted socket gets its own Connection actor whose
    /// reader runs concurrently (one reader per connection — §4.8/§6.11).
    public func start() {
        acceptTask = Task { [weak self] in
            await self?.acceptLoop()
        }
    }

    private func acceptLoop() async {
        while true {
            // Blocking accept on a dedicated OS thread (§7b — same rationale as the
            // per-connection reader: never park the accept on the cooperative pool).
            let sockOpt = await onBlockingThread { [listener] in
                listener.accept()
            }
            guard let sock = sockOpt else { break }
            let id = nextConnID; nextConnID += 1
            let conn = Connection(socket: sock, peer: peer, connID: id)
            // Prune connections that have finished (churn would otherwise grow this
            // unboundedly); cheap since a closed reader Task self-completes.
            connections = connections.filter { $0.readerActive }
            connections.append(conn)
            await conn.start()
        }
    }

    public func stop() async {
        acceptTask?.cancel()
        listener.close()
        for c in connections { await c.close() }
        connections.removeAll()
    }
}

/// A mutex-guarded Bool readable from any isolation domain (the churn-prune liveness
/// flag). A pthread mutex keeps it in Glibc — no Foundation/atomics dependency.
final class AtomicFlag: @unchecked Sendable {
    private var flag: Bool
    private let lock = NSLockBox()
    init(_ initial: Bool) { self.flag = initial }
    var value: Bool {
        get { lock.withLock { flag } }
        set { lock.withLock { flag = newValue } }
    }
}
