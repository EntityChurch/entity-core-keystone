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

    /// Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
    /// refused BEFORE it becomes an admitted request.
    ///
    /// > "A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on
    /// > the wire `[MUST]` — correlated by `request_id` where the id is available, and
    /// > otherwise as a best-effort coded frame carrying no correlation."
    ///
    /// §4.9(c)'s deliver-or-signal rule is scoped to *"every request the peer ADMITS"*
    /// and therefore reaches NONE of these, which is why §4.11 exists. The two
    /// non-conformant behaviours it names are SEPARATE failures and this peer had one of
    /// each: DROPPING the frame (the un-salvageable arm below fell through to silence —
    /// *"the weaker of the two precisely because nothing surfaces it"*) and CLOSING with
    /// no coded frame (the oversize/truncated arm, which broke out of the read loop, and
    /// the non-EXECUTE root, which called `teardown()` directly).
    ///
    /// An EMPTY `requestID` IS the best-effort form, not a bug: it is what the section
    /// prescribes where no id can be recovered.
    private func refusePreAdmission(requestID: String, status: UInt64, code: String) async {
        guard let err = try? Wire.errorEntity(code: code, message: nil),
              let root = try? Wire.buildResponse(requestID: requestID, status: status, result: err),
              let bytes = try? Wire.encodeEnvelope(root: root) else { return }
        await send(bytes)
    }

    private func readLoop() async {
        // Blocking reads happen on a detached task so the actor isn't pinned; each
        // frame is handed back onto the actor for demux.
        while !closed {
            // Blocking read on a DEDICATED OS thread (§7b): a blocking read parked on
            // the small cooperative pool starves accepts/other readers under churn
            // (t2_2 i/o-timeout). A fresh thread per read keeps the pool free.
            let outcome = await onBlockingThread { [socket] in
                socket.readFrame()
            }
            let frame: [UInt8]
            switch outcome {
            case .closed:
                // An ordinary hangup at a frame boundary. Not a refusal of anything and
                // nobody left to answer (§4.11).
                await teardown()
                return
            case .refused(let e):
                // The stream is desynchronized — an oversize body was never drained, a
                // truncated one never arrived — so the coded frame goes out and THEN the
                // loop ends. §4.11 makes the frame mandatory and leaves the close to us;
                // closing is the only sound choice once the framing is lost, and it is a
                // choice rather than an alternative to answering.
                let r = Wire.preAdmissionRefusal(e)
                await refusePreAdmission(requestID: "", status: r.status, code: r.code)
                await teardown()
                return
            case .frame(let f):
                frame = f
            }
            do {
                let env = try Wire.decodeEnvelope(frame)
                await handleFrame(env)
            } catch let error as CodecError {
                // A COMPLETE frame the decoder refused. The framing is intact, so we
                // answer and KEEP SERVING — this used to tear the connection down, then
                // (once that was fixed) still dropped the frame whenever the request_id
                // was unrecoverable, which left the sender blocked until its own §6.11(c)
                // deadline and made a refusal indistinguishable from a dead peer.
                //
                // THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered
                // `non_canonical_ecf` for EVERY cause until 0.8.2.24/.25 pinned them
                // apart: a mis-keyed `included` entry is 400 `hash_mismatch` (its encoding
                // is canonical — what is false is the claim the key makes), a tag-policy
                // violation keeps `non_canonical_ecf`, and everything else that never
                // becomes an Envelope is 400 `invalid_request`.
                //
                // The frame is still REJECTED — we only salvage enough to correlate the
                // response, and an unrecoverable id yields the uncorrelated best-effort
                // frame rather than silence.
                let r = Wire.preAdmissionRefusal(error)
                await refusePreAdmission(requestID: Wire.salvageRequestID(frame) ?? "",
                                         status: r.status, code: r.code)
            }
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
            // §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
            // invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare
            // close — that is indistinguishable from a network fault."
            //
            // §3.3 read "the connection MUST be closed", assigning no code and requiring
            // no frame, and §9.1's floor row MANDATED it; N18 replaced that row. This
            // peer did exactly the bare close, which §4.11 names as non-conformant and
            // which on a multiplexed connection costs every ADMITTED in-flight request
            // its response.
            //
            // This is a PRE-ADMISSION refusal: the root is not an EXECUTE, so nothing was
            // ever admitted and §4.9(c) — scoped to "every request the peer ADMITS" —
            // does not reach it. `request_id` is read best-effort: an arbitrary root type
            // is under no obligation to carry one, and §4.11 licenses the uncorrelated
            // frame exactly there. We do NOT close; §4.11 leaves that to us.
            //
            // The peer layer's own arm for this (`dispatchInner`'s non-EXECUTE guard) is
            // unreachable from here by construction — the transport decides which roots
            // reach dispatch — so the code is fixed HERE, where the wire observes it.
            // Both sites now answer `invalid_request` rather than diverging.
            await refusePreAdmission(requestID: env.root.data.textAt("request_id") ?? "",
                                     status: 400, code: "invalid_request")
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
