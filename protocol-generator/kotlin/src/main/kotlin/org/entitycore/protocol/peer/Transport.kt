package org.entitycore.protocol.peer

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.entitycore.protocol.codec.EcfValue
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Transport (L4): TCP listener + dialer, per-connection reader, §6.11 request_id demux,
 * the §4.8 inbound-concurrent-with-outbound dispatch, and the §6.13(b) reentry seam.
 * Plus the initiator dialer/handshake that drives the loopback.
 *
 * **Concurrency model (A-KT-003 validated): kotlinx.coroutines + dedicated reader OS
 * threads.** This is the Kotlin-native shape and the axis where the peer diverges from
 * Java (Java = platform/virtual threads; Kotlin = structured coroutines over a thread
 * pool). One **dedicated OS thread per connection** runs the blocking framed read loop —
 * the §7b transport rule: NEVER run a blocking syscall (`read`/`accept`) on a bounded
 * cooperative coroutine pool (it would starve `Dispatchers.Default`); blocking I/O lives
 * on dedicated threads, and the dispatched WORK runs as coroutines on
 * [Dispatchers.IO]. The reader demuxes inbound frames (§6.11): an EXECUTE_RESPONSE
 * routes to its awaiting outbound caller by request_id through a
 * `ConcurrentHashMap<requestId, CompletableDeferred<Envelope>>` correlation table (the
 * coroutine analogue of Java's CompletableFuture / OCaml's per-thread demux); an inbound
 * EXECUTE is dispatched in its OWN coroutine (§4.8) so a handler that originates an
 * outbound EXECUTE (§6.13(b)) and `await`s its response does NOT block the reader.
 * Writes are serialized by a per-connection write lock. The N7 demux is the 8-way
 * concurrent check in the smoke. The one non-stdlib runtime dep is kotlinx-coroutines
 * (profile [deps]); the sockets are stdlib `java.net`.
 */
object Transport {

    /** Per-connection IO: the framed stream, the write lock, and the §6.11 demux table. */
    class Io(private val socket: Socket) {
        private val input = DataInputStream(socket.getInputStream())
        private val out: OutputStream = BufferedOutputStream(socket.getOutputStream())
        private val writeLock = Any()
        // request_id → completion; the reader completes it with the correlated response.
        private val pending = ConcurrentHashMap<String, CompletableDeferred<Envelope?>>()

        @Volatile private var closed = false

        init {
            socket.tcpNoDelay = true // §7b: TCP_NODELAY on raw-socket peers
        }

        internal val dataInput: DataInputStream get() = input

        fun writeFramed(env: Envelope) {
            val payload = Wire.frameOfEnvelope(env)
            synchronized(writeLock) { Wire.writeFrame(out, payload) }
        }

        /** §6.13(b) outbound primitive: send a request envelope, suspend-await its
         *  correlated EXECUTE_RESPONSE (§6.11). The reader routes the response. Returns
         *  null if the connection closes first or the wait times out (§6.12). */
        suspend fun outbound(request: Envelope): Envelope? {
            val requestId = request.root.text("request_id") ?: ""
            val deferred = CompletableDeferred<Envelope?>()
            pending[requestId] = deferred
            try {
                writeFramed(request)
                if (closed) return null
                return withTimeoutOrNull(30_000) { deferred.await() }
            } catch (e: EntityTransportException) {
                return null
            } finally {
                pending.remove(requestId)
            }
        }

        internal fun routeResponse(env: Envelope) {
            val requestId = env.root.text("request_id") ?: ""
            pending.remove(requestId)?.complete(env)
        }

        fun close() {
            closed = true
            // wake any waiters so a reentrant outbound doesn't hang past close (→ null).
            for (d in pending.values) d.complete(null)
            try {
                socket.close()
            } catch (ignore: IOException) {
                // best-effort
            }
        }
    }

    /** A running listener: the bound port plus a handle to stop it. */
    class Listener(
        private val server: ServerSocket,
        val port: Int,
        private val scope: CoroutineScope,
        private val job: Job,
    ) : AutoCloseable {
        override fun close() {
            try {
                server.close()
            } catch (ignore: IOException) {
                // best-effort
            }
            job.cancel()
        }
    }

    /** The reader loop (§6.11 demux): EXECUTE_RESPONSE → route; EXECUTE → dispatch in its
     *  own coroutine (§4.8) + write the response. Runs on a dedicated OS thread (§7b: the
     *  blocking framed read never sits on the cooperative pool). Returns when the
     *  connection closes / a malformed frame ends it. */
    private fun readLoop(peer: Peer, conn: Conn, io: Io, scope: CoroutineScope) {
        try {
            while (true) {
                val payload = Wire.readFrame(io.dataInput) ?: break // clean EOF
                val env = try {
                    Wire.envelopeOfFrame(payload)
                } catch (bad: Exception) {
                    continue // skip a malformed frame (§4.9: don't crash, keep serving)
                }
                if (env.root.type == "system/protocol/execute/response") {
                    io.routeResponse(env)
                } else {
                    // §4.8 inbound concurrent with outbound: dispatch on its own coroutine
                    // (Dispatchers.IO) so a handler can reenter (§6.11) without blocking
                    // this reader.
                    scope.launch(Dispatchers.IO) {
                        val resp = try {
                            peer.dispatch(conn, env)
                        } catch (e: RuntimeException) {
                            Envelope(Wire.makeResponse(env.root.text("request_id") ?: "", 500,
                                Wire.errorResult("internal_error", null)))
                        }
                        if (resp != null) {
                            try {
                                io.writeFramed(resp)
                            } catch (ignore: EntityTransportException) {
                                // write failure ends this exchange; reader keeps going
                            }
                        }
                    }
                }
            }
        } catch (e: EntityTransportException) {
            // framing fault ends the connection
        } finally {
            io.close()
        }
    }

    /** Bind 127.0.0.1:port (0 = auto) and spawn the accept loop. */
    fun startListener(peer: Peer, port: Int): Listener {
        val server = ServerSocket()
        server.reuseAddress = true
        server.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 64)
        val bound = server.localPort
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        // accept on a dedicated OS thread (blocking accept off the cooperative pool, §7b).
        val acceptThread = thread(name = "ec-accept", isDaemon = true) {
            while (!server.isClosed) {
                val client = try {
                    server.accept()
                } catch (e: IOException) {
                    break // socket closed → stop
                }
                serveConnection(peer, client, scope)
            }
        }
        val job = scope.launch { /* keep scope alive for the listener's lifetime */ }
        return Listener(server, bound, scope, job).also {
            // tie the accept thread to the job's cancellation.
            scope.coroutineContext[Job]!!.invokeOnCompletion { acceptThread.interrupt() }
        }
    }

    private fun serveConnection(peer: Peer, client: Socket, scope: CoroutineScope) {
        val io = try {
            Io(client)
        } catch (e: IOException) {
            try { client.close() } catch (ignore: IOException) {}
            return
        }
        val conn = Conn()
        // wire the §6.13(b) outbound seam to this connection (§6.11 reentry).
        conn.outbound = { env -> io.outbound(env) }
        // dedicated reader thread per connection (§7b: blocking read off the pool).
        thread(name = "ec-reader", isDaemon = true) { readLoop(peer, conn, io, scope) }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // Client side — the dialer + initiator handshake (drives the two-peer loopback)
    // ══════════════════════════════════════════════════════════════════════════════

    /** A dialed, authenticated session (§4.4): the IO, the minted cap + granter + sig. */
    class Session internal constructor(private val io: Io, private val local: Identity) : AutoCloseable {
        private val reqCounter = AtomicInteger()
        var remotePeerId: String? = null
            internal set
        var capability: Entity? = null
            internal set
        /** The remote peer identity that granted the session cap (the §4.4 granter). */
        var granterPeer: Entity? = null
            internal set
        /** The signature over the session cap (travels with it in `included`). */
        var capSignature: Entity? = null
            internal set

        internal fun nextRequestId(): String = "req-${reqCounter.incrementAndGet()}"

        /** Send REQUEST and await its correlated EXECUTE_RESPONSE (request_id demux). */
        suspend fun send(request: Envelope): Envelope? = io.outbound(request)

        /** Build, sign, and send an authenticated EXECUTE; await the response. The full
         *  §5.8 authority chain travels in `included`. */
        suspend fun execute(uri: String, operation: String, params: Entity, resource: EcfValue.MapVal?): Envelope? {
            val cap = capability!!
            val exec = Wire.makeExecute(nextRequestId(), uri, operation, params,
                local.identityHash(), cap.hash(), resource)
            val execSig = local.sign(exec)
            val inc = listOf(
                Envelope.Included(cap.hash(), cap),
                Envelope.Included(granterPeer!!.hash(), granterPeer!!),
                Envelope.Included(local.identityHash(), local.peerEntity),
                Envelope.Included(capSignature!!.hash(), capSignature!!),
                Envelope.Included(execSig.hash(), execSig),
            )
            return send(Envelope(exec, inc))
        }

        override fun close() {
            io.close()
        }
    }

    /** Open a client connection to host:port and start its reader thread, then drive the
     *  §4.1 forward handshake. Returns the authenticated session. */
    fun dial(initiator: Peer, host: String, port: Int): Session = runBlocking {
        val sock = try {
            Socket(host, port)
        } catch (e: IOException) {
            throw EntityTransportException("dial failed", e)
        }
        val io = Io(sock)
        val session = Session(io, initiator.identity)
        // the client reader: a core responder sends only EXECUTE_RESPONSEs; route them. A
        // reentrant inbound EXECUTE (§6.11) is dispatched on its own coroutine too.
        val conn = Conn()
        conn.outbound = { env -> io.outbound(env) }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        thread(name = "ec-client-reader", isDaemon = true) { readLoop(initiator, conn, io, scope) }
        handshake(session, initiator.identity)
        session
    }

    /** Drive the §4.1 forward handshake as initiator: hello then authenticate. On
     *  success, populate the session with the §4.4 capability the responder minted. */
    private suspend fun handshake(s: Session, local: Identity) {
        // ── hello ──
        val hello = Entity.make("system/protocol/connect/hello",
            Cbor.map(
                "peer_id", local.peerId,
                "nonce", Cbor.bytes(randomNonce()),
                "protocols", Cbor.textArray("entity-core/1.0"),
                "timestamp", EcfValue.IntVal.of(Capability.nowMs()),
                "hash_formats", Cbor.textArray("ecfv1-sha256"),
                "key_types", Cbor.textArray("ed25519"),
            ))
        val r1 = s.send(Envelope(Wire.makeExecute(s.nextRequestId(), "system/protocol/connect", "hello", hello)))
        requireOk(r1, "hello")
        val remoteHello = Wire.responseResult(r1!!)!!
        s.remotePeerId = remoteHello.text("peer_id")
        val remoteNonce = remoteHello.bytes("nonce")!!

        // ── authenticate ──
        val auth = Entity.make("system/protocol/connect/authenticate",
            Cbor.map(
                "peer_id", local.peerId,
                "public_key", Cbor.bytes(local.publicKey()),
                "key_type", "ed25519",
                "nonce", Cbor.bytes(remoteNonce),
            ))
        val authSig = local.sign(auth)
        val authInc = listOf(
            Envelope.Included(local.identityHash(), local.peerEntity),
            Envelope.Included(authSig.hash(), authSig),
        )
        val r2 = s.send(Envelope(
            Wire.makeExecute(s.nextRequestId(), "system/protocol/connect", "authenticate", auth), authInc))
        requireOk(r2, "authenticate")

        // parse the §4.4 initial capability grant
        val grant = Wire.responseResult(r2!!)!!
        val tokenH = grant.bytes("token")!!
        val token = r2.includedGet(tokenH)
            ?: throw EntityTransportException("authenticate grant omits the capability token")
        val granterH = token.bytes("granter")!!
        val granterPeer = r2.includedGet(granterH)
            ?: throw EntityTransportException("authenticate grant omits the granter identity")
        val capSig = Capability.findSignature(token.rawHash(), r2.included)
            ?: throw EntityTransportException("authenticate grant omits the capability signature")
        s.capability = token
        s.granterPeer = granterPeer
        s.capSignature = capSig
    }

    private val NONCE_RNG = java.security.SecureRandom()

    private fun randomNonce(): ByteArray {
        val b = ByteArray(32)
        NONCE_RNG.nextBytes(b)
        return b
    }

    private fun requireOk(env: Envelope?, step: String) {
        if (env == null) throw EntityTransportException("$step failed: no response")
        val status = Wire.responseStatus(env)
        if (status != 200) {
            val r = Wire.responseResult(env)
            val code = r?.text("code")
            val msg = r?.text("message")
            throw EntityTransportException("$step failed: $status $code ${msg ?: ""}")
        }
    }
}
