package org.entitycore.protocol.peer

import org.entitycore.protocol.EcfResult
import org.entitycore.protocol.EntityError
import org.entitycore.protocol.codec.CanonicalCbor
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
    /**
     * §4.11's table (0.8.2.25): the `(status, code, message)` a pre-admission failure's
     * CAUSE takes.
     *
     * *"The frame obligation belongs to the class; the CODE belongs to the cause
     * `[MUST]`"* — a single code for the class would answer an honest caller under the
     * wrong reason and send them to the wrong layer.
     *
     * | cause | answer | stated at |
     * |---|---|---|
     * | connect-auth proof-of-possession | `401 authentication_failed` | §4.6/§4.7 — the connect handler's |
     * | envelope over the configured max | `413 payload_too_large` | §4.10(a), N14 |
     * | resolution integrity (mis-keyed `included`) | `400 hash_mismatch` | §5.2a, §1.8 |
     * | framing / never becomes an Envelope | `400 invalid_request` | §4.7, §4.11 |
     * | root is neither EXECUTE nor EXECUTE_RESPONSE | `400 invalid_request` | in the loop, not here |
     *
     * THE TAG ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules that code
     * non-conformant *"on the framing arm"* and gives its reason in the same sentence:
     * `ENTITY-CBOR-ENCODING` *"defines that code for CBOR tag-policy violations
     * specifically"*, which that document still MUSTs at decode time (§6.3). The two rows
     * are disjoint by CAUSE rather than in conflict: a tag in a DATA-FIELD position is the
     * policy violation with its own code, while a tag in the fixed envelope or
     * entity-wrapper maps is a structurally invalid frame — i.e. the framing arm. Everything
     * else this decoder calls non-canonical (a non-minimal head, an indefinite length,
     * mis-ordered keys) is genuinely "non-canonical CBOR that never becomes an Envelope" and
     * takes `invalid_request`.
     *
     * The messages are a FIXED TABLE, never the internal exception text: a wire-visible
     * string must stay ASCII (two peers in this cohort have been killed at runtime by a
     * non-ASCII byte in an encoded string, on two unrelated compilers), and nothing here
     * echoes attacker-supplied bytes back.
     */
    internal fun preAdmissionRefusal(e: Throwable): Triple<Int, String, String> = when {
        e is FrameTooLargeException ->
            Triple(413, "payload_too_large", "inbound frame exceeds the configured maximum size")
        e is HashMismatchException ->
            Triple(400, "hash_mismatch", "an entity was addressed by a hash that does not bind to it")
        e is CodecRefusalException && e.error is EntityError.CodecError.TagRejected ->
            Triple(400, "non_canonical_ecf", "CBOR tags are forbidden anywhere in an entity data field")
        else -> Triple(400, "invalid_request", "frame did not decode into an envelope")
    }

    /**
     * Recover ONLY the `request_id` from a frame the strict decoder rejected, so the refusal
     * can be delivered CORRELATED rather than as §4.11's uncorrelated best-effort frame.
     * `""` when nothing is recoverable.
     *
     * The frame stays rejected: nothing is built from it, nothing is stored, and a tag is
     * never interpreted — the salvage decode exists solely to read back the correlation key.
     * The envelope and entity-wrapper shapes are fixed maps with no legal tag position, so a
     * frame whose ONLY defect is a tag inside some entity's `data` still has a structurally
     * sound root, which is exactly the case worth recovering (and the one CAP-6a's `>2^64`
     * half arrives as — a bignum can only reach a peer as a major-type-6 tag).
     */
    private fun salvageRequestId(payload: ByteArray): String = try {
        val v = (CanonicalCbor.decodeSalvage(payload) as? EcfResult.Ok)?.value
        val root = Cbor.asMap((v as? EcfValue.MapVal)?.get("root"))
        (Cbor.asMap(root?.get("data"))?.get("request_id") as? EcfValue.Text)?.value ?: ""
    } catch (bad: Exception) {
        ""
    }

    /**
     * Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
     * refused BEFORE it becomes an admitted request.
     *
     * *"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
     * wire `[MUST]` — correlated by `request_id` where the id is available, and otherwise as
     * a best-effort coded frame carrying no correlation."*
     *
     * §4.9(c)'s deliver-or-signal rule is scoped to *"every request the peer ADMITS"* and
     * therefore reaches none of these, which is why §4.11 exists. Both of the non-conformant
     * behaviours it names separately were present on this peer: DROPPING the frame (the
     * un-salvageable decode arm and the non-EXECUTE root, *"the weaker of the two precisely
     * because nothing surfaces it"*) and CLOSING with no coded frame (the oversize and
     * truncated arms).
     *
     * AN EMPTY `requestId` IS THE BEST-EFFORT FORM, not a bug: it is what the section
     * prescribes where no id can be recovered.
     */
    private fun refusePreAdmission(io: Io, requestId: String, cause: Throwable) {
        val (status, code, message) = preAdmissionRefusal(cause)
        writeRefusal(io, requestId, status, code, message)
    }

    private fun writeRefusal(io: Io, requestId: String, status: Int, code: String, message: String) {
        try {
            io.writeFramed(Envelope(Wire.makeResponse(requestId, status, Wire.errorResult(code, message))))
        } catch (ignore: Exception) {
            // A write failure here is a dead socket, not a protocol decision; the read
            // loop's own error handling ends the connection on the next iteration.
        }
    }

    private fun readLoop(peer: Peer, conn: Conn, io: Io, scope: CoroutineScope) {
        try {
            while (true) {
                val payload = try {
                    Wire.readFrame(io.dataInput) ?: break // clean EOF
                } catch (refusal: EntityTransportException) {
                    if (refusal is FrameTooLargeException || refusal is TruncatedFrameException) {
                        // The stream is desynchronized on both REFUSABLE arms — an oversize
                        // body was never drained, a truncated one never arrived — so the
                        // coded frame goes out and THEN the connection closes. §4.11 makes
                        // the frame mandatory and leaves the close to us; closing is the
                        // only sound choice once the framing is lost, and it is a CHOICE
                        // rather than an alternative to answering. An ordinary hangup is not
                        // a refusal and gets nothing, which is what the EOF arm separates.
                        //
                        // §4.11's best-effort UNCORRELATED form: no request_id can be
                        // recovered from a frame whose body never arrived, and guessing one
                        // would correlate the refusal to somebody else's in-flight request.
                        refusePreAdmission(io, "", refusal)
                    }
                    break
                }
                val env = try {
                    Wire.envelopeOfFrame(payload)
                } catch (bad: Exception) {
                    // A COMPLETE frame the decoder refused. The framing is intact, so we
                    // answer and KEEP SERVING — and the refusal MUST be a STATUS, not
                    // silence (§4.11). Skipping it satisfies only the first half of the
                    // sentence and leaves the sender blocked until its own timeout, so a
                    // refusal is indistinguishable from a dead peer. §4.9(c) says the same
                    // from the other direction.
                    //
                    // THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered
                    // `non_canonical_ecf` for every cause until 0.8.2.24/.25 pinned them
                    // apart: a mis-keyed `included` entry is `400 hash_mismatch` (its
                    // encoding is canonical — what is false is the claim the key makes), a
                    // tag-policy violation keeps `non_canonical_ecf`, and everything else
                    // that never becomes an Envelope is `400 invalid_request`.
                    refusePreAdmission(io, salvageRequestId(payload), bad)
                    continue
                }
                if (env.root.type == "system/protocol/execute/response") {
                    io.routeResponse(env)
                } else if (env.root.type != "system/protocol/execute") {
                    // §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
                    // invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare
                    // close — that is indistinguishable from a network fault."
                    //
                    // §3.3 read "the connection MUST be closed", assigning no code and
                    // requiring no frame; this peer did something weaker still — `dispatch`
                    // answers null for a non-EXECUTE root and the loop wrote NOTHING, which
                    // is §4.11's silent-drop failure. §9.1's floor row that MANDATED the bare
                    // close was REPLACED at the same revision (N18).
                    //
                    // The request_id is read best-effort: an arbitrary root type is under no
                    // obligation to carry one, and §4.11 licenses the uncorrelated frame
                    // exactly there. We do NOT close — on a multiplexed connection that would
                    // cost every ADMITTED in-flight request its response.
                    writeRefusal(
                        io, env.root.text("request_id") ?: "", 400, "invalid_request",
                        "root entity is neither EXECUTE nor EXECUTE_RESPONSE",
                    )
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
