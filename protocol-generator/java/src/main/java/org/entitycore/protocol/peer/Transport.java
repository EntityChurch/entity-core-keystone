package org.entitycore.protocol.peer;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import org.entitycore.protocol.codec.EntityCodecException;
import org.entitycore.protocol.crypto.EntityCryptoException;

/**
 * Transport (L4): TCP listener + dialer, per-connection reader threads, §6.11
 * request_id demux, the §4.8 inbound-concurrent-with-outbound dispatch, and the
 * §6.13(b) reentry seam. Plus the initiator dialer/handshake that drives the loopback.
 *
 * <p><b>Concurrency model (A-JAVA-003 validated): JDK 21 virtual threads + platform
 * threads.</b> One reader thread per connection demuxes inbound frames (§6.11): an
 * EXECUTE_RESPONSE routes to its awaiting outbound caller by request_id through a
 * {@link ConcurrentHashMap}{@code <requestId, SynchronousQueue>} correlation table; an
 * inbound EXECUTE is dispatched on its OWN virtual thread (§4.8) so a handler that
 * originates an outbound EXECUTE (§6.13(b)) and awaits its response does NOT block the
 * reader. Writes (inbound responses + outbound requests share the stream) are
 * serialized by a per-connection write lock. Virtual threads (Project Loom, JEP 444 GA
 * in 21) make one-thread-per-connection + one-thread-per-inbound-EXECUTE cheap — the
 * thread-per-connection model other peers justified against thread cost is the
 * RECOMMENDED carrier on Loom. The N7 demux is the 8-way concurrent check in the
 * smoke. Zero third-party dependency ({@code java.util.concurrent} is stdlib).
 */
public final class Transport {
    private Transport() { }

    /** Virtual-thread factory for connection readers + per-EXECUTE dispatch (§4.8). */
    private static final ThreadFactory VTF = Thread.ofVirtual().name("ec-vt-", 0).factory();

    // ── per-connection IO (shared by server + client) ──────────────────────────────

    /** Per-connection IO: the framed stream, the write lock, and the §6.11 demux table. */
    public static final class Io {
        private final Socket socket;
        private final DataInputStream in;
        private final OutputStream out;
        private final Object writeLock = new Object();
        // request_id → rendezvous queue; the reader hands the response to the waiter.
        private final ConcurrentHashMap<String, SynchronousQueue<Object>> pending =
                new ConcurrentHashMap<>();
        private volatile boolean closed;

        Io(Socket socket) throws IOException {
            this.socket = socket;
            this.in = new DataInputStream(socket.getInputStream());
            this.out = new BufferedOutputStream(socket.getOutputStream());
        }

        void writeFramed(Envelope env) throws EntityCodecException, EntityTransportException {
            byte[] payload = Wire.frameOfEnvelope(env);
            synchronized (writeLock) {
                Wire.writeFrame(out, payload);
            }
        }

        /** §6.13(b) outbound primitive: send a request envelope, await its correlated
         *  EXECUTE_RESPONSE (§6.11). Blocks the calling (dispatch worker) thread; the
         *  reader routes the response. Returns null if the connection closes first. */
        Envelope outbound(Envelope request) {
            String requestId = orEmpty(request.root().text("request_id"));
            SynchronousQueue<Object> q = new SynchronousQueue<>();
            pending.put(requestId, q);
            try {
                writeFramed(request);
                Object v;
                // poll in a loop so a close can wake us via the CLOSED sentinel.
                while (true) {
                    if (closed) {
                        return null;
                    }
                    v = q.poll(50, java.util.concurrent.TimeUnit.MILLISECONDS);
                    if (v != null) {
                        break;
                    }
                }
                return (v instanceof Envelope e) ? e : null;
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return null;
            } catch (EntityCodecException | EntityTransportException e) {
                return null;
            } finally {
                pending.remove(requestId);
            }
        }

        private void routeResponse(Envelope env) {
            String requestId = orEmpty(env.root().text("request_id"));
            SynchronousQueue<Object> q = pending.get(requestId);
            if (q != null) {
                q.offer(env);
            }
        }

        void close() {
            closed = true;
            try {
                socket.close();
            } catch (IOException ignore) {
                // best-effort
            }
        }
    }

    /** The reader loop (§6.11 demux): EXECUTE_RESPONSE → route; EXECUTE → dispatch on
     *  its own virtual thread (§4.8) + write the response. Returns when the connection
     *  closes / a malformed frame ends it. */
    static void readLoop(Peer peer, Conn conn, Io io) {
        try {
            while (true) {
                byte[] payload = Wire.readFrame(io.in);
                if (payload == null) {
                    break;                                 // clean EOF
                }
                Envelope env;
                try {
                    env = Wire.envelopeOfFrame(payload);
                } catch (RuntimeException | EntityCodecException bad) {
                    continue;                              // skip a malformed frame
                }
                if (env.root().type().equals("system/protocol/execute/response")) {
                    io.routeResponse(env);
                } else {
                    VTF.newThread(() -> {
                        Envelope resp;
                        try {
                            resp = peer.dispatch(conn, env);
                        } catch (RuntimeException e) {
                            resp = new Envelope(Wire.makeResponse(
                                    orEmpty(env.root().text("request_id")), 500,
                                    Wire.errorResult("internal_error", null)));
                        }
                        if (resp != null) {
                            try {
                                io.writeFramed(resp);
                            } catch (EntityCodecException | EntityTransportException ignore) {
                                // write failure ends this exchange; reader keeps going
                            }
                        }
                    }).start();
                }
            }
        } catch (EntityTransportException e) {
            // framing fault ends the connection
        } finally {
            io.close();
        }
    }

    // ── server: listener + accept loop ──────────────────────────────────────────────

    /** A running listener: the bound port plus a handle to stop it. */
    public static final class Listener implements AutoCloseable {
        private final ServerSocket server;
        private final int port;
        private final Thread acceptThread;

        Listener(ServerSocket server, int port, Thread acceptThread) {
            this.server = server;
            this.port = port;
            this.acceptThread = acceptThread;
        }

        public int port() {
            return port;
        }

        @Override
        public void close() {
            try {
                server.close();
            } catch (IOException ignore) {
                // best-effort
            }
            acceptThread.interrupt();
        }
    }

    /** Bind 127.0.0.1:port (0 = auto) and spawn the accept loop. */
    public static Listener startListener(Peer peer, int port) throws EntityTransportException {
        try {
            ServerSocket server = new ServerSocket();
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 64);
            int bound = server.getLocalPort();
            Thread accept = Thread.ofPlatform().name("ec-accept").daemon(true).unstarted(() -> {
                while (!server.isClosed()) {
                    Socket client;
                    try {
                        client = server.accept();
                    } catch (IOException e) {
                        break;                             // socket closed → stop
                    }
                    VTF.newThread(() -> serveConnection(peer, client)).start();
                }
            });
            accept.start();
            return new Listener(server, bound, accept);
        } catch (IOException e) {
            throw new EntityTransportException("listen failed", e);
        }
    }

    private static void serveConnection(Peer peer, Socket client) {
        try {
            Io io = new Io(client);
            Conn conn = new Conn();
            // wire the §6.13(b) outbound seam to this connection (§6.11 reentry).
            conn.outbound = io::outbound;
            readLoop(peer, conn, io);
        } catch (IOException e) {
            try {
                client.close();
            } catch (IOException ignore) {
                // best-effort
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // Client side — the dialer + initiator handshake (drives the two-peer loopback)
    // ══════════════════════════════════════════════════════════════════════════════

    /** A dialed, authenticated session (§4.4): the IO, the minted cap + granter + sig. */
    public static final class Session implements AutoCloseable {
        private final Io io;
        private final Identity local;
        private final AtomicInteger reqCounter = new AtomicInteger();
        String remotePeerId;
        Entity capability;       // the cap token the remote minted for us at connect
        Entity granterPeer;      // remote peer identity (the cap granter)
        Entity capSignature;     // signature over the cap

        Session(Io io, Identity local) {
            this.io = io;
            this.local = local;
        }

        public String remotePeerId() {
            return remotePeerId;
        }

        public Entity capability() {
            return capability;
        }

        private String nextRequestId() {
            return "req-" + reqCounter.incrementAndGet();
        }

        /** Send REQUEST and await its correlated EXECUTE_RESPONSE (request_id demux). */
        Envelope send(Envelope request) {
            return io.outbound(request);
        }

        /** Build, sign, and send an authenticated EXECUTE; await the response. The full
         *  §5.8 authority chain travels in {@code included}. */
        public Envelope execute(String uri, String operation, Entity params,
                                org.entitycore.protocol.codec.EcfValue.Map resource)
                throws EntityCryptoException {
            Entity exec = Wire.makeExecute(nextRequestId(), uri, operation, params,
                    local.identityHash(), capability.hash(), resource);
            Entity execSig = local.sign(exec);
            java.util.List<Envelope.Included> inc = new java.util.ArrayList<>();
            inc.add(new Envelope.Included(capability.hash(), capability));
            inc.add(new Envelope.Included(granterPeer.hash(), granterPeer));
            inc.add(new Envelope.Included(local.identityHash(), local.peerEntity()));
            inc.add(new Envelope.Included(capSignature.hash(), capSignature));
            inc.add(new Envelope.Included(execSig.hash(), execSig));
            return send(new Envelope(exec, inc));
        }

        @Override
        public void close() {
            io.close();
        }
    }

    /** Open a client connection to host:port and start its reader thread. */
    public static Session dial(Peer initiator, String host, int port)
            throws EntityTransportException, EntityCryptoException {
        try {
            Socket sock = new Socket(host, port);
            Io io = new Io(sock);
            Session session = new Session(io, initiator.identity());
            // the client reader: a core responder sends only EXECUTE_RESPONSEs; route them.
            Conn conn = new Conn();
            conn.outbound = io::outbound;
            VTF.newThread(() -> readLoop(initiator, conn, io)).start();
            handshake(session);
            return session;
        } catch (IOException e) {
            throw new EntityTransportException("dial failed", e);
        }
    }

    /** Drive the §4.1 forward handshake as initiator: hello then authenticate. On
     *  success, populate the session with the §4.4 capability the responder minted. */
    private static void handshake(Session s) throws EntityCryptoException, EntityTransportException {
        Identity local = s.local;
        // ── hello ──
        Entity hello = Entity.make("system/protocol/connect/hello",
                Cbor.map(
                        "peer_id", local.peerId(),
                        "nonce", Cbor.bytes(randomNonce()),
                        "protocols", Cbor.textArray("entity-core/1.0"),
                        "timestamp", org.entitycore.protocol.codec.EcfValue.Int.of(Capability.nowMs()),
                        "hash_formats", Cbor.textArray("ecfv1-sha256"),
                        "key_types", Cbor.textArray("ed25519")));
        Envelope r1 = s.send(new Envelope(
                Wire.makeExecute(s.nextRequestId(), "system/protocol/connect", "hello", hello)));
        requireOk(r1, "hello");
        Entity remoteHello = Wire.responseResult(r1);
        s.remotePeerId = remoteHello.text("peer_id");
        byte[] remoteNonce = remoteHello.bytes("nonce");

        // ── authenticate ──
        Entity auth = Entity.make("system/protocol/connect/authenticate",
                Cbor.map(
                        "peer_id", local.peerId(),
                        "public_key", Cbor.bytes(local.publicKey()),
                        "key_type", "ed25519",
                        "nonce", Cbor.bytes(remoteNonce)));
        Entity authSig = local.sign(auth);
        java.util.List<Envelope.Included> authInc = new java.util.ArrayList<>();
        authInc.add(new Envelope.Included(local.identityHash(), local.peerEntity()));
        authInc.add(new Envelope.Included(authSig.hash(), authSig));
        Envelope r2 = s.send(new Envelope(
                Wire.makeExecute(s.nextRequestId(), "system/protocol/connect", "authenticate", auth),
                authInc));
        requireOk(r2, "authenticate");

        // parse the §4.4 initial capability grant
        Entity grant = Wire.responseResult(r2);
        byte[] tokenH = grant.bytes("token");
        Entity token = r2.includedGet(tokenH);
        if (token == null) {
            throw new EntityTransportException("authenticate grant omits the capability token");
        }
        byte[] granterH = token.bytes("granter");
        Entity granterPeer = r2.includedGet(granterH);
        Entity capSig = Capability.findSignature(token.rawHash(), r2.included());
        if (granterPeer == null) {
            throw new EntityTransportException("authenticate grant omits the granter identity");
        }
        if (capSig == null) {
            throw new EntityTransportException("authenticate grant omits the capability signature");
        }
        s.capability = token;
        s.granterPeer = granterPeer;
        s.capSignature = capSig;
    }

    private static final java.security.SecureRandom NONCE_RNG = new java.security.SecureRandom();

    private static byte[] randomNonce() {
        byte[] b = new byte[32];
        NONCE_RNG.nextBytes(b);
        return b;
    }

    private static void requireOk(Envelope env, String step) throws EntityTransportException {
        if (env == null) {
            throw new EntityTransportException(step + " failed: no response");
        }
        int status = Wire.responseStatus(env);
        if (status != 200) {
            Entity r = Wire.responseResult(env);
            String code = (r != null) ? r.text("code") : null;
            String msg = (r != null) ? r.text("message") : null;
            throw new EntityTransportException(
                    step + " failed: " + status + " " + code + " " + (msg != null ? msg : ""));
        }
    }

    private static String orEmpty(String s) {
        return (s != null) ? s : "";
    }
}
