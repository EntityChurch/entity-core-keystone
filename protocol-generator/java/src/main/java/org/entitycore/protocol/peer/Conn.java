package org.entitycore.protocol.peer;

import java.util.function.Function;

/**
 * Per-connection state (§4.2 connection state is per-connection). Holds the §4.1
 * handshake progress (issued nonce, the initiator's claimed peer_id, established flag)
 * and the §6.13(b) handler-facing outbound seam.
 *
 * <p>The {@code outbound} seam sends an EXECUTE envelope over THIS connection and awaits
 * its correlated EXECUTE_RESPONSE (§6.11 reentry); the transport sets it. It is null
 * when the request did not arrive over a reentrant connection (e.g. an in-process call).
 */
public final class Conn {
    volatile boolean established;
    volatile byte[] issuedNonce;          // nonce we issued in our hello response
    volatile String helloPeerId;          // initiator's claimed peer_id from hello

    /** §6.13(b) reentry seam: send-and-await over this connection; null if unavailable. */
    volatile Function<Envelope, Envelope> outbound;
    private int outCounter;

    synchronized int nextOutCounter() {
        return ++outCounter;
    }
}
