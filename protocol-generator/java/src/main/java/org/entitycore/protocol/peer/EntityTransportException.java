package org.entitycore.protocol.peer;

/**
 * §1.6 / §6.12 transport-layer failure: a malformed frame, a frame exceeding the
 * §1.6 bound, or a closed connection during a framed read/write. Distinct from a
 * protocol-status failure — a transport fault ends the connection (§3.3 keeps every
 * EXECUTE answered only while the framing holds).
 */
public final class EntityTransportException extends EntityProtocolException {
    private static final long serialVersionUID = 1L;

    public EntityTransportException(String message) {
        super(message);
    }

    public EntityTransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
