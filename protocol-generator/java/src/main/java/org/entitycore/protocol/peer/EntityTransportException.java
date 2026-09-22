package org.entitycore.protocol.peer;

/**
 * §1.6 / §6.12 transport-layer failure: a malformed frame, a frame exceeding the
 * §1.6 bound, or a closed connection during a framed read/write. Distinct from a
 * protocol-status failure — a transport fault ends the connection (§3.3 keeps every
 * EXECUTE answered only while the framing holds).
 */
public class EntityTransportException extends EntityProtocolException {
    // NOT `final`: §4.11 (0.8.2.25) makes the two framing refusals carry DIFFERENT codes
    // (`413 payload_too_large` and `400 invalid_request`), so the read loop has to tell
    // them apart by CAUSE. A classifier that recognises the cause by matching on
    // `getMessage()` is one string edit away from silently re-collapsing them.

    private static final long serialVersionUID = 1L;

    public EntityTransportException(String message) {
        super(message);
    }

    public EntityTransportException(String message, Throwable cause) {
        super(message, cause);
    }
}
