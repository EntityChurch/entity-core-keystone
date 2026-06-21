package org.entitycore.protocol.peer;

/**
 * §5.2 / §5.10 authorization (capability) denial — maps to wire status 403 at the
 * dispatcher boundary. A Layer-1 DENY verdict (§5.10 determinism).
 */
public final class AuthorizationException extends EntityProtocolException {
    private static final long serialVersionUID = 1L;

    public AuthorizationException(String message) {
        super(message);
    }
}
