package org.entitycore.protocol.peer;

import org.entitycore.protocol.EntityCoreException;

/**
 * Checked root of the peer-layer protocol error hierarchy (profile error_model =
 * {@code exceptions}, {@code checked = true}). A protocol-level failure that maps to
 * a wire status is a subtype ({@link AuthenticationException} → 401,
 * {@link AuthorizationException} → 403); the dispatcher boundary translates a thrown
 * subtype to its status code. Truly unexpected internal faults stay unchecked and
 * surface as a 500 at the connection boundary (per-request isolation).
 */
public class EntityProtocolException extends EntityCoreException {
    private static final long serialVersionUID = 1L;

    public EntityProtocolException(String message) {
        super(message);
    }

    public EntityProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
