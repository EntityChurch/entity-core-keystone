package org.entitycore.protocol.peer;

/**
 * §4.6 / §5.2 authentication failure — maps to wire status 401 at the dispatcher
 * boundary. The §5.5 unresolvable-grantee carve-out (a grantee that cannot be
 * resolved is a 401, not a 403) is also signalled with this type.
 */
public final class AuthenticationException extends EntityProtocolException {
    private static final long serialVersionUID = 1L;

    public AuthenticationException(String message) {
        super(message);
    }
}
