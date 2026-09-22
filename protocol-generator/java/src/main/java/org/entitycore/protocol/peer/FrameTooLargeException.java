package org.entitycore.protocol.peer;

/**
 * A length prefix over the connection's bound (§4.10(a)).
 *
 * <p>Distinguished from {@link TruncatedFrameException} because §4.11 gives the two
 * DIFFERENT codes: this one is {@code 413 payload_too_large}, and since 0.8.2.25 (N14)
 * emitting it is a MUST rather than a SHOULD.
 */
public class FrameTooLargeException extends EntityTransportException {
    private static final long serialVersionUID = 1L;

    public FrameTooLargeException(String message) {
        super(message);
    }
}
