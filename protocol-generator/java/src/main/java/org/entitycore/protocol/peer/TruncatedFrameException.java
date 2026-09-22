package org.entitycore.protocol.peer;

/**
 * A frame that never completed: a prefix declaring {@code n} bytes followed by fewer.
 * §4.11's framing arm names this input outright — <em>"un-parseable, truncated or
 * non-canonical CBOR, or a length prefix that never completes"</em> →
 * {@code 400 invalid_request}.
 *
 * <p>A SEPARATE TYPE FROM A CLEAN EOF because the two are different events and the stream
 * collapses them. A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing;
 * a stream that ends MID-FRAME is a REFUSAL and is owed a coded frame. This reader
 * previously reported both as a bare {@link EntityTransportException} that ended the loop
 * in silence, which is §4.11's other named non-conformant behaviour.
 */
public class TruncatedFrameException extends EntityTransportException {
    private static final long serialVersionUID = 1L;

    public TruncatedFrameException(String message, Throwable cause) {
        super(message, cause);
    }
}
