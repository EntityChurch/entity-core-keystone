package org.entitycore.protocol.codec;

/** Decode ran off the end of the input buffer (a length or argument promised more
 *  bytes than are present). Status 400. */
public class TruncatedInputException extends EntityCodecException {
    private static final long serialVersionUID = 1L;
    public TruncatedInputException(String message) { super(message); }
}
