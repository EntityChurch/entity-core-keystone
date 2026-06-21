package org.entitycore.protocol.codec;

/** Wire bytes are not canonical ECF (indefinite length, non-minimal arg, trailing
 *  bytes, reserved additional-info, max-depth, bad simple value). Status 400. */
public class NonCanonicalEcfException extends EntityCodecException {
    private static final long serialVersionUID = 1L;
    public NonCanonicalEcfException(String message) { super(message); }
}
