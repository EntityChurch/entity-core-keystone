package org.entitycore.protocol.codec;

/** A canonical ECF map must not repeat a key; a duplicate was seen on decode.
 *  Status 400. */
public class DuplicateKeyException extends EntityCodecException {
    private static final long serialVersionUID = 1L;
    public DuplicateKeyException(String message) { super(message); }
}
