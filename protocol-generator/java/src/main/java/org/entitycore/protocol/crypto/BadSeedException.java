package org.entitycore.protocol.crypto;

/** A signing seed has the wrong length for its curve (Ed25519 = 32 bytes,
 *  Ed448 = 57 bytes). */
public class BadSeedException extends EntityCryptoException {
    private static final long serialVersionUID = 1L;
    public BadSeedException(String message) { super(message); }
}
