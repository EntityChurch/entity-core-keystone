package org.entitycore.protocol.crypto;

import org.entitycore.protocol.EntityCoreException;

/** Checked base for crypto-layer failures (hash construction, key handling,
 *  sign/verify). */
public class EntityCryptoException extends EntityCoreException {
    private static final long serialVersionUID = 1L;
    public EntityCryptoException(String message) { super(message); }
    public EntityCryptoException(String message, Throwable cause) { super(message, cause); }
}
