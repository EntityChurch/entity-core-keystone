package org.entitycore.protocol.crypto;

/** A key_type code outside the allocated set ({@code 0x01}=ed25519,
 *  {@code 0x02}=ed448). */
public class UnsupportedKeyTypeException extends EntityCryptoException {
    private static final long serialVersionUID = 1L;
    public UnsupportedKeyTypeException(String message) { super(message); }
}
