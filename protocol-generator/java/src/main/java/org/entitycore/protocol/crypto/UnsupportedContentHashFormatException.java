package org.entitycore.protocol.crypto;

/** Receive-side: a content_hash format_code outside the allocated set
 *  ({@code 0x00}=sha256, {@code 0x01}=sha384). Status maps to the protocol's
 *  {@code unsupported_content_hash_format}. (Construct-side serializes the code
 *  verbatim; the receive/verify side rejects — A-OC-004 / A-CL-007 asymmetry.) */
public class UnsupportedContentHashFormatException extends EntityCryptoException {
    private static final long serialVersionUID = 1L;
    public UnsupportedContentHashFormatException(String message) { super(message); }
}
