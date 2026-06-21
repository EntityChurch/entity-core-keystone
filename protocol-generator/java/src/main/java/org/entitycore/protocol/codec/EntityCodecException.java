package org.entitycore.protocol.codec;

import org.entitycore.protocol.EntityCoreException;

/**
 * Checked base for all codec-layer (ECF encode/decode) failures. Maps to a 400
 * {@code non_canonical_ecf} protocol status at the dispatcher boundary.
 */
public class EntityCodecException extends EntityCoreException {
    private static final long serialVersionUID = 1L;

    public EntityCodecException(String message) {
        super(message);
    }

    public EntityCodecException(String message, Throwable cause) {
        super(message, cause);
    }
}
