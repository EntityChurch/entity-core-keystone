package org.entitycore.protocol;

/**
 * Root of the entity-core checked-exception hierarchy (profile error_model =
 * {@code exceptions}, {@code checked = true}). Codec/protocol failures are CHECKED
 * — the compiler forces callers to handle a malformed-input path, the static-OO
 * analogue of Zig's error sets / OCaml's result / CL's conditions. Truly
 * unrecoverable programmer errors stay unchecked ({@link RuntimeException}).
 */
public class EntityCoreException extends Exception {
    private static final long serialVersionUID = 1L;

    public EntityCoreException(String message) {
        super(message);
    }

    public EntityCoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
