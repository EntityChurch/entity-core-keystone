package org.entitycore.protocol.peer;

import java.util.List;

/**
 * The §6.6 HandlerContext: everything a handler needs to service one operation —
 * the EXECUTE entity, the per-connection state, the envelope's {@code included}, and
 * the resolved caller capability (null for the unauthenticated connect path).
 */
public record HandlerContext(Entity exec, Conn conn, List<Envelope.Included> included,
                             Entity callerCap, Envelope env) {

    /** The EXECUTE's params entity, or null. */
    public Entity params() {
        return exec.entityField("params");
    }
}
