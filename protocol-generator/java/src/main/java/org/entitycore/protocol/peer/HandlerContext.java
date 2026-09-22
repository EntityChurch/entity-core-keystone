package org.entitycore.protocol.peer;

import java.util.List;

/**
 * The §6.6 HandlerContext: everything a handler needs to service one operation —
 * the EXECUTE entity, the per-connection state, the envelope's {@code included}, the
 * resolved caller capability (null for the unauthenticated connect path), and the
 * OWNING handler's pattern.
 *
 * <p>{@code pattern} is CARRIED, not recomputed (§6.3, 0.8.2.23). §6.3's
 * {@code check_path_permission} needs the handler pattern and the caller's capability,
 * and the dispatch-level check has already computed both; recomputing invites the two to
 * drift, and §6.8 is explicit that the authority is selected by who named the path. It is
 * the OWNING handler's pattern — for the tree handler owner and runner coincide, so the
 * distinction is not observable on a core peer, but the field is named for the owner.
 */
public record HandlerContext(Entity exec, Conn conn, List<Envelope.Included> included,
                             Entity callerCap, Envelope env, String pattern) {

    /** The EXECUTE's params entity, or null. */
    public Entity params() {
        return exec.entityField("params");
    }
}
