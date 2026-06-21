package org.entitycore.protocol.peer;

import java.util.List;

/**
 * A handler outcome: a status, a result entity, and any protocol entities to carry in
 * the response envelope's {@code included} (§3.1) — caps, peer identities, signatures.
 */
public record Outcome(int status, Entity result, List<Envelope.Included> included) {

    public static Outcome ok(Entity result) {
        return new Outcome(200, result, List.of());
    }

    public static Outcome ok(Entity result, List<Envelope.Included> included) {
        return new Outcome(200, result, included);
    }

    public static Outcome err(int status, String code) {
        return new Outcome(status, Wire.errorResult(code, null), List.of());
    }

    public static Outcome err(int status, String code, String message) {
        return new Outcome(status, Wire.errorResult(code, message), List.of());
    }
}
