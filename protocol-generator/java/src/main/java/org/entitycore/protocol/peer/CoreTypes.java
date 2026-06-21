package org.entitycore.protocol.peer;

import java.util.LinkedHashMap;
import java.util.Map;

import org.entitycore.protocol.codec.EcfValue;

/**
 * Core type floor (V7 §9.5) — render-from-model.
 *
 * <p><b>S4 scope (A-JAVA-008 RESOLVED).</b> Publishes the FULL 53-type §9.5 core floor as
 * {@code system/type} entities under the local namespace. The per-type {@code data} maps
 * come from the in-code override table {@link CoreTypeDefs} (generated from the cross-impl
 * Go-rendered type model in the shared test-vectors); each entity's {@code content_hash} is
 * computed by our OWN S2-green codec over {@code {type, data}} (render-from-model, not
 * ingest-bytes), and is diffed byte-for-byte against the canonical
 * {@code type-registry-vectors-v1} in {@code TypeRegistryTest}. This is the surface the
 * oracle's {@code type_system} category fetches at {@code system/type/<name>} (the §9.5
 * 53/53 floor; non-floor type vocabularies are extension-owned and intentionally absent —
 * WARN/matched-if-present under {@code --profile core}, never pre-published by a core peer).
 */
final class CoreTypes {
    private CoreTypes() { }

    /** (type-name → rendered system/type entity) for the full §9.5 53-type core floor. */
    static Map<String, Entity> entities() {
        Map<String, Entity> out = new LinkedHashMap<>();
        for (Map.Entry<String, EcfValue.Map> e : CoreTypeDefs.models().entrySet()) {
            out.put(e.getKey(), type(e.getValue()));
        }
        return out;
    }

    private static Entity type(EcfValue.Map data) {
        return Entity.make("system/type", data);
    }

    /** Publish every core type at /{peer}/system/type/{name}. */
    static void publish(Store store, String localPeer) {
        for (Map.Entry<String, Entity> e : entities().entrySet()) {
            store.bind("/" + localPeer + "/system/type/" + e.getKey(), e.getValue());
        }
    }
}
