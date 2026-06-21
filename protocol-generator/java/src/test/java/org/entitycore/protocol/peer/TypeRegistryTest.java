package org.entitycore.protocol.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * §9.5 type-registry byte-diff — the peer-side dual of the S2 codec corpus, and the
 * golden-file (S8) proof that render-from-model is byte-identical to the oracle's
 * {@code TypeDefinition} entities.
 *
 * <p>Renders all 53 core types (§9.5) from the in-code model ({@link CoreTypeDefs} via
 * {@link CoreTypes#entities()}) and diffs each {@code content_hash} against the canonical
 * cross-impl {@code type-registry-vectors-v1.diag} (the Go-rendered registry). Our hash is
 * 33 bytes (format byte 0x00 ‖ 32-byte SHA-256 digest); the vectors carry
 * {@code ecf-sha256:<64hex>} — we compare the 32-byte digest hex. A green here is what the
 * live oracle's {@code type_system _match} checks confirm independently (53/53).
 */
final class TypeRegistryTest {

    /** name → 64-hex content_hash digest, parsed from the .diag vectors. */
    private static Map<String, String> parseDiag() throws IOException {
        Path diag = Path.of("../shared/test-vectors/v0.8.0/type-registry-vectors-v1.diag");
        List<String> lines = Files.readAllLines(diag);
        Pattern nameP = Pattern.compile("\"name\":\\s*\"([^\"]*)\"");
        Pattern hashP = Pattern.compile("\"content_hash\":\\s*\"ecf-sha256:([0-9a-fA-F]{64})\"");
        java.util.HashMap<String, String> out = new java.util.HashMap<>();
        for (String line : lines) {
            Matcher nm = nameP.matcher(line);
            Matcher hm = hashP.matcher(line);
            if (nm.find() && hm.find()) {
                out.put(nm.group(1), hm.group(1).toLowerCase());
            }
        }
        return out;
    }

    @Test
    void coreFloorRendersByteIdentical() throws IOException {
        Map<String, String> expected = parseDiag();
        int pass = 0;
        StringBuilder fails = new StringBuilder();
        Map<String, Entity> rendered = CoreTypes.entities();
        for (Map.Entry<String, Entity> e : rendered.entrySet()) {
            String name = e.getKey();
            // our hash is 33 bytes: format byte 0x00 ‖ 32-byte digest — compare the digest.
            byte[] full = e.getValue().hash();
            String digestHex = HexFormat.of().formatHex(full, 1, full.length);
            String exp = expected.get(name);
            if (exp == null) {
                fails.append("  ").append(name).append(" — not found in vectors\n");
            } else if (exp.equals(digestHex)) {
                pass++;
            } else {
                fails.append("  ").append(name).append("\n    expected ").append(exp)
                        .append("\n    got      ").append(digestHex).append('\n');
            }
        }
        if (fails.length() > 0) {
            org.junit.jupiter.api.Assertions.fail("type-registry diff failures:\n" + fails);
        }
        assertEquals(53, rendered.size(), "expected exactly the 53-type §9.5 core floor");
        assertEquals(53, pass, "all 53 core types must be byte-identical to the canonical vectors");
    }

    @Test
    void everyCoreTypePublishesScalarSafeEntity() {
        // §1.1: a system/type entity's data is a map; sanity-check the render produces
        // well-formed entities with non-empty content hashes.
        for (Map.Entry<String, Entity> e : CoreTypes.entities().entrySet()) {
            assertNotNull(e.getValue().hash());
            assertEquals(33, e.getValue().hash().length, "ecfv1-sha256 hash is 33 bytes");
        }
    }
}
