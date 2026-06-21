package org.entitycore.protocol.conformance;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.entitycore.protocol.codec.CanonicalCbor;
import org.entitycore.protocol.codec.EcfValue;
import org.entitycore.protocol.codec.EntityCodecException;
import org.entitycore.protocol.crypto.ContentHash;
import org.entitycore.protocol.crypto.Ed;
import org.entitycore.protocol.crypto.PeerId;

/**
 * ECF wire-conformance harness (the codec gate).
 *
 * <p>The normative fixture {@code conformance-vectors-v1.cbor} is itself a
 * canonical-ECF-encoded array of vector maps, each carrying its own cross-blessed
 * {@code canonical} bytes (the Go wire-conformance oracle's
 * {@code build-fixture}/{@code emit-canonical} output, 3-way Go × Rust × Python
 * byte-locked). The harness decodes the fixture with THIS peer's OWN decoder (a
 * decoder bug is itself a conformance failure per ENTITY-CBOR-ENCODING.md §E.3), runs
 * each vector through the codec, and byte-compares against the embedded
 * {@code canonical}. Byte-identity to the fixture == oracle PASS. (Same self-contained
 * mechanism the C#/TS/OCaml/Elixir/Zig/CL peers used; the Go binary is the fixture
 * producer, not a runtime checker.)
 *
 * <p>Dispatch by {@code id} prefix:
 * <ul>
 *   <li>{@code content_hash} → varint(format_code) ‖ SHA-2(ECF({type,data}))</li>
 *   <li>{@code peer_id}      → ECF-text wire? No: peer_id canonical is the Base58
 *       string's UTF-8 bytes wrapped as a CBOR text string</li>
 *   <li>{@code signature}    → Ed25519_sign(seed, ECF({type,data}))</li>
 *   <li>everything else (float/int/map_keys/length/primitive/nested/envelope)
 *       → plain ECF encode(input)</li>
 *   <li>{@code decode_reject} → the decoder MUST reject the canonical wire bytes</li>
 * </ul>
 */
public final class ConformanceHarness {

    public record Result(int pass, int fail, int total, List<String> failures) { }

    /** Resolve the fixture path: env {@code ECF_FIXTURE} or the vendored default. */
    public static Path defaultFixture() {
        String env = System.getenv("ECF_FIXTURE");
        if (env != null && !env.isEmpty()) {
            return Path.of(env);
        }
        return Path.of("../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor");
    }

    public static Result run(Path fixture) throws IOException, EntityCodecException {
        byte[] octets = Files.readAllBytes(fixture);
        EcfValue decoded = CanonicalCbor.decode(octets);
        if (!(decoded instanceof EcfValue.Array arr)) {
            throw new IllegalStateException("fixture top-level is not an array");
        }
        int pass = 0, fail = 0, total = 0;
        List<String> failures = new ArrayList<>();
        for (EcfValue v : arr.items()) {
            if (!(v instanceof EcfValue.Map vm)) {
                continue; // meta / non-vector entries
            }
            String kind = text(vm.get("kind"));
            if (kind == null) {
                continue; // meta entry without a kind -> skip (not counted)
            }
            String id = text(vm.get("id"));
            total++;
            boolean ok;
            String detail = null;
            try {
                if (kind.equals("decode_reject")) {
                    byte[] wire = bytes(vm.get("canonical"));
                    ok = rejects(wire);
                    if (!ok) {
                        detail = "decoder ACCEPTED a reject vector";
                    }
                } else if (kind.equals("encode_equal")) {
                    byte[] want = bytes(vm.get("canonical"));
                    byte[] got = produce(id, vm.get("input"));
                    ok = java.util.Arrays.equals(got, want);
                    if (!ok) {
                        detail = "want=" + hex(want) + " got=" + hex(got);
                    }
                } else {
                    total--; // unknown kind -> not a testable vector
                    continue;
                }
            } catch (Exception e) {
                ok = false;
                detail = "raised: " + e;
            }
            if (ok) {
                pass++;
            } else {
                fail++;
                failures.add("FAIL " + id + ": " + detail);
            }
        }
        return new Result(pass, fail, total, failures);
    }

    private static byte[] produce(String id, EcfValue input)
            throws org.entitycore.protocol.EntityCoreException {
        String cat = category(id);
        return switch (cat) {
            case "content_hash" -> {
                EcfValue.Map m = (EcfValue.Map) input;
                EcfValue fc = m.get("format_code");
                int code = (fc instanceof EcfValue.Int i) ? i.value().intValueExact() : 0;
                EcfValue.Map entity = EcfValue.Map.of("type", m.get("type"), "data", m.get("data"));
                yield ContentHash.compute(entity, code);
            }
            case "peer_id" -> {
                EcfValue.Map m = (EcfValue.Map) input;
                int kt = ((EcfValue.Int) m.get("key_type")).value().intValueExact();
                int ht = ((EcfValue.Int) m.get("hash_type")).value().intValueExact();
                byte[] digest = bytes(m.get("digest"));
                String peerId = PeerId.format(kt, ht, digest);
                // canonical = the peer_id string encoded as a CBOR text string
                yield CanonicalCbor.encode(new EcfValue.Text(peerId));
            }
            case "signature" -> {
                EcfValue.Map m = (EcfValue.Map) input;
                byte[] seed = bytes(m.get("seed"));
                EcfValue.Map entity = (EcfValue.Map) m.get("entity");
                EcfValue.Map hashed = EcfValue.Map.of("type", entity.get("type"),
                                                      "data", entity.get("data"));
                byte[] ecf = CanonicalCbor.encode(hashed);
                yield Ed.sign(seed, ecf, PeerId.Curve.ED25519);
            }
            default -> CanonicalCbor.encode(input);
        };
    }

    private static boolean rejects(byte[] wire) {
        try {
            CanonicalCbor.decode(wire);
            return false;
        } catch (EntityCodecException e) {
            return true;
        }
    }

    private static String category(String id) {
        int dot = id.indexOf('.');
        return dot >= 0 ? id.substring(0, dot) : id;
    }

    private static String text(EcfValue v) {
        return (v instanceof EcfValue.Text t) ? t.value() : null;
    }

    private static byte[] bytes(EcfValue v) {
        if (v instanceof EcfValue.Bytes b) {
            return b.octets();
        }
        throw new IllegalStateException("expected bytes, got " + v);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    private ConformanceHarness() { }
}
