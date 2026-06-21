package org.entitycore.protocol.crypto;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.entitycore.protocol.codec.CanonicalCbor;
import org.entitycore.protocol.codec.EcfValue;
import org.entitycore.protocol.codec.EntityCodecException;
import org.entitycore.protocol.codec.Varint;

/**
 * content_hash construction (ENTITY-CBOR-ENCODING.md §4.2):
 *
 * <pre>content_hash = varint(format_code) ‖ HASH(ECF({type, data}))</pre>
 *
 * <p>Format code {@code 0x00} = ecfv1-sha256 (the required floor); {@code 0x01} =
 * ecfv1-sha384 (agility). The format_code is NOT part of the hashed entity — only
 * {@code {type, data}} is hashed. The varint prefix is multicodec-style LEB128
 * (invariant N1), so a code &gt;= 0x80 extends to multiple bytes.
 *
 * <p>Asymmetry (A-OC-004 / A-CL-007, independently reached): the CONSTRUCT side
 * serializes the caller-supplied format_code verbatim (so content_hash.4 with code
 * 128 passes); the RECEIVE/verify side ({@link #resolveFormat}) rejects any
 * unallocated code with {@link UnsupportedContentHashFormatException}.
 *
 * <p>SHA-256/384 come from the JDK {@link MessageDigest} (SunMessageDigest), zero dep.
 */
public final class ContentHash {
    private ContentHash() { }

    public static final int FORMAT_SHA256 = 0x00;
    public static final int FORMAT_SHA384 = 0x01;

    /**
     * Compute the wire content_hash over an entity {@code {type, data}} map.
     *
     * @param entity      a CBOR map carrying "type" and "data"
     * @param formatCode  the content_hash format code (0x00 sha256, 0x01 sha384, ...)
     * @return varint(formatCode) ‖ digest(ECF({type, data}))
     */
    public static byte[] compute(EcfValue.Map entity, int formatCode) throws EntityCodecException {
        EcfValue type = entity.get("type");
        EcfValue data = entity.get("data");
        if (type == null || data == null) {
            throw new org.entitycore.protocol.codec.NonCanonicalEcfException(
                    "content_hash input must have type and data");
        }
        EcfValue.Map hashed = EcfValue.Map.of("type", type, "data", data);
        byte[] ecf = CanonicalCbor.encode(hashed);
        byte[] digest = digest(constructAlgorithm(formatCode), ecf);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + digest.length);
        byte[] prefix = Varint.encode(formatCode);
        out.write(prefix, 0, prefix.length);
        out.write(digest, 0, digest.length);
        return out.toByteArray();
    }

    /** Convenience: SHA-256-form content_hash (the §9.1 floor). */
    public static byte[] compute(EcfValue.Map entity) throws EntityCodecException {
        return compute(entity, FORMAT_SHA256);
    }

    /** Construct-side digest selection: 0x01 -> SHA-384, everything else -> SHA-256.
     *  The corpus exercises only the varint prefix for synthetic high codes
     *  (content_hash.4); the peer layer (S3) rejects unallocated codes on receive. */
    private static String constructAlgorithm(int formatCode) {
        return formatCode == FORMAT_SHA384 ? "SHA-384" : "SHA-256";
    }

    /** Receive-side: resolve an integer format code to its JCA digest name, or reject. */
    public static String resolveFormat(int code) throws UnsupportedContentHashFormatException {
        return switch (code) {
            case FORMAT_SHA256 -> "SHA-256";
            case FORMAT_SHA384 -> "SHA-384";
            default -> throw new UnsupportedContentHashFormatException(
                    "unsupported content_hash format code: " + code);
        };
    }

    private static byte[] digest(String algo, byte[] input) {
        try {
            return MessageDigest.getInstance(algo).digest(input);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256/384 are JDK-guaranteed; an absence is a programmer/JVM error.
            throw new IllegalStateException("missing JDK digest: " + algo, e);
        }
    }
}
