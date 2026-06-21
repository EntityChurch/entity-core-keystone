package org.entitycore.protocol.crypto

import org.entitycore.protocol.EcfException
import org.entitycore.protocol.EntityError
import org.entitycore.protocol.codec.CanonicalCbor
import org.entitycore.protocol.codec.EcfValue
import org.entitycore.protocol.codec.Varint
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * content_hash construction (ENTITY-CBOR-ENCODING.md §4.2):
 *
 *   content_hash = varint(format_code) ‖ HASH(ECF({type, data}))
 *
 * Format code 0x00 = ecfv1-sha256 (the required §9.1 floor); 0x01 = ecfv1-sha384
 * (agility). The format_code is NOT part of the hashed entity — only `{type, data}` is
 * hashed. The varint prefix is multicodec-style LEB128 (invariant N1), so a code >= 0x80
 * extends to multiple bytes.
 *
 * Asymmetry (corroborates A-OC-004 / A-CL-007): the CONSTRUCT side serializes the
 * caller-supplied format_code verbatim (so content_hash.4 with code 128 passes); the
 * RECEIVE/verify side ([resolveFormat]) rejects any unallocated code.
 *
 * SHA-256/384 come from the JDK [MessageDigest] (SunMessageDigest), zero dep.
 */
object ContentHash {
    const val FORMAT_SHA256 = 0x00
    const val FORMAT_SHA384 = 0x01

    /**
     * Compute the wire content_hash over an entity `{type, data}` map.
     * @return varint(formatCode) ‖ digest(ECF({type, data}))
     */
    fun compute(entity: EcfValue.MapVal, formatCode: Int = FORMAT_SHA256): ByteArray {
        val type = entity["type"]
        val data = entity["data"]
        if (type == null || data == null) {
            throw EcfException(EntityError.CodecError.NonCanonicalEcf(
                "content_hash input must have type and data"))
        }
        val hashed = EcfValue.MapVal.of("type", type, "data", data)
        val ecf = CanonicalCbor.encodeOrThrow(hashed)
        val digest = digest(constructAlgorithm(formatCode), ecf)
        val out = ByteArrayOutputStream(1 + digest.size)
        val prefix = Varint.encode(formatCode.toLong())
        out.write(prefix, 0, prefix.size)
        out.write(digest, 0, digest.size)
        return out.toByteArray()
    }

    /** Construct-side digest selection: 0x01 -> SHA-384, everything else -> SHA-256.
     *  The corpus exercises only the varint prefix for synthetic high codes
     *  (content_hash.4); the peer layer (S3) rejects unallocated codes on receive. */
    private fun constructAlgorithm(formatCode: Int): String =
        if (formatCode == FORMAT_SHA384) "SHA-384" else "SHA-256"

    /** Receive-side: resolve an integer format code to its JCA digest name, or reject. */
    fun resolveFormat(code: Int): String = when (code) {
        FORMAT_SHA256 -> "SHA-256"
        FORMAT_SHA384 -> "SHA-384"
        else -> throw EcfException(EntityError.CryptoError.UnsupportedContentHashFormat(
            "unsupported content_hash format code: $code"))
    }

    private fun digest(algo: String, input: ByteArray): ByteArray =
        MessageDigest.getInstance(algo).digest(input)
}
