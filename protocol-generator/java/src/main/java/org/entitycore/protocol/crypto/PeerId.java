package org.entitycore.protocol.crypto;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.entitycore.protocol.codec.Base58;
import org.entitycore.protocol.codec.EntityCodecException;
import org.entitycore.protocol.codec.Varint;

/**
 * peer-id formatting/parsing + §1.5 canonical-form derivation.
 *
 * <pre>peer_id = Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)</pre>
 *
 * <p>key_type and hash_type are multicodec-style LEB128 varints (invariant N1).
 *
 * <p><b>A-JAVA-004 (FOURTH spec-first peer; corroborates A-ZIG-001 / A-OC-007 /
 * A-CL-002).</b> The Ed25519 peer_id is derived from the §1.5 v7.65 CANONICAL-FORM
 * TABLE (hash_type={@code 0x00} identity-multihash, digest = RAW public key, NO
 * hash), NOT the stale §7.4 / §1.5-line-436 {@code SHA256(pubkey)} skeleton. The
 * §1.5 size-cutoff rule: a key &lt;= 32 bytes is identity-multihash
 * (hash_type={@code 0x00}, digest = key); a larger key is SHA-256-form
 * (hash_type={@code 0x01}, digest = SHA-256(key)). So Ed25519 (32 B) ->
 * {@code (0x01, 0x00, pubkey)} and Ed448 (57 B) -> {@code (0x02, 0x01, sha256(pubkey))}.
 *
 * <p>The S2 conformance corpus uses OPAQUE digests (peer_id.* vectors supply
 * key_type/hash_type/digest explicitly), so a wrong CONSTRUCTION would still pass
 * S2 and only fail at the S4 handshake — hence this is baked in correctly now.
 */
public final class PeerId {
    private PeerId() { }

    public static final int KEY_TYPE_ED25519 = 0x01;
    public static final int KEY_TYPE_ED448 = 0x02;

    /** Format a peer-id string from its abstract components (the corpus path). */
    public static String format(int keyType, int hashType, byte[] digest) {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        byte[] kt = Varint.encode(keyType);
        byte[] ht = Varint.encode(hashType);
        raw.write(kt, 0, kt.length);
        raw.write(ht, 0, ht.length);
        raw.write(digest, 0, digest.length);
        return Base58.encode(raw.toByteArray());
    }

    /** Parsed peer-id components. {@code digest} is a fresh copy. */
    public record Parsed(int keyType, int hashType, byte[] digest) { }

    /** Parse a peer-id string back to its components. */
    public static Parsed parse(String peerId) throws EntityCodecException {
        byte[] raw = Base58.decode(peerId);
        Varint.Decoded kt = Varint.decode(raw, 0);
        Varint.Decoded ht = Varint.decode(raw, kt.next());
        int dlen = raw.length - ht.next();
        byte[] digest = new byte[Math.max(dlen, 0)];
        if (dlen > 0) {
            System.arraycopy(raw, ht.next(), digest, 0, dlen);
        }
        return new Parsed((int) kt.value(), (int) ht.value(), digest);
    }

    /**
     * Derive a peer-id from a RAW public key and curve, per the §1.5 canonical-form
     * table + size-cutoff rule (A-JAVA-004). This is the construction the S4
     * handshake binds against.
     *
     * @param publicKey the RAW public-key bytes (Ed25519 = 32, Ed448 = 57)
     * @param curve     the curve
     */
    public static String fromPublicKey(byte[] publicKey, Curve curve) {
        int keyType = (curve == Curve.ED25519) ? KEY_TYPE_ED25519 : KEY_TYPE_ED448;
        int hashType;
        byte[] digest;
        if (publicKey.length <= 32) {
            hashType = 0x00;          // identity-multihash: digest IS the public key
            digest = publicKey.clone();
        } else {
            hashType = 0x01;          // SHA-256-form for keys > 32 bytes
            digest = sha256(publicKey);
        }
        return format(keyType, hashType, digest);
    }

    /** The signature curves with allocated key_type codes. */
    public enum Curve { ED25519, ED448 }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("missing JDK SHA-256", e);
        }
    }
}
