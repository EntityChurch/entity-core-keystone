package org.entitycore.protocol.peer;

/**
 * A §1.8 / §3.1 RESOLUTION-INTEGRITY failure: an entity whose carried
 * {@code content_hash} is not {@code content_hash({type, data})}, or an {@code included}
 * entry whose MAP KEY does not bind to the entity filed under it.
 *
 * <p>§5.2a pins this arm: <em>"A peer that refuses at the decode boundary MUST answer
 * {@code 400 hash_mismatch} {@code [MUST]}"</em> (mood corrected 0.8.2.24), and in the same
 * breath <em>"{@code 400 non_canonical_ecf} is NOT conformant here {@code [MUST]}"</em>.
 * That code is {@code ENTITY-CBOR-ENCODING} §5.4's, for a CBOR TAG-POLICY violation, and a
 * mis-keyed included entry carries no tag. Its encoding is canonical; what is false is the
 * claim the KEY makes, so the remedy {@code non_canonical_ecf} selects (<em>re-encode</em>)
 * sends an honest caller to the wrong layer. This peer answered {@code non_canonical_ecf}
 * for every decode-boundary refusal until 0.8.2.24 (measured on the wire: arc-probe
 * B1/B2).
 *
 * <p>A TYPE RATHER THAN A MESSAGE, because a classifier that has to recognise the cause by
 * matching on {@code getMessage()} is one string edit away from silently re-collapsing the
 * two codes. It extends {@link IllegalArgumentException} so every existing
 * {@code catch (RuntimeException)} on the decode path keeps catching it unchanged — the
 * shape those sites were already written against.
 */
public class HashMismatchException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    public HashMismatchException(String message) {
        super(message);
    }
}
