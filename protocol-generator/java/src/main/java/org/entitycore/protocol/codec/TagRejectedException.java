package org.entitycore.protocol.codec;

/** A CBOR major-type-6 tag was encountered at any depth on decode. ECF forbids
 *  tags entirely (invariant N2 / §6.3) — hard reject, no recovery. Status 400. */
public class TagRejectedException extends EntityCodecException {
    private static final long serialVersionUID = 1L;
    public TagRejectedException(String message) { super(message); }
}
