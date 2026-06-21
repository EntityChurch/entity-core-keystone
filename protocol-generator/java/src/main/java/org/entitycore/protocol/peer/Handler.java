package org.entitycore.protocol.peer;

import org.entitycore.protocol.crypto.EntityCryptoException;

/**
 * A core system handler (§6.2). The §6.6 backward tree-walk resolves a request URI to a
 * bootstrapped handler instance; {@link #handle} then dispatches the operation.
 *
 * <p><b>The idiom axis (single-dispatch OO ladder).</b> Where the Common Lisp peer
 * externalizes operation routing into a CLOS generic function with MULTIPLE DISPATCH on
 * {@code (handler-class × operation)}, the Java peer is the MAINSTREAM static-OO shape:
 * one interface method per handler, with a {@code switch} over the operation string
 * INSIDE each implementation. The "unknown operation → 501" arm is the default branch of
 * that switch (the CL default-method analogue). This is the single-dispatch decomposition
 * the spec's §6.6 (handler, operation) dispatch key admits — exercised here as the
 * seventh independent arrival at byte/behavior-identical dispatch.
 */
interface Handler {
    Outcome handle(String operation, HandlerContext ctx) throws EntityCryptoException;
}
