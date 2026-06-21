<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A registered handler (§6.13(a)): `handle(operation, ctx)` is the per-operation
 * `match` ladder, with the "unknown operation → 501" arm as the default. Handlers
 * return an {@see Outcome} (the recoverable seam); the unrecoverable
 * transport/codec boundary throws.
 *
 * A handler that originates an outbound EXECUTE (§6.13(b)/§6.11 reentry) calls
 * `$ctx->conn->outbound(...)`, which in the single-thread event loop PUMPS the
 * loop until the correlated EXECUTE_RESPONSE arrives — the handler "awaits" by
 * cooperative re-entry, never by blocking a thread (there are none).
 */
interface Handler
{
    public function handle(string $operation, HandlerContext $ctx): Outcome;
}
