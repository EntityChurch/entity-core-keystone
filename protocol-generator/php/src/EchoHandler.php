<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * §7a conformance handler: echo (the §6.13(a) resolve→dispatch half). Echoes the
 * params entity verbatim. Conformance scaffolding, NOT core protocol — only
 * bootstrapped under --validate.
 */
final class EchoHandler implements Handler
{
    public function __construct(private readonly Peer $peer)
    {
    }

    public function handle(string $operation, HandlerContext $ctx): Outcome
    {
        if ($operation !== 'echo') {
            return Outcome::err(501, 'unsupported_operation', $operation);
        }
        $p = $ctx->params();
        return $p === null
            ? Outcome::err(400, 'invalid_params', 'echo requires a params entity')
            : Outcome::ok($p);
    }
}
