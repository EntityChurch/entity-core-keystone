<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * §7a conformance handler: dispatch-outbound (the §6.13(b)/§6.11 outbound seam).
 *
 * Reads `{target, operation, value}` + the reentry authority
 * `{reentry_capability, reentry_granter, reentry_cap_signature}` from params,
 * originates an outbound EXECUTE back to the CALLER over the SAME inbound
 * connection (§6.11 reentry — validator = B-role on the same connection, NOT a
 * third-peer dial), and returns the inner `{status, result}`. Conformance
 * scaffolding, NOT core protocol — only bootstrapped under --validate. This is the
 * exact surface S4's `dispatch_outbound_reentry` gate exercises.
 */
final class DispatchOutboundHandler implements Handler
{
    public function __construct(private readonly Peer $peer)
    {
    }

    public function handle(string $operation, HandlerContext $ctx): Outcome
    {
        if ($operation !== 'dispatch') {
            return Outcome::err(501, 'unsupported_operation', $operation);
        }
        $p = $ctx->params();
        if ($p === null) {
            return Outcome::err(400, 'invalid_params', 'dispatch-outbound requires a params entity');
        }
        $target = $p->text('target') ?? '';
        $operationField = $p->text('operation') ?? '';
        $value = $p->field('value');
        $capability = $p->entityField('reentry_capability');
        $granterPeer = $p->entityField('reentry_granter');
        $capSig = $p->entityField('reentry_cap_signature');
        if (!($value !== null && $capability !== null && $granterPeer !== null && $capSig !== null)) {
            return Outcome::err(400, 'invalid_params', 'dispatch-outbound requires value + reentry authority');
        }
        // §7a.1 generic relay: `value` is the downstream's params entity data and
        // MUST be forwarded verbatim, never re-wrapped. The validator already
        // shaped it as echo's {value: X} params; a faithful relay passes the map
        // through as the outbound EXECUTE's params data (re-wrapping double-nests —
        // the non-conformant party the keystone matrix caught).
        $valueMap = Ecf::asMap($value);
        $innerData = $valueMap ?? Ecf::map('value', $value);
        $inner = Entity::make('primitive/any', $innerData);
        $resource = Wire::resourceTarget("system/handler/{$target}");
        $env = $this->peer->outboundDispatch($ctx->conn, $target, $operationField, $inner,
            $capability, $granterPeer, $capSig, $resource);
        if ($env === null) {
            return Outcome::err(503, 'no_outbound_seam', 'no live §6.11 reentry connection');
        }
        $status = $env->root->uint('status') ?? \gmp_init(0);
        $resultCbor = $env->root->field('result') ?? Ecf::emptyMap();
        return Outcome::ok(Entity::make('primitive/any', Ecf::map(
            'status', $status, 'result', $resultCbor)));
    }
}
