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
        // GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
        // single-granter case is an array of ONE. They were singular, which made §1.4's
        // multi-signature-root rule ungateable on the wire: driving it needs two granter
        // identities and two signatures, and a single-credential carrier cannot express
        // that input.
        //
        // TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one,
        // because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle
        // sends the SINGULAR names; a plural-only peer reads the triple as absent there,
        // takes the ambient arm and refuses — measured on the `go` vanguard as 2 of 778
        // severities moving PASS -> FAIL. REMOVE THIS FALLBACK AT THE ORACLE RE-PIN.
        $capability = $p->entityField('reentry_capability');
        $granters = self::entityListField($p, 'reentry_granters', 'reentry_granter');
        $capSigs = self::entityListField($p, 'reentry_cap_signatures', 'reentry_cap_signature');
        if ($value === null) {
            return Outcome::err(400, 'invalid_params', 'dispatch-outbound requires value');
        }
        // The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED arm,
        // all three absent selects the AMBIENT arm, and a PARTIAL set is 400
        // invalid_params — a partial credential is malformed, not ambient. An empty array
        // is partial, not present.
        $nPresent = ($capability !== null ? 1 : 0)
            + ($granters === [] ? 0 : 1)
            + ($capSigs === [] ? 0 : 1);
        if ($nPresent !== 0 && $nPresent !== 3) {
            return Outcome::err(400, 'invalid_params', 'dispatch-outbound reentry authority is all-or-none');
        }
        $hasCred = $nPresent === 3;
        $cred = $hasCred ? $capability : null;
        $granterList = $hasCred ? $granters : [];
        $sigList = $hasCred ? $capSigs : [];
        // §7a.1 generic relay: `value` is the downstream's params entity data and
        // MUST be forwarded verbatim, never re-wrapped. The validator already
        // shaped it as echo's {value: X} params; a faithful relay passes the map
        // through as the outbound EXECUTE's params data (re-wrapping double-nests —
        // the non-conformant party the keystone matrix caught).
        $valueMap = Ecf::asMap($value);
        $innerData = $valueMap ?? Ecf::map('value', $value);
        $inner = Entity::make('primitive/any', $innerData);
        // `target` arrives as any of §1.4's three spellings and the validator sends the
        // SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the resource
        // target want the PEER-RELATIVE path — §1.4's PD-2 block says so for Dimension 1,
        // and a resource target carrying a scheme is not a path at all.
        $relTarget = Capability::peerRelativeOf($target);
        $resource = Wire::resourceTarget("system/handler/{$relTarget}");

        // §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer, all
        // four dimensions, on THIS handler's own grant — with a target-minted credential
        // relaxing Dimension 4 and nothing else. Consulting only the presented credential
        // here is the §6.8 confused-deputy bypass.
        $pattern = $ctx->handlerPattern ?? '';
        $ownGrant = $this->peer->store->getAt(
            Capability::grantPathFor($this->peer->localPeer, $pattern)
        );
        if ($ownGrant === null) {
            // §6.8: a handler with no valid grant does not run. Fail closed rather than
            // falling back to the credential, which is the substitution §6.8 forbids.
            return Outcome::err(403, 'capability_denied', "no handler grant for {$pattern}");
        }
        // §7a.2a: the credential, its granters and its signatures arrive NESTED IN PARAMS
        // (ratified shape (a), in-band), so they are NOT in $ctx->included and a verifier
        // handed that alone cannot resolve a single link.
        $bundle = $ctx->included;
        if ($hasCred) {
            foreach (\array_merge([$cred], $granterList, $sigList) as $e) {
                $bundle[] = Envelope::inc($e);
            }
        }
        // §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends the
        // absolute form, so the URI names the target. Where the uri is PEER-RELATIVE
        // there is no peer in it and the §6.11 seam's destination is the connection's
        // remote, so that is the fallback — without it Dimension 4 passes vacuously.
        $uriPeer = Capability::extractPeer($this->peer->localPeer, $target);
        $targetPeer = ($uriPeer === $this->peer->localPeer && $ctx->conn->helloPeerId !== null)
            ? $ctx->conn->helloPeerId : $uriPeer;
        $haveRelax = false;
        $relaxScope = null;
        if ($hasCred) {
            [$haveRelax, $relaxScope] = Capability::targetMintedPeersRelaxation(
                $this->peer->localPeer, $targetPeer, $this->peer->store, $cred, $bundle);
        }
        if (!Capability::checkOutboundSubDispatch($this->peer->localPeer, $targetPeer,
            $relTarget, $operationField, $ownGrant, $resource, $haveRelax, $relaxScope)) {
            // §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
            // transport- or gateway-class code would launder an authorization verdict
            // into a route fault.
            return Outcome::err(403, 'capability_denied',
                'outbound sub-dispatch not authorized by the handler grant');
        }

        $env = $this->peer->outboundDispatch($ctx->conn, $target, $operationField, $inner,
            $cred, $granterList, $sigList, $resource);
        if ($env === null) {
            return Outcome::err(503, 'no_outbound_seam', 'no live section 6.11 reentry connection');
        }
        $status = $env->root->uint('status') ?? \gmp_init(0);
        $resultCbor = $env->root->field('result') ?? Ecf::emptyMap();
        return Outcome::ok(Entity::make('primitive/any', Ecf::map(
            'status', $status, 'result', $resultCbor)));
    }

    /**
     * Decode an ARRAY of nested entities at `$key`, falling back to the SINGULAR spelling
     * as a list of one (the §7a.1 transitional carriers).
     *
     * An EMPTY array means absent, not-a-list, or a MALFORMED array (a member that does
     * not decode) — never a silently shorter list, because the caller's all-or-none test
     * would then read a partial credential as a complete one.
     *
     * @return list<Entity>
     */
    private static function entityListField(Entity $e, string $key, string $singular): array
    {
        $v = $e->field($key);
        if (\is_array($v)) {
            $out = [];
            foreach ($v as $item) {
                if (!($item instanceof EcfMap)) {
                    return [];
                }
                $out[] = Entity::ofCbor($item);
            }
            return $out;
        }
        $one = $e->entityField($singular);
        return $one === null ? [] : [$one];
    }
}
