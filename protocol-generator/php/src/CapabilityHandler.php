<?php

declare(strict_types=1);

namespace EntityCore;

/** §6.2 — the capability handler (request / delegate / revoke / configure). */
final class CapabilityHandler implements Handler
{
    public function __construct(private readonly Peer $peer)
    {
    }

    public function handle(string $operation, HandlerContext $ctx): Outcome
    {
        return match ($operation) {
            'request' => $this->request($ctx),
            'delegate' => $this->delegate($ctx),
            'revoke' => $this->revoke($ctx),
            'configure' => $this->configure($ctx),
            default => Outcome::err(501, 'unsupported_operation', $operation),
        };
    }

    private function request(HandlerContext $ctx): Outcome
    {
        $params = $ctx->exec->entityField('params');
        $author = $ctx->exec->bytes('author');
        if ($author === null) {
            return Outcome::err(403, 'capability_denied');
        }
        return $this->mintBounded($ctx->callerCap, PeerHelpers::reqGrants($params), $author, null);
    }

    private function delegate(HandlerContext $ctx): Outcome
    {
        $params = $ctx->exec->entityField('params');
        $author = $ctx->exec->bytes('author');
        $ph = $params?->bytes('parent');
        if ($ph === null) {
            return Outcome::err(400, 'unexpected_params', 'delegate: parent required');
        }
        if (PeerHelpers::isZeroHash($ph)) {
            return Outcome::err(400, 'unexpected_params', 'delegate: zero parent');
        }
        if (!($author !== null && \hash_equals($this->peer->identity->identityHash(), $author))) {
            return Outcome::err(501, 'unsupported_operation', 'delegate: same-peer-only in v1');
        }
        return $this->mintBounded($ctx->callerCap, PeerHelpers::reqGrants($params), $author, $ph);
    }

    private function revoke(HandlerContext $ctx): Outcome
    {
        $params = $ctx->exec->entityField('params');
        $tokenH = $params?->bytes('token');
        if ($tokenH === null) {
            return Outcome::err(400, 'unexpected_params', 'revoke: missing token');
        }
        if (PeerHelpers::isZeroHash($tokenH)) {
            return Outcome::err(400, 'unexpected_params', 'revoke: zero token');
        }
        $marker = Entity::make('system/capability/revocation', Ecf::map(
            'token', new ByteString($tokenH), 'revoked_at', Capability::nowMs()));
        $this->peer->store->bind(
            "/{$this->peer->localPeer}/system/capability/revocations/" . \bin2hex($tokenH), $marker);
        return Outcome::ok(Wire::emptyParams());
    }

    private function configure(HandlerContext $ctx): Outcome
    {
        $params = $ctx->exec->entityField('params');
        $pp = $params?->text('peer_pattern');
        if ($pp === null) {
            return Outcome::err(400, 'unexpected_params', 'configure: missing peer_pattern');
        }
        $isHex = \strlen($pp) === 66 && \ctype_xdigit($pp) && \strtolower($pp) === $pp;
        if (!($pp === 'default' || $isHex || Capability::isPeerId($pp))) {
            return Outcome::err(400, 'invalid_peer_pattern', $pp);
        }
        $this->peer->store->bind("/{$this->peer->localPeer}/system/capability/policy/{$pp}", $params);
        return Outcome::ok(Wire::emptyParams());
    }

    /**
     * @param list<EcfMap> $reqGrants
     */
    private function mintBounded(?Entity $callerCap, array $reqGrants, string $granteeHash, ?string $parent): Outcome
    {
        $bounded = false;
        if ($callerCap !== null) {
            $parentGrants = Capability::grantsOfToken($callerCap);
            $bounded = true;
            foreach ($reqGrants as $cgRaw) {
                $c = Capability::parseGrant($cgRaw);
                $covered = false;
                foreach ($parentGrants as $pg) {
                    // self-issued mint: granter = local → both frames local.
                    if (Capability::grantSubset($this->peer->localPeer, $this->peer->localPeer, $this->peer->localPeer, $c, $pg)) {
                        $covered = true;
                        break;
                    }
                }
                if (!$covered) {
                    $bounded = false;
                    break;
                }
            }
        }
        if (!$bounded) {
            return Outcome::err(403, 'scope_exceeds_authority');
        }
        $m = $this->peer->mintToken($granteeHash, $reqGrants, $parent);
        return Outcome::ok(
            Entity::make('system/capability/grant', Ecf::map('token', new ByteString($m['token']->hash()))),
            $this->peer->capIncluded($m),
        );
    }
}
