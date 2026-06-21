<?php

declare(strict_types=1);

namespace EntityCore;

/** §6.2 / §6.13(a) — the handlers handler (register / unregister). */
final class HandlersHandler implements Handler
{
    public function __construct(private readonly Peer $peer)
    {
    }

    public function handle(string $operation, HandlerContext $ctx): Outcome
    {
        return match ($operation) {
            'register' => $this->register($ctx),
            'unregister' => $this->unregister($ctx),
            default => Outcome::err(501, 'unsupported_operation', $operation),
        };
    }

    private function register(HandlerContext $ctx): Outcome
    {
        $exec = $ctx->exec;
        $pattern = PeerHelpers::registerPattern($exec);
        if ($pattern === null) {
            return PeerHelpers::registerPatternError($exec);
        }
        $req = $exec->entityField('params');
        if ($req === null) {
            return Outcome::err(400, 'unexpected_params', 'register: missing params');
        }
        if ($req->type !== 'system/handler/register-request') {
            return Outcome::err(400, 'unexpected_params', "register expects register-request, got {$req->type}");
        }
        $manifest = $req->mapField('manifest') ?? new EcfMap();
        $name = Ecf::text($manifest, 'name') ?? $pattern;
        $operations = Ecf::asMap($manifest->get('operations')) ?? new EcfMap();
        $exprPath = Ecf::text($manifest, 'expression_path');
        $internalScope = $manifest->get('internal_scope');
        $grantScope = Ecf::mapList($req->data(), 'requested_scope');
        if ($grantScope === null && \is_array($internalScope)) {
            $grantScope = Ecf::mapList($req->data(), 'internal_scope');
        }
        if ($grantScope === null) {
            $grantScope = [];
        }
        $interfaceRel = "system/handler/{$pattern}";
        // (1) handler manifest at the pattern path
        $hp = new EcfMap();
        $hp->put('interface', $interfaceRel);
        if ($exprPath !== null) {
            $hp->put('expression_path', $exprPath);
        }
        if ($internalScope !== null) {
            $hp->put('internal_scope', $internalScope);
        }
        $this->peer->store->bind($this->peer->abs($pattern), Entity::make('system/handler', $hp));
        // (2) associated types at system/type/{type_name}
        $types = $req->mapField('types');
        if ($types !== null) {
            foreach ($types->entries() as [$tk, $tv]) {
                if (!\is_string($tk)) {
                    continue;
                }
                $td = $tv instanceof EcfMap ? $tv : Ecf::map('def', $tv);
                $this->peer->store->bind($this->peer->abs("system/type/{$tk}"), Entity::make('system/type', $td));
            }
        }
        // (3) self-issued signed handler grant + (4) grant-signature at §3.5
        $m = $this->peer->mintToken($this->peer->identity->identityHash(), $grantScope, null);
        $this->peer->store->bind($this->peer->abs("system/capability/grants/{$pattern}"), $m['token']);
        $this->peer->store->bind($this->peer->abs('system/signature/' . \bin2hex($m['token']->hash())), $m['signature']);
        // (5) handler interface entity (discovery index)
        $this->peer->store->bind($this->peer->abs($interfaceRel), Entity::make('system/handler/interface',
            Ecf::map('pattern', $pattern, 'name', $name, 'operations', $operations)));
        return Outcome::ok(Entity::make('system/handler/register-result',
            Ecf::map('pattern', $pattern, 'grant', $m['token']->data())));
    }

    private function unregister(HandlerContext $ctx): Outcome
    {
        $exec = $ctx->exec;
        $pattern = PeerHelpers::registerPattern($exec);
        if ($pattern === null) {
            return PeerHelpers::registerPatternError($exec);
        }
        $g = $this->peer->store->getAt($this->peer->abs("system/capability/grants/{$pattern}"));
        if ($g !== null) {
            $this->peer->store->unbind($this->peer->abs('system/signature/' . \bin2hex($g->hash())));
            $this->peer->store->unbind($this->peer->abs("system/capability/grants/{$pattern}"));
        }
        $this->peer->store->unbind($this->peer->abs($pattern));
        $this->peer->store->unbind($this->peer->abs("system/handler/{$pattern}"));
        return Outcome::ok(Wire::emptyParams());
    }
}
