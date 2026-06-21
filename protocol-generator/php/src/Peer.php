<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Peer assembly: bootstrap (§6.9 / §6.9a), the MUST system handlers (§6.2:
 * connect, tree, handler, capability, type), the §6.5 dispatch chain, §6.6
 * resolution, and the §6.9a peer-authority seed policy. The pure protocol brain —
 * {@see dispatch} is a function from an inbound envelope to an outbound response
 * envelope. Transport lives in {@see Transport}.
 *
 * Idiom (the verdict/dispatch axis). Each handler is a {@see Handler} whose
 * `handle(op, ctx)` is a `match` over the operation string — the "unknown
 * operation → 501" arm is the default. The §5.2/§5.10 verdicts are PHP enums
 * matched at the dispatch site. A handler that originates an outbound EXECUTE
 * (§6.13(b)/§6.11 reentry) calls `$ctx->conn->outbound(...)`, which PUMPS the
 * single-thread event loop until the reply correlates (no thread to block).
 */
final class Peer
{
    /** @var array<string,Handler> pattern → handler */
    private array $handlers = [];

    private function __construct(
        public readonly Identity $identity,
        public readonly Store $store,
        public readonly string $localPeer,
        private readonly bool $openGrants,   // --debug-open-grants: degenerate wide cap
        private readonly bool $conformance,  // --validate: §7a system/validate/* handlers
    ) {
    }

    /** Construct + bootstrap a peer from a 32-byte Ed25519 seed. */
    public static function create(string $seed, bool $openGrants = false, bool $conformance = false): self
    {
        $identity = Identity::ofSeed($seed);
        $peer = new self($identity, new Store(), $identity->peerId, $openGrants, $conformance);
        $peer->bootstrap();
        return $peer;
    }

    public function getHandler(string $pattern): ?Handler
    {
        return $this->handlers[$pattern] ?? null;
    }

    // ── randomness (nonce; §4.6 SHOULD ≥32-byte CSPRNG) ─────────────────────────

    public function randomBytes(int $n): string
    {
        return \random_bytes($n);
    }

    // ── grant construction (§4.4 / §5.4) ──────────────────────────────────────────

    /**
     * Build a grant map. $peers null → omit (defaults to local at check time).
     *
     * @param list<string> $handlers
     * @param list<string> $resources
     * @param list<string> $operations
     * @param list<string>|null $peers
     */
    public static function grant(array $handlers, array $resources, array $operations, ?array $peers): EcfMap
    {
        $m = new EcfMap();
        $m->put('handlers', self::scope($handlers));
        $m->put('resources', self::scope($resources));
        $m->put('operations', self::scope($operations));
        if ($peers !== null) {
            $m->put('peers', self::scope($peers));
        }
        return $m;
    }

    /** @param list<string> $incl */
    private static function scope(array $incl): EcfMap
    {
        return Ecf::map('include', \array_values($incl));
    }

    /** @return list<EcfMap> */
    private function discoveryFloor(): array
    {
        return [
            self::grant(['system/tree'], ['system/type/*', 'system/handler/*'], ['get'], null),
            self::grant(['system/capability'], [], ['request'], null),
        ];
    }

    /** @return list<EcfMap> */
    private function openGrantsScope(): array
    {
        return [self::grant(['*'], ['*', '/*/*'], ['*'], ['*'])];
    }

    /** @return list<EcfMap> */
    private function ownerGrants(): array
    {
        return [self::grant(['*'], ['*'], ['*'], [$this->localPeer])];
    }

    // ── token mint (§4.4 / §6.9a) ──────────────────────────────────────────────────

    /**
     * @param list<EcfMap> $grants
     * @return array{token:Entity,signature:Entity}
     */
    public function mintToken(string $granteeHash, array $grants, ?string $parent): array
    {
        $m = new EcfMap();
        $m->put('granter', new ByteString($this->identity->identityHash()));
        $m->put('grantee', new ByteString($granteeHash));
        $m->put('grants', \array_values($grants));
        $m->put('created_at', Capability::nowMs());
        if ($parent !== null) {
            $m->put('parent', new ByteString($parent));
        }
        $token = Entity::make('system/capability/token', $m);
        return ['token' => $token, 'signature' => $this->identity->sign($token)];
    }

    /**
     * @param array{token:Entity,signature:Entity} $minted
     * @return list<array{hash:string,entity:Entity}>
     */
    public function capIncluded(array $minted): array
    {
        return [
            Envelope::inc($minted['token']),
            Envelope::inc($this->identity->peerEntity),
            Envelope::inc($minted['signature']),
        ];
    }

    // ── §6.9a seed policy (authenticate-time grant derivation) ──────────────────────

    /** @return list<EcfMap> */
    private function seedEntryGrants(Entity $e): array
    {
        if ($e->type === 'system/capability/token') {
            $sigPath = "/{$this->localPeer}/system/signature/" . \bin2hex($e->hash());
            $sgn = $this->store->getAt($sigPath);
            if ($sgn !== null && Identity::verifySignature($sgn, $this->identity->peerEntity)) {
                return Ecf::mapList($e->data(), 'grants') ?? [];
            }
            return [];
        }
        if ($e->type === 'system/capability/policy-entry') {
            return Ecf::mapList($e->data(), 'grants') ?? [];
        }
        return [];
    }

    /**
     * §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 →
     * default), then UNION the matched scope with the §4.4 discovery floor.
     *
     * @return list<EcfMap>
     */
    public function deriveSeedGrants(Entity $remotePeer, string $remotePeerId): array
    {
        $base = "/{$this->localPeer}/system/capability/policy/";
        $entry = $this->store->getAt($base . \bin2hex($remotePeer->hash()))
            ?? $this->store->getAt($base . $remotePeerId)
            ?? $this->store->getAt($base . 'default');
        $floor = $this->discoveryFloor();
        if ($entry === null) {
            return $floor;
        }
        $policy = $this->seedEntryGrants($entry);
        if ($policy === []) {
            return $floor;
        }
        return \array_merge($floor, $policy);
    }

    // ── §6.13(b) handler-facing outbound dispatch (§6.11 reentry) ───────────────────

    /**
     * Originate an outbound EXECUTE back over $conn (the §6.11 reentry seam) and
     * return the correlated response envelope, or null if there is no live
     * outbound seam / the wait fails. Called by the §7a dispatch-outbound handler.
     */
    public function outboundDispatch(
        Conn $conn,
        string $uri,
        string $operation,
        Entity $params,
        Entity $capability,
        Entity $granterPeer,
        Entity $capSig,
        EcfMap $resource,
    ): ?Envelope {
        $send = $conn->outbound;
        if ($send === null) {
            return null;
        }
        $requestId = 'out-' . $conn->nextOutCounter();
        $exec = Wire::makeExecute($requestId, $uri, $operation, $params,
            $this->identity->identityHash(), $capability->hash(), $resource);
        $execSig = $this->identity->sign($exec);
        $included = [
            Envelope::inc($capability),
            Envelope::inc($granterPeer),
            Envelope::inc($this->identity->peerEntity),
            Envelope::inc($capSig),
            Envelope::inc($execSig),
        ];
        return $send(new Envelope($exec, $included));
    }

    // ── dispatcher-level signature ingestion (§6.5) ────────────────────────────────

    private function ingestSignatures(Envelope $env): void
    {
        foreach ($env->included as $pair) {
            $e = $pair['entity'];
            if ($e->type !== 'system/signature') {
                continue;
            }
            $this->store->putEntity($e);
            $signerH = $e->bytes('signer');
            if ($signerH === null) {
                continue;
            }
            $signerPeer = $env->includedGet($signerH);
            if ($signerPeer === null) {
                continue;
            }
            $this->store->putEntity($signerPeer);
            $target = $e->bytes('target');
            $pk = $signerPeer->bytes('public_key');
            if ($target !== null && $pk !== null) {
                $pid = Identity::peerIdOfPublicKey($pk);
                $this->store->bind("/{$pid}/system/signature/" . \bin2hex($target), $e);
            }
        }
    }

    // ── handler resolution (§6.6) — backward tree-walk ─────────────────────────────

    /** Longest prefix of $path bound to a system/handler entity, or null. */
    private function resolveHandler(string $path): ?string
    {
        $segs = \explode('/', $path);
        for ($i = \count($segs); $i >= 1; $i--) {
            $prefix = \implode('/', \array_slice($segs, 0, $i));
            $e = $this->store->getAt($prefix);
            if ($e !== null && $e->type === 'system/handler') {
                return $prefix;
            }
        }
        return null;
    }

    private function stripLocal(string $pattern): string
    {
        $prefix = "/{$this->localPeer}/";
        return \str_starts_with($pattern, $prefix) ? \substr($pattern, \strlen($prefix)) : $pattern;
    }

    public function abs(string $rel): string
    {
        return "/{$this->localPeer}/{$rel}";
    }

    // ── entity-native dispatch (v7.74 §6.13(a)) ──────────────────────────────────────

    private function entityNativeDispatch(string $handlerPath): Outcome
    {
        $he = $this->store->getAt($handlerPath);
        if ($he === null) {
            return Outcome::err(404, 'handler_not_found', $handlerPath);
        }
        $exprPath = $he->text('expression_path');
        if ($exprPath === null) {
            return Outcome::err(501, 'no_handler_body', $handlerPath);
        }
        $abs = Capability::canonicalize($this->localPeer, $exprPath);
        $expr = $this->store->getAt($abs);
        if ($expr === null) {
            return Outcome::err(404, 'expression_not_found', $abs);
        }
        if ($expr->type === 'compute/literal') {
            $value = $expr->field('value');
            if ($value === null) {
                return Outcome::err(400, 'unexpected_params', 'compute/literal missing value');
            }
            return Outcome::ok(Entity::make('compute/result', Ecf::map(
                'value', $value, 'expression', new ByteString($expr->hash()))));
        }
        return Outcome::err(501, 'unsupported_expression', $expr->type);
    }

    // ── dispatch chain (§6.5) ───────────────────────────────────────────────────────

    /**
     * The §6.5 dispatch chain: returns an EXECUTE_RESPONSE envelope, or null for a
     * non-EXECUTE root (§3.3 server side ignores non-EXECUTE).
     */
    public function dispatch(Conn $conn, Envelope $env): ?Envelope
    {
        $exec = $env->root;
        if ($exec->type !== 'system/protocol/execute') {
            return null;
        }
        $requestId = $exec->text('request_id') ?? '';
        try {
            $outcome = $this->dispatchInner($conn, $env, $exec);
        } catch (UnresolvableGranteeException) {
            $outcome = Outcome::err(401, 'unresolvable_grantee');
        } catch (CodecException) {
            $outcome = Outcome::err(400, 'non_canonical_ecf');
        } catch (\Throwable $t) {
            if (\getenv('PEER_DEBUG_500') !== false) {
                \fwrite(\STDERR, $t->getMessage() . "\n" . $t->getTraceAsString() . "\n");
            }
            $outcome = Outcome::err(500, 'internal_error');
        }
        return new Envelope(Wire::makeResponse($requestId, $outcome->status, $outcome->result), $outcome->included);
    }

    private function dispatchInner(Conn $conn, Envelope $env, Entity $exec): Outcome
    {
        $uri = $exec->text('uri') ?? '';
        $operation = $exec->text('operation') ?? '';
        if ($uri === 'system/protocol/connect') {
            return $this->handlers['system/protocol/connect']
                ->handle($operation, new HandlerContext($exec, $conn, $env->included, null, $env));
        }
        $this->ingestSignatures($env);
        // §5.2 three-way request verdict (+ §4.10(b) chain-depth) — exhaustive match.
        $rv = Capability::verifyRequest($this->localPeer, $this->store, $env);
        $deny = match ($rv) {
            RequestVerdict::AuthnFail => Outcome::err(401, 'authentication_failed'),
            RequestVerdict::AuthzDeny => Outcome::err(403, 'capability_denied'),
            RequestVerdict::ChainTooDeep => Outcome::err(400, 'chain_depth_exceeded'),
            RequestVerdict::Allow => null,
        };
        if ($deny !== null) {
            return $deny;
        }
        $path = Capability::canonicalize($this->localPeer, Capability::normalizeUri($uri));
        // §1.4: inbound dispatch must target the local peer.
        if (Capability::extractPeer($this->localPeer, $path) !== $this->localPeer) {
            return Outcome::err(404, 'handler_not_found', 'not local peer');
        }
        $pattern = $this->resolveHandler($path);
        if ($pattern === null) {
            return Outcome::err(404, 'handler_not_found', $path);
        }
        $capH = $exec->bytes('capability');
        $callerCap = $capH !== null ? $env->includedGet($capH) : null;
        if ($callerCap === null) {
            return Outcome::err(403, 'capability_denied');
        }
        $resolveFn = fn (string $h): ?Entity => Capability::capResolve($env->included, $this->store, $h);
        $granterPeer = Capability::resolveGranterPeerId($resolveFn, $callerCap) ?? $this->localPeer;
        if (Capability::checkPermission($this->localPeer, $granterPeer, $exec, $callerCap, $pattern) === Verdict::Deny) {
            return Outcome::err(403, 'capability_denied');
        }
        $stripped = $this->stripLocal($pattern);
        $inst = $this->handlers[$stripped] ?? null;
        if ($inst !== null) {
            return $inst->handle($operation, new HandlerContext($exec, $conn, $env->included, $callerCap, $env));
        }
        return $this->entityNativeDispatch($pattern);
    }

    // ── bootstrap (§6.9) ─────────────────────────────────────────────────────────────

    /** @param array{0:string,1:?string,2:?string} ...$ops */
    private function opSpec(?string $input, ?string $output): EcfMap
    {
        $m = new EcfMap();
        if ($input !== null) {
            $m->put('input_type', $input);
        }
        if ($output !== null) {
            $m->put('output_type', $output);
        }
        return $m;
    }

    /** @param list<array{0:string,1:?string,2:?string}> $ops */
    private function bootstrapHandlerEntities(string $pattern, string $name, array $ops): void
    {
        $operations = new EcfMap();
        foreach ($ops as [$op, $input, $output]) {
            $operations->put($op, $this->opSpec($input, $output));
        }
        $this->store->bind("/{$this->localPeer}/{$pattern}", Entity::make('system/handler',
            Ecf::map('interface', "system/handler/{$pattern}")));
        $this->store->bind("/{$this->localPeer}/system/handler/{$pattern}", Entity::make('system/handler/interface',
            Ecf::map('pattern', $pattern, 'name', $name, 'operations', $operations)));
        $m = $this->mintToken($this->identity->identityHash(), [], null);
        $this->store->bind("/{$this->localPeer}/system/capability/grants/{$pattern}", $m['token']);
    }

    private function bootstrap(): void
    {
        // local identity entity in the store (root-granter resolution)
        $this->store->putEntity($this->identity->peerEntity);
        // publish the §9.5 core type floor
        CoreTypes::publish($this->store, $this->localPeer);

        // instantiate + register the MUST handler instances (the §6.6 → instance map)
        /** @var list<array{0:string,1:Handler,2:string,3:list<array{0:string,1:?string,2:?string}>}> $bootstrap */
        $bootstrap = [
            ['system/tree', new TreeHandler($this), 'Tree',
                [['get', null, null], ['put', null, null]]],
            ['system/handler', new HandlersHandler($this), 'Handlers',
                [['register', 'system/handler/register-request', 'system/handler/register-result'],
                 ['unregister', 'system/handler/unregister-request', null]]],
            ['system/type', new TypeHandler($this), 'Types',
                [['validate', 'system/type/validate-request', 'system/type/validate-result']]],
            ['system/capability', new CapabilityHandler($this), 'Capability',
                [['request', 'system/capability/request', 'system/capability/grant'],
                 ['revoke', 'system/capability/revoke-request', null],
                 ['configure', 'system/capability/policy-entry', null],
                 ['delegate', 'system/capability/delegate-request', 'system/capability/grant']]],
            ['system/protocol/connect', new ConnectHandler($this), 'Connect',
                [['hello', null, null], ['authenticate', null, null]]],
        ];
        foreach ($bootstrap as [$pattern, $handler, $name, $ops]) {
            $this->handlers[$pattern] = $handler;
            $this->bootstrapHandlerEntities($pattern, $name, $ops);
        }

        // §6.9a Peer Authority Bootstrap (L0 write-set): self-owner cap (root, full
        // scope over /{peer}/*, grantee = own identity; §6.9a.0 detached-sig shape)
        // + default scope-template entry. Read back by authenticate (dual-form).
        $policyBase = "/{$this->localPeer}/system/capability/policy/";
        $owner = $this->mintToken($this->identity->identityHash(), $this->ownerGrants(), null);
        $this->store->bind($policyBase . \bin2hex($this->identity->identityHash()), $owner['token']);
        $this->store->bind("/{$this->localPeer}/system/signature/" . \bin2hex($owner['token']->hash()), $owner['signature']);
        $defaultGrants = $this->openGrants ? $this->openGrantsScope() : $this->discoveryFloor();
        $defaultEntry = Entity::make('system/capability/policy-entry', Ecf::map(
            'peer_pattern', 'default', 'grants', \array_values($defaultGrants)));
        $this->store->bind($policyBase . 'default', $defaultEntry);

        // §7a conformance handlers — only bootstrapped under --validate
        if ($this->conformance) {
            $conf = [
                ['system/validate/echo', new EchoHandler($this), 'validate-echo',
                    [['echo', null, null]]],
                ['system/validate/dispatch-outbound', new DispatchOutboundHandler($this),
                    'validate-dispatch-outbound', [['dispatch', null, null]]],
            ];
            foreach ($conf as [$pattern, $handler, $name, $ops]) {
                $this->handlers[$pattern] = $handler;
                $this->bootstrapHandlerEntities($pattern, $name, $ops);
            }
        }
    }
}
