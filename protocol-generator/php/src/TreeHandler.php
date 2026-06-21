<?php

declare(strict_types=1);

namespace EntityCore;

/** §6.3 — the tree handler (get / put). */
final class TreeHandler implements Handler
{
    public function __construct(private readonly Peer $peer)
    {
    }

    public function handle(string $operation, HandlerContext $ctx): Outcome
    {
        return match ($operation) {
            'get' => $this->get($ctx),
            'put' => $this->put($ctx),
            default => Outcome::err(501, 'unsupported_operation', $operation),
        };
    }

    private function get(HandlerContext $ctx): Outcome
    {
        $exec = $ctx->exec;
        $local = $this->peer->localPeer;
        $target = PeerHelpers::execResourceTarget($exec);
        if ($target !== null && !PeerHelpers::pathFlexOk($target)) {
            return Outcome::err(400, 'invalid_path', $target);
        }
        if ($target === null) {
            return $this->buildListing("/{$local}/");
        }
        if ($target === '' || \str_ends_with($target, '/')) {
            return $this->buildListing(Capability::canonicalize($local, $target));
        }
        $path = Capability::canonicalize($local, $target);
        $e = $this->peer->store->getAt($path);
        if ($e === null) {
            return Outcome::err(404, 'not_found', $path);
        }
        $mode = $exec->entityField('params')?->text('mode');
        if ($mode === 'hash') {
            return Outcome::ok(Entity::make('system/hash', Ecf::map('hash', new ByteString($e->hash()))));
        }
        return Outcome::ok($e);
    }

    private function put(HandlerContext $ctx): Outcome
    {
        $exec = $ctx->exec;
        $local = $this->peer->localPeer;
        $target = PeerHelpers::execResourceTarget($exec);
        if ($target === null) {
            return Outcome::err(400, 'ambiguous_resource', 'tree: missing resource target');
        }
        if (!PeerHelpers::pathFlexOk($target)) {
            return Outcome::err(400, 'invalid_path', $target);
        }
        $path = Capability::canonicalize($local, $target);
        $params = $exec->entityField('params');
        $entity = $params?->entityField('entity');
        $expected = $params?->bytes('expected_hash');
        $current = $this->peer->store->hashAt($path);
        if ($expected === null) {
            $casOk = true;
        } elseif (PeerHelpers::isZeroHash($expected)) {
            $casOk = $current === null;
        } else {
            $casOk = $current !== null && $current === \bin2hex($expected);
        }
        if (!$casOk) {
            return Outcome::err(409, 'hash_mismatch', $path);
        }
        if ($entity === null) {
            return Outcome::err(400, 'unexpected_params', 'put: missing entity');
        }
        $this->peer->store->bind($path, $entity);
        return Outcome::ok(Entity::make('system/hash', Ecf::map('hash', new ByteString($entity->hash()))));
    }

    private function buildListing(string $path): Outcome
    {
        $store = $this->peer->store;
        $entries = [];
        foreach ($store->listing($path) as $row) {
            if ($row['hash_hex'] !== null && !$row['has_children']
                && $this->isDeletionMarker(\hex2bin($row['hash_hex']))) {
                continue;
            }
            $entries[] = $row;
        }
        $entryMap = new EcfMap();
        foreach ($entries as $row) {
            if ($row['hash_hex'] !== null) {
                $data = Ecf::map('has_children', $row['has_children'], 'hash', new ByteString(\hex2bin($row['hash_hex'])));
            } else {
                $data = Ecf::map('has_children', $row['has_children']);
            }
            $le = Entity::make('system/tree/listing-entry', $data);
            $entryMap->put($row['segment'], $le->toCbor());
        }
        return Outcome::ok(Entity::make('system/tree/listing', Ecf::map(
            'path', $path,
            'entries', $entryMap,
            'count', \count($entries),
            'offset', 0,
        )));
    }

    private function isDeletionMarker(string $h): bool
    {
        return $this->peer->store->getByHash($h)?->type === 'system/deletion-marker';
    }
}
