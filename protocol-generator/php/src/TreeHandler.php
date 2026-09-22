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
        $rawEntity = $params?->field('entity');
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
        if ($rawEntity === null) {
            return Outcome::err(400, 'unexpected_params', 'put: missing entity');
        }
        $admitted = $this->admitPut($rawEntity);
        if ($admitted instanceof Outcome) {
            return $admitted;
        }
        $entity = $admitted;
        $this->peer->store->bind($path, $entity);
        return Outcome::ok(Entity::make('system/hash', Ecf::map('hash', new ByteString($entity->hash()))));
    }

    /**
     * Digest byte length for a `content_hash_format` code per the §1.2 seed table,
     * or null when this peer cannot VERIFY that code. The total wire length is this
     * plus the varint prefix, which is not a constant of the code (§7.3): codes
     * >= 0x80 occupy more than one byte.
     */
    private const HASH_DIGEST_LEN = [0x00 => 32, 0x01 => 48];

    /**
     * §6.3's `put` admission ladder (normative, 0.8.2.11).
     *
     * `put` is a RECEIPT path: the submitter authors the entity, the peer validates
     * what it received (§1.8 item 1) and MUST NOT author a submitted entity's
     * `content_hash` on the submitter's behalf. Two ordered steps:
     *
     *  1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any
     *     CBOR value; null is a legal payload), and a `content_hash` that is a
     *     well-formed `system/hash` whose total byte length matches its format code
     *     (§1.2). Any failure -> 400 `invalid_request`. A well-formed hash naming a
     *     format code this peer cannot verify is the separate §1.2 ingest-dispatch
     *     case -> 400 `unsupported_content_hash_format`.
     *  2. HASH — carried `content_hash` vs `content_hash({type, data})`.
     *     Disagreement -> 400 `hash_mismatch`.
     *
     * Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
     * inputs are exactly what step 1 establishes, so a submission that is both
     * malformed and mis-hashed is step 1's and answers `invalid_request`.
     *
     * Structural admission is not semantic validation: `data` is never checked
     * against the type named by `type`.
     *
     * @return Entity|Outcome the admitted entity, or the refusal
     */
    private function admitPut(mixed $v): Entity|Outcome
    {
        $refuse = static fn (string $code, string $message): Outcome
            => Outcome::err(400, $code, $message);

        if (!$v instanceof EcfMap) {
            return $refuse('invalid_request', 'put: entity is not a map');
        }
        $type = $v->get('type');
        if (!\is_string($type) || $type === '') {
            return $refuse('invalid_request', 'put: entity.type absent, empty or not a text string');
        }
        // Presence, not truthiness: a CBOR null is a legal `data` payload.
        if (!$v->hasTextKey('data')) {
            return $refuse('invalid_request', 'put: entity.data absent');
        }
        $data = $v->get('data');
        $ch = $v->get('content_hash');
        if (!$ch instanceof ByteString || $ch->bytes === '') {
            return $refuse('invalid_request', 'put: entity.content_hash absent or not a byte string');
        }
        $carried = $ch->bytes;
        try {
            [$formatCode, $rest] = Varint::decode($carried);
        } catch (TruncatedInputException) {
            return $refuse('invalid_request', 'put: entity.content_hash is not a well-formed system/hash');
        }
        $digestLen = self::HASH_DIGEST_LEN[$formatCode] ?? null;
        if ($digestLen === null) {
            // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
            // invalid_request: the shape is fine, the algorithm is what we lack.
            return $refuse('unsupported_content_hash_format', 'put: unsupported content_hash_format');
        }
        if (\strlen($rest) !== $digestLen) {
            return $refuse('invalid_request', 'put: content_hash length does not match its format code');
        }
        $computed = Hash::contentHash(['type' => $type, 'data' => $data], $formatCode);
        if (!\hash_equals($computed, $carried)) {
            return $refuse('hash_mismatch', 'put: content_hash does not match content_hash({type, data})');
        }
        // The carried hash IS the entity's address; recomputing it into the store
        // would be the authoring arm §6.3 forbids.
        return Entity::admitted($type, $data, $carried);
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
