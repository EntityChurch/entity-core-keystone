<?php

declare(strict_types=1);

namespace EntityCore;

/** §6.3 — the tree handler (get / put). */
final class TreeHandler implements Handler
{
    public function __construct(private readonly Peer $peer)
    {
    }

    /**
     * RULE: RESOLVE THE OPERATION FIRST, ONLY THEN RUN THE §3.3 RESOURCE LADDER.
     *
     * An unknown operation is an OPERATION fault (501); a resource fault is 400. A
     * handler that validates the resource first answers a RESOURCE error for every
     * unknown operation — measured across the cohort as `system/tree:bogusop` WITHOUT a
     * resource answering `ambiguous_resource` while the same call WITH one correctly
     * answered 501, i.e. the fault the caller is told about depended on a field with
     * nothing to do with it. This `match` resolves the operation before anything reads
     * `resource`, and the whole ladder lives INSIDE the two arms, which keeps it that way
     * by construction.
     */
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
        // §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
        // resource.targets: a handler that counts the effective list and then indexes
        // targets[0] has implemented the arithmetic completely and is still reading a
        // path no authorization covered.
        $eff = Capability::effectiveTargets($local, $exec);
        if ($eff === null) {
            // THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION IS
            // WHAT SAYS SO. §3.3's "an empty effective list IS the absent case" is scoped
            // "for an operation that REQUIRES a resource" (0.8.2.24, N7); `get` does not.
            // For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
            // present-but-empty case by whether the absent case is WIDER than the request
            // — BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty — and requires
            // the operation to declare which it is.
            //
            // EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
            // resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root listing",
            // self-excluded case "400 path_required". So both arms here are pinned by
            // text and neither is this peer's choice.
            return $this->buildListing("/{$local}/", $ctx);
        }
        if ($eff === []) {
            // `resource` PRESENT, every target carved out by the caller's own exclude.
            // Serving it the absent case "answers a request for one excluded path with a
            // listing of the tree" (EXTENSION-TREE §2.2a) — the root listing is wider
            // than what was asked for, which is what BROAD-RESULT means.
            return Outcome::err(400, 'path_required', 'tree: effective target list is empty');
        }
        if (\count($eff) > 1) {
            return Outcome::err(400, 'ambiguous_resource', 'tree: more than one effective target');
        }
        $target = $eff[0];
        if (!PeerHelpers::pathFlexOk($target)) {
            return Outcome::err(400, 'invalid_path', $target);
        }
        if ($target === '' || \str_ends_with($target, '/')) {
            return $this->buildListing(Capability::canonicalize($local, $target), $ctx);
        }
        if (PeerHelpers::isPatternPath($target)) {
            return Outcome::err(400, 'malformed_resource', $target);
        }
        $path = Capability::canonicalize($local, $target);
        // §6.3: the handler MUST verify the CALLER's capability covers the path it is
        // about to read. Not a secondary check — the dispatch-level check never saw this
        // path if the caller excluded it.
        if ($ctx->callerCap !== null
            && !Capability::checkPathPermission($local, 'get', $path, $ctx->callerCap, $ctx->handlerPattern ?? '')) {
            return Outcome::err(403, 'capability_denied', $path);
        }
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
        // Same ladder as {@see get}, with the two empties COLLAPSED rather than split:
        // EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's "an
        // empty effective list IS the absent case" applies in its unscoped form and both
        // empties answer `path_required`. That is the same table `get`'s branch cites,
        // read one row down — the field is per-operation and neither answer is derivable
        // from this handler's source.
        //
        // Note the code change 0.8.2.20 forced: this branch answered `ambiguous_resource`
        // for a MISSING target, which 0.8.2.20 names as the exact inversion it forbids
        // ("answering ambiguous_resource for an absent resource inverts them"). The
        // remedies differ — *supply a resource* is not *disambiguate your request* — and
        // the code is what selects between them.
        $eff = Capability::effectiveTargets($local, $exec);
        if ($eff === null || $eff === []) {
            return Outcome::err(400, 'path_required', 'tree: put requires a resource target');
        }
        if (\count($eff) > 1) {
            return Outcome::err(400, 'ambiguous_resource', 'tree: more than one effective target');
        }
        $target = $eff[0];
        if (!PeerHelpers::pathFlexOk($target)) {
            return Outcome::err(400, 'invalid_path', $target);
        }
        if (PeerHelpers::isPatternPath($target)) {
            return Outcome::err(400, 'malformed_resource', $target);
        }
        $path = Capability::canonicalize($local, $target);
        // §6.3 (see get): the CALLER's capability must cover the path this handler is
        // about to write, because the caller's own exclude can vacate the dispatch-level
        // check.
        if ($ctx->callerCap !== null
            && !Capability::checkPathPermission($local, 'put', $path, $ctx->callerCap, $ctx->handlerPattern ?? '')) {
            return Outcome::err(403, 'capability_denied', $path);
        }
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

    /**
     * §6.3's per-entry listing check for one child segment (0.8.2.21/.22).
     *
     * An unauthenticated context is the bootstrap/internal path and is NOT filtered: the
     * filter's subject is "the caller's verified capability", and where there is none
     * there is no caller to narrow.
     */
    private function entryVisible(?HandlerContext $ctx, string $dir, string $segment): bool
    {
        if ($ctx === null || $ctx->callerCap === null) {
            return true;
        }
        $child = (\str_ends_with($dir, '/') ? $dir : $dir . '/') . $segment;
        return Capability::checkPathPermission(
            $this->peer->localPeer,
            'get',
            $child,
            $ctx->callerCap,
            $ctx->handlerPattern ?? '',
        );
    }

    /**
     * Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
     *
     * "When any handler returns a multi-entry result whose entries are tree paths, each
     * entry MUST be individually checked using `check_path_permission`. Entries for which
     * `check_path_permission` returns DENY MUST be omitted. The result's `count` field
     * MUST reflect the filtered entry count, not the source tree's total count."
     *
     * This is the read path at its highest volume and it is the reason 0.8.2.21 refused
     * to carve reads out of the caller-specified-path rule: an unfiltered listing
     * discloses the EXISTENCE of every binding under a prefix to a caller whose
     * capability covers none of them. A `count` following the SOURCE total is that
     * disclosure by itself, which is why it is computed from the emitted entries.
     *
     * The DIRECTORY itself is deliberately NOT checked — §6.3 makes each ENTRY the
     * subject, and testing the prefix would deny a listing to a caller whose grant covers
     * children but not the node above them, which is the ordinary shape of a narrowed
     * grant.
     */
    private function buildListing(string $path, ?HandlerContext $ctx = null): Outcome
    {
        $store = $this->peer->store;
        $entries = [];
        foreach ($store->listing($path) as $row) {
            if ($row['hash_hex'] !== null && !$row['has_children']
                && $this->isDeletionMarker(\hex2bin($row['hash_hex']))) {
                continue;
            }
            if (!$this->entryVisible($ctx, $path, $row['segment'])) {
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
