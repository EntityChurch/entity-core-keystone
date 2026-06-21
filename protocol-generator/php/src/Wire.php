<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
 * EXECUTE_RESPONSE). Frame := `[4-byte BE length][CBOR payload]`; the payload is
 * a canonical-ECF-encoded system/protocol/envelope (§3.1).
 *
 * Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
 * authenticate are OPERATIONS on system/protocol/connect, not message types — any
 * other root type is ignored on the server side (the dispatcher returns no
 * response).
 */
final class Wire
{
    /** §1.6 / §4.10(a) bound — 16 MiB max inbound payload. */
    public const MAX_FRAME = 16 * 1024 * 1024;

    // ── envelope <-> frame ──────────────────────────────────────────────────────

    public static function frameOfEnvelope(Envelope $env): string
    {
        return Cbor::encode($env->toCbor());
    }

    public static function envelopeOfFrame(string $payload): Envelope
    {
        $v = Cbor::decode($payload);
        if (!($v instanceof EcfMap)) {
            throw new WireProtocolException('frame: not a map');
        }
        return Envelope::ofCbor($v);
    }

    /** Prefix $payload with its 4-byte big-endian length. */
    public static function frame(string $payload): string
    {
        return \pack('N', \strlen($payload)) . $payload;
    }

    // ── EXECUTE builder (§3.2) ────────────────────────────────────────────────────

    public static function makeExecute(
        string $requestId,
        string $uri,
        string $operation,
        Entity $params,
        ?string $author = null,
        ?string $capability = null,
        ?EcfMap $resource = null,
    ): Entity {
        $m = new EcfMap();
        $m->put('request_id', $requestId);
        $m->put('uri', $uri);
        $m->put('operation', $operation);
        $m->put('params', $params->toCbor());
        if ($author !== null) {
            $m->put('author', new ByteString($author));
        }
        if ($capability !== null) {
            $m->put('capability', new ByteString($capability));
        }
        if ($resource !== null) {
            $m->put('resource', $resource);
        }
        return Entity::make('system/protocol/execute', $m);
    }

    // ── EXECUTE_RESPONSE builder (§3.3) ────────────────────────────────────────────

    public static function makeResponse(string $requestId, int $status, Entity $result): Entity
    {
        return Entity::make('system/protocol/execute/response', Ecf::map(
            'request_id', $requestId,
            'status', $status,
            'result', $result->toCbor(),
        ));
    }

    public static function errorResult(string $code, ?string $message): Entity
    {
        $data = $message !== null
            ? Ecf::map('code', $code, 'message', $message)
            : Ecf::map('code', $code);
        return Entity::make('system/protocol/error', $data);
    }

    /** Empty-params (§3.2): a primitive/any whose data is the canonical empty map. */
    public static function emptyParams(): Entity
    {
        return Entity::make('primitive/any', Ecf::emptyMap());
    }

    /**
     * Build a resource map `{targets: [...]}`.
     *
     * @param string ...$targets
     */
    public static function resourceTarget(string ...$targets): EcfMap
    {
        return Ecf::map('targets', \array_values($targets));
    }

    // ── response decode helpers (initiator side) ───────────────────────────────────

    public static function responseStatus(Envelope $env): int
    {
        $g = $env->root->uint('status');
        return $g === null ? 0 : \gmp_intval($g);
    }

    public static function responseResult(Envelope $env): ?Entity
    {
        $m = $env->root->mapField('result');
        return $m === null ? null : Entity::ofCbor($m);
    }
}
