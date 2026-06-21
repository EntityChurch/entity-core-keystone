<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Stateless helpers shared by the bootstrap handlers (the Peer.kt companion-object
 * statics, as a PHP helper class). Path/resource parsing + the §3.9 zero-hash +
 * register-pattern extraction.
 */
final class PeerHelpers
{
    /** The first resource target of an EXECUTE, or null. */
    public static function execResourceTarget(Entity $exec): ?string
    {
        $r = $exec->mapField('resource');
        if ($r === null) {
            return null;
        }
        $targets = Ecf::textList($r, 'targets');
        return $targets[0] ?? null;
    }

    /** §1.4 path validity (no NUL, no empty/`.`/`..` segments; abs paths peer-rooted). */
    public static function pathFlexOk(string $target): bool
    {
        if (\strpos($target, "\0") !== false) {
            return false;
        }
        $segs0 = \explode('/', $target);
        if (\str_starts_with($target, '/')) {
            if (\count($segs0) >= 2 && $segs0[0] === '') {
                $absOk = Capability::isPeerId($segs0[1]);
                $body = \array_slice($segs0, 1);
            } else {
                $absOk = false;
                $body = $segs0;
            }
        } else {
            $absOk = true;
            $body = $segs0;
        }
        if (!$absOk) {
            return false;
        }
        if ($body !== [] && \end($body) === '') {
            \array_pop($body);
        }
        foreach ($body as $seg) {
            if ($seg === '' || $seg === '.' || $seg === '..') {
                return false;
            }
        }
        return true;
    }

    public static function isZeroHash(string $h): bool
    {
        return \trim($h, "\0") === '';
    }

    /** @return list<EcfMap> */
    public static function reqGrants(?Entity $params): array
    {
        if ($params === null) {
            return [];
        }
        return Ecf::mapList($params->data(), 'grants') ?? [];
    }

    /** The {pattern} of a system/handler/{pattern} resource target, or null. */
    public static function registerPattern(Entity $exec): ?string
    {
        $target = self::execResourceTarget($exec);
        if ($target === null) {
            return null;
        }
        $prefix = 'system/handler/';
        if (!\str_starts_with($target, $prefix) || \strlen($target) === \strlen($prefix)) {
            return null;
        }
        return \substr($target, \strlen($prefix));
    }

    public static function registerPatternError(Entity $exec): Outcome
    {
        if (self::execResourceTarget($exec) === null) {
            return Outcome::err(400, 'ambiguous_resource', 'register/unregister require exactly one resource target');
        }
        return Outcome::err(400, 'invalid_resource', 'resource target MUST be system/handler/{pattern}');
    }
}
