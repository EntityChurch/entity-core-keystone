<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A handler result: the §3.3 status + the result entity + the §3.1 `included`
 * authority the result carries (the §4.4 grant mint travels here). The
 * recoverable protocol path is this sealed-result seam (NOT a throw — exceptions
 * are reserved for the unrecoverable transport/codec boundary; profile
 * [error_model]).
 */
final class Outcome
{
    /**
     * @param list<array{hash:string,entity:Entity}> $included
     */
    private function __construct(
        public readonly int $status,
        public readonly Entity $result,
        public readonly array $included,
    ) {
    }

    /**
     * A 200 success.
     *
     * @param list<array{hash:string,entity:Entity}> $included
     */
    public static function ok(Entity $result, array $included = []): self
    {
        return new self(200, $result, $included);
    }

    /** An error status with a system/protocol/error result body. */
    public static function err(int $status, string $code, ?string $message = null): self
    {
        return new self($status, Wire::errorResult($code, $message), []);
    }
}
