<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * The per-dispatch context handed to a {@see Handler} (§6.13(a) HandlerContext
 * shape): the EXECUTE entity, the connection it arrived on (the §6.11 reentry
 * outbound seam lives here), the envelope `included` list, and the resolved
 * caller capability (null on the connect handler, which runs pre-authorization).
 *
 * `handlerPattern` is CARRIED, never recomputed: §6.3's path check needs the handler
 * pattern and the caller's capability, and the dispatch-level check already computed
 * both. Recomputing invites the two to drift, and §6.8 is explicit that the authority is
 * selected by who named the path. It is the OWNING handler's pattern (§6.3, 0.8.2.23) —
 * for the tree handler owner and runner coincide, so the distinction is not observable
 * here, but the field is named for the owner. It is null on the unauthenticated connect
 * path, which has no resolved handler entity.
 */
final class HandlerContext
{
    /**
     * @param list<array{hash:string,entity:Entity}> $included
     */
    public function __construct(
        public readonly Entity $exec,
        public readonly Conn $conn,
        public readonly array $included,
        public readonly ?Entity $callerCap,
        public readonly Envelope $env,
        public readonly ?string $handlerPattern = null,
    ) {
    }

    /** The EXECUTE `params` entity (any ECF `data`; never assume a map). */
    public function params(): ?Entity
    {
        return $this->exec->entityField('params');
    }
}
