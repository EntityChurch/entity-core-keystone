<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * The per-dispatch context handed to a {@see Handler} (§6.13(a) HandlerContext
 * shape): the EXECUTE entity, the connection it arrived on (the §6.11 reentry
 * outbound seam lives here), the envelope `included` list, and the resolved
 * caller capability (null on the connect handler, which runs pre-authorization).
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
    ) {
    }

    /** The EXECUTE `params` entity (any ECF `data`; never assume a map). */
    public function params(): ?Entity
    {
        return $this->exec->entityField('params');
    }
}
