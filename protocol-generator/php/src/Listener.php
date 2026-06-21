<?php

declare(strict_types=1);

namespace EntityCore;

/** A running listener: the bound server socket + a handle to stop it. */
final class Listener
{
    /** @param resource $server */
    public function __construct(
        private readonly EventLoop $loop,
        private $server,
        private readonly int $sourceId,
    ) {
    }

    public function close(): void
    {
        $this->loop->remove($this->sourceId);
        if (\is_resource($this->server)) {
            @\fclose($this->server);
        }
    }
}
