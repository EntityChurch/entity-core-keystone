<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * §4.10(a): an inbound frame whose length prefix exceeds the §1.6 max
 * (16 MiB) — rejected BEFORE the body is buffered. A {@see ProtocolException}
 * (the dispatch boundary maps it to 413 payload_too_large); at the transport the
 * over-limit prefix is unrecoverable (the body boundary is unknown) so the
 * connection is closed.
 */
class PayloadTooLargeException extends ProtocolException
{
}
