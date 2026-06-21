<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * §1.6 / §6.12 transport-layer failure: a malformed frame, a frame exceeding the
 * §1.6 / §4.10(a) bound, or a connection closed during a framed read/write. A
 * transport fault ENDS the connection (distinct from a protocol-status
 * {@see Outcome}, which is replied over the still-open connection).
 */
class TransportException extends EntityCoreException
{
}
