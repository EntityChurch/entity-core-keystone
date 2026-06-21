<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A protocol-layer fault distinct from a codec fault: an envelope/handshake/
 * capability violation surfaced at the dispatch boundary. The peer catch-maps
 * these to §5.2a / §6.12 status codes (the recoverable protocol path stays as
 * an {@see Outcome}; this is the throw side of the seam — profile [error_model]).
 */
class ProtocolException extends EntityCoreException
{
}
