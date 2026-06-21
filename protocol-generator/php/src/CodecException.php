<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * CBOR / canonicalization / decode faults (ECF §6.x).
 *
 * The codec throws CodecException subclasses; the peer layer (S3) catch-maps
 * them to §5.2a / §6.12 status codes at the dispatch boundary.
 */
class CodecException extends EntityCoreException
{
}
