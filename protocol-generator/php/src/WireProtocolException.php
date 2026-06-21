<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A wire-level protocol fault (a malformed envelope/frame that is not a codec
 * canonicalization fault). Named WireProtocolException rather than
 * ProtocolErrorException to avoid a `...ErrorError` stutter (A-003 precedent). A
 * {@see TransportException} subclass — it ends the connection.
 */
class WireProtocolException extends TransportException
{
}
