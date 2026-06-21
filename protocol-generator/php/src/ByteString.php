<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A CBOR byte string (major type 2).
 *
 * PHP `string` IS a binary-safe byte buffer, but it cannot distinguish a CBOR
 * byte string (major 2) from a text string (major 3) on its own. The codec maps
 * a bare PHP `string` to a TEXT string by default (the common case — type names,
 * map keys) and uses this wrapper to mark the byte-string seam (digests, raw
 * keys, signatures). The decoder surfaces major-2 values as ByteString.
 *
 * This is the PHP analogue of Ruby's ASCII-8BIT vs UTF-8 String encoding seam and
 * TS's Uint8Array vs string seam — but explicit, because PHP `string` carries no
 * encoding tag. Wire bytes NEVER route through mb_* functions.
 */
final class ByteString implements \Stringable
{
    public function __construct(public readonly string $bytes)
    {
    }

    public static function of(string $bytes): self
    {
        return new self($bytes);
    }

    public function __toString(): string
    {
        return $this->bytes;
    }
}
