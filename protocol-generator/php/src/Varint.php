<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Multicodec-style unsigned LEB128 varints (V7 §1.5 / §7.3, invariant N1).
 *
 * Used for the format-code / key-type / hash-type framing in content hashes and
 * peer-ids. Every currently-allocated code is < 0x80 (a single byte), but the
 * framing routes through a real LEB128 primitive so a future code >= 0x80 extends
 * to multiple bytes correctly instead of silently truncating (N1 — the bug class
 * that bit the reference impls). Codes stay well within native PHP int range, so
 * GMP is not needed here (the carrier trap is in the CBOR head-form, not framing).
 */
final class Varint
{
    /** Encode a non-negative int as unsigned LEB128 (a binary string). */
    public static function encode(int $n): string
    {
        if ($n < 0) {
            throw new UnsupportedValueException("varint must be non-negative: {$n}");
        }
        $out = '';
        do {
            $byte = $n & 0x7F;
            $n >>= 7;
            if ($n !== 0) {
                $byte |= 0x80;
            }
            $out .= \chr($byte);
        } while ($n !== 0);
        return $out;
    }

    /**
     * Decode an unsigned LEB128 varint from the front of $bin.
     *
     * @return array{0:int,1:string} [value, rest]
     */
    public static function decode(string $bin): array
    {
        $value = 0;
        $shift = 0;
        $len = \strlen($bin);
        $i = 0;
        while (true) {
            if ($i >= $len) {
                throw new TruncatedInputException('truncated varint');
            }
            $byte = \ord($bin[$i]);
            $i++;
            $value |= ($byte & 0x7F) << $shift;
            if (($byte & 0x80) === 0) {
                break;
            }
            $shift += 7;
        }
        return [$value, \substr($bin, $i)];
    }
}
