<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Peer-layer value helpers over the S2 codec value model — the {@see Cbor}
 * (codec) analogue at the protocol altitude. Keeps the peer code reading as
 * map/list builders + typed field reads instead of restating the value model
 * inline.
 *
 * == The value model the peer builds on (A-PHP-007 / A-JAVA-010)
 *
 * The codec decodes a CBOR map to an {@see EcfMap} (NOT a native PHP array — a
 * native array cannot carry byte-string keys, which the `included` content-hash
 * map needs), a byte string to a {@see ByteString}, a text string to a bare PHP
 * `string`, an integer to `int`|`\GMP`, an array to a `list`, and a float to
 * `float`. The peer therefore:
 *   - builds maps as {@see EcfMap} so a content-hash key is a {@see ByteString}
 *     (a bare PHP string would encode as a TEXT key — the wrong major type);
 *   - reads fields through {@see get}/{@see text}/{@see bytes}/{@see uint}, never
 *     by array index, and NEVER assumes `data` is a map (it may be a scalar).
 *
 * The encoder canonicalizes map key order, so the peer builds maps in any order.
 *
 * == hex (A-CL-009 trap)
 *
 * {@see hex} renders LOWERCASE — the §3.4/§3.5 tree-path address-space
 * convention (`system/signature/{hash}`, the §5.1 revocation marker, the §6.9a
 * policy path are case-sensitive string keys). bin2hex() is lowercase by default
 * in PHP; we PIN it (never strtoupper).
 */
final class Ecf
{
    // ── map / list builders ─────────────────────────────────────────────────

    /**
     * Build an {@see EcfMap} from alternating key, value pairs. A `string` key
     * becomes a TEXT key; a {@see ByteString} key stays a byte key; values pass
     * through (a bare `string` value is TEXT; wrap bytes with {@see bytes}).
     */
    public static function map(mixed ...$kvs): EcfMap
    {
        if (\count($kvs) % 2 !== 0) {
            throw new UnsupportedValueException('odd key/value count');
        }
        $m = new EcfMap();
        for ($i = 0; $i < \count($kvs); $i += 2) {
            $m->put($kvs[$i], $kvs[$i + 1]);
        }
        return $m;
    }

    /** The canonical empty map (encodes to the single byte 0xA0). */
    public static function emptyMap(): EcfMap
    {
        return new EcfMap();
    }

    /** Wrap raw octets as a CBOR byte string (major 2). */
    public static function bytes(string $octets): ByteString
    {
        return new ByteString($octets);
    }

    /**
     * A CBOR array (major 4) of text strings.
     *
     * @param list<string> $items
     * @return list<string>
     */
    public static function textArray(array $items): array
    {
        return \array_values($items);
    }

    // ── typed field reads (over an EcfMap, null-safe) ────────────────────────

    /** A map view of $v, or null if $v is not an {@see EcfMap}. */
    public static function asMap(mixed $v): ?EcfMap
    {
        return $v instanceof EcfMap ? $v : null;
    }

    /** A TEXT-string field, or null. */
    public static function text(?EcfMap $m, string $key): ?string
    {
        $v = $m?->get($key);
        return \is_string($v) ? $v : null;
    }

    /** A BYTE-string field's raw octets, or null. */
    public static function bytes_(?EcfMap $m, string $key): ?string
    {
        $v = $m?->get($key);
        return $v instanceof ByteString ? $v->bytes : null;
    }

    /**
     * An unsigned/integer field as a {@see \GMP} (uniform — head-form values may
     * be `int` OR `\GMP` off the wire; A-PHP-003). Returns null if absent or not
     * an integer. Compare via gmp_cmp; NEVER blind-cast a `\GMP` past PHP_INT_MAX.
     */
    public static function uint(?EcfMap $m, string $key): ?\GMP
    {
        $v = $m?->get($key);
        if (\is_int($v)) {
            return \gmp_init($v);
        }
        if ($v instanceof \GMP) {
            return $v;
        }
        return null;
    }

    /**
     * The text values of an array field (non-text items skipped), or null.
     *
     * @return list<string>|null
     */
    public static function textList(?EcfMap $m, string $key): ?array
    {
        $v = $m?->get($key);
        if (!\is_array($v)) {
            return null;
        }
        $out = [];
        foreach ($v as $item) {
            if (\is_string($item)) {
                $out[] = $item;
            }
        }
        return $out;
    }

    /**
     * The {@see EcfMap} values of an array field, or null.
     *
     * @return list<EcfMap>|null
     */
    public static function mapList(?EcfMap $m, string $key): ?array
    {
        $v = $m?->get($key);
        if (!\is_array($v)) {
            return null;
        }
        $out = [];
        foreach ($v as $item) {
            if ($item instanceof EcfMap) {
                $out[] = $item;
            }
        }
        return $out;
    }

    public static function isTrue(mixed $v): bool
    {
        return $v === true;
    }

    // ── hex (LOWERCASE — §3.4/§3.5; A-CL-009) ────────────────────────────────

    public static function hex(string $octets): string
    {
        return \bin2hex($octets); // lowercase by default in PHP — PINNED
    }

    public static function unhex(string $hex): string
    {
        $b = \hex2bin($hex);
        if ($b === false) {
            throw new UnsupportedValueException("invalid hex: {$hex}");
        }
        return $b;
    }

    /** Constant-time-ish octet equality (both non-null and byte-identical). */
    public static function octetsEqual(?string $a, ?string $b): bool
    {
        return $a !== null && $b !== null && \hash_equals($a, $b);
    }
}
