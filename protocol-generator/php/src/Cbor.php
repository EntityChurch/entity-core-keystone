<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Entity Canonical Form (ECF) — hand-rolled canonical CBOR encoder/decoder
 * (ENTITY-CBOR-ENCODING.md v1.5). No PHP CBOR library delivers the full ECF
 * contract (length-FIRST map ordering on encoded key bytes, shortest-float incl.
 * f16, recursive major-type-6 rejection on decode, full uint64/nint range,
 * raw-byte `data` fidelity), so the canonical layer is owned here (A-PHP-001).
 *
 * == Value representation
 *
 * The decoder returns native PHP values where they map cleanly, and explicit
 * wrapper types where PHP cannot represent the CBOR distinction:
 *
 * | CBOR                    | PHP                                            |
 * |-------------------------|------------------------------------------------|
 * | unsigned / negative int | int (in [PHP_INT_MIN, PHP_INT_MAX]) | \GMP    |
 * | float (finite)          | float                                          |
 * | float NaN/+Inf/-Inf     | NAN / INF / -INF (native float specials)       |
 * | text string             | string (the default for a bare PHP string)     |
 * | byte string             | EntityCore\ByteString                          |
 * | array (CBOR major 4)    | list<mixed> (a sequential PHP array)           |
 * | map (CBOR major 5)      | array<string,mixed> (an associative PHP array) |
 * | bool                    | true / false                                   |
 * | null                    | null                                           |
 *
 * == The uint64 head-form carrier (A-PHP-003 — THE load-bearing decision)
 *
 * PHP `int` is 64-bit SIGNED (PHP_INT_MAX = 2^63-1) with no native bignum; a
 * literal beyond PHP_INT_MAX silently becomes a lossy float. So the CBOR uint64
 * head-form [2^63, 2^64-1] band CANNOT be a native int and must NEVER round-trip
 * through a float. The codec carries head-form values that fall outside the
 * signed-int range as \GMP objects, assembles their 8 wire bytes from the GMP
 * value (gmp_export), and decodes major-0 args >= 2^63 into \GMP — never an int
 * cast, never a float. Values that DO fit a signed int stay native int (the
 * common path); the >=2^63 band is the GMP path. Decode is uniform: it computes
 * in GMP and demotes to native int only when the value fits exactly.
 *
 * == Float representation on encode
 *
 * A native PHP `float` (is_float) is a CBOR float; a native `int` is a CBOR int.
 * PHP keeps 1.0 (float) distinct from 1 (int) at the value level, so no wrapper
 * is needed for the common case — but Float64 is accepted to carry an
 * integral-valued float unambiguously through a nested structure if desired.
 */
final class Cbor
{
    /** ECF §10.2 nesting limit. */
    public const MAX_DEPTH = 64;

    // Non-finite float sentinels (Rule 4a — exact bytes, no implementation
    // choice). NaN canonicalizes to the 0x7e00 payload.
    private const NAN_BYTES = "\xF9\x7E\x00";
    private const POS_INF_BYTES = "\xF9\x7C\x00";
    private const NEG_INF_BYTES = "\xF9\xFC\x00";
    private const NEG_ZERO_BYTES = "\xF9\x80\x00";

    // ═══════════════════════════════════════════════════════════════════════
    // Encode
    // ═══════════════════════════════════════════════════════════════════════

    /** Encode a PHP value to canonical ECF bytes (a binary string). */
    public static function encode(mixed $value): string
    {
        $buf = '';
        self::enc($value, $buf);
        return $buf;
    }

    private static function enc(mixed $value, string &$buf): void
    {
        if ($value === null) {
            $buf .= "\xF6";
        } elseif ($value === true) {
            $buf .= "\xF5";
        } elseif ($value === false) {
            $buf .= "\xF4";
        } elseif (\is_int($value)) {
            self::encInt($value, $buf);
        } elseif ($value instanceof \GMP) {
            self::encGmp($value, $buf);
        } elseif (\is_float($value)) {
            self::encFloat($value, $buf);
        } elseif ($value instanceof Float64) {
            self::encFloat($value->value, $buf);
        } elseif ($value instanceof ByteString) {
            self::head(2, $value->bytes, $buf);
            $buf .= $value->bytes;
        } elseif (\is_string($value)) {
            // A bare PHP string is a TEXT string (major 3) by default.
            self::headLen(3, \strlen($value), $buf);
            $buf .= $value;
        } elseif ($value instanceof EcfMap) {
            self::encEcfMap($value, $buf);
        } elseif (\is_array($value)) {
            self::encArray($value, $buf);
        } else {
            $t = \get_debug_type($value);
            throw new UnsupportedValueException("cannot ECF-encode value of type {$t}");
        }
    }

    /** Native-int head-form (always fits a signed 64-bit argument). */
    private static function encInt(int $n, string &$buf): void
    {
        if ($n >= 0) {
            self::headLen(0, $n, $buf);
        } else {
            // major 1: argument = -1 - n. For PHP_INT_MIN, -1 - n overflows a
            // native int, so route the negative argument through GMP.
            $arg = \gmp_sub(\gmp_init(-1), \gmp_init($n));
            self::headGmp(1, $arg, $buf);
        }
    }

    /**
     * GMP-carried head-form (A-PHP-003). Splits into a major-0 unsigned or a
     * major-1 negative and computes the argument purely in GMP, so the
     * [2^63, 2^64-1] band never touches a float or a native-int cast.
     */
    private static function encGmp(\GMP $n, string &$buf): void
    {
        if (\gmp_cmp($n, 0) >= 0) {
            self::headGmp(0, $n, $buf);
        } else {
            $arg = \gmp_sub(\gmp_init(-1), $n); // -1 - n, exact in GMP
            self::headGmp(1, $arg, $buf);
        }
    }

    /**
     * Emit a CBOR head byte + minimal argument for a NON-NEGATIVE native-int
     * argument (majors 0/2/3/4/5 lengths and the major-0 value path). Minimal
     * length per Rule 1.
     */
    private static function headLen(int $major, int $n, string &$buf): void
    {
        $mt = $major << 5;
        if ($n < 24) {
            $buf .= \chr($mt | $n);
        } elseif ($n < 0x100) {
            $buf .= \chr($mt | 24) . \chr($n);
        } elseif ($n < 0x10000) {
            $buf .= \chr($mt | 25) . \pack('n', $n);
        } elseif ($n < 0x100000000) {
            $buf .= \chr($mt | 26) . \pack('N', $n);
        } else {
            // A native int here is < 2^63 (PHP_INT_MAX), so pack('J') is exact.
            $buf .= \chr($mt | 27) . \pack('J', $n);
        }
    }

    /** head() for a ByteString length (delegates to headLen). */
    private static function head(int $major, string $payload, string &$buf): void
    {
        self::headLen($major, \strlen($payload), $buf);
    }

    /**
     * Emit a CBOR head byte + minimal argument for a NON-NEGATIVE GMP argument.
     * The [2^63, 2^64-1] band assembles its 8 wire bytes from the GMP value via
     * gmp_export — NEVER an int cast (which would overflow to a lossy float).
     */
    private static function headGmp(int $major, \GMP $n, string &$buf): void
    {
        $mt = $major << 5;
        if (\gmp_cmp($n, 24) < 0) {
            $buf .= \chr($mt | \gmp_intval($n));
        } elseif (\gmp_cmp($n, 0x100) < 0) {
            $buf .= \chr($mt | 24) . \chr(\gmp_intval($n));
        } elseif (\gmp_cmp($n, 0x10000) < 0) {
            $buf .= \chr($mt | 25) . self::gmpToBytes($n, 2);
        } elseif (\gmp_cmp($n, 0x100000000) < 0) {
            $buf .= \chr($mt | 26) . self::gmpToBytes($n, 4);
        } elseif (\gmp_cmp($n, \gmp_init('18446744073709551616')) < 0) { // < 2^64
            $buf .= \chr($mt | 27) . self::gmpToBytes($n, 8);
        } else {
            throw new UnsupportedValueException('integer argument exceeds uint64: ' . \gmp_strval($n));
        }
    }

    /** Big-endian, zero-padded $width-byte encoding of a non-negative GMP value. */
    private static function gmpToBytes(\GMP $n, int $width): string
    {
        if (\gmp_cmp($n, 0) === 0) {
            return \str_repeat("\x00", $width);
        }
        $raw = \gmp_export($n, 1, \GMP_MSW_FIRST | \GMP_BIG_ENDIAN);
        return \str_pad($raw, $width, "\x00", \STR_PAD_LEFT);
    }

    /** @param array<array-key,mixed> $arr */
    private static function encArray(array $arr, string &$buf): void
    {
        if (self::isList($arr)) {
            self::headLen(4, \count($arr), $buf);
            foreach ($arr as $item) {
                self::enc($item, $buf);
            }
        } else {
            self::encMap($arr, $buf);
        }
    }

    /**
     * Map (major 5) — keys sorted by ENCODED key bytes, length-FIRST then
     * lexicographic (RFC 8949 §4.2.1 / ECF Rule 2; the CTAP2 / length-first
     * order, NOT plain bytewise). Each key is encoded to its own buffer so the
     * sort is on the key's encoded form.
     *
     * @param array<array-key,mixed> $map
     */
    private static function encMap(array $map, string &$buf): void
    {
        $entries = [];
        foreach ($map as $k => $v) {
            $ek = self::encodeKey($k);
            $ev = self::encode($v);
            $entries[] = [$ek, $ev];
        }
        \usort($entries, static function (array $a, array $b): int {
            $la = \strlen($a[0]);
            $lb = \strlen($b[0]);
            if ($la !== $lb) {
                return $la <=> $lb;
            }
            return \strcmp($a[0], $b[0]); // bytewise within equal length
        });

        self::headLen(5, \count($map), $buf);
        foreach ($entries as [$ek, $ev]) {
            $buf .= $ek . $ev;
        }
    }

    /**
     * Encode an EcfMap (major 5) — keys sorted length-first then bytewise on
     * their encoded forms (the decoder output path; supports byte-string and
     * integer keys, not just text).
     */
    private static function encEcfMap(EcfMap $map, string &$buf): void
    {
        $entries = [];
        foreach ($map->entries() as [$k, $v]) {
            $entries[] = [self::encode($k), self::encode($v)];
        }
        \usort($entries, static function (array $a, array $b): int {
            $la = \strlen($a[0]);
            $lb = \strlen($b[0]);
            if ($la !== $lb) {
                return $la <=> $lb;
            }
            return \strcmp($a[0], $b[0]);
        });

        self::headLen(5, $map->count(), $buf);
        foreach ($entries as [$ek, $ev]) {
            $buf .= $ek . $ev;
        }
    }

    /**
     * Encode a map key. PHP array keys are int|string. An int key encodes as a
     * CBOR integer; a string key encodes as a CBOR TEXT string. (PHP coerces the
     * numeric string "1" to int 1 as an array key — a language fact; the corpus
     * uses non-numeric text keys and byte-string keys carried as ByteString
     * VALUES, not as native PHP array keys, so this is faithful for the corpus.)
     *
     * @param int|string $k
     */
    private static function encodeKey(int|string $k): string
    {
        return self::encode($k);
    }

    /**
     * Float ladder (Rule 4): specials → -0.0 → f16 → f32 → f64. A narrower
     * candidate is accepted only if it does not overflow to Inf (exponent not
     * all-ones) AND round-trips bit-exactly.
     */
    private static function encFloat(float $f, string &$buf): void
    {
        if (\is_nan($f)) {
            $buf .= self::NAN_BYTES;
            return;
        }
        if (\is_infinite($f)) {
            $buf .= $f > 0 ? self::POS_INF_BYTES : self::NEG_INF_BYTES;
            return;
        }
        if ($f === 0.0 && self::isNegativeZero($f)) {
            $buf .= self::NEG_ZERO_BYTES;
            return;
        }
        $b16 = self::fitsF16($f);
        if ($b16 !== null) {
            $buf .= "\xF9" . $b16;
            return;
        }
        $b32 = self::fitsF32($f);
        if ($b32 !== null) {
            $buf .= "\xFA" . $b32;
            return;
        }
        $buf .= "\xFB" . \pack('E', $f); // big-endian f64
    }

    private static function isNegativeZero(float $f): bool
    {
        // Detect -0.0 by its sign bit (PHP 8 throws on 1.0/0.0, so check bits).
        // -0.0 == 0.0 is true, so compare the raw 64-bit pattern instead.
        return $f === 0.0 && self::f64Bits($f) !== 0;
    }

    /**
     * Hand-assemble f16 from the IEEE-754 binary64 bits (PHP pack/unpack have no
     * half-float code — A-PHP-004). Returns the 2 big-endian half bytes if $f is
     * an EXACT finite f16 value (not an all-ones exponent → silent overflow to
     * Inf), else null. The Ruby A-RUBY-006 ladder shape.
     */
    private static function fitsF16(float $f): ?string
    {
        $bits = self::f64Bits($f);
        $sign = ($bits >> 63) & 0x1;
        $exp = ($bits >> 52) & 0x7FF;
        $mant = $bits & 0xFFFFFFFFFFFFF; // 52 bits

        // +0.0 (the -0.0 case is handled earlier).
        if ($exp === 0 && $mant === 0) {
            return \pack('n', $sign << 15);
        }

        $unbiased = $exp - 1023;
        // f16 normal exponent range is [-14, 15]; outside → not a finite f16.
        if ($unbiased < -14 || $unbiased > 15) {
            return null;
        }
        // The low 42 mantissa bits must be zero (f16 keeps 10; f64 has 52).
        if (($mant & 0x3FFFFFFFFFF) !== 0) {
            return null;
        }

        $halfMant = $mant >> 42;
        $halfExp = $unbiased + 15;
        $half = ($sign << 15) | ($halfExp << 10) | $halfMant;
        return \pack('n', $half);
    }

    /**
     * Returns the 4 big-endian f32 bytes if $f round-trips exactly through
     * binary32 without becoming Inf (all-ones-exponent guard), else null.
     */
    private static function fitsF32(float $f): ?string
    {
        $candidate = \pack('G', $f); // big-endian f32
        $bits = \unpack('N', $candidate)[1];
        $exp = ($bits >> 23) & 0xFF;
        if ($exp === 0xFF) {
            return null; // Inf/NaN — overflow, not exact
        }
        // Round-trip: does the f32 decode back to exactly $f?
        $back = \unpack('G', $candidate)[1];
        if ($back !== $f) {
            return null;
        }
        return $candidate;
    }

    /** Extract the raw 64-bit pattern of a double as an int (sign-safe). */
    private static function f64Bits(float $f): int
    {
        // pack('E') = big-endian f64; unpack('J') = big-endian uint64 → int.
        // PHP_INT is 64-bit signed; the bit pattern is carried exactly (no value
        // arithmetic is done on it, only bit masks/shifts), so the signed
        // reinterpretation is bit-faithful.
        return \unpack('J', \pack('E', $f))[1];
    }

    /** @param array<array-key,mixed> $arr */
    private static function isList(array $arr): bool
    {
        return \array_is_list($arr);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Decode
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Decode canonical ECF bytes to a PHP value. Throws a CodecException subclass
     * on any non-canonical input: a CBOR tag (major 6, N2), indefinite length, a
     * non-minimal argument, reserved additional-info, duplicate map key,
     * over-depth, or trailing bytes.
     */
    public static function decode(string $bin): mixed
    {
        $cur = new Cursor($bin);
        $value = self::decodeValue($cur, 0);
        if (!$cur->eof()) {
            throw new NonCanonicalEcfException('trailing bytes after value: ' . $cur->remaining() . ' byte(s)');
        }
        return $value;
    }

    private static function decodeValue(Cursor $cur, int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            throw new NonCanonicalEcfException('nesting deeper than ' . self::MAX_DEPTH);
        }

        $ib = $cur->readByte();
        $major = $ib >> 5;
        $info = $ib & 0x1F;

        switch ($major) {
            case 0:
                return self::demote(self::readArgument($info, $cur));
            case 1:
                // value = -1 - arg, computed in GMP then demoted.
                $arg = self::readArgument($info, $cur);
                return self::demote(\gmp_sub(\gmp_init(-1), $arg));
            case 2:
                $len = self::readLength($info, $cur);
                return new ByteString($cur->read($len));
            case 3:
                $len = self::readLength($info, $cur);
                $s = $cur->read($len);
                if (!\mb_check_encoding($s, 'UTF-8')) {
                    throw new NonCanonicalEcfException('invalid UTF-8 in text string');
                }
                return $s;
            case 4:
                $len = self::readLength($info, $cur);
                $list = [];
                for ($i = 0; $i < $len; $i++) {
                    $list[] = self::decodeValue($cur, $depth + 1);
                }
                return $list;
            case 5:
                return self::readMap($info, $cur, $depth + 1);
            case 6:
                // Invariant N2 / ECF §6.3 — tags MUST be rejected at any depth.
                throw new TagRejectedException('CBOR tag (major type 6) is not permitted in ECF');
            case 7:
                return self::readSimple($info, $cur);
            default:
                throw new NonCanonicalEcfException('unreachable major type: ' . $major);
        }
    }

    /**
     * Argument decode for majors 0/1 — returns a GMP (the value/argument may be
     * in the [2^63, 2^64-1] band). Enforces minimal-length encoding and rejects
     * reserved additional-info (28-30) and indefinite length (31).
     */
    private static function readArgument(int $info, Cursor $cur): \GMP
    {
        if ($info < 24) {
            return \gmp_init($info);
        }
        switch ($info) {
            case 24:
                $n = $cur->readByte();
                if ($n < 24) {
                    throw new NonCanonicalEcfException('non-minimal uint8 argument: ' . $n);
                }
                return \gmp_init($n);
            case 25:
                $n = \unpack('n', $cur->read(2))[1];
                if ($n < 0x100) {
                    throw new NonCanonicalEcfException('non-minimal uint16 argument: ' . $n);
                }
                return \gmp_init($n);
            case 26:
                $bytes = $cur->read(4);
                $n = \gmp_import($bytes, 1, \GMP_MSW_FIRST | \GMP_BIG_ENDIAN);
                if (\gmp_cmp($n, 0x10000) < 0) {
                    throw new NonCanonicalEcfException('non-minimal uint32 argument: ' . \gmp_strval($n));
                }
                return $n;
            case 27:
                $bytes = $cur->read(8);
                $n = \gmp_import($bytes, 1, \GMP_MSW_FIRST | \GMP_BIG_ENDIAN);
                if (\gmp_cmp($n, 0x100000000) < 0) {
                    throw new NonCanonicalEcfException('non-minimal uint64 argument: ' . \gmp_strval($n));
                }
                return $n;
            case 31:
                throw new NonCanonicalEcfException('indefinite length is not permitted in ECF');
            default: // 28, 29, 30
                throw new NonCanonicalEcfException('reserved additional-info value: ' . $info);
        }
    }

    /**
     * Length decode for majors 2-5 (string/array/map). The length must fit a
     * native int (any real container does); routes through readArgument so the
     * minimality + reserved/indefinite checks apply uniformly.
     */
    private static function readLength(int $info, Cursor $cur): int
    {
        $g = self::readArgument($info, $cur);
        if (\gmp_cmp($g, \gmp_init(\PHP_INT_MAX)) > 0) {
            throw new NonCanonicalEcfException('container length exceeds addressable size');
        }
        return \gmp_intval($g);
    }

    /** Demote a GMP value to a native int if it fits exactly; else keep GMP. */
    private static function demote(\GMP $g): int|\GMP
    {
        if (\gmp_cmp($g, \gmp_init(\PHP_INT_MIN)) >= 0 && \gmp_cmp($g, \gmp_init(\PHP_INT_MAX)) <= 0) {
            return \gmp_intval($g);
        }
        return $g;
    }

    /**
     * Read a map (major 5) into an EcfMap. Keys may be text strings, byte
     * strings, or integers (the corpus carries byte-string keys, which a native
     * PHP array cannot hold). Canonical key order is enforced strictly on the
     * wire: keys MUST be strictly ascending by their ENCODED bytes (length-first
     * then bytewise), which also rejects duplicates (a re-encode by THIS codec
     * then reproduces the input byte-identically).
     */
    private static function readMap(int $info, Cursor $cur, int $depth): EcfMap
    {
        $len = self::readLength($info, $cur);
        $map = new EcfMap();
        $prevKeyBytes = null;
        for ($i = 0; $i < $len; $i++) {
            // Capture the raw encoded key bytes for canonical-order checking.
            $keyStart = $cur->pos();
            $key = self::decodeValue($cur, $depth);
            $keyBytes = $cur->slice($keyStart, $cur->pos() - $keyStart);

            if ($prevKeyBytes !== null && self::keyCmp($prevKeyBytes, $keyBytes) >= 0) {
                throw new NonCanonicalEcfException('map keys not in canonical order (or duplicate)');
            }
            $prevKeyBytes = $keyBytes;

            $val = self::decodeValue($cur, $depth);
            $map->put($key, $val);
        }
        return $map;
    }

    /** Canonical key comparison: length-first then bytewise. */
    private static function keyCmp(string $a, string $b): int
    {
        $la = \strlen($a);
        $lb = \strlen($b);
        if ($la !== $lb) {
            return $la <=> $lb;
        }
        return \strcmp($a, $b);
    }

    private static function readSimple(int $info, Cursor $cur): mixed
    {
        switch ($info) {
            case 20:
                return false;
            case 21:
                return true;
            case 22:
                return null;
            case 25:
                return self::decodeF16($cur->read(2));
            case 26:
                return self::decodeF32($cur->read(4));
            case 27:
                return \unpack('E', $cur->read(8))[1];
            default:
                throw new NonCanonicalEcfException('unsupported simple/float additional-info: ' . $info);
        }
    }

    /** Decode a half-float (no native unpack). Specials → native NAN / ±INF. */
    private static function decodeF16(string $two): float
    {
        $bits = \unpack('n', $two)[1];
        $sign = ($bits >> 15) & 0x1;
        $exp = ($bits >> 10) & 0x1F;
        $mant = $bits & 0x3FF;

        if ($exp === 0x1F) {
            if ($mant !== 0) {
                return \NAN;
            }
            return $sign === 1 ? -\INF : \INF;
        }

        if ($exp === 0) {
            // subnormal: 2^-14 * (mant/1024). PHP has no ldexp(); 2.0 ** e is an
            // exact power-of-two double for these small exponents.
            $value = ($mant / 1024.0) * (2.0 ** -14);
        } else {
            $value = (1.0 + $mant / 1024.0) * (2.0 ** ($exp - 15));
        }
        return $sign === 1 ? -$value : $value;
    }

    private static function decodeF32(string $four): float
    {
        $bits = \unpack('N', $four)[1];
        $exp = ($bits >> 23) & 0xFF;
        $mant = $bits & 0x7FFFFF;
        if ($exp === 0xFF) {
            if ($mant !== 0) {
                return \NAN;
            }
            $sign = ($bits >> 31) & 0x1;
            return $sign === 1 ? -\INF : \INF;
        }
        return \unpack('G', $four)[1];
    }
}
