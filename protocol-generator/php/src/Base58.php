<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Base58 (Bitcoin alphabet) encode/decode, hand-rolled (no Composer dep — dodges
 * a dep + a pin). Used for peer-id formatting/parsing (V7 §1.5). Each leading
 * zero byte maps to a leading "1", per the standard Base58 convention.
 *
 * Base58 needs unsigned arithmetic over arbitrary-size byte strings; PHP has no
 * native bignum, so this reuses the SAME GMP carrier as the codec
 * ([idiom].uint64_carrier) — no native-int path that could overflow to a lossy
 * float.
 */
final class Base58
{
    private const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    /** Encode a binary string to a Base58 (ASCII) string. */
    public static function encode(string $bin): string
    {
        $len = \strlen($bin);
        $zeros = 0;
        while ($zeros < $len && $bin[$zeros] === "\x00") {
            $zeros++;
        }

        // GMP imports the bytes as a big-endian unsigned integer (no float path).
        $n = $len === 0 ? \gmp_init(0) : \gmp_import($bin, 1, \GMP_MSW_FIRST | \GMP_BIG_ENDIAN);

        $body = '';
        $fifty8 = \gmp_init(58);
        while (\gmp_cmp($n, 0) > 0) {
            [$n, $rem] = \gmp_div_qr($n, $fifty8);
            $body = self::ALPHABET[\gmp_intval($rem)] . $body;
        }

        return \str_repeat('1', $zeros) . $body;
    }

    /** Decode a Base58 string back to a binary string. */
    public static function decode(string $str): string
    {
        $len = \strlen($str);
        $ones = 0;
        while ($ones < $len && $str[$ones] === '1') {
            $ones++;
        }

        $n = \gmp_init(0);
        $fifty8 = \gmp_init(58);
        for ($i = 0; $i < $len; $i++) {
            $idx = \strpos(self::ALPHABET, $str[$i]);
            if ($idx === false) {
                throw new CodecException('invalid base58 character: ' . $str[$i]);
            }
            $n = \gmp_add(\gmp_mul($n, $fifty8), $idx);
        }

        $body = \gmp_cmp($n, 0) === 0 ? '' : \gmp_export($n, 1, \GMP_MSW_FIRST | \GMP_BIG_ENDIAN);

        return \str_repeat("\x00", $ones) . $body;
    }
}
