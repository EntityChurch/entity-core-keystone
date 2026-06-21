<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\ByteString;
use EntityCore\Cbor;
use EntityCore\EcfMap;
use EntityCore\NonCanonicalEcfException;
use EntityCore\PeerId;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The S2 codec spike — the load-bearing PHP-specific risks the corpus exercises
 * but which deserve targeted, explicit proof (PHASE-S1 mandate):
 *   1. The GMP uint64 head-form carrier (A-PHP-003) across the [2^63, 2^64-1]
 *      band — the band that overflows a native PHP int to a lossy float.
 *   2. The f16 / f32 / f64 shortest-float ladder (A-PHP-004) — no native pack
 *      half-float code.
 *   3. Length-first (CTAP2) canonical map-key ordering.
 *   4. Base58 + GMP round-trip (the carrier reused for peer-id math).
 */
final class CodecSpikeTest extends TestCase
{
    /**
     * THE #1 correctness risk: the uint64 head-form band [2^63, 2^64-1] must
     * NEVER touch a PHP float or int cast. Build the 8 wire bytes from the GMP
     * value and decode back to GMP exactly. Goes BEYOND the corpus (int.10 tops
     * out at 2^63-1) — this is the past-i64::MAX coverage the oracle can't see.
     *
     */
    #[DataProvider('uint64BandVectors')]
    public function testUint64BandRoundTripsViaGmpNeverFloat(string $decimal, string $hex): void
    {
        $g = \gmp_init($decimal);
        $encoded = Cbor::encode($g);
        self::assertSame($hex, \bin2hex($encoded), "encode of {$decimal}");

        $decoded = Cbor::decode($encoded);
        // Values >= 2^63 must come back as GMP (not int, not float).
        if (\gmp_cmp($g, \gmp_init(\PHP_INT_MAX)) > 0) {
            self::assertInstanceOf(\GMP::class, $decoded, "{$decimal} must decode to GMP, not a lossy native type");
        }
        self::assertSame($decimal, \gmp_strval(\gmp_init(self::asGmpString($decoded))), "round-trip value of {$decimal}");
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function uint64BandVectors(): array
    {
        return [
            // int.10 corpus boundary: max signed i64 = 2^63-1 (still native).
            'int.10 2^63-1' => ['9223372036854775807', '1b7fffffffffffffff'],
            // int.15 (synthetic): 2^63 — first value PAST PHP_INT_MAX.
            'int.15 2^63' => ['9223372036854775808', '1b8000000000000000'],
            // int.16 (synthetic): 2^63 + 7.
            'int.16 2^63+7' => ['9223372036854775815', '1b8000000000000007'],
            // int.17 (synthetic): 2^64-1 = max uint64.
            'int.17 2^64-1' => ['18446744073709551615', '1bffffffffffffffff'],
        ];
    }

    public function testUint64OverflowIsRejected(): void
    {
        $this->expectException(\EntityCore\UnsupportedValueException::class);
        Cbor::encode(\gmp_init('18446744073709551616')); // 2^64 — beyond uint64
    }

    public function testNegativeBandViaGmp(): void
    {
        // -2^63 - 1 = the first negative argument past what a native int can
        // represent for the major-1 (-1-n) argument; carried via GMP.
        $g = \gmp_init('-9223372036854775809');
        $encoded = Cbor::encode($g);
        // major 1, argument = -1 - (-2^63-1) = 2^63 = 0x8000000000000000
        self::assertSame('3b8000000000000000', \bin2hex($encoded));
        $decoded = Cbor::decode($encoded);
        self::assertInstanceOf(\GMP::class, $decoded);
        self::assertSame('-9223372036854775809', \gmp_strval($decoded));
    }

    #[DataProvider('floatVectors')]
    public function testFloatLadder(float $f, string $hex): void
    {
        self::assertSame($hex, \bin2hex(Cbor::encode($f)));
    }

    /** @return array<string,array{0:float,1:string}> */
    public static function floatVectors(): array
    {
        return [
            'f16 1.0' => [1.0, 'f93c00'],
            'f16 1.5' => [1.5, 'f93e00'],
            'f16 max normal 65504' => [65504.0, 'f97bff'],
            'f16 2^15' => [32768.0, 'f97800'],
            'f32 65503' => [65503.0, 'fa477fdf00'],
            'f32 100000' => [100000.0, 'fa47c35000'],
            'f64 1.1' => [1.1, 'fb3ff199999999999a'],
        ];
    }

    public function testFloatSpecialsAndNegZero(): void
    {
        self::assertSame('f90000', \bin2hex(Cbor::encode(0.0)));
        self::assertSame('f98000', \bin2hex(Cbor::encode(-0.0)));
        self::assertSame('f97e00', \bin2hex(Cbor::encode(\NAN)));
        self::assertSame('f97c00', \bin2hex(Cbor::encode(\INF)));
        self::assertSame('f9fc00', \bin2hex(Cbor::encode(-\INF)));
    }

    public function testFloatRoundTripSpecials(): void
    {
        self::assertNan(Cbor::decode("\xF9\x7E\x00"));
        self::assertSame(\INF, Cbor::decode("\xF9\x7C\x00"));
        self::assertSame(-\INF, Cbor::decode("\xF9\xFC\x00"));
        $negZero = Cbor::decode("\xF9\x80\x00");
        self::assertSame(0.0, $negZero); // -0.0 == 0.0
        // The sign bit is preserved — re-encoding yields the -0.0 wire bytes.
        self::assertSame('f98000', \bin2hex(Cbor::encode($negZero)));
    }

    public function testLengthFirstMapOrdering(): void
    {
        // 'z' (len 1 encoded) sorts before 'aa' (len 2 encoded) — length-first.
        $m = new EcfMap([['aa', 2], ['z', 1]]);
        self::assertSame('a2617a0162616102', \bin2hex(Cbor::encode($m)));
    }

    public function testByteStringKeyMap(): void
    {
        // map_keys.5: a byte-string key alongside a text key.
        $m = new EcfMap([
            [new ByteString("\x6b\x65\x79"), 2],
            ['text_key', 1],
        ]);
        self::assertSame('a2436b65790268746578745f6b657901', \bin2hex(Cbor::encode($m)));
    }

    public function testNonCanonicalMapOrderRejected(): void
    {
        // {b:2, a:1} on the wire (b before a) is non-canonical.
        $this->expectException(NonCanonicalEcfException::class);
        Cbor::decode(\hex2bin('a2616202616101'));
    }

    public function testNonMinimalIntRejected(): void
    {
        // 0x1818 = 24 minimally; 0x1817 (24 in a uint8 slot but value 23) → reject.
        $this->expectException(NonCanonicalEcfException::class);
        Cbor::decode("\x18\x17"); // value 23 in 1-byte arg form — non-minimal
    }

    public function testTagRejectedAtDepth(): void
    {
        $this->expectException(\EntityCore\TagRejectedException::class);
        Cbor::decode("\xC0\x00"); // tag 0 wrapping uint 0
    }

    public function testBase58GmpRoundTrip(): void
    {
        // peer_id.1 components → known base58 string, then parse back.
        $digest = \str_repeat("\x00", 32);
        $peer = PeerId::format(1, 1, $digest);
        [$kt, $ht, $d] = PeerId::parse($peer);
        self::assertSame(1, $kt);
        self::assertSame(1, $ht);
        self::assertSame($digest, $d);
    }

    private static function asGmpString(mixed $v): string
    {
        if ($v instanceof \GMP) {
            return \gmp_strval($v);
        }
        if (\is_int($v)) {
            return (string) $v;
        }
        self::fail('decoded value is neither GMP nor int: ' . \get_debug_type($v));
    }
}
