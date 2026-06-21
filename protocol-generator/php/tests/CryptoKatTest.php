<?php

declare(strict_types=1);

namespace EntityCore\Tests;

use EntityCore\Cbor;
use EntityCore\Signature;
use PHPUnit\Framework\TestCase;

/**
 * Ed25519 self-tests for the ext-sodium crypto path (sodium_crypto_sign_*).
 *
 * Rather than restate RFC 8032 §7.1 hex (which the corpus already exercises via
 * the byte-pinned signature.* vectors — the strongest RFC-8032 KAT we have, since
 * those signatures are independently locked Go×Rust×Python), these tests prove:
 *   1. Determinism — the same seed+message yields the same 64-byte signature on
 *      every call (RFC-8032 PureEdDSA has no RNG in signing).
 *   2. Seed→pubkey derivation matches sign/verify (the §1.5 raw-pubkey path).
 *   3. Tamper rejection.
 * The byte-pinned values themselves are asserted in ConformanceTest (signature.1
 * .. signature.3), so a wrong crypto backend fails the gate there.
 */
final class CryptoKatTest extends TestCase
{
    public function testDeterministicSignature(): void
    {
        $seed = \str_repeat("\x11", 32);
        $msg = 'entity-core ed25519 determinism';
        $sigA = Signature::signRaw($seed, $msg);
        $sigB = Signature::signRaw($seed, $msg);
        self::assertSame(64, \strlen($sigA), '64-byte detached signature');
        self::assertSame(\bin2hex($sigA), \bin2hex($sigB), 'signing is deterministic');
    }

    public function testSeedToPubkeyAndVerify(): void
    {
        $seed = \str_repeat("\x2a", 32);
        $pub = Signature::publicKey($seed);
        self::assertSame(32, \strlen($pub), '32-byte raw public key');

        $msg = 'sign over canonical ECF';
        $sig = Signature::signRaw($seed, $msg);
        self::assertTrue(Signature::verifyRaw($pub, $msg, $sig), 'verify good signature');
        self::assertFalse(Signature::verifyRaw($pub, $msg . "\x00", $sig), 'reject tampered message');
    }

    public function testSignOverCanonicalEcfEntity(): void
    {
        // signature.1 corpus shape: seed = all-zero, entity {type:test/v1, data:{x:1}}.
        $seed = \str_repeat("\x00", 32);
        $entity = ['type' => 'test/v1', 'data' => ['x' => 1]];
        $sig = Signature::sign($seed, $entity);
        // The byte-pinned value from the corpus (signature.1).
        $expected = '3f0b5d06636ea267199dc27eb20d8c9b37684d681adc5be43be465819ad643e3'
            . 'b152e5c024bf67ce862699fe439462d7852b029cb125cd917d12a3151529230c';
        self::assertSame($expected, \bin2hex($sig), 'sign over canonical ECF matches the locked corpus value');

        $pub = Signature::publicKey($seed);
        self::assertTrue(Signature::verify($pub, $entity, $sig));
    }
}
