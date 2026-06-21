<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Ed25519 sign/verify over canonical-ECF-encoded entities, via ext-sodium
 * (libsodium, bundled with PHP — a core ext, zero Composer/PECL dep). RFC 8032
 * PureEdDSA is deterministic: a fixed seed + fixed message yields fixed signature
 * bytes (so the corpus byte-pins them; the crypto-library version is
 * conformance-neutral).
 *
 * Ed25519: 32-byte seed, 32-byte pubkey, 64-byte detached signature.
 *
 * Ed448 is DEFERRED for v0.1 (A-PHP-002) — ext-sodium has no Ed448; the agility
 * route is ext-ffi → libentitycore_codec when agility lands. The v0.1 floor is
 * Ed25519 + SHA-256 only, fully covered here.
 *
 * libsodium API (profile [codec].ed25519_library):
 *   $kp  = sodium_crypto_sign_seed_keypair($seed32);  // seed -> keypair
 *   $sk  = sodium_crypto_sign_secretkey($kp);         // 64-byte expanded sk
 *   $pk  = sodium_crypto_sign_publickey($kp);         // 32-byte pubkey
 *   $sig = sodium_crypto_sign_detached($msg, $sk);    // 64-byte sig
 *   $ok  = sodium_crypto_sign_verify_detached($sig, $msg, $pk);
 */
final class Signature
{
    /** Sign an already-serialized message with a 32-byte Ed25519 seed. */
    public static function signRaw(string $seed, string $message): string
    {
        $kp = \sodium_crypto_sign_seed_keypair($seed);
        $sk = \sodium_crypto_sign_secretkey($kp);
        return \sodium_crypto_sign_detached($message, $sk);
    }

    /**
     * Sign the canonical ECF encoding of $entity with a 32-byte Ed25519 seed.
     *
     * @param array<string,mixed> $entity
     */
    public static function sign(string $seed, array $entity): string
    {
        return self::signRaw($seed, Cbor::encode($entity));
    }

    /** Verify a detached signature over an already-serialized message. */
    public static function verifyRaw(string $publicKey, string $message, string $signature): bool
    {
        return \sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
    }

    /**
     * Verify a signature over the canonical ECF encoding of $entity.
     *
     * @param array<string,mixed> $entity
     */
    public static function verify(string $publicKey, array $entity, string $signature): bool
    {
        return self::verifyRaw($publicKey, Cbor::encode($entity), $signature);
    }

    /** Derive the raw 32-byte public key from a 32-byte Ed25519 seed (V7 §1.5). */
    public static function publicKey(string $seed): string
    {
        $kp = \sodium_crypto_sign_seed_keypair($seed);
        return \sodium_crypto_sign_publickey($kp);
    }
}
