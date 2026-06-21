<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * Peer-id formatting/parsing (V7 §1.5):
 *
 *   peer_id = Base58(varint(key_type) || varint(hash_type) || digest)
 *
 * key_type and hash_type are multicodec-style LEB128 varints (invariant N1). The
 * §1.5 canonical-form derivation uses a size cutoff: a key <= 32 bytes is an
 * identity-multihash (hash_type 0x00, digest = the key itself); a larger key is
 * SHA-256-form (hash_type 0x01, digest = SHA-256(key)). So Ed25519 (32 B) maps to
 * (0x01, 0x00, pubkey) and Ed448 (57 B) to (0x02, 0x01, sha256(pubkey)). (§1.5
 * supersedes the stale §7.4 SHA-256 skeleton.)
 */
final class PeerId
{
    /** Format a peer-id string from its abstract components. */
    public static function format(int $keyType, int $hashType, string $digest): string
    {
        return Base58::encode(Varint::encode($keyType) . Varint::encode($hashType) . $digest);
    }

    /** Derive a peer-id from a raw public key (V7 §1.5 size-cutoff rule). */
    public static function fromPublicKey(string $publicKey, KeyType $curve): string
    {
        if (\strlen($publicKey) <= 32) {
            $hashType = 0;
            $digest = $publicKey;
        } else {
            $hashType = 1;
            $digest = \hash('sha256', $publicKey, true);
        }
        return self::format($curve->value, $hashType, $digest);
    }

    /**
     * Parse a peer-id string back to its components.
     *
     * @return array{0:int,1:int,2:string} [key_type, hash_type, digest]
     */
    public static function parse(string $str): array
    {
        $raw = Base58::decode($str);
        [$keyType, $rest1] = Varint::decode($raw);
        [$hashType, $digest] = Varint::decode($rest1);
        return [$keyType, $hashType, $digest];
    }
}
