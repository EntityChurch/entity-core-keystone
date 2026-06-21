<?php

declare(strict_types=1);

namespace EntityCore;

/**
 * A peer's identity (L1): an Ed25519 seed and everything derived from it (§1.5,
 * §3.5, §7.3).
 *
 *   publicKey    = Ed25519 public key of seed                  (32 bytes)
 *   peerId       = §1.5 canonical-form identity-multihash       (Base58)
 *   peerEntity   = system/peer {public_key, key_type}          (§3.5; v7.65 — NO
 *                  peer_id in the hashable basis)
 *   identityHash = content_hash(peerEntity)                    (33 bytes)
 *
 * Signing is over the full 33-byte content_hash (format byte + digest, §7.3), so
 * a signature is bound to the hash format. peer_id is the §1.5 identity-multihash
 * form (the §7.4 SHA-256 skeleton is stale and would fail the handshake).
 */
final class Identity
{
    private function __construct(
        private readonly string $seed,
        private readonly string $publicKeyOctets,
        public readonly string $peerId,
        public readonly Entity $peerEntity,
        private readonly string $identityHashOctets,
    ) {
    }

    /** Construct an identity from a 32-byte Ed25519 seed. */
    public static function ofSeed(string $seed): self
    {
        $pub = Signature::publicKey($seed);
        $peerEntity = self::peerEntityOfPublicKey($pub);
        $peerId = PeerId::fromPublicKey($pub, KeyType::Ed25519);
        return new self($seed, $pub, $peerId, $peerEntity, $peerEntity->hash());
    }

    public function publicKey(): string
    {
        return $this->publicKeyOctets;
    }

    public function identityHash(): string
    {
        return $this->identityHashOctets;
    }

    /**
     * Sign a target entity's content_hash, producing a system/signature entity
     * (§3.5): `target` = the signed entity's hash, `signer` = our identity hash.
     */
    public function sign(Entity $target): Entity
    {
        $sig = Signature::signRaw($this->seed, $target->hash());
        return Entity::make('system/signature', Ecf::map(
            'target', new ByteString($target->hash()),
            'signer', new ByteString($this->identityHashOctets),
            'algorithm', 'ed25519',
            'signature', new ByteString($sig),
        ));
    }

    /** The system/peer entity for a raw public key (v7.65: no peer_id field). */
    public static function peerEntityOfPublicKey(string $publicKey): Entity
    {
        return Entity::make('system/peer', Ecf::map(
            'public_key', new ByteString($publicKey),
            'key_type', 'ed25519',
        ));
    }

    /** The §1.5 canonical (identity-multihash) peer_id for a raw Ed25519 pubkey. */
    public static function peerIdOfPublicKey(string $publicKey): string
    {
        return PeerId::fromPublicKey($publicKey, KeyType::Ed25519);
    }

    /**
     * Verify a system/signature entity against the signer's system/peer entity.
     * Reads public_key from the peer entity; the §5.2 signer-hash binding is the
     * caller's responsibility.
     */
    public static function verifySignature(Entity $signature, Entity $signerPeer): bool
    {
        $target = $signature->bytes('target');
        $sig = $signature->bytes('signature');
        $pub = $signerPeer->bytes('public_key');
        if ($target === null || $sig === null || $pub === null) {
            return false;
        }
        if (\strlen($sig) !== 64 || \strlen($pub) !== 32) {
            return false;
        }
        return Signature::verifyRaw($pub, $target, $sig);
    }
}
