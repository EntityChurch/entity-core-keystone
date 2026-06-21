"""Identity (L1): a peer's keypair + derived entities (§1.5, §3.5, §7.3).

A peer's identity is an Ed25519 seed; everything derives:

    public_key    = Ed25519 pub of seed                 (32 bytes)
    peer_id       = §1.5 canonical form (identity-multihash; hash_type=0x00)
    peer_entity   = system/peer {public_key, key_type}  (§3.5; v7.65 — NO
                    peer_id field in the hashable basis)
    identity_hash = content_hash(peer_entity)

Signing is over the full 33-byte content_hash (format byte + digest, §7.3) so a
signature is bound to the hash format.

§1.5 canonical peer-id derivation (A-SW-008 erratum; NOT the stale §7.4
SHA256(pubkey) skeleton): a key <= 32 bytes is identity-multihash form
(hash_type=0x00, digest = the raw key); a larger key is SHA-256-form
(hash_type=0x01, digest = SHA-256(key)).  Ed25519 (32 B) -> (0x01, 0x00, pub).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..peer_id import format_peer_id, parse_peer_id
from ..signature import (
    ED25519_SEED_SIZE,
    ed25519_public_key,
    sign_ed25519,
    verify_ed25519,
)
from .model import Entity

#: Key types (§1.5).
KEY_TYPE_ED25519 = 0x01
KEY_TYPE_ED448 = 0x02
#: Hash types (§1.5 canonical-form table).
HASH_TYPE_IDENTITY = 0x00  # identity-multihash: digest IS the raw key
HASH_TYPE_SHA256 = 0x01  # SHA-256-form: digest = SHA-256(key)


def peer_id_of_public_key(public_key: bytes, key_type: int = KEY_TYPE_ED25519) -> str:
    """Derive the canonical Base58 peer-id for a raw public key (§1.5)."""
    if len(public_key) <= 32:
        return format_peer_id(key_type, HASH_TYPE_IDENTITY, public_key)
    import hashlib

    return format_peer_id(key_type, HASH_TYPE_SHA256, hashlib.sha256(public_key).digest())


def peer_entity_of_public_key(public_key: bytes) -> Entity:
    """Build the system/peer entity for a raw public key (v7.65: NO peer_id in
    the hashable basis — only {public_key, key_type})."""
    return Entity.make(
        "system/peer",
        {"public_key": bytes(public_key), "key_type": "ed25519"},
    )


@dataclass(frozen=True, slots=True)
class Identity:
    """A peer's keypair plus its derived peer entity and identity hash."""

    seed: bytes
    public_key: bytes
    peer_id: str
    peer_entity: Entity

    @staticmethod
    def of_seed(seed: bytes) -> "Identity":
        """Construct an identity from a 32-byte Ed25519 seed."""
        if len(seed) != ED25519_SEED_SIZE:
            raise ValueError(f"ed25519 seed must be {ED25519_SEED_SIZE} bytes")
        pub = ed25519_public_key(seed)
        return Identity(
            seed=bytes(seed),
            public_key=pub,
            peer_id=peer_id_of_public_key(pub),
            peer_entity=peer_entity_of_public_key(pub),
        )

    @property
    def identity_hash(self) -> bytes:
        """The content_hash of the peer entity (§3.5)."""
        return self.peer_entity.hash

    def sign_entity(self, target: Entity) -> Entity:
        """Sign ``target``'s content_hash, producing the system/signature entity
        (§3.5): target = signed hash, signer = our identity hash, signature =
        Ed25519 over the 33-byte content_hash."""
        sig = sign_ed25519(self.seed, target.hash)
        return Entity.make(
            "system/signature",
            {
                "target": bytes(target.hash),
                "signer": bytes(self.identity_hash),
                "algorithm": "ed25519",
                "signature": sig,
            },
        )


def verify_signature(signature: Entity, signer_peer: Entity) -> bool:
    """Verify a system/signature entity against the signer's system/peer entity.

    Reads public_key from the peer entity; the §5.2 signer-hash binding check is
    the caller's responsibility.
    """
    target = signature.bytes_("target")
    sig = signature.bytes_("signature")
    pub = signer_peer.bytes_("public_key")
    if target is None or sig is None or pub is None or len(pub) != 32:
        return False
    return verify_ed25519(pub, sig, target)


__all__ = [
    "Identity",
    "peer_id_of_public_key",
    "peer_entity_of_public_key",
    "verify_signature",
    "parse_peer_id",
    "KEY_TYPE_ED25519",
    "KEY_TYPE_ED448",
]
