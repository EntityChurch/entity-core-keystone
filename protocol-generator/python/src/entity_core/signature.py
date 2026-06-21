"""Ed25519 (+ Ed448) sign/verify over canonical-ECF entity bytes.

Spec: V7 §7.3 (Ed25519 keygen/sign/verify) + §1.5 crypto-agility (Ed448 =
``key_type 0x02``, the higher bar).  An entity signature is produced over the
canonical-ECF encoding of the entity ``{type, data}`` value (the SAME bytes
that feed the content hash — ENTITY-CBOR-ENCODING §4.2 / §5.2), NOT over the
raw wire bytes (never hash/sign untrusted wire bytes; always re-encode to ECF
first).

Crypto is NATIVE-FULL-AGILITY via ``cryptography`` (pyca, OpenSSL backend,
profile pin 48.0.0): both Ed25519 AND Ed448 reach the identical raw-key
surface, so there is NO FFI and NO second crypto source (the Haskell/Ruby
native-full-agility result; A-PY-002).  Ed25519/Ed448 are deterministic by
construction (RFC 8032 PureEdDSA — no RNG in signing), so a fixed seed yields
a reproducible signature across impls — the property the cross-blessed
``signature.*`` conformance vectors rely on.

Exact API spelling confirmed in-container at S2 (A-PY-003):
``Ed25519PrivateKey.from_private_bytes(seed) / .sign(msg) /
.public_key().verify(sig, msg) / .private_bytes_raw() /
.public_key().public_bytes_raw()`` — identical shape for ``Ed448PrivateKey``.
"""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import _cbor

#: Ed25519: 32-byte seed, 32-byte public key, 64-byte signature (RFC 8032).
ED25519_SEED_SIZE = 32
ED25519_SIG_SIZE = 64
#: Ed448: 57-byte seed, 57-byte public key, 114-byte signature (RFC 8032).
ED448_SEED_SIZE = 57
ED448_SIG_SIZE = 114


# ── Raw-bytes Ed25519 (the floor / default key type) ──────────────────────────
def sign_ed25519(seed: bytes, message: bytes) -> bytes:
    """Deterministically sign ``message`` with a 32-byte Ed25519 seed."""
    if len(seed) != ED25519_SEED_SIZE:
        raise ValueError(
            f"ed25519 seed must be {ED25519_SEED_SIZE} bytes, got {len(seed)}"
        )
    return Ed25519PrivateKey.from_private_bytes(bytes(seed)).sign(bytes(message))


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 ``signature``; return True iff valid (no raise)."""
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(
            bytes(signature), bytes(message)
        )
        return True
    except InvalidSignature:
        return False


def ed25519_public_key(seed: bytes) -> bytes:
    """Return the 32-byte raw Ed25519 public key for ``seed``."""
    if len(seed) != ED25519_SEED_SIZE:
        raise ValueError(
            f"ed25519 seed must be {ED25519_SEED_SIZE} bytes, got {len(seed)}"
        )
    sk = Ed25519PrivateKey.from_private_bytes(bytes(seed))
    return sk.public_key().public_bytes_raw()


# ── Raw-bytes Ed448 (crypto-agility higher bar, key_type 0x02) ────────────────
def sign_ed448(seed: bytes, message: bytes) -> bytes:
    """Deterministically sign ``message`` with a 57-byte Ed448 seed."""
    if len(seed) != ED448_SEED_SIZE:
        raise ValueError(
            f"ed448 seed must be {ED448_SEED_SIZE} bytes, got {len(seed)}"
        )
    return Ed448PrivateKey.from_private_bytes(bytes(seed)).sign(bytes(message))


def verify_ed448(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed448 ``signature``; return True iff valid (no raise)."""
    try:
        Ed448PublicKey.from_public_bytes(bytes(public_key)).verify(
            bytes(signature), bytes(message)
        )
        return True
    except InvalidSignature:
        return False


def ed448_public_key(seed: bytes) -> bytes:
    """Return the 57-byte raw Ed448 public key for ``seed``."""
    if len(seed) != ED448_SEED_SIZE:
        raise ValueError(
            f"ed448 seed must be {ED448_SEED_SIZE} bytes, got {len(seed)}"
        )
    sk = Ed448PrivateKey.from_private_bytes(bytes(seed))
    return sk.public_key().public_bytes_raw()


# ── Entity-level convenience: sign/verify over canonical ECF bytes ────────────
def sign_entity(seed: bytes, entity: Any) -> bytes:
    """Sign the canonical-ECF encoding of ``entity`` with an Ed25519 seed.

    ``entity`` is a value tree (typically ``{"type": ..., "data": ...}``); it
    is canonicalised via :func:`entity_core._cbor.encode` BEFORE signing, so
    the signed bytes are deterministic and content-addressable (§5.2).
    """
    return sign_ed25519(seed, _cbor.encode(entity))


def verify_entity(public_key: bytes, signature: bytes, entity: Any) -> bool:
    """Verify an Ed25519 signature over the canonical ECF of ``entity``."""
    return verify_ed25519(public_key, signature, _cbor.encode(entity))
