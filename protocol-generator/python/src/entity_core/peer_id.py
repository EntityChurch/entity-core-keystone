"""Peer-id parse/format (V7 §1.2 / §1.5 / ENTITY-NATIVE-TYPE-SYSTEM §4.8).

A peer-id is the Base58 (Bitcoin alphabet) encoding of::

    varint(key_type) || varint(hash_type) || digest

where ``key_type`` / ``hash_type`` are multicodec-style LEB128 varints (§1.5
/ §7.3) and ``digest`` is the raw key digest.  Per the v7.75 §1.5 canonical
form (A-SW-008 erratum), ``hash_type == 0x00`` is the identity-multihash and
``digest`` is the raw public key for keys <= 32 bytes; the construction here
is curve/hash agnostic — it carries whatever ``key_type`` / ``hash_type`` /
``digest`` the caller supplies (forward-compat), exactly as the cross-blessed
``peer_id.*`` conformance vectors require (incl. a synthetic ``key_type >=
0x80`` exercising the multi-byte varint prefix).

``format_peer_id`` returns the Base58 ``str``; ``parse_peer_id`` is the
inverse — it Base58-decodes and splits the leading two varints off the
digest.  Round-trip (``format(parse(s)) == s``) is the conformance surface.
"""

from __future__ import annotations

from typing import NamedTuple

from ._base58 import b58decode, b58encode
from ._varint import decode_varint, encode_varint


class PeerIdParts(NamedTuple):
    """The decoded components of a peer-id."""

    key_type: int
    hash_type: int
    digest: bytes


def format_peer_id(key_type: int, hash_type: int, digest: bytes) -> str:
    """Build the Base58 peer-id from its components.

    ``Base58(varint(key_type) || varint(hash_type) || digest)``.
    """
    if key_type < 0 or hash_type < 0:
        raise ValueError("peer_id key_type / hash_type must be >= 0")
    raw = encode_varint(key_type) + encode_varint(hash_type) + bytes(digest)
    return b58encode(raw)


def parse_peer_id(peer_id: str) -> PeerIdParts:
    """Parse a Base58 peer-id back into ``(key_type, hash_type, digest)``.

    Inverse of :func:`format_peer_id`.  The two leading LEB128 varints are the
    ``key_type`` and ``hash_type``; the remaining bytes are the raw digest.
    """
    raw = b58decode(peer_id)
    key_type, off = decode_varint(raw, 0)
    hash_type, off = decode_varint(raw, off)
    digest = raw[off:]
    return PeerIdParts(key_type, hash_type, digest)
