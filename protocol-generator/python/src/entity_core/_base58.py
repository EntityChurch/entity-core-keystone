"""Base58 (Bitcoin alphabet) encode/decode — hand-rolled, no PyPI dependency.

Used for the ``peer_id`` surface (V7 §1.2 / §1.5): a peer-id is the Base58 of
``varint(key_type) || varint(hash_type) || digest``.  Leading 0x00 bytes map
to leading ``'1'`` characters (the standard Base58 leading-zero convention).
"""

from __future__ import annotations

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def b58encode(data: bytes) -> str:
    """Encode raw bytes to a Base58 string (Bitcoin alphabet)."""
    # Count leading zero bytes → leading '1's.
    n_zeros = 0
    for b in data:
        if b == 0:
            n_zeros += 1
        else:
            break

    num = int.from_bytes(data, "big")
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(ALPHABET[rem])
    out.extend(ALPHABET[0:1] * n_zeros)
    out.reverse()
    return out.decode("ascii")


def b58decode(s: str) -> bytes:
    """Decode a Base58 string back to raw bytes."""
    n_zeros = 0
    for ch in s:
        if ch == "1":
            n_zeros += 1
        else:
            break

    num = 0
    for ch in s:
        v = _INDEX.get(ord(ch))
        if v is None:
            raise ValueError(f"invalid base58 character: {ch!r}")
        num = num * 58 + v

    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * n_zeros + body
