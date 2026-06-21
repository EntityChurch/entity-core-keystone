"""Multicodec-style LEB128 varints (V7 §1.5 / §7.3).

Used for the ``key_type`` / ``hash_type`` / ``format_code`` framing in the
content-hash, peer-id, and key-prefix surfaces.  This is the unsigned LEB128
form: 7 payload bits per byte, continuation bit (0x80) set on every byte
except the last, little-endian group order.

We OWN the non-minimal-varint rejection on decode (Rule 1 analogue): a varint
whose final byte is ``0x00`` while the value already terminated, or any
encoding longer than the minimal form, is rejected.  Python's arbitrary-
precision ``int`` carries the full range with no carrier trap.
"""

from __future__ import annotations

from .errors import NonCanonicalEcfError, TruncatedError


def encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as a minimal LEB128 varint."""
    if value < 0:
        raise ValueError(f"varint value must be >= 0, got {value}")
    if value < 0x80:
        return bytes([value])
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_varint(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a minimal LEB128 varint from ``buf`` at ``offset``.

    Returns ``(value, next_offset)``.  Rejects non-minimal encodings (a
    trailing ``0x00`` continuation group that adds no value) per the
    own-the-rejection mandate.
    """
    result = 0
    shift = 0
    pos = offset
    n = len(buf)
    while True:
        if pos >= n:
            raise TruncatedError("varint: unexpected end of input")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if b & 0x80 == 0:
            # Minimality: a multi-byte varint whose terminating group is 0x00
            # encodes a value that fits in fewer bytes — non-canonical.
            if shift > 0 and b == 0x00:
                raise NonCanonicalEcfError("varint: non-minimal encoding (trailing zero group)")
            return result, pos
        shift += 7
