"""Content hash construction (V7 §4.2 / ENTITY-CBOR-ENCODING §4.2).

A content hash is::

    varint(format_code) || SHA256( ECF({"type": type, "data": data}) )

The ``{type, data}`` map is ECF-encoded with canonical key ordering — keys
``"data"`` (4 chars) and ``"type"`` (4 chars) are the same encoded length, so
``"data"`` sorts before ``"type"`` lexicographically.  The ``data`` field is an
arbitrary ECF value (NOT necessarily a dict — A-JAVA-010).

``format_code`` defaults to 0 (single-byte varint); a code >= 0x80 exercises
the multi-byte varint prefix (forward-compat).
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import _cbor
from ._varint import encode_varint


def content_hash(entity_type: str, data: Any, format_code: int = 0) -> bytes:
    """Compute the content-hash bytes for an entity ``{type, data}``."""
    if format_code < 0:
        raise ValueError("format_code must be >= 0")
    hash_input = {"type": entity_type, "data": data}
    encoded = _cbor.encode(hash_input)
    digest = hashlib.sha256(encoded).digest()
    return encode_varint(format_code) + digest
