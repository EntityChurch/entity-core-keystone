"""entity-core-protocol-python — the clean-room Python core-protocol peer.

Public codec surface (S2). The package is the importable ``entity_core``
(PEP 8 snake_case); leading-underscore modules (``_cbor`` / ``_base58`` /
``_varint``) are internal and re-exported here as the stable public API.

Codec strategy: NATIVE — the canonical CBOR layer (Entity Canonical Form,
ECF) is hand-rolled (no Python CBOR library delivers the full ECF contract;
A-PY-001), crypto is native-full-agility via ``cryptography`` (Ed25519 +
Ed448 + SHA-2), and SHA-2 is stdlib ``hashlib``.

The peer machinery (transport, dispatch, store, multisig) is S3 and is not
part of this module yet.
"""

from __future__ import annotations

from ._base58 import b58decode, b58encode
from ._cbor import ByteKey, decode, encode
from ._varint import decode_varint, encode_varint
from .content_hash import content_hash
from .errors import (
    AuthenticationError,
    CodecError,
    ConnectionBrokenError,
    EntityCoreError,
    HelloFailedError,
    NonCanonicalEcfError,
    ProtocolError,
    RecvTimeoutError,
    TransportError,
    TruncatedError,
    WireProtocolError,
)
from .peer_id import PeerIdParts, format_peer_id, parse_peer_id
from .signature import (
    sign_ed448,
    sign_ed25519,
    sign_entity,
    verify_ed448,
    verify_ed25519,
    verify_entity,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # CBOR / ECF
    "encode",
    "decode",
    "ByteKey",
    # varint / base58
    "encode_varint",
    "decode_varint",
    "b58encode",
    "b58decode",
    # content hash
    "content_hash",
    # peer-id
    "format_peer_id",
    "parse_peer_id",
    "PeerIdParts",
    # signatures
    "sign_ed25519",
    "verify_ed25519",
    "sign_ed448",
    "verify_ed448",
    "sign_entity",
    "verify_entity",
    # errors
    "EntityCoreError",
    "CodecError",
    "NonCanonicalEcfError",
    "TruncatedError",
    "ProtocolError",
    "HelloFailedError",
    "AuthenticationError",
    "TransportError",
    "RecvTimeoutError",
    "ConnectionBrokenError",
    "WireProtocolError",
]
