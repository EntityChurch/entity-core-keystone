"""Exception hierarchy for the entity-core Python peer.

Python-idiomatic fallible surface: ``raise`` / ``except`` rooted at
``EntityCoreError`` (an ``Exception`` subclass, NOT ``BaseException`` — faults
stay catchable by a plain ``except Exception``).  The tree mirrors the
C#/TS/Ruby exception hierarchies in *shape* (Codec / Protocol / Transport
families) while reading as Python (PascalCase ``...Error`` class names).

Only the codec-relevant subtree is materialised at S2; the Protocol/Transport
branches are declared per the profile ``[error_model]`` block for the S3 peer
machinery to populate.
"""

from __future__ import annotations


class EntityCoreError(Exception):
    """Root of the entity-core exception hierarchy."""


# ── Codec / canonicalization faults ──────────────────────────────────────────
class CodecError(EntityCoreError):
    """CBOR / canonicalization / decode faults."""


class NonCanonicalEcfError(CodecError):
    """A decoded frame violated ECF canonicality.

    Maps to the spec wire error code ``400 non_canonical_ecf`` (ENTITY-CBOR-
    ENCODING §6.3 / Rule violation): a CBOR tag (major type 6) on a data
    field, an indefinite-length item, a non-shortest integer/float head, or a
    misordered/duplicated map key.
    """

    #: The spec wire error code this exception maps to at the dispatch boundary.
    wire_code = "non_canonical_ecf"


class TruncatedError(CodecError):
    """A short read on decode — the input ended mid-item."""


# ── Protocol / Transport branches (declared for S3; not exercised at S2) ──────
class ProtocolError(EntityCoreError):
    """Protocol-level fault (S3 peer machinery)."""


class HelloFailedError(ProtocolError):
    pass


class AuthenticationError(ProtocolError):
    pass


class TransportError(EntityCoreError):
    """Transport-level fault (S3 peer machinery)."""


class RecvTimeoutError(TransportError):
    pass


class ConnectionBrokenError(TransportError):
    pass


class WireProtocolError(TransportError):
    """Wire-framing fault (avoids the TS ``ProtocolErrorError`` stutter)."""
