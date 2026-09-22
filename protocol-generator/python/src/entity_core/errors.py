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
    """A decoded frame violated ECF canonicality: an indefinite-length item, a
    non-shortest integer/float head, a misordered/duplicated map key, invalid UTF-8,
    trailing bytes.

    THE WIRE CODE IS NOT ``non_canonical_ecf`` FOR THIS CLASS, and the name is a
    historical accident this docstring used to repeat.  ``ENTITY-CORE-PROTOCOL`` §4.11
    (0.8.2.25) puts these inputs on the FRAMING arm — "un-parseable, truncated or
    non-canonical CBOR that never becomes an Envelope" -> ``400 invalid_request`` —
    and rules ``400 non_canonical_ecf`` *"NOT conformant on the framing arm
    ``[MUST]``"*, because ``ENTITY-CBOR-ENCODING`` §6.3 defines that code for CBOR
    **tag-policy** violations specifically and *"your bytes are truncated"* is not
    *"re-encode without the tag."*  The code selects the caller's remedy, so a code
    that is merely in the right family is still wrong.

    :class:`TagRejectedError` is the one subclass that keeps the old code.
    """

    #: The §4.11 wire error code this exception maps to at the dispatch boundary.
    wire_code = "invalid_request"


class TagRejectedError(NonCanonicalEcfError):
    """A CBOR tag (major type 6) in a data-field position.

    ``ENTITY-CBOR-ENCODING`` §6.3 is the sole definition of ``non_canonical_ecf`` in
    the corpus and assigns it to exactly this condition: *"any CBOR major-type-6 item
    encountered in a data-field position is a rejection condition ... Rejection
    returns ``400 non_canonical_ecf``."*  The remedy that code names — re-encode
    without the tag — is the caller's actual remedy here and nowhere else in this
    hierarchy, which is why this is a SUBCLASS rather than a message on the parent:
    the dispatch boundary has to branch on it, and a string comparison is not a branch.

    A subclass so every existing ``except NonCanonicalEcfError`` site — the S2 corpus
    harness among them — keeps catching it unchanged.
    """

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
