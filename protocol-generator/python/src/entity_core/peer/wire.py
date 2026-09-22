"""Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
EXECUTE_RESPONSE).

Frame := ``[4-byte BE length][CBOR payload]``.  The payload is a CBOR-encoded
envelope (§3.1).  Only EXECUTE and EXECUTE_RESPONSE are wire message types
(§3.3); ``hello`` / ``authenticate`` are OPERATIONS on system/protocol/connect,
not message types.

§4.10(a) resource bound: a finite max inbound payload is enforced by checking the
LENGTH PREFIX *before* buffering the body — an over-limit frame is rejected (->
``413 payload_too_large``) at read time, before the oversized buffer is ever
allocated.  Since 0.8.2.25 (N14) that rejection MUST be EMITTED: §4.10(a)'s
"SHOULD ... and otherwise MAY close after a best-effort coded frame" became a MUST,
because the over-size condition is detected at the length prefix with the connection
intact and nothing spent, and the permissive mood contradicted that section's own
"MUST NOT ... degrade service to in-flight requests" four sentences below.  §4.11 is
the emission shape for the whole pre-admission class; the transport still closes
afterwards (the body was never drained, so the framing is lost), but the close is now
IN ADDITION TO the frame rather than instead of it.
:data:`MAX_FRAME` (16 MiB) is the recommended informative DEFAULT,
not the bound: the bound in force is a per-connection value threaded from the
peer (:attr:`Peer.max_frame_bytes`) into :func:`read_frame`, and it is what a
handler body reads back through ``DispatchCtx.frame_budget()``.  A body that
sizes a response against the module constant instead is answering with a number
that may not be the one enforced.
"""

from __future__ import annotations

import socket
import struct
from typing import Any

from .model import Entity, Envelope, decode_envelope, encode_envelope

#: §4.10(a) finite inbound-payload bound — the informative DEFAULT (16 MiB), used
#: when a peer is constructed without an explicit ``max_frame_bytes``.  Read the
#: bound in force from the connection, never from here.
MAX_FRAME = 16 * 1024 * 1024


class FrameTooLargeError(Exception):
    """A length prefix exceeded the connection's frame bound (-> 413 payload_too_large).

    Raised BEFORE the body is buffered (§4.10(a)).
    """


class TruncatedFrameError(Exception):
    """A frame that never completed: a partial length prefix, or a prefix declaring
    ``n`` bytes followed by fewer.  §4.11's framing arm names this input outright —
    "un-parseable, truncated or non-canonical CBOR, or a length prefix that never
    completes" -> ``400 invalid_request``.

    A SEPARATE TYPE FROM ``ConnectionError`` BECAUSE THE TWO ARE DIFFERENT EVENTS AND
    A NAIVE READ-EXACT COLLAPSES THEM.  A clean EOF at a FRAME BOUNDARY is an ordinary
    close and is owed nothing; a stream that ends MID-FRAME is a REFUSAL and is owed a
    coded frame.  Both surface as ``sock.recv`` answering ``b""``, so the distinction
    can only be made here, where the frame boundary is known — and getting it wrong in
    the other direction would answer a 400 to every peer that simply hangs up.
    """


def _recv_exact(sock: socket.socket, n: int, *, at_frame_boundary: bool = False) -> bytes:
    """Read exactly ``n`` bytes.

    ``at_frame_boundary`` says that a close having read ZERO bytes is an ordinary
    hangup (``ConnectionError``) rather than a truncated frame; a close having read
    SOME is a truncation either way.  Only the length-prefix read sits at a boundary.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if at_frame_boundary and not buf:
                raise ConnectionError("connection closed at a frame boundary")
            raise TruncatedFrameError(f"short read: {len(buf)} of {n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket, max_frame: int = MAX_FRAME) -> bytes:
    """Read one length-prefixed frame, returning its CBOR payload.

    The length prefix is validated against ``max_frame`` before any body bytes are
    read (§4.10(a)).  A clean EOF at a frame boundary raises ``ConnectionError``;
    anything that ends mid-frame raises :class:`TruncatedFrameError`, which §4.11
    makes a refusal owed a coded response.

    ``max_frame`` is the bound IN FORCE for this connection, threaded from the
    peer; the default exists for direct callers, not for the serving path.

    A ZERO-LENGTH frame is COMPLETE, not truncated: the body read returns ``b""``
    without touching the socket, and the empty payload reaches the decoder, which
    refuses it as bytes that never become an Envelope.
    """
    hdr = _recv_exact(sock, 4, at_frame_boundary=True)
    (n,) = struct.unpack(">I", hdr)
    if n > max_frame:
        raise FrameTooLargeError(f"{n} > {max_frame} (413 payload_too_large)")
    return _recv_exact(sock, n)


# ── §4.11 pre-admission refusal classification (0.8.2.25) ─────────────────────
#: The message that rides with each code.  A FIXED TABLE, never ``str(exc)``: the
#: internal exception texts carry section signs, and a wire-visible string must stay
#: ASCII (two peers in this cohort have been killed at runtime by a non-ASCII byte in
#: an encoded string).  It is also the reason nothing here echoes attacker-supplied
#: bytes back.
_REFUSAL_MESSAGE = {
    "payload_too_large": "inbound frame exceeds the configured maximum size",
    "hash_mismatch": "an entity was addressed by a hash that does not bind to it",
    "non_canonical_ecf": "CBOR tags are forbidden anywhere in an entity data field",
    "invalid_request": "frame did not decode into an envelope",
}


def pre_admission_refusal(exc: BaseException) -> tuple[int, str, str]:
    """Map a pre-admission failure to the ``(status, code, message)`` §4.11 assigns
    its CAUSE.

    *"The frame obligation belongs to the class; the CODE belongs to the cause
    ``[MUST]``"* — a single code for the class would answer an honest caller under the
    wrong reason and send them to the wrong layer.

    ===================================  ==============================  =============
    cause                                answer                          stated at
    ===================================  ==============================  =============
    connect-auth proof-of-possession     401 authentication_failed       §4.6, §4.7
                                         (the connect handler's, not
                                         this function's)
    envelope over the configured max     413 payload_too_large           §4.10(a), N14
    resolution integrity (mis-keyed)     400 hash_mismatch               §5.2a, §1.8
    framing / never becomes an Envelope  400 invalid_request             §4.7, §4.11
    root is neither EXECUTE nor          400 invalid_request             §3.3, §4.11
      EXECUTE_RESPONSE                   (in dispatch, not here)
    ===================================  ==============================  =============

    THE TAG ARM KEEPS ``non_canonical_ecf`` AND THAT IS DELIBERATE.  §4.11 rules that
    code non-conformant *"on the framing arm"* and gives its reason in the same
    sentence: ``ENTITY-CBOR-ENCODING`` "defines that code for CBOR tag-policy
    violations specifically", which that document still MUSTs at decode time (§6.3).
    Those two rows are disjoint by CAUSE rather than in conflict, and §6.3 says so
    itself: a tag in a DATA-FIELD position is the policy violation with its own code,
    while "the envelope and entity-wrapper CBOR shapes are fixed maps and contain no
    positions where a tag could legally be placed; any tag encountered in those
    structures is a structurally invalid frame rejected by ordinary decoder
    validation" — i.e. the framing arm.  Everything else this decoder calls
    non-canonical (a non-minimal head, an indefinite length, mis-ordered keys) is
    genuinely "non-canonical CBOR that never becomes an Envelope" and takes
    ``invalid_request``.

    ORDER IS LOAD-BEARING: both pairs below are subclass/superclass, so the specific
    arm must be tested first or it can never be reached.
    """
    from .model import HashMismatchError
    from ..errors import TagRejectedError

    if isinstance(exc, FrameTooLargeError):
        code, status = "payload_too_large", 413
    elif isinstance(exc, HashMismatchError):  # before BadEntityError, its parent
        code, status = "hash_mismatch", 400
    elif isinstance(exc, TagRejectedError):  # before NonCanonicalEcfError, its parent
        code, status = "non_canonical_ecf", 400
    else:
        code, status = "invalid_request", 400
    return status, code, _REFUSAL_MESSAGE[code]


def framing_refusal(exc: BaseException) -> bool:
    """Whether a :func:`read_frame` failure is a REFUSAL owed a coded frame (§4.11)
    rather than an ordinary end of connection.  A closed or reset socket is not a
    refusal of anything and there is nobody left to answer."""
    return isinstance(exc, (FrameTooLargeError, TruncatedFrameError))


def write_frame(sock: socket.socket, payload: bytes) -> None:
    """Write ``payload`` as a length-prefixed frame."""
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def frame_of_envelope(env: Envelope) -> bytes:
    return encode_envelope(env)


def envelope_of_frame(payload: bytes) -> Envelope:
    return decode_envelope(payload)


# ── EXECUTE builder (§3.2) ────────────────────────────────────────────────────
def make_execute(
    request_id: str,
    uri: str,
    operation: str,
    params: Entity,
    *,
    author: bytes | None = None,
    capability: bytes | None = None,
    resource: Any = None,
) -> Entity:
    """Build a system/protocol/execute entity (§3.2)."""
    data: dict[str, Any] = {
        "request_id": request_id,
        "uri": uri,
        "operation": operation,
        "params": params.to_cbor(),
    }
    if author is not None:
        data["author"] = bytes(author)
    if capability is not None:
        data["capability"] = bytes(capability)
    if resource is not None:
        data["resource"] = resource
    return Entity.make("system/protocol/execute", data)


# ── EXECUTE_RESPONSE builder (§3.3) ───────────────────────────────────────────
def make_response(request_id: str, status: int, result: Entity) -> Entity:
    """Build a system/protocol/execute/response entity (§3.3)."""
    return Entity.make(
        "system/protocol/execute/response",
        {"request_id": request_id, "status": status, "result": result.to_cbor()},
    )


# ── error result + empty params ───────────────────────────────────────────────
def error_result(code: str, message: str = "") -> Entity:
    """Build a system/protocol/error entity ``{code[, message]}``."""
    data: dict[str, Any] = {"code": code}
    if message:
        data["message"] = message
    return Entity.make("system/protocol/error", data)


def empty_params() -> Entity:
    """The empty-params shape (§3.2): a primitive/any whose data is ``{}``."""
    return Entity.make("primitive/any", {})


def resource_target(*targets: str) -> dict:
    """Build a resource ``{targets: [...]}`` value."""
    return {"targets": list(targets)}


def response_status(env: Envelope) -> int:
    s = env.root.uint("status")
    return s if s is not None else 0


def response_result(env: Envelope) -> Entity | None:
    rc = env.root.field("result")
    if not isinstance(rc, dict):
        return None
    from .model import BadEntityError, entity_of_cbor

    try:
        return entity_of_cbor(rc)
    except BadEntityError:
        return None
