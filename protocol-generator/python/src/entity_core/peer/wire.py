"""Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
EXECUTE_RESPONSE).

Frame := ``[4-byte BE length][CBOR payload]``.  The payload is a CBOR-encoded
envelope (§3.1).  Only EXECUTE and EXECUTE_RESPONSE are wire message types
(§3.3); ``hello`` / ``authenticate`` are OPERATIONS on system/protocol/connect,
not message types.

§4.10(a) resource bound: a finite max inbound payload (:data:`MAX_FRAME`, 16
MiB) is enforced by checking the LENGTH PREFIX *before* buffering the body — an
over-limit frame is rejected (-> ``413 payload_too_large``) at read time, before
the oversized buffer is ever allocated.  The recommended (informative) default
is 16 MiB.
"""

from __future__ import annotations

import socket
import struct
from typing import Any

from .model import Entity, Envelope, decode_envelope, encode_envelope

#: §4.10(a) finite inbound-payload bound (16 MiB, the informative default).
MAX_FRAME = 16 * 1024 * 1024


class FrameTooLargeError(Exception):
    """A length prefix exceeded MAX_FRAME (-> 413 payload_too_large).

    Raised BEFORE the body is buffered (§4.10(a)).
    """


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes, or raise ConnectionError on a short close."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket) -> bytes:
    """Read one length-prefixed frame, returning its CBOR payload.

    The length prefix is validated against :data:`MAX_FRAME` before any body
    bytes are read (§4.10(a)).  A clean EOF raises ConnectionError.
    """
    hdr = _recv_exact(sock, 4)
    (n,) = struct.unpack(">I", hdr)
    if n > MAX_FRAME:
        raise FrameTooLargeError(f"{n} > {MAX_FRAME} (413 payload_too_large)")
    return _recv_exact(sock, n)


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
