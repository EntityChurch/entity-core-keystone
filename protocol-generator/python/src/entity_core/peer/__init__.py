"""entity-core-protocol-python — the live peer machinery (S3).

V7 Layers 1-4 + foundation, built on the S2 codec.  Public surface:

  * :class:`Peer` — a bootstrapped Entity Core peer (dispatch chain, store,
    capability core, the four MUST handlers, §6.9a authority bootstrap).
  * :class:`Identity` — a peer's Ed25519 keypair + derived entities.
  * :func:`listen` / :func:`dial` — TCP transport (thread-per-connection,
    §6.11 reentrant demux, TCP_NODELAY).
  * :class:`Entity` / :class:`Envelope` — the materialized entity + wire envelope.

Concurrency: threaded (thread-per-connection), Lock-guarded store, Condition
request_id demux (profile [async]).
"""

from __future__ import annotations

from .identity import Identity, peer_id_of_public_key, verify_signature
from .model import Entity, Envelope, Included
from .peer import GrantSpec, Peer
from .store import ContentEvent, Store, TreeEvent
from .transport import (
    ClientConnection,
    HandshakeError,
    Listener,
    dial,
    listen,
)
from .wire import (
    MAX_FRAME,
    empty_params,
    error_result,
    make_execute,
    make_response,
    resource_target,
    response_result,
    response_status,
)

__all__ = [
    "Peer",
    "GrantSpec",
    "Identity",
    "peer_id_of_public_key",
    "verify_signature",
    "Entity",
    "Envelope",
    "Included",
    "Store",
    "TreeEvent",
    "ContentEvent",
    "Listener",
    "ClientConnection",
    "HandshakeError",
    "listen",
    "dial",
    "make_execute",
    "make_response",
    "error_result",
    "empty_params",
    "resource_target",
    "response_status",
    "response_result",
    "MAX_FRAME",
]
