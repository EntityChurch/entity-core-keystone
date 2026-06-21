"""Transport (L4): TCP listener + thread-per-connection reader-demux (§1.6
framing, §4.8 inbound concurrency, §6.11 reentry) + the client dialer/handshake
that drives the two-peer loopback.

CONCURRENCY MODEL (profile [async].style = threaded, thread-per-connection):
one reader thread per connection demuxes inbound frames (§6.11).  An
EXECUTE_RESPONSE routes to its awaiting outbound caller by request_id through a
per-conn pending-map + a single :class:`threading.Condition` (the threaded-peer
reader-thread + condvar shape, same as the OCaml / Ruby cohort).  An inbound
EXECUTE is dispatched on ITS OWN thread (§4.8) so a handler that originates an
outbound EXECUTE (§6.11 reentry) and awaits its response does NOT block the
reader.  Writes are serialized by a Lock.  CPython releases the GIL during
blocking socket IO + inside the cryptography/hashlib C extensions, so this is
genuinely concurrent for the IO-bound peer workload (A-PY-007).

TCP_NODELAY (profile [async].tcp_nodelay = true): set on EVERY accepted/dialed
socket from day one — Nagle + delayed-ACK on small req/resp frames is THE §7b
throughput killer.
"""

from __future__ import annotations

import socket
import threading
from typing import Callable

from .model import Entity, Envelope
from .wire import (
    FrameTooLargeError,
    frame_of_envelope,
    make_execute,
    make_response,
    read_frame,
    response_result,
    response_status,
    write_frame,
)
from .peer import Conn, Peer
from .identity import Identity, peer_id_of_public_key


def _set_nodelay(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


class TransportIO:
    """A per-connection IO endpoint shared by server + client."""

    def __init__(self, sock: socket.socket) -> None:
        _set_nodelay(sock)
        self.sock = sock
        self._write_lock = threading.Lock()
        self._cond = threading.Condition()
        self._pending: dict[str, Envelope | None] = {}  # request_id -> response
        self._waiting: set[str] = set()
        self._closed = False

    def write_framed(self, env: Envelope) -> None:
        payload = frame_of_envelope(env)
        with self._write_lock:
            write_frame(self.sock, payload)

    def _route_response(self, env: Envelope) -> None:
        request_id = env.root.text("request_id") or ""
        with self._cond:
            if request_id in self._waiting:
                self._pending[request_id] = env
                self._cond.notify_all()

    def outbound(self, req: Envelope) -> Envelope | None:
        """Send a request envelope and await its correlated EXECUTE_RESPONSE
        (§6.11 demux).  Returns None if the connection closes first."""
        request_id = req.root.text("request_id") or ""
        with self._cond:
            if self._closed:
                return None
            self._waiting.add(request_id)
        try:
            self.write_framed(req)
        except OSError:
            with self._cond:
                self._waiting.discard(request_id)
            return None
        with self._cond:
            while request_id not in self._pending and not self._closed:
                self._cond.wait()
            self._waiting.discard(request_id)
            return self._pending.pop(request_id, None)

    def close(self) -> None:
        with self._cond:
            if self._closed:
                return
            self._closed = True
            self._cond.notify_all()
        try:
            self.sock.close()
        except OSError:
            pass

    def read_loop(self, on_execute: Callable[[Envelope], None]) -> None:
        """§6.11 demux: EXECUTE_RESPONSE -> route; EXECUTE -> dispatch on its own
        thread (§4.8)."""
        from .model import BadEntityError
        from .wire import envelope_of_frame

        while True:
            try:
                payload = read_frame(self.sock)
            except FrameTooLargeError:
                # §4.10(a): rejected before buffering; close + keep the peer
                # serving other connections (this loop just ends).
                return
            except (OSError, ConnectionError):
                return
            try:
                env = envelope_of_frame(payload)
            except (BadEntityError, Exception):
                continue  # malformed frame: skip, keep reading
            if env.root.type == "system/protocol/execute/response":
                self._route_response(env)
            else:
                threading.Thread(target=on_execute, args=(env,), daemon=True).start()


# ── server ────────────────────────────────────────────────────────────────────
class Listener:
    """A running TCP listener for a peer."""

    def __init__(self, peer: Peer, port: int) -> None:
        self.peer = peer
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(64)
        self.port = self._sock.getsockname()[1]
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _accept_loop(self) -> None:
        while True:
            try:
                conn_sock, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn_sock,), daemon=True).start()

    def _serve(self, conn_sock: socket.socket) -> None:
        tio = TransportIO(conn_sock)
        cn = Conn()
        cn.outbound = tio.outbound  # wire the §6.11 reentry seam to this conn

        def on_execute(env: Envelope) -> None:
            # per-request isolation: an adversarial request must NOT tear down the
            # connection (§4.9 no-crash; §3.3 every EXECUTE gets a response).
            try:
                resp = self.peer.dispatch(cn, env)
                if resp is not None:
                    tio.write_framed(resp)
            except Exception:
                request_id = env.root.text("request_id") or ""
                from .wire import error_result

                try:
                    tio.write_framed(Envelope.of(
                        make_response(request_id, 500, error_result("internal_error"))
                    ))
                except OSError:
                    pass

        tio.read_loop(on_execute)
        tio.close()

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def listen(peer: Peer, port: int = 0) -> Listener:
    """Bind 127.0.0.1:port (0 = auto-assign) and start accepting."""
    return Listener(peer, port)


# ══════════════════════════════════════════════════════════════════════════════
# Client side — dialer + initiator handshake (drives the two-peer loopback)
# ══════════════════════════════════════════════════════════════════════════════
class HandshakeError(Exception):
    def __init__(self, step: str, status: int = 0, code: str = "") -> None:
        super().__init__(f"{step} failed: status {status} {code}")
        self.step = step
        self.status = status
        self.code = code


class ClientConnection:
    """An initiator-side session that drives the §4.1 handshake + authenticated
    EXECUTEs over a real TCP connection."""

    def __init__(self, host: str, port: int) -> None:
        sock = socket.create_connection((host, port))
        self._io = TransportIO(sock)
        self._req_counter = 0
        self.remote_peer_id = ""
        self.capability: Entity | None = None
        self._granter_peer: Entity | None = None
        self._cap_sig: Entity | None = None
        threading.Thread(target=self._io.read_loop, args=(lambda env: None,), daemon=True).start()

    def _next_request_id(self) -> str:
        self._req_counter += 1
        return "req-" + str(self._req_counter)

    def _send(self, req: Envelope) -> Envelope | None:
        return self._io.outbound(req)

    def close(self) -> None:
        self._io.close()

    # ── initiator handshake (§4.1 forward leg: hello -> authenticate) ────────
    def handshake(self, local: Identity) -> None:
        import os

        from .model import Envelope as Env

        hello = Entity.make("system/protocol/connect/hello", {
            "peer_id": local.peer_id,
            "nonce": os.urandom(32),
            "protocols": ["entity-core/1.0"],
            "timestamp": int(__import__("time").time() * 1000),
            "hash_formats": ["ecfv1-sha256"],
            "key_types": ["ed25519"],
        })
        r1 = self._send(Env.of(make_execute(self._next_request_id(), "system/protocol/connect", "hello", hello)))
        if r1 is None:
            raise HandshakeError("hello", 0, "connection_broken")
        self._require_ok(r1, "hello")
        remote_hello = response_result(r1)
        if remote_hello is None:
            raise HandshakeError("hello", code="bad_response")
        self.remote_peer_id = remote_hello.text("peer_id") or ""
        remote_nonce = remote_hello.bytes_("nonce")

        auth = Entity.make("system/protocol/connect/authenticate", {
            "peer_id": local.peer_id,
            "public_key": bytes(local.public_key),
            "key_type": "ed25519",
            "nonce": remote_nonce,
        })
        auth_sig = local.sign_entity(auth)
        r2 = self._send(Env.of(
            make_execute(self._next_request_id(), "system/protocol/connect", "authenticate", auth),
            local.peer_entity,
            auth_sig,
        ))
        if r2 is None:
            raise HandshakeError("authenticate", 0, "connection_broken")
        self._require_ok(r2, "authenticate")
        grant = response_result(r2)
        if grant is None:
            raise HandshakeError("authenticate", code="bad_grant")
        token_h = grant.bytes_("token")
        token = r2.included.get_by_hash(token_h)
        if token is None:
            raise HandshakeError("authenticate", code="missing_token")
        granter_h = token.bytes_("granter")
        granter_peer = r2.included.get_by_hash(granter_h)
        cap_sig = _find_signature(token.hash, r2.included)
        if granter_peer is None or cap_sig is None:
            raise HandshakeError("authenticate", code="missing_grant_authority")
        self.capability = token
        self._granter_peer = granter_peer
        self._cap_sig = cap_sig

    def _require_ok(self, env: Envelope, step: str) -> None:
        status = response_status(env)
        if status == 200:
            return
        code = ""
        res = response_result(env)
        if res is not None:
            code = res.text("code") or ""
        raise HandshakeError(step, status, code)

    # ── authenticated EXECUTE (§5.8 full authority chain in `included`) ──────
    def execute(self, local: Identity, uri: str, operation: str, params: Entity, resource=None) -> Envelope | None:
        from .model import Envelope as Env

        if self.capability is None:
            raise RuntimeError("execute before handshake")
        exec_e = make_execute(
            self._next_request_id(), uri, operation, params,
            author=local.identity_hash,
            capability=self.capability.hash,
            resource=resource,
        )
        exec_sig = local.sign_entity(exec_e)
        env = Env.of(
            exec_e, self.capability, self._granter_peer, local.peer_entity, self._cap_sig, exec_sig
        )
        return self._send(env)


def _find_signature(target: bytes, included) -> Entity | None:
    from .capability import find_signature

    return find_signature(target, included)


def dial(host: str, port: int) -> ClientConnection:
    return ClientConnection(host, port)
