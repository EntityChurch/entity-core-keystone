"""The in-process extension surface — keystone peer contract v2.0-draft.1 §4.

``Peer.register_handler(spec, body) -> HandlerHandle`` installs a language-native handler
body: the core §6.13(a) writes (types, handler entity, grant, grant signature, interface),
the body bound in the peer's PRIVATE registration index, refusals before anything is
written.  A body receives a :class:`HandlerContext` — built only by the dispatcher.

This is ADDITIVE.  The public ``Peer.handlers`` dict (a ``handle_op(op, DispatchCtx)``
object bound after the caller writes the §11.6.1 entities itself) keeps working exactly
as before; it is not this surface, and ``DispatchCtx`` — a public dataclass anyone can
construct — is not the certified context.

CONTEXT CONSTRUCTION TOKEN, AND ITS STRENGTH (``context.unforgeable``).  Python has no
enforced privacy.  :class:`HandlerContext` refuses construction unless handed a
module-private sentinel the dispatcher holds; it also refuses ``copy``/``pickle``
reconstruction and attribute assignment after construction.  That stops a consumer from
*calling the constructor* or cloning a context it was handed.  It does NOT stop deliberate
introspection: code that imports the underscore name ``_DISPATCHER``, or allocates with
``object.__new__`` and writes slots through ``object.__setattr__``, can still build one.
It is a runtime convention with a loud failure, not a boundary.
"""

from __future__ import annotations

import threading
import weakref
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from .handlers import Outcome
from .model import Entity
from .store import ExecContext

if TYPE_CHECKING:  # pragma: no cover
    from .peer import Peer


#: The dispatcher's construction token.  Module-private by convention only — see the
#: module docstring for what that is and is not worth.
_DISPATCHER = object()


class ContextForgeryError(TypeError):
    """A :class:`HandlerContext` was constructed (or copied) outside the peer's dispatcher."""


# ── spec ──────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class OperationSpec:
    """One operation a handler declares (§3.7 ``operation-spec``)."""

    name: str
    input_type: str | None = None
    output_type: str | None = None

    def to_cbor(self) -> dict:
        d: dict[str, Any] = {}
        if self.input_type:
            d["input_type"] = self.input_type
        if self.output_type:
            d["output_type"] = self.output_type
        return d


@dataclass(slots=True)
class HandlerSpec:
    """What :meth:`Peer.register_handler` installs (``SDK-OPERATIONS`` §11.6).

    ``operations`` accepts :class:`OperationSpec` or a bare name.  ``internal_scope`` is a
    list of §3.6 grant-entry maps, or ``None`` — which mints a grant covering NOTHING, never
    a wildcard (§11.6.3).  ``types`` maps a type name to its definition, bound at
    ``system/type/{name}`` and left in place when the handle closes (§11.6.2).
    """

    pattern: str
    name: str
    operations: list = field(default_factory=list)
    internal_scope: list | None = None
    types: dict = field(default_factory=dict)
    description: str | None = None

    def operation_specs(self) -> list[OperationSpec]:
        return [o if isinstance(o, OperationSpec) else OperationSpec(o) for o in self.operations]


class RegisterError(Exception):
    """A refused registration, carrying the ``SDK-OPERATIONS`` §12.5 status and code.

    Raised BEFORE anything is written: ``409 pattern_collision`` (a handler — built-in,
    ``handlers``-dict, registered, or wire-registered — is already bound at the pattern) or
    ``400 invalid_handler_spec``.
    """

    def __init__(self, status: int, code: str, message: str = "") -> None:
        super().__init__(f"{status} {code}: {message}" if message else f"{status} {code}")
        self.status = status
        self.code = code
        self.message = message


def is_concrete_pattern(pattern: Any) -> bool:
    """A concrete peer-relative handler path: non-empty segments, no ``.``/``..``, no ``*``,
    no leading ``/``, no NUL."""
    return (
        isinstance(pattern, str)
        and pattern != ""
        and not pattern.startswith("/")
        and "\x00" not in pattern
        and all(seg not in ("", ".", "..") and "*" not in seg for seg in pattern.split("/"))
    )


# ── handle ────────────────────────────────────────────────────────────────────
class HandlerHandle:
    """The registration :meth:`Peer.register_handler` returns (§11.6.2).

    :meth:`close` removes the dispatch index entry FIRST, then the handler, interface and
    grant entries (types stay).  It is idempotent: ``True`` for the call that removed the
    registration, ``False`` afterwards — and ``False`` if a later registration now owns the
    pattern, which this handle never touches.  Unlike rust's, a handle that is dropped does
    NOT close: Python has no deterministic drop, so a peer-lifetime install just keeps (or
    discards) the handle.  ``with peer.register_handler(...) as h:`` closes on exit.
    """

    __slots__ = ("_peer", "_pattern", "_generation", "_closed", "_lock", "__weakref__")

    def __init__(self, token: object, peer: "Peer", pattern: str, generation: int) -> None:
        if token is not _DISPATCHER:
            raise TypeError("HandlerHandle is returned by Peer.register_handler, not constructed")
        self._peer = weakref.ref(peer)
        self._pattern = pattern
        self._generation = generation
        self._closed = False
        self._lock = threading.Lock()

    @property
    def pattern(self) -> str:
        return self._pattern

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> bool:
        with self._lock:
            if self._closed:
                return False
            self._closed = True
        peer = self._peer()
        if peer is None:
            return False
        return peer._close_registration(self._pattern, self._generation)

    def __enter__(self) -> "HandlerHandle":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"HandlerHandle(pattern={self._pattern!r}, closed={self._closed})"


# ── evaluator (install.evaluator, MODULE) ─────────────────────────────────────
@dataclass(frozen=True, slots=True)
class ExpressionRequest:
    """What an installed evaluator is asked to evaluate: the §6.13(a) body entity at
    ``expression_path`` of the handler entity ``handler_entity``."""

    expression_path: str
    expression: Entity
    handler_entity: Entity


#: ``evaluator(request, ctx)`` returns an :class:`Outcome`, or ``None`` to decline.
ExpressionEvaluator = Callable[[ExpressionRequest, "HandlerContext"], "Outcome | None"]

#: A registered body: ``body(ctx) -> Outcome``.
HandlerBody = Callable[["HandlerContext"], Outcome]


# ── context ───────────────────────────────────────────────────────────────────
_CTX_SLOTS = (
    "_peer", "_envelope", "_exec", "_pattern", "_suffix",
    "_caller_capability", "_handler_grant", "_conn", "_depth", "_sealed",
)


class HandlerContext:
    """What a registered body receives (``SDK-OPERATIONS`` §11.4 item 5 + this contract).

    Built only by the peer's dispatcher, after §5.2 allowed the request — see the module
    docstring for the construction token and exactly how strong it is.
    """

    __slots__ = _CTX_SLOTS

    def __init__(
        self,
        token: object,
        *,
        peer: "Peer",
        envelope: Any,
        exec_entity: Entity,
        pattern: str,
        suffix: str,
        caller_capability: Entity | None,
        handler_grant: Entity | None,
        conn: Any,
        depth: int,
    ) -> None:
        if token is not _DISPATCHER:
            raise ContextForgeryError(
                "HandlerContext is constructed only by the peer's dispatcher "
                "(keystone peer contract context.unforgeable)"
            )
        s = object.__setattr__
        s(self, "_peer", peer)
        s(self, "_envelope", envelope)
        s(self, "_exec", exec_entity)
        s(self, "_pattern", pattern)
        s(self, "_suffix", suffix)
        s(self, "_caller_capability", caller_capability)
        s(self, "_handler_grant", handler_grant)
        s(self, "_conn", conn)
        s(self, "_depth", depth)
        s(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        raise ContextForgeryError("HandlerContext is immutable")

    def __reduce_ex__(self, protocol: Any) -> Any:
        raise ContextForgeryError("HandlerContext cannot be copied or pickled")

    def __copy__(self) -> Any:
        raise ContextForgeryError("HandlerContext cannot be copied")

    def __deepcopy__(self, memo: Any) -> Any:
        raise ContextForgeryError("HandlerContext cannot be copied")

    # ── request fields ────────────────────────────────────────────────────
    @property
    def peer(self) -> "Peer":
        return self._peer

    @property
    def local_peer(self) -> str:
        return self._peer.local_peer

    @property
    def store(self) -> Any:
        return self._peer.store

    @property
    def envelope(self) -> Any:
        return self._envelope

    @property
    def execute(self) -> Entity:
        """The ``system/protocol/execute`` entity this body is answering."""
        return self._exec

    @property
    def request_id(self) -> str:
        return self._exec.text("request_id") or ""

    @property
    def operation(self) -> str:
        return self._exec.text("operation") or ""

    @property
    def params(self) -> Entity | None:
        return self._exec.sub_entity("params")

    @property
    def resource(self) -> Any:
        return self._exec.field("resource")

    @property
    def pattern(self) -> str:
        """The resolved handler pattern, peer-relative (``app/contract/context``)."""
        return self._pattern

    @property
    def suffix(self) -> str:
        """The remainder of the request path below :attr:`pattern` (``sub/x``), or ``""``."""
        return self._suffix

    @property
    def author(self) -> bytes | None:
        return self._exec.bytes_("author")

    @property
    def caller_capability(self) -> Entity | None:
        """The capability this request was verified under."""
        return self._caller_capability

    @property
    def handler_grant(self) -> Entity | None:
        """The handler's own grant (§6.8a), minted at registration."""
        return self._handler_grant

    # ── derived ───────────────────────────────────────────────────────────
    def frame_budget(self) -> int:
        """The §4.10(a) inbound frame bound in force for this request's connection."""
        conn_budget = getattr(self._conn, "max_frame_bytes", None)
        if isinstance(conn_budget, int) and conn_budget > 0:
            return conn_budget
        return self._peer.max_frame_bytes

    def exec_context(self) -> ExecContext:
        """The §6.8a execution context for a tree write this request causes — pass it to
        ``store.bind`` / ``store.unbind`` so a consumer sees the caller."""
        return self._peer._exec_context(self._exec, self._pattern)

    def identity_in_authority_chain(self, cap_hash: bytes) -> bool:
        """``SDK-OPERATIONS`` §11.3 SEC-3: is this request's AUTHOR a granter in the verified
        chain of ``cap_hash``?"""
        from .capability import identity_in_authority_chain

        included = getattr(self._envelope, "included", {}) or {}
        return identity_in_authority_chain(
            included, self._peer.store, self._peer.local_peer, cap_hash, self.author
        )

    def dispatch_execute(
        self,
        uri: str,
        operation: str,
        params: Entity,
        *,
        target: str | None = None,
        resource: Any = None,
        capability: Entity | None = None,
    ) -> Outcome:
        """Dispatch a LOCAL EXECUTE in-process through the same §6.6 resolution, §5.2
        ``check_permission`` and body selection a wire EXECUTE takes.

        ``capability`` defaults to the caller's.  Admissible: the caller's capability, this
        handler's grant, or a token this peer issued (signature at the §3.5 pointer,
        in bounds, unrevoked); anything else answers ``403 capability_denied``.  Nothing is
        escalated past the capability used.  ``target`` is shorthand for
        ``resource={"targets": [target]}``.  Nested depth past the peer's bound answers
        ``429 bounds_exceeded``; a foreign namespace or the connect handler
        ``400 invalid_request``.  Failures are statuses, never exceptions.
        """
        if target is not None:
            resource = {"targets": [target]}
        return self._peer._dispatch_local(self, uri, operation, params, resource, capability)
