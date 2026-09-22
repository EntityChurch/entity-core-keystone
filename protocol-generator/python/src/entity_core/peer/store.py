"""Storage (foundation, §1.7): the two layers.

    Content Store: hash -> entity   (immutable, content-addressed, dedup)
    Entity Tree:   path -> hash     (mutable location index)

In-memory minimal impl.  Paths are canonical absolute ``/{peer_id}/rest`` (§1.4);
the peer canonicalizes before calling in.  Hash keys render the 33-byte
content_hash as lowercase hex (a comparable dict key).

DATA-RACE SAFETY (§4.8 / profile ``[async].store_safety = lock-guarded``):
per-connection dispatch runs on its own thread (thread-per-connection +
per-request handling), so the store MUST stay consistent under simultaneous
inbound dispatches.  A single :class:`threading.Lock` guards BOTH maps.  CRUCIAL
(the Ruby GVL / A-PY-007 trap): the CPython GIL does NOT make a compound
read-then-write atomic — a thread can be preempted between the read and the
write of a §3.9 CAS — so the explicit Lock is mandatory, not redundant with the
GIL.  Emit consumers are invoked OUTSIDE the lock (snapshot the consumer list +
the event under the lock, fire after releasing it) so a consumer never re-enters
the store while it is held.

EMIT PATHWAY (§6.10 / §6.13(c)) — the Core Extensibility Boundary: tree/content
writes produce events; the bus delivers them to registered consumers.  The hook
is LIVE even with ZERO consumers (events are produced and discarded) so a future
extension can register a consumer without the peer being rebuilt.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

from .model import Entity


@dataclass(frozen=True, slots=True)
class ExecContext:
    """The §6.8a execution-context core fields (SYSTEM-COMPOSITION §1.4) carried on a
    tree-change event.

    The RESERVED field *names* are the collision contract; the representation is
    impl-defined (§9.4) and this is the Python idiom.  On a core peer most slots are
    inert, and every one of them is read from the wire rather than synthesized — a slot
    the request did not carry stays ``None``.

    ``capability`` is deliberately absent as its own slot: it is redundant with
    ``caller_capability`` / ``handler_grant``, which distinguish the two authorities a
    write runs under.  Capability slots carry the token's CONTENT HASH, which is the
    reference an event consumer can resolve against the store.
    """

    request_id: str
    handler_pattern: str
    operation: str
    author: bytes | None = None
    caller_capability: bytes | None = None
    handler_grant: bytes | None = None
    chain_id: str | None = None
    parent_chain_id: str | None = None
    cascade_depth: int | None = None
    bounds: object | None = None


@dataclass(frozen=True, slots=True)
class TreeEvent:
    """A tree-change event (§6.10).

    ``context`` is the §6.8a execution context of the dispatch that caused the write,
    or ``None`` for an AUTONOMOUS write (the peer's own bootstrap and seeding).  That
    distinction is load-bearing rather than cosmetic: EXTENSION-HISTORY §2.1 defines the
    autonomous case exactly (author = the local peer's identity hash), so an event with
    no context is INDISTINGUISHABLE from an autonomous write, and a conforming recorder
    fills in the autonomous reading and attributes a remote caller's write to the local
    peer.  Defaulted so an existing consumer keeps working.
    """

    event_type: str  # created / modified / deleted
    path: str
    new_hash: str  # hex, empty on delete
    previous_hash: str  # hex, empty on create
    context: ExecContext | None = None


@dataclass(frozen=True, slots=True, order=True)
class ConsumerId:
    """The handle :meth:`Store.register_tree_consumer` / :meth:`Store.register_content_consumer`
    return, for :meth:`Store.unregister_consumer`."""

    value: int


@dataclass(frozen=True, slots=True)
class ContentEvent:
    """A content-store event (§6.10) — fired when an entity is new."""

    hash: bytes
    entity: Entity


@dataclass(frozen=True, slots=True)
class ListingRow:
    """One entry of a one-level listing."""

    segment: str
    hash: str  # hex, empty for an interior-only node
    has_children: bool


def _derive_event_type(prev: str, nxt: str) -> str:
    if prev == "":
        return "created"
    if nxt == "":
        return "deleted"
    return "modified"


class Store:
    """The content-addressed store + the entity tree (Lock-guarded)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._content: dict[str, Entity] = {}  # hash-hex -> entity
        self._tree: dict[str, str] = {}  # path -> hash-hex
        # (id, consumer) in registration order; ids are never reused.
        self._tree_consumers: list[tuple[ConsumerId, Callable[[TreeEvent], None]]] = []
        self._content_consumers: list[tuple[ConsumerId, Callable[[ContentEvent], None]]] = []
        self._next_consumer = 0

    # ── consumer registration (§6.10) ────────────────────────────────────────
    # SYSTEM-COMPOSITION §1.2 / §2.2: consumers run synchronously, in registration order,
    # and a write's content-store event precedes its tree-change event.  Registration is
    # open for the peer's whole life (not only during initialization) and returns a
    # :class:`ConsumerId` that :meth:`unregister_consumer` takes — keystone peer contract
    # ``install.consumer``.  An existing caller that ignored the (formerly ``None``)
    # return value is unaffected.
    def _new_consumer_id(self) -> "ConsumerId":
        self._next_consumer += 1
        return ConsumerId(self._next_consumer)

    def register_tree_consumer(self, fn: Callable[[TreeEvent], None]) -> "ConsumerId":
        with self._lock:
            cid = self._new_consumer_id()
            self._tree_consumers.append((cid, fn))
        return cid

    def register_content_consumer(self, fn: Callable[[ContentEvent], None]) -> "ConsumerId":
        with self._lock:
            cid = self._new_consumer_id()
            self._content_consumers.append((cid, fn))
        return cid

    def unregister_consumer(self, cid: "ConsumerId") -> bool:
        """Stop delivering events to a consumer.  Idempotent: ``False`` when ``cid`` is not
        registered (already removed, or never was)."""
        with self._lock:
            for consumers in (self._tree_consumers, self._content_consumers):
                for i, (c, _fn) in enumerate(consumers):
                    if c == cid:
                        del consumers[i]
                        return True
        return False

    # ── content store ────────────────────────────────────────────────────────
    def put_entity(self, e: Entity) -> bool:
        """Insert into the content store if new (a re-put fires nothing).

        Returns ``True`` when the entity is in the store afterwards (stored now, or already
        present), ``False`` when it was REFUSED: an entity whose carried ``hash`` is not its
        content hash (:meth:`Entity.content_hash_holds`) is never filed, so nothing becomes
        readable under a hash it does not have.  The store is keyed by content hash and the
        authority path resolves grantees through it; trusting the carried hash would let
        in-process code answer for another entity's address (keystone peer contract
        ``embed.data``, §6 Q8).
        """
        if not e.content_hash_holds():
            return False
        k = e.hash.hex()
        with self._lock:
            if k in self._content:
                return True
            self._content[k] = e
            consumers = [fn for _c, fn in self._content_consumers]
        ev = ContentEvent(hash=e.hash, entity=e)
        for fn in consumers:
            fn(ev)
        return True

    def get_by_hash(self, h: bytes | None) -> Entity | None:
        if h is None:
            return None
        with self._lock:
            return self._content.get(bytes(h).hex())

    # ── tree ─────────────────────────────────────────────────────────────────
    def bind(self, path: str, e: Entity, context: ExecContext | None = None) -> bool:
        """Bind ``path`` to entity ``e`` (putting ``e`` in the content store).

        ``context`` is the §6.8a execution context of the dispatch that caused this
        write; omit it for an AUTONOMOUS write (bootstrap, seeding).  See
        :class:`TreeEvent` for why the distinction matters to a recorder.

        Returns ``True`` when bound, ``False`` when refused — the same integrity rule as
        :meth:`put_entity`: an entity whose carried hash is not its content hash binds
        nothing and fires nothing.
        """
        if not self.put_entity(e):
            return False
        nxt = e.hash.hex()
        with self._lock:
            prev = self._tree.get(path, "")
            self._tree[path] = nxt
            changed = prev != nxt
            consumers = [fn for _c, fn in self._tree_consumers]
        if changed:
            ev = TreeEvent(_derive_event_type(prev, nxt), path, nxt, prev, context)
            for fn in consumers:
                fn(ev)
        return True

    def unbind(self, path: str, context: ExecContext | None = None) -> bool:
        """Remove the binding at ``path``; ``True`` when one was removed.  ``context`` as for
        :meth:`bind`."""
        with self._lock:
            prev = self._tree.pop(path, "")
            had = prev != ""
            consumers = [fn for _c, fn in self._tree_consumers]
        if had:
            ev = TreeEvent("deleted", path, "", prev, context)
            for fn in consumers:
                fn(ev)
        return had

    def hash_at(self, path: str) -> str:
        with self._lock:
            return self._tree.get(path, "")

    def get_at(self, path: str) -> Entity | None:
        with self._lock:
            h = self._tree.get(path)
            if h is None:
                return None
            return self._content.get(h)

    def listing(self, prefix: str) -> list[ListingRow]:
        """One-level listing under ``prefix`` (§3.9), sorted by segment."""
        if not prefix.endswith("/"):
            prefix += "/"
        plen = len(prefix)
        acc: dict[str, list] = {}  # seg -> [hash, deeper]
        with self._lock:
            for path, h in self._tree.items():
                if len(path) <= plen or path[:plen] != prefix:
                    continue
                rest = path[plen:]
                i = rest.find("/")
                if i >= 0:
                    seg = rest[:i]
                    cell = acc.setdefault(seg, ["", False])
                    cell[1] = True
                else:
                    cell = acc.setdefault(rest, ["", False])
                    cell[0] = h
        rows = [ListingRow(seg, c[0], c[1]) for seg, c in acc.items()]
        rows.sort(key=lambda r: r.segment)
        return rows
