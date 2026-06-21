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
class TreeEvent:
    """A tree-change event (§6.10)."""

    event_type: str  # created / modified / deleted
    path: str
    new_hash: str  # hex, empty on delete
    previous_hash: str  # hex, empty on create


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
        self._tree_consumers: list[Callable[[TreeEvent], None]] = []
        self._content_consumers: list[Callable[[ContentEvent], None]] = []

    # ── consumer registration (§6.10) ────────────────────────────────────────
    def register_tree_consumer(self, fn: Callable[[TreeEvent], None]) -> None:
        with self._lock:
            self._tree_consumers.append(fn)

    def register_content_consumer(self, fn: Callable[[ContentEvent], None]) -> None:
        with self._lock:
            self._content_consumers.append(fn)

    # ── content store ────────────────────────────────────────────────────────
    def put_entity(self, e: Entity) -> None:
        """Insert into the content store if new (a re-put fires nothing)."""
        k = e.hash.hex()
        with self._lock:
            if k in self._content:
                return
            self._content[k] = e
            consumers = list(self._content_consumers)
        ev = ContentEvent(hash=e.hash, entity=e)
        for fn in consumers:
            fn(ev)

    def get_by_hash(self, h: bytes | None) -> Entity | None:
        if h is None:
            return None
        with self._lock:
            return self._content.get(bytes(h).hex())

    # ── tree ─────────────────────────────────────────────────────────────────
    def bind(self, path: str, e: Entity) -> None:
        """Bind ``path`` to entity ``e`` (putting ``e`` in the content store)."""
        self.put_entity(e)
        nxt = e.hash.hex()
        with self._lock:
            prev = self._tree.get(path, "")
            self._tree[path] = nxt
            changed = prev != nxt
            consumers = list(self._tree_consumers)
        if changed:
            ev = TreeEvent(_derive_event_type(prev, nxt), path, nxt, prev)
            for fn in consumers:
                fn(ev)

    def unbind(self, path: str) -> None:
        with self._lock:
            prev = self._tree.pop(path, "")
            had = prev != ""
            consumers = list(self._tree_consumers)
        if had:
            ev = TreeEvent("deleted", path, "", prev)
            for fn in consumers:
                fn(ev)

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
