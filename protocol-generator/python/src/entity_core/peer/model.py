"""Materialized entity + protocol envelope (§1.1, §3.1, §3.4).

An :class:`Entity` is the materialized ``{type, data, content_hash}`` triple.
The content_hash covers ONLY ``{type, data}`` (§1.1); the wire form carries it
as a third field so entities are self-describing across serialization (§3.1).

``data`` is an ARBITRARY ECF value — NOT necessarily a dict (A-JAVA-010).  The
value tree is the S2 codec's native tree: ``None / bool / int / float / str /
bytes / list / dict``, with byte-string map keys carried as
:class:`entity_core.ByteKey` so they encode as CBOR major type 2.

Field accessors (``field`` / ``text`` / ``bytes_`` / ``uint`` / ``sub_entity``)
return ``None`` (or a sentinel) when ``data`` is not a map or the key is absent,
so a handler never crashes on a malformed inbound entity (§4.9 no-crash).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import _cbor
from ..content_hash import content_hash

#: ecfv1-sha256 floor: a content_hash is the 1-byte format code 0x00 followed by
#: the 32-byte SHA-256 digest (33 bytes total).
FORMAT_ECFV1_SHA256 = 0


class BadEntityError(Exception):
    """A malformed wire entity or a §1.8 content_hash fidelity violation."""


@dataclass(frozen=True, slots=True)
class Entity:
    """A materialized entity: declared type, arbitrary-ECF data, content_hash.

    ``hash`` is the 33-byte content_hash (format byte 0x00 ‖ 32-byte SHA-256)
    computed over the canonical ECF of ``{type, data}``.
    """

    type: str
    data: Any
    hash: bytes

    # ── construction ─────────────────────────────────────────────────────────
    @staticmethod
    def make(entity_type: str, data: Any) -> "Entity":
        """Materialize an entity, computing its ecfv1-sha256 content_hash."""
        h = content_hash(entity_type, data, FORMAT_ECFV1_SHA256)
        return Entity(type=entity_type, data=data, hash=h)

    # ── data-map field accessors (data is an arbitrary ECF value) ────────────
    def field(self, key: str) -> Any:
        """Return the value at ``key`` in the data map, or ``None``."""
        if not isinstance(self.data, dict):
            return None
        return self.data.get(key)

    def text(self, key: str) -> str | None:
        v = self.field(key)
        return v if isinstance(v, str) else None

    def bytes_(self, key: str) -> bytes | None:
        v = self.field(key)
        return bytes(v) if isinstance(v, (bytes, bytearray)) else None

    def uint(self, key: str) -> int | None:
        v = self.field(key)
        # bool is an int subclass — exclude it.
        if isinstance(v, bool):
            return None
        return v if isinstance(v, int) and v >= 0 else None

    def sub_entity(self, key: str) -> "Entity | None":
        """Decode a nested entity (a map with type/data/content_hash) at key."""
        v = self.field(key)
        if not isinstance(v, dict):
            return None
        try:
            return entity_of_cbor(v)
        except BadEntityError:
            return None

    # ── wire form: an entity carries its content_hash ────────────────────────
    def to_cbor(self) -> dict:
        """Serialize to the wire map ``{type, data, content_hash}``."""
        return {"type": self.type, "data": self.data, "content_hash": self.hash}


def entity_of_cbor(m: Any) -> Entity:
    """Parse a wire entity map, recompute the hash from ``{type, data}`` and
    validate it against the carried ``content_hash`` (§1.8 fidelity:
    validate-before-trust — the recomputed hash is trusted, not the wire bytes).
    """
    if not isinstance(m, dict):
        raise BadEntityError("entity is not a map")
    typ = m.get("type")
    if not isinstance(typ, str):
        raise BadEntityError("entity missing text type")
    if "data" not in m:
        raise BadEntityError("entity missing data")
    e = Entity.make(typ, m["data"])
    carried = m.get("content_hash")
    if isinstance(carried, (bytes, bytearray)) and bytes(carried) != e.hash:
        raise BadEntityError("content_hash mismatch (§1.8)")
    return e


# ── envelope (§3.1) ──────────────────────────────────────────────────────────
class Included(dict):
    """The envelope's included-entity set, keyed by content_hash (hex str)."""

    def get_by_hash(self, h: bytes | None) -> Entity | None:
        if h is None:
            return None
        return self.get(bytes(h).hex())

    def add(self, e: Entity) -> None:
        self[e.hash.hex()] = e


@dataclass(frozen=True, slots=True)
class Envelope:
    """The wire envelope ``{root, included}`` (§3.1)."""

    root: Entity
    included: Included

    @staticmethod
    def of(root: Entity, *included: Entity) -> "Envelope":
        inc = Included()
        for e in included:
            inc.add(e)
        return Envelope(root=root, included=inc)

    def to_cbor(self) -> dict:
        from .. import ByteKey  # byte-string map keys (major type 2)

        inc = {ByteKey(bytes.fromhex(k)): e.to_cbor() for k, e in self.included.items()}
        return {"root": self.root.to_cbor(), "included": inc}


def envelope_of_cbor(m: Any) -> Envelope:
    """Parse a wire envelope map, validating each included entity's content_hash
    equals its map key (§3.1)."""
    if not isinstance(m, dict):
        raise BadEntityError("envelope is not a map")
    root_c = m.get("root")
    if not isinstance(root_c, dict):
        raise BadEntityError("envelope missing root map")
    root = entity_of_cbor(root_c)
    included = Included()
    inc_c = m.get("included")
    if isinstance(inc_c, dict):
        for key, val in inc_c.items():
            if not isinstance(key, (bytes, bytearray)):
                raise BadEntityError("included key is not a byte string")
            e = entity_of_cbor(val)
            if bytes(key) != e.hash:
                raise BadEntityError("included key != content_hash (§3.1)")
            included.add(e)
    return Envelope(root=root, included=included)


def encode_envelope(env: Envelope) -> bytes:
    """Encode an envelope to canonical ECF bytes."""
    return _cbor.encode(env.to_cbor())


def decode_envelope(payload: bytes) -> Envelope:
    """Decode canonical ECF bytes into an :class:`Envelope`."""
    return envelope_of_cbor(_cbor.decode(payload))
