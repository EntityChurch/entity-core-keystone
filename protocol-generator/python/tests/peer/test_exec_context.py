"""H8 / H9 — the execution context on a tree-change event, and the path-permission
primitive an extension needs.

Both routed by ``entity-system-generator`` out of building ``EXTENSION-HISTORY`` v1.7.

H8 IS NOT A MISSING TYPE, it is a missing VALUE, and the distinction is the whole
reason this file asserts on ``author`` rather than on "a context is present".
``TreeEvent`` carried four fields and no context at all, so every tree-change event
reached a consumer contextless.  EXTENSION-HISTORY §2.1 defines the AUTONOMOUS case
exactly — author is the local peer's identity hash — so a contextless event is
INDISTINGUISHABLE from an autonomous write.  A conforming recorder therefore fills in
the autonomous reading and attributes a REMOTE caller's write to the local peer, while
scoring 33/34 on ``history``: the four oracle checks over these fields
(``context_author_present`` and friends) are PRESENCE checks over values the extension
itself fabricates.

The two-peer setup is the control.  A single-peer test passes against the fabricated
autonomous value, because there the caller and the local peer ARE the same identity.

H9 exposes core §6.3's path check, which §4.2's dual capability model names by name.
Every scope helper it is built from is leading-underscore — an honest statement of this
module's boundary that left an extension author no way to satisfy §4.2 except by
re-transcribing core §5.2's authorization logic inside the extension.
"""

from __future__ import annotations

from entity_core.peer import (
    ExecContext,
    Identity,
    Peer,
    TreeEvent,
    dial,
    listen,
    resource_target,
    response_status,
)
from entity_core.peer.capability import check_path_permission
from entity_core.peer.model import Entity


def _fixed_seed(b: int) -> bytes:
    return bytes([b] * 32)


def _put_over_the_wire(seed: int) -> tuple[list[TreeEvent], bytes, bytes, str]:
    """Drive a real remote ``system/tree:put`` and collect the events it fired."""
    responder = Peer(_fixed_seed(seed), open_grants=True, conformance=True)
    initiator = Identity.of_seed(_fixed_seed(seed + 1))
    seen: list[TreeEvent] = []
    responder.store.register_tree_consumer(seen.append)
    ln = listen(responder, 0)
    try:
        cc = dial("127.0.0.1", ln.port)
        try:
            cc.handshake(initiator)
            path = "/" + cc.remote_peer_id + "/app/h8/probe"
            body = Entity.make("primitive/any", {"v": 1})
            req = Entity.make("system/tree/put-request", {"entity": body.to_cbor()})
            r = cc.execute(
                initiator, "/" + cc.remote_peer_id + "/system/tree", "put", req,
                resource_target(path),
            )
            assert r is not None and response_status(r) == 200, "tree:put -> 200"
        finally:
            cc.close()
    finally:
        ln.close()
    return (
        seen,
        initiator.identity_hash,
        responder.identity.identity_hash,
        path,
    )


def test_h8_remote_put_attributes_the_remote_caller() -> None:
    seen, caller_hash, local_hash, path = _put_over_the_wire(70)
    evs = [e for e in seen if e.path == path]
    assert evs, "the tree:put fired no tree-change event at the target path"
    ctx = evs[0].context
    assert ctx is not None, "tree-change event carried no context (the H8 defect)"

    # The load-bearing assertion.  Before the fix this field did not exist, and a
    # recorder filling it from §2.1's autonomous rule writes the LOCAL hash here.
    assert ctx.author == caller_hash, "author must be the REMOTE caller's identity"
    assert ctx.author != local_hash, (
        "author is the local peer's own hash — that is the autonomous-fallback "
        "reading, not the caller"
    )

    # "Under what authority?" (§7.2) — both authorities the write ran under.
    assert ctx.caller_capability is not None, "context carried no caller_capability"
    assert ctx.handler_grant is not None, "context carried no handler_grant"
    assert ctx.handler_pattern == "system/tree"
    assert ctx.operation == "put"
    assert ctx.request_id, "context carried no request_id"


def test_h8_control_autonomous_write_carries_no_context() -> None:
    """The other half, and a real case rather than symmetry: a peer's OWN writes are
    autonomous and must stay distinguishable.  Fabricating a context here would be the
    same defect in the opposite direction."""
    peer = Peer(_fixed_seed(72), open_grants=True)
    seen: list[TreeEvent] = []
    peer.store.register_tree_consumer(seen.append)
    path = "/" + peer.local_peer + "/app/h8/autonomous"
    peer.store.bind(path, Entity.make("primitive/any", {"v": 2}))
    peer.store.unbind(path)
    assert len(seen) == 2, "expected one created + one deleted event"
    assert all(e.context is None for e in seen), (
        "an autonomous write carried a caller context; autonomous and dispatched "
        "writes are no longer distinguishable"
    )


def test_h8_context_slots_absent_from_the_wire_stay_none() -> None:
    """A core request carries none of the four chain/bounds slots, and they must read
    as absent rather than as invented values."""
    seen, _, _, path = _put_over_the_wire(74)
    ctx = [e for e in seen if e.path == path][0].context
    assert isinstance(ctx, ExecContext)
    assert ctx.chain_id is None
    assert ctx.parent_chain_id is None
    assert ctx.cascade_depth is None
    assert ctx.bounds is None


# ── H9 ────────────────────────────────────────────────────────────────────────


def _token(local_peer: str, handlers: list[str], ops: list[str], resources: list[str]) -> Entity:
    # A grant is a plain map inside `grants`, NOT a serialized entity -- `GrantRec`
    # reads it as a dict. The first draft of this fixture wrapped each grant in
    # `Entity.make(...).to_cbor()`; every scope then parsed EMPTY, so the function
    # denied everything and all three deny-controls below passed. Only the accept
    # case caught it, which is the reason the accept case exists.
    return Entity.make("system/capability/token", {
        "grants": [{
            "handlers": {"include": handlers},
            "operations": {"include": ops},
            "resources": {"include": resources},
        }],
        "grantee": bytes(33),
        "granter": bytes(33),
        "created_at": 0,
    })


def test_h9_path_permission_allows_a_covered_path() -> None:
    lp = "peer1"
    tok = _token(lp, ["system/tree"], ["put"], ["/" + lp + "/app/*"])
    assert check_path_permission("put", "/" + lp + "/app/x", tok, "system/tree", lp)


def test_h9_path_permission_denies_each_dimension_independently() -> None:
    """Three controls, one per dimension.  One control cannot tell "the function
    denies" from "the function checks the dimension I care about"."""
    lp = "peer1"
    tok = _token(lp, ["system/tree"], ["put"], ["/" + lp + "/app/*"])
    # resource outside the grant
    assert not check_path_permission("put", "/" + lp + "/other/x", tok, "system/tree", lp)
    # operation outside the grant
    assert not check_path_permission("get", "/" + lp + "/app/x", tok, "system/tree", lp)
    # handler pattern outside the grant
    assert not check_path_permission("put", "/" + lp + "/app/x", tok, "system/content", lp)
