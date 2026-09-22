"""Keystone peer contract v2.0-draft.1 — the LOCAL tests (what the wire cannot observe).

Function names carry the requirement prefix ``tools/peer-contract/report.py`` matches
(``context.unforgeable`` -> ``context_unforgeable__``); ``pyproject.toml`` tells pytest to
collect them.  Each requirement's refusal has a positive control beside it, so a refusal
cannot pass on an unrelated error.
"""

from __future__ import annotations

import copy
import pickle

import pytest

from entity_core.peer import (
    ContextForgeryError,
    Entity,
    HandlerContext,
    HandlerSpec,
    Identity,
    Outcome,
    Peer,
    SeedPolicy,
    dial,
    empty_params,
    identity_in_authority_chain,
    listen,
    response_result,
    response_status,
)
from entity_core.peer.extension import HandlerContext as ExtensionHandlerContext


def _seed(b: int) -> bytes:
    return bytes([b] * 32)


def _ok(data: dict) -> Outcome:
    return Outcome.ok(Entity.make("primitive/any", data))


def _call(responder: Peer, initiator: Identity, path: str, op: str) -> tuple[int, Entity | None]:
    """One authenticated EXECUTE from ``initiator`` to ``responder`` over real loopback TCP."""
    ln = listen(responder, 0)
    try:
        cc = dial("127.0.0.1", ln.port)
        try:
            cc.handshake(initiator)
            r = cc.execute(initiator, "/" + cc.remote_peer_id + "/" + path, op, empty_params())
            assert r is not None, "no response"
            return response_status(r), response_result(r)
        finally:
            cc.close()
    finally:
        ln.close()


# ── embed.create ──────────────────────────────────────────────────────────────
def embed_create__two_peers_in_one_process_are_independent() -> None:
    """SDK-OPERATIONS §8.1 (MUST): several independent peers in one process."""
    a = Peer(_seed(0x61), open_grants=True)
    b = Peer(_seed(0x62), open_grants=True)
    assert a.local_peer != b.local_peer, "independent identities"
    h = a.register_handler(HandlerSpec("app/only-on-a", "a", operations=["go"]),
                           lambda ctx: _ok({"on": ctx.local_peer}))
    assert a.store.get_at(f"/{a.local_peer}/app/only-on-a") is not None, "installed on a"
    assert b.store.get_at(f"/{b.local_peer}/app/only-on-a") is None, "b has its own store"
    assert a.has_registered_handler("app/only-on-a") and not b.has_registered_handler("app/only-on-a")
    # Both serve in this process at once; the same pattern answers on a and 404s on b.
    caller = Identity.of_seed(_seed(0x63))
    status_a, res_a = _call(a, caller, "app/only-on-a", "go")
    status_b, _ = _call(b, caller, "app/only-on-a", "go")
    assert (status_a, status_b) == (200, 404), (status_a, status_b)
    assert res_a is not None and res_a.field("on") == a.local_peer
    # Closing a's handle touches a only.
    assert h.close() is True
    assert a.store.get_at(f"/{a.local_peer}/app/only-on-a") is None
    assert b.store.get_at(f"/{b.local_peer}/app/only-on-a") is None


def embed_create__a_peer_with_no_listener_is_fully_usable() -> None:
    """SDK-OPERATIONS §8.1 (MUST): a peer with no listener.  It never binds a socket, and its
    construction values (seed policy, frame budget) are in force."""
    policy = SeedPolicy.standard()
    p = Peer(_seed(0x64), seed_policy=policy, max_frame_bytes=123_456)
    assert p.max_frame_bytes == 123_456
    assert p.store.get_at(f"/{p.local_peer}/system/capability/policy/default") is not None
    seen: list[str] = []
    p.store.register_tree_consumer(lambda ev: seen.append(ev.path))
    h = p.register_handler(HandlerSpec("app/listenerless", "l", operations=["x"]), lambda ctx: _ok({}))
    item = Entity.make("contract/data-item", {"marker": "listenerless"})
    assert p.store.bind(f"/{p.local_peer}/app/data/item", item) is True
    assert p.store.get_by_hash(item.hash) == item
    assert f"/{p.local_peer}/app/listenerless" in seen, "installing fired tree events in-process"
    assert h.close() is True and h.close() is False


# ── context.authority_chain ───────────────────────────────────────────────────
def _chain_answers(responder_seed: int, initiator_seed: int) -> tuple[bool, bool, bool]:
    """(author in chain via the context, local identity in chain, zero hash in chain)."""
    responder = Peer(_seed(responder_seed))
    initiator = Identity.of_seed(_seed(initiator_seed))
    seen: list[tuple[bool, bool, bool]] = []

    def body(ctx: HandlerContext) -> Outcome:
        cap = ctx.caller_capability
        assert cap is not None, "a verified capability"
        included = ctx.envelope.included
        seen.append((
            ctx.identity_in_authority_chain(cap.hash),
            identity_in_authority_chain(included, ctx.store, ctx.local_peer, cap.hash,
                                        responder.identity.identity_hash),
            identity_in_authority_chain(included, ctx.store, ctx.local_peer, bytes(33),
                                        responder.identity.identity_hash),
        ))
        return _ok({})

    responder.register_handler(HandlerSpec("app/chain", "chain", operations=["ask"]), body)
    # The default policy's discovery floor does not reach app/chain; grant the caller its
    # handler so the request is dispatched at all.
    status, _ = _call_with_policy(responder, initiator, "app/chain", "ask")
    assert status == 200, status
    assert len(seen) == 1
    return seen[0]


def _call_with_policy(responder: Peer, initiator: Identity, path: str, op: str) -> tuple[int, Entity | None]:
    responder.store.bind(
        f"/{responder.local_peer}/system/capability/policy/{initiator.identity_hash.hex()}",
        Entity.make("system/capability/policy-entry", {
            "peer_pattern": initiator.identity_hash.hex(),
            "grants": [{"handlers": {"include": [path]}, "resources": {"include": ["*"]},
                        "operations": {"include": [op]}}],
        }),
    )
    return _call(responder, initiator, path, op)


def context_authority_chain__accepts_an_identity_in_the_chain() -> None:
    """SEC-3 accept: the session capability is granted BY the responder, so the responder's
    identity is a granter in its verified chain — and when the author IS that granter (a
    peer calling itself), the context's own method answers True."""
    _author_in, local_in, _zero = _chain_answers(0x71, 0x72)
    assert local_in is True, "the granting peer is in the chain"
    author_in_self, _, _ = _chain_answers(0x73, 0x73)
    assert author_in_self is True, "an author who granted the capability is in its chain"


def context_authority_chain__denies_an_identity_not_in_the_chain() -> None:
    """SEC-3 deny: a remote caller is the chain's GRANTEE, not a granter; and an unresolvable
    hash is never in chain."""
    author_in, local_in, zero_in = _chain_answers(0x74, 0x75)
    assert local_in is True, "control: the same capability does verify, with the granter in it"
    assert author_in is False, "the caller did not grant its own session capability"
    assert zero_in is False, "an unresolvable capability hash is never in chain"


# ── context.unforgeable ───────────────────────────────────────────────────────
def _captured_context() -> HandlerContext:
    """A context the dispatcher really built, captured from inside a body."""
    responder = Peer(_seed(0x76), open_grants=True)
    got: list[HandlerContext] = []

    def body(ctx: HandlerContext) -> Outcome:
        got.append(ctx)
        return _ok({"operation": ctx.operation, "pattern": ctx.pattern})

    responder.register_handler(HandlerSpec("app/ctx", "ctx", operations=["peek"]), body)
    status, res = _call(responder, Identity.of_seed(_seed(0x77)), "app/ctx", "peek")
    assert status == 200 and res is not None and res.field("pattern") == "app/ctx", (status, res)
    assert len(got) == 1
    return got[0]


def context_unforgeable__constructing_a_context_outside_the_dispatcher_is_refused() -> None:
    """The refusal, pinned to its stated reason: construction without the dispatcher's token
    raises ContextForgeryError naming the dispatcher — not a TypeError about arguments."""
    peer = Peer(_seed(0x78))
    kwargs = dict(
        peer=peer, envelope=None, exec_entity=Entity.make("primitive/any", {}), pattern="app/x",
        suffix="", caller_capability=None, handler_grant=None, conn=None, depth=0,
    )
    for token in (object(), None, "_DISPATCHER"):
        with pytest.raises(ContextForgeryError, match="constructed only by the peer's dispatcher"):
            HandlerContext(token, **kwargs)


def context_unforgeable__a_real_context_cannot_be_copied_pickled_or_mutated() -> None:
    """A body cannot mint a second context from the one it was handed, or rewrite it."""
    ctx = _captured_context()
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(ContextForgeryError):
            clone(ctx)
    with pytest.raises(ContextForgeryError):
        ctx._pattern = "system/tree"  # type: ignore[misc]
    assert ctx.pattern == "app/ctx", "unchanged"


def context_unforgeable__control_the_type_is_usable_outside_the_peer() -> None:
    """The control: the type is importable from the public package and a body outside the
    peer receives and reads a real one — so what refuses above is the constructor, not an
    import, a name, or a broken type."""
    assert HandlerContext is ExtensionHandlerContext
    ctx = _captured_context()
    assert isinstance(ctx, HandlerContext)
    assert (ctx.operation, ctx.pattern, ctx.suffix) == ("peek", "app/ctx", "")
    assert ctx.author is not None and ctx.caller_capability is not None and ctx.handler_grant is not None
