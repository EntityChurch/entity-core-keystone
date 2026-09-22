"""H6 — the §4.10(a) frame budget IN FORCE for a request is readable by a handler body.

The keystone host contract's H6: a handler body that must size a response against the
connection's inbound bound has to be able to *read* that bound.  Before this, python's
bound was ``wire.MAX_FRAME`` — a module constant equal to the exact 16 MiB literal
``EXTENSION-CONTENT`` v3.6 Amendment 1 names as the wrong answer — so a body could only
hardcode it, and a peer constructed with any other bound would have been lied to.

Four checks, and the third is the one that makes the accessor mean anything:

  1. a body reaches the budget through ``ctx.frame_budget()`` over a real dispatch, and
     the value is the peer's CONFIGURED bound, not the module default;
  2. an unconfigured peer still reads the informative 16 MiB default, so nothing moved
     for a peer that never asked;
  3. the value READ is the value ENFORCED — a frame over the configured bound is refused
     on a peer that configured it and accepted on one that did not.  An accessor that
     can disagree with the enforcer is worse than no accessor;
  4. off the serving path (no connection, so no frame at all) the fallback is the peer's
     configured value, not the literal.

Two plants, both run, and they redden DISJOINT checks — which is what says the accessor
arm and the enforcer arm are independently measured rather than one being carried by the
other:

  * ``DispatchCtx.frame_budget`` returns ``MAX_FRAME`` (the hardcoded-literal defect) ->
    **1 and 4 RED**, 2 and 3 green;
  * ``read_frame`` called without the connection's bound (the enforcer ignores it) ->
    **3 RED**, 1, 2 and 4 green.

Predicted "1 and 3" before running; that was wrong, and the correction is the point —
check 3 never touches the accessor.
"""

from __future__ import annotations

import socket
import struct

from entity_core.peer import (
    Identity,
    MAX_FRAME,
    Peer,
    dial,
    listen,
    resource_target,
    response_result,
    response_status,
)
from entity_core.peer.handlers import DispatchCtx, Outcome
from entity_core.peer.model import Entity

#: Deliberately not 16 MiB, and small enough to drive the enforcement differential in
#: check 3 without moving real bytes.
CONFIGURED_BOUND = 512 * 1024


def _fixed_seed(b: int) -> bytes:
    return bytes([b] * 32)


class _BudgetProbe:
    """A language-native handler body that answers with the budget it was handed.

    This is the shape the generator's install adapter binds: an object with
    ``handle_op(operation, ctx)`` placed in ``peer.handlers[pattern]`` after the
    §11.6.1 entities exist in the tree.
    """

    def __init__(self) -> None:
        self.seen: list[int] = []

    def handle_op(self, operation: str, ctx: DispatchCtx) -> Outcome:
        budget = ctx.frame_budget()
        self.seen.append(budget)
        return Outcome.ok(Entity.make("primitive/any", {"budget": budget}))


def _install(peer: Peer, initiator: Identity, cc, pattern: str, body: object) -> None:
    """Write the §11.6.1 entities over the wire, then bind the native body.

    The pattern is deliberately outside ``system/*``: the wire register op refuses
    reserved patterns (§6.2), which is why an extension owning a system-namespace
    pattern is a build-time composition rather than a remote install.
    """
    req = Entity.make("system/handler/register-request", {
        "manifest": {"name": pattern, "operations": {"budget": {}}},
    })
    r = cc.execute(
        initiator, "/" + cc.remote_peer_id + "/system/handler", "register", req,
        resource_target("system/handler/" + pattern),
    )
    assert r is not None and response_status(r) == 200, "handler register -> 200"
    peer.handlers[pattern] = body


def _budget_over_the_wire(max_frame_bytes: int | None, seed: int) -> int:
    """Dispatch to an installed body and return the budget it read."""
    kwargs = {} if max_frame_bytes is None else {"max_frame_bytes": max_frame_bytes}
    responder = Peer(_fixed_seed(seed), open_grants=True, conformance=True, **kwargs)
    initiator = Identity.of_seed(_fixed_seed(seed + 1))
    body = _BudgetProbe()
    ln = listen(responder, 0)
    try:
        cc = dial("127.0.0.1", ln.port)
        try:
            cc.handshake(initiator)
            _install(responder, initiator, cc, "demo/budget", body)
            r = cc.execute(
                initiator, "/" + cc.remote_peer_id + "/demo/budget", "budget",
                Entity.make("primitive/any", {}),
            )
            assert r is not None and response_status(r) == 200, "installed body -> 200"
            res = response_result(r)
            assert res is not None, "installed body returned a result"
            reported = res.field("budget")
            assert isinstance(reported, int), "body reported an integer budget"
            # The body's own record and the wire answer must agree — a body that never
            # ran cannot have appended, so this also proves dispatch reached it.
            assert body.seen == [reported], "the body ran once and reported what it read"
            return reported
        finally:
            cc.close()
    finally:
        ln.close()


def test_body_reads_the_configured_bound_not_the_module_default():
    """(1) H6 over a real dispatch, on a peer configured away from the default."""
    reported = _budget_over_the_wire(CONFIGURED_BOUND, 0x51)
    assert reported == CONFIGURED_BOUND, \
        f"body reads the bound in force ({reported} != {CONFIGURED_BOUND})"
    assert reported != MAX_FRAME, \
        "the value is the configured bound, not the 16 MiB module constant"


def test_unconfigured_peer_still_reads_the_informative_default():
    """(2) Nothing moved for a peer that never asked for a bound."""
    assert Peer(_fixed_seed(0x53)).max_frame_bytes == MAX_FRAME, \
        "an unconfigured peer keeps the §4.10(a) informative default"
    assert _budget_over_the_wire(None, 0x55) == MAX_FRAME, \
        "and a body on it reads that same default"


def _frame_header_over_bound_is_refused(max_frame_bytes: int | None, seed: int):
    """Send a length prefix of ``CONFIGURED_BOUND + 1`` and no body.

    Returns ``(status, code)`` of the coded refusal the peer put on the wire, or
    ``None`` if it is still waiting for the body (i.e. the length is within its bound).

    THIS USED TO RETURN "did the peer close with nothing", and that was the right
    assertion right up until 0.8.2.25.  §4.10(a) then went SHOULD -> MUST (N14) and
    §4.11 made the coded frame mandatory for the whole pre-admission class, so a bare
    close is now one of the two named non-conformant behaviours — "indistinguishable
    from a network fault", and on a multiplexed connection it destroys unrelated
    ADMITTED requests.  The check is STRENGTHENED rather than relaxed: it asserted a
    close and now asserts the frame, its status AND its code, and the close after it.
    """
    from entity_core.peer.wire import envelope_of_frame, read_frame

    kwargs = {} if max_frame_bytes is None else {"max_frame_bytes": max_frame_bytes}
    responder = Peer(_fixed_seed(seed), **kwargs)
    ln = listen(responder, 0)
    try:
        s = socket.create_connection(("127.0.0.1", ln.port))
        try:
            s.sendall(struct.pack(">I", CONFIGURED_BOUND + 1))
            s.settimeout(2.0)
            try:
                env = envelope_of_frame(read_frame(s))
            except (socket.timeout, TimeoutError):
                return None  # still parked waiting for the body: within the bound
            result = response_result(env)
            return response_status(env), (result.text("code") if result else "")
        finally:
            s.close()
    finally:
        ln.close()


def test_the_budget_read_is_the_budget_enforced():
    """(3) The differential: the same header is refused at the configured bound and
    accepted at the default.  Without both arms this proves nothing — a peer that
    refused everything would pass the first half."""
    assert _frame_header_over_bound_is_refused(CONFIGURED_BOUND, 0x57) == (
        413, "payload_too_large"
    ), "a frame over the configured bound is refused before its body is buffered"
    assert _frame_header_over_bound_is_refused(None, 0x59) is None, \
        "the same frame is within an unconfigured peer's 16 MiB bound (the control)"


def test_off_the_serving_path_the_fallback_is_the_peer_value():
    """(4) No connection means no frame; the answer is still not the module literal."""
    ctx = DispatchCtx(
        exec=Entity.make("primitive/any", {}), conn=None, included={},
        peer_max_frame=CONFIGURED_BOUND,
    )
    assert ctx.frame_budget() == CONFIGURED_BOUND, \
        "a context with no connection falls back to the peer's value, not to MAX_FRAME"
