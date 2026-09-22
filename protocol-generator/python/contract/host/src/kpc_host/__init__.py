"""``kpc_host`` — the keystone peer contract host for the python peer.

``run_host(argv, install_fixtures)``.  Every fixture below is specified value-for-value in
``protocol-generator/shared/peer-contract/FIXTURE-HOST.md``, and the section numbers in the
comments are that document's.  The shared driver (``tools/peer-contract/driver``) measures
what these fixtures do; nothing here decides a verdict.

It imports only the peer's distribution (``entity_core``).  If a fixture needs something the
package does not expose, that is a contract finding about the peer, and the fix belongs in the
peer, not here.
"""

from __future__ import annotations

import os
import re
import sys
import threading
from importlib import metadata
from typing import Any

from entity_core.peer import (
    Entity,
    HandlerContext,
    HandlerSpec,
    OperationSpec,
    Outcome,
    Peer,
    RegisterError,
    check_path_permission,
    run_host,
)

HOST_DIST = "entity-core-protocol-python-contract-host"
PEER_DIST = "entity-core-protocol-python"


def _any(data: dict) -> Entity:
    return Entity.make("primitive/any", data)


def _ok(data: dict) -> Outcome:
    return Outcome.ok(_any(data))


def _param(ctx: HandlerContext, key: str) -> Any:
    p = ctx.params
    return p.field(key) if p is not None else None


def _text(ctx: HandlerContext, key: str) -> str:
    v = _param(ctx, key)
    return v if isinstance(v, str) else ""


def _hex(b: bytes | None) -> str:
    return bytes(b).hex() if b is not None else ""


def _status_code(out: Outcome) -> Outcome:
    return _ok({"status": out.status, "code": out.result.text("code") or ""})


def _put_request(entity: Entity) -> Entity:
    """A ``system/tree`` put request carrying the submitter-supplied content hash (§6.3)."""
    return Entity.make("system/tree/put-request", {"entity": entity.to_cbor()})


def _refusal(peer: Peer, spec: HandlerSpec) -> tuple[int, str]:
    try:
        peer.register_handler(spec, lambda ctx: _ok({}))
    except RegisterError as exc:
        return exc.status, exc.code
    # Installed when it must not have been: leave it installed (the driver sees it) and
    # report success, which the driver scores as a failure.
    return 200, ""


def _echo_evaluator(req: Any, _ctx: HandlerContext) -> Outcome | None:
    """§2.9 — answers ``contract/echo-expression`` AND ``compute/literal`` bodies, so a peer
    that asked it before its own literal floor would be visible."""
    if req.expression.type not in ("contract/echo-expression", "compute/literal"):
        return None
    return _ok({"evaluated_by": "contract-evaluator", "value": req.expression.field("value")})


def install_fixtures(peer: Peer) -> None:
    nonce = os.environ.get("KPC_NONCE")
    if not nonce:
        raise RuntimeError("KPC_NONCE is not set — the contract host is started by the contract driver")
    local = peer.local_peer

    # §2.1 witness.
    captured = f"{nonce}:app/contract/witness"
    peer.register_handler(
        HandlerSpec(
            "app/contract/witness", "witness",
            operations=[OperationSpec("echo", "primitive/any", "contract/witness-result")],
            types={"contract/witness-result": {"name": "contract/witness-result"}},
        ),
        lambda ctx: _ok({"witness": f"{captured}:{_text(ctx, 'echo')}"}),
    )
    collision = _refusal(peer, HandlerSpec("app/contract/witness", "again", operations=["echo"]))
    builtin = _refusal(peer, HandlerSpec("system/tree", "shadow", operations=["get"]))
    invalid = _refusal(peer, HandlerSpec("app//bad", "bad", operations=["echo"]))

    # §2.2 removable — the handle is kept.
    removable = peer.register_handler(
        HandlerSpec(
            "app/contract/removable", "removable", operations=["echo"],
            types={"contract/removable-type": {"name": "contract/removable-type"}},
        ),
        lambda ctx: _ok({"witness": "removable"}),
    )

    # §2.4 consumers, in order A, B (tree) then C (content).
    log: list[str] = []
    log_lock = threading.Lock()
    events_prefix = f"/{local}/app/contract/events/"

    def tree_consumer(tag: str):
        def consume(ev: Any) -> None:
            if ev.path.startswith(events_prefix):
                author = ev.context.author if ev.context is not None else None
                with log_lock:
                    log.append(f"{tag}|tree|{ev.path}|{_hex(author)}")
        return consume

    def content_consumer(ev: Any) -> None:
        if ev.entity.type == "contract/event-marker":
            with log_lock:
                log.append(f"C|content|{_hex(ev.hash)}|")

    peer.store.register_tree_consumer(tree_consumer("A"))
    consumer_b = peer.store.register_tree_consumer(tree_consumer("B"))
    peer.store.register_content_consumer(content_consumer)

    # §2.3 probe.
    def probe(ctx: HandlerContext) -> Outcome:
        op = ctx.operation
        if op == "install_report":
            return _ok({
                "collision_status": collision[0], "collision_code": collision[1],
                "builtin_collision_status": builtin[0], "builtin_collision_code": builtin[1],
                "invalid_status": invalid[0], "invalid_code": invalid[1],
            })
        if op == "close_removable":
            first = removable.close()
            second = removable.close()
            return _ok({"first": first, "second": second})
        if op == "events":
            with log_lock:
                return _ok({"log": list(log)})
        if op == "unregister_b":
            return _ok({"removed": peer.store.unregister_consumer(consumer_b)})
        return Outcome.err(501, "unsupported_operation", op)

    peer.register_handler(
        HandlerSpec("app/contract/probe", "probe",
                    operations=["install_report", "close_removable", "events", "unregister_b"]),
        probe,
    )

    # §2.5 granted / ungranted.
    def put_under_handler_grant(ctx: HandlerContext, target: str) -> Outcome:
        grant = ctx.handler_grant
        if grant is None:
            return _ok({"status": 403, "code": "capability_denied"})
        out = ctx.dispatch_execute(
            "system/tree", "put", _put_request(_any({"v": 1})), target=target, capability=grant,
        )
        return _status_code(out)

    scope = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": [f"/{local}/app/contract/scratch/*"]},
        "operations": {"include": ["put"]},
    }]
    peer.register_handler(
        HandlerSpec("app/contract/granted", "granted", operations=["put_inside", "put_outside"],
                    internal_scope=scope),
        lambda ctx: put_under_handler_grant(
            ctx,
            "app/contract/scratch/inside" if ctx.operation == "put_inside" else "app/contract/other/outside",
        ),
    )
    peer.register_handler(
        HandlerSpec("app/contract/ungranted", "ungranted", operations=["put_inside"]),
        lambda ctx: put_under_handler_grant(ctx, "app/contract/scratch/inside"),
    )

    # §2.6 context.
    def context(ctx: HandlerContext) -> Outcome:
        if ctx.operation == "budget":
            return _ok({"frame_budget": ctx.frame_budget()})
        cc, hg = ctx.caller_capability, ctx.handler_grant
        return _ok({
            "operation": ctx.operation,
            "pattern": ctx.pattern,
            "suffix": ctx.suffix,
            "author": _hex(ctx.author),
            "caller_capability": _hex(cc.hash) if cc is not None else "",
            "handler_grant": _hex(hg.hash) if hg is not None else "",
            "marker": _text(ctx, "marker"),
        })

    peer.register_handler(HandlerSpec("app/contract/context", "context", operations=["echo", "budget"]), context)

    # §2.7 dispatch.
    def dispatch(ctx: HandlerContext) -> Outcome:
        n = _param(ctx, "n")
        marker = Entity.make("contract/event-marker", {"n": n if n is not None else 0})
        out = ctx.dispatch_execute("system/tree", "put", _put_request(marker), target="app/contract/events/sub")
        return _status_code(out)

    peer.register_handler(HandlerSpec("app/contract/dispatch", "dispatch", operations=["put_as_caller"]), dispatch)

    # §2.8 authz.
    def authz(ctx: HandlerContext) -> Outcome:
        token = ctx.caller_capability
        allowed = token is not None and check_path_permission(
            _text(ctx, "operation"), _text(ctx, "path"), token, _text(ctx, "handler_pattern"), ctx.local_peer,
        )
        return _ok({"allowed": bool(allowed)})

    peer.register_handler(HandlerSpec("app/contract/authz", "authz", operations=["check"]), authz)

    # §2.10 data — the in-process data surface, which is the peer's own store.
    store = peer.store

    def item(marker: str) -> Entity:
        return Entity.make("contract/data-item", {"marker": marker})

    def absp(path: str) -> str:
        return f"/{local}/{path}"

    def found(e: Entity | None) -> Outcome:
        return _ok({
            "found": e is not None,
            "type": e.type if e is not None else "",
            "marker": (e.text("marker") or "") if e is not None else "",
            "hash": _hex(e.hash) if e is not None else "",
        })

    def data(ctx: HandlerContext) -> Outcome:
        op = ctx.operation
        if op == "put":
            e = item(_text(ctx, "marker"))
            return _ok({"hash": _hex(e.hash), "accepted": store.put_entity(e)})
        if op == "get":
            try:
                h = bytes.fromhex(_text(ctx, "hash"))
            except ValueError:
                return found(None)
            return found(store.get_by_hash(h))
        if op == "bind":
            e = item(_text(ctx, "marker"))
            accepted = store.bind(absp(_text(ctx, "path")), e, ctx.exec_context())
            return _ok({"hash": _hex(e.hash), "accepted": accepted})
        if op == "get_at":
            return found(store.get_at(absp(_text(ctx, "path"))))
        if op == "unbind":
            store.unbind(absp(_text(ctx, "path")), ctx.exec_context())
            return _ok({})
        if op == "forge":
            # Entity is a plain dataclass, so the forgery is constructible in python: the
            # forger's data under the victim's content hash.
            forged = Entity(type="contract/data-item", data={"marker": _text(ctx, "marker")},
                            hash=item(_text(ctx, "victim_marker")).hash)
            put_accepted = store.put_entity(forged)
            bind_accepted = store.bind(absp(_text(ctx, "path")), forged)
            return _ok({"constructible": True, "put_accepted": put_accepted, "bind_accepted": bind_accepted})
        return Outcome.err(501, "unsupported_operation", op)

    peer.register_handler(
        HandlerSpec("app/contract/data", "data", operations=["put", "get", "bind", "get_at", "unbind", "forge"]),
        data,
    )

    # §2.9 evaluator (MODULE).
    peer.set_expression_evaluator(_echo_evaluator)


def _requirement_name(req: str) -> str:
    return re.split(r"[\s;<>=!~\[(]", req.strip(), maxsplit=1)[0]


def announcement() -> dict:
    """``contract_host {package, depends_on}``, read from the INSTALLED distribution metadata —
    not restated here — and refused when this host or the peer it imports is running from a
    source tree rather than an installed distribution (a src-path run proves nothing about the
    package boundary)."""
    import entity_core
    import kpc_host

    host = metadata.distribution(HOST_DIST)
    peer = metadata.distribution(PEER_DIST)
    for mod, dist in ((kpc_host, host), (entity_core, peer)):
        root = os.path.realpath(str(dist.locate_file("")))
        if not os.path.realpath(mod.__file__).startswith(root + os.sep):
            raise RuntimeError(f"{mod.__name__} is imported from {mod.__file__}, not from the installed "
                               f"{dist.metadata['Name']} at {root}")
    depends = sorted({_requirement_name(r) for r in (host.requires or [])})
    return {"package": host.metadata["Name"], "depends_on": ",".join(depends)}


def main(argv: list[str] | None = None) -> int:
    try:
        announce = announcement()
    except (metadata.PackageNotFoundError, RuntimeError) as exc:
        print(f"kpc_host: error: {exc}", file=sys.stderr)
        return 1
    return run_host(sys.argv[1:] if argv is None else argv, install_fixtures,
                    extra_record_fields={"contract_host": announce})
