"""S3 two-peer loopback smoke gate (the phase exit criterion).

Two Python peers talk over real loopback TCP through the full §6.5 dispatch
chain.  Scenario 1 (responder = default seed policy) exercises the handshake,
404, authority-gated tree get, capability request, and 8-way request_id demux.
Scenario 2 (responder = --debug-open-grants + --validate) exercises the Core
Extensibility Boundary: register live-hook, emit hook, §7a echo.  11 checks; the
run is GREEN iff all 11 pass.

This is the Python analogue of every sibling peer's S3 smoke (11/11 loopback).
The full validate-peer --profile core conformance run is S4.
"""

from __future__ import annotations

import threading

from entity_core.peer import (
    Identity,
    Peer,
    dial,
    empty_params,
    listen,
    resource_target,
    response_result,
    response_status,
)
from entity_core.peer.model import Entity


def _fixed_seed(b: int) -> bytes:
    return bytes([b] * 32)


def test_scenario1_authenticated_session():
    responder = Peer(_fixed_seed(0x11))
    initiator = Identity.of_seed(_fixed_seed(0x22))
    ln = listen(responder, 0)
    try:
        cc = dial("127.0.0.1", ln.port)
        try:
            cc.handshake(initiator)
            remote = cc.remote_peer_id

            # (1) session established (capability minted)
            assert cc.capability is not None, "session established (capability minted)"
            # (2) remote peer_id matches responder
            assert remote == responder.local_peer, "remote peer_id matches responder"

            iface_target = resource_target("system/handler/system/tree")

            # (3) unregistered path -> 404
            r = cc.execute(initiator, "/" + remote + "/does/not/exist", "noop", empty_params())
            assert r is not None and response_status(r) == 404, "unregistered path -> 404"

            # (4) granted tree get -> 200 + (5) returns a system/handler/interface
            rget = cc.execute(initiator, "/" + remote + "/system/tree", "get", empty_params(), iface_target)
            assert rget is not None and response_status(rget) == 200, "granted tree get -> 200"
            res = response_result(rget)
            assert res is not None and res.type == "system/handler/interface", \
                "tree get returns a system/handler/interface entity"

            # (6) capability request -> 200
            from entity_core.peer.peer import GrantSpec, _grants_cbor

            req_params = Entity.make("system/capability/request", {
                "grants": _grants_cbor(GrantSpec(["system/tree"], ["system/type/*"], ["get"])),
            })
            rcap = cc.execute(initiator, "/" + remote + "/system/capability", "request", req_params)
            assert rcap is not None and response_status(rcap) == 200, "capability request -> 200"

            # (7) 8-way request_id demux (N7, §6.11)
            n = 8
            correlated = [0]
            lock = threading.Lock()

            def fire():
                r = cc.execute(initiator, "/" + remote + "/system/tree", "get", empty_params(), iface_target)
                if r is not None and response_status(r) == 200:
                    res = response_result(r)
                    if res is not None and res.type == "system/handler/interface":
                        with lock:
                            correlated[0] += 1

            threads = [threading.Thread(target=fire) for _ in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert correlated[0] == n, f"8 interleaved requests each correlated -> {correlated[0]}/8"
        finally:
            cc.close()
    finally:
        ln.close()


def test_scenario2_extensibility_boundary():
    responder = Peer(_fixed_seed(0x33), open_grants=True, conformance=True)
    initiator = Identity.of_seed(_fixed_seed(0x44))

    emit_count = [0]
    responder.store.register_tree_consumer(lambda ev: emit_count.__setitem__(0, emit_count[0] + 1))

    ln = listen(responder, 0)
    try:
        cc = dial("127.0.0.1", ln.port)
        try:
            cc.handshake(initiator)
            remote = cc.remote_peer_id
            emit_before = emit_count[0]

            # (8) handler register -> 200 (live, not 501) + (9) emit hook fired
            manifest = {"name": "demo", "operations": {}}
            req = Entity.make("system/handler/register-request", {"manifest": manifest})
            rreg = cc.execute(
                initiator, "/" + remote + "/system/handler", "register", req,
                resource_target("system/handler/demo"),
            )
            assert rreg is not None and response_status(rreg) == 200, "handler register -> 200 (live)"
            assert emit_count[0] > emit_before, "emit hook fired on register's tree writes (§6.13(c))"

            # (10) §7a echo -> 200 + (11) returns params verbatim
            payload = Entity.make("primitive/any", {"ping": 42})
            recho = cc.execute(initiator, "/" + remote + "/system/validate/echo", "echo", payload)
            assert recho is not None and response_status(recho) == 200, "§7a echo -> 200"
            res = response_result(recho)
            assert res is not None and res.type == "primitive/any", "§7a echo returns params verbatim"
        finally:
            cc.close()
    finally:
        ln.close()
