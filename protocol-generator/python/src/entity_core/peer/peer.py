"""Peer assembly: bootstrap (§6.9 / §6.9a), the four MUST system handlers (§6.2),
the §6.5 dispatch chain, §6.6 resolution, the §6.9a peer-authority + seed-policy
bootstrap, the §6.11 reentrant-outbound seam, and per-connection state.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .capability import (
    AUTHN_FAIL,
    AUTHZ_DENY,
    CHAIN_TOO_DEEP,
    UNRESOLVABLE_GRANTEE,
    cap_resolve,
    canonicalize,
    check_permission,
    extract_peer,
    normalize_uri,
    resolve_granter_peer_id,
    verify_request,
)
from .handlers import (
    CapabilityHandler,
    ConnectHandler,
    DispatchCtx,
    DispatchOutboundHandler,
    EchoHandler,
    HandlersHandler,
    Outcome,
    TreeHandler,
)
from .identity import Identity, peer_id_of_public_key, verify_signature
from .model import Entity, Envelope
from .store import Store
from .typedefs import core_type_entities
from .wire import error_result, make_execute, make_response


# ── per-connection state (§4.2) ───────────────────────────────────────────────
@dataclass(slots=True)
class Conn:
    established: bool = False
    issued_nonce: bytes | None = None
    hello_peer_id: str = ""
    outbound: Callable[[Envelope], "Envelope | None"] | None = None
    out_counter: int = 0


# ── grant construction (§4.4 / §5.4) ──────────────────────────────────────────
def _scope_cbor(incl: list[str], excl: list[str] | None = None) -> dict:
    d: dict[str, Any] = {"include": list(incl)}
    if excl:
        d["exclude"] = list(excl)
    return d


@dataclass(frozen=True, slots=True)
class GrantSpec:
    handlers: list[str]
    resources: list[str]
    operations: list[str]
    peers: list[str] | None = None

    def to_cbor(self) -> dict:
        d: dict[str, Any] = {
            "handlers": _scope_cbor(self.handlers),
            "resources": _scope_cbor(self.resources),
            "operations": _scope_cbor(self.operations),
        }
        if self.peers is not None:
            d["peers"] = _scope_cbor(self.peers)
        return d


def _grants_cbor(*specs: GrantSpec) -> list:
    return [gs.to_cbor() for gs in specs]


def _discovery_floor() -> list[GrantSpec]:
    return [
        GrantSpec(["system/tree"], ["system/type/*", "system/handler/*"], ["get"]),
        GrantSpec(["system/capability"], [], ["request"]),
    ]


def _open_grants_scope() -> list[GrantSpec]:
    return [GrantSpec(["*"], ["*", "/*/*"], ["*"], ["*"])]


class Peer:
    """A bootstrapped Entity Core peer."""

    def __init__(self, seed: bytes, *, open_grants: bool = False, conformance: bool = False) -> None:
        self.identity = Identity.of_seed(seed)
        self.store = Store()
        self.local_peer = self.identity.peer_id
        self.open_grants = open_grants
        self.conformance = conformance
        self.handlers: dict[str, Any] = {}
        self._bootstrap()

    # ── small utilities exposed to handlers ──────────────────────────────────
    @staticmethod
    def random_bytes(n: int) -> bytes:
        return os.urandom(n)

    @staticmethod
    def now_millis() -> int:
        return int(time.time() * 1000)

    # ── grants ───────────────────────────────────────────────────────────────
    def _owner_grants(self) -> list[GrantSpec]:
        return [GrantSpec(["*"], ["*"], ["*"], [self.local_peer])]

    # ── token mint (§4.4 / §6.9a) ────────────────────────────────────────────
    def mint_token(self, grantee_hash: bytes, grants: list, parent: bytes | None) -> tuple[Entity, Entity]:
        data: dict[str, Any] = {
            "granter": bytes(self.identity.identity_hash),
            "grantee": bytes(grantee_hash),
            "grants": grants,
            "created_at": self.now_millis(),
        }
        if parent is not None:
            data["parent"] = bytes(parent)
        token = Entity.make("system/capability/token", data)
        sig = self.identity.sign_entity(token)
        return token, sig

    # ── §6.9a seed policy (authenticate-time grant derivation) ───────────────
    def _seed_entry_grants(self, e: Entity) -> list | None:
        if e.type == "system/capability/token":
            sig_path = "/" + self.local_peer + "/system/signature/" + e.hash.hex()
            sgn = self.store.get_at(sig_path)
            if sgn is not None and verify_signature(sgn, self.identity.peer_entity):
                g = e.field("grants")
                if isinstance(g, list):
                    return g
        elif e.type == "system/capability/policy-entry":
            g = e.field("grants")
            if isinstance(g, list):
                return g
        return None

    def derive_seed_grants(self, remote_peer: Entity, remote_peer_id: str) -> list:
        """§6.9a dual-form lookup (hex -> Base58 -> default), UNION'd with the
        §4.4 discovery floor."""
        base = "/" + self.local_peer + "/system/capability/policy/"
        entry = None
        for key in (remote_peer.hash.hex(), remote_peer_id, "default"):
            e = self.store.get_at(base + key)
            if e is not None:
                entry = e
                break
        floor = _grants_cbor(*_discovery_floor())
        if entry is None:
            return floor
        policy_grants = self._seed_entry_grants(entry)
        if policy_grants is None:
            return floor
        return floor + policy_grants

    # ── §6.11 handler-facing outbound dispatch ───────────────────────────────
    def outbound_dispatch(
        self, c: Conn, uri: str, operation: str, params: Entity,
        capability: Entity, granter_peer: Entity, cap_sig: Entity, resource: Any,
    ) -> Envelope | None:
        if c.outbound is None:
            return None
        c.out_counter += 1
        request_id = "out-" + str(c.out_counter)
        exec_e = make_execute(
            request_id, uri, operation, params,
            author=self.identity.identity_hash,
            capability=capability.hash,
            resource=resource,
        )
        exec_sig = self.identity.sign_entity(exec_e)
        env = Envelope.of(exec_e, capability, granter_peer, self.identity.peer_entity, cap_sig, exec_sig)
        return c.outbound(env)

    # ── dispatcher-level signature ingestion (§6.5) ──────────────────────────
    def _ingest_signatures(self, env: Envelope) -> None:
        for e in list(env.included.values()):
            if e.type != "system/signature":
                continue
            self.store.put_entity(e)
            signer_h = e.bytes_("signer")
            if signer_h is None:
                continue
            signer_peer = env.included.get_by_hash(signer_h)
            if signer_peer is None:
                continue
            self.store.put_entity(signer_peer)
            target = e.bytes_("target")
            pk = signer_peer.bytes_("public_key")
            if target is not None and pk is not None:
                pid = peer_id_of_public_key(pk)
                self.store.bind("/" + pid + "/system/signature/" + target.hex(), e)

    # ── handler resolution (§6.6) — backward tree-walk ───────────────────────
    def _resolve_handler(self, path: str) -> str | None:
        segs = path.split("/")
        for i in range(len(segs), 0, -1):
            prefix = "/".join(segs[:i])
            e = self.store.get_at(prefix)
            if e is not None and e.type == "system/handler":
                return prefix
        return None

    def _strip_local(self, pattern: str) -> str:
        prefix = "/" + self.local_peer + "/"
        if pattern.startswith(prefix):
            return pattern[len(prefix):]
        return pattern

    # ── entity-native dispatch (§6.13(a)) ────────────────────────────────────
    def _entity_native_dispatch(self, handler_path: str) -> Outcome:
        he = self.store.get_at(handler_path)
        if he is None:
            return Outcome.err(404, "handler_not_found", handler_path)
        expr_path = he.text("expression_path")
        if expr_path is None:
            return Outcome.err(501, "no_handler_body", handler_path)
        abs_path = canonicalize(self.local_peer, expr_path) or expr_path
        expr = self.store.get_at(abs_path)
        if expr is None:
            return Outcome.err(404, "expression_not_found", abs_path)
        if expr.type == "compute/literal":
            value = expr.field("value")
            if value is not None:
                return Outcome.ok(Entity.make("compute/result", {
                    "value": value,
                    "expression": bytes(expr.hash),
                }))
            return Outcome.err(400, "unexpected_params", "compute/literal missing value")
        return Outcome.err(501, "unsupported_expression", expr.type)

    # ── dispatch chain (§6.5) ────────────────────────────────────────────────
    def dispatch(self, c: Conn, env: Envelope) -> Envelope | None:
        """Run the §6.5 dispatch chain.  Returns an EXECUTE_RESPONSE envelope, or
        None for a non-EXECUTE root (§3.3 server side ignores non-EXECUTE)."""
        exec_e = env.root
        if exec_e.type != "system/protocol/execute":
            return None
        request_id = exec_e.text("request_id") or ""
        uri = exec_e.text("uri") or ""
        oc = self._run_chain(c, env, exec_e, uri)
        resp = make_response(request_id, oc.status, oc.result)
        return Envelope.of(resp, *oc.included)

    def _run_chain(self, c: Conn, env: Envelope, exec_e: Entity, uri: str) -> Outcome:
        operation = exec_e.text("operation") or ""

        # The connect handler is reached pre-authentication (the handshake).
        if uri == "system/protocol/connect":
            h = self.handlers["system/protocol/connect"]
            return h.handle_op(operation, DispatchCtx(exec=exec_e, conn=c, included=env.included))

        self._ingest_signatures(env)

        verdict = verify_request(self.local_peer, self.store, env)
        if verdict == AUTHN_FAIL:
            return Outcome.err(401, "authentication_failed")
        if verdict == AUTHZ_DENY:
            return Outcome.err(403, "capability_denied")
        if verdict == CHAIN_TOO_DEEP:
            return Outcome.err(400, "chain_depth_exceeded")
        if verdict == UNRESOLVABLE_GRANTEE:
            return Outcome.err(401, "unresolvable_grantee")

        # ALLOW:
        path = canonicalize(self.local_peer, normalize_uri(uri))
        if path is None:
            return Outcome.err(400, "invalid_path", uri)
        if extract_peer(self.local_peer, path) != self.local_peer:
            return Outcome.err(404, "handler_not_found", "not local peer")
        pattern = self._resolve_handler(path)
        if pattern is None:
            return Outcome.err(404, "handler_not_found", path)
        cap_h = exec_e.bytes_("capability")
        caller_cap = env.included.get_by_hash(cap_h)
        if caller_cap is None:
            return Outcome.err(403, "capability_denied")
        resolve = cap_resolve(env.included, self.store)
        granter_peer = resolve_granter_peer_id(resolve, caller_cap) or self.local_peer
        if not check_permission(self.local_peer, granter_peer, exec_e, caller_cap, pattern):
            return Outcome.err(403, "capability_denied")
        stripped = self._strip_local(pattern)
        inst = self.handlers.get(stripped)
        if inst is not None:
            return inst.handle_op(operation, DispatchCtx(
                exec=exec_e, conn=c, included=env.included,
                caller_cap=caller_cap, has_cap=True,
            ))
        return self._entity_native_dispatch(pattern)

    # ── bootstrap (§6.9 / §6.9a) ─────────────────────────────────────────────
    _CORE_SPECS = [
        ("system/tree", "Tree", [("get", "", ""), ("put", "", "")], TreeHandler),
        ("system/handler", "Handlers", [
            ("register", "system/handler/register-request", "system/handler/register-result"),
            ("unregister", "system/handler/unregister-request", ""),
        ], HandlersHandler),
        ("system/capability", "Capability", [
            ("request", "system/capability/request", "system/capability/grant"),
            ("revoke", "system/capability/revoke-request", ""),
            ("configure", "system/capability/policy-entry", ""),
            ("delegate", "system/capability/delegate-request", "system/capability/grant"),
        ], CapabilityHandler),
        ("system/protocol/connect", "Connect", [("hello", "", ""), ("authenticate", "", "")], ConnectHandler),
    ]
    _CONFORMANCE_SPECS = [
        ("system/validate/echo", "validate-echo", [("echo", "", "")], EchoHandler),
        ("system/validate/dispatch-outbound", "validate-dispatch-outbound", [("dispatch", "", "")], DispatchOutboundHandler),
    ]

    def _op_spec_cbor(self, in_t: str, out_t: str) -> dict:
        d: dict[str, Any] = {}
        if in_t:
            d["input_type"] = in_t
        if out_t:
            d["output_type"] = out_t
        return d

    def _bootstrap_handler_entities(self, pattern: str, name: str, ops: list) -> None:
        local = self.local_peer
        op_map = {op: self._op_spec_cbor(in_t, out_t) for op, in_t, out_t in ops}
        self.store.bind("/" + local + "/" + pattern, Entity.make("system/handler", {
            "interface": "system/handler/" + pattern,
        }))
        self.store.bind("/" + local + "/system/handler/" + pattern, Entity.make("system/handler/interface", {
            "pattern": pattern,
            "name": name,
            "operations": op_map,
        }))
        token, _ = self.mint_token(self.identity.identity_hash, [], None)
        self.store.bind("/" + local + "/system/capability/grants/" + pattern, token)

    def _bootstrap(self) -> None:
        # local identity entity in the store (root-granter resolution).
        self.store.put_entity(self.identity.peer_entity)

        # MUST handlers + tree entities.
        for pattern, name, ops, cls in self._CORE_SPECS:
            self.handlers[pattern] = cls(self)
            self._bootstrap_handler_entities(pattern, name, ops)

        # §9.5 core type-registry floor (system/type/{name}).
        for tname, entity in core_type_entities():
            self.store.bind("/" + self.local_peer + "/system/type/" + tname, entity)

        # §6.9a Peer Authority Bootstrap: the self-owner capability (root cap,
        # full scope over /{peer_id}/*, grantee = own identity; §6.9a.0 detached-
        # sig shape: cap token at the hex policy path + its self-signature at the
        # §3.5 pointer) + the default scope-template entry.
        policy_base = "/" + self.local_peer + "/system/capability/policy/"
        owner_token, owner_sig = self.mint_token(
            self.identity.identity_hash, _grants_cbor(*self._owner_grants()), None
        )
        self.store.bind(policy_base + self.identity.identity_hash.hex(), owner_token)
        self.store.bind(
            "/" + self.local_peer + "/system/signature/" + owner_token.hash.hex(), owner_sig
        )

        if self.open_grants:
            default_grants = _grants_cbor(*_open_grants_scope())
        else:
            default_grants = _grants_cbor(*_discovery_floor())
        default_entry = Entity.make("system/capability/policy-entry", {
            "peer_pattern": "default",
            "grants": default_grants,
        })
        self.store.bind(policy_base + "default", default_entry)

        # §7a conformance handlers — only under --validate.
        if self.conformance:
            for pattern, name, ops, cls in self._CONFORMANCE_SPECS:
                self.handlers[pattern] = cls(self)
                self._bootstrap_handler_entities(pattern, name, ops)
