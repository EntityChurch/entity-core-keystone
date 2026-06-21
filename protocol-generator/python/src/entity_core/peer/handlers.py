"""The four MUST system handlers (connect / tree / capability / handlers) + the
§7a conformance handlers (echo / dispatch-outbound).

Dispatch idiom: each handler is a class with a ``handle_op(op, ctx)`` method
whose per-operation ``if/elif`` ladder is the idiomatic Python single-dispatch
(contrast the Go method-table / the Common-Lisp CLOS multiple dispatch).  An
unknown operation falls to the default 501 arm.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .capability import (
    GrantRec,
    _grant_subset,
    _grants_of_token,
    canonicalize,
    is_peer_id,
)
from .identity import verify_signature
from .model import Entity
from .wire import (
    empty_params,
    error_result,
    resource_target,
)


def op501(op: str) -> "Outcome":
    return Outcome.err(501, "unsupported_operation", op)


# ── handler result + dispatch context ─────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class Outcome:
    """A handler result: a status, a result entity, and included entities."""

    status: int
    result: Entity
    included: tuple[Entity, ...] = ()

    @staticmethod
    def ok(result: Entity, *included: Entity) -> "Outcome":
        return Outcome(200, result, tuple(included))

    @staticmethod
    def err(status: int, code: str, message: str = "") -> "Outcome":
        return Outcome(status, error_result(code, message))


@dataclass(slots=True)
class DispatchCtx:
    """The §6.6 HandlerContext threaded into a handler."""

    exec: Entity
    conn: Any
    included: dict
    caller_cap: Entity | None = None
    has_cap: bool = False


def _params_entity(exec_e: Entity) -> Entity | None:
    return exec_e.sub_entity("params")


def _str_array(exec_e: Entity, key: str) -> list[str] | None:
    params = _params_entity(exec_e)
    if params is None:
        return None
    v = params.field(key)
    if not isinstance(v, list):
        return None
    return [x for x in v if isinstance(x, str)]


def _exec_resource_target(exec_e: Entity) -> str | None:
    r = exec_e.field("resource")
    if not isinstance(r, dict):
        return None
    targets = r.get("targets")
    if not isinstance(targets, list) or not targets or not isinstance(targets[0], str):
        return None
    return targets[0]


def _path_flex_ok(target: str) -> bool:
    """Validate a caller-supplied resource target (§1.4 / §5.4)."""
    if "\x00" in target:
        return False
    segs = target.split("/")
    if target.startswith("/"):
        # segs[0] == "" ; segs[1] must be a peer-id
        if len(segs) >= 2 and segs[0] == "":
            if not is_peer_id(segs[1]):
                return False
            body = segs[1:]
        else:
            return False
    else:
        body = segs
    if body and body[-1] == "":
        body = body[:-1]
    for s in body:
        if s in ("", ".", ".."):
            return False
    return True


def _all_hex_lower(s: str) -> bool:
    return all(c in "0123456789abcdef" for c in s)


# ── connect handler (§4.1, §4.6) ──────────────────────────────────────────────
class ConnectHandler:
    def __init__(self, p) -> None:
        self.p = p

    def handle_op(self, op: str, ctx: DispatchCtx) -> Outcome:
        if op == "hello":
            return self._hello(ctx)
        if op == "authenticate":
            return self._authenticate(ctx)
        return op501(op)

    def _hello(self, ctx: DispatchCtx) -> Outcome:
        p, c, exec_e = self.p, ctx.conn, ctx.exec
        if c.established:
            return Outcome.err(409, "connection_already_established")
        f = _str_array(exec_e, "hash_formats")
        if f is not None and "ecfv1-sha256" not in f:
            return Outcome.err(400, "incompatible_hash_format")
        k = _str_array(exec_e, "key_types")
        if k is not None and "ed25519" not in k:
            return Outcome.err(400, "unsupported_key_type")
        params = _params_entity(exec_e)
        if params is not None:
            c.hello_peer_id = params.text("peer_id") or ""
        nonce = p.random_bytes(32)
        c.issued_nonce = nonce
        return Outcome.ok(Entity.make("system/protocol/connect/hello", {
            "peer_id": p.local_peer,
            "nonce": nonce,
            "protocols": ["entity-core/1.0"],
            "timestamp": p.now_millis(),
            "hash_formats": ["ecfv1-sha256"],
            "key_types": ["ed25519"],
        }))

    def _authenticate(self, ctx: DispatchCtx) -> Outcome:
        p, c, exec_e = self.p, ctx.conn, ctx.exec
        if c.established:
            return Outcome.err(409, "connection_already_established")
        if c.issued_nonce is None:
            return Outcome.err(401, "invalid_nonce")  # authenticate before hello
        auth = _params_entity(exec_e)
        if auth is None:
            return Outcome.err(401, "authentication_failed")
        kt = auth.text("key_type")
        if kt is not None and kt != "ed25519":
            return Outcome.err(400, "unsupported_key_type")
        pub = auth.bytes_("public_key")
        if pub is not None and len(pub) != 32:
            return Outcome.err(400, "unsupported_key_type")
        echoed = auth.bytes_("nonce")
        claimed = auth.text("peer_id") or ""
        # §4.6 / §7.1 crypto-agility: a peer_id whose embedded key_type is not
        # Ed25519 (e.g. an unknown 0xFD) is an unsupported algorithm, not an
        # identity mismatch — reject 400 unsupported_key_type BEFORE the identity
        # binding (AGILITY-UNKNOWN-1).
        if claimed:
            from .identity import KEY_TYPE_ED25519
            from ..peer_id import parse_peer_id

            try:
                parts = parse_peer_id(claimed)
            except Exception:  # noqa: BLE001
                parts = None
            if parts is not None and parts.key_type != KEY_TYPE_ED25519:
                return Outcome.err(400, "unsupported_key_type")
        if echoed != c.issued_nonce:
            return Outcome.err(401, "invalid_nonce")
        if pub is None:
            return Outcome.err(401, "authentication_failed")
        # proof of possession
        sgn = _find_sig(auth.hash, ctx.included)
        sig_ok = False
        if sgn is not None:
            sb = sgn.bytes_("signature")
            if sb is not None:
                from ..signature import verify_ed25519

                sig_ok = verify_ed25519(pub, sb, auth.hash)
        if not sig_ok:
            return Outcome.err(401, "authentication_failed")
        # identity binding
        from .identity import peer_id_of_public_key

        if claimed == "" or claimed != peer_id_of_public_key(pub):
            return Outcome.err(401, "identity_mismatch")
        if c.hello_peer_id and c.hello_peer_id != claimed:
            return Outcome.err(401, "identity_mismatch")
        # success: mint the §4.4 / §6.9a initial capability for the remote.
        from .identity import peer_entity_of_public_key

        remote_peer = peer_entity_of_public_key(pub)
        grants = p.derive_seed_grants(remote_peer, claimed)
        token, sig = p.mint_token(remote_peer.hash, grants, None)
        c.established = True
        return Outcome.ok(
            Entity.make("system/capability/grant", {"token": bytes(token.hash)}),
            token,
            p.identity.peer_entity,
            sig,
        )


def _find_sig(target: bytes, included: dict) -> Entity | None:
    from .capability import find_signature

    return find_signature(target, included)


# ── tree handler (§6.3) ───────────────────────────────────────────────────────
class TreeHandler:
    def __init__(self, p) -> None:
        self.p = p

    def handle_op(self, op: str, ctx: DispatchCtx) -> Outcome:
        if op == "get":
            return self._get(ctx)
        if op == "put":
            return self._put(ctx)
        return op501(op)

    def _is_deletion_marker(self, hex_hash: str) -> bool:
        try:
            raw = bytes.fromhex(hex_hash)
        except ValueError:
            return False
        e = self.p.store.get_by_hash(raw)
        return e is not None and e.type == "system/deletion-marker"

    def _build_listing(self, path: str) -> Outcome:
        rows = self.p.store.listing(path)
        entries: dict[str, Any] = {}
        count = 0
        for row in rows:
            if row.hash and not row.has_children and self._is_deletion_marker(row.hash):
                continue
            if row.hash:
                data = {"has_children": row.has_children, "hash": bytes.fromhex(row.hash)}
            else:
                data = {"has_children": row.has_children}
            entries[row.segment] = Entity.make("system/tree/listing-entry", data).to_cbor()
            count += 1
        return Outcome.ok(Entity.make("system/tree/listing", {
            "path": path,
            "entries": entries,
            "count": count,
            "offset": 0,
        }))

    def _get(self, ctx: DispatchCtx) -> Outcome:
        p, exec_e = self.p, ctx.exec
        target = _exec_resource_target(exec_e)
        if target is not None and not _path_flex_ok(target):
            return Outcome.err(400, "invalid_path", target)
        if target is None:
            return self._build_listing("/" + p.local_peer + "/")
        if target == "" or target.endswith("/"):
            c = canonicalize(p.local_peer, target) or target
            return self._build_listing(c)
        path = canonicalize(p.local_peer, target)
        if path is None:
            return Outcome.err(400, "invalid_path", target)
        e = p.store.get_at(path)
        if e is None:
            return Outcome.err(404, "not_found", path)
        params = _params_entity(exec_e)
        mode = params.text("mode") if params is not None else None
        if mode == "hash":
            return Outcome.ok(Entity.make("system/hash", {"hash": bytes(e.hash)}))
        return Outcome.ok(e)

    def _put(self, ctx: DispatchCtx) -> Outcome:
        p, exec_e = self.p, ctx.exec
        target = _exec_resource_target(exec_e)
        if target is None:
            return Outcome.err(400, "ambiguous_resource", "tree: missing resource target")
        if not _path_flex_ok(target):
            return Outcome.err(400, "invalid_path", target)
        path = canonicalize(p.local_peer, target)
        params = _params_entity(exec_e)
        entity = params.sub_entity("entity") if params is not None else None
        expected = params.bytes_("expected_hash") if params is not None else None
        current = p.store.hash_at(path)
        cas_ok = True
        if expected is not None:
            if expected == bytes(33):
                cas_ok = current == ""
            else:
                cas_ok = current != "" and current == expected.hex()
        if not cas_ok:
            return Outcome.err(409, "hash_mismatch", path)
        if entity is None:
            return Outcome.err(400, "unexpected_params", "put: missing entity")
        p.store.bind(path, entity)
        return Outcome.ok(Entity.make("system/hash", {"hash": bytes(entity.hash)}))


# ── capability handler (§6.2) ─────────────────────────────────────────────────
class CapabilityHandler:
    def __init__(self, p) -> None:
        self.p = p

    def handle_op(self, op: str, ctx: DispatchCtx) -> Outcome:
        if op == "request":
            return self._request(ctx)
        if op == "delegate":
            return self._delegate(ctx)
        if op == "revoke":
            return self._revoke(ctx)
        if op == "configure":
            return self._configure(ctx)
        return op501(op)

    def _req_grants(self, params: Entity | None) -> list:
        if params is not None:
            g = params.field("grants")
            if isinstance(g, list):
                return g
        return []

    def _mint_bounded(self, ctx: DispatchCtx, req_grants: list, grantee_hash, parent) -> Outcome:
        p = self.p
        bounded = False
        if ctx.has_cap and ctx.caller_cap is not None:
            parent_grants = _grants_of_token(ctx.caller_cap)
            bounded = True
            for cg in req_grants:
                c = GrantRec(cg)
                hit = any(
                    _grant_subset(p.local_peer, p.local_peer, p.local_peer, c, pg)
                    for pg in parent_grants
                )
                if not hit:
                    bounded = False
                    break
        if not bounded:
            return Outcome.err(403, "scope_exceeds_authority")
        token, sig = p.mint_token(grantee_hash, req_grants, parent)
        return Outcome.ok(
            Entity.make("system/capability/grant", {"token": bytes(token.hash)}),
            token,
            p.identity.peer_entity,
            sig,
        )

    def _request(self, ctx: DispatchCtx) -> Outcome:
        exec_e = ctx.exec
        params = _params_entity(exec_e)
        author = exec_e.bytes_("author")
        if author is None:
            return Outcome.err(403, "capability_denied")
        return self._mint_bounded(ctx, self._req_grants(params), author, None)

    def _delegate(self, ctx: DispatchCtx) -> Outcome:
        p, exec_e = self.p, ctx.exec
        params = _params_entity(exec_e)
        author = exec_e.bytes_("author")
        ph = params.bytes_("parent") if params is not None else None
        if ph is None:
            return Outcome.err(400, "unexpected_params", "delegate: parent required")
        if ph == bytes(len(ph)):
            return Outcome.err(400, "unexpected_params", "delegate: zero parent")
        if author != p.identity.identity_hash:
            return Outcome.err(501, "unsupported_operation", "delegate: same-peer-only in v1")
        return self._mint_bounded(ctx, self._req_grants(params), author, ph)

    def _revoke(self, ctx: DispatchCtx) -> Outcome:
        p, exec_e = self.p, ctx.exec
        params = _params_entity(exec_e)
        token_h = params.bytes_("token") if params is not None else None
        if token_h is None:
            return Outcome.err(400, "unexpected_params", "revoke: missing token")
        if token_h == bytes(len(token_h)):
            return Outcome.err(400, "unexpected_params", "revoke: zero token")
        marker = Entity.make("system/capability/revocation", {
            "token": bytes(token_h),
            "revoked_at": p.now_millis(),
        })
        p.store.bind(
            "/" + p.local_peer + "/system/capability/revocations/" + token_h.hex(), marker
        )
        return Outcome.ok(empty_params())

    def _configure(self, ctx: DispatchCtx) -> Outcome:
        p, exec_e = self.p, ctx.exec
        params = _params_entity(exec_e)
        pp = params.text("peer_pattern") if params is not None else None
        if pp is None:
            return Outcome.err(400, "unexpected_params", "configure: missing peer_pattern")
        is_hex = len(pp) == 66 and _all_hex_lower(pp)
        if pp != "default" and not is_hex and not is_peer_id(pp):
            return Outcome.err(400, "invalid_peer_pattern", pp)
        p.store.bind("/" + p.local_peer + "/system/capability/policy/" + pp, params)
        return Outcome.ok(empty_params())


# ── handlers handler (§6.2 / §6.13(a)) — register/unregister ──────────────────
class HandlersHandler:
    def __init__(self, p) -> None:
        self.p = p

    def handle_op(self, op: str, ctx: DispatchCtx) -> Outcome:
        if op == "register":
            return self._register(ctx)
        if op == "unregister":
            return self._unregister(ctx)
        return op501(op)

    def _register_pattern(self, exec_e: Entity) -> tuple[str | None, Outcome | None]:
        target = _exec_resource_target(exec_e)
        if target is None:
            return None, Outcome.err(
                400, "ambiguous_resource", "register/unregister require one resource target"
            )
        prefix = "system/handler/"
        if not target.startswith(prefix) or len(target) == len(prefix):
            return None, Outcome.err(
                400, "invalid_resource", "resource target MUST be system/handler/{pattern}"
            )
        return target[len(prefix):], None

    def _register(self, ctx: DispatchCtx) -> Outcome:
        p, exec_e = self.p, ctx.exec
        pattern, bad = self._register_pattern(exec_e)
        if bad is not None:
            return bad
        req = _params_entity(exec_e)
        if req is None:
            return Outcome.err(400, "unexpected_params", "register: missing params")
        if req.type != "system/handler/register-request":
            return Outcome.err(
                400, "unexpected_params", "register expects register-request, got " + req.type
            )

        def absp(rel: str) -> str:
            return "/" + p.local_peer + "/" + rel

        interface_rel = "system/handler/" + pattern
        manifest = req.field("manifest")
        manifest = manifest if isinstance(manifest, dict) else {}
        name = pattern
        if isinstance(manifest.get("name"), str):
            name = manifest["name"]
        operations = manifest.get("operations") if isinstance(manifest.get("operations"), dict) else {}
        expr_path = manifest.get("expression_path")
        internal_scope = manifest.get("internal_scope")

        grant_scope: list = []
        rs = req.field("requested_scope")
        if isinstance(rs, list):
            grant_scope = rs
        elif isinstance(internal_scope, list):
            grant_scope = internal_scope

        # (1) handler manifest at the pattern path.
        handler_data: dict[str, Any] = {"interface": interface_rel}
        if isinstance(expr_path, str):
            handler_data["expression_path"] = expr_path
        if internal_scope is not None:
            handler_data["internal_scope"] = internal_scope
        p.store.bind(absp(pattern), Entity.make("system/handler", handler_data))

        # (2) associated types at system/type/{type_name}.
        types = req.field("types")
        if isinstance(types, dict):
            for tname, tval in types.items():
                if not isinstance(tname, str):
                    continue
                data = tval if isinstance(tval, dict) else {"def": tval}
                p.store.bind(absp("system/type/" + tname), Entity.make("system/type", data))

        # (3)+(4) self-issued signed handler grant + signature at §3.5.
        token, sig = p.mint_token(p.identity.identity_hash, grant_scope, None)
        p.store.bind(absp("system/capability/grants/" + pattern), token)
        p.store.bind(absp("system/signature/" + token.hash.hex()), sig)

        # (5) handler interface entity (discovery index).
        p.store.bind(absp(interface_rel), Entity.make("system/handler/interface", {
            "pattern": pattern,
            "name": name,
            "operations": operations,
        }))

        return Outcome.ok(Entity.make("system/handler/register-result", {
            "pattern": pattern,
            "grant": token.data,
        }))

    def _unregister(self, ctx: DispatchCtx) -> Outcome:
        p, exec_e = self.p, ctx.exec
        pattern, bad = self._register_pattern(exec_e)
        if bad is not None:
            return bad

        def absp(rel: str) -> str:
            return "/" + p.local_peer + "/" + rel

        g = p.store.get_at(absp("system/capability/grants/" + pattern))
        if g is not None:
            p.store.unbind(absp("system/signature/" + g.hash.hex()))
            p.store.unbind(absp("system/capability/grants/" + pattern))
        p.store.unbind(absp(pattern))
        p.store.unbind(absp("system/handler/" + pattern))
        return Outcome.ok(empty_params())


# ── §7a conformance handlers (system/validate namespace) ──────────────────────
class EchoHandler:
    def __init__(self, p) -> None:
        self.p = p

    def handle_op(self, op: str, ctx: DispatchCtx) -> Outcome:
        if op != "echo":
            return op501(op)
        params = _params_entity(ctx.exec)
        if params is None:
            return Outcome.err(400, "invalid_params", "echo requires a params entity")
        return Outcome.ok(params)


class DispatchOutboundHandler:
    def __init__(self, p) -> None:
        self.p = p

    def handle_op(self, op: str, ctx: DispatchCtx) -> Outcome:
        if op != "dispatch":
            return op501(op)
        p = self.p
        params = _params_entity(ctx.exec)
        if params is None:
            return Outcome.err(400, "invalid_params", "dispatch-outbound requires params")
        target = params.text("target") or ""
        operation = params.text("operation") or ""
        value = params.field("value")
        capability = params.sub_entity("reentry_capability")
        granter_peer = params.sub_entity("reentry_granter")
        cap_sig = params.sub_entity("reentry_cap_signature")
        if value is None or capability is None or granter_peer is None or cap_sig is None:
            return Outcome.err(400, "invalid_params", "dispatch-outbound needs value + reentry authority")
        inner = Entity.make("primitive/any", value)
        resource = resource_target("system/handler/" + target)
        env = p.outbound_dispatch(
            ctx.conn, target, operation, inner, capability, granter_peer, cap_sig, resource
        )
        if env is None:
            return Outcome.err(503, "no_outbound_seam", "no live §6.11 reentry connection")
        status = env.root.uint("status") or 0
        result_cbor = env.root.field("result")
        if not isinstance(result_cbor, dict):
            result_cbor = {}
        return Outcome.ok(Entity.make("primitive/any", {"status": status, "result": result_cbor}))
