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
from .._varint import decode_varint
from ..content_hash import content_hash
from .identity import verify_signature
from .model import Entity
from .store import ExecContext
from .wire import (
    MAX_FRAME,
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
    #: The resolved peer-relative handler pattern for this dispatch (e.g.
    #: ``"system/tree"``), and the grant the handler itself runs under.  Both are
    #: §6.8a execution-context fields; see :meth:`exec_context`.
    handler_pattern: str = ""
    handler_grant: Entity | None = None
    #: The peer's configured frame bound, used only when this context carries no
    #: connection.  Never read it directly — call :meth:`frame_budget`.
    peer_max_frame: int = MAX_FRAME

    def exec_context(self) -> ExecContext:
        """The §6.8a execution context for a §6.10 tree-change event.

        Built from what this dispatch actually holds (SYSTEM-COMPOSITION §1.4 field
        inventory).  Slots a core request does not carry stay ``None`` — they are read
        from the wire, never invented.

        WHY IT EXISTS.  ``TreeEvent`` had no context field at all, so every tree-change
        event reached a consumer contextless.  That is not a neutral absence:
        EXTENSION-HISTORY §2.1 defines the AUTONOMOUS case exactly, so a contextless
        event is indistinguishable from an autonomous write and a conforming recorder
        attributes a REMOTE caller's write to the local peer.  §7.2 calls ``capability``
        the answer to "under what authority?", and the answer was always "its own".
        Routed by ``entity-system-generator`` (H8) out of building HISTORY v1.7; the
        four ``history`` oracle checks over these fields are PRESENCE checks, so a peer
        scores on them either way.
        """
        e = self.exec
        return ExecContext(
            request_id=e.text("request_id") or "",
            handler_pattern=self.handler_pattern,
            operation=e.text("operation") or "",
            author=e.bytes_("author"),
            caller_capability=e.bytes_("capability"),
            handler_grant=bytes(self.handler_grant.hash) if self.handler_grant is not None else None,
            chain_id=e.text("chain_id"),
            parent_chain_id=e.text("parent_chain_id"),
            cascade_depth=e.uint("cascade_depth"),
            bounds=e.field("bounds"),
        )

    def frame_budget(self) -> int:
        """The §4.10(a) inbound frame bound IN FORCE for this request, in bytes.

        A handler that must size a response against the connection's limit reads it
        here.  The value is the one the transport is enforcing on *this* connection,
        falling back to the peer's configured default when the context was built off
        the serving path (an in-process call, where no frame exists at all).

        It is deliberately NOT the module constant: a body that hardcodes 16 MiB, or
        reads :data:`~entity_core.peer.wire.MAX_FRAME`, answers with a number that a
        peer configured or negotiated otherwise is not enforcing.
        """
        conn_budget = getattr(self.conn, "max_frame_bytes", None)
        if isinstance(conn_budget, int):
            return conn_budget
        return self.peer_max_frame


UINT64_MAX = (1 << 64) - 1


def _duration_term(created_at: int, ttl: int | None) -> int | None:
    """Convert a DURATION term (``ttl_ms``) to an absolute timestamp, reporting whether
    it contributes a ceiling at all (§5.6 MIN_DEFINED rule 1 + rule 3).

    Overflow DROPS the term — treated as absent, exactly as a null term is. It MUST NOT
    wrap and MUST NOT saturate: saturation encodes differently from absence and
    manufactures ``expires_at == 2**64-1``, a finite bound no reader can distinguish from
    a deliberate one. Python ints are unbounded, so this is a DELIBERATE range check
    rather than an overflow trap — a bignum language that "just does the arithmetic"
    silently never fires rule 3 at all.

    ``ttl == 0`` is NOT special-cased, deliberately: rule 2 makes 0 a DEFINED value
    yielding ``created_at`` (expire immediately). Letting it fall out of the arithmetic
    is what keeps it from collapsing into the absent/null "no bound" spelling — and that
    collapse is exactly what ``ttl_zero_and_overflow`` caught here.
    """
    if ttl is None:
        return None
    total = created_at + ttl
    return None if total > UINT64_MAX else total


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
            # RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
            # single-use nonce. The anti-replay property is the MUST and the mechanism
            # (established-state tracking) is impl-defined, but the STATUS is pinned to
            # 401 invalid_nonce — a 409 state-conflict under-signals the replay.
            return Outcome.err(401, "invalid_nonce")
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


# ── §6.3 put admission (0.8.2.11) ─────────────────────────────────────────────
def _hash_digest_len(format_code: int) -> int | None:
    """Digest byte length for a ``content_hash_format`` code (§1.2 seed table),
    or ``None`` when this peer cannot VERIFY that code.

    The total wire length is this plus the varint prefix, which is not a
    constant of the code (§7.3): codes >= 0x80 occupy more than one byte. This
    peer computes SHA-256 only.
    """
    return {0x00: 32}.get(format_code)


def _admit_put(v: Any) -> Entity | Outcome:
    """§6.3's ``put`` admission ladder (normative, 0.8.2.11).

    ``put`` is a RECEIPT path: the submitter authors the entity, the peer
    validates what it received (§1.8 item 1) and MUST NOT author a submitted
    entity's ``content_hash`` on the submitter's behalf. Two ordered steps:

    1. STRUCTURE — a map carrying a non-empty text ``type``, a PRESENT ``data``
       (any CBOR value; null is a legal payload), and a ``content_hash`` that is
       a well-formed ``system/hash`` whose total byte length matches its format
       code (§1.2). Any failure -> 400 ``invalid_request``. A well-formed hash
       naming a format code this peer cannot verify is the separate §1.2
       ingest-dispatch case -> 400 ``unsupported_content_hash_format``.
    2. HASH — carried ``content_hash`` vs ``content_hash({type, data})``.
       Disagreement -> 400 ``hash_mismatch``.

    Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
    inputs are exactly what step 1 establishes, so a submission that is both
    malformed and mis-hashed is step 1's and answers ``invalid_request``.

    Structural admission is not semantic validation: ``data`` is never checked
    against the type named by ``type``.

    Returns the admitted ``Entity``, or the ``Outcome`` it was refused with.
    """
    def refuse(code: str, message: str) -> Outcome:
        return Outcome.err(400, code, message)

    if not isinstance(v, dict):
        return refuse("invalid_request", "put: entity is not a map")
    typ = v.get("type")
    if not isinstance(typ, str) or typ == "":
        return refuse("invalid_request", "put: entity.type absent, empty or not a text string")
    if "data" not in v:
        return refuse("invalid_request", "put: entity.data absent")
    data = v["data"]
    carried = v.get("content_hash")
    if not isinstance(carried, (bytes, bytearray)) or len(carried) == 0:
        return refuse("invalid_request", "put: entity.content_hash absent or not a byte string")
    carried = bytes(carried)
    try:
        format_code, n = decode_varint(carried)
    except Exception:
        return refuse("invalid_request", "put: entity.content_hash is not a well-formed system/hash")
    digest_len = _hash_digest_len(format_code)
    if digest_len is None:
        # §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it.
        # NOT invalid_request: the shape is fine, the algorithm is what we lack.
        return refuse("unsupported_content_hash_format", "put: unsupported content_hash_format")
    if len(carried) != n + digest_len:
        return refuse("invalid_request", "put: content_hash length does not match its format code")
    if content_hash(typ, data, format_code) != carried:
        return refuse("hash_mismatch", "put: content_hash does not match content_hash({type, data})")
    # The carried hash IS the entity's address; recomputing it into the store
    # would be the authoring arm §6.3 forbids.
    return Entity(type=typ, data=data, hash=carried)


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
        raw_entity = params.field("entity") if params is not None else None
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
        if raw_entity is None:
            return Outcome.err(400, "unexpected_params", "put: missing entity")
        admitted = _admit_put(raw_entity)
        if isinstance(admitted, Outcome):
            return admitted
        entity = admitted
        p.store.bind(path, entity, ctx.exec_context())
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

    def _mint_bounded(
        self, ctx: DispatchCtx, req_grants: list, grantee_hash, parent, params=None
    ) -> Outcome:
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
        # §6.2 CAP-5 / §5.6 MIN_DEFINED. `request` mints a ROOT token (parent: null), so
        # §5.6's parent-child attenuation rule never reaches it — without this bound,
        # temporal attenuation is the one dimension a requester can escape.
        #
        #   expires_at = MIN_DEFINED(
        #       caller_capability.expires_at,      # ABSOLUTE — enters directly
        #       created_at + policy_entry.ttl_ms,  # DURATION — converted first
        #       created_at + request.ttl_ms)       # DURATION — converted first
        #
        # Term SHAPE is the trap: mixing a duration in unconverted yields a timestamp
        # near the epoch and clamps every token to already-expired. The disposition is a
        # CLAMP, never a rejection — an over-long request from a bounded caller mints at
        # 200 with the clamped value; rejecting it is explicitly non-conformant.
        created_at = p.now_millis()
        terms = [
            ctx.caller_cap.uint("expires_at") if ctx.caller_cap is not None else None,
            _duration_term(created_at, p.policy_ttl_ms(bytes(grantee_hash))),
            _duration_term(created_at, params.uint("ttl_ms") if params is not None else None),
        ]
        defined = [t for t in terms if t is not None]
        expires_at = min(defined) if defined else None
        token, sig = p.mint_token(grantee_hash, req_grants, parent, created_at, expires_at)
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
        return self._mint_bounded(ctx, self._req_grants(params), author, None, params)

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
        return self._mint_bounded(ctx, self._req_grants(params), author, ph, params)

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

    @staticmethod
    def _is_reserved_system_pattern(pattern: str) -> bool:
        """§6.2: user-installed handlers MUST NOT register at system/* paths."""
        return pattern == "system" or pattern.startswith("system/")

    def _register(self, ctx: DispatchCtx) -> Outcome:
        p, exec_e = self.p, ctx.exec
        pattern, bad = self._register_pattern(exec_e)
        if bad is not None:
            return bad
        if self._is_reserved_system_pattern(pattern):
            return Outcome.err(
                403, "forbidden_pattern",
                "§6.2: user-installed handlers MUST NOT register at system/* paths: " + pattern,
            )
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
