"""Peer assembly: bootstrap (§6.9 / §6.9a), the four MUST system handlers (§6.2),
the §6.5 dispatch chain, §6.6 resolution, the §6.9a peer-authority + seed-policy
bootstrap, the §6.11 reentrant-outbound seam, and per-connection state.
"""

from __future__ import annotations

import itertools
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .capability import (
    AUTHN_FAIL,
    AUTHZ_DENY,
    CHAIN_TOO_DEEP,
    UNRESOLVABLE_GRANTEE,
    _temporal_fields_representable,
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
from .store import ExecContext, Store
from .typedefs import core_type_entities
from .seed_policy import (
    GrantSpec,
    SeedPolicy,
    _discovery_floor,
    _grants_cbor,
    _open_grants_scope,
    _scope_cbor,
)
from .wire import MAX_FRAME, error_result, make_execute, make_response

#: Maximum nesting of ``HandlerContext.dispatch_execute`` within one wire request — the
#: peer's own bound on an expression dispatching to a handler whose body dispatches again.
MAX_LOCAL_DISPATCH_DEPTH = 16


# ── per-connection state (§4.2) ───────────────────────────────────────────────
@dataclass(slots=True)
class Conn:
    established: bool = False
    issued_nonce: bytes | None = None
    hello_peer_id: str = ""
    outbound: Callable[[Envelope], "Envelope | None"] | None = None
    out_counter: int = 0
    #: The §4.10(a) inbound frame bound IN FORCE on this connection, stamped by the
    #: transport from the peer's own value.  ``None`` means "this Conn was built
    #: outside the serving path", and a body reading the budget then falls back to
    #: the peer default rather than to a literal — see ``DispatchCtx.frame_budget``.
    max_frame_bytes: int | None = None


# ── grant construction (§4.4 / §5.4) ──────────────────────────────────────────
# The scopes and the grant-entry builder live in ``seed_policy`` (their single home, so
# the policy value and the peer cannot carry two copies of the discovery floor); they are
# re-exported here under their historical names.


class Peer:
    """A bootstrapped Entity Core peer."""

    def __init__(
        self,
        seed: bytes,
        *,
        open_grants: bool = False,
        seed_policy: SeedPolicy | None = None,
        conformance: bool = False,
        max_frame_bytes: int = MAX_FRAME,
    ) -> None:
        """``seed_policy`` is the §6.9a identity -> capability seed policy materialized at
        L0 and consulted at §4.6 authenticate (the ``with_seed_policy`` builder
        affordance; see :class:`SeedPolicy`).  When omitted, the conformant
        :meth:`SeedPolicy.standard` applies -- or, when ``open_grants`` is set,
        :meth:`SeedPolicy.debug_open` (``default -> *``).

        ``open_grants`` is DEPRECATED: it selects the degenerate ``default -> *`` policy
        (the retired ``--debug-open-grants`` behaviour, routed through the real §6.9a
        mechanism) and is IGNORED when ``seed_policy`` is supplied -- a declared policy
        wins.
        """
        self.identity = Identity.of_seed(seed)
        self.store = Store()
        self.local_peer = self.identity.peer_id
        self.open_grants = open_grants
        if seed_policy is not None:
            self.seed_policy = seed_policy
        elif open_grants:
            self.seed_policy = SeedPolicy.debug_open()
        else:
            self.seed_policy = SeedPolicy.standard()
        self.conformance = conformance
        #: §4.10(a): this peer's inbound frame bound.  The transport enforces it
        #: per connection and stamps it onto each :class:`Conn`, so the number a
        #: handler body reads back is the number actually in force.
        self.max_frame_bytes = max_frame_bytes
        self.handlers: dict[str, Any] = {}
        # ── keystone peer contract §4: the PRIVATE registration index behind
        # register_handler (pattern -> (generation, spec, body)), the evaluator seam, and the
        # local-dispatch request counter.  ``handlers`` above stays the public G-2 dict.
        self._registrations: dict[str, tuple[int, Any, Callable[..., Any]]] = {}
        self._registration_lock = threading.RLock()
        self._generation = itertools.count(1)
        self._local_counter = itertools.count(1)
        self._evaluator: Callable[..., Any] | None = None
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
    def mint_token(
        self,
        grantee_hash: bytes,
        grants: list,
        parent: bytes | None,
        created_at: int | None = None,
        expires_at: int | None = None,
    ) -> tuple[Entity, Entity]:
        """Mint + sign a capability token.

        ``created_at`` and ``expires_at`` are passed together on purpose: the §5.6
        duration terms are relative to ``created_at``, so sampling the clock twice would
        let the emitted ``created_at`` and the expiry derived from it skew apart. Callers
        computing a ceiling sample once and thread it through.
        """
        data: dict[str, Any] = {
            "granter": bytes(self.identity.identity_hash),
            "grantee": bytes(grantee_hash),
            "grants": grants,
            "created_at": self.now_millis() if created_at is None else created_at,
        }
        if expires_at is not None:
            data["expires_at"] = expires_at
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

    def policy_ttl_ms(self, grantee_hash: bytes) -> int | None:
        """The ``ttl_ms`` of the policy entry that ceilings THIS caller (§6.2 CAP-5),
        via the same dual-form lookup the §4.4 authenticate path uses
        (hex -> Base58 -> ``default``).

        This is the term that makes policy withdrawal bounded on the ``request`` path:
        the entry's ``ttl_ms`` is the withdrawal latency for tokens already issued.
        """
        from .identity import peer_id_of_public_key

        base = "/" + self.local_peer + "/system/capability/policy/"
        keys = [grantee_hash.hex()]
        peer_e = self.store.get_by_hash(grantee_hash)
        if peer_e is not None:
            pub = peer_e.bytes_("public_key")
            if pub is not None:
                keys.append(peer_id_of_public_key(pub))
        keys.append("default")
        for key in keys:
            e = self.store.get_at(base + key)
            if e is not None:
                return e.uint("ttl_ms")
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
    def _entity_native_dispatch(self, handler_path: str, ctx: Any = None) -> Outcome:
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
        # install.evaluator: the built-in compute/literal floor above answers FIRST; an
        # installed evaluator only ever sees a body the peer would otherwise refuse.
        evaluator = self._evaluator
        if evaluator is not None and ctx is not None:
            from .extension import ExpressionRequest

            try:
                answered = evaluator(ExpressionRequest(expr_path, expr, he), ctx)
            except Exception:  # noqa: BLE001 — third-party code: a status, never a crash
                return Outcome.err(500, "internal_error", "expression evaluator raised")
            if isinstance(answered, Outcome):
                return answered
        return Outcome.err(501, "unsupported_expression", expr.type)

    # ── dispatch chain (§6.5) ────────────────────────────────────────────────
    def dispatch(self, c: Conn, env: Envelope) -> Envelope | None:
        """Run the §6.5 dispatch chain, returning an EXECUTE_RESPONSE envelope.

        The ``None`` in the return type is now unreachable and is kept only so the
        transport's write decision does not have to change shape: every inbound root
        reaching here is answered.
        """
        exec_e = env.root
        if exec_e.type != "system/protocol/execute":
            # §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
            # invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare
            # close — that is indistinguishable from a network fault."
            #
            # §3.3 read "the connection MUST be closed", assigning no code and requiring
            # no frame, and this peer did something weaker still: it returned None, the
            # transport wrote NOTHING, and the connection stayed open — which is §4.11's
            # OTHER non-conformant behaviour, the silent drop, "the weaker of the two
            # precisely because nothing surfaces it". This is a PRE-ADMISSION refusal:
            # the root is not an EXECUTE, so nothing was ever admitted and §4.9(c) does
            # not reach it.
            #
            # The request_id is read best-effort — an arbitrary root type is under no
            # obligation to carry one, and §4.11 licenses the uncorrelated frame exactly
            # there. We do NOT close: on a multiplexed connection that would cost every
            # ADMITTED in-flight request its response, and §4.11 leaves the close to us.
            return Envelope.of(make_response(
                exec_e.text("request_id") or "", 400,
                error_result("invalid_request",
                             "root entity is neither EXECUTE nor EXECUTE_RESPONSE"),
            ))
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
            return h.handle_op(operation, DispatchCtx(
                exec=exec_e, conn=c, included=env.included,
                peer_max_frame=self.max_frame_bytes,
            ))

        self._ingest_signatures(env)

        # §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION, and this gate
        # used to sit below the verdict. A pre-establishment EXECUTE naming a FOREIGN
        # namespace therefore took the 401 an unauthenticated request takes. §4.7's own
        # reason: "a 401 directs the caller to authenticate and retry, and for a
        # foreign-namespace address that retry cannot succeed at any authentication state
        # — so the 401 names a remedy that does not exist." §6.5 step 3 calls it "a gate,
        # not an ordering preference" and §1.4 makes the downstream permission check
        # unreachable on this path, so evaluating authentication first can only mislead.
        #
        # Guarded on a canonicalizable path so a MALFORMED one keeps its existing 400
        # invalid_path disposition below rather than being silently re-coded here.
        addr = canonicalize(self.local_peer, normalize_uri(uri))
        if addr is not None and extract_peer(self.local_peer, addr) != self.local_peer:
            return Outcome.err(400, "invalid_request", "not local peer")

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
        # (The §1.4 / §6.5 step 3 address gate that used to sit here has moved ABOVE the
        # verdict — §4.7 0.8.2.6 orders it before authentication. Reaching this line at
        # all now means the path is local.)
        cap_h = exec_e.bytes_("capability")
        return self._route(c, env, exec_e, path, lambda: env.included.get_by_hash(cap_h), 0)

    def _route(
        self, c: Conn, env: Envelope, exec_e: Entity, path: str,
        caller_cap_of: Callable[[], "Entity | None"], depth: int,
    ) -> Outcome:
        """§6.6 resolution -> §5.2 check_permission -> body selection.  The wire chain and
        ``HandlerContext.dispatch_execute`` share it, so a local dispatch cannot take a
        different path than a wire EXECUTE (``context.dispatch``)."""
        operation = exec_e.text("operation") or ""
        pattern = self._resolve_handler(path)
        if pattern is None:
            return Outcome.err(404, "handler_not_found", path)
        caller_cap = caller_cap_of()
        if caller_cap is None:
            return Outcome.err(403, "capability_denied")
        resolve = cap_resolve(env.included, self.store)
        granter_peer = resolve_granter_peer_id(resolve, caller_cap) or self.local_peer
        if not check_permission(self.local_peer, granter_peer, exec_e, caller_cap, pattern):
            return Outcome.err(403, "capability_denied")
        stripped = self._strip_local(pattern)
        # The handler's own grant (§6.8a): the second authority a write runs
        # under, distinct from the caller's. Bound at bootstrap/registration.
        handler_grant = self.store.get_at(
            "/" + self.local_peer + "/system/capability/grants/" + stripped
        )
        # install.handler — THE READ SITE of the private registration index.  A pattern
        # can only be here if register_handler found no handlers-dict entry for it, so
        # every existing handlers-dict dispatch below is unchanged.
        with self._registration_lock:
            reg = self._registrations.get(stripped)
        if reg is not None:
            ctx = self._handler_context(c, env, exec_e, path, pattern, stripped,
                                        caller_cap, handler_grant, depth)
            try:
                out = reg[2](ctx)
            except Exception:  # noqa: BLE001 — third-party code: a status, never a crash
                return Outcome.err(500, "internal_error", "handler body raised")
            if not isinstance(out, Outcome):
                return Outcome.err(500, "internal_error", "handler body returned no Outcome")
            return out
        inst = self.handlers.get(stripped)
        if inst is not None:
            return inst.handle_op(operation, DispatchCtx(
                exec=exec_e, conn=c, included=env.included,
                caller_cap=caller_cap, has_cap=True,
                handler_pattern=stripped, handler_grant=handler_grant,
                peer_max_frame=self.max_frame_bytes,
            ))
        ctx = self._handler_context(c, env, exec_e, path, pattern, stripped,
                                    caller_cap, handler_grant, depth)
        return self._entity_native_dispatch(pattern, ctx)

    def _handler_context(
        self, c: Conn, env: Envelope, exec_e: Entity, path: str, pattern: str, stripped: str,
        caller_cap: Entity | None, handler_grant: Entity | None, depth: int,
    ) -> Any:
        from .extension import _DISPATCHER, HandlerContext

        return HandlerContext(
            _DISPATCHER, peer=self, envelope=env, exec_entity=exec_e, pattern=stripped,
            suffix=path[len(pattern):].lstrip("/"), caller_capability=caller_cap,
            handler_grant=handler_grant, conn=c, depth=depth,
        )

    def _exec_context(self, exec_e: Entity, handler_pattern: str) -> ExecContext:
        """The §6.8a execution context of a request answered by ``handler_pattern``."""
        grant = self.store.get_at(
            "/" + self.local_peer + "/system/capability/grants/" + handler_pattern
        )
        return ExecContext(
            request_id=exec_e.text("request_id") or "",
            handler_pattern=handler_pattern,
            operation=exec_e.text("operation") or "",
            author=exec_e.bytes_("author"),
            caller_capability=exec_e.bytes_("capability"),
            handler_grant=bytes(grant.hash) if grant is not None else None,
            chain_id=exec_e.text("chain_id"),
            parent_chain_id=exec_e.text("parent_chain_id"),
            cascade_depth=exec_e.uint("cascade_depth"),
            bounds=exec_e.field("bounds"),
        )

    # ── context.dispatch — local EXECUTE under a given capability ─────────────
    def _dispatch_local(
        self, parent: Any, uri: str, operation: str, params: Entity,
        resource: Any, capability: Entity | None,
    ) -> Outcome:
        depth = parent._depth + 1
        if depth > MAX_LOCAL_DISPATCH_DEPTH:
            return Outcome.err(429, "bounds_exceeded", "local dispatch depth exceeds the peer's bound")
        cap = capability if capability is not None else parent.caller_capability
        if cap is None:
            return Outcome.err(403, "capability_denied", "no capability for local dispatch")
        if not self._local_capability_admissible(parent, cap):
            return Outcome.err(
                403, "capability_denied",
                "local dispatch capability is not the caller's, the handler's grant, "
                "or a valid token this peer issued",
            )
        path = canonicalize(self.local_peer, normalize_uri(uri))
        if path is None:
            return Outcome.err(400, "invalid_path", uri)
        if extract_peer(self.local_peer, path) != self.local_peer:
            return Outcome.err(
                400, "invalid_request",
                "local dispatch targets the local peer only; a foreign namespace is the outbound seam",
            )
        if self._strip_local(path) == "system/protocol/connect":
            return Outcome.err(400, "invalid_request", "the connect handler serves a connection, not a local dispatch")
        request_id = f"{parent.request_id}/local-{next(self._local_counter)}"
        author = parent.author if parent.author is not None else self.identity.identity_hash
        exec_e = make_execute(
            request_id, uri, operation, params,
            author=author, capability=cap.hash, resource=resource,
        )
        pc = parent._conn
        sub_conn = Conn(
            established=True,
            outbound=getattr(pc, "outbound", None),
            max_frame_bytes=getattr(pc, "max_frame_bytes", None),
        )
        try:
            return self._route(sub_conn, parent.envelope, exec_e, path, lambda: cap, depth)
        except Exception:  # noqa: BLE001 — a status, never a crash
            return Outcome.err(500, "internal_error", "local dispatch raised")

    def _local_capability_admissible(self, parent: Any, cap: Entity) -> bool:
        """The caller's verified capability and the handler's own grant are admissible by
        identity; any other token must be one THIS peer issued, signed at the §3.5 pointer,
        inside its temporal bounds (CAP-6a: unrepresentable is refused), and unrevoked."""
        cc, hg = parent.caller_capability, parent.handler_grant
        if (cc is not None and cc.hash == cap.hash) or (hg is not None and hg.hash == cap.hash):
            return True
        if cap.type != "system/capability/token" or cap.bytes_("granter") != self.identity.identity_hash:
            return False
        if not cap.content_hash_holds():
            return False
        sig = self.store.get_at("/" + self.local_peer + "/system/signature/" + cap.hash.hex())
        if sig is None or not verify_signature(sig, self.identity.peer_entity):
            return False
        if not _temporal_fields_representable(cap):
            return False
        now = self.now_millis()
        ex, nb = cap.uint("expires_at"), cap.uint("not_before")
        if (ex is not None and now > ex) or (nb is not None and now < nb):
            return False
        revoked = "/" + self.local_peer + "/system/capability/revocations/" + cap.hash.hex()
        return self.store.get_at(revoked) is None

    # ── install.handler / install.remove / install.evaluator ──────────────────
    def register_handler(self, spec: Any, body: Callable[..., Outcome]) -> Any:
        """Install a language-native handler body (keystone peer contract ``install.handler``;
        ``SDK-OPERATIONS`` §11.6, §11.6.1, §12.5).

        Performs the core §6.13(a) writes — types at ``system/type/{name}``, the handler
        entity at the pattern, the handler's grant (minted from ``spec.internal_scope``,
        ``None`` -> a grant covering nothing) with its signature at the §3.5 pointer, and the
        interface at ``system/handler/{pattern}`` — and binds ``body`` in the peer's private
        registration index.  ``body(ctx: HandlerContext) -> Outcome``.

        Raises :class:`~entity_core.peer.extension.RegisterError` BEFORE writing anything:
        ``409 pattern_collision`` when a handler (built-in, ``handlers`` dict, registered,
        or wire-registered) is already bound at the pattern; ``400 invalid_handler_spec``
        for a non-concrete pattern, no operations, a bad operation/type name, a non-list
        ``internal_scope`` or a non-callable body.  ``system/*`` is NOT refused
        (``SDK-OPERATIONS`` v1.13).

        Returns a :class:`~entity_core.peer.extension.HandlerHandle`; the ``handlers`` dict
        is untouched.
        """
        from .extension import _DISPATCHER, HandlerHandle, HandlerSpec, RegisterError, is_concrete_pattern

        def invalid(msg: str) -> RegisterError:
            return RegisterError(400, "invalid_handler_spec", msg)

        if not isinstance(spec, HandlerSpec):
            raise invalid("spec is not a HandlerSpec")
        pattern = spec.pattern
        if not is_concrete_pattern(pattern):
            raise invalid(f"pattern {pattern!r} is not a concrete peer-relative path")
        if not callable(body):
            raise invalid(f"{pattern!r}: body is not callable")
        if not isinstance(spec.name, str):
            raise invalid(f"{pattern!r}: name is not text")
        ops = spec.operation_specs()
        if not ops:
            raise invalid(f"{pattern!r} declares no operations")
        for o in ops:
            if not isinstance(o.name, str) or o.name == "":
                raise invalid(f"{pattern!r}: an operation has no name")
        if spec.internal_scope is not None and not isinstance(spec.internal_scope, list):
            raise invalid(f"{pattern!r}: internal_scope must be a list of grant entries or None")
        types = spec.types or {}
        if not isinstance(types, dict) or any(not isinstance(k, str) or k == "" for k in types):
            raise invalid(f"{pattern!r}: types must map non-empty type names to definitions")

        local = self.local_peer

        def absp(rel: str) -> str:
            return "/" + local + "/" + rel

        with self._registration_lock:
            bound = self.store.get_at(absp(pattern))
            if (
                pattern in self._registrations
                or pattern in self.handlers
                or (bound is not None and bound.type == "system/handler")
            ):
                raise RegisterError(409, "pattern_collision", pattern)
            generation = next(self._generation)
            self._registrations[pattern] = (generation, spec, body)

        # Bound after claiming: until the handler entity exists the pattern does not
        # resolve, so the claimed body is unreachable rather than half-installed.
        interface_rel = "system/handler/" + pattern
        handler_data: dict[str, Any] = {"interface": interface_rel}
        if spec.internal_scope is not None:
            handler_data["internal_scope"] = list(spec.internal_scope)
        self.store.bind(absp(pattern), Entity.make("system/handler", handler_data))
        for tname, tdef in types.items():
            data = tdef if isinstance(tdef, dict) else {"def": tdef}
            self.store.bind(absp("system/type/" + tname), Entity.make("system/type", data))
        token, sig = self.mint_token(self.identity.identity_hash, list(spec.internal_scope or []), None)
        self.store.bind(absp("system/capability/grants/" + pattern), token)
        self.store.bind(absp("system/signature/" + token.hash.hex()), sig)
        iface: dict[str, Any] = {
            "pattern": pattern,
            "name": spec.name,
            "operations": {o.name: o.to_cbor() for o in ops},
        }
        if spec.description:
            iface["description"] = spec.description
        self.store.bind(absp(interface_rel), Entity.make("system/handler/interface", iface))
        return HandlerHandle(_DISPATCHER, self, pattern, generation)

    def _close_registration(self, pattern: str, generation: int) -> bool:
        """§11.6.2: dispatch index first, tree second — only if the live registration at
        ``pattern`` is still the one ``generation`` names."""
        with self._registration_lock:
            reg = self._registrations.get(pattern)
            if reg is None or reg[0] != generation:
                return False
            del self._registrations[pattern]
        self._unbind_handler_entities(pattern)
        return True

    def unregister_handler(self, pattern: str) -> bool:
        """Remove whatever registered body is installed at ``pattern`` and the entities it
        bound (types stay).  ``False`` when none was — a ``handlers``-dict or wire-registered
        handler is not touched.  Prefer ``HandlerHandle.close``."""
        with self._registration_lock:
            if self._registrations.pop(pattern, None) is None:
                return False
        self._unbind_handler_entities(pattern)
        return True

    def has_registered_handler(self, pattern: str) -> bool:
        """Whether a :meth:`register_handler` body is installed at ``pattern``."""
        with self._registration_lock:
            return pattern in self._registrations

    def _unbind_handler_entities(self, pattern: str) -> None:
        local = self.local_peer
        grant_path = "/" + local + "/system/capability/grants/" + pattern
        g = self.store.get_at(grant_path)
        if g is not None:
            self.store.unbind("/" + local + "/system/signature/" + g.hash.hex())
            self.store.unbind(grant_path)
        self.store.unbind("/" + local + "/" + pattern)
        self.store.unbind("/" + local + "/system/handler/" + pattern)

    def set_expression_evaluator(self, evaluator: Callable[..., Any] | None) -> None:
        """``install.evaluator`` (MODULE): install, or clear with ``None``, the evaluator for
        entity-native (§6.13(a)) handler bodies: ``evaluator(ExpressionRequest,
        HandlerContext) -> Outcome | None``.  The built-in ``compute/literal`` floor answers
        FIRST; the evaluator only sees bodies the peer would otherwise refuse with
        ``501 unsupported_expression``, and ``None`` declines."""
        self._evaluator = evaluator

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

        # The default scope template, then any explicitly-named operator/admin/reader
        # entries (§6.9a.1), each a policy-entry at its key -- all from the declared
        # seed policy, never a hardcoded fork.
        default_entry = Entity.make("system/capability/policy-entry", {
            "peer_pattern": "default",
            "grants": list(self.seed_policy.default_grants),
        })
        self.store.bind(policy_base + "default", default_entry)
        for named in self.seed_policy.named_entries:
            self.store.bind(policy_base + named.key, Entity.make("system/capability/policy-entry", {
                "peer_pattern": named.key,
                "grants": list(named.grants),
            }))

        # §7a conformance handlers — only under --validate.
        if self.conformance:
            for pattern, name, ops, cls in self._CONFORMANCE_SPECS:
                self.handlers[pattern] = cls(self)
                self._bootstrap_handler_entities(pattern, name, ops)
