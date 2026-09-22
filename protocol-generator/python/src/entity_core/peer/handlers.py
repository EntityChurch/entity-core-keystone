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
    _canon,
    _grant_subset,
    _grants_of_token,
    canonicalize,
    check_path_permission,
    is_peer_id,
    matches_pattern,
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


def _effective_targets(local_peer: str, exec_e: Entity) -> list[str] | None:
    """§5.2's effective target list (0.8.2.20).

    The caller's own ``resource.exclude`` removes entries from the request BEFORE
    anything else looks at it, and the survivors are returned in the caller's OWN
    spelling — 0.8.2.21 is explicit that ``effective_targets`` yields raw
    survivors rather than canonical forms.

    Returns ``None`` when the EXECUTE carries no ``resource`` at all, which is a
    different input from "a resource whose every target was excluded" — and for a
    resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with
    different answers, not merely different inputs to one disposition.

    ``None``-vs-``[]`` IS THE NON-LOSSY PROJECTION §3.3 REQUIRES ``[MUST]`` (0.8.2.25,
    N11): *"where an implementation projects ``resource.targets`` onto the effective
    set ahead of the handler, that projection MUST NOT be lossy about its own emptiness
    — narrow when narrowing leaves something, and retain the raw pair when narrowing
    would empty it."*  A function returning only a list cannot satisfy that: collapsing
    ``[qA] exclude [qA]`` to ``[]`` would delete the two-empties discriminator before
    any handler could read it, and the handler's refusal arm becomes dead code that
    only a WIRE drive can detect.  Python carries the discriminator as the ``| None``
    rather than as a second return value — the same property, spelled the way this
    substrate spells "absent".

    *"Every seam that narrows is exempted alike, inbound-wire and in-process
    sub-dispatch, or one request receives two different answers according to which door
    it arrived through."*  This peer has exactly ONE narrowing seam — this function,
    called by the handler — and §6.5's dispatch chain does not project: ``_run_chain``
    passes ``exec_e`` through untouched and ``check_permission`` reads ``resource`` for
    itself.  So there is no second door to keep in step, and adding a projection at
    dispatch would create one.

    The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it
    separately from the grant arm): ``_canon`` answers the sentinel and
    ``matches_pattern`` then answers False, so the target simply survives.

    OPEN, AND BOTH VANGUARDS ANSWER IT THE SAME WAY WITHOUT TEXT BEHIND THEM: a
    ``resource`` map carrying NO ``targets`` key at all is reported here as ABSENT, so
    ``get`` serves it the root listing.  §3.2 says *"``targets`` — Array of paths or
    patterns this operation accesses.  MUST contain at least one entry"*, which makes
    that shape a MALFORMED resource rather than an absent one — and N10's whole point
    is that a PRESENT ``resource`` must not be served the wider absent-case answer.
    Left as shipped rather than decided in a sweep (the F86 precedent), because the
    disposition a malformed ``resource`` earns — ``path_required`` or
    ``invalid_request`` — is not pinned anywhere and nothing in the 778-check set
    drives the shape.
    """
    r = exec_e.field("resource")
    if not isinstance(r, dict):
        return None
    if "targets" not in r:
        return None
    # PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, and this line used to say
    # otherwise.  `if not isinstance(targets, list): return None` collapsed an absent
    # `targets` key and a `targets` that is a number into one answer — which is N11's
    # own defect (a projection "lossy about its own emptiness") one field over, and it
    # put the two vanguards on opposite sides of the same cell: `go`'s `textElems` of a
    # non-array yields an EMPTY effective list, so `{"targets": 42}` answers
    # `400 path_required` there and returned the ROOT LISTING here — the wider-than-the-
    # request answer §3.3 forbids.  Corrected toward `go`.
    targets = r.get("targets")
    targets = targets if isinstance(targets, list) else []
    excl = r.get("exclude")
    excl = [x for x in excl if isinstance(x, str)] if isinstance(excl, list) else []
    out: list[str] = []
    for t in targets:
        if not isinstance(t, str):
            continue
        ct = _canon(local_peer, t)
        if any(matches_pattern(ct, _canon(local_peer, x)) for x in excl):
            continue
        out.append(t)
    return out


def _is_pattern_path(t: str) -> bool:
    """A §5.4 PATTERN rather than a concrete path. A resource-requiring operation
    takes a concrete path (0.8.2.20); a trailing "/" is a LISTING request, not a
    pattern — only a ``*`` makes it one."""
    return "*" in t


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
        # §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
        # 400 invalid_request, not the 501 every other handler answers. The table
        # separates a STATE conflict from an UNKNOWN operation because they select
        # different remedies — "an unknown connect operation is not out of order at
        # all; it exists in no state", so connection_sequence_error would point the
        # caller at its ORDERING when the defect is its OPERATION NAME. Row 10 is
        # scoped "in any state", so this arm covers pre-handshake AND established;
        # the genuine sequence cases are refused in _hello/_authenticate, with 409.
        #
        # SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
        # (§3.3's 501 row, §6.2) is a different contract and is separately gated;
        # moving the shared op501 would trade one green check for another.
        return Outcome.err(400, "invalid_request", f"connect: unknown operation {op}")

    def _hello(self, ctx: DispatchCtx) -> Outcome:
        p, c, exec_e = self.p, ctx.conn, ctx.exec
        if c.established:
            return Outcome.err(409, "connection_already_established")
        # §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
        # HALF-OPEN connection (hello done, authenticate not yet) is an operation we
        # implement arriving in a state that forbids it — the same class as
        # connection_already_established above, taking the same 409. A half-open
        # connection is NOT established, so the guard above cannot reach it; §4.7
        # names this gap explicitly because two adjacent rules each look like they
        # cover it and neither does.
        if c.issued_nonce is not None:
            return Outcome.err(409, "connection_sequence_error")
        f = _str_array(exec_e, "hash_formats")
        if f is not None and "ecfv1-sha256" not in f:
            return Outcome.err(400, "incompatible_hash_format")
        k = _str_array(exec_e, "key_types")
        if k is not None and "ed25519" not in k:
            return Outcome.err(400, "unsupported_key_type")
        params = _params_entity(exec_e)
        # §4.5 mutual verifiability, the direction that is NOT the array. `key_types`
        # is an ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in
        # its `peer_id` — so a hello may advertise a perfectly good accept-set and
        # still name an identity we cannot verify. Checking only the array leaves
        # that MUST unenforced at hello, which is where §4.5 wants it; authenticate
        # catches it one leg later, which is conformant but non-canonical.
        #
        # An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
        # field, not a key_type we lack, and authenticate already refuses it.
        hello_pid = params.text("peer_id") if params is not None else None
        if hello_pid:
            from .identity import KEY_TYPE_ED25519
            from ..peer_id import parse_peer_id

            try:
                hp = parse_peer_id(hello_pid)
            except Exception:  # noqa: BLE001
                hp = None
            if hp is not None and hp.key_type != KEY_TYPE_ED25519:
                return Outcome.err(400, "unsupported_key_type")
        # §4.5 `protocols` — the one negotiated field Required with NO default, so
        # there is no floor to fall back to, and its two failure modes carry
        # different codes on purpose (§4.5 table row / §4.7 row 1):
        #
        #   absent or empty     -> 400 invalid_request       (a malformed hello)
        #   non-empty, disjoint -> 400 incompatible_protocol (we compared)
        #
        # "a caller that named no version cannot be told the comparison failed" —
        # the remedies differ (send the field vs change the version) and §4.7 exists
        # so the code selects the remedy. The vocabulary is §8.4's protocol version
        # identifiers, today the single entity-core/1.0.
        #
        # ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
        # precedence between the three, so a hello disjoint in more than one
        # dimension may be refused on any of them — but the choice is OBSERVABLE, and
        # the reference peer refuses key_types first. Checking protocols first is
        # equally spec-legal and makes AGILITY-UNKNOWN-1 answer incompatible_protocol,
        # because that probe's own hello carries protocols ["entity-core/v7"] — a
        # spec-line name, not a §8.4 identifier (F56).
        protos = _str_array(exec_e, "protocols")
        if not protos:
            return Outcome.err(400, "invalid_request", "hello: protocols absent or empty")
        if "entity-core/1.0" not in protos:
            return Outcome.err(400, "incompatible_protocol")
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

    def _entry_visible(self, ctx: DispatchCtx | None, dir_path: str, segment: str) -> bool:
        """§6.3's per-entry listing check for one child segment.

        An unauthenticated context is the bootstrap/internal path and is not
        filtered: the filter's subject is "the caller's verified capability", and
        where there is none there is no caller to narrow.
        """
        if ctx is None or not ctx.has_cap or ctx.caller_cap is None:
            return True
        child = dir_path if dir_path.endswith("/") else dir_path + "/"
        return check_path_permission(
            "get", child + segment, ctx.caller_cap, ctx.handler_pattern, self.p.local_peer
        )

    def _build_listing(self, path: str, ctx: DispatchCtx | None = None) -> Outcome:
        """Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).

        "When any handler returns a multi-entry result whose entries are tree
        paths, each entry MUST be individually checked using
        check_path_permission.  Entries for which check_path_permission returns
        DENY MUST be omitted.  The result's ``count`` field MUST reflect the
        filtered entry count, not the source tree's total count."

        This is the read path at its highest volume and it is the reason 0.8.2.21
        refused to carve reads out of the caller-specified-path rule: an
        unfiltered listing discloses the EXISTENCE of every binding under a
        prefix to a caller whose capability covers none of them.

        The DIRECTORY itself is deliberately not checked — §6.3 makes each ENTRY
        the subject, and testing the prefix would deny a listing to a caller
        whose grant covers children but not the node above them, which is the
        ordinary shape of a narrowed grant.
        """
        rows = self.p.store.listing(path)
        entries: dict[str, Any] = {}
        count = 0
        for row in rows:
            if row.hash and not row.has_children and self._is_deletion_marker(row.hash):
                continue
            if not self._entry_visible(ctx, path, row.segment):
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
        # §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
        # resource.targets: a handler that counts the effective list and then
        # indexes targets[0] has implemented the arithmetic completely and is
        # still reading a path no authorization covered.
        eff = _effective_targets(p.local_peer, exec_e)
        if eff is None:
            # THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION
            # IS WHAT SAYS SO.  §3.3's "an empty effective list IS the absent case" is
            # scoped "for an operation that REQUIRES a resource" (0.8.2.24, N7); `get`
            # does not.  For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
            # present-but-empty case by whether the absent case is WIDER than the
            # request — BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty — and
            # requires the operation to declare which it is.
            #
            # EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
            # resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root listing",
            # self-excluded case "400 path_required".  So both arms here are pinned by
            # text and neither is this peer's choice.  (This branch previously carried
            # an ambiguity note arguing the absent case might owe `path_required` too;
            # it was routed as F86 and §2.2a answers it — the behaviour is unchanged and
            # the justification is no longer ours.)
            return self._build_listing("/" + p.local_peer + "/", ctx)
        if len(eff) == 0:
            # `resource` PRESENT, every target carved out by the caller's own exclude.
            # Serving it the absent case "answers a request for one excluded path with
            # a listing of the tree" (EXTENSION-TREE §2.2a) — the root listing is wider
            # than what was asked for, which is what BROAD-RESULT means.
            return Outcome.err(400, "path_required", "tree: effective target list is empty")
        if len(eff) > 1:
            return Outcome.err(400, "ambiguous_resource", "tree: more than one effective target")
        target = eff[0]
        if not _path_flex_ok(target):
            return Outcome.err(400, "invalid_path", target)
        if target == "" or target.endswith("/"):
            c = canonicalize(p.local_peer, target) or target
            return self._build_listing(c, ctx)
        if _is_pattern_path(target):
            return Outcome.err(400, "malformed_resource", target)
        path = canonicalize(p.local_peer, target)
        if path is None:
            return Outcome.err(400, "invalid_path", target)
        # §6.3: the handler MUST verify the CALLER's capability covers the path
        # it is about to read.  Not a secondary check — the dispatch-level check
        # never saw this path if the caller excluded it.
        if ctx.has_cap and ctx.caller_cap is not None and not check_path_permission(
            "get", path, ctx.caller_cap, ctx.handler_pattern, p.local_peer
        ):
            return Outcome.err(403, "capability_denied", path)
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
        # Same ladder as `_get`, with the two empties COLLAPSED rather than split:
        # EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's "an
        # empty effective list IS the absent case" applies in its unscoped form and both
        # empties answer `path_required`.  That is the same table `_get`'s branch cites,
        # read one row down — the field is per-operation and neither answer is derivable
        # from this handler's source.
        #
        # Note the code change 0.8.2.20 forced: this branch answered
        # `ambiguous_resource` for a MISSING target, which 0.8.2.20 names as the exact
        # inversion it forbids ("answering ambiguous_resource for an absent resource
        # inverts them").  The remedies differ — *supply a resource* is not *disambiguate
        # your request* — and the code selects.
        eff = _effective_targets(p.local_peer, exec_e)
        if eff is None or len(eff) == 0:
            return Outcome.err(400, "path_required", "tree: put requires a resource target")
        if len(eff) > 1:
            return Outcome.err(400, "ambiguous_resource", "tree: more than one effective target")
        target = eff[0]
        if not _path_flex_ok(target):
            return Outcome.err(400, "invalid_path", target)
        if _is_pattern_path(target):
            return Outcome.err(400, "malformed_resource", target)
        path = canonicalize(p.local_peer, target)
        if path is not None and ctx.has_cap and ctx.caller_cap is not None and not check_path_permission(
            "put", path, ctx.caller_cap, ctx.handler_pattern, p.local_peer
        ):
            return Outcome.err(403, "capability_denied", path)
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
            return Outcome.err(503, "no_outbound_seam", "no live section 6.11 reentry connection")
        status = env.root.uint("status") or 0
        result_cbor = env.root.field("result")
        if not isinstance(result_cbor, dict):
            result_cbor = {}
        return Outcome.ok(Entity.make("primitive/any", {"status": status, "result": result_cbor}))
