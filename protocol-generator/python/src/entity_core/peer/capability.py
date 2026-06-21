"""Capability system (L3): the §5 verification core.

Pattern matching (§5.4), request verification (§5.2 verify-request /
check-permission), delegation-chain verification (§5.5), attenuation (§5.6), the
§4.10(b) chain-depth pre-check, and GENUINE §3.6 K-of-N multi-sig (M3/M4/M6).

The verdict is one of the :class:`Verdict` values (§5.10 Layer-1 determinism).
The dispatcher maps:

    AUTHN_FAIL            -> 401 authentication_failed
    AUTHZ_DENY            -> 403 capability_denied
    UNRESOLVABLE_GRANTEE  -> 401 unresolvable_grantee  (§5.5 carve-out)
    CHAIN_TOO_DEEP        -> 400 chain_depth_exceeded   (§4.10(b) structural)

§3.6 MULTI-SIG (root-only K-of-N): ``granter`` is polymorphic — a single
``system/hash`` (single-sig) or a ``system/capability/multi-granter``
``{signers, threshold}``.  Per §5.5 the verifier:

  * M3 — at chain-walk entry, for EVERY chain entity whose granter is a
    multi-granter: parent MUST be null (root-only); ``len(signers) >= 2``; no
    duplicate signers; ``threshold in [2, len(signers)]``.  M3 runs BEFORE any
    signature work (precedence: M3 violations surface 403, not 401).
  * M6 — root check: for a multi-sig root the LOCAL peer MUST be in ``signers``
    AND MUST have signed.
  * M4 — per-link: count DISTINCT-signer valid signatures from ``signers``;
    ALLOW the link iff ``valid >= threshold``.

Single-sig caps verify byte-identically (a strict superset).
"""

from __future__ import annotations

import time
from typing import Any, Callable

from .identity import peer_id_of_public_key, verify_signature
from .model import Entity
from .store import Store

#: §4.10(b) finite max capability-chain depth (64, the informative default).
MAX_CHAIN_DEPTH = 64

# ── verdict (§5.2 / §5.10) ────────────────────────────────────────────────────
ALLOW = "ALLOW"
AUTHN_FAIL = "AUTHN_FAIL"
AUTHZ_DENY = "AUTHZ_DENY"
CHAIN_TOO_DEEP = "CHAIN_TOO_DEEP"
UNRESOLVABLE_GRANTEE = "UNRESOLVABLE_GRANTEE"

Verdict = str
ResolveFn = Callable[[Any], "Entity | None"]


def now_millis() -> int:
    return int(time.time() * 1000)


# ── scope / grant parse ───────────────────────────────────────────────────────
def _text_elems(v: Any) -> list[str]:
    if not isinstance(v, list):
        return []
    return [x for x in v if isinstance(x, str)]


class Scope:
    __slots__ = ("incl", "excl")

    def __init__(self, incl: list[str], excl: list[str]) -> None:
        self.incl = incl
        self.excl = excl


def _parse_scope(v: Any) -> Scope:
    if not isinstance(v, dict):
        return Scope([], [])
    return Scope(_text_elems(v.get("include")), _text_elems(v.get("exclude")))


class GrantRec:
    __slots__ = ("handlers", "resources", "operations", "peers")

    def __init__(self, v: Any) -> None:
        d = v if isinstance(v, dict) else {}
        self.handlers = _parse_scope(d.get("handlers"))
        self.resources = _parse_scope(d.get("resources"))
        self.operations = _parse_scope(d.get("operations"))
        self.peers = _parse_scope(d["peers"]) if isinstance(d.get("peers"), dict) else None


def _grants_of_token(token: Entity) -> list[GrantRec]:
    gv = token.field("grants")
    if not isinstance(gv, list):
        return []
    return [GrantRec(g) for g in gv]


# ── §5.4 pattern matching ─────────────────────────────────────────────────────
def normalize_uri(uri: str) -> str:
    """§1.4: strip the entity:// scheme to an absolute path."""
    if uri.startswith("entity://"):
        return "/" + uri[len("entity://"):]
    return uri


def canonicalize(local_peer: str, path: str) -> str | None:
    """Resolve a peer-relative path to absolute ``/{local}/...`` form.

    Reserved directory-relative + ambiguous bare-wildcard forms return ``None``
    (the §1.4 / §5.4 errors).
    """
    if path.startswith("./") or path.startswith("../") or path.startswith("*/"):
        return None
    if path.startswith("/"):
        return path
    return "/" + local_peer + "/" + path


def _canon(local_peer: str, path: str) -> str:
    """canonicalize with a best-effort fallthrough (non-match desired)."""
    c = canonicalize(local_peer, path)
    return c if c is not None else path


def matches_pattern(path: str, pattern: str) -> bool:
    """Whether (canonical, absolute) ``path`` matches ``pattern``."""
    if pattern == "*":
        return True
    if pattern.startswith("/*/"):
        remainder = pattern[3:]
        i = path.find("/", 1)
        if i < 0:
            return False
        return matches_pattern(path[i + 1:], remainder)
    if pattern.endswith("/*"):
        return path.startswith(pattern[:-1])
    return path == pattern


def _covered(local_peer: str, value: str, pats: list[str]) -> bool:
    cv = _canon(local_peer, value)
    return any(matches_pattern(cv, _canon(local_peer, p)) for p in pats)


def _matches_scope(local_peer: str, value: str, s: Scope) -> bool:
    return _covered(local_peer, value, s.incl) and not _covered(local_peer, value, s.excl)


# ── peer-id detection (§1.4) ──────────────────────────────────────────────────
_BASE58_ALPHABET = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def is_peer_id(seg: str) -> bool:
    return len(seg) >= 46 and all(c in _BASE58_ALPHABET for c in seg)


def first_segment(uri: str) -> str:
    if uri.startswith("/"):
        uri = uri[1:]
    i = uri.find("/")
    return uri[:i] if i >= 0 else uri


def extract_peer(local_peer: str, uri: str) -> str:
    first = first_segment(normalize_uri(uri))
    return first if is_peer_id(first) else local_peer


# ── resolution ────────────────────────────────────────────────────────────────
def cap_resolve(included: dict, store: Store) -> ResolveFn:
    """Resolve a content_hash to an entity (included-first, then store)."""

    def resolve(h: Any) -> Entity | None:
        if h is None:
            return None
        e = included.get(bytes(h).hex()) if isinstance(h, (bytes, bytearray)) else None
        if e is not None:
            return e
        return store.get_by_hash(h)

    return resolve


def find_signature(target: bytes, included: dict) -> Entity | None:
    """Find a system/signature in ``included`` whose target == ``target``."""
    for e in included.values():
        if e.type != "system/signature":
            continue
        if e.bytes_("target") == bytes(target):
            return e
    return None


def find_signature_by_signer(target: bytes, signer: bytes, included: dict) -> Entity | None:
    """§5.2 helper: a system/signature with matching target AND signer."""
    for e in included.values():
        if e.type != "system/signature":
            continue
        if e.bytes_("target") == bytes(target) and e.bytes_("signer") == bytes(signer):
            return e
    return None


# ── multi-granter (§3.6) ──────────────────────────────────────────────────────
def _granter_is_multi(token: Entity) -> bool:
    """Whether the cap's granter is a multi-granter (a {signers, threshold} map)
    rather than a single system/hash (bytes)."""
    g = token.field("granter")
    return isinstance(g, dict) and "signers" in g and "threshold" in g


def _multi_signers(token: Entity) -> list[bytes]:
    g = token.field("granter")
    if not isinstance(g, dict):
        return []
    sv = g.get("signers")
    if not isinstance(sv, list):
        return []
    return [bytes(s) for s in sv if isinstance(s, (bytes, bytearray))]


def _multi_threshold(token: Entity) -> int:
    g = token.field("granter")
    if not isinstance(g, dict):
        return 0
    t = g.get("threshold")
    return t if isinstance(t, int) and not isinstance(t, bool) else 0


def _has_duplicates(signers: list[bytes]) -> bool:
    return len({s for s in signers}) != len(signers)


def m3_valid(token: Entity) -> bool:
    """§3.6 M3 structural validity for a multi-sig cap (root-only)."""
    if token.field("parent") is not None:
        return False  # multi-sig is root-only
    signers = _multi_signers(token)
    threshold = _multi_threshold(token)
    if len(signers) < 2:
        return False
    if _has_duplicates(signers):
        return False
    if threshold < 2 or threshold > len(signers):
        return False
    return True


# ── §5.5 chain collection + the §4.10(b) depth pre-check ──────────────────────
def collect_chain(cap: Entity, resolve: ResolveFn) -> list[Entity] | None:
    """Walk to root via parent hashes (§5.5 collect_authority_chain).  Returns
    the ordered [cap, parent, .., root] chain, or ``None`` on ChainTooDeep /
    ChainUnreachable."""
    chain: list[Entity] = []
    current: Entity | None = cap
    depth = 0
    while current is not None:
        if depth > MAX_CHAIN_DEPTH:
            return None
        chain.append(current)
        parent_h = current.bytes_("parent")
        if parent_h is None:
            return chain
        current = resolve(parent_h)
        if current is None:
            return None  # ChainUnreachable
        depth += 1
    return chain


def chain_exceeds_depth(store: Store, capability: Entity, included: dict) -> bool:
    """§4.10(b) structural-bound pre-check: True iff the authority chain rooted
    at ``capability`` exceeds MAX_CHAIN_DEPTH.  Walks parent pointers WITHOUT
    verifying signatures — depth is purely structural, gated BEFORE the per-link
    authz walk so over-depth -> 400 chain_depth_exceeded (structural excess),
    distinct from a 403 authz failure.  An UNREACHABLE parent is NOT a depth
    problem — it returns False here and is left for the chain walk to deny."""
    resolve = cap_resolve(included, store)
    current = capability
    depth = 0
    while True:
        if depth > MAX_CHAIN_DEPTH:
            return True
        parent_h = current.bytes_("parent")
        if parent_h is None:
            return False  # root reached within bound
        parent = resolve(parent_h)
        if parent is None:
            return False  # unreachable — not a depth problem
        current = parent
        depth += 1


# ── §5.6 attenuation ──────────────────────────────────────────────────────────
def _scope_subset(child_peer: str, parent_peer: str, child: Scope, parent: Scope) -> bool:
    for cp in child.incl:
        cc = _canon(child_peer, cp)
        if not any(matches_pattern(cc, _canon(parent_peer, pp)) for pp in parent.incl):
            return False
    for pe in parent.excl:
        cpe = _canon(parent_peer, pe)
        if not any(matches_pattern(cpe, _canon(child_peer, ce)) for ce in child.excl):
            return False
    return True


def _grant_subset(
    local_peer: str, child_peer: str, parent_peer: str, child: GrantRec, parent: GrantRec
) -> bool:
    if not _scope_subset(local_peer, local_peer, child.handlers, parent.handlers):
        return False
    if not _scope_subset(local_peer, local_peer, child.operations, parent.operations):
        return False
    if not _scope_subset(child_peer, parent_peer, child.resources, parent.resources):
        return False
    cp = child.peers if child.peers is not None else Scope([local_peer], [])
    pp = parent.peers if parent.peers is not None else Scope([local_peer], [])
    return _scope_subset(local_peer, local_peer, cp, pp)


def _is_attenuated(
    local_peer: str, child_peer: str, parent_peer: str, child: Entity, parent: Entity
) -> bool:
    cg = _grants_of_token(child)
    pg = _grants_of_token(parent)
    for c in cg:
        if not any(_grant_subset(local_peer, child_peer, parent_peer, c, p) for p in pg):
            return False
    pe = parent.uint("expires_at")
    ce = child.uint("expires_at")
    if pe is not None and ce is None:
        return False  # child infinite, parent finite
    if pe is not None and ce is not None:
        return ce <= pe
    return True


def _check_delegation_caveats(parent: Entity, child: Entity, depth: int) -> bool:
    caveats = parent.field("delegation_caveats")
    if not isinstance(caveats, dict):
        return True
    if caveats.get("no_delegation") is True:
        return False
    m = caveats.get("max_delegation_depth")
    if isinstance(m, int) and not isinstance(m, bool) and depth >= m:
        return False
    mt = caveats.get("max_delegation_ttl")
    if isinstance(mt, int) and not isinstance(mt, bool):
        ex = child.uint("expires_at")
        cr = child.uint("created_at")
        if ex is not None and cr is not None:
            if ex - cr > mt:
                return False
        elif ex is None:
            return False  # infinite child lifetime exceeds any limit
    return True


def _link_granter_peer(resolve: ResolveFn, local_peer: str, cap: Entity) -> tuple[str, bool]:
    """§5.5a per-link canonicalization frame = the granter's peer_id.  A root
    multi-granter or a root with no granter hash falls to the local frame; an
    unresolvable single-sig granter hard-fails (deny)."""
    if _granter_is_multi(cap):
        return local_peer, True
    gh = cap.bytes_("granter")
    if gh is None:
        return local_peer, True
    g = resolve(gh)
    if g is None:
        return "", False
    pk = g.bytes_("public_key")
    if pk is None:
        return "", False
    return peer_id_of_public_key(pk), True


# ── §5.5 chain verification (single-sig + multi-sig) ──────────────────────────
def verify_capability_chain(
    local_peer: str, store: Store, capability: Entity, included: dict
) -> Verdict:
    """§5.5 dispatch-time chain verification.  Returns ALLOW / AUTHZ_DENY /
    UNRESOLVABLE_GRANTEE."""
    resolve = cap_resolve(included, store)
    chain = collect_chain(capability, resolve)
    if chain is None:
        return AUTHZ_DENY

    # M3 structural validity — EVERY chain entity, BEFORE any signature work
    # (precedence: M3 violations surface 403, not 401).
    for entity in chain:
        if _granter_is_multi(entity) and not m3_valid(entity):
            return AUTHZ_DENY

    # ── root check (M6: generalized for multi-sig) ──
    root = chain[-1]
    if _granter_is_multi(root):
        # Multi-sig root: the local peer MUST be in signers AND have signed.
        local_in_validated_signers = False
        for candidate in _multi_signers(root):
            cand_id = resolve(candidate)
            if cand_id is None:
                continue
            pk = cand_id.bytes_("public_key")
            if pk is None or peer_id_of_public_key(pk) != local_peer:
                continue
            sig = find_signature_by_signer(root.hash, candidate, included)
            if sig is None:
                continue
            if verify_signature(sig, cand_id):
                local_in_validated_signers = True
                break
        if not local_in_validated_signers:
            return AUTHZ_DENY
    else:
        gh = root.bytes_("granter")
        root_granter = resolve(gh) if gh is not None else None
        if root_granter is None:
            return AUTHZ_DENY
        pk = root_granter.bytes_("public_key")
        if pk is None or peer_id_of_public_key(pk) != local_peer:
            return AUTHZ_DENY

    # ── per-level validation ──
    now = now_millis()
    n = len(chain)
    for i in range(n):
        current = chain[i]

        # Signature (M4: branch on granter shape)
        if _granter_is_multi(current):
            # Multi-sig path: K distinct-signer valid signatures.
            threshold = _multi_threshold(current)
            signers = _multi_signers(current)
            if threshold < 2 or threshold > len(signers):
                return AUTHZ_DENY
            seen: set[bytes] = set()
            valid = 0
            for candidate in signers:
                if candidate in seen:
                    continue  # defensive dedupe (distinct-signer counting)
                seen.add(candidate)
                cand_id = resolve(candidate)
                if cand_id is None:
                    continue
                sig = find_signature_by_signer(current.hash, candidate, included)
                if sig is None:
                    continue
                if verify_signature(sig, cand_id):
                    valid += 1
                    if valid >= threshold:
                        break
            if valid < threshold:
                return AUTHZ_DENY
        else:
            # Single-sig path (unchanged).
            gh = current.bytes_("granter")
            if gh is None:
                return AUTHZ_DENY
            sig = find_signature(current.hash, included)
            granter = resolve(gh)
            if sig is None or granter is None:
                return AUTHZ_DENY
            signer = sig.bytes_("signer")
            if signer != gh or not verify_signature(sig, granter):
                return AUTHZ_DENY

        # Grantee resolution -> 401 carve-out (per-link)
        geh = current.bytes_("grantee")
        if geh is None or resolve(geh) is None:
            return UNRESOLVABLE_GRANTEE

        # Temporal validity
        nb = current.uint("not_before")
        if nb is not None and now < nb:
            return AUTHZ_DENY
        ex = current.uint("expires_at")
        if ex is not None and ex < now:
            return AUTHZ_DENY

        # Delegation link to parent (not for root)
        if i < n - 1:
            parent = chain[i + 1]
            child_peer, cok = _link_granter_peer(resolve, local_peer, current)
            parent_peer, pok = _link_granter_peer(resolve, local_peer, parent)
            if not cok or not pok:
                return AUTHZ_DENY
            pg = parent.bytes_("grantee")
            cg = current.bytes_("granter")
            # multi-sig granter is a map (cg is None) — its chain linkage is
            # never reached because M3 forces multi-sig caps to be root-only.
            if (
                pg is None
                or cg is None
                or pg != cg
                or not _is_attenuated(local_peer, child_peer, parent_peer, current, parent)
                or not _check_delegation_caveats(parent, current, i)
            ):
                return AUTHZ_DENY

    return ALLOW


def _is_revoked(local_peer: str, store: Store, capability: Entity, included: dict) -> bool:
    resolve = cap_resolve(included, store)
    root_hash = capability.hash
    chain = collect_chain(capability, resolve)
    if chain is not None:
        root_hash = chain[-1].hash
    base = "/" + local_peer + "/system/capability/revocations/"
    return (
        store.get_at(base + capability.hash.hex()) is not None
        or store.get_at(base + root_hash.hex()) is not None
    )


def resolve_granter_peer_id(resolve: ResolveFn, cap: Entity) -> str:
    """§PR-8 frame for canonicalizing a cap's grant resource patterns."""
    if _granter_is_multi(cap):
        return ""
    gh = cap.bytes_("granter")
    if gh is None:
        return ""
    g = resolve(gh)
    if g is None:
        return ""
    pk = g.bytes_("public_key")
    return peer_id_of_public_key(pk) if pk is not None else ""


# ── §5.2 check-permission ─────────────────────────────────────────────────────
def _check_resource_scope(local_peer: str, granter_peer: str, resource: Any, s: Scope) -> bool:
    if not isinstance(resource, dict):
        return False
    targets = _text_elems(resource.get("targets"))
    caller_excl = _text_elems(resource.get("exclude"))
    if not targets:
        return False

    def covered_local(pats: list[str], v: str) -> bool:
        return any(matches_pattern(v, _canon(local_peer, p)) for p in pats)

    def covered_grant(pats: list[str], v: str) -> bool:
        return any(matches_pattern(v, _canon(granter_peer, p)) for p in pats)

    for tgt in targets:
        ct = _canon(local_peer, tgt)
        if covered_local(caller_excl, ct):
            continue  # excluded by caller — admitted
        if not covered_grant(s.incl, ct):
            return False
        if covered_grant(s.excl, ct):
            return False
    return True


def check_permission(
    local_peer: str, granter_peer: str, exec_e: Entity, token: Entity, handler_pattern: str
) -> bool:
    """§5.2 dispatch-time authorization gate."""
    operation = exec_e.text("operation") or ""
    uri = exec_e.text("uri") or ""
    target_peer = extract_peer(local_peer, uri)
    resource = exec_e.field("resource")

    for g in _grants_of_token(token):
        if not _matches_scope(local_peer, operation, g.operations):
            continue
        if not _matches_scope(local_peer, handler_pattern, g.handlers):
            continue
        peers = g.peers if g.peers is not None else Scope([local_peer], [])
        if not _matches_scope(local_peer, target_peer, peers):
            continue
        if isinstance(resource, dict):
            if not _check_resource_scope(local_peer, granter_peer, resource, g.resources):
                continue
        return True
    return False


# ── §5.2 verify-request (3-way verdict + carve-outs) ──────────────────────────
def verify_request(local_peer: str, store: Store, env) -> Verdict:
    """§5.2 verdict over the request envelope."""
    exec_e = env.root
    included = env.included
    sgn = find_signature(exec_e.hash, included)
    if sgn is None:
        return AUTHN_FAIL
    author_h = exec_e.bytes_("author")
    if author_h is None:
        return AUTHN_FAIL
    signer = sgn.bytes_("signer")
    if signer != author_h:
        return AUTHN_FAIL
    author = included.get_by_hash(author_h)
    if author is None or not verify_signature(sgn, author):
        return AUTHN_FAIL

    cap_h = exec_e.bytes_("capability")
    if cap_h is None:
        return AUTHZ_DENY
    cap = included.get_by_hash(cap_h)
    if cap is None:
        return AUTHZ_DENY

    # §4.10(b): structural over-depth -> 400, BEFORE the per-link authz walk.
    if chain_exceeds_depth(store, cap, included):
        return CHAIN_TOO_DEEP

    verdict = verify_capability_chain(local_peer, store, cap, included)
    if verdict == AUTHZ_DENY:
        return AUTHZ_DENY
    if verdict == UNRESOLVABLE_GRANTEE:
        return UNRESOLVABLE_GRANTEE
    if verdict == ALLOW:
        grantee = cap.bytes_("grantee")
        if grantee != author_h:
            return AUTHZ_DENY
        if _is_revoked(local_peer, store, cap, included):
            return AUTHZ_DENY
        return ALLOW
    return AUTHZ_DENY
