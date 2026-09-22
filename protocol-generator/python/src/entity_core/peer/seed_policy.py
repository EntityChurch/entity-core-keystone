"""The §6.9a identity -> capability seed policy, as a VALUE.

The peer used to take ``open_grants: bool`` and pick between two hardcoded scopes, so
no policy between ``default -> *`` and the §4.4 discovery floor could be constructed at
all -- not from the CLI and not from inside the process.  Every authorization finding at
the extension layer is unobservable under ``default -> *`` (a correct audit and an
under-authorizing one score identically), so a narrow policy is the only posture in which
that class can be measured.  Routed by ``entity-system-generator``.

The file format and the CLI flag are the keystone cross-peer convention
(``protocol-generator/shared/seed-policy/README.md`` + ``seed-policy.schema.json``); the
normative contract is §6.9a.  :class:`SeedPolicy` is the §5 builder value that convention
names; :meth:`SeedPolicy.from_json` / :meth:`SeedPolicy.from_file` are its file form.  The
refusal rules are the rust peer's, so the cohort's hosts refuse the same files.

This module is also the single home of the scopes the peer materializes (the §4.4
discovery floor, the degenerate open scope, the owner scope) -- ``peer.py`` imports
them from here rather than keeping a second copy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .capability import is_peer_id

_U64_MAX = (1 << 64) - 1
_I64_MIN = -(1 << 63)


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


# ── the policy value ──────────────────────────────────────────────────────────
class SeedPolicyError(ValueError):
    """A seed-policy file that cannot be materialized as written."""


@dataclass(frozen=True, slots=True)
class SeedPolicyEntry:
    """A named policy entry (§6.9a.1): the key it is bound under at
    ``system/capability/policy/{key}`` and the §3.6 grant-entry maps materialized there.

    ``key`` is a 66/98-char lowercase identity-hash hex or a Base58 peer id.  ``grants``
    may be empty: an empty entry is the CAP-2 withdrawal form (the entry matches and grants
    nothing, suppressing ``default``).
    """

    key: str
    grants: list = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class SeedPolicy:
    """The declared seed policy a peer materializes at init (§6.9a Bootstrap L0) and
    consults at §4.6 authenticate.

    The ``self`` owner capability is not part of it: the peer mints that regardless,
    because it is a real root capability, not a template.  ``default_grants`` and each
    entry's ``grants`` are §3.6 grant-entry maps (plain dicts, the CBOR data shape).
    """

    default_grants: list
    named_entries: tuple[SeedPolicyEntry, ...] = ()

    # ── builders ────────────────────────────────────────────────────────────
    @staticmethod
    def standard() -> "SeedPolicy":
        """The conformant default: ``default`` = the §4.4 discovery floor, nothing named."""
        return SeedPolicy(_grants_cbor(*_discovery_floor()))

    @staticmethod
    def debug_open() -> "SeedPolicy":
        """The degenerate ``default -> *`` policy -- what the deprecated
        ``--debug-open-grants`` / ``open_grants=True`` selects.  Routed through the real
        §6.9a mechanism, never a fork."""
        return SeedPolicy(_grants_cbor(*_open_grants_scope()))

    @staticmethod
    def of(default_grants: list, named: list[SeedPolicyEntry] | None = None) -> "SeedPolicy":
        """Any policy: the ``default`` entry's grants plus named entries."""
        return SeedPolicy(list(default_grants), tuple(named or ()))

    # ── file form ───────────────────────────────────────────────────────────
    @staticmethod
    def from_file(path: str) -> "SeedPolicy":
        """Read a seed-policy file (``--seed-policy <path>``).  Errors carry the path."""
        try:
            with open(path, "rb") as fh:
                text = fh.read().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise SeedPolicyError(f"{path}: {exc}") from exc
        try:
            return SeedPolicy.from_json(text)
        except SeedPolicyError as exc:
            raise SeedPolicyError(f"{path}: {exc}") from exc

    @staticmethod
    def from_json(text: str) -> "SeedPolicy":
        """Parse the keystone seed-policy JSON format.

        Refuses rather than approximates, on each of the following, because every one of
        them would otherwise be an authorization decision nobody wrote down:

        - an unknown key at root / entry / grant / scope level (the schema is
          ``additionalProperties: false``).  Keys beginning with ``_`` are comments and
          are skipped -- the shipped ``examples/`` carry ``_comment``, which the schema as
          written does not admit;
        - ``version`` other than the integer 1;
        - ``grantee: "self"`` -- the owner capability lives at the self key and is minted
          by the peer; a policy entry there would overwrite it;
        - ``bounds`` -- ``system/capability/policy-entry`` (§6.2) carries
          ``peer_pattern``, ``grants`` and ``ttl_ms`` only, so there is nowhere to
          materialize a ``not_before``/``expires_at`` and dropping it would widen the
          policy silently;
        - a grantee that is not ``default``, an identity-hash hex, or a Base58 peer id;
          the same grantee twice; a second ``default``;
        - anywhere in the document: a float (fraction/exponent/NaN/Infinity), an integer
          outside u64/i64, a duplicate object key, an unpaired surrogate.

        A file with no ``default`` entry gets the §4.4 discovery floor as ``default``.
        """
        root = _strict_loads(text)
        _check_keys(root, ("version", "entries"), "seed policy")
        if "version" not in root:
            raise SeedPolicyError("seed policy: missing version")
        version = root["version"]
        if type(version) is not int or version != 1:  # bool is an int subclass: exclude it
            raise SeedPolicyError("seed policy: version must be 1")
        if "entries" not in root:
            raise SeedPolicyError("seed policy: missing entries")
        entries = root["entries"]
        if not isinstance(entries, list):
            raise SeedPolicyError("seed policy: entries must be an array")

        default_grants: list | None = None
        named: list[SeedPolicyEntry] = []
        for i, entry in enumerate(entries):
            what = f"entries[{i}]"
            _check_keys(entry, ("grantee", "grants", "bounds"), what)
            if "bounds" in entry:
                raise SeedPolicyError(
                    f"{what}: bounds is not supported -- system/capability/policy-entry "
                    "(section 6.2) carries peer_pattern, grants and ttl_ms only, so a "
                    "not_before/expires_at here would be dropped"
                )
            grantee = entry.get("grantee")
            if not isinstance(grantee, str) or grantee == "":
                raise SeedPolicyError(f"{what}: grantee must be a non-empty string")
            grants_json = entry.get("grants")
            if not isinstance(grants_json, list):
                raise SeedPolicyError(f"{what}: grants must be an array")
            grants = [_grant(g, f"{what}.grants[{j}]") for j, g in enumerate(grants_json)]

            if grantee == "default":
                if default_grants is not None:
                    raise SeedPolicyError(f"{what}: a second default entry")
                default_grants = grants
            elif grantee == "self":
                raise SeedPolicyError(
                    f'{what}: grantee "self" is materialized by the peer as its owner '
                    "capability; a policy entry at that key would overwrite it"
                )
            elif _is_identity_hex(grantee) or is_peer_id(grantee):
                if any(e.key == grantee for e in named):
                    raise SeedPolicyError(f"{what}: grantee {grantee} appears twice")
                named.append(SeedPolicyEntry(grantee, grants))
            else:
                raise SeedPolicyError(
                    f'{what}: grantee "{grantee}" is not default, an identity-hash hex, '
                    "or a Base58 peer id"
                )
        return SeedPolicy(
            default_grants if default_grants is not None else _grants_cbor(*_discovery_floor()),
            tuple(named),
        )


# ── strict JSON + validation helpers ──────────────────────────────────────────
def _refuse_float(s: str) -> Any:
    raise SeedPolicyError(
        f"json: numbers must be integers (a fraction or exponent is refused, never approximated): {s}"
    )


def _refuse_constant(s: str) -> Any:
    raise SeedPolicyError(f"json: {s} is not a JSON number")


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise SeedPolicyError(f'json: duplicate key "{k}"')
        out[k] = v
    return out


def _check_value(v: Any) -> None:
    """Integers must fit u64/i64; no string (or key) may carry an unpaired surrogate."""
    if isinstance(v, bool) or v is None:
        return
    if isinstance(v, int):
        if v > _U64_MAX or v < _I64_MIN:
            raise SeedPolicyError(f"json: integer out of range (must fit u64 or i64): {v}")
    elif isinstance(v, str):
        _check_text(v)
    elif isinstance(v, list):
        for x in v:
            _check_value(x)
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_text(k)
            _check_value(x)


def _check_text(s: str) -> None:
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        raise SeedPolicyError("json: unpaired surrogate in string")


def _strict_loads(text: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_refuse_float,
            parse_constant=_refuse_constant,
        )
    except SeedPolicyError:
        raise
    except ValueError as exc:  # json.JSONDecodeError: trailing content, trailing comma, ...
        raise SeedPolicyError(f"json: {exc}") from exc
    _check_value(value)
    return value


def _is_identity_hex(s: str) -> bool:
    return len(s) in (66, 98) and all(c in "0123456789abcdef" for c in s)


def _check_keys(v: Any, allowed: tuple[str, ...], what: str) -> None:
    if not isinstance(v, dict):
        raise SeedPolicyError(f"{what}: must be an object")
    for k in v:
        if not k.startswith("_") and k not in allowed:
            raise SeedPolicyError(f'{what}: unknown key "{k}"')


def _string_list(v: Any, what: str) -> list[str]:
    if not isinstance(v, list):
        raise SeedPolicyError(f"{what}: must be an array")
    for s in v:
        if not isinstance(s, str):
            raise SeedPolicyError(f"{what}: entries must be strings")
    return list(v)


def _scope(v: Any, what: str) -> dict:
    _check_keys(v, ("include", "exclude"), what)
    if "include" not in v:
        raise SeedPolicyError(f"{what}: missing include")
    out: dict[str, Any] = {"include": _string_list(v["include"], f"{what}.include")}
    if "exclude" in v:  # preserved whenever present, including as an empty list
        out["exclude"] = _string_list(v["exclude"], f"{what}.exclude")
    return out


def _grant(v: Any, what: str) -> dict:
    _check_keys(
        v,
        ("handlers", "resources", "operations", "peers", "constraints", "allowances"),
        what,
    )
    out: dict[str, Any] = {}
    for dim in ("handlers", "resources", "operations"):
        if dim not in v:
            raise SeedPolicyError(f"{what}: missing {dim}")
        out[dim] = _scope(v[dim], f"{what}.{dim}")
    if "peers" in v:
        out["peers"] = _scope(v["peers"], f"{what}.peers")
    for extra in ("constraints", "allowances"):
        if extra in v:
            if not isinstance(v[extra], dict):
                raise SeedPolicyError(f"{what}.{extra}: must be an object")
            # Carried verbatim: opaque grant data, not policy-file structure.
            out[extra] = v[extra]
    return out
