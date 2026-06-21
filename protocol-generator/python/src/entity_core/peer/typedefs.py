"""The V7 §9.5 core type-registry floor (53 types).

CLEAN-ROOM: the type definitions below are an in-code MODEL rendered through the
peer's own S2 codec; the served entity's content_hash is computed by our own
encoder over the model, NOT ingested from oracle bytes.  The shapes follow the
V7 §9.5 floor + the cross-peer render-from-model ruling (single source of truth
in code; omit-empty so the canonical ECF map is byte-stable regardless of field
declaration order — the codec re-sorts map keys length-then-lex).

A *core* peer publishes EXACTLY the §9.5 floor (core + operational + the
type-system bootstrap).  Extension vocabularies (compute/*, content/*, …) are
NOT pre-published by a core peer (refined G4 / F17).
"""

from __future__ import annotations

from typing import Any

from .model import Entity


# ── field-spec builders (omit-empty) ──────────────────────────────────────────
def _fref(t: str) -> dict:
    return {"type_ref": t}


def _opt(s: dict) -> dict:
    s = dict(s)
    s["optional"] = True
    return s


def _sized(n: int, s: dict) -> dict:
    s = dict(s)
    s["byte_size"] = n
    return s


def _farray(elem: dict) -> dict:
    return {"array_of": elem}


def _fmap_of(key_type: str, val: dict) -> dict:
    d: dict[str, Any] = {"map_of": val}
    if key_type:
        d["key_type"] = key_type
    return d


def _funion(*variants: dict) -> dict:
    return {"union_of": list(variants)}


# reused nested specs
_sp_string = _fref("primitive/string")
_sp_any = _fref("primitive/any")
_sp_hash = _fref("system/hash")
_sp_core_entity = _fref("core/entity")
_sp_tree_path = _fref("system/tree/path")
_sp_grant_entry = _fref("system/capability/grant-entry")
_sp_multi_granter = _fref("system/capability/multi-granter")
_sp_field_spec = _fref("system/type/field-spec")
_sp_op_spec = _fref("system/handler/operation-spec")
_sp_listing_entry = _fref("system/tree/listing-entry")
_sp_type = _fref("system/type")
_sp_type_name = _fref("system/type/name")


# ── type-def builder ──────────────────────────────────────────────────────────
def _type_def(
    name: str,
    *,
    extends: str | None = None,
    fields: list[tuple[str, dict]] | None = None,
    layout: list[str] | None = None,
) -> dict:
    """Render a system/type data map (omit-empty)."""
    d: dict[str, Any] = {"name": name}
    if extends is not None:
        d["extends"] = extends
    if fields:
        d["fields"] = {fname: fspec for fname, fspec in fields}
    if layout:
        d["layout"] = list(layout)
    return d


def _core_type_defs() -> list[dict]:
    """The V7 §9.5 core type floor (53 definitions) as system/type data maps."""
    return [
        # primitives (8)
        _type_def("primitive/any"),
        _type_def("primitive/bool"),
        _type_def("primitive/bytes"),
        _type_def("primitive/float"),
        _type_def("primitive/int"),
        _type_def("primitive/null"),
        _type_def("primitive/string"),
        _type_def("primitive/uint"),
        # structural roots + envelopes (5)
        _type_def("entity", fields=[
            ("type", _fref("primitive/string")),
            ("data", _fref("primitive/any")),
        ]),
        _type_def("core/entity", fields=[
            ("type", _fref("primitive/string")),
            ("data", _fref("primitive/any")),
            ("content_hash", _fref("system/hash")),
        ]),
        _type_def("core/envelope", fields=[
            ("root", _fref("core/entity")),
            ("included", _opt(_fmap_of("system/hash", _sp_core_entity))),
        ]),
        _type_def("system/envelope", extends="core/envelope"),
        _type_def("system/protocol/envelope", extends="core/envelope"),
        # identity / hash / signature (4)
        _type_def("system/hash", extends="primitive/bytes", fields=[
            ("format_code", _sized(1, _fref("primitive/uint"))),
            ("digest", _fref("primitive/bytes")),
        ], layout=["format_code", "digest"]),
        _type_def("system/peer", fields=[
            ("key_type", _fref("primitive/string")),
            ("peer_id", _fref("system/peer-id")),
            ("public_key", _fref("primitive/bytes")),
        ]),
        _type_def("system/peer-id", extends="primitive/string"),
        _type_def("system/signature", fields=[
            ("algorithm", _fref("primitive/string")),
            ("signature", _fref("primitive/bytes")),
            ("signer", _fref("system/hash")),
            ("target", _fref("system/hash")),
        ]),
        # protocol surface (6)
        _type_def("system/protocol/connect/authenticate", fields=[
            ("key_type", _fref("primitive/string")),
            ("nonce", _fref("primitive/bytes")),
            ("peer_id", _fref("system/peer-id")),
            ("public_key", _fref("primitive/bytes")),
        ]),
        _type_def("system/protocol/connect/hello", fields=[
            ("protocols", _farray(_sp_string)),
            ("nonce", _fref("primitive/bytes")),
            ("peer_id", _fref("system/peer-id")),
            ("timestamp", _fref("primitive/uint")),
            ("compression", _opt(_farray(_sp_string))),
            ("encryption", _opt(_farray(_sp_string))),
            ("hash_formats", _opt(_farray(_sp_string))),
            ("key_types", _opt(_farray(_sp_string))),
        ]),
        _type_def("system/protocol/error", fields=[
            ("code", _fref("primitive/string")),
            ("message", _opt(_fref("primitive/string"))),
            ("rejected_marker", _opt(_fref("system/hash"))),
        ]),
        _type_def("system/protocol/execute", fields=[
            ("operation", _fref("primitive/string")),
            ("params", _fref("core/entity")),
            ("request_id", _fref("primitive/string")),
            ("uri", _fref("system/tree/path")),
            ("author", _opt(_fref("system/hash"))),
            ("bounds", _opt(_fref("system/bounds"))),
            ("capability", _opt(_fref("system/hash"))),
            ("deliver_to", _opt(_fref("system/delivery-spec"))),
            ("deliver_token", _opt(_fref("system/hash"))),
            ("durability_request", _opt(_fref("system/durability-request"))),
            ("resource", _opt(_fref("system/protocol/resource-target"))),
        ]),
        _type_def("system/protocol/execute/response", fields=[
            ("request_id", _fref("primitive/string")),
            ("result", _fref("core/entity")),
            ("status", _fref("primitive/uint")),
            ("durability", _opt(_fref("system/durability-result"))),
        ]),
        _type_def("system/protocol/resource-target", fields=[
            ("targets", _farray(_sp_tree_path)),
            ("exclude", _opt(_farray(_sp_tree_path))),
        ]),
        # capability (12)
        _type_def("system/capability/grant", fields=[
            ("token", _fref("system/hash")),
        ]),
        _type_def("system/capability/grant-entry", fields=[
            ("handlers", _fref("system/capability/path-scope")),
            ("operations", _fref("system/capability/id-scope")),
            ("resources", _fref("system/capability/path-scope")),
            ("allowances", _opt(_fmap_of("", _sp_any))),
            ("constraints", _opt(_fmap_of("", _sp_any))),
            ("peers", _opt(_fref("system/capability/id-scope"))),
        ]),
        _type_def("system/capability/id-scope", fields=[
            ("include", _farray(_sp_string)),
            ("exclude", _opt(_farray(_sp_string))),
        ]),
        _type_def("system/capability/path-scope", fields=[
            ("include", _farray(_sp_tree_path)),
            ("exclude", _opt(_farray(_sp_tree_path))),
        ]),
        _type_def("system/capability/request", fields=[
            ("grants", _farray(_sp_grant_entry)),
            ("ttl_ms", _opt(_fref("primitive/uint"))),
        ]),
        _type_def("system/capability/revocation", fields=[
            ("token", _fref("system/hash")),
            ("revoked_at", _fref("primitive/uint")),
            ("reason", _opt(_fref("primitive/string"))),
        ]),
        _type_def("system/capability/revoke-request", fields=[
            ("token", _fref("system/hash")),
            ("reason", _opt(_fref("primitive/string"))),
        ]),
        _type_def("system/capability/delegate-request", fields=[
            ("grants", _farray(_sp_grant_entry)),
            ("parent", _fref("system/hash")),
            ("ttl_ms", _opt(_fref("primitive/uint"))),
        ]),
        _type_def("system/capability/delegation-caveats", fields=[
            ("max_delegation_depth", _opt(_fref("primitive/uint"))),
            ("max_delegation_ttl", _opt(_fref("primitive/uint"))),
            ("no_delegation", _opt(_fref("primitive/bool"))),
        ]),
        _type_def("system/capability/policy-entry", fields=[
            ("grants", _farray(_sp_grant_entry)),
            ("peer_pattern", _fref("primitive/string")),
            ("notes", _opt(_fref("primitive/string"))),
            ("ttl_ms", _opt(_fref("primitive/uint"))),
        ]),
        _type_def("system/capability/token", fields=[
            ("created_at", _fref("primitive/uint")),
            ("grantee", _fref("system/hash")),
            ("granter", _funion(_sp_hash, _sp_multi_granter)),
            ("grants", _farray(_sp_grant_entry)),
            ("delegation_caveats", _opt(_fref("system/capability/delegation-caveats"))),
            ("expires_at", _opt(_fref("primitive/uint"))),
            ("not_before", _opt(_fref("primitive/uint"))),
            ("parent", _opt(_fref("system/hash"))),
            ("resource_limits", _opt(_fref("system/resource-limits"))),
        ]),
        _type_def("system/capability/multi-granter", fields=[
            ("signers", _farray(_sp_hash)),
            ("threshold", _fref("primitive/uint")),
        ]),
        # handler machinery (6)
        _type_def("system/handler", fields=[
            ("interface", _fref("system/tree/path")),
            ("expression_path", _opt(_fref("system/tree/path"))),
            ("internal_scope", _opt(_farray(_sp_grant_entry))),
            ("max_scope", _opt(_farray(_sp_grant_entry))),
        ]),
        _type_def("system/handler/interface", fields=[
            ("name", _fref("primitive/string")),
            ("operations", _fmap_of("", _sp_op_spec)),
            ("pattern", _fref("system/tree/path")),
        ]),
        _type_def("system/handler/manifest", extends="system/handler/interface", fields=[
            ("name", _fref("primitive/string")),
            ("operations", _fmap_of("", _sp_op_spec)),
            ("pattern", _fref("system/tree/path")),
            ("expression_path", _opt(_fref("system/tree/path"))),
            ("internal_scope", _opt(_farray(_sp_grant_entry))),
            ("max_scope", _opt(_farray(_sp_grant_entry))),
        ]),
        _type_def("system/handler/operation-spec", fields=[
            ("input_type", _opt(_fref("system/type/name"))),
            ("output_type", _opt(_fref("system/type/name"))),
        ]),
        _type_def("system/handler/register-request", fields=[
            ("manifest", _fref("system/handler/manifest")),
            ("requested_scope", _opt(_farray(_sp_grant_entry))),
            ("types", _opt(_fmap_of("", _sp_type))),
        ]),
        _type_def("system/handler/register-result", fields=[
            ("grant", _fref("system/capability/token")),
            ("pattern", _fref("system/tree/path")),
        ]),
        # tree (5)
        _type_def("system/tree/get-request", fields=[
            ("limit", _opt(_fref("primitive/uint"))),
            ("mode", _opt(_fref("primitive/string"))),
            ("offset", _opt(_fref("primitive/uint"))),
            ("tree_id", _opt(_fref("primitive/string"))),
        ]),
        _type_def("system/tree/put-request", fields=[
            ("entity", _opt(_fref("core/entity"))),
            ("expected_hash", _opt(_fref("system/hash"))),
            ("tree_id", _opt(_fref("primitive/string"))),
        ]),
        _type_def("system/tree/listing", fields=[
            ("count", _fref("primitive/uint")),
            ("entries", _fmap_of("", _sp_listing_entry)),
            ("offset", _fref("primitive/uint")),
            ("path", _fref("system/tree/path")),
            ("next_page", _opt(_fref("system/hash"))),
        ]),
        _type_def("system/tree/listing-entry", fields=[
            ("has_children", _fref("primitive/bool")),
            ("hash", _opt(_fref("system/hash"))),
        ]),
        _type_def("system/tree/path", extends="primitive/string"),
        # type-system bootstrap (3)
        _type_def("system/type", fields=[
            ("name", _fref("system/type/name")),
            ("extends", _opt(_fref("system/type/name"))),
            ("fields", _opt(_fmap_of("", _sp_field_spec))),
            ("layout", _opt(_farray(_sp_string))),
            ("type_args", _opt(_fmap_of("", _sp_type_name))),
            ("type_params", _opt(_farray(_sp_string))),
        ]),
        _type_def("system/type/field-spec", fields=[
            ("type_ref", _opt(_fref("system/type/name"))),
            ("optional", _opt(_fref("primitive/bool"))),
            ("array_of", _opt(_fref("system/type/field-spec"))),
            ("map_of", _opt(_fref("system/type/field-spec"))),
            ("union_of", _opt(_farray(_sp_field_spec))),
            ("key_type", _opt(_fref("system/type/name"))),
            ("byte_size", _opt(_fref("primitive/uint"))),
            ("type_param", _opt(_fref("primitive/string"))),
            ("type_args", _opt(_fmap_of("", _sp_type_name))),
            ("default", _opt(_fref("primitive/any"))),
            ("constraints", _opt(_farray(_sp_core_entity))),
        ]),
        _type_def("system/type/name", extends="primitive/string"),
        # operational (4)
        _type_def("system/bounds", fields=[
            ("budget", _opt(_fref("primitive/uint"))),
            ("cascade_depth", _opt(_fref("primitive/uint"))),
            ("chain_id", _opt(_fref("primitive/string"))),
            ("parent_chain_id", _opt(_fref("primitive/string"))),
            ("ttl", _opt(_fref("primitive/uint"))),
            ("visited", _opt(_farray(_sp_tree_path))),
        ]),
        _type_def("system/resource-limits", fields=[
            ("max_budget", _opt(_fref("primitive/uint"))),
            ("max_ttl", _opt(_fref("primitive/uint"))),
            ("max_visited_length", _opt(_fref("primitive/uint"))),
        ]),
        _type_def("system/delivery-spec", fields=[
            ("operation", _fref("primitive/string")),
            ("uri", _fref("system/tree/path")),
        ]),
        _type_def("system/deletion-marker"),
    ]


def core_type_entities() -> list[tuple[str, Entity]]:
    """Materialize each §9.5 floor type as a (name, system/type Entity) pair."""
    out = []
    for td in _core_type_defs():
        out.append((td["name"], Entity.make("system/type", td)))
    return out
