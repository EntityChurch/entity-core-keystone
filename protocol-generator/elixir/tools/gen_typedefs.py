#!/usr/bin/env python3
# Generate lib/entity_core/type_defs_data.ex — the in-code core-type override table
# (render-from-model design, V7 §9.5; A-OC-006 cross-impl source). Twin of the OCaml
# tools/gen-typedefs.py, emitting idiomatic Elixir instead of OCaml: each core type is
# a {name, data} tuple where data is an Elixir map with binary keys (the model layer's
# native CBOR value form — int for Uint, true/false for Bool, list for Array, binary for
# Text). The same field subset the OCaml generator handled (which reached 53/53 byte
# identity) is reproduced exactly. Regenerate on a V7 bump:
#   python3 tools/gen_typedefs.py
import json, os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SHAPES = os.path.join(ROOT, "protocol-generator/shared/test-vectors/v0.8.0/type-registry-shapes.json")
OUT = os.path.join(ROOT, "protocol-generator/elixir/lib/entity_core/type_defs_data.ex")

shapes = json.load(open(SHAPES))
core_order = """primitive/any primitive/bool primitive/bytes primitive/float primitive/int primitive/null primitive/string primitive/uint
entity core/entity core/envelope system/envelope system/protocol/envelope
system/hash system/peer system/peer-id system/signature
system/protocol/connect/authenticate system/protocol/connect/hello system/protocol/error system/protocol/execute system/protocol/execute/response system/protocol/resource-target
system/capability/grant system/capability/grant-entry system/capability/id-scope system/capability/path-scope system/capability/request system/capability/revocation system/capability/revoke-request system/capability/delegate-request system/capability/delegation-caveats system/capability/policy-entry system/capability/token system/capability/multi-granter
system/handler system/handler/interface system/handler/manifest system/handler/operation-spec system/handler/register-request system/handler/register-result
system/tree/get-request system/tree/put-request system/tree/listing system/tree/listing-entry system/tree/path
system/type system/type/field-spec system/type/name
system/bounds system/resource-limits system/delivery-spec system/deletion-marker""".split()
by = {s["Name"]: s for s in shapes}


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def fspec(fs):
    parts = []
    tr = fs.get("TypeRef") or ""
    if tr:
        parts.append(f'"type_ref" => "{esc(tr)}"')
    if fs.get("Optional"):
        parts.append('"optional" => true')
    if fs.get("ArrayOf"):
        parts.append(f'"array_of" => {fspec(fs["ArrayOf"])}')
    if fs.get("MapOf"):
        parts.append(f'"map_of" => {fspec(fs["MapOf"])}')
    if fs.get("UnionOf"):
        elems = ", ".join(fspec(x) for x in fs["UnionOf"])
        parts.append(f'"union_of" => [{elems}]')
    kt = fs.get("KeyType") or ""
    if kt:
        parts.append(f'"key_type" => "{esc(kt)}"')
    bs = fs.get("ByteSize")
    if bs not in (None, 0):
        parts.append(f'"byte_size" => {bs}')
    return "%{" + ", ".join(parts) + "}"


def type_to_ex(s):
    parts = [f'"name" => "{esc(s["Name"])}"']
    flds = s.get("Fields") or {}
    if flds:
        fparts = [f'"{esc(fn)}" => {fspec(fs)}' for fn, fs in flds.items()]
        parts.append(f'"fields" => %{{{", ".join(fparts)}}}')
    ext = s.get("Extends") or ""
    if ext:
        parts.append(f'"extends" => "{esc(ext)}"')
    lay = s.get("Layout") or []
    if lay:
        lparts = ", ".join(f'"{esc(x)}"' for x in lay)
        parts.append(f'"layout" => [{lparts}]')
    return "%{" + ", ".join(parts) + "}"


out = []
out.append("defmodule EntityCore.TypeDefsData do")
out.append("  @moduledoc \"\"\"")
out.append("  GENERATED from test-vectors/v0.8.0/type-registry-shapes.json (the cross-impl")
out.append("  Go-rendered type model) — the in-code core-type override table")
out.append("  (render-from-model design). 53 core types per V7 §9.5. Regenerate with")
out.append("  `tools/gen_typedefs.py` on a V7 bump; diffed byte-for-byte against")
out.append("  type-registry-vectors-v1 in test/type_registry_test.exs.")
out.append("  \"\"\"")
out.append("")
out.append("  @doc \"The 53 core types as `{name, data}` tuples (data = model-form map).\"")
out.append("  @spec core_types() :: [{String.t(), map()}]")
out.append("  def core_types do")
out.append("    [")
for name in core_order:
    out.append(f'      {{"{esc(name)}", {type_to_ex(by[name])}}},')
out.append("    ]")
out.append("  end")
out.append("end")
open(OUT, "w").write("\n".join(out) + "\n")
print(f"wrote {len(core_order)} core types to {OUT}")
