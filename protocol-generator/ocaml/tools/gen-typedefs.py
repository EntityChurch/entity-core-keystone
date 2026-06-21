import json, sys
shapes = json.load(open("protocol-generator/shared/test-vectors/v0.8.0/type-registry-shapes.json"))
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

def esc(s): return s.replace("\\","\\\\").replace('"','\\"')

def fspec_to_ocaml(fs):
    parts = []
    tr = fs.get("TypeRef") or ""
    if tr: parts.append(f'(Cbor.Text "type_ref", Cbor.Text "{esc(tr)}")')
    if fs.get("Optional"): parts.append('(Cbor.Text "optional", Cbor.Bool true)')
    if fs.get("ArrayOf"): parts.append(f'(Cbor.Text "array_of", {fspec_to_ocaml(fs["ArrayOf"])})')
    if fs.get("MapOf"): parts.append(f'(Cbor.Text "map_of", {fspec_to_ocaml(fs["MapOf"])})')
    if fs.get("UnionOf"):
        elems = "; ".join(fspec_to_ocaml(x) for x in fs["UnionOf"])
        parts.append(f'(Cbor.Text "union_of", Cbor.Array [{elems}])')
    kt = fs.get("KeyType") or ""
    if kt: parts.append(f'(Cbor.Text "key_type", Cbor.Text "{esc(kt)}")')
    bs = fs.get("ByteSize")
    if bs not in (None, 0): parts.append(f'(Cbor.Text "byte_size", Cbor.Uint {bs}L)')
    return "Cbor.Map [" + "; ".join(parts) + "]"

def type_to_ocaml(s):
    parts = [f'(Cbor.Text "name", Cbor.Text "{esc(s["Name"])}")']
    flds = s.get("Fields") or {}
    if flds:
        fparts = [f'(Cbor.Text "{esc(fn)}", {fspec_to_ocaml(fs)})' for fn,fs in flds.items()]
        parts.append(f'(Cbor.Text "fields", Cbor.Map [{"; ".join(fparts)}])')
    ext = s.get("Extends") or ""
    if ext: parts.append(f'(Cbor.Text "extends", Cbor.Text "{esc(ext)}")')
    lay = s.get("Layout") or []
    if lay:
        lparts = "; ".join(f'Cbor.Text "{esc(x)}"' for x in lay)
        parts.append(f'(Cbor.Text "layout", Cbor.Array [{lparts}])')
    return "Cbor.Map [" + "; ".join(parts) + "]"

out = []
out.append("(* GENERATED from test-vectors type-registry-shapes.json (the cross-impl Go-rendered")
out.append("   type model) — the in-code core-type override table (render-from-model design).")
out.append("   53 core types per V7 §9.5. Regenerate with tools/gen-typedefs.py on a V7 bump;")
out.append("   diffed byte-for-byte against type-registry-vectors-v1 in test/type_registry.ml. *)")
out.append("")
out.append("let core_types : (string * Cbor.t) list = [")
for name in core_order:
    s = by[name]
    out.append(f'  ("{esc(name)}", {type_to_ocaml(s)});')
out.append("]")
open("protocol-generator/ocaml/src/type_defs_data.ml","w").write("\n".join(out)+"\n")
print(f"wrote {len(core_order)} core types")
