#!/usr/bin/env python3
# Generate src/main/java/org/entitycore/protocol/peer/CoreTypeDefs.java — the in-code
# core-type override table (render-from-model design, V7 §9.5). Reads the cross-impl
# Go-rendered type model from the shared test-vectors (type-registry-shapes.json) and
# emits the 53 core types as Java EcfValue.Map builder forms. Mirrors the OCaml / Common
# Lisp peers' tools/gen-typedefs.py exactly (same 53-type core_order, same field-spec
# mapping) so the rendered content_hash is byte-identical to the canonical
# type-registry-vectors-v1 (diffed in TypeRegistryTest).
#
# The data map is the `data` of a `system/type` entity; Entity.make computes its
# content_hash via our own S2-green codec (canonical CBOR re-sorts keys per ECF Rule 2,
# so the field emit order below is immaterial to the hash — kept OCaml order for diff
# readability).
#
# Regenerate on a V7 bump (run from the repo root):
#   python3 protocol-generator/java/tools/gen-typedefs.py
import json

ROOT = "protocol-generator/shared/test-vectors/v0.8.0"
shapes = json.load(open(f"{ROOT}/type-registry-shapes.json"))

# The 53-type §9.5 core floor — identical name+order to the OCaml/CL peer generators
# and to entity-core-go's coreTypeFloor map (validate-peer profile.go).
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
    """Build a `td(...)` (TypeDef map) call from a Go FieldSpec dict."""
    parts = []
    tr = fs.get("TypeRef") or ""
    if tr:
        parts.append(f'"type_ref", "{esc(tr)}"')
    if fs.get("Optional"):
        parts.append('"optional", TRUE')
    if fs.get("ArrayOf"):
        parts.append(f'"array_of", {fspec(fs["ArrayOf"])}')
    if fs.get("MapOf"):
        parts.append(f'"map_of", {fspec(fs["MapOf"])}')
    if fs.get("UnionOf"):
        elems = ", ".join(fspec(x) for x in fs["UnionOf"])
        parts.append(f'"union_of", arr({elems})')
    kt = fs.get("KeyType") or ""
    if kt:
        parts.append(f'"key_type", "{esc(kt)}"')
    bs = fs.get("ByteSize")
    if bs not in (None, 0):
        parts.append(f'"byte_size", {bs}L')
    return "m(" + ", ".join(parts) + ")"


def type_def(s):
    parts = [f'"name", "{esc(s["Name"])}"']
    flds = s.get("Fields") or {}
    if flds:
        fparts = [f'"{esc(fn)}", {fspec(fs)}' for fn, fs in flds.items()]
        parts.append(f'"fields", m({", ".join(fparts)})')
    ext = s.get("Extends") or ""
    if ext:
        parts.append(f'"extends", "{esc(ext)}"')
    lay = s.get("Layout") or []
    if lay:
        lparts = ", ".join(f'"{esc(x)}"' for x in lay)
        parts.append(f'"layout", strArr({lparts})')
    return "m(" + ", ".join(parts) + ")"


out = []
out.append("package org.entitycore.protocol.peer;")
out.append("")
out.append("import java.util.LinkedHashMap;")
out.append("import java.util.Map;")
out.append("")
out.append("import org.entitycore.protocol.codec.EcfValue;")
out.append("")
out.append("/**")
out.append(" * GENERATED — do not hand-edit. The in-code §9.5 core-type override table")
out.append(" * (render-from-model, V7 §9.5). 53 core types; each value is the `data` map of a")
out.append(" * {@code system/type} entity. Generated from the shared cross-impl test-vectors")
out.append(" * (type-registry-shapes.json, the Go-rendered type model) by")
out.append(" * {@code tools/gen-typedefs.py}; diffed byte-for-byte against")
out.append(" * type-registry-vectors-v1 in {@code TypeRegistryTest}. Regenerate on a V7 bump.")
out.append(" */")
out.append("final class CoreTypeDefs {")
out.append("    private CoreTypeDefs() { }")
out.append("")
out.append("    private static final EcfValue TRUE = EcfValue.Bool.TRUE;")
out.append("")
out.append("    /** Map builder over EcfValue (String keys → Text; values coerced via Cbor.val). */")
out.append("    private static EcfValue.Map m(Object... kvs) {")
out.append("        return Cbor.map(kvs);")
out.append("    }")
out.append("")
out.append("    /** Array builder from EcfValue items (union_of field-spec lists). */")
out.append("    private static EcfValue.Array arr(EcfValue... items) {")
out.append("        return new EcfValue.Array(java.util.List.of(items));")
out.append("    }")
out.append("")
out.append("    /** Array builder from string items (layout name lists). */")
out.append("    private static EcfValue.Array strArr(String... items) {")
out.append("        return Cbor.textArray(items);")
out.append("    }")
out.append("")
out.append("    /** (type-name → data-map) for the 53 §9.5 core types, in floor order. */")
out.append("    static Map<String, EcfValue.Map> models() {")
out.append("        Map<String, EcfValue.Map> out = new LinkedHashMap<>();")
for name in core_order:
    s = by[name]
    out.append(f'        out.put("{esc(name)}", {type_def(s)});')
out.append("        return out;")
out.append("    }")
out.append("}")

dst = "protocol-generator/java/src/main/java/org/entitycore/protocol/peer/CoreTypeDefs.java"
open(dst, "w").write("\n".join(out) + "\n")
print(f"wrote {len(core_order)} core types to {dst}")
