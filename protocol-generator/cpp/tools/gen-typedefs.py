#!/usr/bin/env python3
# Generate src/core_typedefs.cpp — the in-code §9.5 core-type override table
# (render-from-model, V7 §9.5). Reads the cross-impl Go-rendered type model from the
# shared test-vectors (type-registry-shapes.json) and emits the 53 core types as
# idiomatic C++ EcfValue map-builder functions. Mirrors the C / Java / OCaml / Common
# Lisp peers' tools/gen-typedefs.py exactly (same 53-type core_order, same field-spec
# mapping) so the rendered content_hash is byte-identical to the canonical
# type-registry-vectors-v1 (ECF Rule-2 canonical re-sort makes emit order immaterial
# to the hash).
#
# The data map is the `data` of a `system/type` entity; entity::make computes its
# content_hash via our own S2-green codec.
#
# Idiom note: where the C peer used put_t/put_v with goto-cleanup + manual frees, the
# C++ peer uses value semantics — EcfValue maps are built by value (RAII frees them)
# and `put`/`push` take the child by value/move. No fallible allocation handling: a
# std::bad_alloc is a programmer-error (out of scope, per the profile error model).
#
# Regenerate on a V7 bump (run from the repo root):
#   python3 protocol-generator/cpp/tools/gen-typedefs.py
import json

ROOT = "protocol-generator/shared/test-vectors/v0.8.0"
shapes = json.load(open(f"{ROOT}/type-registry-shapes.json"))

# The 53-type §9.5 core floor — identical name+order to the C/Java/OCaml/CL peer
# generators and to entity-core-go's coreTypeFloor map (validate-peer profile.go).
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


def cstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


_tmp = 0


def newtmp():
    global _tmp
    _tmp += 1
    return f"t{_tmp}"


def fspec_expr(fs, lines):
    """Emit C++ building a field-spec EcfValue map; return the C++ var holding it."""
    v = newtmp()
    lines.append(f"    EcfValue {v} = EcfValue::map();")
    tr = fs.get("TypeRef") or ""
    if tr:
        lines.append(f"    {v}.put(EcfValue::text(\"type_ref\"), EcfValue::text({cstr(tr)}));")
    if fs.get("Optional"):
        lines.append(f"    {v}.put(EcfValue::text(\"optional\"), EcfValue::boolean(true));")
    if fs.get("ArrayOf"):
        sub = fspec_expr(fs["ArrayOf"], lines)
        lines.append(f"    {v}.put(EcfValue::text(\"array_of\"), std::move({sub}));")
    if fs.get("MapOf"):
        sub = fspec_expr(fs["MapOf"], lines)
        lines.append(f"    {v}.put(EcfValue::text(\"map_of\"), std::move({sub}));")
    if fs.get("UnionOf"):
        arr = newtmp()
        lines.append(f"    EcfValue {arr} = EcfValue::array();")
        for x in fs["UnionOf"]:
            sub = fspec_expr(x, lines)
            lines.append(f"    {arr}.push(std::move({sub}));")
        lines.append(f"    {v}.put(EcfValue::text(\"union_of\"), std::move({arr}));")
    kt = fs.get("KeyType") or ""
    if kt:
        lines.append(f"    {v}.put(EcfValue::text(\"key_type\"), EcfValue::text({cstr(kt)}));")
    bs = fs.get("ByteSize")
    if bs not in (None, 0):
        lines.append(f"    {v}.put(EcfValue::text(\"byte_size\"), EcfValue::uint({bs}ULL));")
    return v


def type_builder(name, s):
    lines = []
    lines.append("EcfValue build_%s() {" % cident(name))
    lines.append("    EcfValue m = EcfValue::map();")
    lines.append(f"    m.put(EcfValue::text(\"name\"), EcfValue::text({cstr(name)}));")
    flds = s.get("Fields") or {}
    if flds:
        fm = newtmp()
        lines.append(f"    EcfValue {fm} = EcfValue::map();")
        for fn, fsv in flds.items():
            sub = fspec_expr(fsv, lines)
            lines.append(f"    {fm}.put(EcfValue::text({cstr(fn)}), std::move({sub}));")
        lines.append(f"    m.put(EcfValue::text(\"fields\"), std::move({fm}));")
    ext = s.get("Extends") or ""
    if ext:
        lines.append(f"    m.put(EcfValue::text(\"extends\"), EcfValue::text({cstr(ext)}));")
    lay = s.get("Layout") or []
    if lay:
        arr = newtmp()
        lines.append(f"    EcfValue {arr} = EcfValue::array();")
        for x in lay:
            lines.append(f"    {arr}.push(EcfValue::text({cstr(x)}));")
        lines.append(f"    m.put(EcfValue::text(\"layout\"), std::move({arr}));")
    lines.append("    return m;")
    lines.append("}")
    return "\n".join(lines)


def cident(name):
    return name.replace("/", "_").replace("-", "_")


out = []
out.append("// core_typedefs.cpp — GENERATED, do not hand-edit. The in-code §9.5 core-type")
out.append("// override table (render-from-model, V7 §9.5). 53 core types; each builder")
out.append("// returns the `data` EcfValue map of a `system/type` entity, whose content_hash")
out.append("// is computed by our own S2-green codec over {type,data}. Generated from the")
out.append("// shared cross-impl test-vectors (type-registry-shapes.json) by")
out.append("// tools/gen-typedefs.py; the rendered hashes are diffed byte-for-byte against")
out.append("// type-registry-vectors-v1 by the type-registry test. Regenerate on a V7 bump.")
out.append("//")
out.append("// SPDX-License-Identifier: Apache-2.0")
out.append('#include "entity_core/core_typedefs.hpp"')
out.append("")
out.append("namespace entity_core::types {")
out.append("")
out.append("using ecf::EcfValue;")
out.append("")
out.append("namespace {")
out.append("")

builders = []
for name in core_order:
    out.append(type_builder(name, by[name]))
    out.append("")
    builders.append((name, cident(name)))

out.append("}  // namespace")
out.append("")
out.append("const std::vector<CoreTypeDef>& core_typedefs() {")
out.append("    static const std::vector<CoreTypeDef> table = {")
for name, ident in builders:
    out.append(f"        {{ {cstr(name)}, build_{ident} }},")
out.append("    };")
out.append("    return table;")
out.append("}")
out.append("")
out.append("}  // namespace entity_core::types")

dst = "protocol-generator/cpp/src/core_typedefs.cpp"
open(dst, "w").write("\n".join(out) + "\n")
print(f"wrote {len(core_order)} core types to {dst}")
