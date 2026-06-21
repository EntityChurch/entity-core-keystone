#!/usr/bin/env python3
# Generate src/core_typedefs.c — the in-code §9.5 core-type override table
# (render-from-model, V7 §9.5). Reads the cross-impl Go-rendered type model from the
# shared test-vectors (type-registry-shapes.json) and emits the 53 core types as C
# ec_value map-builder forms. Mirrors the Java / OCaml / Common Lisp peers'
# tools/gen-typedefs.py exactly (same 53-type core_order, same field-spec mapping) so
# the rendered content_hash is byte-identical to the canonical
# type-registry-vectors-v1 (ECF Rule-2 canonical re-sort makes emit order immaterial
# to the hash).
#
# The data map is the `data` of a `system/type` entity; ec_entity_make computes its
# content_hash via our own S2-green codec.
#
# Regenerate on a V7 bump (run from the repo root):
#   python3 protocol-generator/c/tools/gen-typedefs.py
import json

ROOT = "protocol-generator/shared/test-vectors/v0.8.0"
shapes = json.load(open(f"{ROOT}/type-registry-shapes.json"))

# The 53-type §9.5 core floor — identical name+order to the Java/OCaml/CL peer
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


# Each builder emits C statements that construct an ec_value* map into a fresh `m`
# using the put_t/put_arr helpers (declared in the emitted file). Every helper returns
# EC_OK/!=; on any failure the builder frees + returns NULL (goto fail). To keep the
# generated code flat and leak-safe we build sub-maps bottom-up into temporaries.

_tmp = 0


def newtmp():
    global _tmp
    _tmp += 1
    return f"t{_tmp}"


def fspec_expr(fs, lines):
    """Emit C building a field-spec ec_value* map; return the C var holding it."""
    v = newtmp()
    lines.append(f"    ec_value *{v} = ec_map(); if (!{v}) goto fail;")
    tr = fs.get("TypeRef") or ""
    if tr:
        lines.append(f"    if (put_t({v}, \"type_ref\", {cstr(tr)})) goto fail;")
    if fs.get("Optional"):
        lines.append(f"    if (put_bool({v}, \"optional\", true)) goto fail;")
    if fs.get("ArrayOf"):
        sub = fspec_expr(fs["ArrayOf"], lines)
        lines.append(f"    if (put_v({v}, \"array_of\", {sub})) goto fail;")
    if fs.get("MapOf"):
        sub = fspec_expr(fs["MapOf"], lines)
        lines.append(f"    if (put_v({v}, \"map_of\", {sub})) goto fail;")
    if fs.get("UnionOf"):
        arr = newtmp()
        lines.append(f"    ec_value *{arr} = ec_array(); if (!{arr}) goto fail;")
        for x in fs["UnionOf"]:
            sub = fspec_expr(x, lines)
            lines.append(f"    if (ec_array_push({arr}, {sub}) != EC_OK) goto fail;")
        lines.append(f"    if (put_v({v}, \"union_of\", {arr})) goto fail;")
    kt = fs.get("KeyType") or ""
    if kt:
        lines.append(f"    if (put_t({v}, \"key_type\", {cstr(kt)})) goto fail;")
    bs = fs.get("ByteSize")
    if bs not in (None, 0):
        lines.append(f"    if (put_u({v}, \"byte_size\", {bs}ULL)) goto fail;")
    return v


def type_builder(name, s):
    lines = []
    lines.append("static ec_value *build_%s(void)" % cident(name))
    lines.append("{")
    lines.append("    ec_value *m = ec_map(); if (!m) goto fail;")
    lines.append(f"    if (put_t(m, \"name\", {cstr(name)})) goto fail;")
    flds = s.get("Fields") or {}
    if flds:
        fm = newtmp()
        lines.append(f"    ec_value *{fm} = ec_map(); if (!{fm}) goto fail;")
        for fn, fsv in flds.items():
            sub = fspec_expr(fsv, lines)
            lines.append(f"    if (put_v({fm}, {cstr(fn)}, {sub})) goto fail;")
        lines.append(f"    if (put_v(m, \"fields\", {fm})) goto fail;")
    ext = s.get("Extends") or ""
    if ext:
        lines.append(f"    if (put_t(m, \"extends\", {cstr(ext)})) goto fail;")
    lay = s.get("Layout") or []
    if lay:
        arr = newtmp()
        lines.append(f"    ec_value *{arr} = ec_array(); if (!{arr}) goto fail;")
        for x in lay:
            lines.append(f"    {{ ec_value *e = ec_text({cstr(x)}); if (!e || ec_array_push({arr}, e) != EC_OK) {{ ec_value_free(e); goto fail; }} }}")
        lines.append(f"    if (put_v(m, \"layout\", {arr})) goto fail;")
    lines.append("    return m;")
    lines.append("fail:")
    lines.append("    ec_value_free(m);")
    lines.append("    return NULL;")
    lines.append("}")
    return "\n".join(lines)


def cident(name):
    return name.replace("/", "_").replace("-", "_")


out = []
out.append("/*")
out.append(" * core_typedefs.c — GENERATED, do not hand-edit. The in-code §9.5 core-type")
out.append(" * override table (render-from-model, V7 §9.5). 53 core types; each builder")
out.append(" * returns the `data` ec_value map of a `system/type` entity, whose content_hash")
out.append(" * is computed by our own S2-green codec over {type,data}. Generated from the")
out.append(" * shared cross-impl test-vectors (type-registry-shapes.json) by")
out.append(" * tools/gen-typedefs.py; the rendered hashes are diffed byte-for-byte against")
out.append(" * type-registry-vectors-v1 by the type-registry test. Regenerate on a V7 bump.")
out.append(" *")
out.append(" * SPDX-License-Identifier: Apache-2.0")
out.append(" */")
out.append('#include "peer_internal.h"')
out.append('#include "core_typedefs.h"')
out.append("")
out.append("#include <stdbool.h>")
out.append("#include <stdlib.h>")
out.append("")
out.append("/* put-text-kv: takes ownership of nothing on success; frees the value on OOM. */")
out.append("static int put_t(ec_value *m, const char *key, const char *val)")
out.append("{")
out.append("    ec_value *k = ec_text(key);")
out.append("    ec_value *v = ec_text(val);")
out.append("    if (!k || !v || ec_map_put(m, k, v) != EC_OK) { ec_value_free(k); ec_value_free(v); return 1; }")
out.append("    return 0;")
out.append("}")
out.append("static int put_bool(ec_value *m, const char *key, bool b)")
out.append("{")
out.append("    ec_value *k = ec_text(key);")
out.append("    ec_value *v = ec_bool(b);")
out.append("    if (!k || !v || ec_map_put(m, k, v) != EC_OK) { ec_value_free(k); ec_value_free(v); return 1; }")
out.append("    return 0;")
out.append("}")
out.append("static int put_u(ec_value *m, const char *key, unsigned long long u)")
out.append("{")
out.append("    ec_value *k = ec_text(key);")
out.append("    ec_value *v = ec_int_u((uint64_t)u);")
out.append("    if (!k || !v || ec_map_put(m, k, v) != EC_OK) { ec_value_free(k); ec_value_free(v); return 1; }")
out.append("    return 0;")
out.append("}")
out.append("/* put-value-kv: takes ownership of `val` (already built); frees both on OOM. */")
out.append("static int put_v(ec_value *m, const char *key, ec_value *val)")
out.append("{")
out.append("    ec_value *k = ec_text(key);")
out.append("    if (!k || !val || ec_map_put(m, k, val) != EC_OK) { ec_value_free(k); ec_value_free(val); return 1; }")
out.append("    return 0;")
out.append("}")
out.append("")

builders = []
for name in core_order:
    out.append(type_builder(name, by[name]))
    out.append("")
    builders.append((name, cident(name)))

out.append("const ec_core_typedef ec_core_typedefs[] = {")
for name, ident in builders:
    out.append(f"    {{ {cstr(name)}, build_{ident} }},")
out.append("};")
out.append("")
out.append("const size_t ec_core_typedefs_count = sizeof(ec_core_typedefs) / sizeof(ec_core_typedefs[0]);")

dst = "protocol-generator/c/src/core_typedefs.c"
open(dst, "w").write("\n".join(out) + "\n")
print(f"wrote {len(core_order)} core types to {dst}")
