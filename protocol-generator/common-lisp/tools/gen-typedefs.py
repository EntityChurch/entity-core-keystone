#!/usr/bin/env python3
# Generate src/type-defs-data.lisp — the in-code core-type override table
# (render-from-model design, V7 §9.5). Reads the cross-impl Go-rendered type model
# from the shared test-vectors (type-registry-shapes.json) and emits the 53 core
# types as Common Lisp cbor-map builder forms. Mirrors the OCaml peer's
# tools/gen-typedefs.py exactly (same 53-type core_order, same field-spec mapping)
# so the rendered content_hash is byte-identical to the canonical
# type-registry-vectors-v1 (diffed in test/type-registry.lisp).
#
# Regenerate on a V7 bump:
#   python3 protocol-generator/common-lisp/tools/gen-typedefs.py
import json

ROOT = "protocol-generator/shared/test-vectors/v0.8.0"
shapes = json.load(open(f"{ROOT}/type-registry-shapes.json"))

# The 53-type §9.5 core floor, identical order to the OCaml peer's generator.
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


def fspec_to_lisp(fs):
    # Build a (map-of "k" v ...) form. The CL canonical encoder re-sorts keys
    # per ECF Rule 2, so emit-order is immaterial to the content_hash; we keep
    # the OCaml field-emit order for readability.
    parts = []
    tr = fs.get("TypeRef") or ""
    if tr:
        parts.append(f'"type_ref" "{esc(tr)}"')
    if fs.get("Optional"):
        parts.append('"optional" :true')
    if fs.get("ArrayOf"):
        parts.append(f'"array_of" {fspec_to_lisp(fs["ArrayOf"])}')
    if fs.get("MapOf"):
        parts.append(f'"map_of" {fspec_to_lisp(fs["MapOf"])}')
    if fs.get("UnionOf"):
        elems = " ".join(fspec_to_lisp(x) for x in fs["UnionOf"])
        parts.append(f'"union_of" (list {elems})')
    kt = fs.get("KeyType") or ""
    if kt:
        parts.append(f'"key_type" "{esc(kt)}"')
    bs = fs.get("ByteSize")
    if bs not in (None, 0):
        parts.append(f'"byte_size" {bs}')
    return "(map-of " + " ".join(parts) + ")" if parts else "(map-of)"


def type_to_lisp(s):
    parts = [f'"name" "{esc(s["Name"])}"']
    flds = s.get("Fields") or {}
    if flds:
        fparts = [f'"{esc(fn)}" {fspec_to_lisp(fs)}' for fn, fs in flds.items()]
        parts.append(f'"fields" (map-of {" ".join(fparts)})')
    ext = s.get("Extends") or ""
    if ext:
        parts.append(f'"extends" "{esc(ext)}"')
    lay = s.get("Layout") or []
    if lay:
        lparts = " ".join(f'"{esc(x)}"' for x in lay)
        parts.append(f'"layout" (list {lparts})')
    return "(map-of " + " ".join(parts) + ")"


out = []
out.append(";;;; type-defs-data.lisp — GENERATED from the shared test-vectors")
out.append(";;;; type-registry-shapes.json (the cross-impl Go-rendered type model).")
out.append(";;;; The in-code core-type override table (render-from-model design).")
out.append(";;;; 53 core types per V7 §9.5. Regenerate with tools/gen-typedefs.py on a")
out.append(";;;; V7 bump; diffed byte-for-byte against type-registry-vectors-v1 in")
out.append(";;;; test/type-registry.lisp.")
out.append("")
out.append("(in-package #:entity-core/peer)")
out.append("")
out.append(";; (type-name . data-cbor-map) for each of the 53 core types (§9.5). The data")
out.append(";; map is the `data' of a `system/type' entity; make-entity computes its hash.")
out.append("(defparameter +core-type-models+")
out.append("  (list")
for name in core_order:
    s = by[name]
    out.append(f'    (cons "{esc(name)}" {type_to_lisp(s)})')
out.append("    ))")
out.append("")
dst = "protocol-generator/common-lisp/src/type-defs-data.lisp"
open(dst, "w").write("\n".join(out) + "\n")
print(f"wrote {len(core_order)} core types to {dst}")
