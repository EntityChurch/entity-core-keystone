// core_typedefs.cpp — GENERATED, do not hand-edit. The in-code §9.5 core-type
// override table (render-from-model, V7 §9.5). 53 core types; each builder
// returns the `data` EcfValue map of a `system/type` entity, whose content_hash
// is computed by our own S2-green codec over {type,data}. Generated from the
// shared cross-impl test-vectors (type-registry-shapes.json) by
// tools/gen-typedefs.py; the rendered hashes are diffed byte-for-byte against
// type-registry-vectors-v1 by the type-registry test. Regenerate on a V7 bump.
//
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/core_typedefs.hpp"

namespace entity_core::types {

using ecf::EcfValue;

namespace {

EcfValue build_primitive_any() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("primitive/any"));
    return m;
}

EcfValue build_primitive_bool() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("primitive/bool"));
    return m;
}

EcfValue build_primitive_bytes() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("primitive/bytes"));
    return m;
}

EcfValue build_primitive_float() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("primitive/float"));
    return m;
}

EcfValue build_primitive_int() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("primitive/int"));
    return m;
}

EcfValue build_primitive_null() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("primitive/null"));
    return m;
}

EcfValue build_primitive_string() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("primitive/string"));
    return m;
}

EcfValue build_primitive_uint() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("primitive/uint"));
    return m;
}

EcfValue build_entity() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("entity"));
    EcfValue t1 = EcfValue::map();
    EcfValue t2 = EcfValue::map();
    t2.put(EcfValue::text("type_ref"), EcfValue::text("primitive/any"));
    t1.put(EcfValue::text("data"), std::move(t2));
    EcfValue t3 = EcfValue::map();
    t3.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t1.put(EcfValue::text("type"), std::move(t3));
    m.put(EcfValue::text("fields"), std::move(t1));
    return m;
}

EcfValue build_core_entity() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("core/entity"));
    EcfValue t4 = EcfValue::map();
    EcfValue t5 = EcfValue::map();
    t5.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t4.put(EcfValue::text("content_hash"), std::move(t5));
    EcfValue t6 = EcfValue::map();
    t6.put(EcfValue::text("type_ref"), EcfValue::text("primitive/any"));
    t4.put(EcfValue::text("data"), std::move(t6));
    EcfValue t7 = EcfValue::map();
    t7.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t4.put(EcfValue::text("type"), std::move(t7));
    m.put(EcfValue::text("fields"), std::move(t4));
    return m;
}

EcfValue build_core_envelope() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("core/envelope"));
    EcfValue t8 = EcfValue::map();
    EcfValue t9 = EcfValue::map();
    t9.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t10 = EcfValue::map();
    t10.put(EcfValue::text("type_ref"), EcfValue::text("core/entity"));
    t9.put(EcfValue::text("map_of"), std::move(t10));
    t9.put(EcfValue::text("key_type"), EcfValue::text("system/hash"));
    t8.put(EcfValue::text("included"), std::move(t9));
    EcfValue t11 = EcfValue::map();
    t11.put(EcfValue::text("type_ref"), EcfValue::text("core/entity"));
    t8.put(EcfValue::text("root"), std::move(t11));
    m.put(EcfValue::text("fields"), std::move(t8));
    return m;
}

EcfValue build_system_envelope() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/envelope"));
    m.put(EcfValue::text("extends"), EcfValue::text("core/envelope"));
    return m;
}

EcfValue build_system_protocol_envelope() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/protocol/envelope"));
    m.put(EcfValue::text("extends"), EcfValue::text("core/envelope"));
    return m;
}

EcfValue build_system_hash() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/hash"));
    EcfValue t12 = EcfValue::map();
    EcfValue t13 = EcfValue::map();
    t13.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bytes"));
    t12.put(EcfValue::text("digest"), std::move(t13));
    EcfValue t14 = EcfValue::map();
    t14.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t14.put(EcfValue::text("byte_size"), EcfValue::uint(1ULL));
    t12.put(EcfValue::text("format_code"), std::move(t14));
    m.put(EcfValue::text("fields"), std::move(t12));
    m.put(EcfValue::text("extends"), EcfValue::text("primitive/bytes"));
    EcfValue t15 = EcfValue::array();
    t15.push(EcfValue::text("format_code"));
    t15.push(EcfValue::text("digest"));
    m.put(EcfValue::text("layout"), std::move(t15));
    return m;
}

EcfValue build_system_peer() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/peer"));
    EcfValue t16 = EcfValue::map();
    EcfValue t17 = EcfValue::map();
    t17.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t16.put(EcfValue::text("key_type"), std::move(t17));
    EcfValue t18 = EcfValue::map();
    t18.put(EcfValue::text("type_ref"), EcfValue::text("system/peer-id"));
    t16.put(EcfValue::text("peer_id"), std::move(t18));
    EcfValue t19 = EcfValue::map();
    t19.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bytes"));
    t16.put(EcfValue::text("public_key"), std::move(t19));
    m.put(EcfValue::text("fields"), std::move(t16));
    return m;
}

EcfValue build_system_peer_id() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/peer-id"));
    m.put(EcfValue::text("extends"), EcfValue::text("primitive/string"));
    return m;
}

EcfValue build_system_signature() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/signature"));
    EcfValue t20 = EcfValue::map();
    EcfValue t21 = EcfValue::map();
    t21.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t20.put(EcfValue::text("algorithm"), std::move(t21));
    EcfValue t22 = EcfValue::map();
    t22.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bytes"));
    t20.put(EcfValue::text("signature"), std::move(t22));
    EcfValue t23 = EcfValue::map();
    t23.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t20.put(EcfValue::text("signer"), std::move(t23));
    EcfValue t24 = EcfValue::map();
    t24.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t20.put(EcfValue::text("target"), std::move(t24));
    m.put(EcfValue::text("fields"), std::move(t20));
    return m;
}

EcfValue build_system_protocol_connect_authenticate() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/protocol/connect/authenticate"));
    EcfValue t25 = EcfValue::map();
    EcfValue t26 = EcfValue::map();
    t26.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t25.put(EcfValue::text("key_type"), std::move(t26));
    EcfValue t27 = EcfValue::map();
    t27.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bytes"));
    t25.put(EcfValue::text("nonce"), std::move(t27));
    EcfValue t28 = EcfValue::map();
    t28.put(EcfValue::text("type_ref"), EcfValue::text("system/peer-id"));
    t25.put(EcfValue::text("peer_id"), std::move(t28));
    EcfValue t29 = EcfValue::map();
    t29.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bytes"));
    t25.put(EcfValue::text("public_key"), std::move(t29));
    m.put(EcfValue::text("fields"), std::move(t25));
    return m;
}

EcfValue build_system_protocol_connect_hello() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/protocol/connect/hello"));
    EcfValue t30 = EcfValue::map();
    EcfValue t31 = EcfValue::map();
    t31.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t32 = EcfValue::map();
    t32.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t31.put(EcfValue::text("array_of"), std::move(t32));
    t30.put(EcfValue::text("compression"), std::move(t31));
    EcfValue t33 = EcfValue::map();
    t33.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t34 = EcfValue::map();
    t34.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t33.put(EcfValue::text("array_of"), std::move(t34));
    t30.put(EcfValue::text("encryption"), std::move(t33));
    EcfValue t35 = EcfValue::map();
    t35.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t36 = EcfValue::map();
    t36.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t35.put(EcfValue::text("array_of"), std::move(t36));
    t30.put(EcfValue::text("hash_formats"), std::move(t35));
    EcfValue t37 = EcfValue::map();
    t37.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t38 = EcfValue::map();
    t38.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t37.put(EcfValue::text("array_of"), std::move(t38));
    t30.put(EcfValue::text("key_types"), std::move(t37));
    EcfValue t39 = EcfValue::map();
    t39.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bytes"));
    t30.put(EcfValue::text("nonce"), std::move(t39));
    EcfValue t40 = EcfValue::map();
    t40.put(EcfValue::text("type_ref"), EcfValue::text("system/peer-id"));
    t30.put(EcfValue::text("peer_id"), std::move(t40));
    EcfValue t41 = EcfValue::map();
    EcfValue t42 = EcfValue::map();
    t42.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t41.put(EcfValue::text("array_of"), std::move(t42));
    t30.put(EcfValue::text("protocols"), std::move(t41));
    EcfValue t43 = EcfValue::map();
    t43.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t30.put(EcfValue::text("timestamp"), std::move(t43));
    m.put(EcfValue::text("fields"), std::move(t30));
    return m;
}

EcfValue build_system_protocol_error() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/protocol/error"));
    EcfValue t44 = EcfValue::map();
    EcfValue t45 = EcfValue::map();
    t45.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t44.put(EcfValue::text("code"), std::move(t45));
    EcfValue t46 = EcfValue::map();
    t46.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t46.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t44.put(EcfValue::text("message"), std::move(t46));
    EcfValue t47 = EcfValue::map();
    t47.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t47.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t44.put(EcfValue::text("rejected_marker"), std::move(t47));
    m.put(EcfValue::text("fields"), std::move(t44));
    return m;
}

EcfValue build_system_protocol_execute() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/protocol/execute"));
    EcfValue t48 = EcfValue::map();
    EcfValue t49 = EcfValue::map();
    t49.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t49.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t48.put(EcfValue::text("author"), std::move(t49));
    EcfValue t50 = EcfValue::map();
    t50.put(EcfValue::text("type_ref"), EcfValue::text("system/bounds"));
    t50.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t48.put(EcfValue::text("bounds"), std::move(t50));
    EcfValue t51 = EcfValue::map();
    t51.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t51.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t48.put(EcfValue::text("capability"), std::move(t51));
    EcfValue t52 = EcfValue::map();
    t52.put(EcfValue::text("type_ref"), EcfValue::text("system/delivery-spec"));
    t52.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t48.put(EcfValue::text("deliver_to"), std::move(t52));
    EcfValue t53 = EcfValue::map();
    t53.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t53.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t48.put(EcfValue::text("deliver_token"), std::move(t53));
    EcfValue t54 = EcfValue::map();
    t54.put(EcfValue::text("type_ref"), EcfValue::text("system/durability-request"));
    t54.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t48.put(EcfValue::text("durability_request"), std::move(t54));
    EcfValue t55 = EcfValue::map();
    t55.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t48.put(EcfValue::text("operation"), std::move(t55));
    EcfValue t56 = EcfValue::map();
    t56.put(EcfValue::text("type_ref"), EcfValue::text("core/entity"));
    t48.put(EcfValue::text("params"), std::move(t56));
    EcfValue t57 = EcfValue::map();
    t57.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t48.put(EcfValue::text("request_id"), std::move(t57));
    EcfValue t58 = EcfValue::map();
    t58.put(EcfValue::text("type_ref"), EcfValue::text("system/protocol/resource-target"));
    t58.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t48.put(EcfValue::text("resource"), std::move(t58));
    EcfValue t59 = EcfValue::map();
    t59.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t48.put(EcfValue::text("uri"), std::move(t59));
    m.put(EcfValue::text("fields"), std::move(t48));
    return m;
}

EcfValue build_system_protocol_execute_response() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/protocol/execute/response"));
    EcfValue t60 = EcfValue::map();
    EcfValue t61 = EcfValue::map();
    t61.put(EcfValue::text("type_ref"), EcfValue::text("system/durability-result"));
    t61.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t60.put(EcfValue::text("durability"), std::move(t61));
    EcfValue t62 = EcfValue::map();
    t62.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t60.put(EcfValue::text("request_id"), std::move(t62));
    EcfValue t63 = EcfValue::map();
    t63.put(EcfValue::text("type_ref"), EcfValue::text("core/entity"));
    t60.put(EcfValue::text("result"), std::move(t63));
    EcfValue t64 = EcfValue::map();
    t64.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t60.put(EcfValue::text("status"), std::move(t64));
    m.put(EcfValue::text("fields"), std::move(t60));
    return m;
}

EcfValue build_system_protocol_resource_target() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/protocol/resource-target"));
    EcfValue t65 = EcfValue::map();
    EcfValue t66 = EcfValue::map();
    t66.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t67 = EcfValue::map();
    t67.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t66.put(EcfValue::text("array_of"), std::move(t67));
    t65.put(EcfValue::text("exclude"), std::move(t66));
    EcfValue t68 = EcfValue::map();
    EcfValue t69 = EcfValue::map();
    t69.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t68.put(EcfValue::text("array_of"), std::move(t69));
    t65.put(EcfValue::text("targets"), std::move(t68));
    m.put(EcfValue::text("fields"), std::move(t65));
    return m;
}

EcfValue build_system_capability_grant() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/grant"));
    EcfValue t70 = EcfValue::map();
    EcfValue t71 = EcfValue::map();
    t71.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t70.put(EcfValue::text("token"), std::move(t71));
    m.put(EcfValue::text("fields"), std::move(t70));
    return m;
}

EcfValue build_system_capability_grant_entry() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/grant-entry"));
    EcfValue t72 = EcfValue::map();
    EcfValue t73 = EcfValue::map();
    t73.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t74 = EcfValue::map();
    t74.put(EcfValue::text("type_ref"), EcfValue::text("primitive/any"));
    t73.put(EcfValue::text("map_of"), std::move(t74));
    t72.put(EcfValue::text("allowances"), std::move(t73));
    EcfValue t75 = EcfValue::map();
    t75.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t76 = EcfValue::map();
    t76.put(EcfValue::text("type_ref"), EcfValue::text("primitive/any"));
    t75.put(EcfValue::text("map_of"), std::move(t76));
    t72.put(EcfValue::text("constraints"), std::move(t75));
    EcfValue t77 = EcfValue::map();
    t77.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/path-scope"));
    t72.put(EcfValue::text("handlers"), std::move(t77));
    EcfValue t78 = EcfValue::map();
    t78.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/id-scope"));
    t72.put(EcfValue::text("operations"), std::move(t78));
    EcfValue t79 = EcfValue::map();
    t79.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/id-scope"));
    t79.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t72.put(EcfValue::text("peers"), std::move(t79));
    EcfValue t80 = EcfValue::map();
    t80.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/path-scope"));
    t72.put(EcfValue::text("resources"), std::move(t80));
    m.put(EcfValue::text("fields"), std::move(t72));
    return m;
}

EcfValue build_system_capability_id_scope() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/id-scope"));
    EcfValue t81 = EcfValue::map();
    EcfValue t82 = EcfValue::map();
    t82.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t83 = EcfValue::map();
    t83.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t82.put(EcfValue::text("array_of"), std::move(t83));
    t81.put(EcfValue::text("exclude"), std::move(t82));
    EcfValue t84 = EcfValue::map();
    EcfValue t85 = EcfValue::map();
    t85.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t84.put(EcfValue::text("array_of"), std::move(t85));
    t81.put(EcfValue::text("include"), std::move(t84));
    m.put(EcfValue::text("fields"), std::move(t81));
    return m;
}

EcfValue build_system_capability_path_scope() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/path-scope"));
    EcfValue t86 = EcfValue::map();
    EcfValue t87 = EcfValue::map();
    t87.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t88 = EcfValue::map();
    t88.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t87.put(EcfValue::text("array_of"), std::move(t88));
    t86.put(EcfValue::text("exclude"), std::move(t87));
    EcfValue t89 = EcfValue::map();
    EcfValue t90 = EcfValue::map();
    t90.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t89.put(EcfValue::text("array_of"), std::move(t90));
    t86.put(EcfValue::text("include"), std::move(t89));
    m.put(EcfValue::text("fields"), std::move(t86));
    return m;
}

EcfValue build_system_capability_request() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/request"));
    EcfValue t91 = EcfValue::map();
    EcfValue t92 = EcfValue::map();
    EcfValue t93 = EcfValue::map();
    t93.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t92.put(EcfValue::text("array_of"), std::move(t93));
    t91.put(EcfValue::text("grants"), std::move(t92));
    EcfValue t94 = EcfValue::map();
    t94.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t94.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t91.put(EcfValue::text("ttl_ms"), std::move(t94));
    m.put(EcfValue::text("fields"), std::move(t91));
    return m;
}

EcfValue build_system_capability_revocation() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/revocation"));
    EcfValue t95 = EcfValue::map();
    EcfValue t96 = EcfValue::map();
    t96.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t96.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t95.put(EcfValue::text("reason"), std::move(t96));
    EcfValue t97 = EcfValue::map();
    t97.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t95.put(EcfValue::text("revoked_at"), std::move(t97));
    EcfValue t98 = EcfValue::map();
    t98.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t95.put(EcfValue::text("token"), std::move(t98));
    m.put(EcfValue::text("fields"), std::move(t95));
    return m;
}

EcfValue build_system_capability_revoke_request() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/revoke-request"));
    EcfValue t99 = EcfValue::map();
    EcfValue t100 = EcfValue::map();
    t100.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t100.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t99.put(EcfValue::text("reason"), std::move(t100));
    EcfValue t101 = EcfValue::map();
    t101.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t99.put(EcfValue::text("token"), std::move(t101));
    m.put(EcfValue::text("fields"), std::move(t99));
    return m;
}

EcfValue build_system_capability_delegate_request() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/delegate-request"));
    EcfValue t102 = EcfValue::map();
    EcfValue t103 = EcfValue::map();
    EcfValue t104 = EcfValue::map();
    t104.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t103.put(EcfValue::text("array_of"), std::move(t104));
    t102.put(EcfValue::text("grants"), std::move(t103));
    EcfValue t105 = EcfValue::map();
    t105.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t102.put(EcfValue::text("parent"), std::move(t105));
    EcfValue t106 = EcfValue::map();
    t106.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t106.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t102.put(EcfValue::text("ttl_ms"), std::move(t106));
    m.put(EcfValue::text("fields"), std::move(t102));
    return m;
}

EcfValue build_system_capability_delegation_caveats() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/delegation-caveats"));
    EcfValue t107 = EcfValue::map();
    EcfValue t108 = EcfValue::map();
    t108.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t108.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t107.put(EcfValue::text("max_delegation_depth"), std::move(t108));
    EcfValue t109 = EcfValue::map();
    t109.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t109.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t107.put(EcfValue::text("max_delegation_ttl"), std::move(t109));
    EcfValue t110 = EcfValue::map();
    t110.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bool"));
    t110.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t107.put(EcfValue::text("no_delegation"), std::move(t110));
    m.put(EcfValue::text("fields"), std::move(t107));
    return m;
}

EcfValue build_system_capability_policy_entry() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/policy-entry"));
    EcfValue t111 = EcfValue::map();
    EcfValue t112 = EcfValue::map();
    EcfValue t113 = EcfValue::map();
    t113.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t112.put(EcfValue::text("array_of"), std::move(t113));
    t111.put(EcfValue::text("grants"), std::move(t112));
    EcfValue t114 = EcfValue::map();
    t114.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t114.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t111.put(EcfValue::text("notes"), std::move(t114));
    EcfValue t115 = EcfValue::map();
    t115.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t111.put(EcfValue::text("peer_pattern"), std::move(t115));
    EcfValue t116 = EcfValue::map();
    t116.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t116.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t111.put(EcfValue::text("ttl_ms"), std::move(t116));
    m.put(EcfValue::text("fields"), std::move(t111));
    return m;
}

EcfValue build_system_capability_token() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/token"));
    EcfValue t117 = EcfValue::map();
    EcfValue t118 = EcfValue::map();
    t118.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t117.put(EcfValue::text("created_at"), std::move(t118));
    EcfValue t119 = EcfValue::map();
    t119.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/delegation-caveats"));
    t119.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t117.put(EcfValue::text("delegation_caveats"), std::move(t119));
    EcfValue t120 = EcfValue::map();
    t120.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t120.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t117.put(EcfValue::text("expires_at"), std::move(t120));
    EcfValue t121 = EcfValue::map();
    t121.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t117.put(EcfValue::text("grantee"), std::move(t121));
    EcfValue t122 = EcfValue::map();
    EcfValue t123 = EcfValue::array();
    EcfValue t124 = EcfValue::map();
    t124.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t123.push(std::move(t124));
    EcfValue t125 = EcfValue::map();
    t125.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/multi-granter"));
    t123.push(std::move(t125));
    t122.put(EcfValue::text("union_of"), std::move(t123));
    t117.put(EcfValue::text("granter"), std::move(t122));
    EcfValue t126 = EcfValue::map();
    EcfValue t127 = EcfValue::map();
    t127.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t126.put(EcfValue::text("array_of"), std::move(t127));
    t117.put(EcfValue::text("grants"), std::move(t126));
    EcfValue t128 = EcfValue::map();
    t128.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t128.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t117.put(EcfValue::text("not_before"), std::move(t128));
    EcfValue t129 = EcfValue::map();
    t129.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t129.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t117.put(EcfValue::text("parent"), std::move(t129));
    EcfValue t130 = EcfValue::map();
    t130.put(EcfValue::text("type_ref"), EcfValue::text("system/resource-limits"));
    t130.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t117.put(EcfValue::text("resource_limits"), std::move(t130));
    m.put(EcfValue::text("fields"), std::move(t117));
    return m;
}

EcfValue build_system_capability_multi_granter() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/capability/multi-granter"));
    EcfValue t131 = EcfValue::map();
    EcfValue t132 = EcfValue::map();
    EcfValue t133 = EcfValue::map();
    t133.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t132.put(EcfValue::text("array_of"), std::move(t133));
    t131.put(EcfValue::text("signers"), std::move(t132));
    EcfValue t134 = EcfValue::map();
    t134.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t131.put(EcfValue::text("threshold"), std::move(t134));
    m.put(EcfValue::text("fields"), std::move(t131));
    return m;
}

EcfValue build_system_handler() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/handler"));
    EcfValue t135 = EcfValue::map();
    EcfValue t136 = EcfValue::map();
    t136.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t136.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t135.put(EcfValue::text("expression_path"), std::move(t136));
    EcfValue t137 = EcfValue::map();
    t137.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t135.put(EcfValue::text("interface"), std::move(t137));
    EcfValue t138 = EcfValue::map();
    t138.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t139 = EcfValue::map();
    t139.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t138.put(EcfValue::text("array_of"), std::move(t139));
    t135.put(EcfValue::text("internal_scope"), std::move(t138));
    EcfValue t140 = EcfValue::map();
    t140.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t141 = EcfValue::map();
    t141.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t140.put(EcfValue::text("array_of"), std::move(t141));
    t135.put(EcfValue::text("max_scope"), std::move(t140));
    m.put(EcfValue::text("fields"), std::move(t135));
    return m;
}

EcfValue build_system_handler_interface() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/handler/interface"));
    EcfValue t142 = EcfValue::map();
    EcfValue t143 = EcfValue::map();
    t143.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t142.put(EcfValue::text("name"), std::move(t143));
    EcfValue t144 = EcfValue::map();
    EcfValue t145 = EcfValue::map();
    t145.put(EcfValue::text("type_ref"), EcfValue::text("system/handler/operation-spec"));
    t144.put(EcfValue::text("map_of"), std::move(t145));
    t142.put(EcfValue::text("operations"), std::move(t144));
    EcfValue t146 = EcfValue::map();
    t146.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t142.put(EcfValue::text("pattern"), std::move(t146));
    m.put(EcfValue::text("fields"), std::move(t142));
    return m;
}

EcfValue build_system_handler_manifest() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/handler/manifest"));
    EcfValue t147 = EcfValue::map();
    EcfValue t148 = EcfValue::map();
    t148.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t148.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t147.put(EcfValue::text("expression_path"), std::move(t148));
    EcfValue t149 = EcfValue::map();
    t149.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t150 = EcfValue::map();
    t150.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t149.put(EcfValue::text("array_of"), std::move(t150));
    t147.put(EcfValue::text("internal_scope"), std::move(t149));
    EcfValue t151 = EcfValue::map();
    t151.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t152 = EcfValue::map();
    t152.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t151.put(EcfValue::text("array_of"), std::move(t152));
    t147.put(EcfValue::text("max_scope"), std::move(t151));
    EcfValue t153 = EcfValue::map();
    t153.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t147.put(EcfValue::text("name"), std::move(t153));
    EcfValue t154 = EcfValue::map();
    EcfValue t155 = EcfValue::map();
    t155.put(EcfValue::text("type_ref"), EcfValue::text("system/handler/operation-spec"));
    t154.put(EcfValue::text("map_of"), std::move(t155));
    t147.put(EcfValue::text("operations"), std::move(t154));
    EcfValue t156 = EcfValue::map();
    t156.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t147.put(EcfValue::text("pattern"), std::move(t156));
    m.put(EcfValue::text("fields"), std::move(t147));
    m.put(EcfValue::text("extends"), EcfValue::text("system/handler/interface"));
    return m;
}

EcfValue build_system_handler_operation_spec() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/handler/operation-spec"));
    EcfValue t157 = EcfValue::map();
    EcfValue t158 = EcfValue::map();
    t158.put(EcfValue::text("type_ref"), EcfValue::text("system/type/name"));
    t158.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t157.put(EcfValue::text("input_type"), std::move(t158));
    EcfValue t159 = EcfValue::map();
    t159.put(EcfValue::text("type_ref"), EcfValue::text("system/type/name"));
    t159.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t157.put(EcfValue::text("output_type"), std::move(t159));
    m.put(EcfValue::text("fields"), std::move(t157));
    return m;
}

EcfValue build_system_handler_register_request() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/handler/register-request"));
    EcfValue t160 = EcfValue::map();
    EcfValue t161 = EcfValue::map();
    t161.put(EcfValue::text("type_ref"), EcfValue::text("system/handler/manifest"));
    t160.put(EcfValue::text("manifest"), std::move(t161));
    EcfValue t162 = EcfValue::map();
    t162.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t163 = EcfValue::map();
    t163.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/grant-entry"));
    t162.put(EcfValue::text("array_of"), std::move(t163));
    t160.put(EcfValue::text("requested_scope"), std::move(t162));
    EcfValue t164 = EcfValue::map();
    t164.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t165 = EcfValue::map();
    t165.put(EcfValue::text("type_ref"), EcfValue::text("system/type"));
    t164.put(EcfValue::text("map_of"), std::move(t165));
    t160.put(EcfValue::text("types"), std::move(t164));
    m.put(EcfValue::text("fields"), std::move(t160));
    return m;
}

EcfValue build_system_handler_register_result() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/handler/register-result"));
    EcfValue t166 = EcfValue::map();
    EcfValue t167 = EcfValue::map();
    t167.put(EcfValue::text("type_ref"), EcfValue::text("system/capability/token"));
    t166.put(EcfValue::text("grant"), std::move(t167));
    EcfValue t168 = EcfValue::map();
    t168.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t166.put(EcfValue::text("pattern"), std::move(t168));
    m.put(EcfValue::text("fields"), std::move(t166));
    return m;
}

EcfValue build_system_tree_get_request() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/tree/get-request"));
    EcfValue t169 = EcfValue::map();
    EcfValue t170 = EcfValue::map();
    t170.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t170.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t169.put(EcfValue::text("limit"), std::move(t170));
    EcfValue t171 = EcfValue::map();
    t171.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t171.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t169.put(EcfValue::text("mode"), std::move(t171));
    EcfValue t172 = EcfValue::map();
    t172.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t172.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t169.put(EcfValue::text("offset"), std::move(t172));
    EcfValue t173 = EcfValue::map();
    t173.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t173.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t169.put(EcfValue::text("tree_id"), std::move(t173));
    m.put(EcfValue::text("fields"), std::move(t169));
    return m;
}

EcfValue build_system_tree_put_request() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/tree/put-request"));
    EcfValue t174 = EcfValue::map();
    EcfValue t175 = EcfValue::map();
    t175.put(EcfValue::text("type_ref"), EcfValue::text("core/entity"));
    t175.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t174.put(EcfValue::text("entity"), std::move(t175));
    EcfValue t176 = EcfValue::map();
    t176.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t176.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t174.put(EcfValue::text("expected_hash"), std::move(t176));
    EcfValue t177 = EcfValue::map();
    t177.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t177.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t174.put(EcfValue::text("tree_id"), std::move(t177));
    m.put(EcfValue::text("fields"), std::move(t174));
    return m;
}

EcfValue build_system_tree_listing() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/tree/listing"));
    EcfValue t178 = EcfValue::map();
    EcfValue t179 = EcfValue::map();
    t179.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t178.put(EcfValue::text("count"), std::move(t179));
    EcfValue t180 = EcfValue::map();
    EcfValue t181 = EcfValue::map();
    t181.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/listing-entry"));
    t180.put(EcfValue::text("map_of"), std::move(t181));
    t178.put(EcfValue::text("entries"), std::move(t180));
    EcfValue t182 = EcfValue::map();
    t182.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t182.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t178.put(EcfValue::text("next_page"), std::move(t182));
    EcfValue t183 = EcfValue::map();
    t183.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t178.put(EcfValue::text("offset"), std::move(t183));
    EcfValue t184 = EcfValue::map();
    t184.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t178.put(EcfValue::text("path"), std::move(t184));
    m.put(EcfValue::text("fields"), std::move(t178));
    return m;
}

EcfValue build_system_tree_listing_entry() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/tree/listing-entry"));
    EcfValue t185 = EcfValue::map();
    EcfValue t186 = EcfValue::map();
    t186.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bool"));
    t185.put(EcfValue::text("has_children"), std::move(t186));
    EcfValue t187 = EcfValue::map();
    t187.put(EcfValue::text("type_ref"), EcfValue::text("system/hash"));
    t187.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t185.put(EcfValue::text("hash"), std::move(t187));
    m.put(EcfValue::text("fields"), std::move(t185));
    return m;
}

EcfValue build_system_tree_path() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/tree/path"));
    m.put(EcfValue::text("extends"), EcfValue::text("primitive/string"));
    return m;
}

EcfValue build_system_type() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/type"));
    EcfValue t188 = EcfValue::map();
    EcfValue t189 = EcfValue::map();
    t189.put(EcfValue::text("type_ref"), EcfValue::text("system/type/name"));
    t189.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t188.put(EcfValue::text("extends"), std::move(t189));
    EcfValue t190 = EcfValue::map();
    t190.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t191 = EcfValue::map();
    t191.put(EcfValue::text("type_ref"), EcfValue::text("system/type/field-spec"));
    t190.put(EcfValue::text("map_of"), std::move(t191));
    t188.put(EcfValue::text("fields"), std::move(t190));
    EcfValue t192 = EcfValue::map();
    t192.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t193 = EcfValue::map();
    t193.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t192.put(EcfValue::text("array_of"), std::move(t193));
    t188.put(EcfValue::text("layout"), std::move(t192));
    EcfValue t194 = EcfValue::map();
    t194.put(EcfValue::text("type_ref"), EcfValue::text("system/type/name"));
    t188.put(EcfValue::text("name"), std::move(t194));
    EcfValue t195 = EcfValue::map();
    t195.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t196 = EcfValue::map();
    t196.put(EcfValue::text("type_ref"), EcfValue::text("system/type/name"));
    t195.put(EcfValue::text("map_of"), std::move(t196));
    t188.put(EcfValue::text("type_args"), std::move(t195));
    EcfValue t197 = EcfValue::map();
    t197.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t198 = EcfValue::map();
    t198.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t197.put(EcfValue::text("array_of"), std::move(t198));
    t188.put(EcfValue::text("type_params"), std::move(t197));
    m.put(EcfValue::text("fields"), std::move(t188));
    return m;
}

EcfValue build_system_type_field_spec() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/type/field-spec"));
    EcfValue t199 = EcfValue::map();
    EcfValue t200 = EcfValue::map();
    t200.put(EcfValue::text("type_ref"), EcfValue::text("system/type/field-spec"));
    t200.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t199.put(EcfValue::text("array_of"), std::move(t200));
    EcfValue t201 = EcfValue::map();
    t201.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t201.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t199.put(EcfValue::text("byte_size"), std::move(t201));
    EcfValue t202 = EcfValue::map();
    t202.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t203 = EcfValue::map();
    t203.put(EcfValue::text("type_ref"), EcfValue::text("core/entity"));
    t202.put(EcfValue::text("array_of"), std::move(t203));
    t199.put(EcfValue::text("constraints"), std::move(t202));
    EcfValue t204 = EcfValue::map();
    t204.put(EcfValue::text("type_ref"), EcfValue::text("primitive/any"));
    t204.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t199.put(EcfValue::text("default"), std::move(t204));
    EcfValue t205 = EcfValue::map();
    t205.put(EcfValue::text("type_ref"), EcfValue::text("system/type/name"));
    t205.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t199.put(EcfValue::text("key_type"), std::move(t205));
    EcfValue t206 = EcfValue::map();
    t206.put(EcfValue::text("type_ref"), EcfValue::text("system/type/field-spec"));
    t206.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t199.put(EcfValue::text("map_of"), std::move(t206));
    EcfValue t207 = EcfValue::map();
    t207.put(EcfValue::text("type_ref"), EcfValue::text("primitive/bool"));
    t207.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t199.put(EcfValue::text("optional"), std::move(t207));
    EcfValue t208 = EcfValue::map();
    t208.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t209 = EcfValue::map();
    t209.put(EcfValue::text("type_ref"), EcfValue::text("system/type/name"));
    t208.put(EcfValue::text("map_of"), std::move(t209));
    t199.put(EcfValue::text("type_args"), std::move(t208));
    EcfValue t210 = EcfValue::map();
    t210.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t210.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t199.put(EcfValue::text("type_param"), std::move(t210));
    EcfValue t211 = EcfValue::map();
    t211.put(EcfValue::text("type_ref"), EcfValue::text("system/type/name"));
    t211.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t199.put(EcfValue::text("type_ref"), std::move(t211));
    EcfValue t212 = EcfValue::map();
    t212.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t213 = EcfValue::map();
    t213.put(EcfValue::text("type_ref"), EcfValue::text("system/type/field-spec"));
    t212.put(EcfValue::text("array_of"), std::move(t213));
    t199.put(EcfValue::text("union_of"), std::move(t212));
    m.put(EcfValue::text("fields"), std::move(t199));
    return m;
}

EcfValue build_system_type_name() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/type/name"));
    m.put(EcfValue::text("extends"), EcfValue::text("primitive/string"));
    return m;
}

EcfValue build_system_bounds() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/bounds"));
    EcfValue t214 = EcfValue::map();
    EcfValue t215 = EcfValue::map();
    t215.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t215.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t214.put(EcfValue::text("budget"), std::move(t215));
    EcfValue t216 = EcfValue::map();
    t216.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t216.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t214.put(EcfValue::text("cascade_depth"), std::move(t216));
    EcfValue t217 = EcfValue::map();
    t217.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t217.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t214.put(EcfValue::text("chain_id"), std::move(t217));
    EcfValue t218 = EcfValue::map();
    t218.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t218.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t214.put(EcfValue::text("parent_chain_id"), std::move(t218));
    EcfValue t219 = EcfValue::map();
    t219.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t219.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t214.put(EcfValue::text("ttl"), std::move(t219));
    EcfValue t220 = EcfValue::map();
    t220.put(EcfValue::text("optional"), EcfValue::boolean(true));
    EcfValue t221 = EcfValue::map();
    t221.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t220.put(EcfValue::text("array_of"), std::move(t221));
    t214.put(EcfValue::text("visited"), std::move(t220));
    m.put(EcfValue::text("fields"), std::move(t214));
    return m;
}

EcfValue build_system_resource_limits() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/resource-limits"));
    EcfValue t222 = EcfValue::map();
    EcfValue t223 = EcfValue::map();
    t223.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t223.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t222.put(EcfValue::text("max_budget"), std::move(t223));
    EcfValue t224 = EcfValue::map();
    t224.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t224.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t222.put(EcfValue::text("max_ttl"), std::move(t224));
    EcfValue t225 = EcfValue::map();
    t225.put(EcfValue::text("type_ref"), EcfValue::text("primitive/uint"));
    t225.put(EcfValue::text("optional"), EcfValue::boolean(true));
    t222.put(EcfValue::text("max_visited_length"), std::move(t225));
    m.put(EcfValue::text("fields"), std::move(t222));
    return m;
}

EcfValue build_system_delivery_spec() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/delivery-spec"));
    EcfValue t226 = EcfValue::map();
    EcfValue t227 = EcfValue::map();
    t227.put(EcfValue::text("type_ref"), EcfValue::text("primitive/string"));
    t226.put(EcfValue::text("operation"), std::move(t227));
    EcfValue t228 = EcfValue::map();
    t228.put(EcfValue::text("type_ref"), EcfValue::text("system/tree/path"));
    t226.put(EcfValue::text("uri"), std::move(t228));
    m.put(EcfValue::text("fields"), std::move(t226));
    return m;
}

EcfValue build_system_deletion_marker() {
    EcfValue m = EcfValue::map();
    m.put(EcfValue::text("name"), EcfValue::text("system/deletion-marker"));
    return m;
}

}  // namespace

const std::vector<CoreTypeDef>& core_typedefs() {
    static const std::vector<CoreTypeDef> table = {
        { "primitive/any", build_primitive_any },
        { "primitive/bool", build_primitive_bool },
        { "primitive/bytes", build_primitive_bytes },
        { "primitive/float", build_primitive_float },
        { "primitive/int", build_primitive_int },
        { "primitive/null", build_primitive_null },
        { "primitive/string", build_primitive_string },
        { "primitive/uint", build_primitive_uint },
        { "entity", build_entity },
        { "core/entity", build_core_entity },
        { "core/envelope", build_core_envelope },
        { "system/envelope", build_system_envelope },
        { "system/protocol/envelope", build_system_protocol_envelope },
        { "system/hash", build_system_hash },
        { "system/peer", build_system_peer },
        { "system/peer-id", build_system_peer_id },
        { "system/signature", build_system_signature },
        { "system/protocol/connect/authenticate", build_system_protocol_connect_authenticate },
        { "system/protocol/connect/hello", build_system_protocol_connect_hello },
        { "system/protocol/error", build_system_protocol_error },
        { "system/protocol/execute", build_system_protocol_execute },
        { "system/protocol/execute/response", build_system_protocol_execute_response },
        { "system/protocol/resource-target", build_system_protocol_resource_target },
        { "system/capability/grant", build_system_capability_grant },
        { "system/capability/grant-entry", build_system_capability_grant_entry },
        { "system/capability/id-scope", build_system_capability_id_scope },
        { "system/capability/path-scope", build_system_capability_path_scope },
        { "system/capability/request", build_system_capability_request },
        { "system/capability/revocation", build_system_capability_revocation },
        { "system/capability/revoke-request", build_system_capability_revoke_request },
        { "system/capability/delegate-request", build_system_capability_delegate_request },
        { "system/capability/delegation-caveats", build_system_capability_delegation_caveats },
        { "system/capability/policy-entry", build_system_capability_policy_entry },
        { "system/capability/token", build_system_capability_token },
        { "system/capability/multi-granter", build_system_capability_multi_granter },
        { "system/handler", build_system_handler },
        { "system/handler/interface", build_system_handler_interface },
        { "system/handler/manifest", build_system_handler_manifest },
        { "system/handler/operation-spec", build_system_handler_operation_spec },
        { "system/handler/register-request", build_system_handler_register_request },
        { "system/handler/register-result", build_system_handler_register_result },
        { "system/tree/get-request", build_system_tree_get_request },
        { "system/tree/put-request", build_system_tree_put_request },
        { "system/tree/listing", build_system_tree_listing },
        { "system/tree/listing-entry", build_system_tree_listing_entry },
        { "system/tree/path", build_system_tree_path },
        { "system/type", build_system_type },
        { "system/type/field-spec", build_system_type_field_spec },
        { "system/type/name", build_system_type_name },
        { "system/bounds", build_system_bounds },
        { "system/resource-limits", build_system_resource_limits },
        { "system/delivery-spec", build_system_delivery_spec },
        { "system/deletion-marker", build_system_deletion_marker },
    };
    return table;
}

}  // namespace entity_core::types
