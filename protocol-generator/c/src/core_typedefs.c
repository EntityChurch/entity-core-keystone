/*
 * core_typedefs.c — GENERATED, do not hand-edit. The in-code §9.5 core-type
 * override table (render-from-model, V7 §9.5). 53 core types; each builder
 * returns the `data` ec_value map of a `system/type` entity, whose content_hash
 * is computed by our own S2-green codec over {type,data}. Generated from the
 * shared cross-impl test-vectors (type-registry-shapes.json) by
 * tools/gen-typedefs.py; the rendered hashes are diffed byte-for-byte against
 * type-registry-vectors-v1 by the type-registry test. Regenerate on a V7 bump.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"
#include "core_typedefs.h"

#include <stdbool.h>
#include <stdlib.h>

/* put-text-kv: takes ownership of nothing on success; frees the value on OOM. */
static int put_t(ec_value *m, const char *key, const char *val)
{
    ec_value *k = ec_text(key);
    ec_value *v = ec_text(val);
    if (!k || !v || ec_map_put(m, k, v) != EC_OK) { ec_value_free(k); ec_value_free(v); return 1; }
    return 0;
}
static int put_bool(ec_value *m, const char *key, bool b)
{
    ec_value *k = ec_text(key);
    ec_value *v = ec_bool(b);
    if (!k || !v || ec_map_put(m, k, v) != EC_OK) { ec_value_free(k); ec_value_free(v); return 1; }
    return 0;
}
static int put_u(ec_value *m, const char *key, unsigned long long u)
{
    ec_value *k = ec_text(key);
    ec_value *v = ec_int_u((uint64_t)u);
    if (!k || !v || ec_map_put(m, k, v) != EC_OK) { ec_value_free(k); ec_value_free(v); return 1; }
    return 0;
}
/* put-value-kv: takes ownership of `val` (already built); frees both on OOM. */
static int put_v(ec_value *m, const char *key, ec_value *val)
{
    ec_value *k = ec_text(key);
    if (!k || !val || ec_map_put(m, k, val) != EC_OK) { ec_value_free(k); ec_value_free(val); return 1; }
    return 0;
}

static ec_value *build_primitive_any(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "primitive/any")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_primitive_bool(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "primitive/bool")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_primitive_bytes(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "primitive/bytes")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_primitive_float(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "primitive/float")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_primitive_int(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "primitive/int")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_primitive_null(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "primitive/null")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_primitive_string(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "primitive/string")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_primitive_uint(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "primitive/uint")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_entity(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "entity")) goto fail;
    ec_value *t1 = ec_map(); if (!t1) goto fail;
    ec_value *t2 = ec_map(); if (!t2) goto fail;
    if (put_t(t2, "type_ref", "primitive/any")) goto fail;
    if (put_v(t1, "data", t2)) goto fail;
    ec_value *t3 = ec_map(); if (!t3) goto fail;
    if (put_t(t3, "type_ref", "primitive/string")) goto fail;
    if (put_v(t1, "type", t3)) goto fail;
    if (put_v(m, "fields", t1)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_core_entity(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "core/entity")) goto fail;
    ec_value *t4 = ec_map(); if (!t4) goto fail;
    ec_value *t5 = ec_map(); if (!t5) goto fail;
    if (put_t(t5, "type_ref", "system/hash")) goto fail;
    if (put_v(t4, "content_hash", t5)) goto fail;
    ec_value *t6 = ec_map(); if (!t6) goto fail;
    if (put_t(t6, "type_ref", "primitive/any")) goto fail;
    if (put_v(t4, "data", t6)) goto fail;
    ec_value *t7 = ec_map(); if (!t7) goto fail;
    if (put_t(t7, "type_ref", "primitive/string")) goto fail;
    if (put_v(t4, "type", t7)) goto fail;
    if (put_v(m, "fields", t4)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_core_envelope(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "core/envelope")) goto fail;
    ec_value *t8 = ec_map(); if (!t8) goto fail;
    ec_value *t9 = ec_map(); if (!t9) goto fail;
    if (put_bool(t9, "optional", true)) goto fail;
    ec_value *t10 = ec_map(); if (!t10) goto fail;
    if (put_t(t10, "type_ref", "core/entity")) goto fail;
    if (put_v(t9, "map_of", t10)) goto fail;
    if (put_t(t9, "key_type", "system/hash")) goto fail;
    if (put_v(t8, "included", t9)) goto fail;
    ec_value *t11 = ec_map(); if (!t11) goto fail;
    if (put_t(t11, "type_ref", "core/entity")) goto fail;
    if (put_v(t8, "root", t11)) goto fail;
    if (put_v(m, "fields", t8)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_envelope(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/envelope")) goto fail;
    if (put_t(m, "extends", "core/envelope")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_protocol_envelope(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/protocol/envelope")) goto fail;
    if (put_t(m, "extends", "core/envelope")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_hash(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/hash")) goto fail;
    ec_value *t12 = ec_map(); if (!t12) goto fail;
    ec_value *t13 = ec_map(); if (!t13) goto fail;
    if (put_t(t13, "type_ref", "primitive/bytes")) goto fail;
    if (put_v(t12, "digest", t13)) goto fail;
    ec_value *t14 = ec_map(); if (!t14) goto fail;
    if (put_t(t14, "type_ref", "primitive/uint")) goto fail;
    if (put_u(t14, "byte_size", 1ULL)) goto fail;
    if (put_v(t12, "format_code", t14)) goto fail;
    if (put_v(m, "fields", t12)) goto fail;
    if (put_t(m, "extends", "primitive/bytes")) goto fail;
    ec_value *t15 = ec_array(); if (!t15) goto fail;
    { ec_value *e = ec_text("format_code"); if (!e || ec_array_push(t15, e) != EC_OK) { ec_value_free(e); goto fail; } }
    { ec_value *e = ec_text("digest"); if (!e || ec_array_push(t15, e) != EC_OK) { ec_value_free(e); goto fail; } }
    if (put_v(m, "layout", t15)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_peer(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/peer")) goto fail;
    ec_value *t16 = ec_map(); if (!t16) goto fail;
    ec_value *t17 = ec_map(); if (!t17) goto fail;
    if (put_t(t17, "type_ref", "primitive/string")) goto fail;
    if (put_v(t16, "key_type", t17)) goto fail;
    ec_value *t18 = ec_map(); if (!t18) goto fail;
    if (put_t(t18, "type_ref", "system/peer-id")) goto fail;
    if (put_v(t16, "peer_id", t18)) goto fail;
    ec_value *t19 = ec_map(); if (!t19) goto fail;
    if (put_t(t19, "type_ref", "primitive/bytes")) goto fail;
    if (put_v(t16, "public_key", t19)) goto fail;
    if (put_v(m, "fields", t16)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_peer_id(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/peer-id")) goto fail;
    if (put_t(m, "extends", "primitive/string")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_signature(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/signature")) goto fail;
    ec_value *t20 = ec_map(); if (!t20) goto fail;
    ec_value *t21 = ec_map(); if (!t21) goto fail;
    if (put_t(t21, "type_ref", "primitive/string")) goto fail;
    if (put_v(t20, "algorithm", t21)) goto fail;
    ec_value *t22 = ec_map(); if (!t22) goto fail;
    if (put_t(t22, "type_ref", "primitive/bytes")) goto fail;
    if (put_v(t20, "signature", t22)) goto fail;
    ec_value *t23 = ec_map(); if (!t23) goto fail;
    if (put_t(t23, "type_ref", "system/hash")) goto fail;
    if (put_v(t20, "signer", t23)) goto fail;
    ec_value *t24 = ec_map(); if (!t24) goto fail;
    if (put_t(t24, "type_ref", "system/hash")) goto fail;
    if (put_v(t20, "target", t24)) goto fail;
    if (put_v(m, "fields", t20)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_protocol_connect_authenticate(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/protocol/connect/authenticate")) goto fail;
    ec_value *t25 = ec_map(); if (!t25) goto fail;
    ec_value *t26 = ec_map(); if (!t26) goto fail;
    if (put_t(t26, "type_ref", "primitive/string")) goto fail;
    if (put_v(t25, "key_type", t26)) goto fail;
    ec_value *t27 = ec_map(); if (!t27) goto fail;
    if (put_t(t27, "type_ref", "primitive/bytes")) goto fail;
    if (put_v(t25, "nonce", t27)) goto fail;
    ec_value *t28 = ec_map(); if (!t28) goto fail;
    if (put_t(t28, "type_ref", "system/peer-id")) goto fail;
    if (put_v(t25, "peer_id", t28)) goto fail;
    ec_value *t29 = ec_map(); if (!t29) goto fail;
    if (put_t(t29, "type_ref", "primitive/bytes")) goto fail;
    if (put_v(t25, "public_key", t29)) goto fail;
    if (put_v(m, "fields", t25)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_protocol_connect_hello(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/protocol/connect/hello")) goto fail;
    ec_value *t30 = ec_map(); if (!t30) goto fail;
    ec_value *t31 = ec_map(); if (!t31) goto fail;
    if (put_bool(t31, "optional", true)) goto fail;
    ec_value *t32 = ec_map(); if (!t32) goto fail;
    if (put_t(t32, "type_ref", "primitive/string")) goto fail;
    if (put_v(t31, "array_of", t32)) goto fail;
    if (put_v(t30, "compression", t31)) goto fail;
    ec_value *t33 = ec_map(); if (!t33) goto fail;
    if (put_bool(t33, "optional", true)) goto fail;
    ec_value *t34 = ec_map(); if (!t34) goto fail;
    if (put_t(t34, "type_ref", "primitive/string")) goto fail;
    if (put_v(t33, "array_of", t34)) goto fail;
    if (put_v(t30, "encryption", t33)) goto fail;
    ec_value *t35 = ec_map(); if (!t35) goto fail;
    if (put_bool(t35, "optional", true)) goto fail;
    ec_value *t36 = ec_map(); if (!t36) goto fail;
    if (put_t(t36, "type_ref", "primitive/string")) goto fail;
    if (put_v(t35, "array_of", t36)) goto fail;
    if (put_v(t30, "hash_formats", t35)) goto fail;
    ec_value *t37 = ec_map(); if (!t37) goto fail;
    if (put_bool(t37, "optional", true)) goto fail;
    ec_value *t38 = ec_map(); if (!t38) goto fail;
    if (put_t(t38, "type_ref", "primitive/string")) goto fail;
    if (put_v(t37, "array_of", t38)) goto fail;
    if (put_v(t30, "key_types", t37)) goto fail;
    ec_value *t39 = ec_map(); if (!t39) goto fail;
    if (put_t(t39, "type_ref", "primitive/bytes")) goto fail;
    if (put_v(t30, "nonce", t39)) goto fail;
    ec_value *t40 = ec_map(); if (!t40) goto fail;
    if (put_t(t40, "type_ref", "system/peer-id")) goto fail;
    if (put_v(t30, "peer_id", t40)) goto fail;
    ec_value *t41 = ec_map(); if (!t41) goto fail;
    ec_value *t42 = ec_map(); if (!t42) goto fail;
    if (put_t(t42, "type_ref", "primitive/string")) goto fail;
    if (put_v(t41, "array_of", t42)) goto fail;
    if (put_v(t30, "protocols", t41)) goto fail;
    ec_value *t43 = ec_map(); if (!t43) goto fail;
    if (put_t(t43, "type_ref", "primitive/uint")) goto fail;
    if (put_v(t30, "timestamp", t43)) goto fail;
    if (put_v(m, "fields", t30)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_protocol_error(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/protocol/error")) goto fail;
    ec_value *t44 = ec_map(); if (!t44) goto fail;
    ec_value *t45 = ec_map(); if (!t45) goto fail;
    if (put_t(t45, "type_ref", "primitive/string")) goto fail;
    if (put_v(t44, "code", t45)) goto fail;
    ec_value *t46 = ec_map(); if (!t46) goto fail;
    if (put_t(t46, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t46, "optional", true)) goto fail;
    if (put_v(t44, "message", t46)) goto fail;
    ec_value *t47 = ec_map(); if (!t47) goto fail;
    if (put_t(t47, "type_ref", "system/hash")) goto fail;
    if (put_bool(t47, "optional", true)) goto fail;
    if (put_v(t44, "rejected_marker", t47)) goto fail;
    if (put_v(m, "fields", t44)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_protocol_execute(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/protocol/execute")) goto fail;
    ec_value *t48 = ec_map(); if (!t48) goto fail;
    ec_value *t49 = ec_map(); if (!t49) goto fail;
    if (put_t(t49, "type_ref", "system/hash")) goto fail;
    if (put_bool(t49, "optional", true)) goto fail;
    if (put_v(t48, "author", t49)) goto fail;
    ec_value *t50 = ec_map(); if (!t50) goto fail;
    if (put_t(t50, "type_ref", "system/bounds")) goto fail;
    if (put_bool(t50, "optional", true)) goto fail;
    if (put_v(t48, "bounds", t50)) goto fail;
    ec_value *t51 = ec_map(); if (!t51) goto fail;
    if (put_t(t51, "type_ref", "system/hash")) goto fail;
    if (put_bool(t51, "optional", true)) goto fail;
    if (put_v(t48, "capability", t51)) goto fail;
    ec_value *t52 = ec_map(); if (!t52) goto fail;
    if (put_t(t52, "type_ref", "system/delivery-spec")) goto fail;
    if (put_bool(t52, "optional", true)) goto fail;
    if (put_v(t48, "deliver_to", t52)) goto fail;
    ec_value *t53 = ec_map(); if (!t53) goto fail;
    if (put_t(t53, "type_ref", "system/hash")) goto fail;
    if (put_bool(t53, "optional", true)) goto fail;
    if (put_v(t48, "deliver_token", t53)) goto fail;
    ec_value *t54 = ec_map(); if (!t54) goto fail;
    if (put_t(t54, "type_ref", "system/durability-request")) goto fail;
    if (put_bool(t54, "optional", true)) goto fail;
    if (put_v(t48, "durability_request", t54)) goto fail;
    ec_value *t55 = ec_map(); if (!t55) goto fail;
    if (put_t(t55, "type_ref", "primitive/string")) goto fail;
    if (put_v(t48, "operation", t55)) goto fail;
    ec_value *t56 = ec_map(); if (!t56) goto fail;
    if (put_t(t56, "type_ref", "core/entity")) goto fail;
    if (put_v(t48, "params", t56)) goto fail;
    ec_value *t57 = ec_map(); if (!t57) goto fail;
    if (put_t(t57, "type_ref", "primitive/string")) goto fail;
    if (put_v(t48, "request_id", t57)) goto fail;
    ec_value *t58 = ec_map(); if (!t58) goto fail;
    if (put_t(t58, "type_ref", "system/protocol/resource-target")) goto fail;
    if (put_bool(t58, "optional", true)) goto fail;
    if (put_v(t48, "resource", t58)) goto fail;
    ec_value *t59 = ec_map(); if (!t59) goto fail;
    if (put_t(t59, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t48, "uri", t59)) goto fail;
    if (put_v(m, "fields", t48)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_protocol_execute_response(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/protocol/execute/response")) goto fail;
    ec_value *t60 = ec_map(); if (!t60) goto fail;
    ec_value *t61 = ec_map(); if (!t61) goto fail;
    if (put_t(t61, "type_ref", "system/durability-result")) goto fail;
    if (put_bool(t61, "optional", true)) goto fail;
    if (put_v(t60, "durability", t61)) goto fail;
    ec_value *t62 = ec_map(); if (!t62) goto fail;
    if (put_t(t62, "type_ref", "primitive/string")) goto fail;
    if (put_v(t60, "request_id", t62)) goto fail;
    ec_value *t63 = ec_map(); if (!t63) goto fail;
    if (put_t(t63, "type_ref", "core/entity")) goto fail;
    if (put_v(t60, "result", t63)) goto fail;
    ec_value *t64 = ec_map(); if (!t64) goto fail;
    if (put_t(t64, "type_ref", "primitive/uint")) goto fail;
    if (put_v(t60, "status", t64)) goto fail;
    if (put_v(m, "fields", t60)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_protocol_resource_target(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/protocol/resource-target")) goto fail;
    ec_value *t65 = ec_map(); if (!t65) goto fail;
    ec_value *t66 = ec_map(); if (!t66) goto fail;
    if (put_bool(t66, "optional", true)) goto fail;
    ec_value *t67 = ec_map(); if (!t67) goto fail;
    if (put_t(t67, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t66, "array_of", t67)) goto fail;
    if (put_v(t65, "exclude", t66)) goto fail;
    ec_value *t68 = ec_map(); if (!t68) goto fail;
    ec_value *t69 = ec_map(); if (!t69) goto fail;
    if (put_t(t69, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t68, "array_of", t69)) goto fail;
    if (put_v(t65, "targets", t68)) goto fail;
    if (put_v(m, "fields", t65)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_grant(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/grant")) goto fail;
    ec_value *t70 = ec_map(); if (!t70) goto fail;
    ec_value *t71 = ec_map(); if (!t71) goto fail;
    if (put_t(t71, "type_ref", "system/hash")) goto fail;
    if (put_v(t70, "token", t71)) goto fail;
    if (put_v(m, "fields", t70)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_grant_entry(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/grant-entry")) goto fail;
    ec_value *t72 = ec_map(); if (!t72) goto fail;
    ec_value *t73 = ec_map(); if (!t73) goto fail;
    if (put_bool(t73, "optional", true)) goto fail;
    ec_value *t74 = ec_map(); if (!t74) goto fail;
    if (put_t(t74, "type_ref", "primitive/any")) goto fail;
    if (put_v(t73, "map_of", t74)) goto fail;
    if (put_v(t72, "allowances", t73)) goto fail;
    ec_value *t75 = ec_map(); if (!t75) goto fail;
    if (put_bool(t75, "optional", true)) goto fail;
    ec_value *t76 = ec_map(); if (!t76) goto fail;
    if (put_t(t76, "type_ref", "primitive/any")) goto fail;
    if (put_v(t75, "map_of", t76)) goto fail;
    if (put_v(t72, "constraints", t75)) goto fail;
    ec_value *t77 = ec_map(); if (!t77) goto fail;
    if (put_t(t77, "type_ref", "system/capability/path-scope")) goto fail;
    if (put_v(t72, "handlers", t77)) goto fail;
    ec_value *t78 = ec_map(); if (!t78) goto fail;
    if (put_t(t78, "type_ref", "system/capability/id-scope")) goto fail;
    if (put_v(t72, "operations", t78)) goto fail;
    ec_value *t79 = ec_map(); if (!t79) goto fail;
    if (put_t(t79, "type_ref", "system/capability/id-scope")) goto fail;
    if (put_bool(t79, "optional", true)) goto fail;
    if (put_v(t72, "peers", t79)) goto fail;
    ec_value *t80 = ec_map(); if (!t80) goto fail;
    if (put_t(t80, "type_ref", "system/capability/path-scope")) goto fail;
    if (put_v(t72, "resources", t80)) goto fail;
    if (put_v(m, "fields", t72)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_id_scope(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/id-scope")) goto fail;
    ec_value *t81 = ec_map(); if (!t81) goto fail;
    ec_value *t82 = ec_map(); if (!t82) goto fail;
    if (put_bool(t82, "optional", true)) goto fail;
    ec_value *t83 = ec_map(); if (!t83) goto fail;
    if (put_t(t83, "type_ref", "primitive/string")) goto fail;
    if (put_v(t82, "array_of", t83)) goto fail;
    if (put_v(t81, "exclude", t82)) goto fail;
    ec_value *t84 = ec_map(); if (!t84) goto fail;
    ec_value *t85 = ec_map(); if (!t85) goto fail;
    if (put_t(t85, "type_ref", "primitive/string")) goto fail;
    if (put_v(t84, "array_of", t85)) goto fail;
    if (put_v(t81, "include", t84)) goto fail;
    if (put_v(m, "fields", t81)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_path_scope(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/path-scope")) goto fail;
    ec_value *t86 = ec_map(); if (!t86) goto fail;
    ec_value *t87 = ec_map(); if (!t87) goto fail;
    if (put_bool(t87, "optional", true)) goto fail;
    ec_value *t88 = ec_map(); if (!t88) goto fail;
    if (put_t(t88, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t87, "array_of", t88)) goto fail;
    if (put_v(t86, "exclude", t87)) goto fail;
    ec_value *t89 = ec_map(); if (!t89) goto fail;
    ec_value *t90 = ec_map(); if (!t90) goto fail;
    if (put_t(t90, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t89, "array_of", t90)) goto fail;
    if (put_v(t86, "include", t89)) goto fail;
    if (put_v(m, "fields", t86)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_request(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/request")) goto fail;
    ec_value *t91 = ec_map(); if (!t91) goto fail;
    ec_value *t92 = ec_map(); if (!t92) goto fail;
    ec_value *t93 = ec_map(); if (!t93) goto fail;
    if (put_t(t93, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t92, "array_of", t93)) goto fail;
    if (put_v(t91, "grants", t92)) goto fail;
    ec_value *t94 = ec_map(); if (!t94) goto fail;
    if (put_t(t94, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t94, "optional", true)) goto fail;
    if (put_v(t91, "ttl_ms", t94)) goto fail;
    if (put_v(m, "fields", t91)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_revocation(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/revocation")) goto fail;
    ec_value *t95 = ec_map(); if (!t95) goto fail;
    ec_value *t96 = ec_map(); if (!t96) goto fail;
    if (put_t(t96, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t96, "optional", true)) goto fail;
    if (put_v(t95, "reason", t96)) goto fail;
    ec_value *t97 = ec_map(); if (!t97) goto fail;
    if (put_t(t97, "type_ref", "primitive/uint")) goto fail;
    if (put_v(t95, "revoked_at", t97)) goto fail;
    ec_value *t98 = ec_map(); if (!t98) goto fail;
    if (put_t(t98, "type_ref", "system/hash")) goto fail;
    if (put_v(t95, "token", t98)) goto fail;
    if (put_v(m, "fields", t95)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_revoke_request(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/revoke-request")) goto fail;
    ec_value *t99 = ec_map(); if (!t99) goto fail;
    ec_value *t100 = ec_map(); if (!t100) goto fail;
    if (put_t(t100, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t100, "optional", true)) goto fail;
    if (put_v(t99, "reason", t100)) goto fail;
    ec_value *t101 = ec_map(); if (!t101) goto fail;
    if (put_t(t101, "type_ref", "system/hash")) goto fail;
    if (put_v(t99, "token", t101)) goto fail;
    if (put_v(m, "fields", t99)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_delegate_request(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/delegate-request")) goto fail;
    ec_value *t102 = ec_map(); if (!t102) goto fail;
    ec_value *t103 = ec_map(); if (!t103) goto fail;
    ec_value *t104 = ec_map(); if (!t104) goto fail;
    if (put_t(t104, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t103, "array_of", t104)) goto fail;
    if (put_v(t102, "grants", t103)) goto fail;
    ec_value *t105 = ec_map(); if (!t105) goto fail;
    if (put_t(t105, "type_ref", "system/hash")) goto fail;
    if (put_v(t102, "parent", t105)) goto fail;
    ec_value *t106 = ec_map(); if (!t106) goto fail;
    if (put_t(t106, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t106, "optional", true)) goto fail;
    if (put_v(t102, "ttl_ms", t106)) goto fail;
    if (put_v(m, "fields", t102)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_delegation_caveats(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/delegation-caveats")) goto fail;
    ec_value *t107 = ec_map(); if (!t107) goto fail;
    ec_value *t108 = ec_map(); if (!t108) goto fail;
    if (put_t(t108, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t108, "optional", true)) goto fail;
    if (put_v(t107, "max_delegation_depth", t108)) goto fail;
    ec_value *t109 = ec_map(); if (!t109) goto fail;
    if (put_t(t109, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t109, "optional", true)) goto fail;
    if (put_v(t107, "max_delegation_ttl", t109)) goto fail;
    ec_value *t110 = ec_map(); if (!t110) goto fail;
    if (put_t(t110, "type_ref", "primitive/bool")) goto fail;
    if (put_bool(t110, "optional", true)) goto fail;
    if (put_v(t107, "no_delegation", t110)) goto fail;
    if (put_v(m, "fields", t107)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_policy_entry(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/policy-entry")) goto fail;
    ec_value *t111 = ec_map(); if (!t111) goto fail;
    ec_value *t112 = ec_map(); if (!t112) goto fail;
    ec_value *t113 = ec_map(); if (!t113) goto fail;
    if (put_t(t113, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t112, "array_of", t113)) goto fail;
    if (put_v(t111, "grants", t112)) goto fail;
    ec_value *t114 = ec_map(); if (!t114) goto fail;
    if (put_t(t114, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t114, "optional", true)) goto fail;
    if (put_v(t111, "notes", t114)) goto fail;
    ec_value *t115 = ec_map(); if (!t115) goto fail;
    if (put_t(t115, "type_ref", "primitive/string")) goto fail;
    if (put_v(t111, "peer_pattern", t115)) goto fail;
    ec_value *t116 = ec_map(); if (!t116) goto fail;
    if (put_t(t116, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t116, "optional", true)) goto fail;
    if (put_v(t111, "ttl_ms", t116)) goto fail;
    if (put_v(m, "fields", t111)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_token(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/token")) goto fail;
    ec_value *t117 = ec_map(); if (!t117) goto fail;
    ec_value *t118 = ec_map(); if (!t118) goto fail;
    if (put_t(t118, "type_ref", "primitive/uint")) goto fail;
    if (put_v(t117, "created_at", t118)) goto fail;
    ec_value *t119 = ec_map(); if (!t119) goto fail;
    if (put_t(t119, "type_ref", "system/capability/delegation-caveats")) goto fail;
    if (put_bool(t119, "optional", true)) goto fail;
    if (put_v(t117, "delegation_caveats", t119)) goto fail;
    ec_value *t120 = ec_map(); if (!t120) goto fail;
    if (put_t(t120, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t120, "optional", true)) goto fail;
    if (put_v(t117, "expires_at", t120)) goto fail;
    ec_value *t121 = ec_map(); if (!t121) goto fail;
    if (put_t(t121, "type_ref", "system/hash")) goto fail;
    if (put_v(t117, "grantee", t121)) goto fail;
    ec_value *t122 = ec_map(); if (!t122) goto fail;
    ec_value *t123 = ec_array(); if (!t123) goto fail;
    ec_value *t124 = ec_map(); if (!t124) goto fail;
    if (put_t(t124, "type_ref", "system/hash")) goto fail;
    if (ec_array_push(t123, t124) != EC_OK) goto fail;
    ec_value *t125 = ec_map(); if (!t125) goto fail;
    if (put_t(t125, "type_ref", "system/capability/multi-granter")) goto fail;
    if (ec_array_push(t123, t125) != EC_OK) goto fail;
    if (put_v(t122, "union_of", t123)) goto fail;
    if (put_v(t117, "granter", t122)) goto fail;
    ec_value *t126 = ec_map(); if (!t126) goto fail;
    ec_value *t127 = ec_map(); if (!t127) goto fail;
    if (put_t(t127, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t126, "array_of", t127)) goto fail;
    if (put_v(t117, "grants", t126)) goto fail;
    ec_value *t128 = ec_map(); if (!t128) goto fail;
    if (put_t(t128, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t128, "optional", true)) goto fail;
    if (put_v(t117, "not_before", t128)) goto fail;
    ec_value *t129 = ec_map(); if (!t129) goto fail;
    if (put_t(t129, "type_ref", "system/hash")) goto fail;
    if (put_bool(t129, "optional", true)) goto fail;
    if (put_v(t117, "parent", t129)) goto fail;
    ec_value *t130 = ec_map(); if (!t130) goto fail;
    if (put_t(t130, "type_ref", "system/resource-limits")) goto fail;
    if (put_bool(t130, "optional", true)) goto fail;
    if (put_v(t117, "resource_limits", t130)) goto fail;
    if (put_v(m, "fields", t117)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_capability_multi_granter(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/capability/multi-granter")) goto fail;
    ec_value *t131 = ec_map(); if (!t131) goto fail;
    ec_value *t132 = ec_map(); if (!t132) goto fail;
    ec_value *t133 = ec_map(); if (!t133) goto fail;
    if (put_t(t133, "type_ref", "system/hash")) goto fail;
    if (put_v(t132, "array_of", t133)) goto fail;
    if (put_v(t131, "signers", t132)) goto fail;
    ec_value *t134 = ec_map(); if (!t134) goto fail;
    if (put_t(t134, "type_ref", "primitive/uint")) goto fail;
    if (put_v(t131, "threshold", t134)) goto fail;
    if (put_v(m, "fields", t131)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_handler(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/handler")) goto fail;
    ec_value *t135 = ec_map(); if (!t135) goto fail;
    ec_value *t136 = ec_map(); if (!t136) goto fail;
    if (put_t(t136, "type_ref", "system/tree/path")) goto fail;
    if (put_bool(t136, "optional", true)) goto fail;
    if (put_v(t135, "expression_path", t136)) goto fail;
    ec_value *t137 = ec_map(); if (!t137) goto fail;
    if (put_t(t137, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t135, "interface", t137)) goto fail;
    ec_value *t138 = ec_map(); if (!t138) goto fail;
    if (put_bool(t138, "optional", true)) goto fail;
    ec_value *t139 = ec_map(); if (!t139) goto fail;
    if (put_t(t139, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t138, "array_of", t139)) goto fail;
    if (put_v(t135, "internal_scope", t138)) goto fail;
    ec_value *t140 = ec_map(); if (!t140) goto fail;
    if (put_bool(t140, "optional", true)) goto fail;
    ec_value *t141 = ec_map(); if (!t141) goto fail;
    if (put_t(t141, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t140, "array_of", t141)) goto fail;
    if (put_v(t135, "max_scope", t140)) goto fail;
    if (put_v(m, "fields", t135)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_handler_interface(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/handler/interface")) goto fail;
    ec_value *t142 = ec_map(); if (!t142) goto fail;
    ec_value *t143 = ec_map(); if (!t143) goto fail;
    if (put_t(t143, "type_ref", "primitive/string")) goto fail;
    if (put_v(t142, "name", t143)) goto fail;
    ec_value *t144 = ec_map(); if (!t144) goto fail;
    ec_value *t145 = ec_map(); if (!t145) goto fail;
    if (put_t(t145, "type_ref", "system/handler/operation-spec")) goto fail;
    if (put_v(t144, "map_of", t145)) goto fail;
    if (put_v(t142, "operations", t144)) goto fail;
    ec_value *t146 = ec_map(); if (!t146) goto fail;
    if (put_t(t146, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t142, "pattern", t146)) goto fail;
    if (put_v(m, "fields", t142)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_handler_manifest(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/handler/manifest")) goto fail;
    ec_value *t147 = ec_map(); if (!t147) goto fail;
    ec_value *t148 = ec_map(); if (!t148) goto fail;
    if (put_t(t148, "type_ref", "system/tree/path")) goto fail;
    if (put_bool(t148, "optional", true)) goto fail;
    if (put_v(t147, "expression_path", t148)) goto fail;
    ec_value *t149 = ec_map(); if (!t149) goto fail;
    if (put_bool(t149, "optional", true)) goto fail;
    ec_value *t150 = ec_map(); if (!t150) goto fail;
    if (put_t(t150, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t149, "array_of", t150)) goto fail;
    if (put_v(t147, "internal_scope", t149)) goto fail;
    ec_value *t151 = ec_map(); if (!t151) goto fail;
    if (put_bool(t151, "optional", true)) goto fail;
    ec_value *t152 = ec_map(); if (!t152) goto fail;
    if (put_t(t152, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t151, "array_of", t152)) goto fail;
    if (put_v(t147, "max_scope", t151)) goto fail;
    ec_value *t153 = ec_map(); if (!t153) goto fail;
    if (put_t(t153, "type_ref", "primitive/string")) goto fail;
    if (put_v(t147, "name", t153)) goto fail;
    ec_value *t154 = ec_map(); if (!t154) goto fail;
    ec_value *t155 = ec_map(); if (!t155) goto fail;
    if (put_t(t155, "type_ref", "system/handler/operation-spec")) goto fail;
    if (put_v(t154, "map_of", t155)) goto fail;
    if (put_v(t147, "operations", t154)) goto fail;
    ec_value *t156 = ec_map(); if (!t156) goto fail;
    if (put_t(t156, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t147, "pattern", t156)) goto fail;
    if (put_v(m, "fields", t147)) goto fail;
    if (put_t(m, "extends", "system/handler/interface")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_handler_operation_spec(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/handler/operation-spec")) goto fail;
    ec_value *t157 = ec_map(); if (!t157) goto fail;
    ec_value *t158 = ec_map(); if (!t158) goto fail;
    if (put_t(t158, "type_ref", "system/type/name")) goto fail;
    if (put_bool(t158, "optional", true)) goto fail;
    if (put_v(t157, "input_type", t158)) goto fail;
    ec_value *t159 = ec_map(); if (!t159) goto fail;
    if (put_t(t159, "type_ref", "system/type/name")) goto fail;
    if (put_bool(t159, "optional", true)) goto fail;
    if (put_v(t157, "output_type", t159)) goto fail;
    if (put_v(m, "fields", t157)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_handler_register_request(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/handler/register-request")) goto fail;
    ec_value *t160 = ec_map(); if (!t160) goto fail;
    ec_value *t161 = ec_map(); if (!t161) goto fail;
    if (put_t(t161, "type_ref", "system/handler/manifest")) goto fail;
    if (put_v(t160, "manifest", t161)) goto fail;
    ec_value *t162 = ec_map(); if (!t162) goto fail;
    if (put_bool(t162, "optional", true)) goto fail;
    ec_value *t163 = ec_map(); if (!t163) goto fail;
    if (put_t(t163, "type_ref", "system/capability/grant-entry")) goto fail;
    if (put_v(t162, "array_of", t163)) goto fail;
    if (put_v(t160, "requested_scope", t162)) goto fail;
    ec_value *t164 = ec_map(); if (!t164) goto fail;
    if (put_bool(t164, "optional", true)) goto fail;
    ec_value *t165 = ec_map(); if (!t165) goto fail;
    if (put_t(t165, "type_ref", "system/type")) goto fail;
    if (put_v(t164, "map_of", t165)) goto fail;
    if (put_v(t160, "types", t164)) goto fail;
    if (put_v(m, "fields", t160)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_handler_register_result(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/handler/register-result")) goto fail;
    ec_value *t166 = ec_map(); if (!t166) goto fail;
    ec_value *t167 = ec_map(); if (!t167) goto fail;
    if (put_t(t167, "type_ref", "system/capability/token")) goto fail;
    if (put_v(t166, "grant", t167)) goto fail;
    ec_value *t168 = ec_map(); if (!t168) goto fail;
    if (put_t(t168, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t166, "pattern", t168)) goto fail;
    if (put_v(m, "fields", t166)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_tree_get_request(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/tree/get-request")) goto fail;
    ec_value *t169 = ec_map(); if (!t169) goto fail;
    ec_value *t170 = ec_map(); if (!t170) goto fail;
    if (put_t(t170, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t170, "optional", true)) goto fail;
    if (put_v(t169, "limit", t170)) goto fail;
    ec_value *t171 = ec_map(); if (!t171) goto fail;
    if (put_t(t171, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t171, "optional", true)) goto fail;
    if (put_v(t169, "mode", t171)) goto fail;
    ec_value *t172 = ec_map(); if (!t172) goto fail;
    if (put_t(t172, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t172, "optional", true)) goto fail;
    if (put_v(t169, "offset", t172)) goto fail;
    ec_value *t173 = ec_map(); if (!t173) goto fail;
    if (put_t(t173, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t173, "optional", true)) goto fail;
    if (put_v(t169, "tree_id", t173)) goto fail;
    if (put_v(m, "fields", t169)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_tree_put_request(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/tree/put-request")) goto fail;
    ec_value *t174 = ec_map(); if (!t174) goto fail;
    ec_value *t175 = ec_map(); if (!t175) goto fail;
    if (put_t(t175, "type_ref", "core/entity")) goto fail;
    if (put_bool(t175, "optional", true)) goto fail;
    if (put_v(t174, "entity", t175)) goto fail;
    ec_value *t176 = ec_map(); if (!t176) goto fail;
    if (put_t(t176, "type_ref", "system/hash")) goto fail;
    if (put_bool(t176, "optional", true)) goto fail;
    if (put_v(t174, "expected_hash", t176)) goto fail;
    ec_value *t177 = ec_map(); if (!t177) goto fail;
    if (put_t(t177, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t177, "optional", true)) goto fail;
    if (put_v(t174, "tree_id", t177)) goto fail;
    if (put_v(m, "fields", t174)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_tree_listing(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/tree/listing")) goto fail;
    ec_value *t178 = ec_map(); if (!t178) goto fail;
    ec_value *t179 = ec_map(); if (!t179) goto fail;
    if (put_t(t179, "type_ref", "primitive/uint")) goto fail;
    if (put_v(t178, "count", t179)) goto fail;
    ec_value *t180 = ec_map(); if (!t180) goto fail;
    ec_value *t181 = ec_map(); if (!t181) goto fail;
    if (put_t(t181, "type_ref", "system/tree/listing-entry")) goto fail;
    if (put_v(t180, "map_of", t181)) goto fail;
    if (put_v(t178, "entries", t180)) goto fail;
    ec_value *t182 = ec_map(); if (!t182) goto fail;
    if (put_t(t182, "type_ref", "system/hash")) goto fail;
    if (put_bool(t182, "optional", true)) goto fail;
    if (put_v(t178, "next_page", t182)) goto fail;
    ec_value *t183 = ec_map(); if (!t183) goto fail;
    if (put_t(t183, "type_ref", "primitive/uint")) goto fail;
    if (put_v(t178, "offset", t183)) goto fail;
    ec_value *t184 = ec_map(); if (!t184) goto fail;
    if (put_t(t184, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t178, "path", t184)) goto fail;
    if (put_v(m, "fields", t178)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_tree_listing_entry(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/tree/listing-entry")) goto fail;
    ec_value *t185 = ec_map(); if (!t185) goto fail;
    ec_value *t186 = ec_map(); if (!t186) goto fail;
    if (put_t(t186, "type_ref", "primitive/bool")) goto fail;
    if (put_v(t185, "has_children", t186)) goto fail;
    ec_value *t187 = ec_map(); if (!t187) goto fail;
    if (put_t(t187, "type_ref", "system/hash")) goto fail;
    if (put_bool(t187, "optional", true)) goto fail;
    if (put_v(t185, "hash", t187)) goto fail;
    if (put_v(m, "fields", t185)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_tree_path(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/tree/path")) goto fail;
    if (put_t(m, "extends", "primitive/string")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_type(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/type")) goto fail;
    ec_value *t188 = ec_map(); if (!t188) goto fail;
    ec_value *t189 = ec_map(); if (!t189) goto fail;
    if (put_t(t189, "type_ref", "system/type/name")) goto fail;
    if (put_bool(t189, "optional", true)) goto fail;
    if (put_v(t188, "extends", t189)) goto fail;
    ec_value *t190 = ec_map(); if (!t190) goto fail;
    if (put_bool(t190, "optional", true)) goto fail;
    ec_value *t191 = ec_map(); if (!t191) goto fail;
    if (put_t(t191, "type_ref", "system/type/field-spec")) goto fail;
    if (put_v(t190, "map_of", t191)) goto fail;
    if (put_v(t188, "fields", t190)) goto fail;
    ec_value *t192 = ec_map(); if (!t192) goto fail;
    if (put_bool(t192, "optional", true)) goto fail;
    ec_value *t193 = ec_map(); if (!t193) goto fail;
    if (put_t(t193, "type_ref", "primitive/string")) goto fail;
    if (put_v(t192, "array_of", t193)) goto fail;
    if (put_v(t188, "layout", t192)) goto fail;
    ec_value *t194 = ec_map(); if (!t194) goto fail;
    if (put_t(t194, "type_ref", "system/type/name")) goto fail;
    if (put_v(t188, "name", t194)) goto fail;
    ec_value *t195 = ec_map(); if (!t195) goto fail;
    if (put_bool(t195, "optional", true)) goto fail;
    ec_value *t196 = ec_map(); if (!t196) goto fail;
    if (put_t(t196, "type_ref", "system/type/name")) goto fail;
    if (put_v(t195, "map_of", t196)) goto fail;
    if (put_v(t188, "type_args", t195)) goto fail;
    ec_value *t197 = ec_map(); if (!t197) goto fail;
    if (put_bool(t197, "optional", true)) goto fail;
    ec_value *t198 = ec_map(); if (!t198) goto fail;
    if (put_t(t198, "type_ref", "primitive/string")) goto fail;
    if (put_v(t197, "array_of", t198)) goto fail;
    if (put_v(t188, "type_params", t197)) goto fail;
    if (put_v(m, "fields", t188)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_type_field_spec(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/type/field-spec")) goto fail;
    ec_value *t199 = ec_map(); if (!t199) goto fail;
    ec_value *t200 = ec_map(); if (!t200) goto fail;
    if (put_t(t200, "type_ref", "system/type/field-spec")) goto fail;
    if (put_bool(t200, "optional", true)) goto fail;
    if (put_v(t199, "array_of", t200)) goto fail;
    ec_value *t201 = ec_map(); if (!t201) goto fail;
    if (put_t(t201, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t201, "optional", true)) goto fail;
    if (put_v(t199, "byte_size", t201)) goto fail;
    ec_value *t202 = ec_map(); if (!t202) goto fail;
    if (put_bool(t202, "optional", true)) goto fail;
    ec_value *t203 = ec_map(); if (!t203) goto fail;
    if (put_t(t203, "type_ref", "core/entity")) goto fail;
    if (put_v(t202, "array_of", t203)) goto fail;
    if (put_v(t199, "constraints", t202)) goto fail;
    ec_value *t204 = ec_map(); if (!t204) goto fail;
    if (put_t(t204, "type_ref", "primitive/any")) goto fail;
    if (put_bool(t204, "optional", true)) goto fail;
    if (put_v(t199, "default", t204)) goto fail;
    ec_value *t205 = ec_map(); if (!t205) goto fail;
    if (put_t(t205, "type_ref", "system/type/name")) goto fail;
    if (put_bool(t205, "optional", true)) goto fail;
    if (put_v(t199, "key_type", t205)) goto fail;
    ec_value *t206 = ec_map(); if (!t206) goto fail;
    if (put_t(t206, "type_ref", "system/type/field-spec")) goto fail;
    if (put_bool(t206, "optional", true)) goto fail;
    if (put_v(t199, "map_of", t206)) goto fail;
    ec_value *t207 = ec_map(); if (!t207) goto fail;
    if (put_t(t207, "type_ref", "primitive/bool")) goto fail;
    if (put_bool(t207, "optional", true)) goto fail;
    if (put_v(t199, "optional", t207)) goto fail;
    ec_value *t208 = ec_map(); if (!t208) goto fail;
    if (put_bool(t208, "optional", true)) goto fail;
    ec_value *t209 = ec_map(); if (!t209) goto fail;
    if (put_t(t209, "type_ref", "system/type/name")) goto fail;
    if (put_v(t208, "map_of", t209)) goto fail;
    if (put_v(t199, "type_args", t208)) goto fail;
    ec_value *t210 = ec_map(); if (!t210) goto fail;
    if (put_t(t210, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t210, "optional", true)) goto fail;
    if (put_v(t199, "type_param", t210)) goto fail;
    ec_value *t211 = ec_map(); if (!t211) goto fail;
    if (put_t(t211, "type_ref", "system/type/name")) goto fail;
    if (put_bool(t211, "optional", true)) goto fail;
    if (put_v(t199, "type_ref", t211)) goto fail;
    ec_value *t212 = ec_map(); if (!t212) goto fail;
    if (put_bool(t212, "optional", true)) goto fail;
    ec_value *t213 = ec_map(); if (!t213) goto fail;
    if (put_t(t213, "type_ref", "system/type/field-spec")) goto fail;
    if (put_v(t212, "array_of", t213)) goto fail;
    if (put_v(t199, "union_of", t212)) goto fail;
    if (put_v(m, "fields", t199)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_type_name(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/type/name")) goto fail;
    if (put_t(m, "extends", "primitive/string")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_bounds(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/bounds")) goto fail;
    ec_value *t214 = ec_map(); if (!t214) goto fail;
    ec_value *t215 = ec_map(); if (!t215) goto fail;
    if (put_t(t215, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t215, "optional", true)) goto fail;
    if (put_v(t214, "budget", t215)) goto fail;
    ec_value *t216 = ec_map(); if (!t216) goto fail;
    if (put_t(t216, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t216, "optional", true)) goto fail;
    if (put_v(t214, "cascade_depth", t216)) goto fail;
    ec_value *t217 = ec_map(); if (!t217) goto fail;
    if (put_t(t217, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t217, "optional", true)) goto fail;
    if (put_v(t214, "chain_id", t217)) goto fail;
    ec_value *t218 = ec_map(); if (!t218) goto fail;
    if (put_t(t218, "type_ref", "primitive/string")) goto fail;
    if (put_bool(t218, "optional", true)) goto fail;
    if (put_v(t214, "parent_chain_id", t218)) goto fail;
    ec_value *t219 = ec_map(); if (!t219) goto fail;
    if (put_t(t219, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t219, "optional", true)) goto fail;
    if (put_v(t214, "ttl", t219)) goto fail;
    ec_value *t220 = ec_map(); if (!t220) goto fail;
    if (put_bool(t220, "optional", true)) goto fail;
    ec_value *t221 = ec_map(); if (!t221) goto fail;
    if (put_t(t221, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t220, "array_of", t221)) goto fail;
    if (put_v(t214, "visited", t220)) goto fail;
    if (put_v(m, "fields", t214)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_resource_limits(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/resource-limits")) goto fail;
    ec_value *t222 = ec_map(); if (!t222) goto fail;
    ec_value *t223 = ec_map(); if (!t223) goto fail;
    if (put_t(t223, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t223, "optional", true)) goto fail;
    if (put_v(t222, "max_budget", t223)) goto fail;
    ec_value *t224 = ec_map(); if (!t224) goto fail;
    if (put_t(t224, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t224, "optional", true)) goto fail;
    if (put_v(t222, "max_ttl", t224)) goto fail;
    ec_value *t225 = ec_map(); if (!t225) goto fail;
    if (put_t(t225, "type_ref", "primitive/uint")) goto fail;
    if (put_bool(t225, "optional", true)) goto fail;
    if (put_v(t222, "max_visited_length", t225)) goto fail;
    if (put_v(m, "fields", t222)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_delivery_spec(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/delivery-spec")) goto fail;
    ec_value *t226 = ec_map(); if (!t226) goto fail;
    ec_value *t227 = ec_map(); if (!t227) goto fail;
    if (put_t(t227, "type_ref", "primitive/string")) goto fail;
    if (put_v(t226, "operation", t227)) goto fail;
    ec_value *t228 = ec_map(); if (!t228) goto fail;
    if (put_t(t228, "type_ref", "system/tree/path")) goto fail;
    if (put_v(t226, "uri", t228)) goto fail;
    if (put_v(m, "fields", t226)) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

static ec_value *build_system_deletion_marker(void)
{
    ec_value *m = ec_map(); if (!m) goto fail;
    if (put_t(m, "name", "system/deletion-marker")) goto fail;
    return m;
fail:
    ec_value_free(m);
    return NULL;
}

const ec_core_typedef ec_core_typedefs[] = {
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

const size_t ec_core_typedefs_count = sizeof(ec_core_typedefs) / sizeof(ec_core_typedefs[0]);
