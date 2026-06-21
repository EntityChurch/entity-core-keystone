/*
 * wire.c — message builders (§3.2 EXECUTE / §3.3 EXECUTE_RESPONSE) + error result +
 * empty-params + resource-target. Framing (the 4-byte BE length prefix + body) lives in
 * transport.c; this file builds the envelope-payload entities.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wire.h"

#include <stdlib.h>
#include <string.h>

/* put a text key + value into a map, taking ownership; returns EC_OK / frees both on err. */
static ec_status put_kv(ec_value *map, const char *key, ec_value *val)
{
    if (!val) {
        return EC_ERR_OOM;
    }
    ec_value *k = ec_text(key);
    if (!k) {
        ec_value_free(val);
        return EC_ERR_OOM;
    }
    ec_status st = ec_map_put(map, k, val);
    if (st != EC_OK) {
        ec_value_free(k);
        ec_value_free(val);
    }
    return st;
}

ec_status ec_make_execute(const char *request_id, const char *uri, const char *operation,
                          ec_entity *params, const uint8_t *author, const uint8_t *capability,
                          ec_value *resource, ec_entity **out)
{
    ec_status st = EC_ERR_OOM;
    ec_value *m = ec_map();
    ec_value *params_cbor = NULL;
    if (!m) {
        goto cleanup;
    }
    if ((st = put_kv(m, "request_id", ec_text(request_id))) != EC_OK) { goto cleanup; }
    if ((st = put_kv(m, "uri", ec_text(uri))) != EC_OK) { goto cleanup; }
    if ((st = put_kv(m, "operation", ec_text(operation))) != EC_OK) { goto cleanup; }
    st = ec_entity_to_cbor(params, &params_cbor);
    if (st != EC_OK) { goto cleanup; }
    if ((st = put_kv(m, "params", params_cbor)) != EC_OK) { goto cleanup; }
    params_cbor = NULL;
    if (author) {
        if ((st = put_kv(m, "author", ec_bytes(author, 33))) != EC_OK) { goto cleanup; }
    }
    if (capability) {
        if ((st = put_kv(m, "capability", ec_bytes(capability, 33))) != EC_OK) { goto cleanup; }
    }
    if (resource) {
        if ((st = put_kv(m, "resource", resource)) != EC_OK) { goto cleanup; }
        resource = NULL;
    }
    st = ec_entity_make_owning("system/protocol/execute", m, out);
    return st;          /* m consumed by make_owning */
cleanup:
    ec_value_free(params_cbor);
    ec_value_free(resource);
    ec_value_free(m);
    return st;
}

ec_status ec_make_response(const char *request_id, uint64_t status, ec_entity *result,
                           ec_entity **out)
{
    ec_status st = EC_ERR_OOM;
    ec_value *m = ec_map();
    ec_value *result_cbor = NULL;
    if (!m) {
        goto cleanup;
    }
    if ((st = put_kv(m, "request_id", ec_text(request_id))) != EC_OK) { goto cleanup; }
    if ((st = put_kv(m, "status", ec_int_u(status))) != EC_OK) { goto cleanup; }
    st = ec_entity_to_cbor(result, &result_cbor);
    if (st != EC_OK) { goto cleanup; }
    if ((st = put_kv(m, "result", result_cbor)) != EC_OK) { goto cleanup; }
    result_cbor = NULL;
    return ec_entity_make_owning("system/protocol/execute/response", m, out);
cleanup:
    ec_value_free(result_cbor);
    ec_value_free(m);
    return st;
}

ec_status ec_error_result(const char *code, const char *message, ec_entity **out)
{
    ec_status st = EC_ERR_OOM;
    ec_value *m = ec_map();
    if (!m) {
        goto cleanup;
    }
    if ((st = put_kv(m, "code", ec_text(code))) != EC_OK) { goto cleanup; }
    if (message) {
        if ((st = put_kv(m, "message", ec_text(message))) != EC_OK) { goto cleanup; }
    }
    return ec_entity_make_owning("system/protocol/error", m, out);
cleanup:
    ec_value_free(m);
    return st;
}

ec_status ec_empty_params(ec_entity **out)
{
    ec_value *m = ec_map();      /* empty → 0xA0 (N3) */
    if (!m) {
        return EC_ERR_OOM;
    }
    return ec_entity_make_owning("primitive/any", m, out);
}

ec_status ec_resource_target(const char *target, ec_value **out)
{
    ec_value *m = ec_map();
    if (!m) {
        return EC_ERR_OOM;
    }
    ec_value *k = ec_text("targets");
    ec_value *arr = ec_array();
    ec_value *t = ec_text(target);
    if (!k || !arr || !t || ec_array_push(arr, t) != EC_OK) {
        ec_value_free(k); ec_value_free(arr); ec_value_free(t); ec_value_free(m);
        return EC_ERR_OOM;
    }
    if (ec_map_put(m, k, arr) != EC_OK) {
        ec_value_free(k); ec_value_free(arr); ec_value_free(m);
        return EC_ERR_OOM;
    }
    *out = m;
    return EC_OK;
}
