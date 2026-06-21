/*
 * entity.c — materialized entity {type,data,content_hash} (§1.1/§3.4), the value/
 * field-read helpers (the Cbor.java analogue), lowercase hex (§3.4/§3.5 A-CL-009),
 * and the §3.1 envelope. On top of the S2 codec (ec_value + ec_content_hash).
 *
 * Memory: entities are refcounted (shared between store/envelope/outcome). `data` is
 * owned (cloned in on make/parse). goto-cleanup on the error paths.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"

#include <stdlib.h>
#include <string.h>

/* ── materialized entity ────────────────────────────────────────────────────── */

/* Build the {type,data} hashable basis map and compute content_hash (sha256 floor). */
static ec_status compute_entity_hash(const char *type, const ec_value *data,
                                     uint8_t out_hash[33])
{
    ec_value *type_v = ec_text(type);
    if (!type_v) {
        return EC_ERR_OOM;
    }
    uint8_t *h = NULL;
    size_t hlen = 0;
    ec_status st = ec_content_hash(type_v, data, EC_CONTENT_HASH_FORMAT_SHA256, &h, &hlen);
    ec_value_free(type_v);
    if (st != EC_OK) {
        return st;
    }
    if (hlen != 33) {
        free(h);
        return EC_ERR_CRYPTO;
    }
    memcpy(out_hash, h, 33);
    free(h);
    return EC_OK;
}

ec_status ec_entity_make_owning(const char *type, ec_value *data, ec_entity **out)
{
    ec_status st;
    ec_entity *e = NULL;
    if (!type || !data || !out) {
        st = EC_ERR_BAD_INPUT;
        goto cleanup;
    }
    e = calloc(1, sizeof(*e));
    if (!e) {
        st = EC_ERR_OOM;
        goto cleanup;
    }
    e->type = strdup(type);
    if (!e->type) {
        st = EC_ERR_OOM;
        goto cleanup;
    }
    st = compute_entity_hash(type, data, e->hash);
    if (st != EC_OK) {
        goto cleanup;
    }
    e->data = data;             /* take ownership */
    e->refcount = 1;
    *out = e;
    return EC_OK;
cleanup:
    if (e) {
        free(e->type);
        free(e);
    }
    ec_value_free(data);
    return st;
}

ec_status ec_entity_make(const char *type, const ec_value *data, ec_entity **out)
{
    ec_value *copy = ec_value_clone(data);
    if (!copy) {
        return EC_ERR_OOM;
    }
    return ec_entity_make_owning(type, copy, out);
}

ec_entity *ec_entity_ref(ec_entity *e)
{
    if (e) {
        /* §4.8: atomic increment — shared entities are ref'd concurrently across the
         * per-EXECUTE dispatch threads; a relaxed bump is sufficient (it can only race
         * with another bump or a non-final drop, never with the free). */
        atomic_fetch_add_explicit(&e->refcount, 1, memory_order_relaxed);
    }
    return e;
}

void ec_entity_unref(ec_entity *e)
{
    if (!e) {
        return;
    }
    /* §4.8: atomic decrement with acquire/release ordering so the thread that drops the
     * last reference (and frees) sees all prior writes through this entity. */
    if (atomic_fetch_sub_explicit(&e->refcount, 1, memory_order_acq_rel) > 1) {
        return;
    }
    free(e->type);
    ec_value_free(e->data);
    free(e);
}

ec_status ec_entity_to_cbor(const ec_entity *e, ec_value **out)
{
    ec_status st = EC_ERR_OOM;
    ec_value *m = ec_map();
    ec_value *kt = NULL, *vt = NULL, *kd = NULL, *vd = NULL, *kh = NULL, *vh = NULL;
    if (!m) {
        goto cleanup;
    }
    kt = ec_text("type"); vt = ec_text(e->type);
    kd = ec_text("data"); vd = ec_value_clone(e->data);
    kh = ec_text("content_hash"); vh = ec_bytes(e->hash, 33);
    if (!kt || !vt || !kd || !vd || !kh || !vh) {
        goto cleanup;
    }
    if (ec_map_put(m, kt, vt) != EC_OK) { goto cleanup; }
    kt = vt = NULL;
    if (ec_map_put(m, kd, vd) != EC_OK) { goto cleanup; }
    kd = vd = NULL;
    if (ec_map_put(m, kh, vh) != EC_OK) { goto cleanup; }
    kh = vh = NULL;
    *out = m;
    return EC_OK;
cleanup:
    ec_value_free(kt); ec_value_free(vt);
    ec_value_free(kd); ec_value_free(vd);
    ec_value_free(kh); ec_value_free(vh);
    ec_value_free(m);
    return st;
}

ec_status ec_entity_to_wire(const ec_entity *e, uint8_t **out, size_t *out_len)
{
    ec_value *m = NULL;
    ec_status st = ec_entity_to_cbor(e, &m);
    if (st != EC_OK) {
        return st;
    }
    st = ec_ecf_encode(m, out, out_len);
    ec_value_free(m);
    return st;
}

ec_status ec_entity_of_cbor(const ec_value *m, ec_entity **out)
{
    if (!m || m->kind != EC_MAP) {
        return EC_ERR_BAD_INPUT;
    }
    const ec_value *type_v = ec_map_get(m, "type");
    const ec_value *data_v = ec_map_get(m, "data");
    if (!type_v || type_v->kind != EC_TEXT || !data_v) {
        return EC_ERR_BAD_INPUT;
    }
    ec_entity *e = NULL;
    ec_status st = ec_entity_make("", data_v, &e);  /* placeholder type, replaced below */
    if (st != EC_OK) {
        return st;
    }
    /* Replace placeholder type with the real one + recompute hash. */
    free(e->type);
    e->type = strndup((const char *)type_v->as.bytes.p, type_v->as.bytes.len);
    if (!e->type) {
        ec_entity_unref(e);
        return EC_ERR_OOM;
    }
    st = compute_entity_hash(e->type, e->data, e->hash);
    if (st != EC_OK) {
        ec_entity_unref(e);
        return st;
    }
    /* §1.8 fidelity: if a content_hash is carried, it MUST match our recompute. */
    const ec_value *carried = ec_map_get(m, "content_hash");
    if (carried && carried->kind == EC_BYTES) {
        if (carried->as.bytes.len != 33 || memcmp(carried->as.bytes.p, e->hash, 33) != 0) {
            ec_entity_unref(e);
            return EC_ERR_NON_CANONICAL_ECF;
        }
    }
    *out = e;
    return EC_OK;
}

/* ── entity field reads ─────────────────────────────────────────────────────── */

const char *ec_ent_text(const ec_entity *e, const char *key)
{
    return e ? ec_v_text(e->data, key) : NULL;
}

const uint8_t *ec_ent_bytes(const ec_entity *e, const char *key, size_t *len)
{
    return e ? ec_v_bytes(e->data, key, len) : NULL;
}

bool ec_ent_uint(const ec_entity *e, const char *key, uint64_t *out)
{
    return e ? ec_v_uint(e->data, key, out) : false;
}

const ec_value *ec_ent_field(const ec_entity *e, const char *key)
{
    return e ? ec_v_get(e->data, key) : NULL;
}

const ec_value *ec_ent_map_field(const ec_entity *e, const char *key)
{
    const ec_value *v = ec_ent_field(e, key);
    return (v && v->kind == EC_MAP) ? v : NULL;
}

ec_entity *ec_ent_entity_field(const ec_entity *e, const char *key)
{
    const ec_value *m = ec_ent_map_field(e, key);
    if (!m) {
        return NULL;
    }
    ec_entity *out = NULL;
    if (ec_entity_of_cbor(m, &out) != EC_OK) {
        return NULL;
    }
    return out;
}

/* ── value helpers ──────────────────────────────────────────────────────────── */

const char *ec_v_text(const ec_value *m, const char *key)
{
    const ec_value *v = ec_v_get(m, key);
    return (v && v->kind == EC_TEXT) ? (const char *)v->as.bytes.p : NULL;
}

const uint8_t *ec_v_bytes(const ec_value *m, const char *key, size_t *len)
{
    const ec_value *v = ec_v_get(m, key);
    if (v && v->kind == EC_BYTES) {
        if (len) { *len = v->as.bytes.len; }
        return v->as.bytes.p;
    }
    return NULL;
}

bool ec_v_uint(const ec_value *m, const char *key, uint64_t *out)
{
    const ec_value *v = ec_v_get(m, key);
    if (v && v->kind == EC_INT && !v->as.i.negative) {
        if (out) { *out = v->as.i.u; }
        return true;
    }
    return false;
}

const ec_value *ec_v_get(const ec_value *m, const char *key)
{
    return ec_map_get(m, key);
}

bool ec_v_is_true(const ec_value *v)
{
    return v && v->kind == EC_BOOL && v->as.b;
}

char *ec_hex(const uint8_t *p, size_t len)
{
    static const char hexc[] = "0123456789abcdef";   /* LOWERCASE (A-CL-009) */
    char *out = malloc(len * 2 + 1);
    if (!out) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hexc[p[i] >> 4];
        out[i * 2 + 1] = hexc[p[i] & 0x0f];
    }
    out[len * 2] = 0;
    return out;
}

ec_value *ec_v_text_array(const char *const *items, size_t n)
{
    ec_value *a = ec_array();
    if (!a) {
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        ec_value *t = ec_text(items[i]);
        if (!t || ec_array_push(a, t) != EC_OK) {
            ec_value_free(t);
            ec_value_free(a);
            return NULL;
        }
    }
    return a;
}

/* ── envelope (§3.1) ────────────────────────────────────────────────────────── */

ec_status ec_env_new(ec_entity *root, ec_envelope **out)
{
    if (!root || !out) {
        return EC_ERR_BAD_INPUT;
    }
    ec_envelope *env = calloc(1, sizeof(*env));
    if (!env) {
        return EC_ERR_OOM;
    }
    env->root = ec_entity_ref(root);
    *out = env;
    return EC_OK;
}

void ec_env_free(ec_envelope *env)
{
    if (!env) {
        return;
    }
    ec_entity_unref(env->root);
    for (size_t i = 0; i < env->included_len; i++) {
        ec_entity_unref(env->included[i].entity);
    }
    free(env->included);
    free(env);
}

ec_status ec_env_add(ec_envelope *env, ec_entity *entity)
{
    if (!env || !entity) {
        return EC_ERR_BAD_INPUT;
    }
    /* dedup by hash (§3.1 unique-key) */
    for (size_t i = 0; i < env->included_len; i++) {
        if (memcmp(env->included[i].hash, entity->hash, 33) == 0) {
            return EC_OK;
        }
    }
    if (env->included_len == env->included_cap) {
        size_t cap = env->included_cap ? env->included_cap * 2 : 4;
        ec_included *grown = realloc(env->included, cap * sizeof(*grown));
        if (!grown) {
            return EC_ERR_OOM;
        }
        env->included = grown;
        env->included_cap = cap;
    }
    memcpy(env->included[env->included_len].hash, entity->hash, 33);
    env->included[env->included_len].entity = ec_entity_ref(entity);
    env->included_len++;
    return EC_OK;
}

ec_entity *ec_env_get(const ec_envelope *env, const uint8_t *h33)
{
    if (!env || !h33) {
        return NULL;
    }
    for (size_t i = 0; i < env->included_len; i++) {
        if (memcmp(env->included[i].hash, h33, 33) == 0) {
            return env->included[i].entity;
        }
    }
    return NULL;
}

ec_status ec_env_to_wire(const ec_envelope *env, uint8_t **out, size_t *out_len)
{
    ec_status st = EC_ERR_OOM;
    ec_value *m = ec_map();
    ec_value *kr = NULL, *vr = NULL, *ki = NULL, *vi = NULL;
    if (!m) {
        goto cleanup;
    }
    kr = ec_text("root");
    if (!kr || ec_entity_to_cbor(env->root, &vr) != EC_OK) {
        goto cleanup;
    }
    if (ec_map_put(m, kr, vr) != EC_OK) {
        goto cleanup;
    }
    kr = vr = NULL;
    ki = ec_text("included");
    vi = ec_map();
    if (!ki || !vi) {
        goto cleanup;
    }
    for (size_t i = 0; i < env->included_len; i++) {
        ec_value *hk = ec_bytes(env->included[i].hash, 33);
        ec_value *ev = NULL;
        if (!hk || ec_entity_to_cbor(env->included[i].entity, &ev) != EC_OK) {
            ec_value_free(hk);
            goto cleanup;
        }
        if (ec_map_put(vi, hk, ev) != EC_OK) {
            ec_value_free(hk);
            ec_value_free(ev);
            goto cleanup;
        }
    }
    if (ec_map_put(m, ki, vi) != EC_OK) {
        goto cleanup;
    }
    ki = vi = NULL;
    st = ec_ecf_encode(m, out, out_len);
    ec_value_free(m);
    return st;
cleanup:
    ec_value_free(kr); ec_value_free(vr);
    ec_value_free(ki); ec_value_free(vi);
    ec_value_free(m);
    return st;
}

ec_status ec_env_of_wire(const uint8_t *in, size_t in_len, ec_envelope **out)
{
    ec_value *m = NULL;
    ec_status st = ec_ecf_decode(in, in_len, &m);
    if (st != EC_OK) {
        return st;
    }
    ec_entity *root = NULL;
    ec_envelope *env = NULL;
    const ec_value *root_v = ec_map_get(m, "root");
    if (!root_v || root_v->kind != EC_MAP) {
        st = EC_ERR_BAD_INPUT;
        goto cleanup;
    }
    st = ec_entity_of_cbor(root_v, &root);
    if (st != EC_OK) {
        goto cleanup;
    }
    st = ec_env_new(root, &env);
    if (st != EC_OK) {
        goto cleanup;
    }
    const ec_value *inc = ec_map_get(m, "included");
    if (inc && inc->kind == EC_MAP) {
        for (size_t i = 0; i < inc->as.map.len; i++) {
            const ec_value *k = inc->as.map.entries[i].key;
            const ec_value *v = inc->as.map.entries[i].val;
            if (!k || k->kind != EC_BYTES || k->as.bytes.len != 33 || !v || v->kind != EC_MAP) {
                st = EC_ERR_BAD_INPUT;
                goto cleanup;
            }
            ec_entity *ent = NULL;
            st = ec_entity_of_cbor(v, &ent);
            if (st != EC_OK) {
                goto cleanup;
            }
            /* §3.1: the included key MUST equal the entity's content_hash (N5). */
            if (memcmp(k->as.bytes.p, ent->hash, 33) != 0) {
                ec_entity_unref(ent);
                st = EC_ERR_NON_CANONICAL_ECF;
                goto cleanup;
            }
            st = ec_env_add(env, ent);
            ec_entity_unref(ent);
            if (st != EC_OK) {
                goto cleanup;
            }
        }
    }
    ec_entity_unref(root);
    ec_value_free(m);
    *out = env;
    return EC_OK;
cleanup:
    ec_env_free(env);
    ec_entity_unref(root);
    ec_value_free(m);
    return st;
}
