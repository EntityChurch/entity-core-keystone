/*
 * dispatch.c — the peer protocol brain (L1–L4): bootstrap (§6.9 / §6.9a), the four MUST
 * system handlers (§6.2: connect, tree, handler, capability), the §6.5 dispatch chain,
 * §6.6 backward handler resolution, §6.9a seed-policy derivation, the §7a conformance
 * handlers (behind --validate), and the §6.13(b) outbound seam.
 *
 * Idiom (the C return-code / single-dispatch-via-switch axis): a handler is a function
 * pointer `ec_handler_fn(ec_peer*, ec_conn*, const ec_envelope*, const ec_entity* exec,
 * ec_outcome*)` that switches over the operation string — the procedural analogue of the
 * Java single-dispatch `switch(op)` ladder (and the contrast with CL's CLOS multiple
 * dispatch). Each MUST handler is one such function, registered in a flat pattern→fn
 * table (the C namespace is flat; the table IS the §6.6 instance map).
 *
 * An outcome carries (status, result entity, included list). The dispatcher wraps it in
 * an EXECUTE_RESPONSE envelope. Errors are NEVER unwound — every fallible step returns a
 * status int and the handler returns an error Outcome (the inverse of Java's checked
 * exceptions; the §5.2 trichotomy 401/403/401-unresolvable maps a verdict → wire status).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"
#include "capability.h"
#include "core_typedefs.h"
#include "transport.h"
#include "wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── outcome ─────────────────────────────────────────────────────────────────── */

typedef struct ec_outcome {
    uint64_t status;
    ec_entity *result;          /* +1 ref */
    ec_entity **included;       /* +1 refs */
    size_t included_len, included_cap;
} ec_outcome;

static void outcome_init(ec_outcome *o)
{
    memset(o, 0, sizeof(*o));
}

static void outcome_clear(ec_outcome *o)
{
    ec_entity_unref(o->result);
    for (size_t i = 0; i < o->included_len; i++) {
        ec_entity_unref(o->included[i]);
    }
    free(o->included);
    memset(o, 0, sizeof(*o));
}

/* Set the outcome to OK with the given result (takes the +1 ref on result). */
static void outcome_ok(ec_outcome *o, ec_entity *result)
{
    o->status = 200;
    o->result = result;
}

/* Set the outcome to an error (status + code[/message]). Owns nothing on input. */
static void outcome_err(ec_outcome *o, uint64_t status, const char *code, const char *msg)
{
    ec_entity *r = NULL;
    if (ec_error_result(code, msg, &r) != EC_OK) {
        o->status = 500;
        o->result = NULL;
        return;
    }
    o->status = status;
    o->result = r;
}

static ec_status outcome_add_included(ec_outcome *o, ec_entity *e)
{
    if (o->included_len == o->included_cap) {
        size_t cap = o->included_cap ? o->included_cap * 2 : 4;
        ec_entity **grown = realloc(o->included, cap * sizeof(*grown));
        if (!grown) {
            return EC_ERR_OOM;
        }
        o->included = grown;
        o->included_cap = cap;
    }
    o->included[o->included_len++] = ec_entity_ref(e);
    return EC_OK;
}

/* ── peer struct + handler table ─────────────────────────────────────────────── */

struct ec_peer;

typedef void (*ec_handler_fn)(struct ec_peer *p, ec_conn *conn, const ec_envelope *env,
                              const ec_entity *exec, const ec_entity *caller_cap,
                              const char *op, ec_outcome *out);

typedef struct handler_row {
    char *pattern;              /* relative pattern e.g. "system/tree" */
    ec_handler_fn fn;
} handler_row;

struct ec_peer {
    ec_identity *identity;
    ec_store *store;
    char *local;                /* peer_id (== identity->peer_id) */
    bool open_grants;
    bool conformance;
    handler_row *handlers;
    size_t handlers_len, handlers_cap;
};

const char *ec_peer_local(const ec_peer *p) { return p->local; }
ec_store *ec_peer_store(ec_peer *p) { return p->store; }
const ec_identity *ec_peer_identity(const ec_peer *p) { return p->identity; }

static ec_handler_fn lookup_handler(ec_peer *p, const char *pattern)
{
    for (size_t i = 0; i < p->handlers_len; i++) {
        if (strcmp(p->handlers[i].pattern, pattern) == 0) {
            return p->handlers[i].fn;
        }
    }
    return NULL;
}

static ec_status register_handler(ec_peer *p, const char *pattern, ec_handler_fn fn)
{
    if (p->handlers_len == p->handlers_cap) {
        size_t cap = p->handlers_cap ? p->handlers_cap * 2 : 8;
        handler_row *grown = realloc(p->handlers, cap * sizeof(*grown));
        if (!grown) {
            return EC_ERR_OOM;
        }
        p->handlers = grown;
        p->handlers_cap = cap;
    }
    p->handlers[p->handlers_len].pattern = strdup(pattern);
    if (!p->handlers[p->handlers_len].pattern) {
        return EC_ERR_OOM;
    }
    p->handlers[p->handlers_len].fn = fn;
    p->handlers_len++;
    return EC_OK;
}

/* ── small value builders ────────────────────────────────────────────────────── */

/* "/{local}/{rel}" → malloc'd. */
static char *abs_path(ec_peer *p, const char *rel)
{
    size_t n = strlen(p->local) + strlen(rel) + 3;
    char *s = malloc(n);
    if (s) {
        snprintf(s, n, "/%s/%s", p->local, rel);
    }
    return s;
}

/* scope map {include:[...]} (or {include,exclude}). owned value out. */
static ec_value *scope_cbor(const char *const *incl, size_t nincl)
{
    ec_value *m = ec_map();
    if (!m) { return NULL; }
    ec_value *k = ec_text("include");
    ec_value *arr = ec_v_text_array(incl, nincl);
    if (!k || !arr || ec_map_put(m, k, arr) != EC_OK) {
        ec_value_free(k); ec_value_free(arr); ec_value_free(m);
        return NULL;
    }
    return m;
}

/* a grant map {handlers,resources,operations[,peers]} — each dim is an include list. */
static ec_value *grant_cbor(const char *const *h, size_t nh, const char *const *r, size_t nr,
                            const char *const *o, size_t no, const char *const *pe, size_t npe)
{
    ec_value *m = ec_map();
    if (!m) { return NULL; }
    struct { const char *key; const char *const *list; size_t n; bool present; } dims[] = {
        { "handlers",   h,  nh,  true },
        { "resources",  r,  nr,  true },
        { "operations", o,  no,  true },
        { "peers",      pe, npe, pe != NULL },
    };
    for (size_t i = 0; i < 4; i++) {
        if (!dims[i].present) {
            continue;
        }
        ec_value *k = ec_text(dims[i].key);
        ec_value *sc = scope_cbor(dims[i].list, dims[i].n);
        if (!k || !sc || ec_map_put(m, k, sc) != EC_OK) {
            ec_value_free(k); ec_value_free(sc); ec_value_free(m);
            return NULL;
        }
    }
    return m;
}

/* the §4.4 discovery floor (two grants). owned array value out. */
static ec_value *discovery_floor(void)
{
    const char *h1[] = { "system/tree" };
    const char *r1[] = { "system/type/*", "system/handler/*" };
    const char *o1[] = { "get" };
    const char *h2[] = { "system/capability" };
    const char *o2[] = { "request" };
    ec_value *arr = ec_array();
    ec_value *g1 = grant_cbor(h1, 1, r1, 2, o1, 1, NULL, 0);
    ec_value *g2 = grant_cbor(h2, 1, NULL, 0, o2, 1, NULL, 0);
    if (!arr || !g1 || !g2 ||
        ec_array_push(arr, g1) != EC_OK || ec_array_push(arr, g2) != EC_OK) {
        ec_value_free(g1); ec_value_free(g2); ec_value_free(arr);
        return NULL;
    }
    return arr;
}

/* wide-open admin scope (= --debug-open-grants). owned array value out. */
static ec_value *open_grants_scope(void)
{
    const char *star[] = { "*" };
    const char *res[] = { "*", "/*/*" };
    ec_value *arr = ec_array();
    ec_value *g = grant_cbor(star, 1, res, 2, star, 1, star, 1);
    if (!arr || !g || ec_array_push(arr, g) != EC_OK) {
        ec_value_free(g); ec_value_free(arr);
        return NULL;
    }
    return arr;
}

/* full owner authority over the local namespace (§6.9a). owned array value out. */
static ec_value *owner_grants(ec_peer *p)
{
    const char *star[] = { "*" };
    const char *peers[] = { p->local };
    ec_value *arr = ec_array();
    ec_value *g = grant_cbor(star, 1, star, 1, star, 1, peers, 1);
    if (!arr || !g || ec_array_push(arr, g) != EC_OK) {
        ec_value_free(g); ec_value_free(arr);
        return NULL;
    }
    return arr;
}

/* ── token mint (§4.4 / §6.9a) ───────────────────────────────────────────────── */

/* Mint a token + its signature. `grants` is an owned array value (CONSUMED). On EC_OK
 * *token and *sig are +1 refs the caller unrefs. */
static ec_status mint_token(ec_peer *p, const uint8_t grantee[33], ec_value *grants,
                            const uint8_t *parent, ec_entity **token, ec_entity **sig)
{
    ec_status st = EC_ERR_OOM;
    ec_value *m = ec_map();
    if (!m) {
        ec_value_free(grants);
        return EC_ERR_OOM;
    }
    ec_value *k;
    k = ec_text("granter");
    if (!k || ec_map_put(m, k, ec_bytes(p->identity->identity_hash, 33)) != EC_OK) {
        ec_value_free(k); goto cleanup;
    }
    k = ec_text("grantee");
    if (!k || ec_map_put(m, k, ec_bytes(grantee, 33)) != EC_OK) {
        ec_value_free(k); goto cleanup;
    }
    k = ec_text("grants");
    if (!k || ec_map_put(m, k, grants) != EC_OK) {
        ec_value_free(k);
        goto cleanup;            /* grants consumed-or-freed by put */
    }
    grants = NULL;
    k = ec_text("created_at");
    if (!k || ec_map_put(m, k, ec_int_u(ec_now_ms())) != EC_OK) {
        ec_value_free(k); goto cleanup;
    }
    if (parent) {
        k = ec_text("parent");
        if (!k || ec_map_put(m, k, ec_bytes(parent, 33)) != EC_OK) {
            ec_value_free(k); goto cleanup;
        }
    }
    ec_entity *tok = NULL;
    st = ec_entity_make_owning("system/capability/token", m, &tok);
    m = NULL;
    if (st != EC_OK) {
        return st;
    }
    ec_entity *s = NULL;
    st = ec_identity_sign(p->identity, tok, &s);
    if (st != EC_OK) {
        ec_entity_unref(tok);
        return st;
    }
    *token = tok;
    *sig = s;
    return EC_OK;
cleanup:
    ec_value_free(grants);
    ec_value_free(m);
    return st;
}

/* Attach the cap {token, peer-identity, signature} to an outcome's included (§5.8). */
static ec_status outcome_attach_cap(ec_peer *p, ec_outcome *o, ec_entity *token, ec_entity *sig)
{
    ec_status st;
    if ((st = outcome_add_included(o, token)) != EC_OK) { return st; }
    if ((st = outcome_add_included(o, p->identity->peer_entity)) != EC_OK) { return st; }
    if ((st = outcome_add_included(o, sig)) != EC_OK) { return st; }
    return EC_OK;
}

/* ── §6.9a seed-policy derivation ────────────────────────────────────────────── */

/* Append the grants from a policy entry (a cap token w/ a verified sig, or a
 * policy-entry) into `out_arr`. */
static void append_entry_grants(ec_peer *p, ec_entity *entry, ec_value *out_arr)
{
    const ec_value *grants = NULL;
    if (strcmp(entry->type, "system/capability/token") == 0) {
        char *hex = ec_hex(entry->hash, 33);
        if (!hex) { return; }
        size_t n = strlen(p->local) + strlen(hex) + 32;
        char *path = malloc(n);
        if (path) {
            snprintf(path, n, "/%s/system/signature/%s", p->local, hex);
            ec_entity *sgn = ec_store_get_at(p->store, path);
            if (sgn && ec_verify_signature(sgn, p->identity->peer_entity)) {
                grants = ec_ent_field(entry, "grants");
            }
            ec_entity_unref(sgn);
            free(path);
        }
        free(hex);
    } else if (strcmp(entry->type, "system/capability/policy-entry") == 0) {
        grants = ec_ent_field(entry, "grants");
    }
    if (grants && grants->kind == EC_ARRAY) {
        for (size_t i = 0; i < grants->as.arr.len; i++) {
            ec_value *c = ec_value_clone(grants->as.arr.items[i]);
            if (c) { ec_array_push(out_arr, c); }
        }
    }
}

/* Dual-form lookup (hex → Base58 → default) then UNION with the discovery floor.
 * Returns an owned grants array (the §4.4 floor UNION policy). */
static ec_value *derive_seed_grants(ec_peer *p, const ec_entity *remote_peer,
                                    const char *remote_peer_id)
{
    ec_value *floor = discovery_floor();
    if (!floor) {
        return NULL;
    }
    char *rhex = ec_hex(remote_peer->hash, 33);
    ec_entity *entry = NULL;
    if (rhex) {
        size_t n = strlen(p->local) + strlen(rhex) + 48;
        char *path = malloc(n);
        if (path) {
            snprintf(path, n, "/%s/system/capability/policy/%s", p->local, rhex);
            entry = ec_store_get_at(p->store, path);
            free(path);
        }
        free(rhex);
    }
    if (!entry && remote_peer_id) {
        size_t n = strlen(p->local) + strlen(remote_peer_id) + 48;
        char *path = malloc(n);
        if (path) {
            snprintf(path, n, "/%s/system/capability/policy/%s", p->local, remote_peer_id);
            entry = ec_store_get_at(p->store, path);
            free(path);
        }
    }
    if (!entry) {
        char *path = abs_path(p, "system/capability/policy/default");
        if (path) {
            entry = ec_store_get_at(p->store, path);
            free(path);
        }
    }
    if (entry) {
        append_entry_grants(p, entry, floor);
        ec_entity_unref(entry);
    }
    return floor;
}

/* ── handler resolution (§6.6) backward tree-walk ────────────────────────────── */

/* Longest prefix of `path` bound to a system/handler entity, or NULL (caller frees). */
static char *resolve_handler_path(ec_peer *p, const char *path)
{
    char *work = strdup(path);
    if (!work) {
        return NULL;
    }
    char *result = NULL;
    /* walk from the full path back, trimming a trailing segment each time */
    for (;;) {
        ec_entity *e = ec_store_get_at(p->store, work);
        if (e) {
            bool is_handler = strcmp(e->type, "system/handler") == 0;
            ec_entity_unref(e);
            if (is_handler) {
                result = strdup(work);
                break;
            }
        }
        char *slash = strrchr(work, '/');
        if (!slash || slash == work) {
            break;
        }
        *slash = 0;
    }
    free(work);
    return result;
}

/* Strip the /{local}/ prefix from a resolved absolute pattern → the registration key. */
static const char *strip_local(ec_peer *p, const char *pattern)
{
    size_t n = strlen(p->local) + 2;
    char prefix[512];
    snprintf(prefix, sizeof(prefix), "/%s/", p->local);
    if (ec_startswith(prefix, pattern)) {
        return pattern + n;
    }
    return pattern;
}

/* ── §6.5 dispatcher-level signature ingestion ───────────────────────────────── */

static void ingest_signatures(ec_peer *p, const ec_envelope *env)
{
    for (size_t i = 0; i < env->included_len; i++) {
        ec_entity *e = env->included[i].entity;
        if (strcmp(e->type, "system/signature") != 0) {
            continue;
        }
        ec_store_put(p->store, e);
        size_t sl = 0;
        const uint8_t *signer_h = ec_ent_bytes(e, "signer", &sl);
        if (!signer_h || sl != 33) {
            continue;
        }
        ec_entity *signer_peer = ec_env_get(env, signer_h);
        if (!signer_peer) {
            continue;
        }
        ec_store_put(p->store, signer_peer);
        size_t tl = 0, pl = 0;
        const uint8_t *target = ec_ent_bytes(e, "target", &tl);
        const uint8_t *pk = ec_ent_bytes(signer_peer, "public_key", &pl);
        if (target && tl == 33 && pk && pl == 32) {
            char *pid = NULL;
            char *thex = ec_hex(target, 33);
            if (ec_peer_id_of_pubkey32(pk, &pid) == EC_OK && pid && thex) {
                size_t n = strlen(pid) + strlen(thex) + 32;
                char *path = malloc(n);
                if (path) {
                    snprintf(path, n, "/%s/system/signature/%s", pid, thex);
                    ec_store_bind(p->store, path, e);
                    free(path);
                }
            }
            free(pid);
            free(thex);
        }
    }
}

/* ── handler helpers ─────────────────────────────────────────────────────────── */

/* The single resource target string off an EXECUTE (borrow into the exec's value tree). */
/* Borrow the first resource target as a C string. If out_len is non-NULL it also reports
 * the raw byte length (which differs from strlen when the segment carries an embedded NUL —
 * a §1.4 R1 violation the C-string view would otherwise hide). */
static const char *exec_resource_target_n(const ec_entity *exec, size_t *out_len)
{
    if (out_len) { *out_len = 0; }
    const ec_value *r = ec_ent_map_field(exec, "resource");
    if (!r) {
        return NULL;
    }
    const ec_value *targets = ec_v_get(r, "targets");
    if (targets && targets->kind == EC_ARRAY && targets->as.arr.len > 0) {
        const ec_value *t = targets->as.arr.items[0];
        if (t && t->kind == EC_TEXT) {
            if (out_len) { *out_len = t->as.bytes.len; }
            return (const char *)t->as.bytes.p;
        }
    }
    return NULL;
}

static const char *exec_resource_target(const ec_entity *exec)
{
    return exec_resource_target_n(exec, NULL);
}

static bool path_flex_ok_n(const char *target, size_t raw_len)
{
    if (!target) {
        return false;
    }
    /* §1.4 R1: a NUL byte is not valid in any path segment. When the wire text carried an
     * embedded NUL, raw_len (the value-node byte length) exceeds strlen(target) — the
     * C-string view stops at the NUL and would otherwise hide the violation. */
    if (raw_len != 0 && raw_len != strlen(target)) {
        return false;
    }
    /* §1.4 R1: reject empty segments (consecutive // — strtok_r collapses them, so detect
     * the literal "//" before tokenizing). A single trailing '/' is allowed (listing). */
    {
        size_t L = strlen(target);
        for (size_t i = 0; i + 1 < L; i++) {
            if (target[i] == '/' && target[i + 1] == '/') {
                return false;
            }
        }
        if (L == 1 && target[0] == '/') {
            return false;        /* bare "/" is not a valid put target */
        }
    }
    /* split, validate each segment is non-empty / not . / not .. ; allow a trailing / */
    char *work = strdup(target);
    if (!work) {
        return false;
    }
    bool ok = true;
    const char *body = work;
    if (work[0] == '/') {
        /* absolute: /{peer}/... — the first segment must be a peer_id */
        char *second = strchr(work + 1, '/');
        char saved = 0;
        char *seg1 = work + 1;
        if (second) {
            saved = *second;
            *second = 0;
        }
        if (!ec_is_peer_id(seg1)) {
            ok = false;
        }
        if (second) {
            *second = saved;
            body = second + 1;
        } else {
            body = work + strlen(work);   /* just "/{peer}" */
        }
    }
    if (ok) {
        char *seg = strdup(body);
        if (!seg) {
            free(work);
            return false;
        }
        /* strip a single trailing slash */
        size_t L = strlen(seg);
        if (L > 0 && seg[L - 1] == '/') {
            seg[L - 1] = 0;
        }
        char *save = NULL;
        for (char *tok = strtok_r(seg, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
            if (tok[0] == 0 || strcmp(tok, ".") == 0 || strcmp(tok, "..") == 0) {
                ok = false;
                break;
            }
        }
        free(seg);
    }
    free(work);
    return ok;
}

static bool is_zero_hash(const uint8_t *h, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (h[i]) { return false; }
    }
    return true;
}

/* ── connect handler (§4.1/§4.6) ─────────────────────────────────────────────── */

/*
 * §4.5 negotiation: does the initiator's advertised text-array `key` overlap with our
 * supported `want` token? An ABSENT or empty advertisement means "no constraint" (accept
 * — back-compat with pre-v7.69 hellos). A non-empty advertisement that EXCLUDES `want` is
 * a disjoint set → the caller rejects the hello (NEGOTIATE-FORMAT-1b / KEYTYPE-1b).
 */
static bool advertised_excludes(const ec_entity *params, const char *key, const char *want)
{
    const ec_value *arr = params ? ec_ent_field(params, key) : NULL;
    if (!arr || arr->kind != EC_ARRAY || arr->as.arr.len == 0) {
        return false;   /* absent/empty advertisement = no constraint */
    }
    for (size_t i = 0; i < arr->as.arr.len; i++) {
        const ec_value *it = arr->as.arr.items[i];
        if (it && it->kind == EC_TEXT && it->as.bytes.p &&
            strcmp((const char *)it->as.bytes.p, want) == 0) {
            return false;   /* overlap found */
        }
    }
    return true;            /* non-empty + no overlap = disjoint */
}

static void h_connect(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                      const ec_entity *exec, const ec_entity *caller_cap,
                      const char *op, ec_outcome *out)
{
    (void)caller_cap;
    if (strcmp(op, "hello") == 0) {
        if (conn->established) {
            outcome_err(out, 409, "connection_already_established", NULL);
            return;
        }
        ec_entity *params = ec_ent_entity_field(exec, "params");
        const char *initiator = params ? ec_ent_text(params, "peer_id") : NULL;
        /* §4.5 format/key-type negotiation: reject a hello whose advertised accept-set is
         * disjoint from our floor (ecfv1-sha256 / ed25519). */
        if (advertised_excludes(params, "hash_formats", "ecfv1-sha256")) {
            ec_entity_unref(params);
            outcome_err(out, 400, "incompatible_hash_format", NULL);
            return;
        }
        if (advertised_excludes(params, "key_types", "ed25519")) {
            ec_entity_unref(params);
            outcome_err(out, 400, "unsupported_key_type", NULL);
            return;
        }
        /* issue a fresh CSPRNG 32-byte nonce, bound to THIS connection (F12: a clock-
         * derived nonce collides across connections opened in the same millisecond, so a
         * valid authenticate captured on one connection replays on another — the §4.6
         * cross-connection replay. A per-connection random nonce makes the challenge
         * unique, so the replay's echoed nonce fails the conn->issued_nonce check). */
        uint8_t nonce[32];
        if (ec_random_bytes(nonce, 32) != EC_OK) {
            outcome_err(out, 500, "internal_error", NULL);
            ec_entity_unref(params);
            return;
        }
        memcpy(conn->issued_nonce, nonce, 32);
        conn->have_nonce = true;
        free(conn->hello_peer_id);
        conn->hello_peer_id = initiator ? strdup(initiator) : NULL;
        ec_entity_unref(params);

        ec_value *m = ec_map();
        if (!m) { outcome_err(out, 500, "internal_error", NULL); return; }
        ec_value *k;
        bool bad = false;
        k = ec_text("peer_id");
        bad |= !k || ec_map_put(m, k, ec_text(p->local)) != EC_OK;
        k = ec_text("nonce");
        bad |= !k || ec_map_put(m, k, ec_bytes(nonce, 32)) != EC_OK;
        const char *protos[] = { "entity-core/1.0" };
        k = ec_text("protocols");
        bad |= !k || ec_map_put(m, k, ec_v_text_array(protos, 1)) != EC_OK;
        k = ec_text("timestamp");
        bad |= !k || ec_map_put(m, k, ec_int_u(ec_now_ms())) != EC_OK;
        const char *hf[] = { "ecfv1-sha256" };
        k = ec_text("hash_formats");
        bad |= !k || ec_map_put(m, k, ec_v_text_array(hf, 1)) != EC_OK;
        const char *kt[] = { "ed25519" };
        k = ec_text("key_types");
        bad |= !k || ec_map_put(m, k, ec_v_text_array(kt, 1)) != EC_OK;
        if (bad) { ec_value_free(m); outcome_err(out, 500, "internal_error", NULL); return; }
        ec_entity *result = NULL;
        if (ec_entity_make_owning("system/protocol/connect/hello", m, &result) != EC_OK) {
            outcome_err(out, 500, "internal_error", NULL);
            return;
        }
        outcome_ok(out, result);
        return;
    }
    if (strcmp(op, "authenticate") == 0) {
        if (conn->established) {
            outcome_err(out, 409, "connection_already_established", NULL);
            return;
        }
        if (!conn->have_nonce) {
            outcome_err(out, 401, "invalid_nonce", NULL);   /* authenticate before hello */
            return;
        }
        ec_entity *auth = ec_ent_entity_field(exec, "params");
        if (!auth) {
            outcome_err(out, 401, "authentication_failed", NULL);
            return;
        }
        const char *ktf = ec_ent_text(auth, "key_type");
        bool bad_kt = (ktf && strcmp(ktf, "ed25519") != 0);
        size_t publ = 0;
        const uint8_t *pub = ec_ent_bytes(auth, "public_key", &publ);
        if (!bad_kt && pub && publ != 32) {
            bad_kt = true;
        }
        const char *claimed = ec_ent_text(auth, "peer_id");
        if (!bad_kt && claimed) {
            uint64_t kt = 0, ht = 0;
            uint8_t *dig = NULL;
            size_t dlen = 0;
            if (ec_peer_id_parse(claimed, &kt, &ht, &dig, &dlen) == EC_OK) {
                if (kt != EC_KEY_TYPE_ED25519) { bad_kt = true; }
                free(dig);
            }
        }
        if (bad_kt) { ec_entity_unref(auth); outcome_err(out, 400, "unsupported_key_type", NULL); return; }
        size_t nl = 0;
        const uint8_t *echoed = ec_ent_bytes(auth, "nonce", &nl);
        if (!(echoed && nl == 32 && memcmp(echoed, conn->issued_nonce, 32) == 0)) {
            ec_entity_unref(auth); outcome_err(out, 401, "invalid_nonce", NULL); return;
        }
        if (!pub) { ec_entity_unref(auth); outcome_err(out, 401, "authentication_failed", NULL); return; }
        /* step 2: proof of possession — find sig over auth, verify against pub */
        bool sig_ok = false;
        for (size_t i = 0; i < env->included_len; i++) {
            ec_entity *sg = env->included[i].entity;
            if (strcmp(sg->type, "system/signature") != 0) { continue; }
            size_t tl = 0;
            const uint8_t *tg = ec_ent_bytes(sg, "target", &tl);
            if (tg && tl == 33 && memcmp(tg, auth->hash, 33) == 0) {
                size_t sl = 0;
                const uint8_t *sb = ec_ent_bytes(sg, "signature", &sl);
                if (sb && sl == EC_ED25519_SIG_LEN &&
                    ec_ed25519_verify(pub, 32, sb, sl, auth->hash, 33) == EC_OK) {
                    sig_ok = true;
                }
                break;
            }
        }
        if (!sig_ok) { ec_entity_unref(auth); outcome_err(out, 401, "authentication_failed", NULL); return; }
        /* Copy the pubkey + claimed peer_id OUT of the auth entity before we free it
         * (they are borrowed views into auth's value tree — using them after unref is a
         * use-after-free). */
        uint8_t pub_copy[32];
        memcpy(pub_copy, pub, 32);
        char *claimed_copy = claimed ? strdup(claimed) : NULL;
        ec_entity_unref(auth);
        /* step 3: identity binding */
        char *derived = NULL;
        ec_peer_id_of_pubkey32(pub_copy, &derived);
        bool bound = derived && claimed_copy && strcmp(derived, claimed_copy) == 0;
        if (bound && conn->hello_peer_id && strcmp(conn->hello_peer_id, claimed_copy) != 0) {
            bound = false;
        }
        free(derived);
        if (!bound) { free(claimed_copy); outcome_err(out, 401, "identity_mismatch", NULL); return; }

        /* success: mint the initial capability (§4.4 / §6.9a) */
        ec_entity *remote_peer = NULL;
        if (ec_peer_entity_of_pubkey(pub_copy, &remote_peer) != EC_OK) {
            free(claimed_copy);
            outcome_err(out, 500, "internal_error", NULL); return;
        }
        ec_value *grants = derive_seed_grants(p, remote_peer, claimed_copy);
        free(claimed_copy);
        if (!grants) { ec_entity_unref(remote_peer); outcome_err(out, 500, "internal_error", NULL); return; }
        ec_entity *token = NULL, *sig = NULL;
        ec_status st = mint_token(p, remote_peer->hash, grants, NULL, &token, &sig);
        ec_entity_unref(remote_peer);
        if (st != EC_OK) { outcome_err(out, 500, "internal_error", NULL); return; }
        conn->established = true;

        /* result = system/capability/grant {token: token.hash} */
        ec_value *gm = ec_map();
        ec_value *gk = gm ? ec_text("token") : NULL;
        ec_entity *grant_ent = NULL;
        if (gm && gk && ec_map_put(gm, gk, ec_bytes(token->hash, 33)) == EC_OK &&
            ec_entity_make_owning("system/capability/grant", gm, &grant_ent) == EC_OK) {
            outcome_ok(out, grant_ent);
            outcome_attach_cap(p, out, token, sig);
        } else {
            ec_value_free(gk);
            ec_value_free(gm);
            outcome_err(out, 500, "internal_error", NULL);
        }
        ec_entity_unref(token);
        ec_entity_unref(sig);
        return;
    }
    outcome_err(out, 501, "unsupported_operation", op);
}

/* ── tree handler (§6.3) ─────────────────────────────────────────────────────── */

static void build_listing(ec_peer *p, const char *path, ec_outcome *out);

static void h_tree(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                   const ec_entity *exec, const ec_entity *caller_cap,
                   const char *op, ec_outcome *out)
{
    (void)conn; (void)env; (void)caller_cap;
    if (strcmp(op, "get") == 0) {
        size_t target_len = 0;
        const char *target = exec_resource_target_n(exec, &target_len);
        if (target && !path_flex_ok_n(target, target_len)) {
            outcome_err(out, 400, "invalid_path", target);
            return;
        }
        if (!target) {
            char *root = abs_path(p, "");
            if (root) {
                /* abs_path("") gives "/{local}/" */
                build_listing(p, root, out);
                free(root);
            } else {
                outcome_err(out, 500, "internal_error", NULL);
            }
            return;
        }
        size_t tlen = strlen(target);
        if (tlen == 0 || target[tlen - 1] == '/') {
            char *path = NULL;
            if (ec_canonicalize(p->local, target, &path) != EC_OK) {
                outcome_err(out, 400, "invalid_path", target);
                return;
            }
            build_listing(p, path, out);
            free(path);
            return;
        }
        char *path = NULL;
        if (ec_canonicalize(p->local, target, &path) != EC_OK) {
            outcome_err(out, 400, "invalid_path", target);
            return;
        }
        ec_entity *e = ec_store_get_at(p->store, path);
        free(path);
        if (!e) {
            outcome_err(out, 404, "not_found", target);
            return;
        }
        ec_entity *params = ec_ent_entity_field(exec, "params");
        const char *mode = params ? ec_ent_text(params, "mode") : NULL;
        if (mode && strcmp(mode, "hash") == 0) {
            ec_value *m = ec_map();
            ec_value *k = m ? ec_text("hash") : NULL;
            ec_entity *r = NULL;
            if (m && k && ec_map_put(m, k, ec_bytes(e->hash, 33)) == EC_OK &&
                ec_entity_make_owning("system/hash", m, &r) == EC_OK) {
                outcome_ok(out, r);
            } else {
                ec_value_free(k); ec_value_free(m);
                outcome_err(out, 500, "internal_error", NULL);
            }
        } else {
            outcome_ok(out, ec_entity_ref(e));
        }
        ec_entity_unref(params);
        ec_entity_unref(e);
        return;
    }
    if (strcmp(op, "put") == 0) {
        size_t target_len = 0;
        const char *target = exec_resource_target_n(exec, &target_len);
        if (!target) {
            outcome_err(out, 400, "ambiguous_resource", "tree: missing resource target");
            return;
        }
        if (!path_flex_ok_n(target, target_len)) {
            outcome_err(out, 400, "invalid_path", target);
            return;
        }
        char *path = NULL;
        if (ec_canonicalize(p->local, target, &path) != EC_OK) {
            outcome_err(out, 400, "invalid_path", target);
            return;
        }
        ec_entity *params = ec_ent_entity_field(exec, "params");
        ec_entity *entity = params ? ec_ent_entity_field(params, "entity") : NULL;
        size_t exl = 0;
        const uint8_t *expected = params ? ec_ent_bytes(params, "expected_hash", &exl) : NULL;
        char *current = NULL;
        bool have_current = (ec_store_hash_at(p->store, path, &current) == EC_OK);
        bool cas_ok;
        if (!expected) {
            cas_ok = true;
        } else if (exl == 33 && is_zero_hash(expected, exl)) {
            cas_ok = !have_current;
        } else {
            char *ehex = ec_hex(expected, exl);
            cas_ok = have_current && ehex && strcmp(current, ehex) == 0;
            free(ehex);
        }
        free(current);
        if (!cas_ok) {
            free(path); ec_entity_unref(params); ec_entity_unref(entity);
            outcome_err(out, 409, "hash_mismatch", target);
            return;
        }
        if (!entity) {
            free(path); ec_entity_unref(params);
            outcome_err(out, 400, "unexpected_params", "put: missing entity");
            return;
        }
        ec_store_bind(p->store, path, entity);
        ec_value *m = ec_map();
        ec_value *k = m ? ec_text("hash") : NULL;
        ec_entity *r = NULL;
        if (m && k && ec_map_put(m, k, ec_bytes(entity->hash, 33)) == EC_OK &&
            ec_entity_make_owning("system/hash", m, &r) == EC_OK) {
            outcome_ok(out, r);
        } else {
            ec_value_free(k); ec_value_free(m);
            outcome_err(out, 500, "internal_error", NULL);
        }
        free(path);
        ec_entity_unref(params);
        ec_entity_unref(entity);
        return;
    }
    outcome_err(out, 501, "unsupported_operation", op);
}

static bool is_deletion_marker(ec_peer *p, const char *hex)
{
    /* hex is the 66-char content hash; resolve via the content store */
    if (strlen(hex) != 66) {
        return false;
    }
    uint8_t h[33];
    for (size_t i = 0; i < 33; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        h[i] = (uint8_t)strtol(b, NULL, 16);
    }
    ec_entity *e = ec_store_get_by_hash(p->store, h);
    bool dm = e && strcmp(e->type, "system/deletion-marker") == 0;
    ec_entity_unref(e);
    return dm;
}

static void build_listing(ec_peer *p, const char *path, ec_outcome *out)
{
    ec_list_entry *rows = NULL;
    size_t nrows = 0;
    if (ec_store_listing(p->store, path, &rows, &nrows) != EC_OK) {
        outcome_err(out, 500, "internal_error", NULL);
        return;
    }
    ec_value *entries = ec_map();
    ec_value *m = ec_map();
    if (!entries || !m) {
        ec_value_free(entries); ec_value_free(m);
        ec_store_listing_free(rows, nrows);
        outcome_err(out, 500, "internal_error", NULL);
        return;
    }
    size_t count = 0;
    for (size_t i = 0; i < nrows; i++) {
        if (rows[i].hash_hex[0] && !rows[i].has_children &&
            is_deletion_marker(p, rows[i].hash_hex)) {
            continue;
        }
        /* listing-entry {has_children[, hash]} */
        ec_value *data = ec_map();
        ec_value *hk = ec_text("has_children");
        if (!data || !hk || ec_map_put(data, hk, ec_bool(rows[i].has_children)) != EC_OK) {
            ec_value_free(hk); ec_value_free(data);
            continue;
        }
        if (rows[i].hash_hex[0]) {
            uint8_t h[33];
            for (size_t j = 0; j < 33; j++) {
                char b[3] = { rows[i].hash_hex[j * 2], rows[i].hash_hex[j * 2 + 1], 0 };
                h[j] = (uint8_t)strtol(b, NULL, 16);
            }
            ec_value *bk = ec_text("hash");
            if (bk) { ec_map_put(data, bk, ec_bytes(h, 33)); }
        }
        ec_entity *le = NULL;
        if (ec_entity_make_owning("system/tree/listing-entry", data, &le) == EC_OK) {
            ec_value *seg = ec_text(rows[i].segment);
            ec_value *lev = NULL;
            if (seg && ec_entity_to_cbor(le, &lev) == EC_OK) {
                ec_map_put(entries, seg, lev);
                count++;
            } else {
                ec_value_free(seg);
            }
            ec_entity_unref(le);
        }
    }
    ec_store_listing_free(rows, nrows);
    bool bad = false;
    ec_value *k;
    k = ec_text("path"); bad |= !k || ec_map_put(m, k, ec_text(path)) != EC_OK;
    k = ec_text("entries"); bad |= !k || ec_map_put(m, k, entries) != EC_OK;
    entries = NULL;
    k = ec_text("count"); bad |= !k || ec_map_put(m, k, ec_int_u(count)) != EC_OK;
    k = ec_text("offset"); bad |= !k || ec_map_put(m, k, ec_int_u(0)) != EC_OK;
    if (bad) {
        ec_value_free(entries); ec_value_free(m);
        outcome_err(out, 500, "internal_error", NULL);
        return;
    }
    ec_entity *r = NULL;
    if (ec_entity_make_owning("system/tree/listing", m, &r) == EC_OK) {
        outcome_ok(out, r);
    } else {
        outcome_err(out, 500, "internal_error", NULL);
    }
}

/* ── capability handler (§6.2) ───────────────────────────────────────────────── */

static const ec_value *req_grants(const ec_entity *params)
{
    if (!params) {
        return NULL;
    }
    const ec_value *g = ec_ent_field(params, "grants");
    return (g && g->kind == EC_ARRAY) ? g : NULL;
}

/* mint a bounded token: requested grants ⊆ caller's cap grants (self-issued frame). */
static void mint_bounded(ec_peer *p, const ec_entity *caller_cap, const ec_value *requested,
                         const uint8_t grantee[33], const uint8_t *parent, ec_outcome *out)
{
    bool bounded = false;
    if (caller_cap) {
        const ec_value *parent_grants = NULL;
        const ec_value *pg = ec_ent_field(caller_cap, "grants");
        parent_grants = (pg && pg->kind == EC_ARRAY) ? pg : NULL;
        bounded = true;
        if (requested) {
            for (size_t i = 0; i < requested->as.arr.len && bounded; i++) {
                bool some = false;
                if (parent_grants) {
                    for (size_t j = 0; j < parent_grants->as.arr.len; j++) {
                        if (ec_cap_grant_subset(p->local, p->local, p->local,
                                                requested->as.arr.items[i],
                                                parent_grants->as.arr.items[j])) {
                            some = true;
                            break;
                        }
                    }
                }
                if (!some) { bounded = false; }
            }
        }
    }
    if (!bounded) {
        outcome_err(out, 403, "scope_exceeds_authority", NULL);
        return;
    }
    /* clone the requested grants into an owned array for the mint */
    ec_value *grants = ec_array();
    if (!grants) { outcome_err(out, 500, "internal_error", NULL); return; }
    if (requested) {
        for (size_t i = 0; i < requested->as.arr.len; i++) {
            ec_value *c = ec_value_clone(requested->as.arr.items[i]);
            if (c) { ec_array_push(grants, c); }
        }
    }
    ec_entity *token = NULL, *sig = NULL;
    if (mint_token(p, grantee, grants, parent, &token, &sig) != EC_OK) {
        outcome_err(out, 500, "internal_error", NULL);
        return;
    }
    ec_value *gm = ec_map();
    ec_value *gk = gm ? ec_text("token") : NULL;
    ec_entity *grant_ent = NULL;
    if (gm && gk && ec_map_put(gm, gk, ec_bytes(token->hash, 33)) == EC_OK &&
        ec_entity_make_owning("system/capability/grant", gm, &grant_ent) == EC_OK) {
        outcome_ok(out, grant_ent);
        outcome_attach_cap(p, out, token, sig);
    } else {
        ec_value_free(gk); ec_value_free(gm);
        outcome_err(out, 500, "internal_error", NULL);
    }
    ec_entity_unref(token);
    ec_entity_unref(sig);
}

static void h_capability(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                         const ec_entity *exec, const ec_entity *caller_cap,
                         const char *op, ec_outcome *out)
{
    (void)conn; (void)env;
    ec_entity *params = ec_ent_entity_field(exec, "params");
    if (strcmp(op, "request") == 0) {
        size_t al = 0;
        const uint8_t *author = ec_ent_bytes(exec, "author", &al);
        if (!author || al != 33) {
            ec_entity_unref(params);
            outcome_err(out, 403, "capability_denied", NULL);
            return;
        }
        mint_bounded(p, caller_cap, req_grants(params), author, NULL, out);
        ec_entity_unref(params);
        return;
    }
    if (strcmp(op, "delegate") == 0) {
        size_t al = 0, phl = 0;
        const uint8_t *author = ec_ent_bytes(exec, "author", &al);
        /* §2.6 closeout F1: delegate is SAME-PEER-ONLY in v1 — a remote caller (author is
         * not this peer's identity) MUST receive 501 unsupported_operation (NOT 403/400),
         * checked BEFORE any params validation so the verdict is shape-independent. */
        if (!(author && al == 33 && memcmp(author, p->identity->identity_hash, 33) == 0)) {
            ec_entity_unref(params);
            outcome_err(out, 501, "unsupported_operation", "delegate: same-peer-only in v1");
            return;
        }
        const uint8_t *ph = params ? ec_ent_bytes(params, "parent", &phl) : NULL;
        if (!ph || phl != 33) {
            ec_entity_unref(params);
            outcome_err(out, 400, "unexpected_params", "delegate: parent required");
            return;
        }
        if (is_zero_hash(ph, phl)) {
            ec_entity_unref(params);
            outcome_err(out, 400, "unexpected_params", "delegate: zero parent");
            return;
        }
        mint_bounded(p, caller_cap, req_grants(params), author, ph, out);
        ec_entity_unref(params);
        return;
    }
    if (strcmp(op, "revoke") == 0) {
        size_t tl = 0;
        const uint8_t *tok = params ? ec_ent_bytes(params, "token", &tl) : NULL;
        if (!tok || tl != 33) {
            ec_entity_unref(params);
            outcome_err(out, 400, "unexpected_params", "revoke: missing token");
            return;
        }
        if (is_zero_hash(tok, tl)) {
            ec_entity_unref(params);
            outcome_err(out, 400, "unexpected_params", "revoke: zero token");
            return;
        }
        ec_value *m = ec_map();
        ec_value *k1 = m ? ec_text("token") : NULL;
        ec_value *k2 = m ? ec_text("revoked_at") : NULL;
        ec_entity *marker = NULL;
        char *thex = ec_hex(tok, 33);
        if (m && k1 && k2 && thex &&
            ec_map_put(m, k1, ec_bytes(tok, 33)) == EC_OK &&
            ec_map_put(m, k2, ec_int_u(ec_now_ms())) == EC_OK &&
            ec_entity_make_owning("system/capability/revocation", m, &marker) == EC_OK) {
            size_t n = strlen(p->local) + strlen(thex) + 48;
            char *path = malloc(n);
            if (path) {
                snprintf(path, n, "/%s/system/capability/revocations/%s", p->local, thex);
                ec_store_bind(p->store, path, marker);
                free(path);
            }
            ec_entity_unref(marker);
            ec_entity *ep = NULL;
            if (ec_empty_params(&ep) == EC_OK) { outcome_ok(out, ep); }
            else { outcome_err(out, 500, "internal_error", NULL); }
        } else {
            ec_value_free(k1); ec_value_free(k2); ec_value_free(m);
            outcome_err(out, 500, "internal_error", NULL);
        }
        free(thex);
        ec_entity_unref(params);
        return;
    }
    if (strcmp(op, "configure") == 0) {
        const char *pp = params ? ec_ent_text(params, "peer_pattern") : NULL;
        if (!pp) {
            ec_entity_unref(params);
            outcome_err(out, 400, "unexpected_params", "configure: missing peer_pattern");
            return;
        }
        bool is_hex = strlen(pp) == 66;
        if (is_hex) {
            for (const char *c = pp; *c; c++) {
                if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))) { is_hex = false; break; }
            }
        }
        if (!(strcmp(pp, "default") == 0 || is_hex || ec_is_peer_id(pp))) {
            ec_entity_unref(params);
            outcome_err(out, 400, "invalid_peer_pattern", pp);
            return;
        }
        size_t n = strlen(p->local) + strlen(pp) + 48;
        char *path = malloc(n);
        if (path) {
            snprintf(path, n, "/%s/system/capability/policy/%s", p->local, pp);
            ec_store_bind(p->store, path, params);
            free(path);
        }
        ec_entity_unref(params);
        ec_entity *ep = NULL;
        if (ec_empty_params(&ep) == EC_OK) { outcome_ok(out, ep); }
        else { outcome_err(out, 500, "internal_error", NULL); }
        return;
    }
    ec_entity_unref(params);
    outcome_err(out, 501, "unsupported_operation", op);
}

/* ── handlers handler (§6.2 / §6.13(a) register/unregister) ──────────────────── */

/* the register pattern off the resource target, or NULL. */
static char *register_pattern(const ec_entity *exec)
{
    const char *target = exec_resource_target(exec);
    if (!target) {
        return NULL;
    }
    const char *prefix = "system/handler/";
    size_t pl = strlen(prefix);
    if (!ec_startswith(prefix, target) || strlen(target) == pl) {
        return NULL;
    }
    return strdup(target + pl);
}

static void h_handlers(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                       const ec_entity *exec, const ec_entity *caller_cap,
                       const char *op, ec_outcome *out)
{
    (void)conn; (void)env; (void)caller_cap;
    bool is_register = strcmp(op, "register") == 0;
    bool is_unregister = strcmp(op, "unregister") == 0;
    if (!is_register && !is_unregister) {
        outcome_err(out, 501, "unsupported_operation", op);
        return;
    }
    char *pattern = register_pattern(exec);
    if (!pattern) {
        const char *target = exec_resource_target(exec);
        if (!target) {
            outcome_err(out, 400, "ambiguous_resource",
                        "register/unregister require exactly one resource target");
        } else {
            outcome_err(out, 400, "invalid_resource",
                        "resource target MUST be system/handler/{pattern}");
        }
        return;
    }

    if (is_unregister) {
        char *grants_path = NULL;
        size_t gn = strlen(pattern) + 64;
        grants_path = malloc(strlen(p->local) + gn);
        if (grants_path) {
            snprintf(grants_path, strlen(p->local) + gn,
                     "/%s/system/capability/grants/%s", p->local, pattern);
            ec_entity *g = ec_store_get_at(p->store, grants_path);
            if (g) {
                char *ghex = ec_hex(g->hash, 33);
                if (ghex) {
                    size_t n = strlen(p->local) + strlen(ghex) + 32;
                    char *sig_path = malloc(n);
                    if (sig_path) {
                        snprintf(sig_path, n, "/%s/system/signature/%s", p->local, ghex);
                        ec_store_unbind(p->store, sig_path);
                        free(sig_path);
                    }
                    free(ghex);
                }
                ec_store_unbind(p->store, grants_path);
                ec_entity_unref(g);
            }
            free(grants_path);
        }
        char *pat_path = abs_path(p, pattern);
        if (pat_path) { ec_store_unbind(p->store, pat_path); free(pat_path); }
        size_t hn = strlen(p->local) + strlen(pattern) + 32;
        char *iface_path = malloc(hn);
        if (iface_path) {
            snprintf(iface_path, hn, "/%s/system/handler/%s", p->local, pattern);
            ec_store_unbind(p->store, iface_path);
            free(iface_path);
        }
        free(pattern);
        ec_entity *ep = NULL;
        if (ec_empty_params(&ep) == EC_OK) { outcome_ok(out, ep); }
        else { outcome_err(out, 500, "internal_error", NULL); }
        return;
    }

    /* register */
    ec_entity *req = ec_ent_entity_field(exec, "params");
    if (!req) {
        free(pattern);
        outcome_err(out, 400, "unexpected_params", "register: missing params");
        return;
    }
    if (strcmp(req->type, "system/handler/register-request") != 0) {
        free(pattern); ec_entity_unref(req);
        outcome_err(out, 400, "unexpected_params", "register expects register-request");
        return;
    }
    const ec_value *manifest = ec_ent_map_field(req, "manifest");
    const char *name = manifest ? ec_v_text(manifest, "name") : NULL;
    if (!name) { name = pattern; }
    const ec_value *operations = manifest ? ec_v_get(manifest, "operations") : NULL;
    if (!operations || operations->kind != EC_MAP) { operations = NULL; }

    /* (1) handler manifest at the pattern path */
    {
        ec_value *hm = ec_map();
        ec_value *k = hm ? ec_text("interface") : NULL;
        size_t n = strlen("system/handler/") + strlen(pattern) + 1;
        char *iface_rel = malloc(n);
        if (iface_rel) { snprintf(iface_rel, n, "system/handler/%s", pattern); }
        ec_entity *he = NULL;
        if (hm && k && iface_rel &&
            ec_map_put(hm, k, ec_text(iface_rel)) == EC_OK &&
            ec_entity_make_owning("system/handler", hm, &he) == EC_OK) {
            char *path = abs_path(p, pattern);
            if (path) { ec_store_bind(p->store, path, he); free(path); }
            ec_entity_unref(he);
        } else {
            ec_value_free(k); ec_value_free(hm);
        }
        free(iface_rel);
    }
    /* (3)+(4) self-issued signed grant + grant signature at §3.5 */
    {
        const ec_value *scope = NULL;
        const ec_value *rs = ec_ent_field(req, "requested_scope");
        if (rs && rs->kind == EC_ARRAY) { scope = rs; }
        ec_value *grants = ec_array();
        if (grants) {
            if (scope) {
                for (size_t i = 0; i < scope->as.arr.len; i++) {
                    ec_value *c = ec_value_clone(scope->as.arr.items[i]);
                    if (c) { ec_array_push(grants, c); }
                }
            }
            ec_entity *token = NULL, *sig = NULL;
            if (mint_token(p, p->identity->identity_hash, grants, NULL, &token, &sig) == EC_OK) {
                size_t gpn = strlen(p->local) + strlen(pattern) + 48;
                char *gpath = malloc(gpn);
                if (gpath) {
                    snprintf(gpath, gpn, "/%s/system/capability/grants/%s", p->local, pattern);
                    ec_store_bind(p->store, gpath, token);
                    free(gpath);
                }
                char *thex = ec_hex(token->hash, 33);
                if (thex) {
                    size_t spn = strlen(p->local) + strlen(thex) + 32;
                    char *spath = malloc(spn);
                    if (spath) {
                        snprintf(spath, spn, "/%s/system/signature/%s", p->local, thex);
                        ec_store_bind(p->store, spath, sig);
                        free(spath);
                    }
                    free(thex);
                }
                ec_entity_unref(token);
                ec_entity_unref(sig);
            }
        }
    }
    /* (5) handler interface entity (discovery index) */
    {
        ec_value *im = ec_map();
        bool bad = !im;
        ec_value *k;
        k = ec_text("pattern"); bad |= !k || ec_map_put(im, k, ec_text(pattern)) != EC_OK;
        k = ec_text("name"); bad |= !k || ec_map_put(im, k, ec_text(name)) != EC_OK;
        k = ec_text("operations");
        bad |= !k || ec_map_put(im, k, operations ? ec_value_clone(operations) : ec_map()) != EC_OK;
        ec_entity *ie = NULL;
        if (!bad && ec_entity_make_owning("system/handler/interface", im, &ie) == EC_OK) {
            size_t n = strlen(p->local) + strlen(pattern) + 32;
            char *path = malloc(n);
            if (path) {
                snprintf(path, n, "/%s/system/handler/%s", p->local, pattern);
                ec_store_bind(p->store, path, ie);
                free(path);
            }
            ec_entity_unref(ie);
        } else {
            ec_value_free(im);
        }
    }
    /* result */
    {
        ec_value *m = ec_map();
        ec_value *k = m ? ec_text("pattern") : NULL;
        ec_entity *r = NULL;
        if (m && k && ec_map_put(m, k, ec_text(pattern)) == EC_OK &&
            ec_entity_make_owning("system/handler/register-result", m, &r) == EC_OK) {
            outcome_ok(out, r);
        } else {
            ec_value_free(k); ec_value_free(m);
            outcome_err(out, 500, "internal_error", NULL);
        }
    }
    free(pattern);
    ec_entity_unref(req);
}

/* ── §9.5 type registry (render-from-model) + system/type:validate ───────────── */

/*
 * Publish the full §9.5 53-type core floor as `system/type` entities under the local
 * namespace, bound at /{peer}/system/type/{name}. The per-type `data` maps come from the
 * GENERATED core_typedefs table (rendered from the cross-impl Go type model in the shared
 * test-vectors); each entity's content_hash is computed by our own S2-green codec over
 * {type,data} (render-from-model, byte-diffed against type-registry-vectors-v1). This is
 * the surface the oracle's type_system category fetches at system/type/<name>.
 */
static ec_status publish_core_types(ec_peer *p)
{
    for (size_t i = 0; i < ec_core_typedefs_count; i++) {
        ec_value *data = ec_core_typedefs[i].build();
        if (!data) {
            return EC_ERR_OOM;
        }
        ec_entity *e = NULL;
        if (ec_entity_make_owning("system/type", data, &e) != EC_OK) {
            return EC_ERR_OOM;       /* data consumed by make_owning */
        }
        size_t n = strlen(p->local) + strlen(ec_core_typedefs[i].name) + 32;
        char *path = malloc(n);
        if (!path) {
            ec_entity_unref(e);
            return EC_ERR_OOM;
        }
        snprintf(path, n, "/%s/system/type/%s", p->local, ec_core_typedefs[i].name);
        ec_store_bind(p->store, path, e);
        free(path);
        ec_entity_unref(e);
    }
    return EC_OK;
}

/*
 * system/type:validate — a real structural type-validate body (EXTENSION-TYPE floor).
 * Resolves the type definition (explicit `type_path` wins, else the subject entity's own
 * type), then checks required-field presence + reports unevaluated (extra) fields →
 * system/type/validate-result {valid, violations?, unevaluated_fields?}. Mirrors the Java
 * TypeHandler. An unknown type is a verdict (valid:false, kind:unknown_type), not a 4xx —
 * the request itself is well-formed.
 */
static void h_type(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                   const ec_entity *exec, const ec_entity *caller_cap,
                   const char *op, ec_outcome *out)
{
    (void)conn; (void)env; (void)caller_cap;
    if (strcmp(op, "validate") != 0) {
        outcome_err(out, 501, "unsupported_operation", op);
        return;
    }
    ec_entity *req = ec_ent_entity_field(exec, "params");
    if (!req) {
        outcome_err(out, 400, "invalid_params", "validate requires a params entity");
        return;
    }
    ec_entity *subject = ec_ent_entity_field(req, "entity");
    if (!subject) {
        ec_entity_unref(req);
        outcome_err(out, 400, "unexpected_params", "validate-request missing entity");
        return;
    }
    const char *type_path = ec_ent_text(req, "type_path");
    const char *type_name = type_path ? type_path : subject->type;

    /* resolve the type definition from the local registry */
    size_t tpl = strlen(p->local) + strlen(type_name) + 32;
    char *tpath = malloc(tpl);
    ec_entity *typedef_e = NULL;
    if (tpath) {
        snprintf(tpath, tpl, "/%s/system/type/%s", p->local, type_name);
        typedef_e = ec_store_get_at(p->store, tpath);
        free(tpath);
    }

    if (!typedef_e) {
        /* unknown type → verdict (not a 4xx): one unknown_type violation */
        ec_value *m = ec_map();
        ec_value *vs = ec_array();
        ec_value *v = ec_map();
        bool bad = !m || !vs || !v;
        if (!bad) {
            ec_value *k;
            k = ec_text("kind"); bad |= !k || ec_map_put(v, k, ec_text("unknown_type")) != EC_OK;
            k = ec_text("field"); bad |= !k || ec_map_put(v, k, ec_text(type_name)) != EC_OK;
            k = ec_text("message"); bad |= !k || ec_map_put(v, k, ec_text("no registered type definition")) != EC_OK;
        }
        ec_entity *r = NULL;
        if (!bad && ec_array_push(vs, v) == EC_OK) {
            v = NULL;
            ec_value *k1 = ec_text("valid");
            ec_value *k2 = ec_text("violations");
            if (k1 && k2 && ec_map_put(m, k1, ec_bool(false)) == EC_OK &&
                ec_map_put(m, k2, vs) == EC_OK &&
                ec_entity_make_owning("system/type/validate-result", m, &r) == EC_OK) {
                outcome_ok(out, r);
            } else {
                ec_value_free(k1); ec_value_free(k2); ec_value_free(vs); ec_value_free(m);
                outcome_err(out, 500, "internal_error", NULL);
            }
        } else {
            ec_value_free(v); ec_value_free(vs); ec_value_free(m);
            outcome_err(out, 500, "internal_error", NULL);
        }
        ec_entity_unref(subject);
        ec_entity_unref(req);
        return;
    }

    /* declared fields (a map of field-name → field-spec) + subject data (may be scalar) */
    const ec_value *fields = ec_ent_map_field(typedef_e, "fields");
    const ec_value *subj_data = (subject->data && subject->data->kind == EC_MAP)
                                ? subject->data : NULL;

    ec_value *violations = ec_array();
    ec_value *unevaluated = ec_array();
    bool bad = !violations || !unevaluated;

    /* required-field presence (a field is required unless its spec has optional:true) */
    if (!bad && fields && fields->kind == EC_MAP) {
        for (size_t i = 0; i < fields->as.map.len; i++) {
            const ec_value *fk = fields->as.map.entries[i].key;
            const ec_value *spec = fields->as.map.entries[i].val;
            if (!fk || fk->kind != EC_TEXT) {
                continue;
            }
            const char *fname = (const char *)fk->as.bytes.p;
            bool optional = false;
            if (spec && spec->kind == EC_MAP) {
                const ec_value *opt = ec_map_get(spec, "optional");
                optional = ec_v_is_true(opt);
            }
            bool present = subj_data && ec_map_get(subj_data, fname) != NULL;
            if (!optional && !present) {
                ec_value *viol = ec_map();
                ec_value *k;
                bool vb = !viol;
                k = ec_text("kind"); vb |= !k || ec_map_put(viol, k, ec_text("missing_required_field")) != EC_OK;
                k = ec_text("field"); vb |= !k || ec_map_put(viol, k, ec_text(fname)) != EC_OK;
                k = ec_text("message"); vb |= !k || ec_map_put(viol, k, ec_text("required field absent")) != EC_OK;
                if (vb || ec_array_push(violations, viol) != EC_OK) {
                    ec_value_free(viol);
                    bad = true;
                    break;
                }
            }
        }
    }

    /* unevaluated (extra) fields not declared by the type — reporting, not a hard fail */
    if (!bad && subj_data) {
        for (size_t i = 0; i < subj_data->as.map.len; i++) {
            const ec_value *sk = subj_data->as.map.entries[i].key;
            if (!sk || sk->kind != EC_TEXT) {
                continue;
            }
            const char *sname = (const char *)sk->as.bytes.p;
            bool declared = fields && fields->kind == EC_MAP && ec_map_get(fields, sname) != NULL;
            if (!declared) {
                ec_value *e = ec_text(sname);
                if (!e || ec_array_push(unevaluated, e) != EC_OK) {
                    ec_value_free(e);
                    bad = true;
                    break;
                }
            }
        }
    }

    ec_entity *result = NULL;
    if (!bad) {
        bool valid = violations->as.arr.len == 0;
        ec_value *m = ec_map();
        ec_value *k = m ? ec_text("valid") : NULL;
        bool mb = !m || !k || ec_map_put(m, k, ec_bool(valid)) != EC_OK;
        if (!mb && violations->as.arr.len > 0) {
            ec_value *kv = ec_text("violations");
            mb = !kv || ec_map_put(m, kv, violations) != EC_OK;
            if (!mb) { violations = NULL; }
        }
        if (!mb && unevaluated->as.arr.len > 0) {
            ec_value *ku = ec_text("unevaluated_fields");
            mb = !ku || ec_map_put(m, ku, unevaluated) != EC_OK;
            if (!mb) { unevaluated = NULL; }
        }
        if (!mb && ec_entity_make_owning("system/type/validate-result", m, &result) == EC_OK) {
            outcome_ok(out, result);
        } else {
            ec_value_free(m);
            outcome_err(out, 500, "internal_error", NULL);
        }
    } else {
        outcome_err(out, 500, "internal_error", NULL);
    }
    ec_value_free(violations);
    ec_value_free(unevaluated);
    ec_entity_unref(typedef_e);
    ec_entity_unref(subject);
    ec_entity_unref(req);
}

/* ── §7a conformance handlers ────────────────────────────────────────────────── */

static void h_validate_echo(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                            const ec_entity *exec, const ec_entity *caller_cap,
                            const char *op, ec_outcome *out)
{
    (void)p; (void)conn; (void)env; (void)caller_cap;
    if (strcmp(op, "echo") != 0) {
        outcome_err(out, 501, "unsupported_operation", op);
        return;
    }
    ec_entity *params = ec_ent_entity_field(exec, "params");
    if (params) {
        outcome_ok(out, params);   /* transfers the +1 ref */
    } else {
        outcome_err(out, 400, "invalid_params", "echo requires a params entity");
    }
}

/*
 * §6.13(b) handler-facing outbound dispatch: originate an EXECUTE back to the caller
 * (validator-as-B) over the SAME inbound connection (§6.11 reentry; NOT a fresh dial) and
 * await its response. The reentry capability + granter + cap-signature travel in `included`
 * exactly as a session EXECUTE carries its §5.8 authority chain. *out_resp is the response
 * envelope (+1 ref; caller frees) or NULL. The whole authority is caller-supplied (the
 * validator minted the reentry cap); we sign the EXECUTE with our own identity.
 */
static ec_status outbound_dispatch(ec_peer *p, ec_conn *conn, const char *uri,
                                   const char *operation, ec_entity *params,
                                   ec_entity *capability, ec_entity *granter,
                                   ec_entity *cap_sig, ec_value *resource,
                                   ec_envelope **out_resp)
{
    *out_resp = NULL;
    if (!conn || !conn->io) {
        return EC_ERR_BAD_INPUT;     /* no live reentry seam */
    }
    pthread_mutex_lock(&conn->lock);
    int n = ++conn->out_counter;
    pthread_mutex_unlock(&conn->lock);
    char rid[32];
    snprintf(rid, sizeof(rid), "out-%d", n);

    ec_entity *exec = NULL;
    ec_status st = ec_make_execute(rid, uri, operation, params,
                                   p->identity->identity_hash, capability->hash, resource, &exec);
    if (st != EC_OK) {
        return st;                   /* resource consumed by make_execute on success only */
    }
    ec_entity *exec_sig = NULL;
    st = ec_identity_sign(p->identity, exec, &exec_sig);
    if (st != EC_OK) {
        ec_entity_unref(exec);
        return st;
    }
    ec_envelope *req = NULL;
    st = ec_env_new(exec, &req);
    ec_entity_unref(exec);
    if (st != EC_OK) {
        ec_entity_unref(exec_sig);
        return st;
    }
    /* §5.8 authority chain travels in included (reentry cap + granter + our peer + sigs) */
    ec_env_add(req, capability);
    ec_env_add(req, granter);
    ec_env_add(req, p->identity->peer_entity);
    ec_env_add(req, cap_sig);
    ec_env_add(req, exec_sig);
    ec_entity_unref(exec_sig);

    *out_resp = ec_io_outbound(conn->io, req);
    ec_env_free(req);
    return EC_OK;
}

/*
 * dispatch-outbound (§6.13(b)/§6.11) — the real reentry relay (S4). A *generic relay*: the
 * params carry {target, operation, value, reentry_capability, reentry_granter,
 * reentry_cap_signature}. `value` is the downstream's params data and MUST be forwarded
 * VERBATIM (never re-wrapped/inspected — re-wrapping double-nests it, the keystone matrix
 * non-conformance, RULINGS-CONCURRENCY-GATE-7b-MATRIX-2026-06-13 #2). We originate an
 * EXECUTE back to the caller over the inbound connection (system/handler/{target}:{op})
 * with the caller-minted reentry authority, and return {status, result} from the
 * downstream response. With no live reentry seam → honest 503. OFF by default (--validate).
 */
static void h_validate_dispatch_outbound(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                                         const ec_entity *exec, const ec_entity *caller_cap,
                                         const char *op, ec_outcome *out)
{
    (void)env; (void)caller_cap;
    if (strcmp(op, "dispatch") != 0) {
        outcome_err(out, 501, "unsupported_operation", op);
        return;
    }
    ec_entity *params = ec_ent_entity_field(exec, "params");
    if (!params) {
        outcome_err(out, 400, "invalid_params", "dispatch-outbound requires a params entity");
        return;
    }
    const char *target = ec_ent_text(params, "target");
    const char *operation = ec_ent_text(params, "operation");
    const ec_value *value = ec_ent_field(params, "value");
    ec_entity *capability = ec_ent_entity_field(params, "reentry_capability");
    ec_entity *granter = ec_ent_entity_field(params, "reentry_granter");
    ec_entity *cap_sig = ec_ent_entity_field(params, "reentry_cap_signature");
    if (!target) { target = ""; }
    if (!operation) { operation = ""; }
    if (!value || !capability || !granter || !cap_sig) {
        ec_entity_unref(capability); ec_entity_unref(granter); ec_entity_unref(cap_sig);
        ec_entity_unref(params);
        outcome_err(out, 400, "invalid_params", "dispatch-outbound requires value + reentry authority");
        return;
    }
    if (!conn || !conn->io) {
        ec_entity_unref(capability); ec_entity_unref(granter); ec_entity_unref(cap_sig);
        ec_entity_unref(params);
        outcome_err(out, 503, "no_outbound_seam", "no live §6.11 reentry connection");
        return;
    }

    /* generic relay: forward `value` verbatim as the downstream EXECUTE's params data.
     * The validator already shapes it as the echo {value: X} params map; pass it through. */
    ec_entity *inner = NULL;
    if (ec_entity_make("primitive/any", value, &inner) != EC_OK) {
        ec_entity_unref(capability); ec_entity_unref(granter); ec_entity_unref(cap_sig);
        ec_entity_unref(params);
        outcome_err(out, 500, "internal_error", NULL);
        return;
    }

    /* resource target = the downstream handler path */
    size_t tn = strlen("system/handler/") + strlen(target) + 1;
    char *rt = malloc(tn);
    ec_value *resource = NULL;
    if (rt) {
        snprintf(rt, tn, "system/handler/%s", target);
        if (ec_resource_target(rt, &resource) != EC_OK) { resource = NULL; }
        free(rt);
    }

    ec_envelope *resp = NULL;
    ec_status st = outbound_dispatch(p, conn, target, operation, inner,
                                     capability, granter, cap_sig, resource, &resp);
    ec_entity_unref(inner);
    ec_entity_unref(capability);
    ec_entity_unref(granter);
    ec_entity_unref(cap_sig);
    ec_entity_unref(params);

    if (st != EC_OK || !resp) {
        ec_env_free(resp);
        outcome_err(out, 503, "no_outbound_seam", "reentry dispatch produced no response");
        return;
    }

    /* return {status, result} from the downstream response, verbatim */
    uint64_t dstatus = 0;
    ec_ent_uint(resp->root, "status", &dstatus);
    const ec_value *dresult = ec_ent_field(resp->root, "result");
    ec_value *m = ec_map();
    ec_value *k1 = m ? ec_text("status") : NULL;
    ec_value *k2 = m ? ec_text("result") : NULL;
    ec_value *result_copy = dresult ? ec_value_clone(dresult) : ec_map();
    ec_entity *r = NULL;
    if (m && k1 && k2 && result_copy &&
        ec_map_put(m, k1, ec_int_u(dstatus)) == EC_OK &&
        ec_map_put(m, k2, result_copy) == EC_OK &&
        ec_entity_make_owning("primitive/any", m, &r) == EC_OK) {
        outcome_ok(out, r);
    } else {
        ec_value_free(k1); ec_value_free(k2); ec_value_free(result_copy); ec_value_free(m);
        outcome_err(out, 500, "internal_error", NULL);
    }
    ec_env_free(resp);
}

/* ── §6.5 dispatch chain ─────────────────────────────────────────────────────── */

/* Wrap an outcome in an EXECUTE_RESPONSE envelope (+1 ref out). */
static ec_status build_response_envelope(const char *request_id, ec_outcome *o,
                                         ec_envelope **out)
{
    ec_entity *result = o->result;
    bool made_empty = false;
    if (!result) {
        if (ec_empty_params(&result) != EC_OK) {
            return EC_ERR_OOM;
        }
        made_empty = true;
    }
    ec_entity *resp = NULL;
    ec_status st = ec_make_response(request_id, o->status, result, &resp);
    if (made_empty) {
        ec_entity_unref(result);
    }
    if (st != EC_OK) {
        return st;
    }
    ec_envelope *env = NULL;
    st = ec_env_new(resp, &env);
    ec_entity_unref(resp);
    if (st != EC_OK) {
        return st;
    }
    for (size_t i = 0; i < o->included_len; i++) {
        ec_env_add(env, o->included[i]);
    }
    *out = env;
    return EC_OK;
}

ec_status ec_peer_dispatch(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                           ec_envelope **out)
{
    ec_entity *exec = env->root;
    if (strcmp(exec->type, "system/protocol/execute") != 0) {
        *out = NULL;             /* §3.3 server side ignores non-EXECUTE roots */
        return EC_OK;
    }
    const char *request_id = ec_ent_text(exec, "request_id");
    if (!request_id) { request_id = ""; }
    const char *uri = ec_ent_text(exec, "uri");
    const char *operation = ec_ent_text(exec, "operation");
    if (!uri) { uri = ""; }
    if (!operation) { operation = ""; }

    ec_outcome o;
    outcome_init(&o);

    /* connect path: unauthenticated */
    if (strcmp(uri, "system/protocol/connect") == 0) {
        ec_handler_fn fn = lookup_handler(p, "system/protocol/connect");
        if (fn) {
            fn(p, conn, env, exec, NULL, operation, &o);
        } else {
            outcome_err(&o, 500, "internal_error", NULL);
        }
        goto respond;
    }

    /* §6.5 signature ingestion + §5.2 verify */
    ingest_signatures(p, env);
    ec_req_verdict v = ec_cap_verify_request(p->local, p->store, env);
    switch (v) {
        case EC_REQ_AUTHN_FAIL:    outcome_err(&o, 401, "authentication_failed", NULL); goto respond;
        case EC_REQ_AUTHZ_DENY:    outcome_err(&o, 403, "capability_denied", NULL); goto respond;
        case EC_REQ_CHAIN_TOO_DEEP:outcome_err(&o, 400, "chain_depth_exceeded", NULL); goto respond;
        case EC_REQ_UNRESOLVABLE:  outcome_err(&o, 401, "unresolvable_grantee", NULL); goto respond;
        case EC_REQ_ALLOW:         break;
    }

    /* §1.4 path resolution + local-peer gate */
    {
        char *norm = NULL, *path = NULL, *target_peer = NULL;
        if (ec_normalize_uri(uri, &norm) != EC_OK ||
            ec_canonicalize(p->local, norm, &path) != EC_OK) {
            free(norm);
            outcome_err(&o, 400, "invalid_path", uri);
            goto respond;
        }
        free(norm);
        if (ec_extract_peer(p->local, path, &target_peer) != EC_OK ||
            strcmp(target_peer, p->local) != 0) {
            free(path); free(target_peer);
            outcome_err(&o, 404, "handler_not_found", "not local peer");
            goto respond;
        }
        free(target_peer);

        char *pattern = resolve_handler_path(p, path);
        free(path);
        if (!pattern) {
            outcome_err(&o, 404, "handler_not_found", uri);
            goto respond;
        }

        /* resolve the caller cap from the envelope */
        size_t cl = 0;
        const uint8_t *cap_h = ec_ent_bytes(exec, "capability", &cl);
        ec_entity *caller_cap = (cap_h && cl == 33) ? ec_env_get(env, cap_h) : NULL;
        if (!caller_cap) {
            free(pattern);
            outcome_err(&o, 403, "capability_denied", NULL);
            goto respond;
        }
        ec_entity_ref(caller_cap);

        /* §PR-8 granter frame */
        char *granter_peer = NULL;
        if (ec_cap_resolve_granter_peer(env, p->store, caller_cap, &granter_peer) != EC_OK) {
            granter_peer = NULL;
        }
        const char *gframe = granter_peer ? granter_peer : p->local;

        ec_verdict perm = ec_cap_check_permission(p->local, gframe, exec, caller_cap, pattern);
        free(granter_peer);
        if (perm == EC_V_DENY) {
            free(pattern);
            ec_entity_unref(caller_cap);
            outcome_err(&o, 403, "capability_denied", NULL);
            goto respond;
        }

        const char *stripped = strip_local(p, pattern);
        ec_handler_fn fn = lookup_handler(p, stripped);
        if (fn) {
            fn(p, conn, env, exec, caller_cap, operation, &o);
        } else {
            outcome_err(&o, 501, "no_handler_body", pattern);
        }
        free(pattern);
        ec_entity_unref(caller_cap);
    }

respond:
    {
        ec_status st = build_response_envelope(request_id, &o, out);
        outcome_clear(&o);
        return st;
    }
}

/* ── bootstrap (§6.9 / §6.9a) ────────────────────────────────────────────────── */

/* Bootstrap the handler-discovery entities (manifest + interface + empty grant). */
/* Build the interface `operations` map: op-name → operation-spec (empty spec map; the
 * §6 operations-match check only requires the op-name keys to be present). owned out. */
static ec_value *operations_map(const char *const *ops, size_t nops)
{
    ec_value *m = ec_map();
    if (!m) { return NULL; }
    for (size_t i = 0; i < nops; i++) {
        ec_value *k = ec_text(ops[i]);
        ec_value *spec = ec_map();
        if (!k || !spec || ec_map_put(m, k, spec) != EC_OK) {
            ec_value_free(k); ec_value_free(spec); ec_value_free(m);
            return NULL;
        }
    }
    return m;
}

static ec_status bootstrap_handler_entities(ec_peer *p, const char *pattern, const char *name,
                                            const char *const *ops, size_t nops)
{
    /* manifest at /{local}/{pattern} */
    ec_value *hm = ec_map();
    if (!hm) { return EC_ERR_OOM; }
    ec_value *k = ec_text("interface");
    size_t n = strlen("system/handler/") + strlen(pattern) + 1;
    char *iface_rel = malloc(n);
    if (iface_rel) { snprintf(iface_rel, n, "system/handler/%s", pattern); }
    ec_entity *he = NULL;
    if (!k || !iface_rel || ec_map_put(hm, k, ec_text(iface_rel)) != EC_OK ||
        ec_entity_make_owning("system/handler", hm, &he) != EC_OK) {
        ec_value_free(k); ec_value_free(hm); free(iface_rel);
        return EC_ERR_OOM;
    }
    free(iface_rel);
    char *path = abs_path(p, pattern);
    if (path) { ec_store_bind(p->store, path, he); free(path); }
    ec_entity_unref(he);

    /* interface entity at /{local}/system/handler/{pattern} */
    ec_value *im = ec_map();
    bool bad = !im;
    k = ec_text("pattern"); bad |= !k || ec_map_put(im, k, ec_text(pattern)) != EC_OK;
    k = ec_text("name"); bad |= !k || ec_map_put(im, k, ec_text(name)) != EC_OK;
    {
        ec_value *opm = operations_map(ops, nops);
        k = ec_text("operations");
        bad |= !k || !opm || ec_map_put(im, k, opm) != EC_OK;
        if (bad && opm && !k) { ec_value_free(opm); }
    }
    ec_entity *ie = NULL;
    if (bad || ec_entity_make_owning("system/handler/interface", im, &ie) != EC_OK) {
        if (bad) { ec_value_free(im); }
        return EC_ERR_OOM;
    }
    size_t hn = strlen(p->local) + strlen(pattern) + 32;
    char *ipath = malloc(hn);
    if (ipath) {
        snprintf(ipath, hn, "/%s/system/handler/%s", p->local, pattern);
        ec_store_bind(p->store, ipath, ie);
        free(ipath);
    }
    ec_entity_unref(ie);

    /* empty self-grant */
    ec_value *grants = ec_array();
    ec_entity *token = NULL, *sig = NULL;
    if (grants && mint_token(p, p->identity->identity_hash, grants, NULL, &token, &sig) == EC_OK) {
        size_t gn = strlen(p->local) + strlen(pattern) + 48;
        char *gpath = malloc(gn);
        if (gpath) {
            snprintf(gpath, gn, "/%s/system/capability/grants/%s", p->local, pattern);
            ec_store_bind(p->store, gpath, token);
            free(gpath);
        }
        ec_entity_unref(token);
        ec_entity_unref(sig);
    }
    return EC_OK;
}

ec_status ec_peer_create(const uint8_t seed[32], bool open_grants, bool conformance,
                         ec_peer **out)
{
    ec_status st;
    ec_peer *p = calloc(1, sizeof(*p));
    if (!p) {
        return EC_ERR_OOM;
    }
    p->open_grants = open_grants;
    p->conformance = conformance;
    st = ec_identity_of_seed(seed, &p->identity);
    if (st != EC_OK) { goto fail; }
    st = ec_store_new(&p->store);
    if (st != EC_OK) { goto fail; }
    p->local = strdup(p->identity->peer_id);
    if (!p->local) { st = EC_ERR_OOM; goto fail; }

    /* local identity entity in the store (root-granter resolution) */
    ec_store_put(p->store, p->identity->peer_entity);

    /* register + bootstrap the MUST handlers + the §9.5 type-registry handler. The `ops`
     * are the §6 operation names the interface entity advertises (operations-match gate). */
    static const char *ops_tree[]    = { "get", "put" };
    static const char *ops_handler[] = { "register", "unregister" };
    static const char *ops_cap[]     = { "request", "revoke", "configure", "delegate" };
    static const char *ops_connect[] = { "hello", "authenticate" };
    static const char *ops_type[]    = { "validate" };
    struct { const char *pattern; const char *name; ec_handler_fn fn;
             const char *const *ops; size_t nops; } must[] = {
        { "system/tree", "Tree", h_tree, ops_tree, 2 },
        { "system/handler", "Handlers", h_handlers, ops_handler, 2 },
        { "system/capability", "Capability", h_capability, ops_cap, 4 },
        { "system/protocol/connect", "Connect", h_connect, ops_connect, 2 },
        { "system/type", "Type", h_type, ops_type, 1 },
    };
    for (size_t i = 0; i < sizeof(must) / sizeof(must[0]); i++) {
        st = register_handler(p, must[i].pattern, must[i].fn);
        if (st != EC_OK) { goto fail; }
        st = bootstrap_handler_entities(p, must[i].pattern, must[i].name, must[i].ops, must[i].nops);
        if (st != EC_OK) { goto fail; }
    }

    /* §6.9a Peer Authority Bootstrap: self-owner cap + default policy entry */
    {
        ec_value *og = owner_grants(p);
        ec_entity *token = NULL, *sig = NULL;
        if (og && mint_token(p, p->identity->identity_hash, og, NULL, &token, &sig) == EC_OK) {
            char *ihex = ec_hex(p->identity->identity_hash, 33);
            if (ihex) {
                size_t n = strlen(p->local) + strlen(ihex) + 48;
                char *path = malloc(n);
                if (path) {
                    snprintf(path, n, "/%s/system/capability/policy/%s", p->local, ihex);
                    ec_store_bind(p->store, path, token);
                    free(path);
                }
                char *thex = ec_hex(token->hash, 33);
                if (thex) {
                    size_t n2 = strlen(p->local) + strlen(thex) + 32;
                    char *spath = malloc(n2);
                    if (spath) {
                        snprintf(spath, n2, "/%s/system/signature/%s", p->local, thex);
                        ec_store_bind(p->store, spath, sig);
                        free(spath);
                    }
                    free(thex);
                }
                free(ihex);
            }
            ec_entity_unref(token);
            ec_entity_unref(sig);
        } else {
            ec_value_free(og);
        }
        /* default policy entry */
        ec_value *def_grants = open_grants ? open_grants_scope() : discovery_floor();
        ec_value *dm = ec_map();
        ec_value *k1 = dm ? ec_text("peer_pattern") : NULL;
        ec_value *k2 = dm ? ec_text("grants") : NULL;
        ec_entity *de = NULL;
        if (def_grants && dm && k1 && k2 &&
            ec_map_put(dm, k1, ec_text("default")) == EC_OK &&
            ec_map_put(dm, k2, def_grants) == EC_OK &&
            ec_entity_make_owning("system/capability/policy-entry", dm, &de) == EC_OK) {
            char *path = abs_path(p, "system/capability/policy/default");
            if (path) { ec_store_bind(p->store, path, de); free(path); }
            ec_entity_unref(de);
        } else {
            ec_value_free(def_grants); ec_value_free(k1); ec_value_free(k2); ec_value_free(dm);
        }
    }

    /* §9.5 53-type core floor — published for every peer (the type_system surface) */
    st = publish_core_types(p);
    if (st != EC_OK) { goto fail; }

    /* §7a conformance handlers — only under --validate */
    if (conformance) {
        static const char *ops_echo[]     = { "echo" };
        static const char *ops_dispatch[] = { "dispatch" };
        struct { const char *pattern; const char *name; ec_handler_fn fn;
                 const char *const *ops; size_t nops; } conf[] = {
            { "system/validate/echo", "validate-echo", h_validate_echo, ops_echo, 1 },
            { "system/validate/dispatch-outbound", "validate-dispatch-outbound",
              h_validate_dispatch_outbound, ops_dispatch, 1 },
        };
        for (size_t i = 0; i < sizeof(conf) / sizeof(conf[0]); i++) {
            st = register_handler(p, conf[i].pattern, conf[i].fn);
            if (st != EC_OK) { goto fail; }
            st = bootstrap_handler_entities(p, conf[i].pattern, conf[i].name, conf[i].ops, conf[i].nops);
            if (st != EC_OK) { goto fail; }
        }
    }

    *out = p;
    return EC_OK;
fail:
    ec_peer_free(p);
    return st;
}

void ec_peer_free(ec_peer *p)
{
    if (!p) {
        return;
    }
    ec_identity_free(p->identity);
    ec_store_free(p->store);
    free(p->local);
    for (size_t i = 0; i < p->handlers_len; i++) {
        free(p->handlers[i].pattern);
    }
    free(p->handlers);
    free(p);
}
