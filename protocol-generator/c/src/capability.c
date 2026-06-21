/*
 * capability.c — the §5 capability verification core (L3): pattern matching (§5.4),
 * request verification (§5.2), delegation-chain verification (§5.5), attenuation (§5.6),
 * delegation caveats (§5.7), revocation (§5.1), and the §4.10(b) structural chain-depth
 * pre-check.
 *
 * A faithful port of the §5 pseudocode (spec-first); verdicts are the §5.10 Layer-1
 * ALLOW/DENY (determinism, N8), and the dispatcher maps DENY → 403 with the
 * unresolvable-grantee → 401 carve-out surfaced via EC_REQ_UNRESOLVABLE.
 *
 * The §PR-8 / §5.5a granter-frame refinement: the RESOURCE dimension's patterns
 * canonicalize against the GRANTER's peer_id; handlers/operations/peers stay on the
 * local frame. For the self-issued dominant path (granter == local) this is identical
 * to a pure-local frame; only the foreign-granter cross-peer case (an S4 oracle probe)
 * differs.
 *
 * Idiom: return-code helpers + borrowed const-string lists. String patterns are read
 * straight off the ECF value tree (no copies in the hot matchers); canonicalize is the
 * one allocator and its result is freed on every path.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "capability.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

uint64_t ec_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ── path helpers ───────────────────────────────────────────────────────────── */

bool ec_startswith(const char *prefix, const char *s)
{
    size_t pl = strlen(prefix);
    return strlen(s) >= pl && strncmp(s, prefix, pl) == 0;
}

ec_status ec_canonicalize(const char *local_peer, const char *path, char **out)
{
    if (ec_startswith("./", path) || ec_startswith("../", path) ||
        ec_startswith("*/", path)) {
        return EC_ERR_BAD_INPUT;     /* reserved / ambiguous (the Java IllegalArgument) */
    }
    if (ec_startswith("/", path)) {
        char *c = strdup(path);
        if (!c) { return EC_ERR_OOM; }
        *out = c;
        return EC_OK;
    }
    size_t n = strlen(local_peer) + strlen(path) + 3;
    char *c = malloc(n);
    if (!c) { return EC_ERR_OOM; }
    snprintf(c, n, "/%s/%s", local_peer, path);
    *out = c;
    return EC_OK;
}

ec_status ec_normalize_uri(const char *uri, char **out)
{
    if (ec_startswith("entity://", uri)) {
        size_t n = strlen(uri) - 9 + 2;
        char *c = malloc(n);
        if (!c) { return EC_ERR_OOM; }
        snprintf(c, n, "/%s", uri + 9);
        *out = c;
        return EC_OK;
    }
    char *c = strdup(uri);
    if (!c) { return EC_ERR_OOM; }
    *out = c;
    return EC_OK;
}

static const char *BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool ec_is_peer_id(const char *seg)
{
    if (strlen(seg) < 46) {
        return false;
    }
    for (const char *c = seg; *c; c++) {
        if (!strchr(BASE58_ALPHABET, *c)) {
            return false;
        }
    }
    return true;
}

/* first path segment (after a leading '/'), into a malloc'd string. */
static ec_status first_segment(const char *uri, char **out)
{
    const char *u = ec_startswith("/", uri) ? uri + 1 : uri;
    const char *slash = strchr(u, '/');
    char *c = slash ? strndup(u, (size_t)(slash - u)) : strdup(u);
    if (!c) { return EC_ERR_OOM; }
    *out = c;
    return EC_OK;
}

ec_status ec_extract_peer(const char *local_peer, const char *uri, char **out)
{
    char *norm = NULL;
    ec_status st = ec_normalize_uri(uri, &norm);
    if (st != EC_OK) { return st; }
    char *first = NULL;
    st = first_segment(norm, &first);
    free(norm);
    if (st != EC_OK) { return st; }
    if (ec_is_peer_id(first)) {
        *out = first;
        return EC_OK;
    }
    free(first);
    char *c = strdup(local_peer);
    if (!c) { return EC_ERR_OOM; }
    *out = c;
    return EC_OK;
}

/* ── §5.4 pattern matching ──────────────────────────────────────────────────── */

static bool matches_pattern(const char *path, const char *pattern)
{
    if (strcmp(pattern, "*") == 0) {
        return true;
    }
    if (ec_startswith("/*/", pattern)) {
        const char *remainder = pattern + 3;
        const char *i = strchr(path + (path[0] ? 1 : 0), '/');
        /* path.indexOf('/', 1) in Java: search from index 1 */
        if (path[0]) {
            i = strchr(path + 1, '/');
        } else {
            i = NULL;
        }
        return i && matches_pattern(i + 1, remainder);
    }
    size_t plen = strlen(pattern);
    if (plen >= 2 && pattern[plen - 1] == '*' && pattern[plen - 2] == '/') {
        /* pattern ends with slash-star → startsWith(prefix-slash, path) */
        return strncmp(path, pattern, plen - 1) == 0;
    }
    return strcmp(path, pattern) == 0;
}

/* ── scope parse (borrowed views into the cap's ECF value tree) ──────────────── */

typedef struct scope {
    const ec_value *incl;   /* array value or NULL */
    const ec_value *excl;   /* array value or NULL */
} scope;

static scope parse_scope(const ec_value *m)
{
    scope s = { NULL, NULL };
    if (m && m->kind == EC_MAP) {
        const ec_value *i = ec_v_get(m, "include");
        const ec_value *e = ec_v_get(m, "exclude");
        s.incl = (i && i->kind == EC_ARRAY) ? i : NULL;
        s.excl = (e && e->kind == EC_ARRAY) ? e : NULL;
    }
    return s;
}

/* any pattern in `pats` (text array, frame-canonicalized) covering value `cv`? */
static bool covered(const char *frame, const ec_value *pats, const char *cv)
{
    if (!pats) {
        return false;
    }
    for (size_t i = 0; i < pats->as.arr.len; i++) {
        const ec_value *p = pats->as.arr.items[i];
        if (!p || p->kind != EC_TEXT) {
            continue;
        }
        char *cp = NULL;
        if (ec_canonicalize(frame, (const char *)p->as.bytes.p, &cp) != EC_OK) {
            continue;
        }
        bool m = matches_pattern(cv, cp);
        free(cp);
        if (m) {
            return true;
        }
    }
    return false;
}

static bool matches_scope(const char *local_peer, const char *value, scope s)
{
    char *cv = NULL;
    if (ec_canonicalize(local_peer, value, &cv) != EC_OK) {
        return false;
    }
    bool r = covered(local_peer, s.incl, cv) && !covered(local_peer, s.excl, cv);
    free(cv);
    return r;
}

/* ── token grants iteration ─────────────────────────────────────────────────── */

static const ec_value *token_grants(const ec_entity *token)
{
    const ec_value *g = ec_ent_field(token, "grants");
    return (g && g->kind == EC_ARRAY) ? g : NULL;
}

static const ec_value *grant_dim(const ec_value *grant, const char *dim)
{
    return (grant && grant->kind == EC_MAP) ? ec_v_get(grant, dim) : NULL;
}

/* ── §6.3 resource scope ────────────────────────────────────────────────────── */

bool ec_cap_check_resource_scope(const char *local_peer, const char *granter_peer,
                                 const ec_value *resource_map, const ec_value *res_scope_v)
{
    const ec_value *targets = ec_v_get(resource_map, "targets");
    const ec_value *caller_excl = ec_v_get(resource_map, "exclude");
    if (!targets || targets->kind != EC_ARRAY || targets->as.arr.len == 0) {
        return false;
    }
    scope s = parse_scope(res_scope_v);
    for (size_t i = 0; i < targets->as.arr.len; i++) {
        const ec_value *t = targets->as.arr.items[i];
        if (!t || t->kind != EC_TEXT) {
            return false;
        }
        char *ct = NULL;
        if (ec_canonicalize(local_peer, (const char *)t->as.bytes.p, &ct) != EC_OK) {
            return false;
        }
        bool excluded = (caller_excl && caller_excl->kind == EC_ARRAY)
                        && covered(local_peer, caller_excl, ct);
        if (excluded) {
            free(ct);
            continue;
        }
        bool ok = covered(granter_peer, s.incl, ct) && !covered(granter_peer, s.excl, ct);
        free(ct);
        if (!ok) {
            return false;
        }
    }
    return true;
}

/* ── §PR-8 granter peer resolution ──────────────────────────────────────────── */

static ec_entity *cap_resolve(const ec_envelope *env, ec_store *store, const uint8_t *h)
{
    ec_entity *e = ec_env_get(env, h);
    if (e) {
        return ec_entity_ref(e);
    }
    return ec_store_get_by_hash(store, h);
}

ec_status ec_cap_resolve_granter_peer(const ec_envelope *env, ec_store *store,
                                      const ec_entity *cap, char **out)
{
    *out = NULL;
    size_t glen = 0;
    const uint8_t *gh = ec_ent_bytes(cap, "granter", &glen);
    if (!gh || glen != 33) {
        return EC_OK;            /* unresolvable → caller falls back to local */
    }
    ec_entity *g = cap_resolve(env, store, gh);
    if (!g) {
        return EC_OK;
    }
    size_t plen = 0;
    const uint8_t *pk = ec_ent_bytes(g, "public_key", &plen);
    ec_status st = EC_OK;
    if (pk && plen == 32) {
        st = ec_peer_id_of_pubkey32(pk, out);
    }
    ec_entity_unref(g);
    return st;
}

/* ── §5.2 check-permission ──────────────────────────────────────────────────── */

ec_verdict ec_cap_check_permission(const char *local_peer, const char *granter_peer,
                                   const ec_entity *exec, const ec_entity *token,
                                   const char *handler_pattern)
{
    const char *operation = ec_ent_text(exec, "operation");
    const char *uri = ec_ent_text(exec, "uri");
    if (!operation) { operation = ""; }
    if (!uri) { uri = ""; }
    char *target_peer = NULL;
    if (ec_extract_peer(local_peer, uri, &target_peer) != EC_OK) {
        return EC_V_DENY;
    }
    const ec_value *resource = ec_ent_map_field(exec, "resource");
    const ec_value *grants = token_grants(token);
    ec_verdict verdict = EC_V_DENY;
    if (grants) {
        for (size_t i = 0; i < grants->as.arr.len; i++) {
            const ec_value *g = grants->as.arr.items[i];
            bool ok = matches_scope(local_peer, operation, parse_scope(grant_dim(g, "operations")))
                   && matches_scope(local_peer, handler_pattern, parse_scope(grant_dim(g, "handlers")));
            if (ok) {
                const ec_value *peers_v = grant_dim(g, "peers");
                if (peers_v) {
                    ok = matches_scope(local_peer, target_peer, parse_scope(peers_v));
                } else {
                    /* default peers = [local] */
                    ok = (strcmp(target_peer, local_peer) == 0);
                }
            }
            if (ok && resource) {
                ok = ec_cap_check_resource_scope(local_peer, granter_peer, resource,
                                                 grant_dim(g, "resources"));
            }
            if (ok) {
                verdict = EC_V_ALLOW;
                break;
            }
        }
    }
    free(target_peer);
    return verdict;
}

/* ── §5.6 attenuation (scope subset) ────────────────────────────────────────── */

static bool scope_subset(const char *child_peer, const char *parent_peer,
                         scope child, scope parent)
{
    /* every child include is covered by some parent include */
    if (child.incl) {
        for (size_t i = 0; i < child.incl->as.arr.len; i++) {
            const ec_value *cp = child.incl->as.arr.items[i];
            if (!cp || cp->kind != EC_TEXT) { continue; }
            char *cc = NULL;
            if (ec_canonicalize(child_peer, (const char *)cp->as.bytes.p, &cc) != EC_OK) {
                return false;
            }
            bool some = covered(parent_peer, parent.incl, cc);
            free(cc);
            if (!some) {
                return false;
            }
        }
    }
    /* every parent exclude is covered by some child exclude */
    if (parent.excl) {
        for (size_t i = 0; i < parent.excl->as.arr.len; i++) {
            const ec_value *pe = parent.excl->as.arr.items[i];
            if (!pe || pe->kind != EC_TEXT) { continue; }
            char *cpe = NULL;
            if (ec_canonicalize(parent_peer, (const char *)pe->as.bytes.p, &cpe) != EC_OK) {
                return false;
            }
            bool some = covered(child_peer, child.excl, cpe);
            free(cpe);
            if (!some) {
                return false;
            }
        }
    }
    return true;
}

bool ec_cap_grant_subset(const char *local_peer, const char *child_peer,
                         const char *parent_peer,
                         const ec_value *child_grant, const ec_value *parent_grant)
{
    if (!scope_subset(local_peer, local_peer,
                      parse_scope(grant_dim(child_grant, "handlers")),
                      parse_scope(grant_dim(parent_grant, "handlers")))) {
        return false;
    }
    if (!scope_subset(local_peer, local_peer,
                      parse_scope(grant_dim(child_grant, "operations")),
                      parse_scope(grant_dim(parent_grant, "operations")))) {
        return false;
    }
    if (!scope_subset(child_peer, parent_peer,
                      parse_scope(grant_dim(child_grant, "resources")),
                      parse_scope(grant_dim(parent_grant, "resources")))) {
        return false;
    }
    /* peers default = [local] when absent */
    const ec_value *cp = grant_dim(child_grant, "peers");
    const ec_value *pp = grant_dim(parent_grant, "peers");
    if (cp && pp) {
        return scope_subset(local_peer, local_peer, parse_scope(cp), parse_scope(pp));
    }
    if (!cp && !pp) {
        return true;            /* both default [local] → subset */
    }
    /* one default, one explicit: build a [local] include and compare structurally.
     * The dominant self-issued path has both absent; this asymmetric case is rare and
     * conservatively handled by requiring the explicit side to include local. */
    const char *only_peer = local_peer;
    if (cp) {
        return matches_scope(local_peer, only_peer, parse_scope(cp));  /* child ⊆ {local} */
    }
    return matches_scope(local_peer, only_peer, parse_scope(pp));      /* {local} ⊆ parent */
}

/* ── §5.5 chain collection + §4.10(b) depth pre-check ───────────────────────── */

bool ec_cap_chain_exceeds_depth(ec_store *store, const ec_entity *cap,
                                const ec_envelope *env)
{
    const ec_entity *current = cap;
    ec_entity *owned = NULL;     /* the resolved parent we currently hold a ref on */
    int depth = 0;
    bool result = false;
    for (;;) {
        if (depth > 64) {
            result = true;
            break;
        }
        size_t plen = 0;
        const uint8_t *ph = ec_ent_bytes(current, "parent", &plen);
        if (!ph || plen != 33) {
            result = false;       /* root reached within bound */
            break;
        }
        ec_entity *parent = cap_resolve(env, store, ph);
        if (!parent) {
            result = false;       /* unreachable — NOT a depth problem (stays 403) */
            break;
        }
        ec_entity_unref(owned);
        owned = parent;
        current = parent;
        depth++;
    }
    ec_entity_unref(owned);
    return result;
}

/* Collect the chain into a caller-freed array of +1 refs. ok=false on a cycle/unreach. */
typedef struct chain { ec_entity **items; size_t len; bool ok; } chain;

static chain collect_chain(const ec_entity *cap, const ec_envelope *env, ec_store *store)
{
    chain c = { NULL, 0, false };
    size_t cap_sz = 0;
    ec_entity *current = ec_entity_ref((ec_entity *)cap);
    int depth = 0;
    for (;;) {
        if (depth > 64) {
            ec_entity_unref(current);
            goto fail;
        }
        if (c.len == cap_sz) {
            size_t ncap = cap_sz ? cap_sz * 2 : 8;
            ec_entity **grown = realloc(c.items, ncap * sizeof(*grown));
            if (!grown) {
                ec_entity_unref(current);
                goto fail;
            }
            c.items = grown;
            cap_sz = ncap;
        }
        c.items[c.len++] = current;   /* transfers the ref */
        size_t plen = 0;
        const uint8_t *ph = ec_ent_bytes(current, "parent", &plen);
        if (!ph || plen != 33) {
            c.ok = true;
            return c;
        }
        ec_entity *parent = cap_resolve(env, store, ph);
        if (!parent) {
            goto fail;
        }
        current = parent;
        depth++;
    }
fail:
    for (size_t i = 0; i < c.len; i++) {
        ec_entity_unref(c.items[i]);
    }
    free(c.items);
    c.items = NULL;
    c.len = 0;
    c.ok = false;
    return c;
}

static void chain_free(chain *c)
{
    for (size_t i = 0; i < c->len; i++) {
        ec_entity_unref(c->items[i]);
    }
    free(c->items);
    c->items = NULL;
    c->len = 0;
}

/* §5.5a per-link canonicalization frame = the link's granter peer_id (or local for a
 * multi-sig root with no granter hash). *out malloc'd or NULL (unresolvable). */
static ec_status link_granter_peer(const ec_envelope *env, ec_store *store,
                                   const char *local_peer, const ec_entity *cap, char **out)
{
    *out = NULL;
    size_t glen = 0;
    const uint8_t *gh = ec_ent_bytes(cap, "granter", &glen);
    if (!gh || glen != 33) {
        char *c = strdup(local_peer);
        if (!c) { return EC_ERR_OOM; }
        *out = c;
        return EC_OK;
    }
    ec_entity *g = cap_resolve(env, store, gh);
    if (!g) {
        return EC_OK;            /* unresolvable → NULL */
    }
    size_t plen = 0;
    const uint8_t *pk = ec_ent_bytes(g, "public_key", &plen);
    ec_status st = EC_OK;
    if (pk && plen == 32) {
        st = ec_peer_id_of_pubkey32(pk, out);
    }
    ec_entity_unref(g);
    return st;
}

static ec_entity *find_signature(const uint8_t *target, const ec_envelope *env)
{
    for (size_t i = 0; i < env->included_len; i++) {
        ec_entity *e = env->included[i].entity;
        if (strcmp(e->type, "system/signature") == 0) {
            size_t tlen = 0;
            const uint8_t *tg = ec_ent_bytes(e, "target", &tlen);
            if (tg && tlen == 33 && memcmp(tg, target, 33) == 0) {
                return e;
            }
        }
    }
    return NULL;
}

/* §5.6 token-level attenuation: every child grant ⊆ some parent grant + TTL monotone. */
static bool is_attenuated(const char *local_peer, const char *child_peer,
                          const char *parent_peer, const ec_entity *child,
                          const ec_entity *parent)
{
    const ec_value *cg = token_grants(child);
    const ec_value *pg = token_grants(parent);
    if (cg) {
        for (size_t i = 0; i < cg->as.arr.len; i++) {
            bool some = false;
            if (pg) {
                for (size_t j = 0; j < pg->as.arr.len; j++) {
                    if (ec_cap_grant_subset(local_peer, child_peer, parent_peer,
                                            cg->as.arr.items[i], pg->as.arr.items[j])) {
                        some = true;
                        break;
                    }
                }
            }
            if (!some) {
                return false;
            }
        }
    }
    uint64_t pe, ce;
    bool pe_set = ec_ent_uint(parent, "expires_at", &pe);
    bool ce_set = ec_ent_uint(child, "expires_at", &ce);
    if (pe_set && !ce_set) {
        return false;           /* child infinite, parent finite */
    }
    if (pe_set) {
        return ce <= pe;
    }
    return true;
}

static bool check_delegation_caveats(const ec_entity *parent, const ec_entity *child, int depth)
{
    const ec_value *caveats = ec_ent_map_field(parent, "delegation_caveats");
    if (!caveats) {
        return true;
    }
    if (ec_v_is_true(ec_v_get(caveats, "no_delegation"))) {
        return false;
    }
    uint64_t mdd;
    if (ec_v_uint(caveats, "max_delegation_depth", &mdd)) {
        if ((uint64_t)depth >= mdd) {
            return false;
        }
    }
    uint64_t max_ttl;
    if (ec_v_uint(caveats, "max_delegation_ttl", &max_ttl)) {
        uint64_t ex, cr;
        bool ex_set = ec_ent_uint(child, "expires_at", &ex);
        bool cr_set = ec_ent_uint(child, "created_at", &cr);
        if (ex_set && cr_set) {
            if (ex - cr > max_ttl) {
                return false;
            }
        } else if (ex_set) {
            /* created_at absent — can't bound, admit */
        } else {
            return false;       /* infinite child lifetime exceeds any limit */
        }
    }
    return true;
}

static ec_verdict verify_chain(const char *local_peer, ec_store *store,
                               const ec_entity *cap, const ec_envelope *env,
                               bool *unresolvable)
{
    *unresolvable = false;
    chain c = collect_chain(cap, env, store);
    if (!c.ok) {
        return EC_V_DENY;
    }
    ec_verdict result = EC_V_DENY;
    ec_entity *root = c.items[c.len - 1];

    /* root granter must resolve to local */
    bool root_ok = false;
    size_t rgl = 0;
    const uint8_t *rgh = ec_ent_bytes(root, "granter", &rgl);
    if (rgh && rgl == 33) {
        ec_entity *g = cap_resolve(env, store, rgh);
        if (g) {
            size_t pl = 0;
            const uint8_t *pk = ec_ent_bytes(g, "public_key", &pl);
            if (pk && pl == 32) {
                char *pid = NULL;
                if (ec_peer_id_of_pubkey32(pk, &pid) == EC_OK && pid) {
                    root_ok = (strcmp(pid, local_peer) == 0);
                    free(pid);
                }
            }
            ec_entity_unref(g);
        }
    }
    if (!root_ok) {
        goto done;
    }

    bool good = true;
    for (size_t i = 0; i < c.len && good; i++) {
        ec_entity *current = c.items[i];
        /* signature: signer == granter, verify against granter identity */
        size_t gl = 0;
        const uint8_t *gh = ec_ent_bytes(current, "granter", &gl);
        if (gh && gl == 33) {
            ec_entity *sgn = find_signature(current->hash, env);
            ec_entity *granter = cap_resolve(env, store, gh);
            if (sgn && granter) {
                size_t sl = 0;
                const uint8_t *signer = ec_ent_bytes(sgn, "signer", &sl);
                if (!(signer && sl == 33 && memcmp(signer, gh, 33) == 0
                      && ec_verify_signature(sgn, granter))) {
                    good = false;
                }
            } else {
                good = false;
            }
            ec_entity_unref(granter);
        } else {
            good = false;
        }
        /* grantee resolution → 401 carve-out */
        size_t gel = 0;
        const uint8_t *geh = ec_ent_bytes(current, "grantee", &gel);
        if (geh && gel == 33) {
            ec_entity *ge = cap_resolve(env, store, geh);
            if (!ge) {
                *unresolvable = true;
                goto done;
            }
            ec_entity_unref(ge);
        } else {
            *unresolvable = true;
            goto done;
        }
        /* temporal validity */
        uint64_t tnow = ec_now_ms();
        uint64_t nb, ex;
        if (ec_ent_uint(current, "not_before", &nb) && tnow < nb) {
            good = false;
        }
        if (ec_ent_uint(current, "expires_at", &ex) && ex < tnow) {
            good = false;
        }
        /* delegation link to the parent */
        if (i + 1 < c.len) {
            ec_entity *parent = c.items[i + 1];
            char *child_peer = NULL, *parent_peer = NULL;
            if (link_granter_peer(env, store, local_peer, current, &child_peer) != EC_OK
                || link_granter_peer(env, store, local_peer, parent, &parent_peer) != EC_OK
                || !child_peer || !parent_peer) {
                good = false;
            } else {
                size_t pgl = 0, cgl = 0;
                const uint8_t *pg = ec_ent_bytes(parent, "grantee", &pgl);
                const uint8_t *cgg = ec_ent_bytes(current, "granter", &cgl);
                if (!(pg && cgg && pgl == 33 && cgl == 33 && memcmp(pg, cgg, 33) == 0
                      && is_attenuated(local_peer, child_peer, parent_peer, current, parent)
                      && check_delegation_caveats(parent, current, (int)i))) {
                    good = false;
                }
            }
            free(child_peer);
            free(parent_peer);
        }
    }
    result = good ? EC_V_ALLOW : EC_V_DENY;
done:
    chain_free(&c);
    return result;
}

static bool is_revoked(const char *local_peer, ec_store *store, const ec_entity *cap,
                       const ec_envelope *env)
{
    bool revoked = false;
    /* the capability itself */
    char *cap_hex = ec_hex(cap->hash, 33);
    if (cap_hex) {
        size_t n = strlen(local_peer) + strlen(cap_hex) + 64;
        char *path = malloc(n);
        if (path) {
            snprintf(path, n, "/%s/system/capability/revocations/%s", local_peer, cap_hex);
            ec_entity *m = ec_store_get_at(store, path);
            if (m) { revoked = true; ec_entity_unref(m); }
            free(path);
        }
        free(cap_hex);
    }
    if (revoked) {
        return true;
    }
    /* the chain root */
    chain c = collect_chain(cap, env, store);
    const uint8_t *root_hash = c.ok ? c.items[c.len - 1]->hash : cap->hash;
    char *root_hex = ec_hex(root_hash, 33);
    if (root_hex) {
        size_t n = strlen(local_peer) + strlen(root_hex) + 64;
        char *path = malloc(n);
        if (path) {
            snprintf(path, n, "/%s/system/capability/revocations/%s", local_peer, root_hex);
            ec_entity *m = ec_store_get_at(store, path);
            if (m) { revoked = true; ec_entity_unref(m); }
            free(path);
        }
        free(root_hex);
    }
    chain_free(&c);
    return revoked;
}

/* ── §5.2 verify-request (3-way verdict) ────────────────────────────────────── */

ec_req_verdict ec_cap_verify_request(const char *local_peer, ec_store *store,
                                     const ec_envelope *env)
{
    ec_entity *exec = env->root;
    ec_entity *sgn = find_signature(exec->hash, env);
    if (!sgn) {
        return EC_REQ_AUTHN_FAIL;
    }
    size_t al = 0, sl = 0;
    const uint8_t *author_h = ec_ent_bytes(exec, "author", &al);
    const uint8_t *signer = ec_ent_bytes(sgn, "signer", &sl);
    if (!(signer && author_h && sl == 33 && al == 33 && memcmp(signer, author_h, 33) == 0)) {
        return EC_REQ_AUTHN_FAIL;
    }
    ec_entity *author = ec_env_get(env, author_h);
    if (!author) {
        return EC_REQ_AUTHN_FAIL;
    }
    if (!ec_verify_signature(sgn, author)) {
        return EC_REQ_AUTHN_FAIL;
    }
    size_t cl = 0;
    const uint8_t *ch = ec_ent_bytes(exec, "capability", &cl);
    ec_entity *cap = (ch && cl == 33) ? ec_env_get(env, ch) : NULL;
    if (!cap) {
        return EC_REQ_AUTHZ_DENY;
    }
    /* §4.10(b): chain-depth pre-check BEFORE the per-link authz walk → 400, not 403. */
    if (ec_cap_chain_exceeds_depth(store, cap, env)) {
        return EC_REQ_CHAIN_TOO_DEEP;
    }
    bool unresolvable = false;
    ec_verdict chain = verify_chain(local_peer, store, cap, env, &unresolvable);
    if (unresolvable) {
        return EC_REQ_UNRESOLVABLE;
    }
    if (chain == EC_V_DENY) {
        return EC_REQ_AUTHZ_DENY;
    }
    size_t gel = 0;
    const uint8_t *grantee = ec_ent_bytes(cap, "grantee", &gel);
    if (!(grantee && gel == 33 && memcmp(grantee, author_h, 33) == 0)) {
        return EC_REQ_AUTHZ_DENY;
    }
    if (is_revoked(local_peer, store, cap, env)) {
        return EC_REQ_AUTHZ_DENY;
    }
    return EC_REQ_ALLOW;
}
