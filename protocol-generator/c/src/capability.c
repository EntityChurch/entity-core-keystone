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

/* The unmatchable value (0.8.2.20). Unreachable as a canonical path by CONSTRUCTION:
 * its first segment cannot be a peer_id, since a peer_id needs >= 46 Base58 characters
 * and '-' is outside the Base58 alphabet. */
#define EC_NEVER_MATCH "/never-match"

/* ec_canonicalize FOR THE MATCHERS, which have no error channel. TOTAL (0.8.2.20):
 * the result is "a canonical path OR EC_NEVER_MATCH" (NULL only on OOM).
 *
 * ec_canonicalize itself keeps its EC_ERR_BAD_INPUT, because dispatch.c's address gate
 * and tree-path consumers use it as a refusal and are exactly the callers 0.8.2.20 says
 * SHOULD have the diagnostic. The defect was HERE: `covered` did `continue` on a
 * reserved form — the desired outcome in an INCLUDE and the opposite of it in an
 * EXCLUDE, so a grant exclude carrying "../x" carved out nothing and the grant was
 * silently wider than its author wrote (measured on the wire 2026-09-14). */
static char *canon_match(const char *frame, const char *path)
{
    char *c = NULL;
    if (ec_canonicalize(frame, path, &c) == EC_OK) {
        return c;
    }
    return strdup(EC_NEVER_MATCH);
}

/* AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED in
 * an include (covers nothing -> the grant grants nothing) and fail-OPEN in an exclude
 * (carves out nothing), so the reading is chosen where the POSITION is known and
 * matches_pattern stays uniform over its operands.
 *
 * PATH-SCOPE ONLY (0.8.2.24, N2/N3) — every caller must gate this on the dimension's
 * scope type. The two live callers do: matches_scope tests `kind == SCOPE_PATH`, and
 * check_resource_scope is the RESOURCES dimension, path-scope by definition. */
static bool exclude_is_unmatchable(const char *frame, const ec_value *excl)
{
    if (!excl || excl->kind != EC_ARRAY) {
        return false;
    }
    for (size_t i = 0; i < excl->as.arr.len; i++) {
        const ec_value *p = excl->as.arr.items[i];
        if (!p || p->kind != EC_TEXT) {
            continue;
        }
        char *cp = canon_match(frame, (const char *)p->as.bytes.p);
        bool nm = (cp != NULL) && strcmp(cp, EC_NEVER_MATCH) == 0;
        free(cp);
        if (nm) {
            return true;
        }
    }
    return false;
}

static bool matches_pattern(const char *path, const char *pattern)
{
    /* EC_NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
     * rule rather than a property of the string: the arm below returns true for a bare
     * "*", so safety must not rest on a value merely looking unmatchable. */
    if (strcmp(path, EC_NEVER_MATCH) == 0 || strcmp(pattern, EC_NEVER_MATCH) == 0) {
        return false;
    }
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
        char *cp = canon_match(frame, (const char *)p->as.bytes.p);
        if (!cp) {
            continue;                /* OOM only */
        }
        bool m = matches_pattern(cv, cp);
        free(cp);
        if (m) {
            return true;
        }
    }
    return false;
}

/* §5.2 id-scope match (0.8.1, F40) — `operations` and `peers`. Literal compare with
 * exactly two wildcard forms: bare "*" and a trailing slash-star segment-prefix. None
 * of the §5.4 path transforms apply — no leading-slash universal reading, no interior
 * peer-wildcard, no peer-relative qualification — so a pattern carrying path syntax is
 * matched as a literal string: a non-match, never a fault. */
static bool matches_id_pattern(const char *value, const char *pattern)
{
    if (strcmp(pattern, "*") == 0) {
        return true;
    }
    size_t plen = strlen(pattern);
    if (plen >= 2 && pattern[plen - 1] == '*' && pattern[plen - 2] == '/') {
        return strncmp(value, pattern, plen - 1) == 0;
    }
    return strcmp(value, pattern) == 0;
}

/* any id-scope pattern in `pats` covering `value` — no canonicalization */
static bool covered_id(const ec_value *pats, const char *value)
{
    if (!pats) {
        return false;
    }
    for (size_t i = 0; i < pats->as.arr.len; i++) {
        const ec_value *p = pats->as.arr.items[i];
        if (!p || p->kind != EC_TEXT) {
            continue;
        }
        if (matches_id_pattern(value, (const char *)p->as.bytes.p)) {
            return true;
        }
    }
    return false;
}

/* Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
 * call site — no default — so a new one cannot inherit the wrong matcher silently,
 * which is exactly the F40 defect. */
typedef enum { SCOPE_ID, SCOPE_PATH } scope_kind;

static bool matches_scope(const char *local_peer, const char *value, scope s, scope_kind kind)
{
    /* SCOPED TO PATH-SCOPE (0.8.2.24, N2/N3). §5.2's exclude loop now tests the
     * sentinel INSIDE `if dimension_type == "system/capability/path-scope"`, and §5.4
     * says the same from the other side: "a capability carrying an unmatchable
     * PATH-SCOPE pattern is INVALID ... It does NOT reach `operations` or `peers`
     * [MUST]". This guard was UNCONDITIONAL until 0.8.2.24 — which was the text at the
     * time (F82 was our own ask, and the grant created this work) — and under it an
     * ordinary namespaced operation name (a bare star, a slash, then "apply")
     * path-canonicalizes to the
     * sentinel and DENIES THE WHOLE DIMENSION. Over-denial, invisible on well-formed
     * grants.
     *
     * The two id-scope dimensions reach covered_id's literal arm below unguarded,
     * which is correct: under §3.6's id-scope grammar every non-"*" pattern is a
     * literal and a literal is never structurally unmatchable, so there is nothing
     * here for the sentinel to detect. §5.4 says so outright and leaves the id-scope
     * form of the carves-out-nothing hazard deliberately open rather than minting a
     * second sentinel for it — a scope boundary, not an omission. */
    if (kind == SCOPE_PATH && exclude_is_unmatchable(local_peer, s.excl)) {
        return false;                /* 0.8.2.21 — deny, do not carve out nothing */
    }
    if (kind == SCOPE_ID) {
        return covered_id(s.incl, value) && !covered_id(s.excl, value);
    }
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
    /* An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
     * target: the coverage test below is correct in isolation and is simply never
     * reached on a sentinel, because matches_pattern answers false. */
    if (exclude_is_unmatchable(granter_peer, s.excl)) {
        return false;
    }
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

/* ── §5.2 effective targets and §6.3 check_path_permission ──────────────────── */

/* effective_targets derives §5.2's effective target list (0.8.2.20): the caller's own
 * `resource.exclude` removes entries from the request BEFORE anything else looks at it.
 *
 * The survivors are BORROWED, in the caller's OWN SPELLING, not canonicalized —
 * 0.8.2.21 is explicit that effective_targets yields raw survivors, and the distinction
 * is load-bearing here because the value flows on to ec_store_get_at, which
 * canonicalizes for itself. The `len` beside each pointer is the VALUE-NODE byte length,
 * not strlen: a §1.4 R1 embedded NUL is invisible to the C-string view and path_flex_ok
 * needs both to see it.
 *
 * `had_resource` says whether a `resource` carrying a `targets` key was present at all.
 * An ABSENT resource and a resource whose every target was excluded are different inputs
 * to §3.3, and for a resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT
 * REQUESTS with different answers rather than merely different inputs to one.
 *
 * THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11): "where an
 * implementation projects resource.targets onto the effective set ahead of the handler,
 * that projection MUST NOT be lossy about its own emptiness — narrow when narrowing
 * leaves something, and retain the raw pair when narrowing would empty it." A function
 * returning only a list cannot satisfy that: collapsing [qA] exclude [qA] to [] deletes
 * the two-empties discriminator before any handler can read it, and the handler's
 * refusal arm becomes dead code only a WIRE drive can detect.
 *
 * This peer has exactly ONE narrowing seam — this function, called by the tree handler.
 * §6.5's dispatch chain does not project: ec_cap_check_permission reads `resource` for
 * itself. So there is no second door to keep in step, and adding a projection at
 * dispatch would create one.
 *
 * A PRESENT-BUT-ILL-TYPED `targets` is PRESENT: a non-array yields an empty survivor
 * list rather than "absent", so {"targets": 42} answers the present-but-empty
 * disposition and never the WIDER absent-case one. That is N11's own defect one field
 * over, and it is the cell the two vanguards initially disagreed on. */
ec_status ec_cap_effective_targets(const char *local_peer, const ec_entity *exec,
                                   ec_effective *out)
{
    out->items = NULL;
    out->len = 0;
    out->had_resource = false;
    const ec_value *r = ec_ent_map_field(exec, "resource");
    if (!r || r->kind != EC_MAP) {
        return EC_OK;
    }
    const ec_value *targets = ec_v_get(r, "targets");
    if (!targets) {
        return EC_OK;                /* no `targets` key at all — the ABSENT case */
    }
    out->had_resource = true;
    if (targets->kind != EC_ARRAY || targets->as.arr.len == 0) {
        return EC_OK;                /* present-but-empty / ill-typed: NOT absent */
    }
    const ec_value *caller_excl = ec_v_get(r, "exclude");
    ec_tgt *items = calloc(targets->as.arr.len, sizeof(*items));
    if (!items) {
        return EC_ERR_OOM;
    }
    size_t n = 0;
    for (size_t i = 0; i < targets->as.arr.len; i++) {
        const ec_value *t = targets->as.arr.items[i];
        if (!t || t->kind != EC_TEXT) {
            continue;
        }
        const char *raw = (const char *)t->as.bytes.p;
        char *ct = NULL;
        if (ec_canonicalize(local_peer, raw, &ct) != EC_OK) {
            /* ec_canonicalize answers the sentinel rather than failing for the two
             * reserved forms; a hard failure here is OOM, and dropping the target
             * would be the lossy narrowing N11 forbids — keep it and let the ladder's
             * own path validation refuse it. */
            items[n].s = raw;
            items[n].len = t->as.bytes.len;
            n++;
            continue;
        }
        /* The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's table
         * rules it separately from the grant arm): ec_canonicalize answers
         * EC_NEVER_MATCH and matches_pattern then answers false, so the target simply
         * SURVIVES. That asymmetry is 0.8.2.21's whole point and it is INHERITED from
         * `covered` here, never restated. */
        bool dropped = (caller_excl && caller_excl->kind == EC_ARRAY)
                       && covered(local_peer, caller_excl, ct);
        free(ct);
        if (!dropped) {
            items[n].s = raw;
            items[n].len = t->as.bytes.len;
            n++;
        }
    }
    out->items = items;
    out->len = n;
    return EC_OK;
}

void ec_cap_effective_free(ec_effective *e)
{
    free(e->items);
    e->items = NULL;
    e->len = 0;
}

/* ec_cap_check_path_permission is §6.3's handler-level path check.
 *
 * IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
 * subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
 * by caller-controlled input: a caller who excludes the one target its capability does
 * not cover removes that target from check_permission's view entirely, and a handler
 * that then acts on it has authorized nothing.
 *
 * THREE DIMENSIONS, NOT FOUR. `peers` is not consulted — the path is local by
 * construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
 * step 3, before any handler runs), and §6.3's signature names only handlers,
 * operations and resources.
 *
 * THE FRAME IS local_peer, NOT THE GRANTER, and that is the spec's own signature rather
 * than a choice: §6.3's block reads `matches_scope(canonical_path, grant.resources,
 * "path-scope", local_peer_id)` — there is no granter parameter to pass. §5.5a governs
 * chain ATTENUATION, where the subject is a PATTERN compared against a parent's
 * pattern; this call site compares a CONCRETE LOCAL PATH the handler is about to touch.
 * Adding a frame here is the over-scoping defect this cohort has recorded three times.
 *
 * There is no caller-exclude set at this call site: the subject is a single concrete
 * path and the caller's exclusions have already been applied in deriving it. Every
 * grant exclude covering the subject therefore denies — which matches_scope already
 * implements, including 0.8.2.21's sentinel rule, so this function is three calls to it
 * and nothing else. An empty `resources.include` is a legal grant shape (§5.2: handlers
 * that touch no tree paths) and DENIES every path here, which is what that note says it
 * should: `covered` over a NULL/empty include list is false. */
bool ec_cap_check_path_permission(const char *local_peer, const char *operation,
                                  const char *path, const ec_entity *token,
                                  const char *handler_pattern)
{
    const ec_value *grants = token ? token_grants(token) : NULL;
    if (!grants) {
        return false;
    }
    /* ec_canonicalize is TOTAL and may answer EC_NEVER_MATCH, which matches no grant
     * (§5.4) — so a malformed path falls through to DENY rather than being matched
     * against anything. matches_scope canonicalizes its `value` itself, and an already
     * absolute path (including the sentinel) passes through unchanged. */
    for (size_t i = 0; i < grants->as.arr.len; i++) {
        const ec_value *g = grants->as.arr.items[i];
        if (!g || g->kind != EC_MAP) {
            continue;
        }
        if (!matches_scope(local_peer, handler_pattern,
                           parse_scope(grant_dim(g, "handlers")), SCOPE_PATH)) {
            continue;
        }
        if (!matches_scope(local_peer, operation,
                           parse_scope(grant_dim(g, "operations")), SCOPE_ID)) {
            continue;
        }
        if (!matches_scope(local_peer, path,
                           parse_scope(grant_dim(g, "resources")), SCOPE_PATH)) {
            continue;
        }
        return true;
    }
    return false;
}

/* ── §6.2 CAP-6a: unrepresentable temporal fields on INGEST ──────────────────── */

/* True when every CAP-6a temporal field on a RECEIVED token is either absent
 * (legal) or representable as a uint64.
 *
 * This is the reader-side half of CAP-6 and it is where a peer fails OPEN. The
 * ec_ent_uint accessor answers false both when a field is ABSENT and when it is
 * PRESENT but not a uint — a negative integer or a bignum — so a token carrying
 * expires_at:-1 silently skipped the expiry check and was honored with 200. §6.2
 * CAP-6a is explicit: such a token "is malformed. A verifier MUST refuse it and
 * MUST NOT treat the unrepresentable field as absent." An absent expires_at stays
 * legal and is deliberately NOT rejected here.
 *
 * Refusal must be the §5.2 capability_denied disposition (a status-bearing
 * response), never a decode-layer silent drop or a transport close. */
static bool temporal_fields_representable(const ec_entity *tok)
{
    static const char *const keys[] = { "expires_at", "not_before", "created_at" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const ec_value *v = ec_ent_field(tok, keys[i]);
        if (!v) {
            continue;                    /* absent is legal */
        }
        if (v->kind != EC_INT || v->as.i.negative) {
            return false;                /* present but not a uint64 => malformed */
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

/* §5.6: the parent token's ABSOLUTE expires_at term, resolved from the frame's
 * included set or the local store. False when there is no parent, the parent is
 * unresolvable, or it carries no representable expiry — in each case it simply
 * contributes no term to MIN_DEFINED. */
bool ec_cap_parent_expiry(const ec_envelope *env, ec_store *store,
                          const uint8_t *parent_hash, uint64_t *out)
{
    if (!parent_hash) {
        return false;
    }
    ec_entity *parent = cap_resolve(env, store, parent_hash);
    if (!parent) {
        return false;
    }
    bool ok = ec_ent_uint(parent, "expires_at", out);
    ec_entity_unref(parent);
    return ok;
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
            bool ok = matches_scope(local_peer, operation, parse_scope(grant_dim(g, "operations")), SCOPE_ID)
                   && matches_scope(local_peer, handler_pattern, parse_scope(grant_dim(g, "handlers")), SCOPE_PATH);
            if (ok) {
                const ec_value *peers_v = grant_dim(g, "peers");
                if (peers_v) {
                    ok = matches_scope(local_peer, target_peer, parse_scope(peers_v), SCOPE_ID);
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

/* One side of a §5.5a subset comparison: does any pattern in `pats` (read under
 * `frame`) cover `value`? Dispatches on the dimension's SCOPE KIND — see scope_subset. */
static bool subset_covered(const char *frame, const ec_value *pats, const char *value,
                           scope_kind kind)
{
    return kind == SCOPE_ID ? covered_id(pats, value) : covered(frame, pats, value);
}

/* §5.5a subset check: every child include must be covered by some parent include, and
 * every parent exclude must be inherited by some child exclude.
 *
 * TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; `entity-core-formalization` K-7).
 * §3.6's id-scope grammar binds the scope TYPE, not one function — "An implementation
 * on the canonicalizing reading is non-conformant and MUST adopt the literal matcher"
 * — so the rule F40 landed on matches_scope reaches here too, with delegation-chain
 * WIDENING named as the reason: on the canonicalizing reading "/tree/get" is covered by
 * "*" in one direction and "*\/apply" is not, so a child grant can come out WIDER than
 * its parent. `lean`'s differential put it at 2 of 64 include pairs and 2 of 64 exclude
 * pairs, fail-closed, with a 16-pair control alphabet reporting 0 — which is why every
 * hand-tried example missed it.
 *
 * `kind` has NO DEFAULT and is named at every call site, because a default is how the
 * next dimension inherits the wrong matcher silently — the original F40 defect.
 * handlers/resources -> SCOPE_PATH; operations/peers -> SCOPE_ID. The per-link granter
 * frames are meaningless on the id arm (an id pattern is never canonicalized) and are
 * simply unread there rather than being a second parameter to get wrong. */
static bool scope_subset(const char *child_peer, const char *parent_peer,
                         scope child, scope parent, scope_kind kind)
{
    /* every child include is covered by some parent include */
    if (child.incl) {
        for (size_t i = 0; i < child.incl->as.arr.len; i++) {
            const ec_value *cp = child.incl->as.arr.items[i];
            if (!cp || cp->kind != EC_TEXT) { continue; }
            const char *raw = (const char *)cp->as.bytes.p;
            char *cc = NULL;
            if (kind == SCOPE_PATH && ec_canonicalize(child_peer, raw, &cc) != EC_OK) {
                return false;
            }
            bool some = subset_covered(parent_peer, parent.incl, cc ? cc : raw, kind);
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
            const char *raw = (const char *)pe->as.bytes.p;
            char *cpe = NULL;
            if (kind == SCOPE_PATH && ec_canonicalize(parent_peer, raw, &cpe) != EC_OK) {
                return false;
            }
            bool some = subset_covered(child_peer, child.excl, cpe ? cpe : raw, kind);
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
    /* The scope KIND is a property of the DIMENSION, named here, never defaulted
     * (F50 / 0.8.2.16). Only RESOURCES takes the §5.5a per-link granter frames;
     * handlers stays local, and the two id dimensions do not canonicalize at all. */
    if (!scope_subset(local_peer, local_peer,
                      parse_scope(grant_dim(child_grant, "handlers")),
                      parse_scope(grant_dim(parent_grant, "handlers")), SCOPE_PATH)) {
        return false;
    }
    if (!scope_subset(local_peer, local_peer,
                      parse_scope(grant_dim(child_grant, "operations")),
                      parse_scope(grant_dim(parent_grant, "operations")), SCOPE_ID)) {
        return false;
    }
    if (!scope_subset(child_peer, parent_peer,
                      parse_scope(grant_dim(child_grant, "resources")),
                      parse_scope(grant_dim(parent_grant, "resources")), SCOPE_PATH)) {
        return false;
    }
    /* peers default = [local] when absent */
    const ec_value *cp = grant_dim(child_grant, "peers");
    const ec_value *pp = grant_dim(parent_grant, "peers");
    if (cp && pp) {
        return scope_subset(local_peer, local_peer, parse_scope(cp), parse_scope(pp), SCOPE_ID);
    }
    if (!cp && !pp) {
        return true;            /* both default [local] → subset */
    }
    /* one default, one explicit: build a [local] include and compare structurally.
     * The dominant self-issued path has both absent; this asymmetric case is rare and
     * conservatively handled by requiring the explicit side to include local. */
    const char *only_peer = local_peer;
    if (cp) {
        return matches_scope(local_peer, only_peer, parse_scope(cp), SCOPE_ID);  /* child ⊆ {local} */
    }
    return matches_scope(local_peer, only_peer, parse_scope(pp), SCOPE_ID);      /* {local} ⊆ parent */
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

/* ── §3.6 / §5.5 multi-signature root (K-of-N quorum, root-only) ─────────────
 *
 * A multi-sig cap carries `granter` as a MAP {signers:[hash,…], threshold:k}
 * instead of a single granter hash — the root is authorized by a quorum. §3.6 M3
 * (structure): root-only, 2 ≤ threshold ≤ N, N ≥ 2, distinct signers. §5.5 M6:
 * the local peer is one of the signers. §5.5 M4: at least `threshold` DISTINCT
 * signers each carry a valid signature over the root content hash. */
static bool is_multisig(const ec_entity *cap)
{
    return ec_ent_map_field(cap, "granter") != NULL;
}

/* The signature over `target` authored by `signer` (borrow; NULL if none). */
static ec_entity *find_signature_by(const uint8_t *target, const uint8_t *signer,
                                    const ec_envelope *env)
{
    for (size_t i = 0; i < env->included_len; i++) {
        ec_entity *e = env->included[i].entity;
        if (strcmp(e->type, "system/signature") != 0) {
            continue;
        }
        size_t tlen = 0, slen = 0;
        const uint8_t *tg = ec_ent_bytes(e, "target", &tlen);
        if (!tg || tlen != 33 || memcmp(tg, target, 33) != 0) {
            continue;
        }
        const uint8_t *sg = ec_ent_bytes(e, "signer", &slen);
        if (sg && slen == 33 && memcmp(sg, signer, 33) == 0) {
            return e;
        }
    }
    return NULL;
}

static bool multisig_root_ok(const char *local_peer, const ec_envelope *env,
                             ec_store *store, const ec_entity *root)
{
    const ec_value *gm = ec_ent_map_field(root, "granter");
    if (!gm) {
        return false;
    }
    const ec_value *signers = ec_map_get(gm, "signers");
    const ec_value *thr = ec_map_get(gm, "threshold");
    if (!signers || signers->kind != EC_ARRAY) {
        return false;
    }
    if (!thr || thr->kind != EC_INT || thr->as.i.negative) {
        return false;
    }
    uint64_t threshold = thr->as.i.u;
    size_t n = signers->as.arr.len;

    /* M3: root-only, quorum shape, distinct signers. */
    size_t plen = 0;
    if (ec_ent_bytes(root, "parent", &plen)) {
        return false; /* multi-sig is root-only */
    }
    if (n < 2 || threshold < 2 || threshold > n) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        const ec_value *si = signers->as.arr.items[i];
        if (!si || si->kind != EC_BYTES || si->as.bytes.len != 33) {
            return false;
        }
        for (size_t j = i + 1; j < n; j++) {
            const ec_value *sj = signers->as.arr.items[j];
            if (sj && sj->kind == EC_BYTES && sj->as.bytes.len == 33
                && memcmp(si->as.bytes.p, sj->as.bytes.p, 33) == 0) {
                return false; /* duplicate signer */
            }
        }
    }

    /* M6: the local peer MUST be a quorum member. */
    bool local_in = false;
    for (size_t i = 0; i < n && !local_in; i++) {
        const ec_value *si = signers->as.arr.items[i];
        ec_entity *s = cap_resolve(env, store, si->as.bytes.p);
        if (s) {
            size_t pl = 0;
            const uint8_t *pk = ec_ent_bytes(s, "public_key", &pl);
            if (pk && pl == 32) {
                char *pid = NULL;
                if (ec_peer_id_of_pubkey32(pk, &pid) == EC_OK && pid) {
                    if (strcmp(pid, local_peer) == 0) {
                        local_in = true;
                    }
                    free(pid);
                }
            }
            ec_entity_unref(s);
        }
    }
    if (!local_in) {
        return false;
    }

    /* M4: count DISTINCT signers with a valid signature over the root hash.
     * (signers are already distinct by M3, so each contributes at most once.) */
    uint64_t valid = 0;
    for (size_t i = 0; i < n; i++) {
        const ec_value *si = signers->as.arr.items[i];
        ec_entity *s = cap_resolve(env, store, si->as.bytes.p);
        if (!s) {
            continue;
        }
        ec_entity *sgn = find_signature_by(root->hash, si->as.bytes.p, env);
        if (sgn && ec_verify_signature(sgn, s)) {
            valid++;
        }
        ec_entity_unref(s);
    }
    return valid >= threshold;
}

static ec_verdict verify_chain_rooted_at(const char *local_peer, const char *root_peer,
                                         ec_store *store, const ec_entity *cap,
                                         const ec_envelope *env, bool *unresolvable);

static ec_verdict verify_chain(const char *local_peer, ec_store *store,
                               const ec_entity *cap, const ec_envelope *env,
                               bool *unresolvable)
{
    return verify_chain_rooted_at(local_peer, local_peer, store, cap, env, unresolvable);
}

/* verify_chain with the expected ROOT granter named separately from the verifying peer.
 *
 * §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is minted
 * by the TARGET peer, so root-trust is relaxed away from the local peer — and every other
 * clause (per-link signatures, grantee resolution, temporal validity, attenuation,
 * caveats) is unchanged. Parameterized rather than forked because a second copy of a
 * chain walk is a second copy that drifts.
 *
 * A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When root_peer
 * differs from local_peer the quorum arm is REFUSED outright rather than verified:
 * "minted by the target" means the target SOLELY minted it, and a K-of-N root is a
 * GROUP's authority — its co-signers authorized it too. Accepting it would let any one
 * signer's target confer the whole group's grant, which is E3/F66's over-acceptance.
 * §5.5's M6 also requires the LOCAL peer in the signer set, so the quorum arm has no
 * meaning in a foreign frame even on its own terms. */
static ec_verdict verify_chain_rooted_at(const char *local_peer, const char *root_peer,
                                         ec_store *store, const ec_entity *cap,
                                         const ec_envelope *env, bool *unresolvable)
{
    *unresolvable = false;
    chain c = collect_chain(cap, env, store);
    if (!c.ok) {
        return EC_V_DENY;
    }
    ec_verdict result = EC_V_DENY;
    ec_entity *root = c.items[c.len - 1];

    /* root granter must resolve to root_peer (single-sig), or pass the §3.6 K-of-N
     * quorum (multi-sig root: granter is a {signers, threshold} map) — LOCAL frame only. */
    if (is_multisig(root)) {
        if (strcmp(root_peer, local_peer) != 0 ||
            !multisig_root_ok(local_peer, env, store, root)) {
            goto done; /* result stays EC_V_DENY */
        }
    } else {
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
                        root_ok = (strcmp(pid, root_peer) == 0);
                        free(pid);
                    }
                }
                ec_entity_unref(g);
            }
        }
        if (!root_ok) {
            goto done;
        }
    }

    bool good = true;
    for (size_t i = 0; i < c.len && good; i++) {
        ec_entity *current = c.items[i];
        /* signature: signer == granter, verify against granter identity. A §3.6
         * multi-sig root has no single granter — it is authorized by the quorum
         * verified above (root-only, so it is the last chain item); grantee +
         * temporal checks below still apply. */
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
        } else if (!is_multisig(current)) {
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
        /* temporal validity.
         *
         * CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
         * created_at is MALFORMED and must be refused outright. This has to run
         * BEFORE the two range checks below, because those use ec_ent_uint, which
         * cannot tell "absent" from "present but not a uint64" — so on its own it
         * would skip the check and honor the token (fail-open). */
        if (!temporal_fields_representable(current)) {
            good = false;
        }
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

/* ── §1.4 PD-2: outbound sub-dispatch authorization ─────────────────────────── */

/* Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
 * *out is malloc'd.
 *
 * §1.4 admits three spellings of one address — system/tree, /{peer}/system/tree and
 * entity://{peer}/system/tree — and §1.4's PD-2 block requires Dimension 1's handler
 * pattern to be the target uri's peer-relative path, because a grant names HANDLERS and a
 * handler pattern never carries a peer segment. Matching a grant against the absolute or
 * schemed form matches nothing, silently, which reads at the wire as an authority refusal.
 *
 * The first segment is dropped ONLY when it is a peer_id. A peer-relative
 * system/protocol/connect must not lose `system` — the standing defect on smalltalk and
 * forth, where an unconditional strip made every self-minted grant unusable while the
 * handshake stayed green. */
ec_status ec_cap_peer_relative_of(const char *uri, char **out)
{
    *out = NULL;
    char *norm = NULL;
    ec_status st = ec_normalize_uri(uri ? uri : "", &norm);
    if (st != EC_OK) {
        return st;
    }
    if (norm[0] != '/') {
        *out = norm;
        return EC_OK;
    }
    const char *body = norm + 1;
    const char *slash = strchr(body, '/');
    size_t firstlen = slash ? (size_t)(slash - body) : strlen(body);
    char *first = malloc(firstlen + 1);
    if (!first) { free(norm); return EC_ERR_OOM; }
    memcpy(first, body, firstlen);
    first[firstlen] = '\0';
    const char *rest = ec_is_peer_id(first) ? (slash ? slash + 1 : "") : body;
    char *res = strdup(rest);
    free(first);
    free(norm);
    if (!res) { return EC_ERR_OOM; }
    *out = res;
    return EC_OK;
}

/* Store key of a handler's OWN grant (§6.8: system/capability/grants/{pattern}),
 * tolerant of the pattern arriving absolute or peer-relative. *out is malloc'd.
 *
 * §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while the
 * grant path is built from the PEER-RELATIVE one. The two are one segment apart and
 * concatenating the wrong one yields a doubled peer segment whose lookup misses — which
 * fails closed as "no handler grant" and is indistinguishable, at the wire, from a
 * genuine authority refusal. */
ec_status ec_cap_grant_path_for(const char *local_peer, const char *pattern, char **out)
{
    *out = NULL;
    size_t pn = strlen(local_peer) + 3;
    char *prefix = malloc(pn);
    if (!prefix) { return EC_ERR_OOM; }
    snprintf(prefix, pn, "/%s/", local_peer);
    const char *rel = ec_startswith(prefix, pattern) ? pattern + strlen(prefix) : pattern;
    free(prefix);
    size_t n = strlen(local_peer) + strlen(rel) + 64;
    char *res = malloc(n);
    if (!res) { return EC_ERR_OOM; }
    snprintf(res, n, "/%s/system/capability/grants/%s", local_peer, rel);
    *out = res;
    return EC_OK;
}

/* Verify a presented reentry credential against §1.4's clauses and, where they all hold,
 * answer the `peers` scope Dimension 4 relaxes to. Returns NULL (borrowed into the cred's
 * value tree when non-NULL) when nothing relaxes.
 *
 * Every clause is required and failing any relaxes nothing: the chain ROOT granter
 * resolves to the TARGET peer and is NOT a multi-signature root (a K-of-N root is a
 * GROUP's authority and never relaxes Dimension 4 — verify_chain_rooted_at refuses the
 * quorum arm in a foreign frame, which is where that rule lands); the LEAF grantee is the
 * local peer; the chain is valid and not revoked. */
/* Verify a presented reentry credential against §1.4's clauses. Answers true when every
 * clause holds; *out_scope is then the `peers` scope Dimension 4 relaxes to, BORROWED into
 * the credential's value tree, or NULL meaning "the target itself" (an absent `peers`
 * dimension is the ordinary reentry shape: "you may dispatch back to me").
 *
 * THE BOOL AND THE SCOPE ARE SEPARATE ON PURPOSE. A NULL scope is a legitimate RESULT
 * here, not a failure, so a single-return signature would collapse "the credential relaxes
 * to the target" into "the credential relaxes nothing" — the same absent-vs-present
 * conflation §6.2's CAP-6a records for temporal accessors, one layer up.
 *
 * Every clause is required and failing any relaxes nothing: the chain ROOT granter
 * resolves to the TARGET peer and is NOT a multi-signature root (a K-of-N root is a
 * GROUP's authority and never relaxes Dimension 4 — verify_chain_rooted_at refuses the
 * quorum arm in a foreign frame, which is where that rule lands); the LEAF grantee is the
 * local peer; the chain is valid and not revoked. */
static bool target_minted_peers_relaxation(const char *local_peer, const char *target_peer,
                                           ec_store *store, const ec_entity *cred,
                                           const ec_envelope *env,
                                           const ec_value **out_scope)
{
    *out_scope = NULL;
    /* Nothing to relax — the default already covers this peer. Treating a self-targeted
     * credential as a relaxation would make the exemption reachable with no foreign mint
     * at all. */
    if (!cred || strcmp(target_peer, local_peer) == 0) {
        return false;
    }
    bool unresolvable = false;
    if (verify_chain_rooted_at(local_peer, target_peer, store, cred, env, &unresolvable)
        != EC_V_ALLOW) {
        return false;
    }
    if (is_revoked(local_peer, store, cred, env)) {
        return false;
    }
    size_t ghl = 0;
    const uint8_t *gh = ec_ent_bytes(cred, "grantee", &ghl);
    if (!gh || ghl != 33) {
        return false;
    }
    ec_entity *ge = cap_resolve(env, store, gh);
    if (!ge) {
        return false;
    }
    bool grantee_is_local = false;
    size_t pl = 0;
    const uint8_t *pk = ec_ent_bytes(ge, "public_key", &pl);
    if (pk && pl == 32) {
        char *pid = NULL;
        if (ec_peer_id_of_pubkey32(pk, &pid) == EC_OK && pid) {
            grantee_is_local = (strcmp(pid, local_peer) == 0);
            free(pid);
        }
    }
    ec_entity_unref(ge);
    if (!grantee_is_local) {
        return false;
    }
    const ec_value *grants = token_grants(cred);
    if (!grants || grants->as.arr.len == 0) {
        return false;
    }
    const ec_value *g0 = grants->as.arr.items[0];
    if (!g0 || g0->kind != EC_MAP) {
        return false;
    }
    *out_scope = grant_dim(g0, "peers");   /* NULL => the target itself */
    return true;
}

/* §1.4's PD-2 gate: check_permission run BEFORE a locally-originated sub-dispatch LEAVES
 * the peer, with all four dimensions applied.
 *
 * ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT decides
 * all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's pattern the
 * target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE TARGET PEER naming
 * this peer as grantee relaxes Dimension 4 (peers) AND ONLY DIMENSION 4.
 *
 * "The target answers WHERE; the handler's grant answers WHAT." A credential is NOT a
 * grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
 * sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
 * BYPASS it is distinguished from is a peer that treats the credential as a standalone
 * authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
 * obvious vectors agree under either reading (sources agree -> allow, no source ->
 * refuse), so the only input that separates them is a VALID credential presented to a
 * handler whose own grant does NOT cover the request, which MUST refuse.
 *
 * A credential failing any verification clause relaxes NOTHING and the handler grant gates
 * unrelaxed — it does not turn the verdict into an error.
 *
 * `target_peer` is supplied by the caller rather than derived here: on the §6.11 reentry
 * seam the uri may be PEER-RELATIVE and the destination is the connection's remote, so
 * ec_extract_peer would answer the LOCAL peer and Dimension 4 would pass vacuously on the
 * default {include: [local]} — the exemption would then never be exercised and a bypass
 * would read as a compose.
 *
 * `cred == NULL` is the ambient arm: Dimension 4 is decided by the handler's grant alone. */
bool ec_cap_check_outbound_sub_dispatch(const char *local_peer, const char *target_peer,
                                        const char *handler_pattern, const char *operation,
                                        ec_store *store, const ec_entity *handler_grant,
                                        const ec_value *resource, const ec_entity *cred,
                                        const ec_envelope *env)
{
    const ec_value *grants = handler_grant ? token_grants(handler_grant) : NULL;
    if (!grants) {
        return false;
    }
    /* Computed FIRST and consulted LAST, so no credential can stand in for 1-3. */
    const ec_value *relax_scope = NULL;
    bool have_relax = target_minted_peers_relaxation(local_peer, target_peer, store, cred,
                                                     env, &relax_scope);
    for (size_t i = 0; i < grants->as.arr.len; i++) {
        const ec_value *g = grants->as.arr.items[i];
        if (!g || g->kind != EC_MAP) {
            continue;
        }
        if (!matches_scope(local_peer, handler_pattern,
                           parse_scope(grant_dim(g, "handlers")), SCOPE_PATH)) {
            continue;
        }
        if (!matches_scope(local_peer, operation,
                           parse_scope(grant_dim(g, "operations")), SCOPE_ID)) {
            continue;
        }
        if (!ec_cap_check_resource_scope(local_peer, local_peer, resource,
                                         grant_dim(g, "resources"))) {
            continue;
        }
        /* Dimension 4. §5.2's default for an absent `peers` scope is
         * {include: [local_peer_id]}, so a foreign target fails unless this grant names it
         * or a target-minted credential relaxes it. */
        const ec_value *pd = grant_dim(g, "peers");
        if (pd) {
            if (matches_scope(local_peer, target_peer, parse_scope(pd), SCOPE_ID)) {
                return true;
            }
        } else if (strcmp(target_peer, local_peer) == 0) {
            return true;
        }
        if (have_relax) {
            if (relax_scope) {
                if (matches_scope(local_peer, target_peer, parse_scope(relax_scope), SCOPE_ID)) {
                    return true;
                }
            } else {
                /* Absent `peers` on the credential relaxes to the granter — the target. */
                return true;
            }
        }
    }
    return false;
}
