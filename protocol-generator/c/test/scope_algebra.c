/*
 * scope_algebra.c — unit gate for the §5 scope algebra as it stands at 0.8.2.25.
 *
 * WHAT THIS COVERS AND WHAT IT DOES NOT, stated rather than left to inference. These are
 * the §5 PRIMITIVES driven directly: the §5.4 sentinel's scope-type scoping (RULE B /
 * 0.8.2.24 N2/N3), §5.5a scope_subset's typing by scope kind (RULE E / F50), §5.2
 * effective_targets' non-lossy pair (0.8.2.25 N11), and §6.3 check_path_permission. The
 * §3.3 LADDER that consumes them is a handler-internal path reached only through an
 * authenticated dispatch; it is driven end to end by test/smoke.c (scenario 3) and by
 * tools/arc-probe, which is the cohort instrument for it.
 *
 * Built under ASan/LSan/UBSan like every other harness here: a leak or a use-after-free
 * in the new allocation paths FAILS the run. effective_targets hands back an array of
 * BORROWED pointers into the exec's value tree, which is exactly the shape a sanitizer
 * is needed to police.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"
#include "capability.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

static void check(const char *name, bool ok)
{
    ok ? g_pass++ : g_fail++;
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

static const char *LOCAL = "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg";

/* ── small builders ─────────────────────────────────────────────────────────── */

static ec_value *strlist(const char *const *items, size_t n)
{
    ec_value *a = ec_array();
    for (size_t i = 0; i < n; i++) {
        ec_array_push(a, ec_text(items[i]));
    }
    return a;
}

static ec_value *scope_v(const char *const *inc, size_t ni, const char *const *exc, size_t ne)
{
    ec_value *m = ec_map();
    ec_map_put(m, ec_text("exclude"), strlist(exc, ne));
    ec_map_put(m, ec_text("include"), strlist(inc, ni));
    return m;
}

/* one grant {handlers, operations, resources} */
static ec_value *grant_v(const char *const *h, size_t nh, const char *const *o, size_t no,
                         const char *const *r, size_t nr, const char *const *rx, size_t nrx)
{
    ec_value *g = ec_map();
    ec_map_put(g, ec_text("handlers"), scope_v(h, nh, NULL, 0));
    ec_map_put(g, ec_text("operations"), scope_v(o, no, NULL, 0));
    ec_map_put(g, ec_text("resources"), scope_v(r, nr, rx, nrx));
    return g;
}

/* a system/capability/token carrying exactly the grants given (consumed). */
static ec_entity *token_of(ec_value *grants)
{
    ec_value *m = ec_map();
    ec_map_put(m, ec_text("grants"), grants);
    ec_entity *e = NULL;
    if (ec_entity_make_owning("system/capability/token", m, &e) != EC_OK) {
        return NULL;
    }
    return e;
}

static ec_entity *token_one_grant(const char *const *h, size_t nh, const char *const *o, size_t no,
                                  const char *const *r, size_t nr, const char *const *rx, size_t nrx)
{
    ec_value *gs = ec_array();
    ec_array_push(gs, grant_v(h, nh, o, no, r, nr, rx, nrx));
    return token_of(gs);
}

/* an EXECUTE carrying `resource` (consumed) or none when both lists are NULL. */
static ec_entity *exec_of(const char *const *targets, size_t nt, bool have_targets,
                          const char *const *excl, size_t nx, bool have_resource)
{
    ec_value *m = ec_map();
    ec_map_put(m, ec_text("operation"), ec_text("get"));
    if (have_resource) {
        ec_value *r = ec_map();
        if (nx || excl) {
            ec_map_put(r, ec_text("exclude"), strlist(excl, nx));
        }
        if (have_targets) {
            ec_map_put(r, ec_text("targets"), strlist(targets, nt));
        }
        ec_map_put(m, ec_text("resource"), r);
    }
    ec_entity *e = NULL;
    if (ec_entity_make_owning("system/protocol/execute", m, &e) != EC_OK) {
        return NULL;
    }
    return e;
}

/* ── RULE B — the §5.4 sentinel is scoped to PATH-SCOPE (0.8.2.24 N2/N3) ────── */

static void t_sentinel_scoping(void)
{
    printf("RULE B: the section 5.4 sentinel is scoped to path-scope (0.8.2.24 N2/N3):\n");
    /* THE DEFECT THE SCOPING REMOVES. A bare star, a slash and "apply" is an ordinary
     * namespaced OPERATION name; it path-canonicalizes to the sentinel, and under the
     * unconditional guard this whole dimension denied — over-denial, invisible on
     * well-formed grants. Driven through check_path_permission because matches_scope is
     * file-static; the operations dimension is the one under test. */
    const char *h[] = { "system/tree" };
    const char *o[] = { "*" };
    const char *r[] = { "*" };
    ec_value *gs = ec_array();
    ec_value *g = ec_map();
    const char *ox[] = { "*/apply" };
    ec_map_put(g, ec_text("handlers"), scope_v(h, 1, NULL, 0));
    ec_map_put(g, ec_text("operations"), scope_v(o, 1, ox, 1));
    ec_map_put(g, ec_text("resources"), scope_v(r, 1, NULL, 0));
    ec_array_push(gs, g);
    ec_entity *tok = token_of(gs);

    char path[256];
    snprintf(path, sizeof(path), "/%s/app/q", LOCAL);
    check("an id-scope exclude that path-canonicalizes to the sentinel does NOT deny the dimension",
          ec_cap_check_path_permission(LOCAL, "get", path, tok, "system/tree"));
    /* ... and the id-scope exclude still EXCLUDES its own literal, which is the control
     * that says the dimension is being evaluated rather than waved through. */
    check("the same id-scope exclude still denies its own literal operation",
          !ec_cap_check_path_permission(LOCAL, "*/apply", path, tok, "system/tree"));
    ec_entity_unref(tok);

    /* PATH-SCOPE keeps the guard: an unmatchable exclude there denies everything
     * (0.8.2.21), because a path exclude that carves out nothing is a grant silently
     * wider than its author wrote. */
    const char *rx[] = { "../nope" };
    ec_entity *t2 = token_one_grant(h, 1, o, 1, r, 1, rx, 1);
    check("a path-scope exclude that canonicalizes to the sentinel DENIES the dimension",
          !ec_cap_check_path_permission(LOCAL, "get", path, t2, "system/tree"));
    ec_entity_unref(t2);
    /* Control: the same dimension with a MATCHABLE exclude still grants elsewhere. */
    const char *rx2[] = { "app/secret" };
    ec_entity *t3 = token_one_grant(h, 1, o, 1, r, 1, rx2, 1);
    check("a matchable path exclude grants elsewhere and denies its own target",
          ec_cap_check_path_permission(LOCAL, "get", path, t3, "system/tree"));
    char secret[256];
    snprintf(secret, sizeof(secret), "/%s/app/secret", LOCAL);
    check("... and denies the excluded path",
          !ec_cap_check_path_permission(LOCAL, "get", secret, t3, "system/tree"));
    ec_entity_unref(t3);
}

/* ── RULE E — scope_subset is typed by scope kind (F50, 0.8.2.16) ───────────── */

static void t_subset_typing(void)
{
    printf("RULE E: scope_subset is typed by scope kind (F50, ruled 0.8.2.16):\n");
    /* THE INCLUDE PAIR THAT DISAGREES. Child operations include a star-slash-apply
     * form, parent "*". Under section 3.6's literal matcher "*" covers it and the child
     * is a subset. Under the canonicalizing reading it becomes the sentinel, matches
     * nothing, and the pair is refused — fail-CLOSED, which is why no hand-tried example
     * found it. `lean`'s differential put it at 2 of 64 include pairs. */
    const char *h[] = { "system/tree" };
    const char *r[] = { "*" };
    const char *co[] = { "*/apply" };
    const char *po[] = { "*" };
    ec_value *child = grant_v(h, 1, co, 1, r, 1, NULL, 0);
    ec_value *parent = grant_v(h, 1, po, 1, r, 1, NULL, 0);
    check("an id-scope child include carrying path syntax is covered by the literal '*'",
          ec_cap_grant_subset(LOCAL, LOCAL, LOCAL, child, parent));
    ec_value_free(child);
    ec_value_free(parent);

    /* THE EXCLUDE PAIR. A parent exclude must be INHERITED by some child exclude; under
     * the canonicalizing reading an unmatchable exclude is not even inherited by an
     * identical copy of itself, so a scope stops being a subset of ITSELF. */
    ec_value *g1 = ec_map();
    ec_map_put(g1, ec_text("handlers"), scope_v(h, 1, NULL, 0));
    ec_map_put(g1, ec_text("operations"), scope_v(po, 1, co, 1));
    ec_map_put(g1, ec_text("resources"), scope_v(r, 1, NULL, 0));
    ec_value *g2 = ec_map();
    ec_map_put(g2, ec_text("handlers"), scope_v(h, 1, NULL, 0));
    ec_map_put(g2, ec_text("operations"), scope_v(po, 1, co, 1));
    ec_map_put(g2, ec_text("resources"), scope_v(r, 1, NULL, 0));
    check("an id-scope exclude carrying path syntax is inherited by an identical copy",
          ec_cap_grant_subset(LOCAL, LOCAL, LOCAL, g1, g2));
    ec_value_free(g1);
    ec_value_free(g2);

    /* THE CONTROL, and it is what makes the two above measurements rather than a claim
     * that the function says yes: a genuinely WIDER child is still refused on the id
     * arm. "*" is not covered by the literal "get". */
    const char *wide[] = { "*" };
    const char *narrow[] = { "get" };
    ec_value *cw = grant_v(h, 1, wide, 1, r, 1, NULL, 0);
    ec_value *pn = grant_v(h, 1, narrow, 1, r, 1, NULL, 0);
    check("a wider id-scope child is still refused",
          !ec_cap_grant_subset(LOCAL, LOCAL, LOCAL, cw, pn));
    ec_value_free(cw);
    ec_value_free(pn);

    /* And the PATH arm is unchanged — it must still canonicalize, or section 5.5a's
     * per-link granter frames stop working. */
    const char *o1[] = { "get" };
    const char *cr[] = { "app/q" };
    const char *pr[] = { "app/*" };
    ec_value *cp = grant_v(h, 1, o1, 1, cr, 1, NULL, 0);
    ec_value *pp = grant_v(h, 1, o1, 1, pr, 1, NULL, 0);
    check("a path-scope child include is still covered by canonicalization",
          ec_cap_grant_subset(LOCAL, LOCAL, LOCAL, cp, pp));
    check("... and the reverse is still refused",
          !ec_cap_grant_subset(LOCAL, LOCAL, LOCAL, pp, cp));
    ec_value_free(cp);
    ec_value_free(pp);
}

/* ── RULE A — effective_targets keeps the two empties apart (0.8.2.25 N11) ──── */

static void t_effective_targets(void)
{
    printf("RULE A: effective_targets, the non-lossy pair (0.8.2.25 N11):\n");
    ec_effective eff;

    /* ABSENT: no `resource` at all. */
    ec_entity *e0 = exec_of(NULL, 0, false, NULL, 0, false);
    ec_cap_effective_targets(LOCAL, e0, &eff);
    check("no resource at all -> had_resource false", !eff.had_resource && eff.len == 0);
    ec_cap_effective_free(&eff);
    ec_entity_unref(e0);

    /* PRESENT with survivors — the accept case, and the only one that says the exclude
     * loop is being run rather than short-circuited. */
    const char *t2[] = { "app/qA", "app/qB" };
    const char *x1[] = { "app/qA" };
    ec_entity *e1 = exec_of(t2, 2, true, x1, 1, true);
    ec_cap_effective_targets(LOCAL, e1, &eff);
    check("the caller's own exclude removes a target",
          eff.had_resource && eff.len == 1 &&
          strncmp(eff.items[0].s, "app/qB", eff.items[0].len) == 0);
    ec_cap_effective_free(&eff);
    ec_entity_unref(e1);

    /* PRESENT and SELF-EXCLUDED: every target carved out. This is the cell N11 is about
     * — a projection returning only a list collapses it into the absent case above, and
     * the handler's refusal arm becomes dead code. */
    const char *t1[] = { "app/qA" };
    ec_entity *e2 = exec_of(t1, 1, true, x1, 1, true);
    ec_cap_effective_targets(LOCAL, e2, &eff);
    check("a self-excluded resource is PRESENT with an empty survivor list",
          eff.had_resource && eff.len == 0);
    ec_cap_effective_free(&eff);
    ec_entity_unref(e2);

    /* A `resource` map with NO `targets` key is ABSENT. (This case ran GREEN against the
     * pre-change peer on both vanguards — an inert control — so it is asserted here
     * rather than assumed.) */
    ec_entity *e3 = exec_of(NULL, 0, false, x1, 1, true);
    ec_cap_effective_targets(LOCAL, e3, &eff);
    check("a resource map with no `targets` key is the ABSENT case", !eff.had_resource);
    ec_cap_effective_free(&eff);
    ec_entity_unref(e3);

    /* The caller-exclude arm is fail-OPEN on an unmatchable pattern (section 5.4): the
     * target SURVIVES. The opposite of the grant arm, deliberately. */
    const char *xn[] = { "../nope" };
    ec_entity *e4 = exec_of(t1, 1, true, xn, 1, true);
    ec_cap_effective_targets(LOCAL, e4, &eff);
    check("an unmatchable CALLER exclude carves out nothing (fail-open)",
          eff.had_resource && eff.len == 1);
    ec_cap_effective_free(&eff);
    ec_entity_unref(e4);
}

/* ── RULE A — check_path_permission: three dimensions, local frame ──────────── */

static void t_check_path_permission(void)
{
    printf("RULE A: section 6.3 check_path_permission:\n");
    const char *h[] = { "system/tree" };
    const char *o[] = { "*" };
    const char *r[] = { "app/*" };
    const char *rx[] = { "app/secret" };
    ec_entity *tok = token_one_grant(h, 1, o, 1, r, 1, rx, 1);
    char q[256], secret[256], other[256];
    snprintf(q, sizeof(q), "/%s/app/q", LOCAL);
    snprintf(secret, sizeof(secret), "/%s/app/secret", LOCAL);
    snprintf(other, sizeof(other), "/%s/other/q", LOCAL);

    /* THE ACCEPT CASE, AND IT IS THE ONE THAT VALIDATES THE FIXTURE. A predicate test
     * built only from deny cases is indistinguishable from one asserting false == false
     * — a fixture that parses to an empty scope denies everything and every deny case
     * passes for free. */
    check("a covered path is permitted",
          ec_cap_check_path_permission(LOCAL, "get", q, tok, "system/tree"));

    /* One deny per DIMENSION, because a single deny cannot distinguish "the predicate
     * checks the dimension I care about" from "the predicate denies". */
    check("resources exclude denies", !ec_cap_check_path_permission(LOCAL, "get", secret, tok, "system/tree"));
    check("resources include denies",  !ec_cap_check_path_permission(LOCAL, "get", other, tok, "system/tree"));
    check("handlers dimension denies", !ec_cap_check_path_permission(LOCAL, "get", q, tok, "system/handler"));
    ec_entity_unref(tok);

    const char *o2[] = { "put" };
    ec_entity *t2 = token_one_grant(h, 1, o2, 1, r, 1, NULL, 0);
    check("operations dimension denies", !ec_cap_check_path_permission(LOCAL, "get", q, t2, "system/tree"));
    ec_entity_unref(t2);

    /* An empty `resources.include` is a legal grant shape (section 5.2: handlers that
     * touch no tree paths) and DENIES every path. */
    ec_entity *t3 = token_one_grant(h, 1, o, 1, NULL, 0, NULL, 0);
    check("an empty resources.include denies every path",
          !ec_cap_check_path_permission(LOCAL, "get", q, t3, "system/tree"));
    ec_entity_unref(t3);

    /* A malformed path canonicalizes to the sentinel, which matches no grant — so it
     * falls through to DENY rather than being matched against anything. */
    ec_entity *t4 = token_one_grant(h, 1, o, 1, r, 1, NULL, 0);
    check("a malformed path falls through to DENY",
          !ec_cap_check_path_permission(LOCAL, "get", "../escape", t4, "system/tree"));
    /* A NULL token is not an authorization. */
    check("a NULL token authorizes nothing",
          !ec_cap_check_path_permission(LOCAL, "get", q, NULL, "system/tree"));
    ec_entity_unref(t4);
}

/* ── RULE C — the decode-boundary cause split (0.8.2.24 N4/N5) ──────────────── */

/* Encode a hand-built envelope map and hand it to ec_env_of_wire. The map is consumed. */
static ec_status decode_env(ec_value *m)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    ec_status st = ec_ecf_encode(m, &buf, &len);
    ec_value_free(m);
    if (st != EC_OK) {
        return st;
    }
    ec_envelope *env = NULL;
    st = ec_env_of_wire(buf, len, &env);
    free(buf);
    ec_env_free(env);
    return st;
}

static ec_value *entity_v(const char *type, ec_value *data, const uint8_t *hash)
{
    ec_value *m = ec_map();
    ec_map_put(m, ec_text("type"), ec_text(type));
    ec_map_put(m, ec_text("data"), data);
    if (hash) {
        ec_map_put(m, ec_text("content_hash"), ec_bytes(hash, 33));
    }
    return m;
}

static void t_decode_cause_split(void)
{
    printf("RULE C: the decode-boundary refusal names its CAUSE (0.8.2.24 N4/N5):\n");
    /* A real entity, so its content_hash is the true one. */
    ec_value *d = ec_map();
    ec_map_put(d, ec_text("x"), ec_int_u(1));
    ec_entity *good = NULL;
    ec_entity_make_owning("primitive/any", d, &good);
    ec_value *root_d = ec_map();
    ec_map_put(root_d, ec_text("request_id"), ec_text("t1"));
    ec_entity *root = NULL;
    ec_entity_make_owning("system/protocol/execute", root_d, &root);

    /* THE ACCEPT CONTROL FIRST. Without it every refusal below is satisfied by a decoder
     * that refuses everything, and the split says nothing. */
    {
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("root"), entity_v(root->type, ec_value_clone(root->data), root->hash));
        ec_value *inc = ec_map();
        ec_map_put(inc, ec_bytes(good->hash, 33),
                   entity_v(good->type, ec_value_clone(good->data), good->hash));
        ec_map_put(m, ec_text("included"), inc);
        check("a well-formed envelope still decodes", decode_env(m) == EC_OK);
    }
    /* §5.2a (N4/N5): "A peer that refuses at the decode boundary MUST answer `400
     * hash_mismatch` [MUST]" and, in the same breath, "`400 non_canonical_ecf` is NOT
     * conformant here [MUST]". A mis-keyed `included` entry carries no tag and its
     * encoding IS canonical; what is false is the claim the KEY makes. Both arms
     * returned EC_ERR_NON_CANONICAL_ECF until 0.8.2.24 — right property, wrong code. */
    {
        uint8_t bogus[33];
        memset(bogus, 0x11, sizeof(bogus));
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("root"), entity_v(root->type, ec_value_clone(root->data), root->hash));
        ec_value *inc = ec_map();
        ec_map_put(inc, ec_bytes(bogus, 33),
                   entity_v(good->type, ec_value_clone(good->data), good->hash));
        ec_map_put(m, ec_text("included"), inc);
        check("a mis-keyed `included` entry -> EC_ERR_HASH_MISMATCH",
              decode_env(m) == EC_ERR_HASH_MISMATCH);
    }
    /* A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same
     * class (§1.8 item 1) and takes the same code. */
    {
        uint8_t bogus[33];
        memset(bogus, 0x22, sizeof(bogus));
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("root"), entity_v(root->type, ec_value_clone(root->data), bogus));
        check("a tampered root content_hash -> EC_ERR_HASH_MISMATCH",
              decode_env(m) == EC_ERR_HASH_MISMATCH);
    }
    /* STRUCTURAL faults stay EC_ERR_BAD_INPUT -> invalid_request. This is the
     * discriminator: if both causes collapsed into one status the split above would pass
     * vacuously. */
    {
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("nope"), ec_int_u(1));
        check("bytes that are not an envelope -> EC_ERR_BAD_INPUT (not hash_mismatch)",
              decode_env(m) == EC_ERR_BAD_INPUT);
    }
    ec_entity_unref(good);
    ec_entity_unref(root);
}

int main(void)
{
    if (ec_crypto_init() != EC_OK) {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }
    printf("== scope algebra (0.8.2.24 / 0.8.2.25) ==\n");
    t_sentinel_scoping();
    t_subset_typing();
    t_effective_targets();
    t_check_path_permission();
    t_decode_cause_split();
    printf("\nTOTAL: %d pass, %d fail\n", g_pass, g_pass + g_fail == 0 ? -1 : g_fail);
    /* The COUNT is asserted, not just the failure list: a gate that examined zero things
     * prints the same word as one that examined twenty-seven (AGENTS.md, ratified). */
    if (g_pass + g_fail < 27) {
        printf("SCOPE-ALGEBRA: FAIL (only %d cases ran, floor is 27)\n", g_pass + g_fail);
        return 1;
    }
    printf("SCOPE-ALGEBRA: %s (%d/%d)\n", g_fail == 0 ? "PASS" : "FAIL", g_pass, g_pass + g_fail);
    return g_fail == 0 ? 0 : 1;
}
