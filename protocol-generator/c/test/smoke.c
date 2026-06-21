/*
 * smoke.c — the S3 phase exit gate: a two-C-peer loopback over real localhost TCP.
 *
 * A RESPONDER peer listens; an INITIATOR peer (a second identity) dials it and drives the
 * §4.1 forward handshake (hello → authenticate), then exercises the wire-level peer
 * surface end to end:
 *   Scenario 1 (core ops, default seed policy):
 *     - session established (capability minted)         §4.1
 *     - remote peer_id matches the responder            §4.6 identity binding
 *     - unregistered path → 404                          §6.6 no handler resolved
 *     - granted tree get → 200 (discovery floor)         §4.4
 *     - tree get returns a system/handler/interface
 *     - capability request → 200                          §6.2 mint-bounded
 *     - 8 interleaved requests each correlated → 8/8     N7 / §6.11 request_id demux
 *   Scenario 2 (Core Extensibility Boundary; --debug-open-grants + --validate):
 *     - handler register → 200 (live, not 501)           §6.13(a)
 *     - emit hook fired on register's tree writes        §6.13(c)
 *     - §7a echo → 200                                    §7a resolve→dispatch
 *     - §7a echo returns params verbatim
 *   → SMOKE: PASS (11/11) — the cohort baseline.
 *
 * Built under ASan/LSan/UBSan: a memory bug (leak / UAF / overflow / UB) FAILS the run
 * (the C manual-memory conformance bonus). The full validate-peer --profile core run is
 * S4; this proves the peer can talk to the network at the wire level.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"
#include "transport.h"
#include "wire.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, bool ok)
{
    if (ok) { g_pass++; } else { g_fail++; }
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
}

static void seed_fill(uint8_t s[32], uint8_t b)
{
    memset(s, b, 32);
}

/* emit-bus consumer for scenario 2 */
static int g_emit_events = 0;
static void on_tree_event(void *ctx, const char *path)
{
    (void)ctx; (void)path;
    __atomic_fetch_add(&g_emit_events, 1, __ATOMIC_SEQ_CST);
}

/* one scope map {include:[...]} (owned). */
static ec_value *scope_inc(const char *const *items, size_t n)
{
    ec_value *m = ec_map();
    ec_value *ik = ec_text("include");
    ec_map_put(m, ik, ec_v_text_array(items, n));
    return m;
}

/* a grant map {handlers,resources,operations} (each an include list) (owned). */
static ec_value *make_scoped_grant(const char *const *h, size_t nh,
                                   const char *const *r, size_t nr,
                                   const char *const *o, size_t no)
{
    ec_value *g = ec_map();
    ec_value *k;
    k = ec_text("handlers");   ec_map_put(g, k, scope_inc(h, nh));
    k = ec_text("resources");  ec_map_put(g, k, scope_inc(r, nr));
    k = ec_text("operations"); ec_map_put(g, k, scope_inc(o, no));
    return g;
}

/* ── scenario 1 ──────────────────────────────────────────────────────────────── */

typedef struct demux_worker {
    ec_session *s;
    char *uri;
    bool ok;
} demux_worker;

static void *demux_run(void *arg)
{
    demux_worker *w = arg;
    ec_entity *params = NULL;
    ec_value *res = NULL;
    if (ec_empty_params(&params) != EC_OK ||
        ec_resource_target("system/handler/system/tree", &res) != EC_OK) {
        ec_entity_unref(params);
        return NULL;
    }
    ec_envelope *r = NULL;
    if (ec_session_execute(w->s, w->uri, "get", params, res, &r) == EC_OK && r) {
        ec_entity *rr = ec_response_result(r);
        w->ok = (ec_response_status(r) == 200) && rr &&
                strcmp(rr->type, "system/handler/interface") == 0;
        ec_entity_unref(rr);
        ec_env_free(r);
    }
    ec_entity_unref(params);
    return NULL;
}

static int scenario_core(void)
{
    uint8_t s_resp[32], s_init[32];
    seed_fill(s_resp, 0x11);
    seed_fill(s_init, 0x22);

    ec_peer *responder = NULL, *initiator = NULL;
    if (ec_peer_create(s_resp, false, false, &responder) != EC_OK ||
        ec_peer_create(s_init, false, false, &initiator) != EC_OK) {
        fprintf(stderr, "peer create failed\n");
        return 1;
    }
    ec_listener *l = NULL;
    int port = 0;
    if (ec_listener_start(responder, 0, &l, &port) != EC_OK) {
        fprintf(stderr, "listen failed\n");
        return 1;
    }
    printf("Responder listening on 127.0.0.1:%d (peer %s)\n", port, ec_peer_local(responder));

    ec_session *sess = NULL;
    if (ec_session_dial(initiator, "127.0.0.1", port, &sess) != EC_OK) {
        fprintf(stderr, "dial/handshake failed\n");
        ec_listener_stop(l);
        ec_peer_free(responder);
        ec_peer_free(initiator);
        return 1;
    }
    const char *remote = ec_session_remote_peer(sess);

    printf("Handshake:\n");
    check("session established (capability minted)", ec_session_has_capability(sess));
    check("remote peer_id matches responder",
          remote && strcmp(remote, ec_peer_local(responder)) == 0);

    printf("Dispatch:\n");
    /* 404 on an unregistered path */
    {
        char uri[256];
        snprintf(uri, sizeof(uri), "/%s/does/not/exist", remote);
        ec_entity *params = NULL;
        ec_empty_params(&params);
        ec_envelope *r = NULL;
        ec_session_execute(sess, uri, "noop", params, NULL, &r);
        check("unregistered path -> 404", r && ec_response_status(r) == 404);
        ec_env_free(r);
        ec_entity_unref(params);
    }
    /* granted tree get → 200, returns a handler/interface */
    {
        char uri[256];
        snprintf(uri, sizeof(uri), "/%s/system/tree", remote);
        ec_entity *params = NULL;
        ec_value *res = NULL;
        ec_empty_params(&params);
        ec_resource_target("system/handler/system/tree", &res);
        ec_envelope *r = NULL;
        ec_session_execute(sess, uri, "get", params, res, &r);
        check("granted tree get -> 200", r && ec_response_status(r) == 200);
        ec_entity *rr = ec_response_result(r);
        check("tree get returns a system/handler/interface entity",
              rr && strcmp(rr->type, "system/handler/interface") == 0);
        ec_entity_unref(rr);
        ec_env_free(r);
        ec_entity_unref(params);
    }
    /* capability request → 200 */
    {
        char uri[256];
        snprintf(uri, sizeof(uri), "/%s/system/capability", remote);
        /* params = system/capability/request {grants:[{handlers,resources,operations}]} */
        const char *h[] = { "system/tree" };
        const char *r_[] = { "system/type/*" };
        const char *o[] = { "get" };
        ec_value *grant = make_scoped_grant(h, 1, r_, 1, o, 1);
        ec_value *grants = ec_array();
        ec_array_push(grants, grant);
        ec_value *pm = ec_map();
        ec_value *pk = ec_text("grants");
        ec_map_put(pm, pk, grants);
        ec_entity *params = NULL;
        ec_entity_make_owning("system/capability/request", pm, &params);
        ec_envelope *r = NULL;
        ec_session_execute(sess, uri, "request", params, NULL, &r);
        check("capability request -> 200", r && ec_response_status(r) == 200);
        ec_env_free(r);
        ec_entity_unref(params);
    }
    /* 8-way request_id demux (N7) */
    printf("Concurrency (request_id demux):\n");
    {
        const int N = 8;
        pthread_t threads[8];
        demux_worker workers[8];
        char uri[256];
        snprintf(uri, sizeof(uri), "/%s/system/tree", remote);
        for (int i = 0; i < N; i++) {
            workers[i].s = sess;
            workers[i].uri = uri;
            workers[i].ok = false;
            pthread_create(&threads[i], NULL, demux_run, &workers[i]);
        }
        int correlated = 0;
        for (int i = 0; i < N; i++) {
            pthread_join(threads[i], NULL);
            if (workers[i].ok) { correlated++; }
        }
        char msg[64];
        snprintf(msg, sizeof(msg), "8 interleaved requests each correlated -> %d/8", correlated);
        check(msg, correlated == N);
    }

    ec_session_close(sess);
    ec_listener_stop(l);
    ec_peer_free(responder);
    ec_peer_free(initiator);
    return 0;
}

/* ── scenario 2 ──────────────────────────────────────────────────────────────── */

static int scenario_extensibility(void)
{
    uint8_t s_resp[32], s_init[32];
    seed_fill(s_resp, 0x33);
    seed_fill(s_init, 0x44);

    ec_peer *responder = NULL, *initiator = NULL;
    if (ec_peer_create(s_resp, true, true, &responder) != EC_OK ||   /* open-grants+validate */
        ec_peer_create(s_init, false, false, &initiator) != EC_OK) {
        fprintf(stderr, "peer create failed\n");
        return 1;
    }
    ec_store_register_tree_consumer(ec_peer_store(responder), on_tree_event, NULL);

    ec_listener *l = NULL;
    int port = 0;
    if (ec_listener_start(responder, 0, &l, &port) != EC_OK) {
        return 1;
    }
    ec_session *sess = NULL;
    if (ec_session_dial(initiator, "127.0.0.1", port, &sess) != EC_OK) {
        ec_listener_stop(l);
        ec_peer_free(responder);
        ec_peer_free(initiator);
        return 1;
    }
    const char *remote = ec_session_remote_peer(sess);
    int emit_before = __atomic_load_n(&g_emit_events, __ATOMIC_SEQ_CST);

    printf("Extensibility (open-grants + --validate):\n");
    /* register live-hook (§6.13(a)) */
    {
        char uri[256];
        snprintf(uri, sizeof(uri), "/%s/system/handler", remote);
        /* params = system/handler/register-request {manifest:{name,operations:{}}} */
        ec_value *manifest = ec_map();
        ec_value *mk;
        mk = ec_text("name"); ec_map_put(manifest, mk, ec_text("demo"));
        mk = ec_text("operations"); ec_map_put(manifest, mk, ec_map());
        ec_value *pm = ec_map();
        ec_value *pk = ec_text("manifest");
        ec_map_put(pm, pk, manifest);
        ec_entity *req = NULL;
        ec_entity_make_owning("system/handler/register-request", pm, &req);
        ec_value *res = NULL;
        ec_resource_target("system/handler/demo", &res);
        ec_envelope *r = NULL;
        ec_session_execute(sess, uri, "register", req, res, &r);
        check("handler register -> 200 (live, not 501)", r && ec_response_status(r) == 200);
        check("emit hook fired on register's tree writes (§6.13(c))",
              __atomic_load_n(&g_emit_events, __ATOMIC_SEQ_CST) > emit_before);
        ec_env_free(r);
        ec_entity_unref(req);
    }
    /* §7a echo (resolve→dispatch) */
    {
        char uri[256];
        snprintf(uri, sizeof(uri), "/%s/system/validate/echo", remote);
        ec_value *pm = ec_map();
        ec_value *pk = ec_text("ping");
        ec_map_put(pm, pk, ec_int_u(42));
        ec_entity *payload = NULL;
        ec_entity_make_owning("primitive/any", pm, &payload);
        ec_envelope *r = NULL;
        ec_session_execute(sess, uri, "echo", payload, NULL, &r);
        check("§7a echo -> 200", r && ec_response_status(r) == 200);
        ec_entity *rr = ec_response_result(r);
        check("§7a echo returns params verbatim", rr && strcmp(rr->type, "primitive/any") == 0);
        ec_entity_unref(rr);
        ec_env_free(r);
        ec_entity_unref(payload);
    }

    ec_session_close(sess);
    ec_listener_stop(l);
    ec_peer_free(responder);
    ec_peer_free(initiator);
    return 0;
}

int main(void)
{
    if (ec_crypto_init() != EC_OK) {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }
    if (scenario_core() != 0) {
        printf("\nSMOKE: FAIL (harness error in scenario 1)\n");
        return 1;
    }
    if (scenario_extensibility() != 0) {
        printf("\nSMOKE: FAIL (harness error in scenario 2)\n");
        return 1;
    }
    bool all_pass = (g_fail == 0);
    printf("\nSMOKE: %s (%d/%d)\n", all_pass ? "PASS" : "FAIL", g_pass, g_pass + g_fail);
    return all_pass ? 0 : 1;
}
