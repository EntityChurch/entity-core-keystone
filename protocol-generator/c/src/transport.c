/*
 * transport.c — L4 TCP transport: listener + dialer, one reader thread per connection,
 * §6.11 request_id demux (a hashtable<request_id, condvar-slot> — the reader signals the
 * waiting outbound dispatch via a pthread_cond_t), §4.8 inbound-concurrent-with-outbound
 * dispatch (an inbound EXECUTE is serviced on its OWN dispatch thread so the reader keeps
 * reading + a handler-originated outbound does not block it), §7b TCP_NODELAY on every
 * connection socket, and a per-connection write mutex serializing the shared stream.
 *
 * Concurrency model (profile [concurrency]): pthreads. One reader thread per connection;
 * a blocking recv only blocks that connection's own thread (the Swift cooperative-pool-
 * starvation trap is sidestepped structurally). The demux table maps request_id → a slot
 * carrying the arriving response envelope; the outbound caller parks on the slot's
 * condvar until the reader fills it (or the connection closes).
 *
 * Framing (§1.6): a 4-byte big-endian length prefix then the CBOR envelope payload. The
 * length is checked against EC_MAX_FRAME (16 MiB) BEFORE the body is read (§4.10(a) →
 * 413/clean close; we close on an over-limit prefix).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "transport.h"
#include "wire.h"
#include "capability.h"   /* ec_now_ms */

#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── conn helpers ────────────────────────────────────────────────────────────── */

void ec_conn_init(ec_conn *c)
{
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->lock, NULL);
}

void ec_conn_destroy(ec_conn *c)
{
    free(c->hello_peer_id);
    pthread_mutex_destroy(&c->lock);
}

/* ── request_id demux slot ───────────────────────────────────────────────────── */

typedef struct demux_slot {
    char *request_id;
    ec_envelope *response;      /* filled by the reader (+1 ref) */
    bool filled;
    pthread_cond_t cv;
    struct demux_slot *next;
} demux_slot;

struct ec_io {
    int fd;
    pthread_mutex_t write_lock;     /* serialize the shared stream (§4.8) */
    pthread_mutex_t demux_lock;     /* guards the slot list */
    demux_slot *slots;              /* request_id → slot */
    bool closed;
    int out_counter;
    pthread_mutex_t out_lock;
};

ec_status ec_io_new(int fd, ec_io **out)
{
    ec_io *io = calloc(1, sizeof(*io));
    if (!io) {
        close(fd);
        return EC_ERR_OOM;
    }
    io->fd = fd;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));  /* §7b */
    pthread_mutex_init(&io->write_lock, NULL);
    pthread_mutex_init(&io->demux_lock, NULL);
    pthread_mutex_init(&io->out_lock, NULL);
    *out = io;
    return EC_OK;
}

void ec_io_close(ec_io *io)
{
    if (!io) {
        return;
    }
    pthread_mutex_lock(&io->demux_lock);
    io->closed = true;
    /* wake every parked outbound waiter */
    for (demux_slot *s = io->slots; s; s = s->next) {
        pthread_cond_signal(&s->cv);
    }
    pthread_mutex_unlock(&io->demux_lock);
    /* shutdown forces a blocked recv() to return (a bare close of an fd parked in
     * recv() does not reliably wake it on Linux). */
    shutdown(io->fd, SHUT_RDWR);
}

void ec_io_free(ec_io *io)
{
    if (!io) {
        return;
    }
    close(io->fd);
    /* drain any leftover slots (should be none after a clean teardown) */
    demux_slot *s = io->slots;
    while (s) {
        demux_slot *next = s->next;
        ec_env_free(s->response);
        pthread_cond_destroy(&s->cv);
        free(s->request_id);
        free(s);
        s = next;
    }
    pthread_mutex_destroy(&io->write_lock);
    pthread_mutex_destroy(&io->demux_lock);
    pthread_mutex_destroy(&io->out_lock);
    free(io);
}

/* ── framed read/write ───────────────────────────────────────────────────────── */

static bool read_n(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) {
            return false;
        }
        got += (size_t)r;
    }
    return true;
}

static bool write_n(int fd, const uint8_t *buf, size_t n)
{
    size_t put = 0;
    while (put < n) {
        ssize_t w = send(fd, buf + put, n - put, MSG_NOSIGNAL);
        if (w <= 0) {
            return false;
        }
        put += (size_t)w;
    }
    return true;
}

/* Read one frame's payload (caller frees). Returns EC_OK + *out NULL on clean EOF;
 * EC_ERR_PAYLOAD_TOO_LARGE on an over-limit prefix; EC_ERR_TRUNCATED on a short body. */
static ec_status read_frame(ec_io *io, uint8_t **out, size_t *out_len)
{
    uint8_t hdr[4];
    if (!read_n(io->fd, hdr, 4)) {
        *out = NULL;
        return EC_OK;            /* clean EOF at a frame boundary */
    }
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    /* §4.10(a): bound the payload BEFORE buffering the body. */
    if (len > EC_MAX_FRAME) {
        return EC_ERR_PAYLOAD_TOO_LARGE;
    }
    uint8_t *buf = malloc(len ? len : 1);
    if (!buf) {
        return EC_ERR_OOM;
    }
    if (len && !read_n(io->fd, buf, len)) {
        free(buf);
        return EC_ERR_TRUNCATED;
    }
    *out = buf;
    *out_len = len;
    return EC_OK;
}

static ec_status write_envelope(ec_io *io, const ec_envelope *env)
{
    uint8_t *payload = NULL;
    size_t plen = 0;
    ec_status st = ec_env_to_wire(env, &payload, &plen);
    if (st != EC_OK) {
        return st;
    }
    uint8_t hdr[4] = {
        (uint8_t)(plen >> 24), (uint8_t)(plen >> 16),
        (uint8_t)(plen >> 8), (uint8_t)plen
    };
    pthread_mutex_lock(&io->write_lock);
    bool ok = write_n(io->fd, hdr, 4) && (plen == 0 || write_n(io->fd, payload, plen));
    pthread_mutex_unlock(&io->write_lock);
    free(payload);
    return ok ? EC_OK : EC_ERR_TRUNCATED;
}

/* ── demux: register / route / wait ──────────────────────────────────────────── */

static demux_slot *demux_register(ec_io *io, const char *request_id)
{
    demux_slot *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->request_id = strdup(request_id ? request_id : "");
    pthread_cond_init(&s->cv, NULL);
    pthread_mutex_lock(&io->demux_lock);
    s->next = io->slots;
    io->slots = s;
    pthread_mutex_unlock(&io->demux_lock);
    return s;
}

static void demux_remove(ec_io *io, demux_slot *slot)
{
    pthread_mutex_lock(&io->demux_lock);
    demux_slot **pp = &io->slots;
    while (*pp) {
        if (*pp == slot) {
            *pp = slot->next;
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&io->demux_lock);
    ec_env_free(slot->response);
    pthread_cond_destroy(&slot->cv);
    free(slot->request_id);
    free(slot);
}

/* Route a response envelope to its awaiting slot (takes ownership of env). */
static void demux_route(ec_io *io, ec_envelope *env)
{
    const char *rid = ec_ent_text(env->root, "request_id");
    if (!rid) { rid = ""; }
    pthread_mutex_lock(&io->demux_lock);
    for (demux_slot *s = io->slots; s; s = s->next) {
        if (strcmp(s->request_id, rid) == 0 && !s->filled) {
            s->response = env;
            s->filled = true;
            pthread_cond_signal(&s->cv);
            pthread_mutex_unlock(&io->demux_lock);
            return;
        }
    }
    pthread_mutex_unlock(&io->demux_lock);
    ec_env_free(env);            /* no waiter: drop */
}

/* Wait for a slot to fill or the connection to close. Returns the response (+1 ref,
 * transferred to the caller) or NULL. */
static ec_envelope *demux_wait(ec_io *io, demux_slot *slot)
{
    pthread_mutex_lock(&io->demux_lock);
    while (!slot->filled && !io->closed) {
        pthread_cond_wait(&slot->cv, &io->demux_lock);
    }
    ec_envelope *resp = slot->response;
    slot->response = NULL;       /* transfer ownership out */
    pthread_mutex_unlock(&io->demux_lock);
    return resp;
}

/* The §6.13(b) outbound primitive (used by the dispatch-outbound seam + the session). */
static ec_envelope *io_outbound(ec_io *io, ec_envelope *request)
{
    const char *rid = ec_ent_text(request->root, "request_id");
    demux_slot *slot = demux_register(io, rid);
    if (!slot) {
        return NULL;
    }
    if (write_envelope(io, request) != EC_OK) {
        demux_remove(io, slot);
        return NULL;
    }
    ec_envelope *resp = demux_wait(io, slot);
    demux_remove(io, slot);
    return resp;
}

/* Public §6.13(b)/§6.11 reentry primitive (the dispatch-outbound seam). */
ec_envelope *ec_io_outbound(ec_io *io, ec_envelope *request)
{
    return io_outbound(io, request);
}

/* ── reader loop (§6.11 demux + §4.8 inbound dispatch) ───────────────────────── */

typedef struct dispatch_job {
    ec_peer *peer;
    ec_conn *conn;
    ec_io *io;
    ec_envelope *env;            /* owned; freed by the job */
} dispatch_job;

static void *dispatch_thread(void *arg)
{
    dispatch_job *j = arg;
    ec_envelope *resp = NULL;
    if (ec_peer_dispatch(j->peer, j->conn, j->env, &resp) == EC_OK && resp) {
        write_envelope(j->io, resp);
        ec_env_free(resp);
    }
    ec_env_free(j->env);
    free(j);
    return NULL;
}

typedef struct reader_args {
    ec_peer *peer;
    ec_conn *conn;
    ec_io *io;
} reader_args;

static void *reader_loop(void *arg)
{
    reader_args *ra = arg;
    for (;;) {
        uint8_t *payload = NULL;
        size_t plen = 0;
        ec_status st = read_frame(ra->io, &payload, &plen);
        if (st != EC_OK) {
            break;               /* §4.10(a) over-limit / truncated / OOM ends the conn */
        }
        if (!payload) {
            break;               /* clean EOF */
        }
        ec_envelope *env = NULL;
        st = ec_env_of_wire(payload, plen, &env);
        free(payload);
        if (st != EC_OK) {
            continue;            /* skip a malformed frame (keep reading, N6/§4.9) */
        }
        if (strcmp(env->root->type, "system/protocol/execute/response") == 0) {
            demux_route(ra->io, env);   /* takes ownership */
        } else {
            /* §4.8: dispatch the inbound EXECUTE on its OWN thread so the reader keeps
             * reading + a handler-originated outbound (§6.13(b)) does not block it. */
            dispatch_job *j = malloc(sizeof(*j));
            if (!j) {
                ec_env_free(env);
                continue;
            }
            j->peer = ra->peer;
            j->conn = ra->conn;
            j->io = ra->io;
            j->env = env;
            pthread_t t;
            if (pthread_create(&t, NULL, dispatch_thread, j) == 0) {
                pthread_detach(t);
            } else {
                ec_env_free(env);
                free(j);
            }
        }
    }
    ec_io_close(ra->io);
    free(ra);
    return NULL;
}

/* ── server: listener + accept loop ──────────────────────────────────────────── */

struct ec_listener {
    ec_peer *peer;
    int server_fd;
    int port;
    pthread_t accept_thread;
    volatile bool stop;
};

/* per-connection serving state (the reader owns it for the connection's lifetime). */
typedef struct serve_state {
    ec_io *io;
    ec_conn conn;
    pthread_t reader;
} serve_state;

/* Joins the connection's reader, then frees its io + conn (so every connection is
 * deterministically reaped → LSan-clean). */
static void *serve_reaper(void *arg)
{
    serve_state **box = arg;
    serve_state *ss = *box;
    free(box);
    pthread_join(ss->reader, NULL);
    ec_io_free(ss->io);
    ec_conn_destroy(&ss->conn);
    free(ss);
    return NULL;
}

static void *accept_loop(void *arg)
{
    ec_listener *l = arg;
    while (!l->stop) {
        int client = accept(l->server_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) { continue; }
            break;               /* socket closed → stop */
        }
        serve_state *ss = calloc(1, sizeof(*ss));
        if (!ss) {
            close(client);
            continue;
        }
        if (ec_io_new(client, &ss->io) != EC_OK) {
            free(ss);
            continue;
        }
        ec_conn_init(&ss->conn);
        ss->conn.io = ss->io;    /* §6.13(b) reentry seam: this is the inbound connection */
        reader_args *ra = malloc(sizeof(*ra));
        serve_state **box = malloc(sizeof(*box));
        if (!ra || !box) {
            free(ra); free(box);
            ec_io_free(ss->io);
            ec_conn_destroy(&ss->conn);
            free(ss);
            continue;
        }
        ra->peer = l->peer;
        ra->conn = &ss->conn;
        ra->io = ss->io;
        /* The reader owns ss for the connection's lifetime (it reads via ra->io). A
         * reaper joins the reader then frees ss → every connection is deterministically
         * freed (LSan-clean), without a per-listener registry. */
        if (pthread_create(&ss->reader, NULL, reader_loop, ra) != 0) {
            free(ra); free(box);
            ec_io_free(ss->io);
            ec_conn_destroy(&ss->conn);
            free(ss);
            continue;
        }
        *box = ss;
        pthread_t reaper;
        if (pthread_create(&reaper, NULL, serve_reaper, box) == 0) {
            pthread_detach(reaper);
        } else {
            /* reaper failed: detach the reader + accept the connection-state leak (rare) */
            pthread_detach(ss->reader);
            free(box);
        }
    }
    return NULL;
}

ec_status ec_listener_start(ec_peer *peer, int port, ec_listener **out, int *out_port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return EC_ERR_CRYPTO;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(fd, 64) < 0) {
        close(fd);
        return EC_ERR_CRYPTO;
    }
    socklen_t alen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &alen);
    ec_listener *l = calloc(1, sizeof(*l));
    if (!l) {
        close(fd);
        return EC_ERR_OOM;
    }
    l->peer = peer;
    l->server_fd = fd;
    l->port = ntohs(addr.sin_port);
    if (pthread_create(&l->accept_thread, NULL, accept_loop, l) != 0) {
        close(fd);
        free(l);
        return EC_ERR_CRYPTO;
    }
    *out = l;
    if (out_port) { *out_port = l->port; }
    return EC_OK;
}

void ec_listener_stop(ec_listener *l)
{
    if (!l) {
        return;
    }
    l->stop = true;
    shutdown(l->server_fd, SHUT_RDWR);
    close(l->server_fd);
    pthread_join(l->accept_thread, NULL);
    free(l);
}

/* ── client: session + initiator handshake ───────────────────────────────────── */

struct ec_session {
    ec_io *io;
    ec_peer *initiator;
    const ec_identity *local;    /* == ec_peer_identity(initiator) */
    ec_conn conn;
    pthread_t reader;
    char *remote_peer_id;
    ec_entity *capability;       /* +1 ref */
    ec_entity *granter_peer;     /* +1 ref */
    ec_entity *cap_signature;    /* +1 ref */
    int req_counter;
    pthread_mutex_t counter_lock;
};

static char *next_request_id(ec_session *s)
{
    pthread_mutex_lock(&s->counter_lock);
    int n = ++s->req_counter;
    pthread_mutex_unlock(&s->counter_lock);
    char *id = malloc(32);
    if (id) { snprintf(id, 32, "req-%d", n); }
    return id;
}

static uint64_t resp_status(const ec_envelope *resp)
{
    uint64_t s = 0;
    ec_ent_uint(resp->root, "status", &s);
    return s;
}

uint64_t ec_response_status(const ec_envelope *resp)
{
    return resp ? resp_status(resp) : 0;
}

ec_entity *ec_response_result(const ec_envelope *resp)
{
    return resp ? ec_ent_entity_field(resp->root, "result") : NULL;
}

const char *ec_session_remote_peer(const ec_session *s) { return s->remote_peer_id; }
bool ec_session_has_capability(const ec_session *s) { return s->capability != NULL; }

/* Build, sign, send an authenticated EXECUTE; await the correlated response. */
ec_status ec_session_execute(ec_session *s, const char *uri, const char *operation,
                             ec_entity *params, ec_value *resource, ec_envelope **out_resp)
{
    char *rid = next_request_id(s);
    if (!rid) {
        ec_value_free(resource);
        return EC_ERR_OOM;
    }
    ec_entity *exec = NULL;
    ec_status st = ec_make_execute(rid, uri, operation, params,
                                   s->local->identity_hash,
                                   s->capability->hash, resource, &exec);
    free(rid);
    if (st != EC_OK) {
        return st;
    }
    ec_entity *exec_sig = NULL;
    st = ec_identity_sign(s->local, exec, &exec_sig);
    if (st != EC_OK) {
        ec_entity_unref(exec);
        return st;
    }
    ec_envelope *env = NULL;
    st = ec_env_new(exec, &env);
    ec_entity_unref(exec);
    if (st != EC_OK) {
        ec_entity_unref(exec_sig);
        return st;
    }
    /* §5.8 authority chain travels in included */
    ec_env_add(env, s->capability);
    ec_env_add(env, s->granter_peer);
    ec_env_add(env, (ec_entity *)s->local->peer_entity);
    ec_env_add(env, s->cap_signature);
    ec_env_add(env, exec_sig);
    ec_entity_unref(exec_sig);

    ec_envelope *resp = io_outbound(s->io, env);
    ec_env_free(env);
    *out_resp = resp;
    return EC_OK;
}

/* one handshake leg: send an envelope, await the response. */
static ec_envelope *session_send(ec_session *s, ec_envelope *request)
{
    return io_outbound(s->io, request);
}

static bool resp_ok(const ec_envelope *resp)
{
    return resp && resp_status(resp) == 200;
}

/* Drive the §4.1 forward handshake: hello then authenticate. */
static ec_status handshake(ec_session *s)
{
    const ec_identity *local = s->local;
    ec_status st = EC_ERR_TRUNCATED;

    /* ── hello ── */
    uint8_t nonce[32];
    for (size_t i = 0; i < 32; i++) {
        nonce[i] = (uint8_t)(ec_now_ms() >> (i % 8)) ^ (uint8_t)(i * 17 + 3);
    }
    ec_value *hm = ec_map();
    if (!hm) { return EC_ERR_OOM; }
    {
        ec_value *k;
        bool bad = false;
        k = ec_text("peer_id"); bad |= !k || ec_map_put(hm, k, ec_text(local->peer_id)) != EC_OK;
        k = ec_text("nonce"); bad |= !k || ec_map_put(hm, k, ec_bytes(nonce, 32)) != EC_OK;
        const char *protos[] = { "entity-core/1.0" };
        k = ec_text("protocols"); bad |= !k || ec_map_put(hm, k, ec_v_text_array(protos, 1)) != EC_OK;
        k = ec_text("timestamp"); bad |= !k || ec_map_put(hm, k, ec_int_u(ec_now_ms())) != EC_OK;
        const char *hf[] = { "ecfv1-sha256" };
        k = ec_text("hash_formats"); bad |= !k || ec_map_put(hm, k, ec_v_text_array(hf, 1)) != EC_OK;
        const char *kt[] = { "ed25519" };
        k = ec_text("key_types"); bad |= !k || ec_map_put(hm, k, ec_v_text_array(kt, 1)) != EC_OK;
        if (bad) { ec_value_free(hm); return EC_ERR_OOM; }
    }
    ec_entity *hello = NULL;
    if (ec_entity_make_owning("system/protocol/connect/hello", hm, &hello) != EC_OK) {
        return EC_ERR_OOM;
    }
    char *rid = next_request_id(s);
    ec_entity *exec1 = NULL;
    st = ec_make_execute(rid ? rid : "req-h", "system/protocol/connect", "hello", hello,
                         NULL, NULL, NULL, &exec1);
    free(rid);
    ec_entity_unref(hello);
    if (st != EC_OK) { return st; }
    ec_envelope *env1 = NULL;
    if (ec_env_new(exec1, &env1) != EC_OK) { ec_entity_unref(exec1); return EC_ERR_OOM; }
    ec_entity_unref(exec1);
    ec_envelope *r1 = session_send(s, env1);
    ec_env_free(env1);
    if (!resp_ok(r1)) { ec_env_free(r1); return EC_ERR_VERIFY_FAILED; }
    ec_entity *remote_hello = ec_response_result(r1);
    const char *remote_pid = remote_hello ? ec_ent_text(remote_hello, "peer_id") : NULL;
    size_t rnl = 0;
    const uint8_t *remote_nonce = remote_hello ? ec_ent_bytes(remote_hello, "nonce", &rnl) : NULL;
    if (!remote_pid || !remote_nonce || rnl != 32) {
        ec_entity_unref(remote_hello); ec_env_free(r1);
        return EC_ERR_VERIFY_FAILED;
    }
    s->remote_peer_id = strdup(remote_pid);
    uint8_t echoed_nonce[32];
    memcpy(echoed_nonce, remote_nonce, 32);
    ec_entity_unref(remote_hello);
    ec_env_free(r1);

    /* ── authenticate ── */
    ec_value *am = ec_map();
    if (!am) { return EC_ERR_OOM; }
    {
        ec_value *k;
        bool bad = false;
        k = ec_text("peer_id"); bad |= !k || ec_map_put(am, k, ec_text(local->peer_id)) != EC_OK;
        k = ec_text("public_key"); bad |= !k || ec_map_put(am, k, ec_bytes(local->public_key, 32)) != EC_OK;
        k = ec_text("key_type"); bad |= !k || ec_map_put(am, k, ec_text("ed25519")) != EC_OK;
        k = ec_text("nonce"); bad |= !k || ec_map_put(am, k, ec_bytes(echoed_nonce, 32)) != EC_OK;
        if (bad) { ec_value_free(am); return EC_ERR_OOM; }
    }
    ec_entity *auth = NULL;
    if (ec_entity_make_owning("system/protocol/connect/authenticate", am, &auth) != EC_OK) {
        return EC_ERR_OOM;
    }
    ec_entity *auth_sig = NULL;
    st = ec_identity_sign(local, auth, &auth_sig);
    if (st != EC_OK) { ec_entity_unref(auth); return st; }
    rid = next_request_id(s);
    ec_entity *exec2 = NULL;
    st = ec_make_execute(rid ? rid : "req-a", "system/protocol/connect", "authenticate", auth,
                         NULL, NULL, NULL, &exec2);
    free(rid);
    ec_entity_unref(auth);
    if (st != EC_OK) { ec_entity_unref(auth_sig); return st; }
    ec_envelope *env2 = NULL;
    if (ec_env_new(exec2, &env2) != EC_OK) { ec_entity_unref(exec2); ec_entity_unref(auth_sig); return EC_ERR_OOM; }
    ec_entity_unref(exec2);
    ec_env_add(env2, (ec_entity *)local->peer_entity);
    ec_env_add(env2, auth_sig);
    ec_entity_unref(auth_sig);
    ec_envelope *r2 = session_send(s, env2);
    ec_env_free(env2);
    if (!resp_ok(r2)) { ec_env_free(r2); return EC_ERR_VERIFY_FAILED; }

    /* parse the §4.4 initial capability grant */
    ec_entity *grant = ec_response_result(r2);
    size_t tl = 0;
    const uint8_t *tok_h = grant ? ec_ent_bytes(grant, "token", &tl) : NULL;
    ec_entity *token = (tok_h && tl == 33) ? ec_env_get(r2, tok_h) : NULL;
    if (!token) {
        ec_entity_unref(grant); ec_env_free(r2);
        return EC_ERR_VERIFY_FAILED;
    }
    size_t gl = 0;
    const uint8_t *granter_h = ec_ent_bytes(token, "granter", &gl);
    ec_entity *granter = (granter_h && gl == 33) ? ec_env_get(r2, granter_h) : NULL;
    /* find the cap signature over the token */
    ec_entity *cap_sig = NULL;
    for (size_t i = 0; i < r2->included_len; i++) {
        ec_entity *e = r2->included[i].entity;
        if (strcmp(e->type, "system/signature") == 0) {
            size_t sl = 0;
            const uint8_t *tg = ec_ent_bytes(e, "target", &sl);
            if (tg && sl == 33 && memcmp(tg, token->hash, 33) == 0) {
                cap_sig = e;
                break;
            }
        }
    }
    if (!granter || !cap_sig) {
        ec_entity_unref(grant); ec_env_free(r2);
        return EC_ERR_VERIFY_FAILED;
    }
    s->capability = ec_entity_ref(token);
    s->granter_peer = ec_entity_ref(granter);
    s->cap_signature = ec_entity_ref(cap_sig);
    ec_entity_unref(grant);
    ec_env_free(r2);
    return EC_OK;
}

ec_status ec_session_dial(ec_peer *initiator, const char *host, int port, ec_session **out)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return EC_ERR_CRYPTO;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return EC_ERR_CRYPTO;
    }
    ec_session *s = calloc(1, sizeof(*s));
    if (!s) {
        close(fd);
        return EC_ERR_OOM;
    }
    s->initiator = initiator;
    s->local = ec_peer_identity(initiator);
    pthread_mutex_init(&s->counter_lock, NULL);
    ec_conn_init(&s->conn);
    ec_status st = ec_io_new(fd, &s->io);
    if (st != EC_OK) {
        pthread_mutex_destroy(&s->counter_lock);
        ec_conn_destroy(&s->conn);
        free(s);
        return st;
    }
    s->conn.io = s->io;
    /* the client reader: a core responder sends only EXECUTE_RESPONSEs (routed by demux);
     * an inbound EXECUTE (reentry) would dispatch on its own thread. */
    reader_args *ra = malloc(sizeof(*ra));
    if (!ra) {
        ec_io_free(s->io);
        pthread_mutex_destroy(&s->counter_lock);
        ec_conn_destroy(&s->conn);
        free(s);
        return EC_ERR_OOM;
    }
    ra->peer = initiator;
    ra->conn = &s->conn;
    ra->io = s->io;
    if (pthread_create(&s->reader, NULL, reader_loop, ra) != 0) {
        ec_io_free(s->io);
        free(ra);
        pthread_mutex_destroy(&s->counter_lock);
        ec_conn_destroy(&s->conn);
        free(s);
        return EC_ERR_CRYPTO;
    }
    st = handshake(s);
    if (st != EC_OK) {
        ec_session_close(s);
        return st;
    }
    *out = s;
    return EC_OK;
}

void ec_session_close(ec_session *s)
{
    if (!s) {
        return;
    }
    ec_io_close(s->io);
    pthread_join(s->reader, NULL);
    ec_io_free(s->io);
    ec_entity_unref(s->capability);
    ec_entity_unref(s->granter_peer);
    ec_entity_unref(s->cap_signature);
    free(s->remote_peer_id);
    pthread_mutex_destroy(&s->counter_lock);
    ec_conn_destroy(&s->conn);
    free(s);
}
