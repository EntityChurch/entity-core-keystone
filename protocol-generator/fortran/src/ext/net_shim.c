/* entity-core-protocol-fortran — the C net-shim (L4 transport substrate).
 *
 * Fortran has NO native sockets, so this thin C shim owns the real BSD sockets, the
 * single select() loop, and the §1.6 length-prefixed de-framing. Unlike the Rexx peer
 * (whose Regina interpreter cannot dlopen a C extension, forcing a co-process daemon
 * over FIFOs), Fortran's first-class C interop (iso_c_binding) links this shim DIRECTLY
 * — the Fortran peer calls ec_net_* by symbol. This is the ONLY C wrapper in the peer;
 * crypto/base58/framing bind libentitycore_codec directly (no wrapper) per the profile.
 *
 * == Concurrency model (profile [async] = single-thread-select). ONE process, ONE
 * thread, ONE select loop. The Fortran peer pumps ec_net_poll() in a loop; each call
 * runs at most one select() iteration and returns the NEXT decoded event. §7b/§4.8
 * store-safety is STRUCTURAL: there is no second thread, so the peer's store can never
 * be accessed concurrently — the MUST holds by construction, no lock, no race.
 *
 * == Event model. The shim keeps an internal FIFO of decoded events; ec_net_poll pops
 * the next queued event, and only when the queue is empty does it block in select()
 * (up to timeout_ms; -1 = infinite) to fill it, then pops. Event kinds:
 *   EC_EV_NONE(0)     select timed out, no event
 *   EC_EV_ACCEPT(1)   a new inbound connection was accepted   (out_id = conn id)
 *   EC_EV_FRAME(2)    a complete §1.6 frame was de-framed     (out_id, out_buf/out_len)
 *   EC_EV_CLOSED(3)   a connection closed / errored           (out_id)
 *   EC_EV_OVERSIZE(4) §4.10 413: a length prefix exceeded EC_MAX_PAYLOAD; the body was
 *                     DRAINED, never buffered (the check is on the length prefix BEFORE
 *                     the body is read) and the connection is KEPT (keep serving). The
 *                     Fortran peer answers 413 payload_too_large. (out_id)
 *
 * == §4.10 / §4.9 floor (built in here, not rediscovered at S4):
 *   §4.10(a) finite max inbound payload: EC_MAX_PAYLOAD (16 MiB). Enforced on the length
 *            prefix BEFORE buffering -> EC_EV_OVERSIZE, connection kept.
 *   §4.10(c) connection admission: EC_MAXCONN cap (well above the flood probe's burst +
 *            follow-up), so the peer accepts the flood AND keeps serving (a SHOULD Warn,
 *            not a fall-over). Idle slots cost ~0 (buffers malloc'd lazily).
 *   §4.9    deliver-or-signal: every write is non-blocking + queued (per-conn out queue
 *            drained on select() write-readiness) so the loop never blocks and never
 *            silently drops; a broken socket surfaces as EC_EV_CLOSED.
 *   §7b     TCP_NODELAY set on every accepted/dialed socket.
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <signal.h>

#define EC_MAX_PAYLOAD (16 * 1024 * 1024)   /* §4.10(a) informative default: 16 MiB */
#define EC_CONNBUF     (1024 * 1024)         /* per-conn de-framing buffer; a frame larger
                                                than this but <= MAX_PAYLOAD is still
                                                delivered by growing (see conn_read). */
#define EC_MAXCONN     512                   /* §4.10(c): above the 256-burst flood probe
                                                + its follow-up keep-serving connection. */

enum { EC_EV_NONE = 0, EC_EV_ACCEPT = 1, EC_EV_FRAME = 2, EC_EV_CLOSED = 3, EC_EV_OVERSIZE = 4,
       EC_EV_TRUNCATED = 5 };

struct conn {
    int fd; int id;
    unsigned char *buf; long have, cap;    /* inbound de-framing buffer (grows) */
    long drain;                             /* §4.10(a): bytes of an oversize body left to discard */
    int rdclosed;                           /* §4.11: peer sent FIN; our write side stays open
                                             * until the refusal is flushed, then we drop */
    unsigned char *obuf; long olen, ocap, ohead;  /* outbound queue (non-blocking write) */
};

/* a decoded event queued for the Fortran side. */
struct ev { int kind; int id; unsigned char *buf; long len; };

static struct conn conns[EC_MAXCONN];
static int nconn = 0;
static int listen_fd = -1;
static int next_id = 1;

static struct ev *evq = 0;
static long evq_len = 0, evq_cap = 0, evq_head = 0;

static void ev_push(int kind, int id, const unsigned char *b, long n)
{
    if (evq_head > 0 && evq_head == evq_len) { evq_len = evq_head = 0; }
    if (evq_len >= evq_cap) {
        evq_cap = evq_cap ? evq_cap * 2 : 64;
        evq = (struct ev *)realloc(evq, evq_cap * sizeof(struct ev));
    }
    struct ev *e = &evq[evq_len++];
    e->kind = kind; e->id = id; e->len = n; e->buf = 0;
    if (n > 0) { e->buf = (unsigned char *)malloc(n); memcpy(e->buf, b, n); }
}

/* ── connection bookkeeping ── */
static struct conn *conn_new(int fd)
{
    if (nconn >= EC_MAXCONN) { close(fd); return 0; }   /* §4.10(c) admission cap */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));   /* §7b */
    fcntl(fd, F_SETFL, O_NONBLOCK);
    struct conn *c = &conns[nconn++];
    memset(c, 0, sizeof(*c));
    c->fd = fd; c->id = next_id++;
    c->buf = (unsigned char *)malloc(EC_CONNBUF); c->cap = EC_CONNBUF;
    return c;
}

static struct conn *conn_by_id(int id)
{
    for (int i = 0; i < nconn; i++) if (conns[i].id == id) return &conns[i];
    return 0;
}

static void conn_drop(int idx)
{
    ev_push(EC_EV_CLOSED, conns[idx].id, 0, 0);
    close(conns[idx].fd);
    free(conns[idx].buf);
    free(conns[idx].obuf);
    conns[idx] = conns[nconn - 1];
    nconn--;
}

/* queue outbound bytes (drained on socket writability; never blocks — §4.9). */
static void conn_out(struct conn *c, const unsigned char *s, long n)
{
    if (c->ohead > 0 && c->ohead == c->olen) { c->olen = c->ohead = 0; }
    if (c->olen + n > c->ocap) {
        while (c->ocap < c->olen + n) c->ocap = c->ocap ? c->ocap * 2 : 65536;
        c->obuf = (unsigned char *)realloc(c->obuf, c->ocap);
    }
    memcpy(c->obuf + c->olen, s, n);
    c->olen += n;
}

static void conn_flush(struct conn *c)
{
    while (c->ohead < c->olen) {
        /* MSG_NOSIGNAL: a write to a peer-closed socket must surface as EPIPE, never a
         * process-terminating SIGPIPE (the churn/reentry probes close mid-exchange). */
        long w = send(c->fd, c->obuf + c->ohead, c->olen - c->ohead, MSG_NOSIGNAL);
        if (w <= 0) return;                 /* EAGAIN/EPIPE/err: retry next writable / drop on close */
        c->ohead += w;
    }
    c->olen = c->ohead = 0;
}

/* de-frame every complete §1.6 frame buffered in c, pushing an EC_EV_FRAME per payload.
 * §4.10(a): a length prefix > EC_MAX_PAYLOAD -> EC_EV_OVERSIZE, drain the body, KEEP the
 * connection (never a silent close of a pooled connection). */
static void drain_frames(struct conn *c)
{
    for (;;) {
        if (c->drain > 0) {
            long d = (c->have < c->drain) ? c->have : c->drain;
            c->drain -= d;
            memmove(c->buf, c->buf + d, c->have - d);
            c->have -= d;
            if (c->drain > 0) return;
        }
        if (c->have < 4) return;
        long flen = ((long)c->buf[0] << 24) | ((long)c->buf[1] << 16) |
                    ((long)c->buf[2] << 8) | (long)c->buf[3];
        if (flen < 0 || flen > EC_MAX_PAYLOAD) {
            /* §4.10(a): oversize — signal 413 BEFORE buffering the body, then drain. */
            ev_push(EC_EV_OVERSIZE, c->id, 0, 0);
            long buffered = c->have - 4;
            if (buffered >= flen) {
                memmove(c->buf, c->buf + 4 + flen, c->have - 4 - flen);
                c->have -= (4 + flen);
                continue;
            }
            c->drain = flen - buffered;
            c->have = 0;
            return;
        }
        if (4 + flen > c->cap) {            /* grow to hold a large (but legal) frame */
            long ncap = c->cap;
            while (ncap < 4 + flen) ncap *= 2;
            c->buf = (unsigned char *)realloc(c->buf, ncap); c->cap = ncap;
        }
        if (c->have < 4 + flen) return;     /* need more bytes */
        ev_push(EC_EV_FRAME, c->id, c->buf + 4, flen);
        memmove(c->buf, c->buf + 4 + flen, c->have - 4 - flen);
        c->have -= (4 + flen);
    }
}

/* ── public C-ABI (bound via iso_c_binding) ── */

/* wall-clock milliseconds since the epoch (§4.4 created_at / temporal caveats). Fortran's
 * date_and_time gives broken-down local time; a monotonic ms is cleaner from C. */
long long ec_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* fill `buf` with `n` CSPRNG bytes (§4.6 nonce). */
void ec_random(int8_t *buf, int n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    long off = 0;
    if (fd >= 0) {
        while (off < n) { long r = read(fd, buf + off, n - off); if (r <= 0) break; off += r; }
        close(fd);
    }
    for (; off < n; off++) buf[off] = 0;
}

/* bind + listen on 127.0.0.1:port (0 = ephemeral). Returns the bound port, or -1. */
int ec_net_listen(int port)
{
    signal(SIGPIPE, SIG_IGN);   /* never let a broken pipe terminate the long-running server */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
    if (listen(fd, 64) < 0) { close(fd); return -1; }
    struct sockaddr_in b; socklen_t bl = sizeof(b);
    int bound = port;
    if (getsockname(fd, (struct sockaddr *)&b, &bl) == 0) bound = ntohs(b.sin_port);
    listen_fd = fd;
    return bound;
}

/* dial 127.0.0.1:port. Returns a conn id, or -1. */
int ec_net_connect(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
    struct conn *c = conn_new(fd);
    if (!c) return -1;
    return c->id;
}

/* frame (4-byte BE length prefix, §1.6) + queue `len` payload bytes to conn `id`. */
void ec_net_send(int id, const int8_t *buf, int len)
{
    struct conn *c = conn_by_id(id);
    if (!c) return;
    unsigned char hdr[4];
    hdr[0] = (unsigned char)((len >> 24) & 0xff);
    hdr[1] = (unsigned char)((len >> 16) & 0xff);
    hdr[2] = (unsigned char)((len >> 8) & 0xff);
    hdr[3] = (unsigned char)(len & 0xff);
    conn_out(c, hdr, 4);
    conn_out(c, (const unsigned char *)buf, len);
    conn_flush(c);                          /* opportunistic; rest drains on writable */
}

void ec_net_close(int id)
{
    for (int i = 0; i < nconn; i++) if (conns[i].id == id) { conn_drop(i); return; }
}

void ec_net_shutdown(void)
{
    for (int i = nconn - 1; i >= 0; i--) { close(conns[i].fd); free(conns[i].buf); free(conns[i].obuf); }
    nconn = 0;
    if (listen_fd >= 0) { close(listen_fd); listen_fd = -1; }
    for (long i = evq_head; i < evq_len; i++) free(evq[i].buf);
    free(evq); evq = 0; evq_len = evq_cap = evq_head = 0;
}

/* Pop the next decoded event. If the queue is empty, run one select() (blocking up to
 * timeout_ms; <0 = infinite) to fill it, then pop. Returns the event kind; for FRAME/
 * OVERSIZE the payload is copied into out_buf (<= out_cap) with *out_len set; out_id is
 * the connection id for ACCEPT/FRAME/CLOSED/OVERSIZE. */
int ec_net_poll(int timeout_ms, int *out_id, int8_t *out_buf, int out_cap, int *out_len)
{
    *out_id = 0; *out_len = 0;
    if (evq_head >= evq_len) {
        /* queue empty: one select() pass to produce events. */
        fd_set rf, wf;
        FD_ZERO(&rf); FD_ZERO(&wf);
        int maxfd = -1;
        if (listen_fd >= 0) { FD_SET(listen_fd, &rf); if (listen_fd > maxfd) maxfd = listen_fd; }
        for (int i = 0; i < nconn; i++) {
            /* A half-closed connection is never read again -- select would report it
             * readable forever at EOF and spin. It stays in the table only so its
             * §4.11 refusal can be written. */
            if (!conns[i].rdclosed) { FD_SET(conns[i].fd, &rf); if (conns[i].fd > maxfd) maxfd = conns[i].fd; }
            if (conns[i].ohead < conns[i].olen) { FD_SET(conns[i].fd, &wf); if (conns[i].fd > maxfd) maxfd = conns[i].fd; }
        }
        if (maxfd < 0) return EC_EV_NONE;
        struct timeval tv, *tvp = 0;
        if (timeout_ms >= 0) { tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000; tvp = &tv; }
        int r = select(maxfd + 1, &rf, &wf, 0, tvp);
        if (r < 0) { if (errno == EINTR) return EC_EV_NONE; return EC_EV_CLOSED; }
        if (r == 0) return EC_EV_NONE;
        for (int i = 0; i < nconn; i++) if (FD_ISSET(conns[i].fd, &wf)) conn_flush(&conns[i]);
        /* the half-close teardown: once the refusal has left, the connection is done. */
        for (int i = 0; i < nconn; ) {
            if (conns[i].rdclosed && conns[i].ohead >= conns[i].olen) { conn_drop(i); continue; }
            i++;
        }
        if (listen_fd >= 0 && FD_ISSET(listen_fd, &rf)) {
            int cfd = accept(listen_fd, 0, 0);
            if (cfd >= 0) { struct conn *c = conn_new(cfd); if (c) ev_push(EC_EV_ACCEPT, c->id, 0, 0); }
        }
        for (int i = 0; i < nconn; ) {
            struct conn *c = &conns[i];
            if (!c->rdclosed && FD_ISSET(c->fd, &rf)) {
                if (c->have + 65536 > c->cap && c->cap < EC_MAX_PAYLOAD) {
                    long ncap = c->cap * 2; c->buf = (unsigned char *)realloc(c->buf, ncap); c->cap = ncap;
                }
                long room = c->cap - c->have;
                if (room <= 0) room = 65536;   /* defensive */
                long rd = read(c->fd, c->buf + c->have, room);
                if (rd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { i++; continue; }
                if (rd < 0) { conn_drop(i); continue; }   /* a real error: no refusal is owed */
                if (rd == 0) {
                    /* §4.11: THE TWO ENDS-OF-STREAM DIFFER BY ONE BUFFERED BYTE.
                     * Nothing buffered is a CLEAN CLOSE at a frame boundary and is owed
                     * NOTHING (pa-probe D3). Bytes still buffered are "a length prefix
                     * that never completes" and are owed a coded 400 (D2). The cheapest
                     * way to pass D2 is to answer every read error, which DELETES that
                     * distinction rather than implementing it -- so the test is on
                     * c->have, not on the read result.
                     *
                     * c->drain > 0 is excluded: an oversize frame already had its 413
                     * (§4.10(a)), and answering again is two refusals for one cause.
                     *
                     * WE DO NOT CLOSE HERE. A FIN closes the peer's write side, not ours,
                     * and closing on receipt would make the mandatory refusal
                     * undeliverable -- the same defect Node's `allowHalfOpen` default and
                     * the BEAM's `exit_on_close` produce for free. Raw sockets let us
                     * simply not do it: mark the read side closed, let the peer queue its
                     * refusal, flush, and drop once the output queue is empty. */
                    if (c->have > 0 && c->drain == 0) {
                        ev_push(EC_EV_TRUNCATED, c->id, 0, 0);
                        c->have = 0;
                        c->rdclosed = 1;
                        i++; continue;
                    }
                    conn_drop(i); continue;
                }
                c->have += rd;
                drain_frames(c);
            }
            i++;
        }
    }
    if (evq_head >= evq_len) return EC_EV_NONE;
    struct ev *e = &evq[evq_head++];
    *out_id = e->id;
    int kind = e->kind;
    if (e->buf && e->len > 0) {
        long n = e->len < out_cap ? e->len : out_cap;
        memcpy(out_buf, e->buf, n);
        *out_len = (int)n;
        free(e->buf); e->buf = 0;
    }
    if (evq_head == evq_len) { evq_head = evq_len = 0; }
    return kind;
}
