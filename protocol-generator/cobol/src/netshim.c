/* entity-core-protocol-cobol — TCP transport C shim.
 *
 * COBOL has no socket API; the §4.8/§7b transport rides this thin C seam (same
 * FFI mechanism as the codec). All functions return >=0 on success, -1 on error.
 * Blocking I/O is intended to run on dedicated OS threads, not a bounded pool
 * (§7b) — the COBOL peer's accept loop hands each connection to a thread.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

/* Current wall-clock time in milliseconds since the epoch (§5.5 temporal
 * validity: not_before / expires_at compared against now). COBOL has
 * FUNCTION CURRENT-DATE but assembling epoch-ms from it is awkward; this rides
 * the same FFI seam as the sockets. */
void ec_now_ms(long long *out)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    *out = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Fill buf with n cryptographic-quality random bytes (§4.6 nonce). Returns 0 on
 * success, -1 on error. COBOL has no RNG seam; this rides the same FFI as the
 * sockets. */
int ec_random(unsigned char *buf, long n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    long off = 0;
    while (off < n) {
        long r = (long)read(fd, buf + off, (size_t)(n - off));
        if (r <= 0) { close(fd); return -1; }
        off += r;
    }
    close(fd);
    return 0;
}

/* Listen on 127.0.0.1:port, return the listening fd (or -1). */
int ec_tcp_listen(int port)
{
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
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    return fd;
}

/* Accept one connection; return the connected fd (or -1). */
int ec_tcp_accept(int listen_fd)
{
    int cfd = accept(listen_fd, 0, 0);
    if (cfd >= 0) { int one = 1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
    return cfd;
}

/* Connect to 127.0.0.1:port; return the connected fd (or -1). */
int ec_tcp_connect(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
    return fd;
}

/* A connected AF_UNIX pair for in-process transport tests. fds_out: two ints. */
int ec_socketpair(int *fds_out)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) return -1;
    fds_out[0] = fds[0];
    fds_out[1] = fds[1];
    return 0;
}

/* Write exactly n bytes. Returns n, or -1. */
long ec_fd_write(int fd, const unsigned char *buf, long n)
{
    long off = 0;
    while (off < n) {
        long w = (long)write(fd, buf + off, (size_t)(n - off));
        if (w <= 0) return -1;
        off += w;
    }
    return off;
}

/* Read exactly n bytes. Returns n, 0 on clean EOF before any byte, -1 on error. */
long ec_fd_read(int fd, unsigned char *buf, long n)
{
    long off = 0;
    while (off < n) {
        long r = (long)read(fd, buf + off, (size_t)(n - off));
        if (r == 0) return off == 0 ? 0 : -1;   /* short read = broken */
        if (r < 0) return -1;
        off += r;
    }
    return off;
}

int ec_fd_close(int fd) { return close(fd); }

/* ── single-threaded poll() serve loop (§4.8 / §6.11) ────────────────────────
 *
 * COBOL has no threads, so concurrent connections (the validator holds its main
 * connection open while dialing fresh proof-probe connections) are multiplexed
 * by one poll() loop. Each readable fd accumulates a framed message; on a full
 * frame we call back into the COBOL `dispatch` program and write its response.
 * Single-threaded ⇒ the shared content store / tree (store.cob) is accessed
 * serially with no locking — the COBOL-faithful equivalent of the cohort's
 * runtime-serialized store access. */

#include <poll.h>
#include <stdint.h>
#include <libcob.h>

/* The COBOL dispatch program is invoked via cob_call (handles module
 * resolution + init properly from a C caller):
 *   dispatch(conn[256], env[65535], &env_len(int32), out[65535],
 *            &out_len(int32), &hasresp(char '0'|'1'))                          */

/* §4.10(c) connection-admission bound (SHOULD): cap concurrent connections.
 * Sized to stay serveable under the conformance flood (the peer keeps accepting
 * and serving the follow-up probe rather than falling over); excess beyond the
 * cap is refused via the listen-fd gating below. */
#define EC_MAXCONN 320
#define EC_FRAMECAP 65535

struct ec_slot {
    int fd;
    unsigned char conn[256];          /* per-connection handshake state */
    unsigned char in[4 + EC_FRAMECAP];
    long have;                         /* bytes accumulated in `in` */
    long drain;                        /* bytes of an oversize frame still to discard */
};

static long be32(const unsigned char *p)
{
    return ((long)p[0] << 24) | ((long)p[1] << 16) | ((long)p[2] << 8) | p[3];
}

/* Serve all connections arriving on listen_fd until it errors. */
int ec_serve(int listen_fd)
{
    static struct ec_slot slots[EC_MAXCONN];
    struct pollfd pfds[EC_MAXCONN + 1];
    int nslots = 0;
    unsigned char out[EC_FRAMECAP];
    unsigned char outhdr[4];

    for (;;) {
        /* §4.10(c) self-bounded admission: at capacity, stop polling (and thus
         * accepting) the listen fd — excess inbound connections back up in the
         * listen backlog and are then refused by the kernel (a clean refusal the
         * peer surfaces without falling over), instead of accept-then-close which
         * a client still counts as a successful open. fd = -1 is ignored by poll. */
        pfds[0].fd = (nslots < EC_MAXCONN) ? listen_fd : -1;
        pfds[0].events = POLLIN;
        for (int i = 0; i < nslots; i++) { pfds[i + 1].fd = slots[i].fd; pfds[i + 1].events = POLLIN; }
        if (poll(pfds, nslots + 1, -1) < 0) return -1;

        /* new connection */
        if (pfds[0].revents & POLLIN) {
            int cfd = ec_tcp_accept(listen_fd);
            if (cfd >= 0 && nslots < EC_MAXCONN) {
                memset(&slots[nslots], 0, sizeof(struct ec_slot));
                slots[nslots].fd = cfd;
                /* A freshly-accepted fd was NOT part of this poll() — its pollfd
                 * slot holds stale revents from a prior iteration. Clear it so the
                 * readable-connections loop below does not do a blocking read() on a
                 * connection that has not sent data yet (which wedges the single-
                 * threaded loop under churn/flood/oversize). It is polled next round. */
                pfds[nslots + 1].revents = 0;
                nslots++;
            } else if (cfd >= 0) {
                close(cfd);
            }
        }

        /* readable connections */
        for (int i = 0; i < nslots; ) {
            struct ec_slot *s = &slots[i];
            int closed = 0;
            if (pfds[i + 1].revents & (POLLIN | POLLHUP | POLLERR)) {
                long r = (long)read(s->fd, s->in + s->have,
                                    (size_t)(sizeof(s->in) - s->have));
                if (r <= 0) {
                    closed = 1;
                } else {
                    s->have += r;
                    /* §4.10(a): discard the tail of an oversize frame, keep serving. */
                    if (s->drain > 0) {
                        long d = (s->have < s->drain) ? s->have : s->drain;
                        s->drain -= d;
                        memmove(s->in, s->in + d, (size_t)(s->have - d));
                        s->have -= d;
                    }
                    /* process every complete frame currently buffered */
                    while (s->drain == 0 && s->have >= 4) {
                        long flen = be32(s->in);
                        if (flen < 0 || flen > EC_FRAMECAP) {
                            /* §4.10(a) oversize: do NOT close the connection (that would
                             * drop the caller's pooled/main connection and break every
                             * later request on it). Drain the frame body and keep serving. */
                            long buffered = s->have - 4;
                            if (buffered >= flen) {
                                memmove(s->in, s->in + 4 + flen, (size_t)(s->have - 4 - flen));
                                s->have -= (4 + flen);
                                continue;
                            }
                            s->drain = flen - buffered;
                            s->have = 0;
                            break;
                        }
                        if (s->have < 4 + flen) break;          /* need more */
                        int32_t env_len = (int32_t)flen, out_len = 0;
                        char hasresp = '0';
                        void *argv[6] = { s->conn, s->in + 4, &env_len, out, &out_len, &hasresp };
                        cob_call("dispatch", 6, argv);
                        if (hasresp == '1' && out_len > 0) {
                            outhdr[0] = (unsigned char)((out_len >> 24) & 0xff);
                            outhdr[1] = (unsigned char)((out_len >> 16) & 0xff);
                            outhdr[2] = (unsigned char)((out_len >> 8) & 0xff);
                            outhdr[3] = (unsigned char)(out_len & 0xff);
                            if (ec_fd_write(s->fd, outhdr, 4) != 4 ||
                                ec_fd_write(s->fd, out, out_len) != out_len) {
                                closed = 1; break;
                            }
                        }
                        /* shift the remaining bytes down */
                        long consumed = 4 + flen;
                        memmove(s->in, s->in + consumed, (size_t)(s->have - consumed));
                        s->have -= consumed;
                    }
                }
            }
            if (closed) {
                close(s->fd);
                /* Compact: move the last slot into this position AND carry its
                 * matching pollfd revents, so the moved slot is reprocessed with
                 * its own readiness — not the closed slot's stale revents (which
                 * would drive a blocking read() on a no-data fd and wedge the
                 * single-threaded loop under churn/flood). */
                slots[i] = slots[nslots - 1];
                pfds[i + 1] = pfds[nslots];
                nslots--;
            } else {
                i++;
            }
        }
    }
}

/* Load a 32-byte Ed25519 seed from ~/.entity/peers/NAME/keypair (entity-core
 * PEM: base64 of the 32-byte seed between BEGIN/END lines). 0 ok, -1 error. */
static int b64val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Read an entire file into buf (up to maxlen). Returns the byte count, or -1.
 * Used to load the pre-encoded core-type data payloads (§9.5) at bootstrap. */
long ec_read_file(const char *path, unsigned char *buf, long maxlen)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long n = 0, r;
    while (n < maxlen && (r = (long)read(fd, buf + n, (size_t)(maxlen - n))) > 0) n += r;
    close(fd);
    return n;
}

int ec_load_seed(const char *name, unsigned char *out32)
{
    const char *home = getenv("HOME");
    if (!home) home = "/root";
    char path[1024];
    snprintf(path, sizeof(path), "%s/.entity/peers/%s/keypair", home, name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char raw[4096]; long n = 0, r;
    while ((r = (long)read(fd, raw + n, (size_t)(sizeof(raw) - 1 - n))) > 0) { n += r; if (n >= (long)sizeof(raw) - 1) break; }
    close(fd);
    /* decode base64, skipping PEM header/footer lines and whitespace */
    unsigned int acc = 0; int bits = 0; long outn = 0;
    int skip_line = 0;
    for (long i = 0; i < n; i++) {
        char c = raw[i];
        if (c == '-') { skip_line = 1; continue; }           /* dashes: PEM boundary */
        if (c == '\n') { skip_line = 0; continue; }
        if (skip_line) continue;
        int v = b64val((unsigned char)c);
        if (v < 0) continue;
        acc = (acc << 6) | (unsigned)v; bits += 6;
        if (bits >= 8) { bits -= 8; if (outn < 32) out32[outn++] = (unsigned char)((acc >> bits) & 0xff); }
    }
    return outn == 32 ? 0 : -1;
}
