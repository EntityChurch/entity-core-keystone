/* teeproxy.c — throwaway wire-capture tool (NOT part of the peer).
 * Frame-aware TCP tee between validate-peer and a reference peer: listens on
 * LISTEN_PORT, connects to UPSTREAM_PORT, and hexdumps each length-prefixed frame
 * in both directions so we can build the asm parser against ground-truth bytes.
 *
 * CONCURRENCY: fork-per-connection, and within each connection a poll(2) loop pumps
 * BOTH directions in the one child process. The earlier version pumped a connection to
 * completion in the accept-loop parent BEFORE accepting the next — so validate-peer's
 * concurrent / lingering connections (it holds A open while probing B) were stranded in
 * the listen backlog and their frames (get/put/type) were never captured. Now every
 * accepted connection is served independently and immediately.
 *
 * Each dumped frame is named <c2s|s2c>_c<connseq>_f<frameseq>.bin under $DUMPDIR — the
 * connection sequence groups a request with the response it drew (both directions share
 * the one child's counters).
 *
 * Usage: teeproxy <listen_port> <upstream_port> [max_frames]
 * Build:  cc -O0 -o teeproxy teeproxy.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int readn(int fd, unsigned char *b, int n) {
    int got = 0;
    while (got < n) { int r = read(fd, b + got, n - got); if (r <= 0) return got; got += r; }
    return got;
}

static void writen(int fd, const unsigned char *b, int n) {
    int put = 0;
    while (put < n) { int r = write(fd, b + put, n - put); if (r <= 0) return; put += r; }
}

static void dump_frame(const char *dir, const unsigned char *body, int len) {
    fprintf(stderr, "\n=== %s frame len=%d ===\n", dir, len);
    int show = len > 4096 ? 4096 : len;
    for (int i = 0; i < show; i++) {
        fprintf(stderr, "%02x", body[i]);
        if ((i & 31) == 31) fprintf(stderr, "\n"); else fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
}

/* Pump one frame (4-byte BE len + body) from src to dst, dumping it.
 * conn = per-connection sequence (stable within this child); *fseq = frame counter.
 * Return 0 on EOF/short-read (connection half-closed), 1 otherwise. */
static int pump(int src, int dst, const char *dir, int conn, int *fseq) {
    unsigned char hdr[4];
    if (readn(src, hdr, 4) != 4) return 0;
    int len = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
    unsigned char *body = malloc(len > 0 ? len : 1);
    if (readn(src, body, len) != len) { free(body); return 0; }
    const char *dd = getenv("DUMPDIR");
    if (dd) {
        char path[512];
        snprintf(path, sizeof path, "%s/%s_c%d_f%d.bin", dd,
                 dir[0] == 'C' ? "c2s" : "s2c", conn, (*fseq)++);
        FILE *fp = fopen(path, "wb");
        if (fp) { fwrite(body, 1, len, fp); fclose(fp); }
    }
    dump_frame(dir, body, len);
    writen(dst, hdr, 4);
    writen(dst, body, len);
    free(body);
    return 1;
}

/* Serve one accepted connection to completion: poll both fds, pump frames each way. */
static void serve_conn(int cs, int us, int conn) {
    int cseq = 0, sseq = 0;
    struct pollfd pfd[2];
    pfd[0].fd = cs; pfd[0].events = POLLIN;   /* client -> server */
    pfd[1].fd = us; pfd[1].events = POLLIN;   /* server -> client */
    for (;;) {
        int n = poll(pfd, 2, -1);
        if (n < 0) break;
        if (pfd[0].revents & POLLIN) {
            if (!pump(cs, us, "C->S", conn, &cseq)) break;
        }
        if (pfd[1].revents & POLLIN) {
            if (!pump(us, cs, "S->C", conn, &sseq)) break;
        }
        if ((pfd[0].revents | pfd[1].revents) & (POLLHUP | POLLERR)) {
            /* drain any last readable frame, then exit on the next empty poll */
            if (pfd[0].revents & POLLIN) pump(cs, us, "C->S", conn, &cseq);
            if (pfd[1].revents & POLLIN) pump(us, cs, "S->C", conn, &sseq);
            break;
        }
    }
    shutdown(us, SHUT_RDWR);
    shutdown(cs, SHUT_RDWR);
    close(us);
    close(cs);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s listen upstream [maxframes]\n", argv[0]); return 2; }
    int lport = atoi(argv[1]), uport = atoi(argv[2]);
    signal(SIGCHLD, SIG_IGN);   /* auto-reap forked connection handlers */

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(lport);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (void*)&a, sizeof a) || listen(ls, 64)) { perror("bind/listen"); return 1; }
    fprintf(stderr, "teeproxy: %d -> %d (concurrent)\n", lport, uport);

    int conn = 0;
    for (;;) {
        int cs = accept(ls, 0, 0);
        if (cs < 0) continue;
        int us = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in ua = {0}; ua.sin_family = AF_INET; ua.sin_port = htons(uport);
        ua.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(us, (void*)&ua, sizeof ua)) { perror("connect upstream"); close(cs); continue; }
        int myconn = conn++;
        pid_t pid = fork();
        if (pid == 0) { close(ls); serve_conn(cs, us, myconn); _exit(0); }
        close(cs); close(us);   /* parent: hand off to the child, keep accepting */
    }
    return 0;
}
