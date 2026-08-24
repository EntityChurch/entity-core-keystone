/* entity-core-protocol-rexx — crypto helper BINARY (A-RX-005 pivot).
 *
 * fedora's Regina 3.9.6 does NOT load dynamic external-function libraries via
 * `rxfuncadd` (rc 60 even for the built-in regutil; strace shows no dlopen attempt).
 * But `ADDRESS SYSTEM cmd WITH INPUT STEM / OUTPUT STEM` works. So the §9.1 crypto
 * floor crosses the C-ABI through this standalone helper binary over a HEX stem-pipe
 * (line-oriented hex is binary-safe) rather than an in-process C extension — still
 * FFI-hybrid (crypto in C over libentitycore_codec), just at the process boundary.
 *
 * Protocol: argv[1] = op; hex arguments arrive one-per-line on stdin; the result is
 * written as one hex line (or "0"/"1" for verify, or the raw string for impl_info):
 *   sha256          <hex data>                 -> hex(32)
 *   sha384          <hex data>                 -> hex(48)
 *   ed25519_pubkey  <hex seed(32)>             -> hex(32)
 *   ed25519_sign    <hex seed(32)> <hex msg>   -> hex(64)
 *   ed25519_verify  <hex pub(32)> <hex msg> <hex sig(64)>  -> "1" | "0"
 *   impl_info                                   -> provenance string
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "entitycore_codec.h"

/* read one hex line from stdin -> a freshly malloc'd byte buffer; *len set. */
static unsigned char *readhex(size_t *len) {
    char *line = NULL; size_t cap = 0;
    ssize_t r = getline(&line, &cap, stdin);
    if (r < 0) { free(line); *len = 0; return (unsigned char *)calloc(1, 1); }
    while (r > 0 && (line[r - 1] == '\n' || line[r - 1] == '\r')) line[--r] = 0;
    size_t n = (size_t)r / 2;
    unsigned char *buf = (unsigned char *)malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(line + 2 * i, "%2x", &v);
        buf[i] = (unsigned char)v;
    }
    free(line);
    *len = n;
    return buf;
}

static void puthex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *op = argv[1];
    unsigned char out[64];
    size_t l1, l2, l3;

    if (!strcmp(op, "sha256")) {
        unsigned char *d = readhex(&l1);
        if (ec_sha256(d, l1, out) != 0) return 1;
        puthex(out, 32); free(d);
    } else if (!strcmp(op, "sha384")) {
        unsigned char *d = readhex(&l1);
        if (ec_sha384(d, l1, out) != 0) return 1;
        puthex(out, 48); free(d);
    } else if (!strcmp(op, "ed25519_pubkey")) {
        unsigned char *seed = readhex(&l1);
        if (l1 != 32 || ec_ed25519_seed_to_pubkey(seed, out) != 0) return 1;
        puthex(out, 32); free(seed);
    } else if (!strcmp(op, "ed25519_sign")) {
        unsigned char *seed = readhex(&l1);
        unsigned char *msg = readhex(&l2);
        if (l1 != 32 || ec_ed25519_sign(seed, msg, l2, out) != 0) return 1;
        puthex(out, 64); free(seed); free(msg);
    } else if (!strcmp(op, "ed25519_verify")) {
        unsigned char *pub = readhex(&l1);
        unsigned char *msg = readhex(&l2);
        unsigned char *sig = readhex(&l3);
        int rc = (l1 == 32 && l3 == 64) ? ec_ed25519_verify(pub, msg, l2, sig) : -1;
        printf("%d\n", rc == 0 ? 1 : 0);
        free(pub); free(msg); free(sig);
    } else if (!strcmp(op, "impl_info")) {
        printf("%s\n", ec_impl_info());
    } else if (!strcmp(op, "now")) {
        /* §5.5 temporal validity: epoch milliseconds (Regina has no epoch-ms). */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        printf("%lld\n", (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    } else if (!strcmp(op, "random")) {
        /* §4.6 nonce: N cryptographic-quality random bytes as one hex line. N rides
         * argv[2] (not the hex stdin pipe). */
        if (argc < 3) return 2;
        long n = strtol(argv[2], NULL, 10);
        if (n < 0 || n > 4096) return 2;
        unsigned char *buf = (unsigned char *)malloc(n ? n : 1);
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) { free(buf); return 1; }
        long off = 0;
        while (off < n) {
            long r = (long)read(fd, buf + off, (size_t)(n - off));
            if (r <= 0) { close(fd); free(buf); return 1; }
            off += r;
        }
        close(fd);
        puthex(buf, (size_t)n);
        free(buf);
    } else {
        return 2;
    }
    return 0;
}
