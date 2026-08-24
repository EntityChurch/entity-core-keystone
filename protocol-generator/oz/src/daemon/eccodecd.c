/* entity-core-protocol-oz — the entity-codec-daemon co-process (crypto seam).
 *
 * See DAEMON-PROTOCOL.md (the convention this file implements) and
 * arch/PROFILE-RATIONALE.md (why a co-process: the Mozart RPM ships zero
 * headers, so a native-functor FFI would demand the full source build S1
 * rejected; Open.pipe is byte-clean, so the seam is a child process).
 *
 * The daemon wraps libentitycore_codec (the codec C-ABI) and owns ONLY
 * crypto + wall-clock + entropy. No sockets (Oz listens natively), no CBOR
 * (the Oz peer hand-rolls canonical ECF — that's the probe).
 *
 * Framing (binary, v1):  request  = op:u8 || len:u32be || payload
 *                        response = status:u8 || len:u32be || payload
 * One response per request, in order. Exits cleanly on stdin EOF.
 *
 * Build: gcc -O2 -o eccodecd eccodecd.c -I<c-abi-spec-dir> \
 *            -L<codec-build-dir> -lentitycore_codec
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdint.h>
#include "entitycore_codec.h"

#define OP_SHA256         0x01
#define OP_SHA384         0x02
#define OP_ED25519_PUB    0x03
#define OP_ED25519_SIGN   0x04
#define OP_ED25519_VERIFY 0x05
#define OP_ED448_PUB      0x06
#define OP_ED448_SIGN     0x07
#define OP_ED448_VERIFY   0x08
#define OP_NOW            0x10
#define OP_RND            0x11

#define MAX_PAYLOAD (32u * 1024u * 1024u)  /* > frame cap + headroom; a 16 MiB
                                              entity body must be hashable */

static int read_exact(int fd, unsigned char *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r == 0) return 0;              /* EOF */
        if (r < 0) return -1;
        off += (size_t)r;
    }
    return 1;
}

static int write_exact(int fd, const unsigned char *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 1;
}

static int respond(int status, const unsigned char *payload, uint32_t len)
{
    unsigned char hdr[5];
    hdr[0] = (unsigned char)status;
    hdr[1] = (unsigned char)(len >> 24);
    hdr[2] = (unsigned char)(len >> 16);
    hdr[3] = (unsigned char)(len >> 8);
    hdr[4] = (unsigned char)(len);
    if (write_exact(1, hdr, 5) < 0) return -1;
    if (len && write_exact(1, payload, len) < 0) return -1;
    return 0;
}

static int err(const char *msg)
{
    return respond(1, (const unsigned char *)msg, (uint32_t)strlen(msg));
}

int main(void)
{
    unsigned char *buf = (unsigned char *)malloc(MAX_PAYLOAD);
    if (!buf) return 1;

    for (;;) {
        unsigned char hdr[5];
        int r = read_exact(0, hdr, 5);
        if (r == 0) break;                 /* peer closed stdin: clean exit */
        if (r < 0) return 1;
        unsigned op = hdr[0];
        uint32_t len = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
                       ((uint32_t)hdr[3] << 8) | (uint32_t)hdr[4];
        if (len > MAX_PAYLOAD) { return 1; /* protocol violation: unrecoverable */ }
        if (len && read_exact(0, buf, len) != 1) return 1;

        switch (op) {
        case OP_SHA256: {
            unsigned char o[EC_SHA256_LEN];
            if (ec_sha256(buf, len, o) != EC_OK) { if (err("sha256")) return 1; break; }
            if (respond(0, o, sizeof(o))) return 1;
            break;
        }
        case OP_SHA384: {
            unsigned char o[EC_SHA384_LEN];
            if (ec_sha384(buf, len, o) != EC_OK) { if (err("sha384")) return 1; break; }
            if (respond(0, o, sizeof(o))) return 1;
            break;
        }
        case OP_ED25519_PUB: {
            unsigned char o[EC_ED25519_PUB_LEN];
            if (len != EC_ED25519_PRIV_LEN) { if (err("badlen")) return 1; break; }
            if (ec_ed25519_seed_to_pubkey(buf, o) != EC_OK) { if (err("pub")) return 1; break; }
            if (respond(0, o, sizeof(o))) return 1;
            break;
        }
        case OP_ED25519_SIGN: {
            unsigned char o[EC_ED25519_SIG_LEN];
            if (len < EC_ED25519_PRIV_LEN) { if (err("badlen")) return 1; break; }
            if (ec_ed25519_sign(buf, buf + 32, len - 32, o) != EC_OK) { if (err("sign")) return 1; break; }
            if (respond(0, o, sizeof(o))) return 1;
            break;
        }
        case OP_ED25519_VERIFY: {
            unsigned char v;
            if (len < 32 + 64) { if (err("badlen")) return 1; break; }
            v = (ec_ed25519_verify(buf, buf + 96, len - 96, buf + 32) == EC_OK) ? 1 : 0;
            if (respond(0, &v, 1)) return 1;
            break;
        }
        case OP_ED448_PUB: {
            unsigned char o[EC_ED448_PUB_LEN];
            if (len != EC_ED448_PRIV_LEN) { if (err("badlen")) return 1; break; }
            if (ec_ed448_seed_to_pubkey(buf, o) != EC_OK) { if (err("ed448pub")) return 1; break; }
            if (respond(0, o, sizeof(o))) return 1;
            break;
        }
        case OP_ED448_SIGN: {
            unsigned char o[EC_ED448_SIG_LEN];
            if (len < EC_ED448_PRIV_LEN) { if (err("badlen")) return 1; break; }
            if (ec_ed448_sign(buf, buf + 57, len - 57, o) != EC_OK) { if (err("ed448sign")) return 1; break; }
            if (respond(0, o, sizeof(o))) return 1;
            break;
        }
        case OP_ED448_VERIFY: {
            unsigned char v;
            if (len < 57 + 114) { if (err("badlen")) return 1; break; }
            v = (ec_ed448_verify(buf, buf + 171, len - 171, buf + 57) == EC_OK) ? 1 : 0;
            if (respond(0, &v, 1)) return 1;
            break;
        }
        case OP_NOW: {
            struct timespec ts;
            unsigned char o[8];
            clock_gettime(CLOCK_REALTIME, &ts);
            uint64_t ms = (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
            for (int i = 7; i >= 0; i--) { o[i] = (unsigned char)(ms & 0xff); ms >>= 8; }
            if (respond(0, o, 8)) return 1;
            break;
        }
        case OP_RND: {
            unsigned n;
            if (len != 2) { if (err("badlen")) return 1; break; }
            n = ((unsigned)buf[0] << 8) | buf[1];
            if (n > 4096) { if (err("toolong")) return 1; break; }
            {
                unsigned char o[4096];
                int fd = open("/dev/urandom", O_RDONLY);
                if (fd < 0 || read_exact(fd, o, n) != 1) { if (fd >= 0) close(fd); if (err("rnd")) return 1; break; }
                close(fd);
                if (respond(0, o, n)) return 1;
            }
            break;
        }
        default:
            if (err("unknown_op")) return 1;
            break;
        }
    }
    free(buf);
    return 0;
}
