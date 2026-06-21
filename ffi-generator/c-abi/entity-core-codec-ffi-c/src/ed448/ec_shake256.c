#include "ec_shake256.h"
#include <stdlib.h>
#include <string.h>

/* Raw Keccak sponge from the vendored keccak1600.c (same pinned OpenSSL 3.3.2).
 *   SHA3_absorb absorbs floor(len/r) full r-byte blocks, returns len % r.
 *   SHA3_squeeze extracts from the post-absorb state; next must be 0 for a
 *   single squeeze (it does NOT permute before the first block). */
size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len, size_t r);
void   SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r, int next);

#define SHAKE256_RATE 136   /* (1600 - 2*256) / 8 */
#define SHAKE_DOMAIN  0x1F  /* SHAKE padding (vs 0x06 for fixed-length SHA-3) */

int shake256_init(shake256_ctx *c)
{
    memset(c, 0, sizeof(*c));
    return 1;
}

int shake256_update(shake256_ctx *c, const void *data, size_t len)
{
    const unsigned char *inp = (const unsigned char *)data;
    const size_t bsz = SHAKE256_RATE;
    size_t num = c->bufsz, rem;

    if (len == 0)
        return 1;

    /* Top off a partial block first. */
    if (num != 0) {
        rem = bsz - num;
        if (len < rem) {
            memcpy(c->buf + num, inp, len);
            c->bufsz += len;
            return 1;
        }
        memcpy(c->buf + num, inp, rem);
        inp += rem;
        len -= rem;
        (void)SHA3_absorb(c->A, c->buf, bsz, bsz);
        c->bufsz = 0;
    }

    /* Absorb whole blocks; stash the remainder. */
    rem = SHA3_absorb(c->A, inp, len, bsz);
    if (rem != 0) {
        memcpy(c->buf, inp + len - rem, rem);
        c->bufsz = rem;
    }
    return 1;
}

int shake256_final_xof(shake256_ctx *c, uint8_t *out, size_t outlen)
{
    const size_t bsz = SHAKE256_RATE;
    size_t num = c->bufsz;

    /* Pad10*1 with the SHAKE domain separator, then absorb the final block. */
    c->buf[num++] = SHAKE_DOMAIN;
    memset(c->buf + num, 0, bsz - num);
    c->buf[bsz - 1] |= 0x80;
    (void)SHA3_absorb(c->A, c->buf, bsz, bsz);

    SHA3_squeeze(c->A, out, outlen, bsz, 0);
    return 1;
}

shake256_ctx *shake256_new(void)
{
    shake256_ctx *c = (shake256_ctx *)malloc(sizeof(*c));
    if (c != NULL)
        shake256_init(c);
    return c;
}

void shake256_free(shake256_ctx *c)
{
    if (c != NULL) {
        memset(c, 0, sizeof(*c));
        free(c);
    }
}

void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    shake256_ctx c;
    shake256_init(&c);
    shake256_update(&c, in, inlen);
    shake256_final_xof(&c, out, outlen);
}
