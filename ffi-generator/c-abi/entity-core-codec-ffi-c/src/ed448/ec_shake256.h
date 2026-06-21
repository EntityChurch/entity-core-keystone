/* SHAKE256 (FIPS 202) over the vendored OpenSSL keccak1600 sponge.
 *
 * Ed448 (RFC 8032) hashes with SHAKE256, which neither libsodium nor the
 * hand-rolled sha384.c provide. Rather than add a crypto dependency, this wraps
 * the raw Keccak-f[1600] sponge from the same pinned OpenSSL 3.3.2 source
 * (vendor/keccak/keccak1600.c) with the standard SHA-3 absorb / 0x1F-pad /
 * squeeze buffering (rate = 136 bytes for SHAKE256). Compiled into the codec
 * object; nothing here is exported from the .so (export.map localizes all but
 * ec_*), so the artifact stays self-contained (ldd = libc only). */
#ifndef EC_SHAKE256_H
#define EC_SHAKE256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t      A[5][5];   /* Keccak state */
    unsigned char buf[136];  /* SHAKE256 rate block */
    size_t        bufsz;     /* bytes pending in buf */
} shake256_ctx;

/* Incremental: init -> update* -> final_xof (single XOF call). Return 1 always
 * (the int return + 1-on-success mirrors the EVP API the eddsa.c rewire calls). */
int  shake256_init(shake256_ctx *c);
int  shake256_update(shake256_ctx *c, const void *data, size_t len);
int  shake256_final_xof(shake256_ctx *c, uint8_t *out, size_t outlen);

/* Heap ctx helpers (eddsa.c uses an allocated handle). */
shake256_ctx *shake256_new(void);
void             shake256_free(shake256_ctx *c);

/* One-shot SHAKE256(in) -> out[outlen]. */
void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

#endif /* EC_SHAKE256_H */
