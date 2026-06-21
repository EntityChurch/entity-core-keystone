#include "ed448_glue.h"
#include <openssl/crypto.h>   /* OSSL_LIB_CTX + OPENSSL_cleanse decl (compat shim) */
#include <string.h>

/* Public entry points from the vendored eddsa.c. In OpenSSL these are declared
 * in crypto/ecx.h (which we shim minimally), so declare them here to match the
 * eddsa.c definitions exactly. ctx and propq are unused in this build (no
 * provider/libctx machinery) and are always passed NULL; phflag = 0 selects
 * pure Ed448 (not Ed448ph); context is empty. */
extern int ossl_ed448_public_from_private(OSSL_LIB_CTX *ctx,
                                          uint8_t out_public_key[57],
                                          const uint8_t private_key[57],
                                          const char *propq);
extern int ossl_ed448_sign(OSSL_LIB_CTX *ctx, uint8_t *out_sig,
                           const uint8_t *message, size_t message_len,
                           const uint8_t public_key[57],
                           const uint8_t private_key[57],
                           const uint8_t *context, size_t context_len,
                           const uint8_t phflag, const char *propq);
extern int ossl_ed448_verify(OSSL_LIB_CTX *ctx,
                             const uint8_t *message, size_t message_len,
                             const uint8_t signature[114],
                             const uint8_t public_key[57],
                             const uint8_t *context, size_t context_len,
                             const uint8_t phflag, const char *propq);

int ed448_derive_pubkey(const uint8_t seed[57], uint8_t pub[57])
{
    return ossl_ed448_public_from_private(NULL, pub, seed, NULL) ? 0 : -1;
}

int ed448_sign(const uint8_t seed[57], const uint8_t *msg, size_t msg_len,
               uint8_t sig[114])
{
    uint8_t pub[57];
    int ok;

    /* Ed448 signing needs the public key; derive it from the seed. */
    if (!ossl_ed448_public_from_private(NULL, pub, seed, NULL))
        return -1;
    ok = ossl_ed448_sign(NULL, sig, msg, msg_len, pub, seed,
                         NULL, 0, 0, NULL);
    OPENSSL_cleanse(pub, sizeof(pub));
    return ok ? 0 : -1;
}

int ed448_verify(const uint8_t pub[57], const uint8_t *msg, size_t msg_len,
                 const uint8_t sig[114])
{
    return ossl_ed448_verify(NULL, msg, msg_len, sig, pub, NULL, 0, 0, NULL)
               ? 0 : -1;
}

/* Constant-time wipe used throughout the vendored curve448 sources. */
void OPENSSL_cleanse(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0)
        *p++ = 0;
}
