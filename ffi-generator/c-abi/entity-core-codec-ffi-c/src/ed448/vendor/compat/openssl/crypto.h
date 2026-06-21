/* Shim for <openssl/crypto.h>. The vendored curve448 sources use exactly two
 * things from it: the opaque OSSL_LIB_CTX type (only ever passed as an ignored
 * pointer in this build) and OPENSSL_cleanse (constant-time wipe). The cleanse
 * implementation lives in ed448_glue.c. */
#ifndef EC_SHIM_OPENSSL_CRYPTO_H
#define EC_SHIM_OPENSSL_CRYPTO_H

#include <stddef.h>

typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

void OPENSSL_cleanse(void *ptr, size_t len);

#endif /* EC_SHIM_OPENSSL_CRYPTO_H */
