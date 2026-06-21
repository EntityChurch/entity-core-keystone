/* Shim for "crypto/ecx.h". curve448.c and eddsa.c #include this, but the only
 * X448 symbols they actually use (X448_PRIVATE_BYTES, X448_ENCODE_RATIO) are
 * defined in the vendored point_448.h. The real OpenSSL ecx.h drags in
 * opensslconf.h / core.h / crypto/types.h / refcount.h — none of which this
 * library-free build has. The public size macros below are provided for
 * completeness only. */
#ifndef EC_SHIM_CRYPTO_ECX_H
#define EC_SHIM_CRYPTO_ECX_H

# define X448_KEYLEN        56
# define X448_BITS          448
# define X448_SECURITY_BITS 224

#endif /* EC_SHIM_CRYPTO_ECX_H */
