/* Minimal shim for the vendored OpenSSL curve448 + keccak sources.
 * Provides only what those files use from <openssl/e_os2.h>: fixed-width
 * integer types and the `ossl_inline` macro. The real OpenSSL header pulls in
 * opensslconf.h and a large configuration chain we deliberately do NOT vendor
 * (this build links no OpenSSL library — only its curve448/keccak source).
 */
#ifndef EC_SHIM_OPENSSL_E_OS2_H
#define EC_SHIM_OPENSSL_E_OS2_H

#include <stddef.h>
#include <stdint.h>

#ifndef ossl_inline
# define ossl_inline inline
#endif

/* Attribute macros the vendored headers (point_448.h, etc.) take from the real
 * e_os2.h. __owur = warn on unused result. */
#ifndef __owur
# if defined(__GNUC__) || defined(__clang__)
#  define __owur __attribute__((__warn_unused_result__))
# else
#  define __owur
# endif
#endif

#ifndef ossl_unused
# if defined(__GNUC__) || defined(__clang__)
#  define ossl_unused __attribute__((unused))
# else
#  define ossl_unused
# endif
#endif

#endif /* EC_SHIM_OPENSSL_E_OS2_H */
