/* Shim for <openssl/macros.h>: the vendored curve448 sources only reference
 * NON_EMPTY_TRANSLATION_UNIT (a guard for files that may compile to nothing). */
#ifndef EC_SHIM_OPENSSL_MACROS_H
#define EC_SHIM_OPENSSL_MACROS_H

#ifndef NON_EMPTY_TRANSLATION_UNIT
# define NON_EMPTY_TRANSLATION_UNIT typedef int ec_shim_nonempty_tu_;
#endif

#endif /* EC_SHIM_OPENSSL_MACROS_H */
