/* Shim for "internal/e_os.h". The vendored field-arithmetic translation units
 * (arch_64/f_impl64.c) include it for standard C library facilities only
 * (assert, memcpy/memset, malloc). The real OpenSSL e_os.h is a large
 * host-portability header none of which the curve448 math needs. */
#ifndef EC_SHIM_INTERNAL_E_OS_H
#define EC_SHIM_INTERNAL_E_OS_H

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#endif /* EC_SHIM_INTERNAL_E_OS_H */
