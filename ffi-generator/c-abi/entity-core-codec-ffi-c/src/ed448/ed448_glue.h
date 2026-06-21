/* Thin adapter between the codec's ec_ed448_* ABI surface (codec.c) and the
 * vendored OpenSSL curve448 Ed448 (eddsa.c). Pure Ed448 (RFC 8032, empty
 * context, phflag = 0). Seeds/private keys are the 57-byte secret; signatures
 * are 114 bytes. Each function returns 0 on success, -1 on failure. */
#ifndef ED448_GLUE_H
#define ED448_GLUE_H

#include <stddef.h>
#include <stdint.h>

int ed448_derive_pubkey(const uint8_t seed[57], uint8_t pub[57]);
int ed448_sign(const uint8_t seed[57], const uint8_t *msg, size_t msg_len,
               uint8_t sig[114]);
int ed448_verify(const uint8_t pub[57], const uint8_t *msg, size_t msg_len,
                 const uint8_t sig[114]);

#endif /* ED448_GLUE_H */
