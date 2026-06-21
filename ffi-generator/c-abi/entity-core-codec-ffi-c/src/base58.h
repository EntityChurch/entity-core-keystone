/*
 * base58.h — Bitcoin-alphabet Base58 (hand-rolled; ffi-c.md: a dep for this is
 * pure liability). Twin of the Rust impl's `bs58` usage for peer-id.
 */
#ifndef BASE58_H
#define BASE58_H

#include <stddef.h>
#include <stdint.h>

/* Encode `in` (len bytes) → Base58 into `out` (caller buffer of `out_cap`).
 * Writes the encoded length to *out_len. Returns 1 on success, 0 if out_cap is
 * too small (*out_len still set to the required length). NOT null-terminated. */
int base58_encode(const uint8_t *in, size_t len,
                  char *out, size_t out_cap, size_t *out_len);

/* Decode Base58 string `in` (len chars) → bytes into `out` (caller buffer of
 * out_cap). Writes decoded length to *out_len. Returns 1 on success, 0 on
 * invalid character or insufficient out_cap. */
int base58_decode(const char *in, size_t len,
                  uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* BASE58_H */
