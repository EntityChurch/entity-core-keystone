/*
 * base58.c — Bitcoin-alphabet Base58, hand-rolled long-division (ffi-c.md).
 * The peer_id corpus vectors confirm it. Peer-ids are tiny (~34 bytes), so the
 * straightforward O(n*m) long-division is used — clarity over micro-opt.
 */
#include "base58.h"

#include <stdlib.h>

static const char ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* reverse lookup: char → value, -1 if not in alphabet */
static int b58_val(char c) {
    for (int i = 0; i < 58; i++)
        if (ALPHABET[i] == c) return i;
    return -1;
}

int base58_encode(const uint8_t *in, size_t len,
                  char *out, size_t out_cap, size_t *out_len) {
    size_t zeros = 0;
    while (zeros < len && in[zeros] == 0) zeros++;

    /* log(256)/log(58) ≈ 1.365 → *138/100 + 1 base-58 digits for the rest */
    size_t bufsz = (len - zeros) * 138 / 100 + 1;
    uint8_t *b58 = (uint8_t *)calloc(bufsz ? bufsz : 1, 1);
    if (!b58) return 0;

    for (size_t i = zeros; i < len; i++) {
        int carry = in[i];
        for (size_t j = bufsz; j-- > 0; ) {
            carry += 256 * b58[j];
            b58[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        /* carry is 0 here by construction of bufsz */
    }

    size_t start = 0;
    while (start < bufsz && b58[start] == 0) start++;

    size_t need = zeros + (bufsz - start);
    *out_len = need;
    if (need > out_cap) { free(b58); return 0; }

    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) out[o++] = '1';
    for (size_t i = start; i < bufsz; i++) out[o++] = ALPHABET[b58[i]];

    free(b58);
    return 1;
}

int base58_decode(const char *in, size_t len,
                  uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t zeros = 0;
    while (zeros < len && in[zeros] == '1') zeros++;

    /* log(58)/log(256) ≈ 0.733 → *733/1000 + 1 bytes for the rest */
    size_t bufsz = (len - zeros) * 733 / 1000 + 1;
    uint8_t *bin = (uint8_t *)calloc(bufsz ? bufsz : 1, 1);
    if (!bin) return 0;

    for (size_t i = zeros; i < len; i++) {
        int val = b58_val(in[i]);
        if (val < 0) { free(bin); return 0; } /* invalid character */
        int carry = val;
        for (size_t j = bufsz; j-- > 0; ) {
            carry += 58 * bin[j];
            bin[j] = (uint8_t)(carry & 0xff);
            carry >>= 8;
        }
    }

    size_t start = 0;
    while (start < bufsz && bin[start] == 0) start++;

    size_t need = zeros + (bufsz - start);
    *out_len = need;
    if (need > out_cap) { free(bin); return 0; }

    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) out[o++] = 0;
    for (size_t i = start; i < bufsz; i++) out[o++] = bin[i];

    free(bin);
    return 1;
}
