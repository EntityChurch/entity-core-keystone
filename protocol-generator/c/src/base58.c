/*
 * base58.c — Base58 (Bitcoin alphabet) encode/decode, hand-rolled.
 *
 * Used for peer_id formatting/parsing (V7 §1.2 / §7.3). Leading zero bytes map to
 * a leading '1' each (leading-zero preserving in both directions). Implemented by
 * byte-wise long division / multiplication (no bignum dep).
 *
 * Memory: *out is malloc'd; the caller frees with free().
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "entity_core/protocol.h"

#include <stdlib.h>
#include <string.h>

static const char ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* Reverse map: char -> value, -1 if not a base58 char. */
static int b58_index(char c)
{
    for (int i = 0; i < 58; i++) {
        if (ALPHABET[i] == c) {
            return i;
        }
    }
    return -1;
}

ec_status ec_base58_encode(const uint8_t *in, size_t in_len, char **out)
{
    if (!out) {
        return EC_ERR_BAD_INPUT;
    }
    *out = NULL;

    size_t zeros = 0;
    while (zeros < in_len && in[zeros] == 0) {
        zeros++;
    }

    /* Upper bound on the base58 digit count: ceil(in_len * log(256)/log(58)) + 1.
     * log(256)/log(58) ~= 1.365658; use 138/100 as a safe rational over-estimate. */
    size_t cap = in_len * 138 / 100 + 1;
    uint8_t *digits = calloc(cap > 0 ? cap : 1, 1);
    if (!digits) {
        return EC_ERR_OOM;
    }

    /* `length` = number of base58 digits currently held at the END of `digits`. */
    size_t length = 0;
    for (size_t b = 0; b < in_len; b++) {
        int carry = in[b];
        size_t k = cap; /* write index, walking backward */
        for (size_t processed = 0; processed < length || carry != 0; processed++) {
            k--;
            carry += 256 * digits[k];
            digits[k] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        length = cap - k;
    }

    /* Most-significant digit starts at cap-length; no leading zero-digits remain. */
    size_t k = cap - length;

    size_t out_len = zeros + (cap - k);
    char *s = malloc(out_len + 1);
    if (!s) {
        free(digits);
        return EC_ERR_OOM;
    }
    size_t pos = 0;
    for (size_t z = 0; z < zeros; z++) {
        s[pos++] = '1';
    }
    for (; k < cap; k++) {
        s[pos++] = ALPHABET[digits[k]];
    }
    s[pos] = '\0';

    free(digits);
    *out = s;
    return EC_OK;
}

ec_status ec_base58_decode(const char *str, uint8_t **out, size_t *out_len)
{
    if (!str || !out || !out_len) {
        return EC_ERR_BAD_INPUT;
    }
    *out = NULL;
    *out_len = 0;

    size_t slen = strlen(str);
    size_t ones = 0;
    while (ones < slen && str[ones] == '1') {
        ones++;
    }

    /* Upper bound on the byte count: ceil(slen * log(58)/log(256)) + 1.
     * log(58)/log(256) ~= 0.7322; use 733/1000 as a safe over-estimate. */
    size_t cap = slen * 733 / 1000 + 1;
    uint8_t *bytes = calloc(cap > 0 ? cap : 1, 1);
    if (!bytes) {
        return EC_ERR_OOM;
    }

    /* `length` = number of base256 bytes currently held at the END of `bytes`. */
    size_t length = 0;
    for (size_t i = 0; i < slen; i++) {
        int d = b58_index(str[i]);
        if (d < 0) {
            free(bytes);
            return EC_ERR_BAD_INPUT;
        }
        int carry = d;
        size_t k2 = cap;
        for (size_t processed = 0; processed < length || carry != 0; processed++) {
            k2--;
            carry += 58 * bytes[k2];
            bytes[k2] = (uint8_t)(carry & 0xff);
            carry >>= 8;
        }
        length = cap - k2;
    }

    /* Most-significant byte starts at cap-length; no leading zero-bytes remain. */
    size_t k = cap - length;

    size_t body = cap - k;
    size_t total = ones + body;
    uint8_t *result = malloc(total > 0 ? total : 1);
    if (!result) {
        free(bytes);
        return EC_ERR_OOM;
    }
    memset(result, 0, ones); /* leading '1' -> 0x00 */
    if (body > 0) {
        memcpy(result + ones, bytes + k, body);
    }

    free(bytes);
    *out = result;
    *out_len = total;
    return EC_OK;
}
