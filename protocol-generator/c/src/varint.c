/*
 * varint.c — multicodec-style unsigned LEB128 varints (V7 §1.5 / §7.3).
 *
 * Invariant N1: every format-code / key-type / hash-type prefix routes through a
 * REAL varint primitive, NOT a fixed byte. All currently-allocated codes are
 * < 0x80 (single byte), but a code >= 0x80 MUST extend (128 -> 0x80 0x01). The
 * corpus exercises this with synthetic high codes (content_hash.4 fc=128,
 * peer_id.3 key_type=128).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "entity_core/protocol.h"

/* Worst case for a uint64 LEB128 is 10 bytes. */
size_t ec_varint_encode(uint64_t n, uint8_t *buf)
{
    size_t i = 0;
    do {
        uint8_t b = (uint8_t)(n & 0x7f);
        n >>= 7;
        if (n != 0) {
            b |= 0x80;
        }
        buf[i++] = b;
    } while (n != 0);
    return i;
}

ec_status ec_varint_decode(const uint8_t *in, size_t in_len,
                           uint64_t *value, size_t *consumed)
{
    uint64_t v = 0;
    unsigned shift = 0;
    size_t i = 0;
    for (;;) {
        if (i >= in_len) {
            return EC_ERR_TRUNCATED;
        }
        if (shift >= 64) {
            return EC_ERR_NON_CANONICAL_ECF; /* > 64 bits */
        }
        uint8_t b = in[i++];
        v |= (uint64_t)(b & 0x7f) << shift;
        if ((b & 0x80) == 0) {
            /* Reject a non-minimal trailing 0x00 continuation (LEB128 minimality). */
            if (b == 0 && shift != 0) {
                return EC_ERR_NON_CANONICAL_ECF;
            }
            if (value) *value = v;
            if (consumed) *consumed = i;
            return EC_OK;
        }
        shift += 7;
    }
}
