/*
 * content_hash.c — content_hash construction + lowercase hex.
 *
 *   content_hash = varint(format_code) || HASH(ECF({type, data}))
 *
 * Format code 0x00 = ecfv1-sha256 (the §9.1 floor). The format_code is NOT part
 * of the hashed entity — only {type,data} is hashed. The varint prefix is
 * multicodec LEB128 (N1), so a code >= 0x80 extends to multiple bytes.
 *
 * Construct/receive asymmetry (A-OC-004 / A-CL-007, independently reached): the
 * CONSTRUCT side serializes the caller-supplied format_code verbatim (so
 * content_hash.4 with code 128 emits the 0x80 0x01 prefix) and digests with
 * SHA-256 on the core path — the corpus pins the SHA-256 digest even under the
 * synthetic 128 prefix. A receive/verify path (peer layer, S3) rejects
 * unallocated codes with EC_ERR_UNSUPPORTED_HASH_FORMAT.
 *
 * Memory: *out malloc'd, caller frees with free().
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "entity_core/protocol.h"

#include <stdlib.h>
#include <string.h>

ec_status ec_content_hash(const ec_value *type, const ec_value *data,
                          uint64_t format_code, uint8_t **out, size_t *out_len)
{
    if (!type || !data || !out || !out_len) {
        return EC_ERR_BAD_INPUT;
    }
    *out = NULL;
    *out_len = 0;

    /* Build {type, data} aliasing the caller nodes, ECF-encode, then detach. */
    ec_value *entity = ec_map();
    if (!entity) {
        return EC_ERR_OOM;
    }
    ec_value *kt = ec_text("type");
    ec_value *kd = ec_text("data");
    if (!kt || !kd) {
        ec_value_free(kt); ec_value_free(kd); ec_value_free(entity);
        return EC_ERR_OOM;
    }
    ec_status st = ec_map_put(entity, kt, (ec_value *)type);
    if (st == EC_OK) {
        st = ec_map_put(entity, kd, (ec_value *)data);
    }
    if (st != EC_OK) {
        for (size_t i = 0; i < entity->as.map.len; i++) {
            ec_value *v = entity->as.map.entries[i].val;
            if (v == type || v == data) entity->as.map.entries[i].val = NULL;
        }
        ec_value_free(entity);
        return st;
    }

    uint8_t *enc = NULL;
    size_t enc_len = 0;
    st = ec_ecf_encode(entity, &enc, &enc_len);
    for (size_t i = 0; i < entity->as.map.len; i++) {
        ec_value *v = entity->as.map.entries[i].val;
        if (v == type || v == data) entity->as.map.entries[i].val = NULL;
    }
    ec_value_free(entity);
    if (st != EC_OK) {
        return st;
    }

    uint8_t digest[EC_SHA256_LEN];
    st = ec_sha256(enc, enc_len, digest);
    free(enc);
    if (st != EC_OK) {
        return st;
    }

    uint8_t prefix[10];
    size_t plen = ec_varint_encode(format_code, prefix);

    size_t total = plen + EC_SHA256_LEN;
    uint8_t *result = malloc(total);
    if (!result) {
        return EC_ERR_OOM;
    }
    memcpy(result, prefix, plen);
    memcpy(result + plen, digest, EC_SHA256_LEN);
    *out = result;
    *out_len = total;
    return EC_OK;
}

ec_status ec_hex_lower(const uint8_t *in, size_t in_len, char **out)
{
    if (!out || (!in && in_len > 0)) {
        return EC_ERR_BAD_INPUT;
    }
    static const char H[] = "0123456789abcdef"; /* lowercase pinned (P2 / A-CL-009) */
    char *s = malloc(in_len * 2 + 1);
    if (!s) {
        *out = NULL;
        return EC_ERR_OOM;
    }
    for (size_t i = 0; i < in_len; i++) {
        s[2 * i] = H[in[i] >> 4];
        s[2 * i + 1] = H[in[i] & 0xf];
    }
    s[in_len * 2] = 0;
    *out = s;
    return EC_OK;
}
