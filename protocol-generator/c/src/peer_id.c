/*
 * peer_id.c — peer_id formatting/parsing + §1.5 canonical-form derivation.
 *
 *   peer_id = Base58(varint(key_type) || varint(hash_type) || digest)
 *
 * key_type / hash_type are multicodec LEB128 varints (N1).
 *
 * §1.5 canonical-form (P1; A-C pre-resolved): the Ed25519 peer_id is derived from
 * the §1.5 size-cutoff table — a key <= 32 bytes is identity-multihash
 * (hash_type=0x00, digest = RAW pubkey, NO hash); a larger key is SHA-256-form
 * (hash_type=0x01, digest = SHA-256(key)). So Ed25519 (32 B) -> (0x01, 0x00,
 * pubkey) and Ed448 (57 B) -> (0x02, 0x01, sha256(pubkey)). The stale §7.4
 * SHA-256 skeleton is NOT a construction path for v7.65+.
 *
 * The S2 corpus supplies key_type/hash_type/digest explicitly (opaque digests),
 * so the FORMAT path is what the corpus exercises; the from-pubkey derivation is
 * the construction the S4 handshake binds against, baked in correctly now.
 *
 * Memory: *out / *digest malloc'd, caller frees with free().
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "entity_core/protocol.h"

#include <stdlib.h>
#include <string.h>

ec_status ec_peer_id_format(uint64_t key_type, uint64_t hash_type,
                            const uint8_t *digest, size_t digest_len, char **out)
{
    if (!out || (!digest && digest_len > 0)) {
        return EC_ERR_BAD_INPUT;
    }
    *out = NULL;

    uint8_t kt[10], ht[10];
    size_t ktl = ec_varint_encode(key_type, kt);
    size_t htl = ec_varint_encode(hash_type, ht);

    size_t raw_len = ktl + htl + digest_len;
    uint8_t *raw = malloc(raw_len > 0 ? raw_len : 1);
    if (!raw) {
        return EC_ERR_OOM;
    }
    memcpy(raw, kt, ktl);
    memcpy(raw + ktl, ht, htl);
    if (digest_len > 0) {
        memcpy(raw + ktl + htl, digest, digest_len);
    }

    ec_status st = ec_base58_encode(raw, raw_len, out);
    free(raw);
    return st;
}

ec_status ec_peer_id_parse(const char *peer_id, uint64_t *key_type,
                           uint64_t *hash_type, uint8_t **digest, size_t *digest_len)
{
    if (!peer_id || !key_type || !hash_type || !digest || !digest_len) {
        return EC_ERR_BAD_INPUT;
    }
    *digest = NULL;
    *digest_len = 0;

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    ec_status st = ec_base58_decode(peer_id, &raw, &raw_len);
    if (st != EC_OK) {
        return st;
    }

    uint64_t kt = 0, ht = 0;
    size_t c1 = 0, c2 = 0;
    st = ec_varint_decode(raw, raw_len, &kt, &c1);
    if (st == EC_OK) {
        st = ec_varint_decode(raw + c1, raw_len - c1, &ht, &c2);
    }
    if (st != EC_OK) {
        free(raw);
        return st;
    }

    size_t off = c1 + c2;
    size_t dlen = raw_len - off;
    uint8_t *dig = malloc(dlen > 0 ? dlen : 1);
    if (!dig) {
        free(raw);
        return EC_ERR_OOM;
    }
    if (dlen > 0) {
        memcpy(dig, raw + off, dlen);
    }
    free(raw);

    *key_type = kt;
    *hash_type = ht;
    *digest = dig;
    *digest_len = dlen;
    return EC_OK;
}

ec_status ec_peer_id_from_pubkey(uint64_t key_type, const uint8_t *pubkey,
                                 size_t pubkey_len, char **out)
{
    if (!out || !pubkey || pubkey_len == 0) {
        return EC_ERR_BAD_INPUT;
    }
    if (pubkey_len <= 32) {
        /* identity-multihash: digest IS the public key */
        return ec_peer_id_format(key_type, EC_HASH_TYPE_IDENTITY, pubkey, pubkey_len, out);
    }
    /* SHA-256-form for keys > 32 bytes */
    uint8_t digest[EC_SHA256_LEN];
    ec_status st = ec_sha256(pubkey, pubkey_len, digest);
    if (st != EC_OK) {
        return st;
    }
    return ec_peer_id_format(key_type, EC_HASH_TYPE_SHA256, digest, EC_SHA256_LEN, out);
}
