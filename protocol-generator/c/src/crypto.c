/*
 * crypto.c — Ed25519 + SHA-256 via libsodium (the one authorized runtime dep).
 *
 * §9.1 floor: Ed25519 (RFC-8032 deterministic detached) + SHA-256. libsodium
 * supplies both from one audited source:
 *   - crypto_sign_seed_keypair  : 32-byte seed -> (pk, sk)
 *   - crypto_sign_detached      : deterministic 64-byte signature
 *   - crypto_sign_verify_detached
 *   - crypto_hash_sha256
 *
 * Ed448 / SHA-384 agility is DEFERRED (A-C-001): libsodium has no Ed448. The core
 * path is Ed25519 + SHA-256 only.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "entity_core/protocol.h"

#include <sodium.h>
#include <string.h>

ec_status ec_crypto_init(void)
{
    if (sodium_init() < 0) {
        return EC_ERR_CRYPTO;
    }
    return EC_OK;
}

ec_status ec_sha256(const uint8_t *in, size_t in_len, uint8_t out[EC_SHA256_LEN])
{
    if (!out || (!in && in_len > 0)) {
        return EC_ERR_BAD_INPUT;
    }
    if (crypto_hash_sha256(out, in, in_len) != 0) {
        return EC_ERR_CRYPTO;
    }
    return EC_OK;
}

ec_status ec_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf && len > 0) {
        return EC_ERR_BAD_INPUT;
    }
    if (sodium_init() < 0) {
        return EC_ERR_CRYPTO;
    }
    randombytes_buf(buf, len);   /* libsodium CSPRNG — per-connection unique nonce (F12) */
    return EC_OK;
}

ec_status ec_ed25519_pubkey(const uint8_t *seed, size_t seed_len,
                            uint8_t out_pubkey[EC_ED25519_PUBKEY_LEN])
{
    if (!seed || !out_pubkey) {
        return EC_ERR_BAD_INPUT;
    }
    if (seed_len != EC_ED25519_SEED_LEN) {
        return EC_ERR_BAD_SEED;
    }
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        sodium_memzero(sk, sizeof(sk));
        return EC_ERR_CRYPTO;
    }
    memcpy(out_pubkey, pk, EC_ED25519_PUBKEY_LEN);
    sodium_memzero(sk, sizeof(sk));
    return EC_OK;
}

ec_status ec_ed25519_sign(const uint8_t *seed, size_t seed_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t out_sig[EC_ED25519_SIG_LEN])
{
    if (!seed || !out_sig || (!msg && msg_len > 0)) {
        return EC_ERR_BAD_INPUT;
    }
    if (seed_len != EC_ED25519_SEED_LEN) {
        return EC_ERR_BAD_SEED;
    }
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        sodium_memzero(sk, sizeof(sk));
        return EC_ERR_CRYPTO;
    }
    unsigned long long siglen = 0;
    int rc = crypto_sign_detached(out_sig, &siglen, msg, msg_len, sk);
    sodium_memzero(sk, sizeof(sk));
    if (rc != 0 || siglen != EC_ED25519_SIG_LEN) {
        return EC_ERR_CRYPTO;
    }
    return EC_OK;
}

ec_status ec_ed25519_verify(const uint8_t *pubkey, size_t pubkey_len,
                            const uint8_t *sig, size_t sig_len,
                            const uint8_t *msg, size_t msg_len)
{
    if (!pubkey || !sig || (!msg && msg_len > 0)) {
        return EC_ERR_BAD_INPUT;
    }
    if (pubkey_len != EC_ED25519_PUBKEY_LEN || sig_len != EC_ED25519_SIG_LEN) {
        return EC_ERR_BAD_INPUT;
    }
    if (crypto_sign_verify_detached(sig, msg, msg_len, pubkey) != 0) {
        return EC_ERR_VERIFY_FAILED;
    }
    return EC_OK;
}

ec_status ec_sign_entity(const uint8_t *seed, size_t seed_len,
                         const ec_value *type, const ec_value *data,
                         uint8_t out_sig[EC_ED25519_SIG_LEN])
{
    if (!type || !data || !out_sig) {
        return EC_ERR_BAD_INPUT;
    }
    /* Build {type, data} and ECF-encode it as the signed message. */
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
    /* type/data are borrowed; deep-copy via re-encode would be heavy — instead
     * encode {type,data} from a temporary map that ALIASES the caller's nodes,
     * then detach them before freeing the temp map so we don't double-free. */
    ec_status st = ec_map_put(entity, kt, (ec_value *)type);
    if (st == EC_OK) {
        st = ec_map_put(entity, kd, (ec_value *)data);
    }
    if (st != EC_OK) {
        /* type/data may not be installed; detach whatever is, then free temp. */
        for (size_t i = 0; i < entity->as.map.len; i++) {
            if (entity->as.map.entries[i].val == type ||
                entity->as.map.entries[i].val == data) {
                entity->as.map.entries[i].val = NULL;
            }
        }
        ec_value_free(entity);
        return st;
    }
    uint8_t *enc = NULL;
    size_t enc_len = 0;
    st = ec_ecf_encode(entity, &enc, &enc_len);
    /* Detach the aliased type/data so ec_value_free(entity) does not free them. */
    for (size_t i = 0; i < entity->as.map.len; i++) {
        if (entity->as.map.entries[i].val == type ||
            entity->as.map.entries[i].val == data) {
            entity->as.map.entries[i].val = NULL;
        }
    }
    ec_value_free(entity);
    if (st != EC_OK) {
        return st;
    }
    st = ec_ed25519_sign(seed, seed_len, enc, enc_len, out_sig);
    free(enc);
    return st;
}
