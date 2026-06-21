/*
 * identity.c — peer identity (L1): seed → public_key → §1.5 identity-multihash peer_id
 * (A-C P1: hash_type=0x00, raw pubkey, NOT the stale §7.4 SHA-256 form) + system/peer
 * entity + content_hash, plus the §3.5 sign/verify surface.
 *
 *   public_key   = Ed25519 pubkey of seed                         (32 bytes, libsodium)
 *   peer_id      = §1.5 canonical-form Base58(0x01||0x00||pubkey)
 *   peer_entity  = system/peer {public_key, key_type}             (§3.5 v7.65 basis)
 *   identityHash = content_hash(peer_entity)                      (33 bytes)
 *
 * Signing covers the full 33-byte content_hash (format byte + digest, §7.3) so a
 * signature is bound to the hash format.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "peer_internal.h"

#include <stdlib.h>
#include <string.h>

/* Build the system/peer entity for a raw 32-byte public key (+1 ref). */
ec_status ec_peer_entity_of_pubkey(const uint8_t pubkey[32], ec_entity **out)
{
    ec_status st = EC_ERR_OOM;
    ec_value *data = ec_map();
    ec_value *kp = NULL, *vp = NULL, *kt = NULL, *vt = NULL;
    if (!data) {
        goto cleanup;
    }
    kp = ec_text("public_key"); vp = ec_bytes(pubkey, 32);
    kt = ec_text("key_type");   vt = ec_text("ed25519");
    if (!kp || !vp || !kt || !vt) {
        goto cleanup;
    }
    if (ec_map_put(data, kp, vp) != EC_OK) { goto cleanup; }
    kp = vp = NULL;
    if (ec_map_put(data, kt, vt) != EC_OK) { goto cleanup; }
    kt = vt = NULL;
    return ec_entity_make_owning("system/peer", data, out);
cleanup:
    ec_value_free(kp); ec_value_free(vp);
    ec_value_free(kt); ec_value_free(vt);
    ec_value_free(data);
    return st;
}

ec_status ec_peer_id_of_pubkey32(const uint8_t pubkey[32], char **out)
{
    /* §1.5: Ed25519 (32B) → (key_type=0x01, hash_type=0x00 identity, digest=pubkey). */
    return ec_peer_id_from_pubkey(EC_KEY_TYPE_ED25519, pubkey, 32, out);
}

ec_status ec_identity_of_seed(const uint8_t seed[32], ec_identity **out)
{
    if (!seed || !out) {
        return EC_ERR_BAD_INPUT;
    }
    ec_status st = ec_crypto_init();
    if (st != EC_OK) {
        return st;
    }
    ec_identity *id = calloc(1, sizeof(*id));
    if (!id) {
        return EC_ERR_OOM;
    }
    memcpy(id->seed, seed, 32);
    st = ec_ed25519_pubkey(seed, 32, id->public_key);
    if (st != EC_OK) {
        goto cleanup;
    }
    st = ec_peer_entity_of_pubkey(id->public_key, &id->peer_entity);
    if (st != EC_OK) {
        goto cleanup;
    }
    memcpy(id->identity_hash, id->peer_entity->hash, 33);
    st = ec_peer_id_of_pubkey32(id->public_key, &id->peer_id);
    if (st != EC_OK) {
        goto cleanup;
    }
    *out = id;
    return EC_OK;
cleanup:
    ec_identity_free(id);
    return st;
}

void ec_identity_free(ec_identity *id)
{
    if (!id) {
        return;
    }
    ec_entity_unref(id->peer_entity);
    free(id->peer_id);
    /* seed is on the heap inside the struct; zero it before free (hygiene). */
    memset(id->seed, 0, sizeof(id->seed));
    free(id);
}

ec_status ec_identity_sign(const ec_identity *id, const ec_entity *target, ec_entity **out)
{
    if (!id || !target || !out) {
        return EC_ERR_BAD_INPUT;
    }
    uint8_t sig[EC_ED25519_SIG_LEN];
    ec_status st = ec_ed25519_sign(id->seed, 32, target->hash, 33, sig);
    if (st != EC_OK) {
        return st;
    }
    ec_value *data = ec_map();
    ec_value *kt = NULL, *vt = NULL, *ks = NULL, *vs = NULL;
    ec_value *ka = NULL, *va = NULL, *kg = NULL, *vg = NULL;
    st = EC_ERR_OOM;
    if (!data) {
        goto cleanup;
    }
    kt = ec_text("target");    vt = ec_bytes(target->hash, 33);
    ks = ec_text("signer");    vs = ec_bytes(id->identity_hash, 33);
    ka = ec_text("algorithm"); va = ec_text("ed25519");
    kg = ec_text("signature"); vg = ec_bytes(sig, EC_ED25519_SIG_LEN);
    if (!kt || !vt || !ks || !vs || !ka || !va || !kg || !vg) {
        goto cleanup;
    }
    if (ec_map_put(data, kt, vt) != EC_OK) { goto cleanup; } kt = vt = NULL;
    if (ec_map_put(data, ks, vs) != EC_OK) { goto cleanup; } ks = vs = NULL;
    if (ec_map_put(data, ka, va) != EC_OK) { goto cleanup; } ka = va = NULL;
    if (ec_map_put(data, kg, vg) != EC_OK) { goto cleanup; } kg = vg = NULL;
    return ec_entity_make_owning("system/signature", data, out);
cleanup:
    ec_value_free(kt); ec_value_free(vt);
    ec_value_free(ks); ec_value_free(vs);
    ec_value_free(ka); ec_value_free(va);
    ec_value_free(kg); ec_value_free(vg);
    ec_value_free(data);
    return st;
}

bool ec_verify_signature(const ec_entity *signature, const ec_entity *signer_peer)
{
    if (!signature || !signer_peer) {
        return false;
    }
    size_t tlen = 0, slen = 0, plen = 0;
    const uint8_t *target = ec_ent_bytes(signature, "target", &tlen);
    const uint8_t *sig = ec_ent_bytes(signature, "signature", &slen);
    const uint8_t *pub = ec_ent_bytes(signer_peer, "public_key", &plen);
    if (!target || !sig || !pub || plen != 32 || slen != EC_ED25519_SIG_LEN) {
        return false;
    }
    return ec_ed25519_verify(pub, plen, sig, slen, target, tlen) == EC_OK;
}
