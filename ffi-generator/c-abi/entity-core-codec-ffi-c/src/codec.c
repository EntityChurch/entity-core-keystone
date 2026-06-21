/*
 * codec.c — the Entity Codec C-ABI exports (entitycore_codec.h) for the C impl,
 * plus the shared core helpers (codec_core.h). Twin of the Rust impl's lib.rs.
 *
 * FIRST-PASS SCOPE (mirrors the Rust first pass): encode / content_hash /
 * sha256 / ed25519 sign+verify+keygen / peer-id format+parse / LEB128
 * format-code / decode tag-reject (N2) are real. Envelope verify + the arena
 * trio + full N4 arena decode are stubbed (return EC_INTERNAL_ERROR) — no
 * conformance vector drives them yet (see README first-pass scope).
 *
 * C has no unwinding, so the Rust catch_unwind discipline (R6) maps to plain
 * defensive null/length checks here — no Rust panic can cross a boundary that
 * doesn't exist. The 6 codec-correctness learnings from the Rust review pass
 * (SESSION-NOTE-2026-06-07) are honored structurally; see ecf.c.
 */
#include "../include/entitycore_codec.h"
#include "codec_core.h"
#include "base58.h"
#include "ecf.h"
#include "sha384.h"
#include "ed448/ed448_glue.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

/* ─────────────────────────── shared core helpers ─────────────────────────── */

int cc_sodium_ready(void) {
    static int ready = 0;
    if (!ready) {
        if (sodium_init() < 0) return 0; /* -1 = failure; 0/1 = ok */
        ready = 1;
    }
    return 1;
}

void cc_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    crypto_hash_sha256(out, data, (unsigned long long)len);
}

void cc_content_hash(const uint8_t *type, size_t type_len,
                     const uint8_t *data, size_t data_len,
                     uint64_t format_code, ecbuf *out) {
    /* entity = {data: <opaque canonical CBOR>, type: <text>} (key-sorted at
     * encode time). content_hash hashes this 2-key map; format_code contributes
     * only the LEB128 prefix, never the hashed body (Rust review learning #4). */
    ec_value *entity = ev_new(EV_MAP);
    ec_pair *pairs = (ec_pair *)malloc(2 * sizeof(ec_pair));
    pairs[0].key = ev_text("data", 4);
    pairs[0].val = ev_preencoded(data, data_len);
    pairs[1].key = ev_text("type", 4);
    pairs[1].val = ev_text((const char *)type, type_len);
    entity->u.map.pairs = pairs;
    entity->u.map.len = 2;

    ecbuf body;
    ecbuf_init(&body);
    ecf_encode(entity, &body);

    uint8_t digest[32];
    cc_sha256(body.ptr, body.len, digest);
    ecbuf_free(&body);

    leb128_encode(format_code, out);
    ecbuf_append(out, digest, 32);
}

int cc_content_hash_format_supported(uint64_t code) {
    return code == 0 || code == 1;
}

int cc_content_hash_with_format(const uint8_t *type, size_t type_len,
                                const uint8_t *data, size_t data_len,
                                uint64_t format_code, ecbuf *out) {
    if (!cc_content_hash_format_supported(format_code)) return 0;

    /* entity = {data: <opaque canonical CBOR>, type: <text>}, hashed under the
     * digest the format code selects. Mirrors api::content_hash_with_format. */
    ec_value *entity = ev_new(EV_MAP);
    ec_pair *pairs = (ec_pair *)malloc(2 * sizeof(ec_pair));
    pairs[0].key = ev_text("data", 4);
    pairs[0].val = ev_preencoded(data, data_len);
    pairs[1].key = ev_text("type", 4);
    pairs[1].val = ev_text((const char *)type, type_len);
    entity->u.map.pairs = pairs;
    entity->u.map.len = 2;

    ecbuf body;
    ecbuf_init(&body);
    ecf_encode(entity, &body);

    leb128_encode(format_code, out);
    if (format_code == 0) {
        uint8_t digest[32];
        cc_sha256(body.ptr, body.len, digest);
        ecbuf_append(out, digest, 32);
    } else { /* 0x01 → SHA-384 */
        uint8_t digest[EC_SHA384_DIGEST_LEN];
        cc_sha384(body.ptr, body.len, digest);
        ecbuf_append(out, digest, EC_SHA384_DIGEST_LEN);
    }
    ecbuf_free(&body);
    return 1;
}

int cc_peerid_format(uint64_t key_type, uint64_t hash_type,
                     const uint8_t *digest, size_t digest_len, ecbuf *out) {
    ecbuf raw;
    ecbuf_init(&raw);
    leb128_encode(key_type, &raw);
    leb128_encode(hash_type, &raw);
    ecbuf_append(&raw, digest, digest_len);

    size_t cap = raw.len * 2 + 4; /* Base58 expands by ~1.37x; +slack */
    char *str = (char *)malloc(cap);
    size_t slen = 0;
    int ok = base58_encode(raw.ptr, raw.len, str, cap, &slen);
    if (ok) ecbuf_append(out, (const uint8_t *)str, slen);
    free(str);
    ecbuf_free(&raw);
    return ok;
}

int cc_peerid_parse(const uint8_t *base58, size_t base58_len,
                    uint64_t *key_type, uint64_t *hash_type,
                    uint8_t *digest, size_t *digest_len) {
    uint8_t raw[256];
    size_t raw_len = 0;
    if (!base58_decode((const char *)base58, base58_len, raw, sizeof(raw), &raw_len))
        return 0;
    uint64_t kt, ht;
    size_t n1 = leb128_decode(raw, raw_len, &kt);
    if (n1 == 0) return 0;
    size_t n2 = leb128_decode(raw + n1, raw_len - n1, &ht);
    if (n2 == 0) return 0;
    size_t dlen = raw_len - n1 - n2;
    *key_type = kt;
    *hash_type = ht;
    memcpy(digest, raw + n1 + n2, dlen);
    *digest_len = dlen;
    return 1;
}

int cc_ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len,
                    uint8_t out_sig[64]) {
    if (!cc_sodium_ready()) return 0;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) return 0;
    int ok = crypto_sign_detached(out_sig, NULL, msg, (unsigned long long)msg_len, sk) == 0;
    sodium_memzero(sk, sizeof(sk));
    return ok;
}

int cc_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[64]) {
    if (!cc_sodium_ready()) return 0;
    return crypto_sign_verify_detached(sig, msg, (unsigned long long)msg_len, pub) == 0;
}

/* ───────────────────────────── ABI: shared util ──────────────────────────── */

/* Copy `src` into the caller buffer, honoring the OUT_OF_SPACE protocol
 * (spec sec.5 rule 2): always write the required size; copy iff it fits. */
static int32_t write_out(const uint8_t *src, size_t src_len,
                         uint8_t *out_ptr, size_t out_cap, size_t *out_len) {
    if (out_len) *out_len = src_len;
    if (!out_ptr || out_cap < src_len) return EC_OUT_OF_SPACE;
    memcpy(out_ptr, src, src_len);
    return EC_OK;
}

/* ──────────────────────── ABI: ECF / hash / entity ────────────────────────── */

int32_t ec_encode_ecf(const uint8_t *type_ptr, size_t type_len,
                      const uint8_t *data_ptr, size_t data_len,
                      uint8_t *out_ptr, size_t out_cap, size_t *out_len) {
    if (!type_ptr || !data_ptr) return EC_INVALID_ARGUMENT;
    /* entity-shaped encode: {data: <opaque>, type: <text>} */
    ec_value *entity = ev_new(EV_MAP);
    ec_pair *pairs = (ec_pair *)malloc(2 * sizeof(ec_pair));
    pairs[0].key = ev_text("data", 4);
    pairs[0].val = ev_preencoded(data_ptr, data_len);
    pairs[1].key = ev_text("type", 4);
    pairs[1].val = ev_text((const char *)type_ptr, type_len);
    entity->u.map.pairs = pairs;
    entity->u.map.len = 2;

    ecbuf out;
    ecbuf_init(&out);
    ecf_encode(entity, &out);
    int32_t rc = write_out(out.ptr, out.len, out_ptr, out_cap, out_len);
    ecbuf_free(&out);
    return rc;
}

int32_t ec_content_hash(const uint8_t *type_ptr, size_t type_len,
                       const uint8_t *data_ptr, size_t data_len,
                       uint8_t *out_ptr /* EC_CONTENT_HASH_LEN */) {
    if (!type_ptr || !data_ptr || !out_ptr) return EC_INVALID_ARGUMENT;
    ecbuf out;
    ecbuf_init(&out);
    cc_content_hash(type_ptr, type_len, data_ptr, data_len, 0, &out);
    /* common 0x00-code case = 33 bytes (EC_CONTENT_HASH_LEN); caller-sized. */
    memcpy(out_ptr, out.ptr, out.len);
    ecbuf_free(&out);
    return EC_OK;
}

/* content_hash under an explicit format code (C-ABI v1.1). Variable length
 * (33 B for 0x00, 49 B for 0x01); honors the OUT_OF_SPACE protocol. Unsupported
 * code → EC_DECODE_ERROR (unsupported_content_hash_format). */
int32_t ec_content_hash_with_format(const uint8_t *type_ptr, size_t type_len,
                                    const uint8_t *data_ptr, size_t data_len,
                                    uint64_t format_code,
                                    uint8_t *out_ptr, size_t out_cap, size_t *out_len) {
    if (!type_ptr || !data_ptr) return EC_INVALID_ARGUMENT;
    ecbuf out;
    ecbuf_init(&out);
    if (!cc_content_hash_with_format(type_ptr, type_len, data_ptr, data_len, format_code, &out)) {
        ecbuf_free(&out);
        return EC_DECODE_ERROR; /* unsupported_content_hash_format */
    }
    int32_t rc = write_out(out.ptr, out.len, out_ptr, out_cap, out_len);
    ecbuf_free(&out);
    return rc;
}

int32_t ec_decode_entity(const uint8_t *bytes_ptr, size_t len, ec_arena_t *arena,
                        const uint8_t **out_type_ptr, size_t *out_type_len,
                        const uint8_t **out_data_ptr, size_t *out_data_len,
                        const uint8_t **out_orig_ptr, size_t *out_orig_len) {
    (void)arena; /* borrowed-span decode (N4 option a); arena may be NULL */
    if (!bytes_ptr) return EC_INVALID_ARGUMENT;
    /* N4 (spec sec.4.1 option a): type/data/orig are all BORROWED slices of the
     * caller's input. ecf_entity_spans runs the tag scan (N2) and returns the
     * value spans of `type` and `data`. */
    ec_span tspan, dspan;
    if (!ecf_entity_spans(bytes_ptr, len, &tspan, &dspan)) return EC_DECODE_ERROR;
    if (out_type_ptr) *out_type_ptr = bytes_ptr + tspan.off;
    if (out_type_len) *out_type_len = tspan.len;
    if (out_data_ptr) *out_data_ptr = bytes_ptr + dspan.off;
    if (out_data_len) *out_data_len = dspan.len;
    if (out_orig_ptr) *out_orig_ptr = bytes_ptr;
    if (out_orig_len) *out_orig_len = len;
    return EC_OK;
}

int32_t ec_entity_original_bytes(const uint8_t *bytes_ptr, size_t len,
                                const uint8_t **out_ptr, size_t *out_len) {
    if (!bytes_ptr) return EC_INVALID_ARGUMENT;
    if (!ecf_validate_no_tags(bytes_ptr, len)) return EC_DECODE_ERROR;
    if (out_ptr) *out_ptr = bytes_ptr;
    if (out_len) *out_len = len;
    return EC_OK;
}

int32_t ec_hash_format_code_encode(uint64_t code,
                                   uint8_t *out_ptr, size_t out_cap, size_t *out_len) {
    ecbuf out;
    ecbuf_init(&out);
    leb128_encode(code, &out);
    int32_t rc = write_out(out.ptr, out.len, out_ptr, out_cap, out_len);
    ecbuf_free(&out);
    return rc;
}

int32_t ec_hash_format_code_decode(const uint8_t *in_ptr, size_t in_len,
                                   uint64_t *out_code, size_t *out_consumed) {
    if (!in_ptr) return EC_INVALID_ARGUMENT;
    uint64_t code = 0;
    size_t consumed = leb128_decode(in_ptr, in_len, &code);
    if (consumed == 0) return EC_DECODE_ERROR;
    if (out_code) *out_code = code;
    if (out_consumed) *out_consumed = consumed;
    return EC_OK;
}

/* ───────────────────────────────── Peer ID ───────────────────────────────── */

int32_t ec_peerid_parse(const uint8_t *base58_ptr, size_t base58_len,
                       uint64_t *out_key_type, uint64_t *out_hash_type,
                       uint8_t *out_digest_ptr, size_t *out_digest_len) {
    if (!base58_ptr) return EC_INVALID_ARGUMENT;
    uint64_t kt, ht;
    uint8_t digest[128];
    size_t dlen = 0;
    if (!cc_peerid_parse(base58_ptr, base58_len, &kt, &ht, digest, &dlen))
        return EC_PEERID_INVALID;
    if (out_key_type) *out_key_type = kt;
    if (out_hash_type) *out_hash_type = ht;
    if (out_digest_ptr) memcpy(out_digest_ptr, digest, dlen);
    if (out_digest_len) *out_digest_len = dlen;
    return EC_OK;
}

int32_t ec_peerid_format(uint64_t key_type, uint64_t hash_type,
                        const uint8_t *digest_ptr, size_t digest_len,
                        uint8_t *out_ptr, size_t out_cap, size_t *out_len) {
    if (!digest_ptr) return EC_INVALID_ARGUMENT;
    ecbuf out;
    ecbuf_init(&out);
    if (!cc_peerid_format(key_type, hash_type, digest_ptr, digest_len, &out)) {
        ecbuf_free(&out);
        return EC_INTERNAL_ERROR;
    }
    int32_t rc = write_out(out.ptr, out.len, out_ptr, out_cap, out_len);
    ecbuf_free(&out);
    return rc;
}

/* ───────────────────────────────── Crypto ────────────────────────────────── */

int32_t ec_ed25519_keygen(uint8_t *out_priv /* 32 */, uint8_t *out_pub /* 32 */) {
    if (!out_priv || !out_pub) return EC_INVALID_ARGUMENT;
    if (!cc_sodium_ready()) return EC_INTERNAL_ERROR;
    /* libsodium CSPRNG seed → deterministic keypair. (The Rust first pass
     * stubbed this pending an OsRng decision; in C libsodium's randombytes is
     * the audited CSPRNG, so it's implemented here. No vector drives it.) */
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    uint8_t seed[32];
    randombytes_buf(seed, sizeof(seed));
    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        sodium_memzero(seed, sizeof(seed));
        return EC_INTERNAL_ERROR;
    }
    memcpy(out_priv, seed, 32);
    memcpy(out_pub, pk, 32);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(sk, sizeof(sk));
    return EC_OK;
}

int32_t ec_ed25519_sign(const uint8_t *priv_ptr /* 32 */,
                       const uint8_t *msg_ptr, size_t msg_len,
                       uint8_t *out_sig /* 64 */) {
    if (!priv_ptr || !msg_ptr || !out_sig) return EC_INVALID_ARGUMENT;
    uint8_t seed[32];
    memcpy(seed, priv_ptr, 32);
    int ok = cc_ed25519_sign(seed, msg_ptr, msg_len, out_sig);
    sodium_memzero(seed, sizeof(seed));
    return ok ? EC_OK : EC_INTERNAL_ERROR;
}

int32_t ec_ed25519_verify(const uint8_t *pub_ptr /* 32 */,
                         const uint8_t *msg_ptr, size_t msg_len,
                         const uint8_t *sig_ptr /* 64 */) {
    if (!pub_ptr || !msg_ptr || !sig_ptr) return EC_INVALID_ARGUMENT;
    return cc_ed25519_verify(pub_ptr, msg_ptr, msg_len, sig_ptr)
               ? EC_OK : EC_SIGNATURE_INVALID;
}

/* Ed25519 seed -> 32-byte public key (RFC 8032). Mirrors ec_ed448_seed_to_pubkey
 * so an FFI-sourced-crypto peer can derive its identity public key from a
 * persistent on-disk seed (the --name keypair convention). */
int32_t ec_ed25519_seed_to_pubkey(const uint8_t *seed_ptr /* 32 */, uint8_t *out_pub /* 32 */) {
    if (!seed_ptr || !out_pub) return EC_INVALID_ARGUMENT;
    uint8_t sk[64];
    int rc = crypto_sign_seed_keypair(out_pub, sk, seed_ptr);
    sodium_memzero(sk, sizeof(sk));
    return rc == 0 ? EC_OK : EC_INTERNAL_ERROR;
}

int32_t ec_sha256(const uint8_t *data_ptr, size_t data_len, uint8_t *out_ptr /* 32 */) {
    if (!data_ptr || !out_ptr) return EC_INVALID_ARGUMENT;
    cc_sha256(data_ptr, data_len, out_ptr);
    return EC_OK;
}

int32_t ec_sha384(const uint8_t *data_ptr, size_t data_len, uint8_t *out_ptr /* 48 */) {
    if (!data_ptr || !out_ptr) return EC_INVALID_ARGUMENT;
    cc_sha384(data_ptr, data_len, out_ptr);
    return EC_OK;
}

/* ──────────────────────── Crypto agility: Ed448 (RFC 8032) ─────────────────── */
/* Implemented over the vendored OpenSSL curve448 (constant-time, Goldilocks
 * lineage) + a SHAKE256 wrapper on the same source's keccak1600 sponge — all
 * compiled into this object, so the .so stays self-contained (ldd = libc only).
 * libsodium has no Ed448; vendoring source (not linking a library) is the S6/S11
 * decision recorded in src/ed448/PROVENANCE.md. Pure Ed448: empty context,
 * phflag = 0. Seed = the 57-byte secret; pubkey 57; signature 114. */
int32_t ec_ed448_keygen(uint8_t *out_priv /* 57 */, uint8_t *out_pub /* 57 */) {
    if (!out_priv || !out_pub) return EC_INVALID_ARGUMENT;
    if (!cc_sodium_ready()) return EC_INTERNAL_ERROR;
    uint8_t seed[EC_ED448_PRIV_LEN];
    randombytes_buf(seed, sizeof(seed));   /* libsodium CSPRNG (same as ed25519) */
    if (ed448_derive_pubkey(seed, out_pub) != 0) {
        sodium_memzero(seed, sizeof(seed));
        return EC_INTERNAL_ERROR;
    }
    memcpy(out_priv, seed, EC_ED448_PRIV_LEN);
    sodium_memzero(seed, sizeof(seed));
    return EC_OK;
}
int32_t ec_ed448_seed_to_pubkey(const uint8_t *seed_ptr /* 57 */, uint8_t *out_pub /* 57 */) {
    if (!seed_ptr || !out_pub) return EC_INVALID_ARGUMENT;
    return ed448_derive_pubkey(seed_ptr, out_pub) == 0 ? EC_OK : EC_INTERNAL_ERROR;
}
int32_t ec_ed448_sign(const uint8_t *priv_ptr /* 57 */,
                      const uint8_t *msg_ptr, size_t msg_len, uint8_t *out_sig /* 114 */) {
    if (!priv_ptr || !msg_ptr || !out_sig) return EC_INVALID_ARGUMENT;
    return ed448_sign(priv_ptr, msg_ptr, msg_len, out_sig) == 0 ? EC_OK : EC_INTERNAL_ERROR;
}
int32_t ec_ed448_verify(const uint8_t *pub_ptr /* 57 */,
                       const uint8_t *msg_ptr, size_t msg_len, const uint8_t *sig_ptr /* 114 */) {
    if (!pub_ptr || !msg_ptr || !sig_ptr) return EC_INVALID_ARGUMENT;
    return ed448_verify(pub_ptr, msg_ptr, msg_len, sig_ptr) == 0
               ? EC_OK : EC_SIGNATURE_INVALID;
}

/* ──────────────────────────── Envelope verification ───────────────────────── */

/* Lookup a text-keyed field in a decoded EV_MAP value. */
static const ec_value *ev_map_get(const ec_value *m, const char *key) {
    if (!m || m->kind != EV_MAP) return NULL;
    size_t kl = strlen(key);
    for (size_t i = 0; i < m->u.map.len; i++) {
        const ec_value *k = m->u.map.pairs[i].key;
        if (k->kind == EV_TEXT && k->u.bytes.len == kl && memcmp(k->u.bytes.ptr, key, kl) == 0)
            return m->u.map.pairs[i].val;
    }
    return NULL;
}

#define EC_MAX_INCLUDED 512

/* Decode an envelope, recompute the root entity's content_hash from {type,data}
 * and compare to the declared root.content_hash (spec sec.4.4 / sec.5.3). The
 * declared hash's LEB128 prefix selects the digest. NOTE: ecf_decode builds a
 * value tree that this short-lived path does not free (the documented C decode
 * pragmatic; the deferred arena addresses the long-running peer). Twin of
 * api::envelope_verify_root_hash. */
int32_t ec_envelope_verify_root_hash(const uint8_t *envelope_ptr, size_t envelope_len) {
    if (!envelope_ptr) return EC_INVALID_ARGUMENT;
    ec_value *env = ecf_decode(envelope_ptr, envelope_len);
    if (!env || env->kind != EV_MAP) return EC_DECODE_ERROR;
    const ec_value *root = ev_map_get(env, "root");
    const ec_value *type = ev_map_get(root, "type");
    const ec_value *data = ev_map_get(root, "data");
    const ec_value *ch = ev_map_get(root, "content_hash");
    if (!type || type->kind != EV_TEXT || !data || !ch || ch->kind != EV_BYTES)
        return EC_DECODE_ERROR;
    uint64_t fmt;
    if (leb128_decode(ch->u.bytes.ptr, ch->u.bytes.len, &fmt) == 0) return EC_DECODE_ERROR;
    /* canonical input ⇒ re-encoding the decoded data field is identity. */
    ecbuf db;
    ecbuf_init(&db);
    ecf_encode(data, &db);
    ecbuf got;
    ecbuf_init(&got);
    int ok = cc_content_hash_with_format(type->u.bytes.ptr, type->u.bytes.len,
                                         db.ptr, db.len, fmt, &got);
    ecbuf_free(&db);
    if (!ok) { ecbuf_free(&got); return EC_DECODE_ERROR; }
    int match = (got.len == ch->u.bytes.len && memcmp(got.ptr, ch->u.bytes.ptr, got.len) == 0);
    ecbuf_free(&got);
    return match ? EC_OK : EC_HASH_MISMATCH;
}

/* Scan `included` for a system/signature entity whose data.target == target_hash;
 * return its borrowed byte span within the envelope. Twin of
 * api::envelope_find_signature_for. */
int32_t ec_envelope_find_signature_for(const uint8_t *envelope_ptr, size_t envelope_len,
                                      const uint8_t *target_hash_ptr, size_t target_hash_len,
                                      const uint8_t **out_sig_entity_ptr, size_t *out_len) {
    if (!envelope_ptr || !target_hash_ptr) return EC_INVALID_ARGUMENT;
    ec_span root, ikeys[EC_MAX_INCLUDED], ients[EC_MAX_INCLUDED];
    size_t nin;
    if (!ecf_envelope_spans(envelope_ptr, envelope_len, &root, ikeys, ients, &nin, EC_MAX_INCLUDED))
        return EC_DECODE_ERROR;
    for (size_t i = 0; i < nin; i++) {
        const uint8_t *eb = envelope_ptr + ients[i].off;
        ec_value *e = ecf_decode(eb, ients[i].len);
        const ec_value *t = ev_map_get(e, "type");
        if (!t || t->kind != EV_TEXT || t->u.bytes.len < 16 ||
            memcmp(t->u.bytes.ptr, "system/signature", 16) != 0)
            continue;
        const ec_value *d = ev_map_get(e, "data");
        const ec_value *tgt = ev_map_get(d, "target");
        if (!tgt || tgt->kind != EV_BYTES) continue;
        if (tgt->u.bytes.len == target_hash_len &&
            memcmp(tgt->u.bytes.ptr, target_hash_ptr, target_hash_len) == 0) {
            if (out_sig_entity_ptr) *out_sig_entity_ptr = eb;
            if (out_len) *out_len = ients[i].len;
            return EC_OK;
        }
    }
    return EC_DECODE_ERROR;
}

/* ──────────────────────────── Arena management ────────────────────────────── */
/* This impl decodes by borrowed span (N4 option a) — ec_decode_entity needs no
 * arena. The trio is real for ABI completeness: new returns a non-NULL handle,
 * free is well-defined. Mirrors the Rust impl. */
ec_arena_t *ec_arena_new(void) { return (ec_arena_t *)malloc(1); }
void        ec_arena_reset(ec_arena_t *arena) { (void)arena; }
void        ec_arena_free(ec_arena_t *arena) { free(arena); }

/* ──────────────────────── F6: bare-encode test hook ───────────────────────── */
/* The shipped ABI exposes only the entity-shaped ec_encode_ecf; the bare
 * canonical encoder is otherwise unreachable across the boundary (F6). This
 * test-only hook decodes one canonical ECF value and re-encodes it, proving the
 * encoder core is reachable + canonical (identity for canonical input). Twin of
 * the Rust ec_encode_bare_value → unblocks the 5-way Class-A differential. */
int32_t ec_encode_bare_value(const uint8_t *in_ptr, size_t in_len,
                             uint8_t *out_ptr, size_t out_cap, size_t *out_len) {
    if (!in_ptr) return EC_INVALID_ARGUMENT;
    ec_value *v = ecf_decode(in_ptr, in_len);
    if (!v) return EC_DECODE_ERROR;
    ecbuf out;
    ecbuf_init(&out);
    ecf_encode(v, &out);
    int32_t rc = write_out(out.ptr, out.len, out_ptr, out_cap, out_len);
    ecbuf_free(&out);
    return rc;
}

/* ───────────────────────────────── Introspection ─────────────────────────── */

const char *ec_abi_version(void) { return "1.1"; }
const char *ec_impl_info(void) {
    return "c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 / libsodium 1.0.22 "
           "(+ hand-rolled sha384; ed448 via vendored openssl-3.3.2 curve448 + shake256)";
}
