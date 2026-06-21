/*
 * codec_core.h — internal core helpers shared by the C-ABI exports (codec.c)
 * and the conformance harness. These mirror the Rust impl's `api` module; the
 * exported ec_* symbols (entitycore_codec.h) wrap them. Keeping one
 * implementation means the harness exercises the same code the ABI ships.
 *
 * NOT part of the public ABI — the public surface is include/entitycore_codec.h.
 */
#ifndef CODEC_CORE_H
#define CODEC_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "ecf.h"

/* Lazy, idempotent libsodium init. Returns 1 on success, 0 on failure. */
int cc_sodium_ready(void);

/* SHA-256 of `data` → out (32 bytes). */
void cc_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* content_hash = varint(format_code) ‖ SHA256(ECF({data, type})) (spec sec.4.1).
 * `data` is the opaque, already-canonical CBOR of the data field (N4). Appends
 * to `out` (caller inits/frees). NOTE: always SHA-256 regardless of format_code
 * (the 0x00-form alias used by ec_content_hash); use the _with_format variant
 * for agility codes. */
void cc_content_hash(const uint8_t *type, size_t type_len,
                     const uint8_t *data, size_t data_len,
                     uint64_t format_code, ecbuf *out);

/* content_hash under an explicit format code (C-ABI v1.1 / spec sec.4.1a):
 *   varint(format_code) ‖ DIGEST_format(ECF({data, type}))
 * 0x00 → SHA-256 (33 B), 0x01 → SHA-384 (49 B). Returns 1 + appends to `out`
 * for a supported code; returns 0 (out untouched) for an unsupported code
 * (unsupported_content_hash_format). Twin of api::content_hash_with_format. */
int cc_content_hash_with_format(const uint8_t *type, size_t type_len,
                                const uint8_t *data, size_t data_len,
                                uint64_t format_code, ecbuf *out);

/* True iff `code` has a digest algorithm bound (V7 sec.1.2 seed table): 0x00
 * SHA-256, 0x01 SHA-384. BLAKE3/etc. (Phase 3a) are deferred. */
int cc_content_hash_format_supported(uint64_t code);

/* peer-id format: Base58(varint(key_type) ‖ varint(hash_type) ‖ digest).
 * Appends the Base58 string bytes to `out`. Returns 1/0. */
int cc_peerid_format(uint64_t key_type, uint64_t hash_type,
                     const uint8_t *digest, size_t digest_len, ecbuf *out);

/* peer-id parse → (key_type, hash_type, digest). `digest` must hold >= 64 bytes;
 * *digest_len gets the actual length. Returns 1 on success, 0 on malformed. */
int cc_peerid_parse(const uint8_t *base58, size_t base58_len,
                    uint64_t *key_type, uint64_t *hash_type,
                    uint8_t *digest, size_t *digest_len);

/* Deterministic Ed25519 sign over `msg` with a 32-byte seed (RFC 8032).
 * Returns 1 on success, 0 on failure. */
int cc_ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len,
                    uint8_t out_sig[64]);

/* Returns 1 iff `sig` is a valid Ed25519 signature of `msg` under `pub`. */
int cc_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
                      const uint8_t sig[64]);

#endif /* CODEC_CORE_H */
