/*
 * entitycore_codec.h — Entity Codec C-ABI, canonical header.
 *
 * This header is the machine-readable face of ENTITY-CODEC-C-ABI-V1.md, which
 * is NORMATIVE on semantics. Every conforming implementation
 * (entity-core-codec-ffi-rust, entity-core-codec-ffi-c, ...) ships THIS header,
 * unchanged, and exports exactly these symbols. The shared library is named
 * libentitycore_codec.{so,dylib,dll} regardless of which implementation built
 * it; provenance is queried via ec_impl_info(), not the filename.
 *
 * ABI version: 1.1.  Spec: ffi-generator/c-abi/spec/ENTITY-CODEC-C-ABI-V1.md
 * License: Apache-2.0 (keystone S9).
 *
 * v1.1 adds the crypto-agility surface (V7 §1.2/§1.5, v7.67): per-algorithm
 * symbols ec_sha384 + ec_ed448_{keygen,sign,verify,seed_to_pubkey}, the
 * format-aware ec_content_hash_with_format, and the test-only ec_encode_bare_value
 * hook (F6). The Ed25519 + SHA-256 floor is unchanged; the new symbols are
 * validated-not-required. Supported content_hash_format codes = {0x00 SHA-256,
 * 0x01 SHA-384}; any other → EC_DECODE_ERROR (unsupported_content_hash_format).
 *
 * Conventions (spec §5):
 *   - All fallible functions return int32_t (EC_* codes below); EC_OK (0) = success.
 *   - Buffers are (ptr, len) pairs; strings are NOT null-terminated (except the
 *     static const char* returned by the introspection calls).
 *   - All inputs are borrowed; the callee retains no input pointer past return.
 *   - Output buffers are caller-allocated; EC_OUT_OF_SPACE writes the required
 *     size to the *_out_len pointer so the caller can grow and retry.
 *   - Decoded entity bodies live in a caller-owned ec_arena_t.
 */

#ifndef ENTITYCORE_CODEC_H
#define ENTITYCORE_CODEC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -- Error codes (spec §6); numeric values are part of the ABI -- */
#define EC_OK                  0
#define EC_INVALID_ARGUMENT   -1
#define EC_OUT_OF_SPACE       -2
#define EC_DECODE_ERROR       -3
#define EC_ENCODE_ERROR       -4
#define EC_HASH_MISMATCH      -5
#define EC_SIGNATURE_INVALID  -6
#define EC_KEY_INVALID        -7
#define EC_PEERID_INVALID     -8
#define EC_ARENA_EXHAUSTED    -9
#define EC_INTERNAL_ERROR    -99

/* content_hash is varint(format_code) ‖ digest; for the current 0x00 code that
 * is 33 bytes (1 + 32). Callers sizing buffers for the common case use this. */
#define EC_CONTENT_HASH_LEN   33
#define EC_SHA256_LEN         32
#define EC_ED25519_PRIV_LEN   32
#define EC_ED25519_PUB_LEN    32
#define EC_ED25519_SIG_LEN    64

/* Crypto-agility lengths (C-ABI v1.1). content_hash under SHA-384 (format 0x01)
 * is 49 bytes (1 + 48). Ed448 (key_type 0x02) uses RFC 8032 sizes. */
#define EC_SHA384_LEN         48
#define EC_CONTENT_HASH_SHA384_LEN 49
#define EC_ED448_PRIV_LEN     57
#define EC_ED448_PUB_LEN      57
#define EC_ED448_SIG_LEN     114

/* Opaque caller-owned arena for decoded entity bodies (spec §4.5, §5 rule 3). */
typedef struct ec_arena ec_arena_t;

/* === ECF / hash / entity (spec §4.1) === */

int32_t ec_encode_ecf(const uint8_t *type_ptr, size_t type_len,
                      const uint8_t *data_ptr, size_t data_len,
                      uint8_t *out_ptr, size_t out_cap, size_t *out_len);

int32_t ec_content_hash(const uint8_t *type_ptr, size_t type_len,
                       const uint8_t *data_ptr, size_t data_len,
                       uint8_t *out_ptr /* EC_CONTENT_HASH_LEN */);

/* Decode one entity. type/data slices are written into `arena`. AND (N4): the
 * exact original wire bytes of the decoded entity are returned as a borrowed
 * slice (orig_ptr/orig_len) into the caller's input buffer (valid only as long
 * as bytes_ptr is). Runs the tag scanner (spec §3.2); rejects with
 * EC_DECODE_ERROR on any major-type-6 item in a data region. */
int32_t ec_decode_entity(const uint8_t *bytes_ptr, size_t len, ec_arena_t *arena,
                        const uint8_t **out_type_ptr, size_t *out_type_len,
                        const uint8_t **out_data_ptr, size_t *out_data_len,
                        const uint8_t **out_orig_ptr, size_t *out_orig_len);

/* Optional convenience (spec §4.1): validate one entity and return its
 * original-byte span. ec_decode_entity already satisfies N4; this is sugar. */
int32_t ec_entity_original_bytes(const uint8_t *bytes_ptr, size_t len,
                                const uint8_t **out_ptr, size_t *out_len);

/* LEB128 format-code primitives (spec §3.1 / N1). */
int32_t ec_hash_format_code_encode(uint64_t code,
                                   uint8_t *out_ptr, size_t out_cap, size_t *out_len);
int32_t ec_hash_format_code_decode(const uint8_t *in_ptr, size_t in_len,
                                   uint64_t *out_code, size_t *out_consumed);

/* content_hash under an explicit format code (spec §4.1a, C-ABI v1.1):
 *   varint(format_code) ‖ DIGEST_format(ECF({type,data}))
 * 0x00 → SHA-256 (33 B), 0x01 → SHA-384 (49 B). Variable-length output honors
 * the OUT_OF_SPACE protocol. Unsupported format code → EC_DECODE_ERROR
 * (unsupported_content_hash_format). ec_content_hash is the 0x00 SHA-256 alias. */
int32_t ec_content_hash_with_format(const uint8_t *type_ptr, size_t type_len,
                                    const uint8_t *data_ptr, size_t data_len,
                                    uint64_t format_code,
                                    uint8_t *out_ptr, size_t out_cap, size_t *out_len);

/* Test-only (F6): decode one canonical ECF value and re-encode it through the
 * bare canonical encoder, making the Class-A encoder core reachable across the
 * ABI for the cross-impl differential. NOT a protocol surface — canonical CBOR
 * in, canonical CBOR out (identity for canonical input). */
int32_t ec_encode_bare_value(const uint8_t *in_ptr, size_t in_len,
                             uint8_t *out_ptr, size_t out_cap, size_t *out_len);

/* === Peer ID (spec §4.2) === */

int32_t ec_peerid_parse(const uint8_t *base58_ptr, size_t base58_len,
                       uint64_t *out_key_type, uint64_t *out_hash_type,
                       uint8_t *out_digest_ptr, size_t *out_digest_len);

int32_t ec_peerid_format(uint64_t key_type, uint64_t hash_type,
                        const uint8_t *digest_ptr, size_t digest_len,
                        uint8_t *out_ptr, size_t out_cap, size_t *out_len);

/* === Crypto (spec §4.3) === */

int32_t ec_ed25519_keygen(uint8_t *out_priv /* 32 */, uint8_t *out_pub /* 32 */);
int32_t ec_ed25519_sign(const uint8_t *priv_ptr /* 32 */,
                       const uint8_t *msg_ptr, size_t msg_len,
                       uint8_t *out_sig /* 64 */);
int32_t ec_ed25519_verify(const uint8_t *pub_ptr /* 32 */,
                         const uint8_t *msg_ptr, size_t msg_len,
                         const uint8_t *sig_ptr /* 64 */);
/* Ed25519 seed -> 32-byte public key (RFC 8032). Mirrors ec_ed448_seed_to_pubkey
 * for the Ed25519 family so an FFI-sourced-crypto peer can derive its identity
 * public key from a persistent on-disk seed (the --name keypair convention). */
int32_t ec_ed25519_seed_to_pubkey(const uint8_t *seed_ptr /* 32 */, uint8_t *out_pub /* 32 */);
int32_t ec_sha256(const uint8_t *data_ptr, size_t data_len, uint8_t *out_ptr /* 32 */);

/* === Crypto agility (spec §4.3a, C-ABI v1.1) ===
 * Per-algorithm symbols (Option A). SHA-384 = content_hash_format 0x01 digest;
 * Ed448 = key_type 0x02 (RFC 8032 pure, no context). The Ed25519+SHA-256 floor
 * is unchanged; these are validated-not-required. An impl MAY return
 * EC_INTERNAL_ERROR for an algorithm it does not yet implement (provenance via
 * ec_impl_info); the conformance floor does not require Ed448. */
int32_t ec_sha384(const uint8_t *data_ptr, size_t data_len, uint8_t *out_ptr /* 48 */);
int32_t ec_ed448_keygen(uint8_t *out_priv /* 57 */, uint8_t *out_pub /* 57 */);
int32_t ec_ed448_seed_to_pubkey(const uint8_t *seed_ptr /* 57 */, uint8_t *out_pub /* 57 */);
int32_t ec_ed448_sign(const uint8_t *priv_ptr /* 57 */,
                      const uint8_t *msg_ptr, size_t msg_len,
                      uint8_t *out_sig /* 114 */);
int32_t ec_ed448_verify(const uint8_t *pub_ptr /* 57 */,
                        const uint8_t *msg_ptr, size_t msg_len,
                        const uint8_t *sig_ptr /* 114 */);

/* === Envelope verification (spec §4.4) === */

int32_t ec_envelope_verify_root_hash(const uint8_t *envelope_ptr, size_t envelope_len);
int32_t ec_envelope_find_signature_for(const uint8_t *envelope_ptr, size_t envelope_len,
                                      const uint8_t *target_hash_ptr, size_t target_hash_len,
                                      const uint8_t **out_sig_entity_ptr, size_t *out_len);

/* === Arena management (spec §4.5) === */

ec_arena_t *ec_arena_new(void);
void        ec_arena_reset(ec_arena_t *arena);
void        ec_arena_free(ec_arena_t *arena);

/* === Introspection / provenance (spec §4.6) === */

/* This ABI spec version, e.g. "1.0". Identical across all conforming impls. */
const char *ec_abi_version(void);
/* Implementation provenance, e.g. "rust 0.1.0 / ecf-c-abi 1.0 / spec-data v7.56".
 * This — not the filename — is how a consumer tells which library it linked. */
const char *ec_impl_info(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ENTITYCORE_CODEC_H */
