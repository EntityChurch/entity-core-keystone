/*
 * entity_core/protocol.h — entity-core-protocol-c, public umbrella header.
 *
 * Peer #10 (C / C11 / POSIX). Hand-rolled canonical ECF (CBOR) codec + base58 +
 * multicodec LEB128 varint + libsodium crypto (Ed25519 + SHA-256). Core types
 * only (Entity, system/hash, system/peer, system/signature, system/capability
 * token shape, envelopes, protocol messages) — NO extension types.
 *
 * Idiom (per profile.toml):
 *   - error model: return-code + out-param. Every fallible function returns an
 *     `ec_status` int (EC_OK == 0; negative == a specific failure enum) and
 *     writes its result through an out-pointer. The caller MUST check the return
 *     before using the out-param. No setjmp/longjmp, no errno-smuggling.
 *   - memory: explicit malloc/free, documented caller-frees ownership. Every
 *     allocating API documents who frees (the matching ec_*_free()).
 *   - value model: `ec_value` is a tagged union over the ECF major types — the
 *     entity `data` field is a GENERAL ECF value (A-JAVA-010: never map-typed),
 *     so a scalar-data entity round-trips correctly.
 *   - decode is structural and OWNS its node tree (caller frees via
 *     ec_value_free); byte strings/text are copied into the node, so the input
 *     buffer need not outlive the decoded tree. (The zero-copy borrow variant is
 *     a peer-layer refinement, not needed for the codec gate.)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ENTITY_CORE_PROTOCOL_H
#define ENTITY_CORE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Export macro: -fvisibility=hidden hides everything; EC_API marks the ABI. */
#ifndef EC_API
#  if defined(_WIN32)
#    define EC_API
#  else
#    define EC_API __attribute__((visibility("default")))
#  endif
#endif

/* ── status codes (the return-code error model) ─────────────────────────── */
typedef enum ec_status {
    EC_OK = 0,
    EC_ERR_OOM = -1,                       /* malloc failed */
    EC_ERR_TRUNCATED = -2,                 /* input ran off the end */
    EC_ERR_NON_CANONICAL_ECF = -3,         /* not minimal / not canonical / trailing bytes */
    EC_ERR_TAG_REJECTED = -4,              /* major-type-6 tag anywhere (N2) */
    EC_ERR_DUPLICATE_KEY = -5,             /* duplicate map key */
    EC_ERR_BAD_SEED = -6,                  /* malformed signing seed */
    EC_ERR_UNSUPPORTED_KEY_TYPE = -7,
    EC_ERR_UNSUPPORTED_HASH_FORMAT = -8,
    EC_ERR_BAD_INPUT = -9,                 /* malformed caller arguments */
    EC_ERR_VERIFY_FAILED = -10,            /* signature verification failed */
    EC_ERR_CRYPTO = -11,                   /* libsodium init / internal */
    /* peer-layer (S3) additions — §4.10 resource bounds + the §5.2 trichotomy */
    EC_ERR_PAYLOAD_TOO_LARGE = -12,        /* §4.10(a): frame > max (→ 413 / close) */
    EC_ERR_CHAIN_DEPTH_EXCEEDED = -13,     /* §4.10(b): chain > 64 (→ 400, NOT 403) */
    EC_ERR_AUTHN = -14,                    /* §5.2: authentication_failed (→ 401) */
    EC_ERR_AUTHZ = -15                     /* §5.2: capability_denied (→ 403) */
} ec_status;

/* ── ECF value model: a tagged union over the ECF major types ───────────── */
typedef enum ec_kind {
    EC_INT,          /* major 0/1: a signed integer in the full uint64/-2^64 range */
    EC_BYTES,        /* major 2 */
    EC_TEXT,         /* major 3 (UTF-8) */
    EC_ARRAY,        /* major 4 */
    EC_MAP,          /* major 5 */
    EC_BOOL,         /* major 7: f4/f5 */
    EC_NULL,         /* major 7: f6 */
    EC_FLOAT,        /* major 7: finite f16/f32/f64 (carried as double) */
    EC_FLOAT_NAN,    /* major 7: f9 7e00 */
    EC_FLOAT_POS_INF,/* major 7: f9 7c00 */
    EC_FLOAT_NEG_INF,/* major 7: f9 fc00 */
    EC_FLOAT_NEG_ZERO/* major 7: f9 8000 */
} ec_kind;

typedef struct ec_value ec_value;

/* A map entry. Keys are ECF text or byte strings (canonical map keys). */
typedef struct ec_entry {
    ec_value *key;
    ec_value *val;
} ec_entry;

/*
 * The full uint64 / -2^64 head-form range does not fit a signed 64-bit int.
 * EC_INT carries the value as (negative flag, uint64 magnitude-form):
 *   - non-negative integer n:        negative=false, u = n            (0 .. 2^64-1)
 *   - negative integer -1-arg:       negative=true,  u = arg          (so value = -1-u)
 * This mirrors the CBOR major-0/1 head argument directly (native uint64_t).
 */
typedef struct ec_int {
    bool negative;   /* true => value is a major-1 nint = -1 - u */
    uint64_t u;      /* major-0 magnitude, or the major-1 argument */
} ec_int;

struct ec_value {
    ec_kind kind;
    union {
        ec_int    i;        /* EC_INT */
        double    f;        /* EC_FLOAT (finite) */
        bool      b;        /* EC_BOOL */
        struct { uint8_t *p; size_t len; } bytes;  /* EC_BYTES / EC_TEXT (text NUL-terminated for convenience) */
        struct { ec_value **items; size_t len; } arr;  /* EC_ARRAY */
        struct { ec_entry *entries; size_t len; } map; /* EC_MAP */
    } as;
};

/* ── value constructors (heap-allocated; free the whole tree via ec_value_free) ─ */
EC_API ec_value *ec_int_u(uint64_t n);              /* non-negative */
EC_API ec_value *ec_int_neg(uint64_t arg);          /* nint, value = -1 - arg */
EC_API ec_value *ec_float(double f);
EC_API ec_value *ec_bool(bool b);
EC_API ec_value *ec_null(void);
EC_API ec_value *ec_special(ec_kind special_kind);  /* NAN/POS_INF/NEG_INF/NEG_ZERO */
EC_API ec_value *ec_bytes(const uint8_t *p, size_t len);
EC_API ec_value *ec_text(const char *s);            /* NUL-terminated UTF-8 */
EC_API ec_value *ec_text_n(const char *s, size_t len);
EC_API ec_value *ec_array(void);                    /* empty; grow with ec_array_push */
EC_API ec_status ec_array_push(ec_value *arr, ec_value *item);  /* takes ownership of item */
EC_API ec_value *ec_map(void);                      /* empty; add with ec_map_put */
EC_API ec_status ec_map_put(ec_value *map, ec_value *key, ec_value *val); /* takes ownership */
EC_API ec_value *ec_map_get(const ec_value *map, const char *text_key);   /* borrow; NULL if absent */

EC_API void ec_value_free(ec_value *v);

/* Deep-copy a value tree (caller frees with ec_value_free); NULL on OOM. */
EC_API ec_value *ec_value_clone(const ec_value *v);

/* ── canonical ECF encode / decode ──────────────────────────────────────── */

/*
 * Encode `v` to canonical ECF bytes. On EC_OK, *out points to a malloc'd buffer
 * of *out_len bytes that the CALLER frees with free(). On error, *out is NULL.
 */
EC_API ec_status ec_ecf_encode(const ec_value *v, uint8_t **out, size_t *out_len);

/*
 * Decode canonical ECF bytes. On EC_OK, *out owns a fresh node tree the CALLER
 * frees with ec_value_free(). Rejects trailing bytes (non-canonical), tags (N2),
 * indefinite lengths, non-minimal integer/length args, and duplicate map keys.
 */
EC_API ec_status ec_ecf_decode(const uint8_t *in, size_t in_len, ec_value **out);

/* ── multicodec LEB128 varint (N1) ──────────────────────────────────────── */
/* Encode `n` into `buf` (>= 10 bytes); returns the byte count, 0 on overflow. */
EC_API size_t ec_varint_encode(uint64_t n, uint8_t *buf);
/* Decode a minimal LEB128 varint; writes value + bytes-consumed. */
EC_API ec_status ec_varint_decode(const uint8_t *in, size_t in_len,
                                  uint64_t *value, size_t *consumed);

/* ── base58 (Bitcoin alphabet) ──────────────────────────────────────────── */
/* Encode to a NUL-terminated string; *out is malloc'd, caller frees. */
EC_API ec_status ec_base58_encode(const uint8_t *in, size_t in_len, char **out);
/* Decode; *out is malloc'd (may be 0 bytes), caller frees. */
EC_API ec_status ec_base58_decode(const char *s, uint8_t **out, size_t *out_len);

/* ── content_hash: varint(format_code) || HASH(ECF({type,data})) ────────── */
#define EC_CONTENT_HASH_FORMAT_SHA256 0x00
#define EC_CONTENT_HASH_FORMAT_SHA384 0x01  /* agility — not in the libsodium core path */

/*
 * Compute the wire content_hash over an entity {type,data} map for the given
 * format_code. *out is malloc'd (varint prefix + digest), caller frees.
 * The construct side serializes the caller-supplied format_code verbatim
 * (content_hash.4 fc=128 passes) and uses SHA-256 for the digest unless a
 * libsodium-supported format requires otherwise (only 0x00 is on the core path).
 */
EC_API ec_status ec_content_hash(const ec_value *type, const ec_value *data,
                                 uint64_t format_code, uint8_t **out, size_t *out_len);

/* Lowercase hex of a content_hash (or any bytes). *out malloc'd, caller frees. */
EC_API ec_status ec_hex_lower(const uint8_t *in, size_t in_len, char **out);

/* ── peer_id: Base58(varint(key_type) || varint(hash_type) || digest) ───── */
#define EC_KEY_TYPE_ED25519 0x01
#define EC_KEY_TYPE_ED448   0x02
#define EC_HASH_TYPE_IDENTITY 0x00  /* identity-multihash: digest IS the key */
#define EC_HASH_TYPE_SHA256   0x01

/* Format a peer_id string from abstract components. *out malloc'd, caller frees. */
EC_API ec_status ec_peer_id_format(uint64_t key_type, uint64_t hash_type,
                                   const uint8_t *digest, size_t digest_len, char **out);

/* Parse a peer_id string back to its components (digest malloc'd, caller frees). */
EC_API ec_status ec_peer_id_parse(const char *peer_id, uint64_t *key_type,
                                  uint64_t *hash_type, uint8_t **digest, size_t *digest_len);

/*
 * Derive the §1.5 canonical-form peer_id from a RAW public key (A-C P1):
 * key <= 32 B => hash_type=0x00 identity-multihash, digest = raw pubkey;
 * key > 32 B  => hash_type=0x01, digest = SHA-256(pubkey).
 * Ed25519 (32 B) => (0x01, 0x00, pubkey). *out malloc'd, caller frees.
 */
EC_API ec_status ec_peer_id_from_pubkey(uint64_t key_type, const uint8_t *pubkey,
                                        size_t pubkey_len, char **out);

/* ── crypto (libsodium: Ed25519 + SHA-256) ──────────────────────────────── */
#define EC_ED25519_SEED_LEN   32
#define EC_ED25519_PUBKEY_LEN 32
#define EC_ED25519_SIG_LEN    64
#define EC_SHA256_LEN         32

EC_API ec_status ec_crypto_init(void);  /* call once; idempotent */

/* Derive a 32-byte Ed25519 public key from a 32-byte seed. */
EC_API ec_status ec_ed25519_pubkey(const uint8_t *seed, size_t seed_len,
                                   uint8_t out_pubkey[EC_ED25519_PUBKEY_LEN]);

/* Deterministic detached Ed25519 signature over `msg`. */
EC_API ec_status ec_ed25519_sign(const uint8_t *seed, size_t seed_len,
                                 const uint8_t *msg, size_t msg_len,
                                 uint8_t out_sig[EC_ED25519_SIG_LEN]);

/* Verify a detached Ed25519 signature. Returns EC_OK if valid. */
EC_API ec_status ec_ed25519_verify(const uint8_t *pubkey, size_t pubkey_len,
                                   const uint8_t *sig, size_t sig_len,
                                   const uint8_t *msg, size_t msg_len);

EC_API ec_status ec_sha256(const uint8_t *in, size_t in_len, uint8_t out[EC_SHA256_LEN]);

/* Fill `buf` with `len` cryptographically-secure random bytes (libsodium CSPRNG). */
EC_API ec_status ec_random_bytes(uint8_t *buf, size_t len);

/*
 * Sign an entity {type,data}: signature = Ed25519_sign(seed, ECF({type,data})).
 * *out_sig is the 64-byte signature written into the caller buffer.
 */
EC_API ec_status ec_sign_entity(const uint8_t *seed, size_t seed_len,
                                const ec_value *type, const ec_value *data,
                                uint8_t out_sig[EC_ED25519_SIG_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ENTITY_CORE_PROTOCOL_H */
