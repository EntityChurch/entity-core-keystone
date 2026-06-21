/*
 * peer_internal.h — entity-core-protocol-c peer machinery (S3), internal header.
 *
 * The peer layer (L1–L4 + foundation) on top of the S2 codec. NOT part of the
 * public ABI (include/entity_core/protocol.h) — these are the in-tree types the
 * store / dispatch / transport / identity / capability modules share.
 *
 * Idiom (per profile.toml):
 *   - return-code + out-param error model: every fallible function returns an
 *     ec_status int (EC_OK==0; negative == failure enum) and writes results
 *     through out-pointers; the caller checks the return before using the
 *     out-param. goto-cleanup on error paths.
 *   - manual memory, documented caller-frees ownership. Materialized entities are
 *     reference-counted (ec_entity_ref / ec_entity_unref) because they are shared
 *     between the store, envelopes, and outcomes; everything else is plain
 *     malloc/free with a documented owner.
 *   - concurrency: pthreads. The store is pthread_rwlock_t-guarded (§4.8); the
 *     transport runs one reader thread per connection with a pthread_cond_t
 *     request_id demux table (§6.11) and a per-connection write mutex.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef EC_PEER_INTERNAL_H
#define EC_PEER_INTERNAL_H

#include "entity_core/protocol.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* Peer-layer status codes extend the public ec_status enum range (all negative,
 * non-overlapping). The dispatcher maps these / handler outcomes to wire status. */

/* ── materialized entity {type, data, content_hash} (§1.1 / §3.4) ───────────── */

/*
 * A materialized entity: its type string, its `data` (an ARBITRARY ECF value —
 * A-JAVA-010, never forced to a map), and the 33-byte content_hash over
 * ECF({type,data}) computed by our own S2 codec.
 *
 * Reference-counted: shared between the store, envelopes and outcomes. ec_entity_make
 * returns a +1 reference; ec_entity_ref bumps it, ec_entity_unref drops it (freeing at
 * zero). `data` is OWNED by the entity (cloned in on make / parse).
 */
typedef struct ec_entity {
    char *type;                 /* NUL-terminated type string (owned) */
    ec_value *data;             /* owned; arbitrary ECF value */
    uint8_t hash[33];           /* content_hash: 0x00 || SHA-256(ECF({type,data})) */
    atomic_int refcount;        /* §4.8 atomic refcount — shared entities are ref'd/unref'd
                                 * concurrently across dispatch threads (one per inbound
                                 * EXECUTE); a plain int races → use-after-free under load. */
} ec_entity;

/* Make a materialized entity. `data` is CLONED (caller keeps ownership of its arg).
 * On EC_OK *out is a +1 reference the caller unrefs. */
ec_status ec_entity_make(const char *type, const ec_value *data, ec_entity **out);

/* Take ownership of `data` (no clone) — used on hot construction paths. On any
 * outcome `data` is consumed (freed on error). */
ec_status ec_entity_make_owning(const char *type, ec_value *data, ec_entity **out);

ec_entity *ec_entity_ref(ec_entity *e);
void ec_entity_unref(ec_entity *e);

/* Wire form: encode {type, data, content_hash} to canonical ECF (caller frees *out). */
ec_status ec_entity_to_wire(const ec_entity *e, uint8_t **out, size_t *out_len);

/* Wire form as an ec_value map {type,data,content_hash} (caller frees with ec_value_free). */
ec_status ec_entity_to_cbor(const ec_entity *e, ec_value **out);

/* Parse a wire entity cbor-map; recompute + verify content_hash (§1.8). +1 ref out. */
ec_status ec_entity_of_cbor(const ec_value *m, ec_entity **out);

/* ── typed field reads off an entity's data (null-safe; data may be scalar) ──── */
const char *ec_ent_text(const ec_entity *e, const char *key);   /* borrow; NULL if absent */
const uint8_t *ec_ent_bytes(const ec_entity *e, const char *key, size_t *len); /* borrow */
bool ec_ent_uint(const ec_entity *e, const char *key, uint64_t *out);
const ec_value *ec_ent_field(const ec_entity *e, const char *key);   /* borrow value node */
const ec_value *ec_ent_map_field(const ec_entity *e, const char *key); /* borrow if map */
/* Decode a nested entity carried at `key` (a wire cbor-map). +1 ref out (NULL if absent). */
ec_entity *ec_ent_entity_field(const ec_entity *e, const char *key);

/* ── value helpers (the peer-layer Cbor.java analogue) ──────────────────────── */
const char *ec_v_text(const ec_value *m, const char *key);
const uint8_t *ec_v_bytes(const ec_value *m, const char *key, size_t *len);
bool ec_v_uint(const ec_value *m, const char *key, uint64_t *out);
const ec_value *ec_v_get(const ec_value *m, const char *key); /* borrow */
bool ec_v_is_true(const ec_value *v);

/* lowercase hex of bytes (§3.4/§3.5 A-CL-009 trap — always %02x). caller frees. */
char *ec_hex(const uint8_t *p, size_t len);

/* build helpers (return owned values; NULL on OOM) */
ec_value *ec_v_text_array(const char *const *items, size_t n);

/* ── envelope (§3.1): root + included(hash → entity) ────────────────────────── */

typedef struct ec_included {
    uint8_t hash[33];
    ec_entity *entity;          /* +1 ref held by the envelope */
} ec_included;

typedef struct ec_envelope {
    ec_entity *root;            /* +1 ref */
    ec_included *included;      /* array */
    size_t included_len;
    size_t included_cap;
} ec_envelope;

/* Create an envelope taking a +1 ref on root (caller keeps its own ref). */
ec_status ec_env_new(ec_entity *root, ec_envelope **out);
void ec_env_free(ec_envelope *env);
/* Append an included entry (takes a +1 ref on entity, copies its hash as the key). */
ec_status ec_env_add(ec_envelope *env, ec_entity *entity);
/* Find an included entity by hash (borrow; NULL if absent). */
ec_entity *ec_env_get(const ec_envelope *env, const uint8_t *h33);

ec_status ec_env_to_wire(const ec_envelope *env, uint8_t **out, size_t *out_len);
ec_status ec_env_of_wire(const uint8_t *in, size_t in_len, ec_envelope **out);

/* ── store (foundation §1.7): content(hash→entity) + tree(path→hash) ─────────── */
/* pthread_rwlock_t-guarded (§4.8 data-race safety, N6). Emit bus is live with zero
 * consumers (§6.13(c)). */

typedef struct ec_store ec_store;

ec_status ec_store_new(ec_store **out);
void ec_store_free(ec_store *s);

/* Put an entity in the content store (dedup by hash). Takes its own +1 ref. */
void ec_store_put(ec_store *s, ec_entity *e);
/* Borrow-by-hash: returns a +1 ref the caller unrefs (NULL if absent). */
ec_entity *ec_store_get_by_hash(ec_store *s, const uint8_t *h33);
/* Bind path → entity (also puts in content store). +1 ref taken. */
void ec_store_bind(ec_store *s, const char *path, ec_entity *e);
void ec_store_unbind(ec_store *s, const char *path);
/* Get entity at path: +1 ref the caller unrefs (NULL if absent). */
ec_entity *ec_store_get_at(ec_store *s, const char *path);
/* Hex hash bound at path into out_hex (caller frees); EC_OK / EC_ERR_BAD_INPUT(absent). */
ec_status ec_store_hash_at(ec_store *s, const char *path, char **out_hex);

/* One-level listing under prefix. */
typedef struct ec_list_entry {
    char *segment;              /* owned */
    char hash_hex[67];          /* "" if a pure intermediate node */
    bool has_children;
} ec_list_entry;
/* Returns a malloc'd array (sorted by segment); caller frees each segment + the array. */
ec_status ec_store_listing(ec_store *s, const char *prefix,
                           ec_list_entry **out, size_t *out_n);
void ec_store_listing_free(ec_list_entry *rows, size_t n);

/* Emit bus: register a tree-change consumer (live any time). */
typedef void (*ec_tree_consumer)(void *ctx, const char *path);
void ec_store_register_tree_consumer(ec_store *s, ec_tree_consumer fn, void *ctx);

/* ── identity (L1) ──────────────────────────────────────────────────────────── */

typedef struct ec_identity {
    uint8_t seed[32];
    uint8_t public_key[32];
    char *peer_id;              /* §1.5 identity-multihash, owned */
    ec_entity *peer_entity;     /* system/peer {public_key,key_type}; +1 ref */
    uint8_t identity_hash[33];  /* content_hash(peer_entity) */
} ec_identity;

ec_status ec_identity_of_seed(const uint8_t seed[32], ec_identity **out);
void ec_identity_free(ec_identity *id);

/* system/peer entity for a raw 32-byte pubkey (+1 ref out). */
ec_status ec_peer_entity_of_pubkey(const uint8_t pubkey[32], ec_entity **out);
/* §1.5 peer_id for a raw pubkey (caller frees). */
ec_status ec_peer_id_of_pubkey32(const uint8_t pubkey[32], char **out);

/* Sign a target entity → a system/signature entity (§3.5). +1 ref out. */
ec_status ec_identity_sign(const ec_identity *id, const ec_entity *target, ec_entity **out);
/* Verify a system/signature entity against the signer's system/peer entity. */
bool ec_verify_signature(const ec_entity *signature, const ec_entity *signer_peer);

/* ── per-connection state (§4.2) + outbound seam (§6.13(b)) ──────────────────── */

struct ec_io;  /* transport-private */

typedef struct ec_conn {
    bool established;
    uint8_t issued_nonce[32];
    bool have_nonce;
    char *hello_peer_id;        /* owned; initiator's claimed peer_id from hello */
    struct ec_io *io;           /* reentry seam: the connection this request arrived on */
    int out_counter;
    pthread_mutex_t lock;
} ec_conn;

void ec_conn_init(ec_conn *c);
void ec_conn_destroy(ec_conn *c);

/* ── peer (the protocol brain) ──────────────────────────────────────────────── */

typedef struct ec_peer ec_peer;

ec_status ec_peer_create(const uint8_t seed[32], bool open_grants, bool conformance,
                         ec_peer **out);
void ec_peer_free(ec_peer *p);
const char *ec_peer_local(const ec_peer *p);          /* borrow peer_id */
ec_store *ec_peer_store(ec_peer *p);
const ec_identity *ec_peer_identity(const ec_peer *p);

/*
 * The §6.5 dispatch chain. Consumes an inbound envelope, returns a response envelope
 * (+1 ref out) or sets *out=NULL for a non-EXECUTE root (§3.3 server side ignores).
 * Returns EC_OK on a produced response (incl. error responses).
 */
ec_status ec_peer_dispatch(ec_peer *p, ec_conn *conn, const ec_envelope *env,
                           ec_envelope **out);

#endif /* EC_PEER_INTERNAL_H */
