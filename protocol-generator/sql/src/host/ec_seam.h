/*
 * ec_seam.h — the codec/crypto SEAM of the SQL (authority-as-query) peer (#SQL).
 *
 * The THINNEST possible bridge from the C host to the language-agnostic C-ABI
 * codec (libentitycore_codec / ffi-generator/c-abi). It owns exactly what the
 * SQL substrate genuinely cannot do — canonical CBOR bytes, content_hash,
 * peer-id, Ed25519/SHA crypto, entity/envelope byte navigation — and NOTHING of
 * the §5/§6.6 authority interior, which is authored as legible SQL queries (the
 * FLOW-DESIGN wrapper-guard, carried from the visual-paradigm probes).
 *
 * S2 SCOPE (this file): ECF encode / decode / content_hash / peer-id parse+format
 * / Ed25519 sign+verify / SHA-256 / envelope root-hash verify — every one
 * DELEGATED to ec_* across the C-ABI (profile [codec].strategy = "ffi-c-host";
 * SQL/SQLite has no CBOR/crypto). Plus the tight-seam move: those crypto
 * primitives are registered as SQLite APPLICATION-DEFINED FUNCTIONS so they are
 * callable FROM SQL (sha256 / content_hash / ed25519_verify), keeping even the
 * §5.2 verify sequencing inside the query. NOT here: sockets, §1.6 framing,
 * §6.5 dispatch, the §4 handshake state machine, or any authority SQL — those
 * are S3 (the host imperative shell + the SQL interior).
 *
 * Number-model tax (A-SQL-002): the CBOR uint64 head-form + the mt7 shortest-
 * float ladder live BELOW this seam, in libentitycore_codec, which owns the wire
 * bytes. SQL never sees a raw wire integer; out-of-int64 values ride as opaque
 * blobs. This seam only moves bytes/handles across the C-ABI.
 *
 * Ownership: variable-length outputs (*_alloc) are malloc'd here and OWNED BY THE
 * CALLER (free() them). Fixed-length outputs write into a caller buffer. All
 * functions return 0 on success or a negative EC_* code (entitycore_codec.h).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef EC_SEAM_H
#define EC_SEAM_H

#include <stddef.h>
#include <stdint.h>

#include "entitycore_codec.h"
#include "sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── provenance (proves the C-ABI link; see A-SQL-001 on the label lag) ── */
const char *ec_seam_impl_info(void);
const char *ec_seam_abi_version(void);

/* ── ECF entity encode: {type,data} → canonical ECF bytes (delegated
 * ec_encode_ecf). *out is malloc'd, caller frees. The canonical 2-key
 * {data,type} map — the signature/hash preimage. ── */
int32_t ec_seam_encode_ecf_alloc(const unsigned char *type, size_t type_len,
                                 const unsigned char *data, size_t data_len,
                                 unsigned char **out, size_t *out_len);

/* ── content_hash: varint(format_code) ‖ DIGEST_format(ECF({type,data}))
 * (delegated ec_content_hash_with_format). format 0x00 → SHA-256 (33 B),
 * 0x01 → SHA-384 (49 B); any other code → EC_DECODE_ERROR (the delegated
 * codec refuses to emit wrong bytes for an unallocated code — A-SQL-005).
 * *out is malloc'd, caller frees. ── */
int32_t ec_seam_content_hash_alloc(const unsigned char *type, size_t type_len,
                                   const unsigned char *data, size_t data_len,
                                   uint64_t format_code,
                                   unsigned char **out, size_t *out_len);

/* ── decode ONE entity: borrowed spans of type/data + the exact original wire
 * bytes (N4 entity fidelity — forward original bytes, never re-serialize). Runs
 * the §3.2 recursive tag scanner; rejects a major-type-6 tag with EC_DECODE_ERROR.
 * All out pointers borrow into `bytes` (valid while `bytes` is). Delegated. ── */
int32_t ec_seam_decode_entity(const unsigned char *bytes, size_t len,
                             const unsigned char **type, size_t *type_len,
                             const unsigned char **data, size_t *data_len,
                             const unsigned char **orig, size_t *orig_len);

/* ── bare canonical value round-trip (F6 hook): decode one canonical ECF value +
 * re-encode via the bare canonical encoder — identity for canonical input, the
 * Class-A byte-identity differential reachable through the delegated codec. Runs
 * the tag scanner (a tag anywhere → EC_DECODE_ERROR). *out malloc'd, caller
 * frees. ── */
int32_t ec_seam_canonicalize_alloc(const unsigned char *in, size_t in_len,
                                   unsigned char **out, size_t *out_len);

/* ── peer-id §1.5: format = Base58(varint(key_type)‖varint(hash_type)‖digest);
 * parse the inverse. *out (format) is a malloc'd NUL-terminated string, caller
 * frees. parse writes the digest into a caller buffer (≥64). Delegated. ── */
int32_t ec_seam_peerid_format_alloc(uint64_t key_type, uint64_t hash_type,
                                    const unsigned char *digest, size_t digest_len,
                                    char **out);
int32_t ec_seam_peerid_parse(const char *b58, size_t b58_len,
                            uint64_t *key_type, uint64_t *hash_type,
                            unsigned char *digest_out, size_t *digest_len);

/* ── crypto (delegated ec_*): SHA-256, Ed25519 sign/verify, seed→pubkey. ── */
int32_t ec_seam_sha256(const unsigned char *data, size_t len, unsigned char out32[32]);
int32_t ec_seam_ed25519_sign(const unsigned char seed32[32],
                            const unsigned char *msg, size_t msg_len,
                            unsigned char out_sig64[64]);
int32_t ec_seam_ed25519_verify(const unsigned char pub32[32],
                              const unsigned char *msg, size_t msg_len,
                              const unsigned char sig64[64]);
int32_t ec_seam_ed25519_seed_to_pubkey(const unsigned char seed32[32],
                                       unsigned char out_pub32[32]);

/* ── envelope §4.4/§5.3: recompute the root entity's content_hash and compare to
 * the declared root.content_hash. EC_OK / EC_HASH_MISMATCH / EC_DECODE_ERROR.
 * Delegated. ── */
int32_t ec_seam_envelope_verify_root_hash(const unsigned char *env, size_t len);

/* ── THE TIGHT-SEAM MOVE: register the crypto primitives as SQLite application-
 * defined functions so the §5.2 verdict query calls them inline (crypto callable
 * FROM SQL — the whole point of the SQLite choice, proven at the S1 GO-gate).
 * Registers:
 *   sha256(blob)                       → blob(32)   [ec_sha256]
 *   content_hash(text type, blob data) → blob(33)   [ec_content_hash, format 0]
 *   ed25519_verify(blob pub, blob msg, blob sig) → int 1/0   [ec_ed25519_verify]
 * Returns SQLITE_OK on success. The host (S3) calls this once per db handle. ── */
int ec_seam_register_sql_functions(sqlite3 *db);

#ifdef __cplusplus
}
#endif

#endif /* EC_SEAM_H */
