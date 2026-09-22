/*
 * ec_seam.c — implementation of the codec/crypto seam (see ec_seam.h).
 *
 * Every primitive is a thin wrapper over an ec_* C-ABI call into
 * libentitycore_codec. Nothing here re-implements canonical CBOR or crypto (the
 * durable cohort lesson: no platform lib suffices for canonical ECF, so we
 * DELEGATE — SQL cannot assemble bytes at all). The only local logic is the
 * two-call EC_OUT_OF_SPACE sizing dance and the SQLite function trampolines.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ec_seam.h"

#include <stdlib.h>
#include <string.h>

const char *ec_seam_impl_info(void)   { return ec_impl_info(); }
const char *ec_seam_abi_version(void) { return ec_abi_version(); }

/* ── two-call sizing helpers over the C-ABI OUT_OF_SPACE protocol ──────────────
 * Each ec_* variable-length function writes the required size to *out_len even
 * when the buffer is NULL/too small (returning EC_OUT_OF_SPACE), so a sizing call
 * with a zero buffer yields the length. A code OTHER than OK/OUT_OF_SPACE on the
 * sizing call (e.g. EC_DECODE_ERROR for an unsupported content_hash format) is a
 * REAL error and is propagated verbatim — the delegated codec refuses to emit
 * wrong bytes, and the caller distinguishes that from a byte mismatch. */

int32_t ec_seam_encode_ecf_alloc(const unsigned char *type, size_t type_len,
                                 const unsigned char *data, size_t data_len,
                                 unsigned char **out, size_t *out_len)
{
    size_t need = 0;
    int32_t rc = ec_encode_ecf(type, type_len, data, data_len, NULL, 0, &need);
    if (rc != EC_OK && rc != EC_OUT_OF_SPACE) return rc;
    unsigned char *buf = (unsigned char *)malloc(need ? need : 1);
    if (!buf) return EC_INTERNAL_ERROR;
    rc = ec_encode_ecf(type, type_len, data, data_len, buf, need, &need);
    if (rc != EC_OK) { free(buf); return rc; }
    *out = buf; *out_len = need;
    return EC_OK;
}

int32_t ec_seam_content_hash_alloc(const unsigned char *type, size_t type_len,
                                   const unsigned char *data, size_t data_len,
                                   uint64_t format_code,
                                   unsigned char **out, size_t *out_len)
{
    size_t need = 0;
    int32_t rc = ec_content_hash_with_format(type, type_len, data, data_len,
                                             format_code, NULL, 0, &need);
    if (rc != EC_OK && rc != EC_OUT_OF_SPACE) return rc; /* unsupported code, etc. */
    unsigned char *buf = (unsigned char *)malloc(need ? need : 1);
    if (!buf) return EC_INTERNAL_ERROR;
    rc = ec_content_hash_with_format(type, type_len, data, data_len,
                                     format_code, buf, need, &need);
    if (rc != EC_OK) { free(buf); return rc; }
    *out = buf; *out_len = need;
    return EC_OK;
}

int32_t ec_seam_canonicalize_alloc(const unsigned char *in, size_t in_len,
                                   unsigned char **out, size_t *out_len)
{
    size_t need = 0;
    int32_t rc = ec_encode_bare_value(in, in_len, NULL, 0, &need);
    if (rc != EC_OK && rc != EC_OUT_OF_SPACE) return rc;
    unsigned char *buf = (unsigned char *)malloc(need ? need : 1);
    if (!buf) return EC_INTERNAL_ERROR;
    rc = ec_encode_bare_value(in, in_len, buf, need, &need);
    if (rc != EC_OK) { free(buf); return rc; }
    *out = buf; *out_len = need;
    return EC_OK;
}

int32_t ec_seam_decode_entity(const unsigned char *bytes, size_t len,
                             const unsigned char **type, size_t *type_len,
                             const unsigned char **data, size_t *data_len,
                             const unsigned char **orig, size_t *orig_len)
{
    return ec_decode_entity(bytes, len, NULL,
                            type, type_len, data, data_len, orig, orig_len);
}

int32_t ec_seam_peerid_format_alloc(uint64_t key_type, uint64_t hash_type,
                                    const unsigned char *digest, size_t digest_len,
                                    char **out)
{
    size_t need = 0;
    int32_t rc = ec_peerid_format(key_type, hash_type, digest, digest_len,
                                  NULL, 0, &need);
    if (rc != EC_OK && rc != EC_OUT_OF_SPACE) return rc;
    char *buf = (char *)malloc(need + 1); /* +1 for NUL */
    if (!buf) return EC_INTERNAL_ERROR;
    rc = ec_peerid_format(key_type, hash_type, digest, digest_len,
                          (unsigned char *)buf, need, &need);
    if (rc != EC_OK) { free(buf); return rc; }
    buf[need] = '\0';
    *out = buf;
    return EC_OK;
}

int32_t ec_seam_peerid_parse(const char *b58, size_t b58_len,
                            uint64_t *key_type, uint64_t *hash_type,
                            unsigned char *digest_out, size_t *digest_len)
{
    return ec_peerid_parse((const unsigned char *)b58, b58_len,
                           key_type, hash_type, digest_out, digest_len);
}

int32_t ec_seam_sha256(const unsigned char *data, size_t len, unsigned char out32[32])
{
    return ec_sha256(data, len, out32);
}

int32_t ec_seam_ed25519_sign(const unsigned char seed32[32],
                            const unsigned char *msg, size_t msg_len,
                            unsigned char out_sig64[64])
{
    return ec_ed25519_sign(seed32, msg, msg_len, out_sig64);
}

int32_t ec_seam_ed25519_verify(const unsigned char pub32[32],
                              const unsigned char *msg, size_t msg_len,
                              const unsigned char sig64[64])
{
    return ec_ed25519_verify(pub32, msg, msg_len, sig64);
}

int32_t ec_seam_ed25519_seed_to_pubkey(const unsigned char seed32[32],
                                       unsigned char out_pub32[32])
{
    return ec_ed25519_seed_to_pubkey(seed32, out_pub32);
}

int32_t ec_seam_envelope_verify_root_hash(const unsigned char *env, size_t len)
{
    return ec_envelope_verify_root_hash(env, len);
}

/* ── SQLite application-defined function trampolines (crypto callable FROM SQL) ─
 * Each is the thinnest bridge: pull the blob/text args, call the ec_* primitive,
 * set the blob/int result. A NULL arg or an FFI error becomes a SQL error (the
 * host's fail-closed §4.9(c) frame maps that to 500 — never a silent NULL). */

static void sqlfn_sha256(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc != 1) { sqlite3_result_error(ctx, "sha256() takes 1 arg", -1); return; }
    const unsigned char *data = (const unsigned char *)sqlite3_value_blob(argv[0]);
    int n = sqlite3_value_bytes(argv[0]);
    unsigned char out[EC_SHA256_LEN];
    if (ec_sha256(data ? data : (const unsigned char *)"", (size_t)n, out) != EC_OK) {
        sqlite3_result_error(ctx, "ec_sha256 FFI failed", -1);
        return;
    }
    sqlite3_result_blob(ctx, out, EC_SHA256_LEN, SQLITE_TRANSIENT);
}

/* content_hash(text type, blob data) → blob(33) = 0x00 ‖ SHA-256(ECF{type,data}).
 * The §5.2 grant/token integrity primitive, callable inline from the verdict
 * query. Fixed to format 0x00 (the core SHA-256 home format). */
static void sqlfn_content_hash(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc != 2) { sqlite3_result_error(ctx, "content_hash() takes 2 args", -1); return; }
    const unsigned char *type = sqlite3_value_text(argv[0]);
    int type_len = sqlite3_value_bytes(argv[0]);
    const unsigned char *data = (const unsigned char *)sqlite3_value_blob(argv[1]);
    int data_len = sqlite3_value_bytes(argv[1]);
    if (!type || !data) { sqlite3_result_error(ctx, "content_hash() NULL arg", -1); return; }
    unsigned char out[EC_CONTENT_HASH_LEN];
    if (ec_content_hash(type, (size_t)type_len, data, (size_t)data_len, out) != EC_OK) {
        sqlite3_result_error(ctx, "ec_content_hash FFI failed", -1);
        return;
    }
    sqlite3_result_blob(ctx, out, EC_CONTENT_HASH_LEN, SQLITE_TRANSIENT);
}

/* ed25519_verify(blob pub[32], blob msg, blob sig[64]) → int 1 (valid) / 0.
 * The §5.2 signature rung, called inline in the CASE ladder. A malformed key/sig
 * width returns 0 (fail-closed), not a SQL error. */
static void sqlfn_ed25519_verify(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc != 3) { sqlite3_result_error(ctx, "ed25519_verify() takes 3 args", -1); return; }
    const unsigned char *pub = (const unsigned char *)sqlite3_value_blob(argv[0]);
    int pub_len = sqlite3_value_bytes(argv[0]);
    const unsigned char *msg = (const unsigned char *)sqlite3_value_blob(argv[1]);
    int msg_len = sqlite3_value_bytes(argv[1]);
    const unsigned char *sig = (const unsigned char *)sqlite3_value_blob(argv[2]);
    int sig_len = sqlite3_value_bytes(argv[2]);
    if (!pub || pub_len != EC_ED25519_PUB_LEN || !sig || sig_len != EC_ED25519_SIG_LEN) {
        sqlite3_result_int(ctx, 0); /* fail-closed on a malformed key/sig */
        return;
    }
    int32_t rc = ec_ed25519_verify(pub, msg ? msg : (const unsigned char *)"",
                                   (size_t)msg_len, sig);
    sqlite3_result_int(ctx, rc == EC_OK ? 1 : 0);
}

/* id_match(text value, text pattern) → int 1/0. The §5.4 / §3.6 ID-SCOPE matcher, for
 * the `operations` and `peers` dimensions.
 *
 * WHY THIS IS NOT GLOB, WHICH IS WHAT THE ID DIMENSIONS USED TO USE. Section 3.6's
 * id-scope grammar admits exactly two wildcard forms -- a bare star, and a segment prefix
 * ending in slash-then-star -- and NOTHING ELSE: "an implementation on the canonicalizing
 * reading is non-conformant and MUST adopt the literal matcher". SQLite GLOB treats star
 * as a free wildcard ANYWHERE, so an operations pattern spelled star-slash-apply -- an
 * ordinary namespaced operation name, a LITERAL under the id grammar that matches only
 * itself -- GLOBs any value ending in slash-apply. That is the F50 divergence
 * (entity-core-formalization K-7): lean's differential put it at 2 of 64 include pairs and
 * 2 of 64 exclude pairs, with a 16-pair control alphabet reporting 0, which is why every
 * hand-tried example missed it.
 *
 * NOTE THE SPELLING, AND DO NOT "TIDY" IT BACK. The witness is written in WORDS because
 * star-slash-apply contains a C block-comment TERMINATOR: writing it literally ends this
 * comment mid-sentence and the compiler then reads the rest as code. That is the fifth
 * comment-delimiter format this cohort has hit (Pd records, Tcl switch bodies, Smalltalk
 * chunk strings, PHP docblocks, and now C). The fix is to spell it out -- never to hide it
 * behind an invisible character.
 *
 * ONE DEFINITION, CALLED BY NAME AT EVERY ID-SCOPE SITE. Inlining the CASE at each site
 * would be a second copy of the grammar, and a second copy drifts.
 */
static void sqlfn_id_match(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc != 2) { sqlite3_result_error(ctx, "id_match() takes 2 args", -1); return; }
    const char *value = (const char *)sqlite3_value_text(argv[0]);
    const char *pattern = (const char *)sqlite3_value_text(argv[1]);
    if (!value || !pattern) { sqlite3_result_int(ctx, 0); return; }  /* fail-closed on NULL */
    if (strcmp(pattern, "*") == 0) { sqlite3_result_int(ctx, 1); return; }   /* bare star */
    size_t pl = strlen(pattern);
    if (pl >= 2 && pattern[pl - 1] == '*' && pattern[pl - 2] == '/') {   /* segment prefix */
        sqlite3_result_int(ctx, strncmp(value, pattern, pl - 1) == 0 ? 1 : 0);
        return;
    }
    sqlite3_result_int(ctx, strcmp(value, pattern) == 0 ? 1 : 0);            /* literal */
}

/* path_match(text value, text pattern) → int 1/0. The section 5.4 PATH-SCOPE matcher,
 * for the `handlers` and `resources` dimensions: GLOB against the canonicalized pattern,
 * with section 5.4's UNMATCHABLE-SENTINEL arm FIRST and over BOTH operands.
 *
 * WHY THE GUARD IS HERE AND NOT AT THE CALL SITES. 0.8.2.22 names the class: "a sentinel
 * arm is a control-flow obligation, not a line ... the guard MUST sit on every path that
 * reaches the decision it protects." Written as a per-site `AND canon <> '/never-match'`
 * it is a rule with eight copies, and the eighth is the one that gets forgotten -- which
 * is exactly how lean's scopeSubset bypassed its own wrapper, permissively. Here there is
 * no unguarded variant to call.
 *
 * AND THE GUARD IS LOAD-BEARING IN SQL IN A WAY IT IS NOT IN THE IMPERATIVE COHORT.
 * There the sentinel is "unreachable as a canonical path by construction", so a bare GLOB
 * usually refuses it anyway. SQLite GLOB's star is NOT segment-anchored: a grant pattern
 * spelled slash-star -- already absolute, so it survives canonicalization unchanged --
 * GLOBs ANY string beginning with a slash, INCLUDING '/never-match'. Without this arm a
 * caller supplying a reserved-form path (dot-dot-slash-escape) under a slash-star grant
 * would have the sentinel MATCH and be authorized. Measured: planting the arm away leaves
 * a subtree-pattern fixture green and reddens a slash-star one.
 *
 * The witness is spelled in WORDS for the same reason star-slash-apply is above: a
 * slash-star inside a C block comment is a nested comment opener, which -Wcomment flags
 * and which a later editor will silently "tidy". Never make it invisible instead.
 */
static void sqlfn_path_match(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc != 2) { sqlite3_result_error(ctx, "path_match() takes 2 args", -1); return; }
    const char *value = (const char *)sqlite3_value_text(argv[0]);
    const char *pattern = (const char *)sqlite3_value_text(argv[1]);
    if (!value || !pattern) { sqlite3_result_int(ctx, 0); return; }  /* fail-closed on NULL */
    if (strcmp(value, "/never-match") == 0 || strcmp(pattern, "/never-match") == 0) {
        sqlite3_result_int(ctx, 0);   /* NEVER_MATCH never matches, in EITHER operand */
        return;
    }
    sqlite3_result_int(ctx, sqlite3_strglob(pattern, value) == 0 ? 1 : 0);
}

int ec_seam_register_sql_functions(sqlite3 *db)
{
    const int F = SQLITE_UTF8 | SQLITE_DETERMINISTIC;
    int rc;
    rc = sqlite3_create_function(db, "sha256", 1, F, NULL, sqlfn_sha256, NULL, NULL);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "content_hash", 2, F, NULL, sqlfn_content_hash, NULL, NULL);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "ed25519_verify", 3, F, NULL, sqlfn_ed25519_verify, NULL, NULL);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "id_match", 2, F, NULL, sqlfn_id_match, NULL, NULL);
    if (rc != SQLITE_OK) return rc;
    rc = sqlite3_create_function(db, "path_match", 2, F, NULL, sqlfn_path_match, NULL, NULL);
    return rc;
}
