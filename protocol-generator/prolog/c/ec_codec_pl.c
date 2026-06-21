/* ec_codec_pl.c — SWI-Prolog foreign-predicate shim over the entity-codec C-ABI.
 *
 * The Prolog peer (entity-core-protocol-prolog) is an FFI peer: the byte-floor
 * (canonical CBOR encode/decode, base58/peer_id, Ed25519/Ed448 sign+verify,
 * SHA-256/384) is owned by libentitycore_codec (C-ABI v1.1). Prolog owns the
 * relational core (S3). This file wraps the ec_* symbols as SWI foreign
 * predicates loadable via use_foreign_library/1 — the standard dependency-free
 * SWI FFI route (no external `ffi` pack; supply-chain conscious, A-PL-002).
 *
 * The C-ABI prototypes below are transcribed VERBATIM from the canonical contract
 *   ffi-generator/c-abi/entity-core-codec-ffi-c/include/entitycore_codec.h
 * (C-ABI v1.1) — only the symbols this shim binds are declared, so the build
 * links -lentitycore_codec WITHOUT the header on the include path. This mirrors
 * the OCaml seam (protocol-generator/ocaml/src/agility/ec_ffi_stubs.c).
 *
 * BYTES ON THE PROLOG SIDE: raw octet payloads (CBOR, digests, keys, signatures)
 * cross the boundary as SWI strings built/read with REP_ISO_LATIN_1 — a 1:1
 * byte<->code mapping (code 0..255), NUL-safe and length-carried (never strlen).
 * peer_id base58 text crosses as a UTF-8 atom/string. All shim predicates are
 * SEMIDET (true on EC_OK, false otherwise) — the deterministic-codec discipline
 * (A-PL-005) is enforced one layer up in codec.pl with once/1.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <SWI-Prolog.h>

/* ── verbatim from entitycore_codec.h (C-ABI v1.1) ───────────────────────── */
#define EC_OK                  0
#define EC_CONTENT_HASH_LEN   33
#define EC_SHA256_LEN         32
#define EC_SHA384_LEN         48
#define EC_ED25519_PUB_LEN    32
#define EC_ED25519_SIG_LEN    64
#define EC_ED448_PUB_LEN      57
#define EC_ED448_SIG_LEN     114

typedef struct ec_arena ec_arena_t;

extern int32_t ec_encode_ecf(const uint8_t *type_ptr, size_t type_len,
                             const uint8_t *data_ptr, size_t data_len,
                             uint8_t *out_ptr, size_t out_cap, size_t *out_len);
extern int32_t ec_content_hash(const uint8_t *type_ptr, size_t type_len,
                              const uint8_t *data_ptr, size_t data_len,
                              uint8_t *out_ptr /* 33 */);
extern int32_t ec_content_hash_with_format(const uint8_t *type_ptr, size_t type_len,
                                           const uint8_t *data_ptr, size_t data_len,
                                           uint64_t format_code,
                                           uint8_t *out_ptr, size_t out_cap, size_t *out_len);
extern int32_t ec_encode_bare_value(const uint8_t *in_ptr, size_t in_len,
                                    uint8_t *out_ptr, size_t out_cap, size_t *out_len);
extern int32_t ec_decode_entity(const uint8_t *bytes_ptr, size_t len, ec_arena_t *arena,
                               const uint8_t **out_type_ptr, size_t *out_type_len,
                               const uint8_t **out_data_ptr, size_t *out_data_len,
                               const uint8_t **out_orig_ptr, size_t *out_orig_len);
extern int32_t ec_hash_format_code_encode(uint64_t code,
                                          uint8_t *out_ptr, size_t out_cap, size_t *out_len);
extern int32_t ec_hash_format_code_decode(const uint8_t *in_ptr, size_t in_len,
                                          uint64_t *out_code, size_t *out_consumed);
extern int32_t ec_peerid_parse(const uint8_t *base58_ptr, size_t base58_len,
                              uint64_t *out_key_type, uint64_t *out_hash_type,
                              uint8_t *out_digest_ptr, size_t *out_digest_len);
extern int32_t ec_peerid_format(uint64_t key_type, uint64_t hash_type,
                               const uint8_t *digest_ptr, size_t digest_len,
                               uint8_t *out_ptr, size_t out_cap, size_t *out_len);
extern int32_t ec_ed25519_keygen(uint8_t *out_priv, uint8_t *out_pub);
extern int32_t ec_ed25519_sign(const uint8_t *priv_ptr,
                              const uint8_t *msg_ptr, size_t msg_len,
                              uint8_t *out_sig);
extern int32_t ec_ed25519_verify(const uint8_t *pub_ptr,
                                const uint8_t *msg_ptr, size_t msg_len,
                                const uint8_t *sig_ptr);
extern int32_t ec_ed25519_seed_to_pubkey(const uint8_t *seed_ptr /* 32 */, uint8_t *out_pub /* 32 */);
extern int32_t ec_sha256(const uint8_t *data_ptr, size_t data_len, uint8_t *out_ptr);
extern int32_t ec_sha384(const uint8_t *data_ptr, size_t data_len, uint8_t *out_ptr);
extern int32_t ec_ed448_seed_to_pubkey(const uint8_t *seed_ptr, uint8_t *out_pub);
extern int32_t ec_ed448_sign(const uint8_t *priv_ptr,
                            const uint8_t *msg_ptr, size_t msg_len,
                            uint8_t *out_sig);
extern int32_t ec_ed448_verify(const uint8_t *pub_ptr,
                              const uint8_t *msg_ptr, size_t msg_len,
                              const uint8_t *sig_ptr);
extern const char *ec_abi_version(void);
extern const char *ec_impl_info(void);

/* ── byte<->term helpers (REP_ISO_LATIN_1: 1 byte == 1 code, NUL-safe) ────── */

/* Read a Prolog byte-string term into (buf, len). Returns FALSE on type error.
 * The buffer is on the Prolog ring (BUF_STACK) — valid until the next PL call
 * that reuses it; we copy out or consume immediately. */
static int get_bytes(term_t t, char **buf, size_t *len) {
    return PL_get_nchars(t, len, buf, CVT_ATOM | CVT_STRING | CVT_LIST | BUF_STACK | REP_ISO_LATIN_1);
}

static int unify_bytes(term_t t, const uint8_t *buf, size_t len) {
    return PL_unify_string_nchars(t, len, (const char *)buf);
}

/* ── foreign predicates ───────────────────────────────────────────────────── */

/* pl_encode_ecf(+Type, +DataBytes, -Bytes) : ECF({type,data}) → canonical CBOR. */
static foreign_t pl_encode_ecf(term_t type, term_t data, term_t out) {
    char *tp, *dp; size_t tl, dl;
    if (!get_bytes(type, &tp, &tl) || !get_bytes(data, &dp, &dl)) PL_fail;
    size_t need = 0;
    /* size probe then exact alloc (honors the OUT_OF_SPACE protocol). */
    uint8_t stackbuf[512];
    int32_t rc = ec_encode_ecf((const uint8_t*)tp, tl, (const uint8_t*)dp, dl,
                               stackbuf, sizeof(stackbuf), &need);
    if (rc == EC_OK) return unify_bytes(out, stackbuf, need);
    if (rc != -2 /* EC_OUT_OF_SPACE */) PL_fail;
    uint8_t *heap = (uint8_t*)malloc(need);
    if (!heap) PL_fail;
    rc = ec_encode_ecf((const uint8_t*)tp, tl, (const uint8_t*)dp, dl, heap, need, &need);
    int ok = (rc == EC_OK) && unify_bytes(out, heap, need);
    free(heap);
    return ok ? TRUE : FALSE;
}

/* pl_encode_bare_value(+InBytes, -OutBytes) : decode one canonical ECF value and
 * re-encode through the bare canonical encoder. Identity for canonical input; the
 * Class-A encode_equal driver (decode-then-canonical-re-encode). */
static foreign_t pl_encode_bare_value(term_t in, term_t out) {
    char *ip; size_t il;
    if (!get_bytes(in, &ip, &il)) PL_fail;
    size_t need = 0;
    uint8_t stackbuf[1024];
    int32_t rc = ec_encode_bare_value((const uint8_t*)ip, il, stackbuf, sizeof(stackbuf), &need);
    if (rc == EC_OK) return unify_bytes(out, stackbuf, need);
    if (rc != -2) PL_fail;
    uint8_t *heap = (uint8_t*)malloc(need);
    if (!heap) PL_fail;
    rc = ec_encode_bare_value((const uint8_t*)ip, il, heap, need, &need);
    int ok = (rc == EC_OK) && unify_bytes(out, heap, need);
    free(heap);
    return ok ? TRUE : FALSE;
}

/* pl_decode_entity(+Bytes) : SEMIDET — true iff Bytes decode as a valid entity
 * (runs the §3.2 tag scanner; tag-6 in a data region → fail). Used by the
 * decode_reject vectors (reject ⇒ this fails). */
static foreign_t pl_decode_entity(term_t bytes) {
    char *bp; size_t bl;
    if (!get_bytes(bytes, &bp, &bl)) PL_fail;
    ec_arena_t *arena = NULL;
    /* ec_arena_new is part of the ABI; declare+call lazily to avoid an extern. */
    extern ec_arena_t *ec_arena_new(void);
    extern void ec_arena_free(ec_arena_t *);
    arena = ec_arena_new();
    if (!arena) PL_fail;
    const uint8_t *tp, *dp, *op; size_t tl, dl, ol;
    int32_t rc = ec_decode_entity((const uint8_t*)bp, bl, arena, &tp, &tl, &dp, &dl, &op, &ol);
    ec_arena_free(arena);
    return (rc == EC_OK) ? TRUE : FALSE;
}

/* pl_content_hash(+Type, +DataBytes, -Hash33) : varint(0x00) ‖ SHA-256(ECF). */
static foreign_t pl_content_hash(term_t type, term_t data, term_t out) {
    char *tp, *dp; size_t tl, dl;
    if (!get_bytes(type, &tp, &tl) || !get_bytes(data, &dp, &dl)) PL_fail;
    uint8_t h[EC_CONTENT_HASH_LEN];
    int32_t rc = ec_content_hash((const uint8_t*)tp, tl, (const uint8_t*)dp, dl, h);
    if (rc != EC_OK) PL_fail;
    return unify_bytes(out, h, EC_CONTENT_HASH_LEN);
}

/* pl_content_hash_with_format(+Type, +DataBytes, +FormatCode, -Hash) :
 * varint(format_code) ‖ DIGEST_format(ECF). 0x00→SHA-256(33B), 0x01→SHA-384(49B).
 * Unsupported format codes → fail (the public ABI rejects them — A-PL-011). */
static foreign_t pl_content_hash_with_format(term_t type, term_t data, term_t fc, term_t out) {
    char *tp, *dp; size_t tl, dl;
    int64_t code;
    if (!get_bytes(type, &tp, &tl) || !get_bytes(data, &dp, &dl)) PL_fail;
    if (!PL_get_int64(fc, &code)) PL_fail;
    uint8_t buf[64]; size_t need = 0;
    int32_t rc = ec_content_hash_with_format((const uint8_t*)tp, tl, (const uint8_t*)dp, dl,
                                             (uint64_t)code, buf, sizeof(buf), &need);
    if (rc != EC_OK) PL_fail;
    return unify_bytes(out, buf, need);
}

/* pl_hash_format_code_encode(+Code, -Bytes) : LEB128 of the format code. */
static foreign_t pl_hash_format_code_encode(term_t code, term_t out) {
    int64_t c;
    if (!PL_get_int64(code, &c)) PL_fail;
    uint8_t buf[16]; size_t need = 0;
    int32_t rc = ec_hash_format_code_encode((uint64_t)c, buf, sizeof(buf), &need);
    if (rc != EC_OK) PL_fail;
    return unify_bytes(out, buf, need);
}

/* pl_peerid_format(+KeyType, +HashType, +DigestBytes, -Base58Text). */
static foreign_t pl_peerid_format(term_t kt, term_t ht, term_t digest, term_t out) {
    int64_t k, h; char *dp; size_t dl;
    if (!PL_get_int64(kt, &k) || !PL_get_int64(ht, &h) || !get_bytes(digest, &dp, &dl)) PL_fail;
    uint8_t buf[256]; size_t need = 0;
    int32_t rc = ec_peerid_format((uint64_t)k, (uint64_t)h, (const uint8_t*)dp, dl,
                                  buf, sizeof(buf), &need);
    if (rc == -2) { /* grow */
        uint8_t *heap = (uint8_t*)malloc(need);
        if (!heap) PL_fail;
        rc = ec_peerid_format((uint64_t)k, (uint64_t)h, (const uint8_t*)dp, dl, heap, need, &need);
        int ok = (rc == EC_OK) && PL_unify_string_nchars(out, need, (const char*)heap);
        free(heap);
        return ok ? TRUE : FALSE;
    }
    if (rc != EC_OK) PL_fail;
    return PL_unify_string_nchars(out, need, (const char*)buf);
}

/* pl_peerid_parse(+Base58Text, -KeyType, -HashType, -DigestBytes). */
static foreign_t pl_peerid_parse(term_t in, term_t kt, term_t ht, term_t digest) {
    char *bp; size_t bl;
    if (!get_bytes(in, &bp, &bl)) PL_fail;
    uint64_t k, h; uint8_t dbuf[256]; size_t dl = 0;
    int32_t rc = ec_peerid_parse((const uint8_t*)bp, bl, &k, &h, dbuf, &dl);
    if (rc != EC_OK) PL_fail;
    return PL_unify_int64(kt, (int64_t)k)
        && PL_unify_int64(ht, (int64_t)h)
        && unify_bytes(digest, dbuf, dl);
}

/* pl_ed25519_keygen(-PrivBytes32, -PubBytes32). */
static foreign_t pl_ed25519_keygen(term_t priv, term_t pub) {
    uint8_t sk[32], pk[32];
    if (ec_ed25519_keygen(sk, pk) != EC_OK) PL_fail;
    return unify_bytes(priv, sk, 32) && unify_bytes(pub, pk, 32);
}

/* pl_ed25519_sign(+SeedBytes32, +MsgBytes, -SigBytes64). */
static foreign_t pl_ed25519_sign(term_t seed, term_t msg, term_t out) {
    char *sp, *mp; size_t sl, ml;
    if (!get_bytes(seed, &sp, &sl) || !get_bytes(msg, &mp, &ml)) PL_fail;
    if (sl != 32) PL_fail;
    uint8_t sig[EC_ED25519_SIG_LEN];
    if (ec_ed25519_sign((const uint8_t*)sp, (const uint8_t*)mp, ml, sig) != EC_OK) PL_fail;
    return unify_bytes(out, sig, EC_ED25519_SIG_LEN);
}

/* pl_ed25519_verify(+PubBytes32, +MsgBytes, +SigBytes64) : SEMIDET. */
static foreign_t pl_ed25519_verify(term_t pub, term_t msg, term_t sig) {
    char *pp, *mp, *gp; size_t pl, ml, gl;
    if (!get_bytes(pub, &pp, &pl) || !get_bytes(msg, &mp, &ml) || !get_bytes(sig, &gp, &gl)) PL_fail;
    if (pl != 32 || gl != 64) PL_fail;
    return (ec_ed25519_verify((const uint8_t*)pp, (const uint8_t*)mp, ml,
                              (const uint8_t*)gp) == EC_OK) ? TRUE : FALSE;
}

/* pl_ed25519_seed_to_pubkey(+SeedBytes32, -PubBytes32). */
static foreign_t pl_ed25519_seed_to_pubkey(term_t seed, term_t out) {
    char *sp; size_t sl;
    if (!get_bytes(seed, &sp, &sl) || sl != 32) PL_fail;
    uint8_t pub[EC_ED25519_PUB_LEN];
    if (ec_ed25519_seed_to_pubkey((const uint8_t*)sp, pub) != EC_OK) PL_fail;
    return unify_bytes(out, pub, EC_ED25519_PUB_LEN);
}

/* pl_sha256(+DataBytes, -Digest32) / pl_sha384(+DataBytes, -Digest48). */
static foreign_t pl_sha256(term_t data, term_t out) {
    char *dp; size_t dl;
    if (!get_bytes(data, &dp, &dl)) PL_fail;
    uint8_t h[EC_SHA256_LEN];
    if (ec_sha256((const uint8_t*)dp, dl, h) != EC_OK) PL_fail;
    return unify_bytes(out, h, EC_SHA256_LEN);
}
static foreign_t pl_sha384(term_t data, term_t out) {
    char *dp; size_t dl;
    if (!get_bytes(data, &dp, &dl)) PL_fail;
    uint8_t h[EC_SHA384_LEN];
    if (ec_sha384((const uint8_t*)dp, dl, h) != EC_OK) PL_fail;
    return unify_bytes(out, h, EC_SHA384_LEN);
}

/* pl_ed448_seed_to_pubkey(+SeedBytes57, -PubBytes57). */
static foreign_t pl_ed448_seed_to_pubkey(term_t seed, term_t out) {
    char *sp; size_t sl;
    if (!get_bytes(seed, &sp, &sl) || sl != 57) PL_fail;
    uint8_t pub[EC_ED448_PUB_LEN];
    if (ec_ed448_seed_to_pubkey((const uint8_t*)sp, pub) != EC_OK) PL_fail;
    return unify_bytes(out, pub, EC_ED448_PUB_LEN);
}
/* pl_ed448_sign(+SeedBytes57, +MsgBytes, -SigBytes114). */
static foreign_t pl_ed448_sign(term_t seed, term_t msg, term_t out) {
    char *sp, *mp; size_t sl, ml;
    if (!get_bytes(seed, &sp, &sl) || !get_bytes(msg, &mp, &ml) || sl != 57) PL_fail;
    uint8_t sig[EC_ED448_SIG_LEN];
    if (ec_ed448_sign((const uint8_t*)sp, (const uint8_t*)mp, ml, sig) != EC_OK) PL_fail;
    return unify_bytes(out, sig, EC_ED448_SIG_LEN);
}
/* pl_ed448_verify(+PubBytes57, +MsgBytes, +SigBytes114) : SEMIDET. */
static foreign_t pl_ed448_verify(term_t pub, term_t msg, term_t sig) {
    char *pp, *mp, *gp; size_t pl, ml, gl;
    if (!get_bytes(pub, &pp, &pl) || !get_bytes(msg, &mp, &ml) || !get_bytes(sig, &gp, &gl)) PL_fail;
    if (pl != 57 || gl != 114) PL_fail;
    return (ec_ed448_verify((const uint8_t*)pp, (const uint8_t*)mp, ml,
                            (const uint8_t*)gp) == EC_OK) ? TRUE : FALSE;
}

/* pl_abi_version(-Atom) / pl_impl_info(-Atom). */
static foreign_t pl_abi_version(term_t out) {
    return PL_unify_atom_chars(out, ec_abi_version());
}
static foreign_t pl_impl_info(term_t out) {
    return PL_unify_atom_chars(out, ec_impl_info());
}

/* ── registration (called by SWI on use_foreign_library/1) ────────────────────
 * Flag 0 = deterministic foreign (SWI's default; only PL_FA_NONDETERMINISTIC
 * makes a foreign predicate retry — there is no separate "deterministic" flag).
 * Each predicate here succeeds at most once (det/semidet) and NEVER offers an
 * alternative solution — the wire is a function (A-PL-005). findall/3 over any of
 * these yields exactly one solution; the once/1 wrappers in ec_codec.pl are the
 * explicit no-choice-point guard at the public surface. (Note: deterministic/1
 * immediately after a foreign call inside an (If->Then) can still report `false`
 * — a known SWI reporting artifact of foreign-call frame teardown, not a real
 * leaked choice point; the single-solution findall is the authoritative check.) */
install_t install_ec_codec_pl(void) {
    PL_register_foreign("pl_encode_ecf",               3, pl_encode_ecf,               0);
    PL_register_foreign("pl_encode_bare_value",        2, pl_encode_bare_value,        0);
    PL_register_foreign("pl_decode_entity",            1, pl_decode_entity,            0);
    PL_register_foreign("pl_content_hash",             3, pl_content_hash,             0);
    PL_register_foreign("pl_content_hash_with_format", 4, pl_content_hash_with_format, 0);
    PL_register_foreign("pl_hash_format_code_encode",  2, pl_hash_format_code_encode,  0);
    PL_register_foreign("pl_peerid_format",            4, pl_peerid_format,            0);
    PL_register_foreign("pl_peerid_parse",             4, pl_peerid_parse,             0);
    PL_register_foreign("pl_ed25519_keygen",           2, pl_ed25519_keygen,           0);
    PL_register_foreign("pl_ed25519_sign",             3, pl_ed25519_sign,             0);
    PL_register_foreign("pl_ed25519_verify",           3, pl_ed25519_verify,           0);
    PL_register_foreign("pl_ed25519_seed_to_pubkey",   2, pl_ed25519_seed_to_pubkey,   0);
    PL_register_foreign("pl_sha256",                   2, pl_sha256,                   0);
    PL_register_foreign("pl_sha384",                   2, pl_sha384,                   0);
    PL_register_foreign("pl_ed448_seed_to_pubkey",     2, pl_ed448_seed_to_pubkey,     0);
    PL_register_foreign("pl_ed448_sign",               3, pl_ed448_sign,               0);
    PL_register_foreign("pl_ed448_verify",             3, pl_ed448_verify,             0);
    PL_register_foreign("pl_abi_version",              1, pl_abi_version,              0);
    PL_register_foreign("pl_impl_info",                1, pl_impl_info,                0);
}
