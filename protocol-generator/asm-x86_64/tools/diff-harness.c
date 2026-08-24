/* diff-harness.c — L2 codec differential driver (compiled in-container, no python).
 *
 * Feeds each pinned ECF conformance vector's GOLDEN canonical bytes through our
 * hand-written x86-64 asm `ec_encode_bare_value` (the F6 Class-A encoder hook) and
 * checks the result against ground truth:
 *   - encode_equal : bare_value(golden) MUST return EC_OK and reproduce golden byte-
 *                    for-byte. Since the encoder re-derives canonical form (shortest
 *                    int, shortest-float ladder, length-then-lex key sort) from the
 *                    DECODED value, an identity result proves the canonical logic —
 *                    a wrong ladder/sort choice diverges from golden and is caught.
 *   - decode_reject: bare_value(golden) MUST fail with EC_DECODE_ERROR (the recursive
 *                    major-type-6 tag scanner / self-describe reject).
 *
 * The golden bytes are the 3-way-locked corpus (Go x Rust x Python), so this is a
 * real differential, not a self-consistency check. Milestone 1 runs the crypto-free
 * Class-A categories; peer_id/content_hash/signature (Class B) join at M2.
 *
 * Usage: diff-harness [category]     (no arg = all M1 categories)
 * Exit: 0 iff every selected vector PASSes.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "corpus_vectors.h"

#define EC_OK             0
#define EC_OUT_OF_SPACE  -2
#define EC_DECODE_ERROR  -3

extern int32_t ec_encode_bare_value(const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t out_cap, size_t *out_len);
/* Class-B (native codec + FFI crypto). content_hash = varint(fmt) || SHA-256(ECF). */
extern int32_t ec_content_hash(const uint8_t *type, size_t tlen,
                               const uint8_t *data, size_t dlen, uint8_t *out /*33*/);
extern int32_t ec_content_hash_with_format(const uint8_t *type, size_t tlen,
                                           const uint8_t *data, size_t dlen, uint64_t fmt,
                                           uint8_t *out, size_t cap, size_t *out_len);
extern int32_t ec_peerid_format(uint64_t kt, uint64_t ht, const uint8_t *digest, size_t dlen,
                                uint8_t *out, size_t cap, size_t *out_len);
/* signature = ed25519_sign(seed, content_hash) — the full 33 hash bytes (ENTITY-CORE
 * §7.3 "Sign full hash bytes: format code + digest"). content_hash is our NATIVE
 * ECF+sha256; the sign itself stays FFI at L2. ec_ed25519_sign: seed IS the 32-byte priv. */
extern int32_t ec_ed25519_sign(const uint8_t *priv /*32*/, const uint8_t *msg, size_t msg_len,
                               uint8_t *out_sig /*64*/);
extern int32_t ec_ed25519_verify(const uint8_t *pub /*32*/, const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig /*64*/);
extern int32_t ec_ed25519_seed_to_pubkey(const uint8_t *seed /*32*/, uint8_t *out_pub /*32*/);
extern int32_t ec_encode_ecf(const uint8_t *type, size_t tlen, const uint8_t *data, size_t dlen,
                             uint8_t *out, size_t cap, size_t *out_len);

static const corpus_vec_t *find_vec(const char *id) {
    for (size_t i = 0; i < CORPUS_VECTOR_COUNT; i++)
        if (strcmp(CORPUS_VECTORS[i].id, id) == 0) return &CORPUS_VECTORS[i];
    return 0;
}

/* Milestone-1 categories: pure canonical CBOR, no crypto. */
static int is_m1(const char *cat) {
    static const char *M1[] = { "float","int","map_keys","length",
                                "primitive","nested","envelope","tag_reject", 0 };
    for (int i = 0; M1[i]; i++) if (strcmp(cat, M1[i]) == 0) return 1;
    return 0;
}

static void hexdump(const char *label, const uint8_t *p, size_t n) {
    fprintf(stderr, "    %s (%zu):", label, n);
    for (size_t i = 0; i < n; i++) fprintf(stderr, " %02x", p[i]);
    fprintf(stderr, "\n");
}

/* Synthetic canonicalization vectors: UNSORTED-map input → SORTED canonical
 * output. The pinned corpus can't cover the key-sort (its map_keys inputs are
 * pre-sorted, so identity-on-canonical passes vacuously — A-ASM-015). These feed
 * deliberately mis-ordered maps through ec_encode_bare_value and require the
 * length-then-lex canonical result — a real test of the transcoder's sort. */
typedef struct { const char *id; const char *in; size_t inlen; const char *out; size_t outlen; } synth_vec_t;
static const synth_vec_t SYNTH[] = {
    /* {"z":1,"a":2} → {"a":2,"z":1} (same length, lex a<z) */
    { "sort.lex",    "\xa2\x61\x7a\x01\x61\x61\x02", 7, "\xa2\x61\x61\x02\x61\x7a\x01", 7 },
    /* {"aa":1,"z":2} → {"z":2,"aa":1} (length first: 'z' len2 before 'aa' len3) */
    { "sort.length", "\xa2\x62\x61\x61\x01\x61\x7a\x02", 8, "\xa2\x61\x7a\x02\x62\x61\x61\x01", 8 },
    /* {"b":{"y":1,"x":2}} → inner sorted {"x":2,"y":1} (nested sort) */
    { "sort.nested", "\xa1\x61\x62\xa2\x61\x79\x01\x61\x78\x02", 10, "\xa1\x61\x62\xa2\x61\x78\x02\x61\x79\x01", 10 },
    /* 3 keys reverse order {"c":1,"b":2,"a":3} → {"a":3,"b":2,"c":1} */
    { "sort.three",  "\xa3\x61\x63\x01\x61\x62\x02\x61\x61\x03", 10, "\xa3\x61\x61\x03\x61\x62\x02\x61\x63\x01", 10 },
};
#define SYNTH_COUNT (sizeof(SYNTH)/sizeof(SYNTH[0]))

static int run_synth(void) {
    uint8_t out[256]; size_t outlen; int pass = 0, fail = 0;
    for (size_t i = 0; i < SYNTH_COUNT; i++) {
        const synth_vec_t *v = &SYNTH[i];
        outlen = 0;
        int32_t rc = ec_encode_bare_value((const uint8_t*)v->in, v->inlen, out, sizeof(out), &outlen);
        int ok = (rc == EC_OK && outlen == v->outlen && memcmp(out, v->out, v->outlen) == 0);
        if (ok) { pass++; printf("PASS %s\n", v->id); }
        else {
            fail++;
            fprintf(stderr, "FAIL %-14s rc=%d\n", v->id, rc);
            hexdump("want", (const uint8_t*)v->out, v->outlen);
            if (rc == EC_OK) hexdump("got ", out, outlen);
        }
    }
    printf("== synthetic sort: %d PASS, %d FAIL ==\n", pass, fail);
    return fail;
}

/* content_hash Class-B: native ECF encode (WITH key-sort) + FFI SHA-256. The data
 * maps are fed in the .diag's abstract order — content_hash.3 is UNSORTED, so a
 * match proves the key-sort in the REAL ECF encoder (not just bare_value). Golden
 * hashes come from the pinned corpus (looked up by id). */
static int run_content_hash(void) {
    uint8_t out[64]; size_t outlen; int pass = 0, fail = 0;
    struct { const char *id; const char *type; const uint8_t *data; size_t dlen; int fmt; } T[] = {
        { "content_hash.1", "system/empty", (const uint8_t*)"\xa0", 1, 0 },
        { "content_hash.2", "test/v1", (const uint8_t*)"\xa1\x65\x76\x61\x6c\x75\x65\x18\x2a", 9, 0 },
        /* UNSORTED {"z":1,"a":2,"bb":3,"aaa":4} → encoder must canonical-sort */
        { "content_hash.3", "test/v1", (const uint8_t*)"\xa4\x61\x7a\x01\x61\x61\x02\x62\x62\x62\x03\x63\x61\x61\x61\x04", 16, 0 },
        { "content_hash.4", "test/v1", (const uint8_t*)"\xa1\x61\x78\x01", 4, 128 },
    };
    for (size_t i = 0; i < sizeof(T)/sizeof(T[0]); i++) {
        const corpus_vec_t *g = find_vec(T[i].id);
        if (!g) { fprintf(stderr, "FAIL %-14s (golden not found)\n", T[i].id); fail++; continue; }
        int32_t rc; outlen = 0;
        if (T[i].fmt == 0) {
            rc = ec_content_hash((const uint8_t*)T[i].type, strlen(T[i].type), T[i].data, T[i].dlen, out);
            outlen = 33;
        } else {
            rc = ec_content_hash_with_format((const uint8_t*)T[i].type, strlen(T[i].type),
                                             T[i].data, T[i].dlen, (uint64_t)T[i].fmt, out, sizeof(out), &outlen);
        }
        int ok = (rc == EC_OK && outlen == g->len && memcmp(out, g->bytes, g->len) == 0);
        if (ok) { pass++; printf("PASS %s\n", T[i].id); }
        else {
            fail++; fprintf(stderr, "FAIL %-14s rc=%d\n", T[i].id, rc);
            hexdump("want", g->bytes, g->len);
            if (rc == EC_OK) hexdump("got ", out, outlen);
        }
    }
    printf("== content_hash (native ECF + FFI sha256): %d PASS, %d FAIL ==\n", pass, fail);
    return fail;
}

/* peer_id Class-B: native base58 + LEB128 varint (no crypto). The corpus golden is
 * the CBOR text-string wrapping the base58 (0x78, len, ascii...), so the expected
 * ASCII is golden[2..]. digests: .1 = 32 zero bytes; .2/.3 = 0x00..0x1f. */
static int run_peerid(void) {
    uint8_t out[128]; size_t outlen; int pass = 0, fail = 0;
    uint8_t d_zero[32] = {0};
    uint8_t d_seq[32]; for (int i = 0; i < 32; i++) d_seq[i] = (uint8_t)i;
    struct { const char *id; uint64_t kt, ht; const uint8_t *dg; } T[] = {
        { "peer_id.1", 1, 1, d_zero },
        { "peer_id.2", 1, 1, d_seq  },
        { "peer_id.3", 128, 1, d_seq },
    };
    for (size_t i = 0; i < sizeof(T)/sizeof(T[0]); i++) {
        const corpus_vec_t *g = find_vec(T[i].id);
        if (!g) { fprintf(stderr, "FAIL %-14s (golden not found)\n", T[i].id); fail++; continue; }
        const uint8_t *exp = g->bytes + 2; size_t explen = g->len - 2;  /* strip 0x78,len */
        outlen = 0;
        int32_t rc = ec_peerid_format(T[i].kt, T[i].ht, T[i].dg, 32, out, sizeof(out), &outlen);
        int ok = (rc == EC_OK && outlen == explen && memcmp(out, exp, explen) == 0);
        if (ok) { pass++; printf("PASS %s\n", T[i].id); }
        else {
            fail++; fprintf(stderr, "FAIL %-14s rc=%d\n", T[i].id, rc);
            hexdump("want", exp, explen);
            if (rc == EC_OK) hexdump("got ", out, outlen);
        }
    }
    printf("== peer_id (native base58): %d PASS, %d FAIL ==\n", pass, fail);
    return fail;
}

/* signature Class-B: native content_hash (ECF+sha256, WITH key-sort) fed to FFI
 * ed25519 sign. signature.2's data is unsorted — a golden match proves the native
 * canonical encoding reaches the signature correctly. Seeds/data hand-authored from
 * the .diag; golden 64-byte sigs from the pinned corpus. */
static int run_signature(void) {
    uint8_t ch[33], sig[64]; int pass = 0, fail = 0;
    uint8_t s_zero[32] = {0}, s_ff[32], s_seq[32];
    for (int i = 0; i < 32; i++) { s_ff[i] = 0xff; s_seq[i] = (uint8_t)i; }
    struct { const char *id; const uint8_t *seed; const char *type; const uint8_t *data; size_t dlen; } T[] = {
        { "signature.1", s_zero, "test/v1", (const uint8_t*)"\xa1\x61\x78\x01", 4 },
        /* unsorted {"z":1,"a":2} — sort must reach the hashed ECF */
        { "signature.2", s_ff,   "test/v1", (const uint8_t*)"\xa2\x61\x7a\x01\x61\x61\x02", 7 },
        { "signature.3", s_seq,  "test/v1", (const uint8_t*)"\xa1\x65\x6f\x75\x74\x65\x72\xa1\x65\x69\x6e\x6e\x65\x72\x01", 15 },
    };
    for (size_t i = 0; i < sizeof(T)/sizeof(T[0]); i++) {
        const corpus_vec_t *g = find_vec(T[i].id);
        if (!g) { fprintf(stderr, "FAIL %-14s (golden not found)\n", T[i].id); fail++; continue; }
        /* sign the NATIVE canonical ECF of the entity (ENTITY-CBOR corpus convention:
         * "sign the entity" = sign its canonical ECF bytes; sort must reach the ECF —
         * signature.2's data is unsorted). ec_encode_ecf here is OUR asm (linked first). */
        uint8_t ecf[256]; size_t ecflen = 0;
        int32_t rc = ec_encode_ecf((const uint8_t*)T[i].type, strlen(T[i].type), T[i].data, T[i].dlen,
                                   ecf, sizeof(ecf), &ecflen);
        if (rc == EC_OK) rc = ec_ed25519_sign(T[i].seed, ecf, ecflen, sig);
        int ok = (rc == EC_OK && g->len == 64 && memcmp(sig, g->bytes, 64) == 0);
        if (ok) { pass++; printf("PASS %s\n", T[i].id); }
        else {
            fail++; fprintf(stderr, "FAIL %-14s rc=%d ecflen=%zu\n", T[i].id, rc, ecflen);
            hexdump("want", g->bytes, g->len);
            if (rc == EC_OK) hexdump("got ", sig, 64);
        }
    }
    printf("== signature (native content_hash + FFI ed25519): %d PASS, %d FAIL ==\n", pass, fail);
    return fail;
}

int main(int argc, char **argv) {
    const char *only = (argc > 1) ? argv[1] : 0;
    uint8_t out[8192];
    size_t outlen;
    int pass = 0, fail = 0, skip = 0;

    if (only && strcmp(only, "synth") == 0) return run_synth() ? 1 : 0;
    if (only && strcmp(only, "content_hash") == 0) return run_content_hash() ? 1 : 0;
    if (only && strcmp(only, "peer_id") == 0) return run_peerid() ? 1 : 0;
    if (only && strcmp(only, "signature") == 0) return run_signature() ? 1 : 0;

    for (size_t i = 0; i < CORPUS_VECTOR_COUNT; i++) {
        const corpus_vec_t *v = &CORPUS_VECTORS[i];
        if (only) { if (strcmp(v->cat, only) != 0) continue; }
        else if (!is_m1(v->cat)) { skip++; continue; }

        outlen = 0;
        int32_t rc = ec_encode_bare_value(v->bytes, v->len, out, sizeof(out), &outlen);

        int ok;
        if (v->reject) {
            ok = (rc == EC_DECODE_ERROR);
            if (!ok) fprintf(stderr, "FAIL %-14s expected EC_DECODE_ERROR, got rc=%d\n", v->id, rc);
        } else {
            ok = (rc == EC_OK && outlen == v->len && memcmp(out, v->bytes, v->len) == 0);
            if (!ok) {
                fprintf(stderr, "FAIL %-14s rc=%d\n", v->id, rc);
                hexdump("want", v->bytes, v->len);
                if (rc == EC_OK) hexdump("got ", out, outlen);
            }
        }
        if (ok) { pass++; printf("PASS %s\n", v->id); }
        else fail++;
    }
    printf("\n== differential: %d PASS, %d FAIL, %d skipped (non-M1) ==\n", pass, fail, skip);
    if (!only) {
        printf("\n-- synthetic key-sort (input unsorted → canonical) --\n"); fail += run_synth();
        printf("\n-- content_hash (Class-B: native ECF + FFI sha256) --\n"); fail += run_content_hash();
        printf("\n-- peer_id (Class-B: native base58) --\n"); fail += run_peerid();
        printf("\n-- signature (Class-B: native content_hash + FFI ed25519) --\n"); fail += run_signature();
    }
    return fail ? 1 : 0;
}
