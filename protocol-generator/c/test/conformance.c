/*
 * conformance.c — ECF wire-conformance harness (the codec gate) + uncovered-range
 * self-tests + Ed25519 RFC-8032 KAT. Hand-rolled assert/count driver (no test
 * framework), built + run under ASan/LSan/UBSan so a memory bug is a test failure.
 *
 * The normative fixture conformance-vectors-v1.cbor is itself a canonical-ECF
 * array of vector maps, each carrying its own cross-blessed `canonical` bytes (the
 * Go wire-conformance oracle's build-fixture/emit-canonical output, 3-way Go ×
 * Rust × Python byte-locked, arch commit 23db2546). The harness decodes the
 * fixture with THIS peer's OWN decoder (a decoder bug is itself a conformance
 * failure per ENTITY-CBOR-ENCODING.md §E.3), runs each vector through the codec,
 * and byte-compares against the embedded `canonical`. Byte-identity == oracle PASS.
 *
 * Dispatch by `kind` + `id` category prefix:
 *   decode_reject -> the decoder MUST reject the `canonical` wire bytes
 *   encode_equal, category:
 *     content_hash -> varint(format_code) || SHA-256(ECF({type,data}))
 *     peer_id      -> CBOR-text(Base58(varint(kt)||varint(ht)||digest))
 *     signature    -> Ed25519_sign(seed, ECF({type,data}))
 *     else         -> plain ECF encode(input)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "entity_core/protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

static char *to_hex(const uint8_t *p, size_t n)
{
    static const char H[] = "0123456789abcdef";
    char *s = malloc(n * 2 + 1);
    if (!s) return NULL;
    for (size_t i = 0; i < n; i++) {
        s[2 * i] = H[p[i] >> 4];
        s[2 * i + 1] = H[p[i] & 0xf];
    }
    s[n * 2] = 0;
    return s;
}

/* Read a whole file into a malloc'd buffer. */
static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = 0;
    *out_len = (size_t)sz;
    return buf;
}

/* Extract a text field's C-string from a decoded vector map (borrow). */
static const char *vec_text(const ec_value *m, const char *key)
{
    ec_value *v = ec_map_get(m, key);
    if (v && v->kind == EC_TEXT) {
        return (const char *)v->as.bytes.p;
    }
    return NULL;
}

/* Extract a bytes field (borrow). */
static const ec_value *vec_field(const ec_value *m, const char *key)
{
    return ec_map_get(m, key);
}

/* Read a small non-negative integer field. */
static int vec_int(const ec_value *m, const char *key, uint64_t *out)
{
    ec_value *v = ec_map_get(m, key);
    if (v && v->kind == EC_INT && !v->as.i.negative) {
        *out = v->as.i.u;
        return 1;
    }
    return 0;
}

static const char *id_category(const char *id, char *buf, size_t buflen)
{
    const char *dot = strchr(id, '.');
    size_t n = dot ? (size_t)(dot - id) : strlen(id);
    if (n >= buflen) n = buflen - 1;
    memcpy(buf, id, n);
    buf[n] = 0;
    return buf;
}

/*
 * Produce the canonical output for an `encode_equal` vector. Returns EC_OK and a
 * malloc'd buffer in *out / *out_len, or an error status.
 */
static ec_status produce(const char *id, const ec_value *input,
                         uint8_t **out, size_t *out_len)
{
    char cat[32];
    id_category(id, cat, sizeof(cat));

    if (strcmp(cat, "content_hash") == 0) {
        const ec_value *type = vec_field(input, "type");
        const ec_value *data = vec_field(input, "data");
        uint64_t fc = 0;
        vec_int(input, "format_code", &fc); /* default 0 */
        return ec_content_hash(type, data, fc, out, out_len);
    }
    if (strcmp(cat, "peer_id") == 0) {
        uint64_t kt = 0, ht = 0;
        if (!vec_int(input, "key_type", &kt) || !vec_int(input, "hash_type", &ht)) {
            return EC_ERR_BAD_INPUT;
        }
        const ec_value *digv = vec_field(input, "digest");
        if (!digv || digv->kind != EC_BYTES) {
            return EC_ERR_BAD_INPUT;
        }
        char *pid = NULL;
        ec_status st = ec_peer_id_format(kt, ht, digv->as.bytes.p, digv->as.bytes.len, &pid);
        if (st != EC_OK) {
            return st;
        }
        /* canonical = the peer_id string encoded as a CBOR text string */
        ec_value *t = ec_text(pid);
        free(pid);
        if (!t) {
            return EC_ERR_OOM;
        }
        st = ec_ecf_encode(t, out, out_len);
        ec_value_free(t);
        return st;
    }
    if (strcmp(cat, "signature") == 0) {
        const ec_value *seedv = vec_field(input, "seed");
        const ec_value *entity = vec_field(input, "entity");
        if (!seedv || seedv->kind != EC_BYTES || !entity || entity->kind != EC_MAP) {
            return EC_ERR_BAD_INPUT;
        }
        const ec_value *type = vec_field(entity, "type");
        const ec_value *data = vec_field(entity, "data");
        if (!type || !data) {
            return EC_ERR_BAD_INPUT;
        }
        uint8_t sig[EC_ED25519_SIG_LEN];
        ec_status st = ec_sign_entity(seedv->as.bytes.p, seedv->as.bytes.len,
                                      type, data, sig);
        if (st != EC_OK) {
            return st;
        }
        uint8_t *buf = malloc(EC_ED25519_SIG_LEN);
        if (!buf) {
            return EC_ERR_OOM;
        }
        memcpy(buf, sig, EC_ED25519_SIG_LEN);
        *out = buf;
        *out_len = EC_ED25519_SIG_LEN;
        return EC_OK;
    }
    /* default: plain ECF encode of the input */
    return ec_ecf_encode(input, out, out_len);
}

static void record_pass(void) { g_pass++; }

static void record_fail(const char *id, const char *detail)
{
    g_fail++;
    printf("FAIL %s: %s\n", id ? id : "(no id)", detail ? detail : "");
}

static int run_corpus(const char *path)
{
    size_t flen = 0;
    uint8_t *fbuf = read_file(path, &flen);
    if (!fbuf) {
        printf("FATAL: cannot read fixture %s\n", path);
        return 1;
    }

    ec_value *top = NULL;
    ec_status st = ec_ecf_decode(fbuf, flen, &top);
    free(fbuf);
    if (st != EC_OK) {
        printf("FATAL: fixture decode failed: status %d\n", st);
        return 1;
    }
    if (top->kind != EC_ARRAY) {
        printf("FATAL: fixture top-level is not an array\n");
        ec_value_free(top);
        return 1;
    }

    int total = 0;
    for (size_t vi = 0; vi < top->as.arr.len; vi++) {
        ec_value *m = top->as.arr.items[vi];
        if (m->kind != EC_MAP) {
            continue; /* meta / non-vector */
        }
        const char *kind = vec_text(m, "kind");
        if (!kind) {
            continue; /* meta entry without a kind -> not counted */
        }
        const char *id = vec_text(m, "id");
        const ec_value *canon = vec_field(m, "canonical");
        if (!canon || canon->kind != EC_BYTES) {
            record_fail(id, "missing/invalid canonical bytes");
            total++;
            continue;
        }

        if (strcmp(kind, "decode_reject") == 0) {
            total++;
            ec_value *dummy = NULL;
            ec_status d = ec_ecf_decode(canon->as.bytes.p, canon->as.bytes.len, &dummy);
            if (d == EC_OK) {
                ec_value_free(dummy);
                record_fail(id, "decoder ACCEPTED a reject vector");
            } else {
                record_pass();
            }
            continue;
        }
        if (strcmp(kind, "encode_equal") == 0) {
            total++;
            const ec_value *input = vec_field(m, "input");
            uint8_t *got = NULL;
            size_t got_len = 0;
            ec_status p = produce(id, input, &got, &got_len);
            if (p != EC_OK) {
                char buf[64];
                snprintf(buf, sizeof(buf), "produce failed: status %d", p);
                record_fail(id, buf);
                continue;
            }
            if (got_len == canon->as.bytes.len &&
                memcmp(got, canon->as.bytes.p, got_len) == 0) {
                record_pass();
            } else {
                char *wh = to_hex(canon->as.bytes.p, canon->as.bytes.len);
                char *gh = to_hex(got, got_len);
                char detail[2048];
                snprintf(detail, sizeof(detail), "want=%s got=%s",
                         wh ? wh : "?", gh ? gh : "?");
                record_fail(id, detail);
                free(wh);
                free(gh);
            }
            free(got);
            continue;
        }
        /* unknown kind -> not a testable vector (skip, uncounted) */
    }

    ec_value_free(top);
    printf("== ECF conformance: %d/%d PASS, %d FAIL ==\n", g_pass, total, g_fail);
    return g_fail == 0 ? 0 : 1;
}

/* ── uncovered-range self-tests + Ed25519 RFC-8032 KAT ──────────────────── */

static int hexcmp_encode(const char *label, ec_value *v, const char *want)
{
    uint8_t *enc = NULL;
    size_t len = 0;
    ec_status st = ec_ecf_encode(v, &enc, &len);
    ec_value_free(v);
    if (st != EC_OK) {
        printf("FAIL selftest %s: encode status %d\n", label, st);
        g_fail++;
        return 0;
    }
    char *gh = to_hex(enc, len);
    free(enc);
    int ok = gh && strcmp(gh, want) == 0;
    if (ok) {
        g_pass++;
    } else {
        printf("FAIL selftest %s: want=%s got=%s\n", label, want, gh ? gh : "?");
        g_fail++;
    }
    free(gh);
    return ok;
}

/* Round-trip a value through encode->decode->encode and require byte-identity. */
static int roundtrip(const char *label, ec_value *v)
{
    uint8_t *e1 = NULL; size_t l1 = 0;
    ec_status st = ec_ecf_encode(v, &e1, &l1);
    ec_value_free(v);
    if (st != EC_OK) { printf("FAIL rt %s enc1 %d\n", label, st); g_fail++; return 0; }
    ec_value *d = NULL;
    st = ec_ecf_decode(e1, l1, &d);
    if (st != EC_OK) { printf("FAIL rt %s dec %d\n", label, st); g_fail++; free(e1); return 0; }
    uint8_t *e2 = NULL; size_t l2 = 0;
    st = ec_ecf_encode(d, &e2, &l2);
    ec_value_free(d);
    if (st != EC_OK) { printf("FAIL rt %s enc2 %d\n", label, st); g_fail++; free(e1); return 0; }
    int ok = (l1 == l2 && memcmp(e1, e2, l1) == 0);
    if (ok) g_pass++; else { printf("FAIL rt %s not identical\n", label); g_fail++; }
    free(e1);
    free(e2);
    return ok;
}

static void run_selftests(void)
{
    /* uint64 = 2^64-1 and 2^63 (above signed-i64 max; native uint64_t carrier) */
    hexcmp_encode("u64_max", ec_int_u(0xffffffffffffffffULL), "1bffffffffffffffff");
    hexcmp_encode("u63", ec_int_u(0x8000000000000000ULL), "1b8000000000000000");
    /* nint min -2^64 => major 1, arg = 2^64-1 */
    hexcmp_encode("nint_min", ec_int_neg(0xffffffffffffffffULL), "3bffffffffffffffff");

    /* float ladder boundaries beyond the corpus */
    hexcmp_encode("f16_max_rt", ec_float(65504.0), "f97bff");
    hexcmp_encode("subnormal_smallest_f16", ec_float(5.960464477539063e-08), "f90001");

    /* round-trips */
    {
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("z"), ec_int_u(1));
        ec_map_put(m, ec_text("a"), ec_special(EC_FLOAT_NAN));
        ec_map_put(m, ec_text("bb"), ec_bool(true));
        roundtrip("mixed_map", m);
    }
    { roundtrip("neg_zero", ec_special(EC_FLOAT_NEG_ZERO)); }

    /* N2: bare tag 55799 (d9 d9 f7) must reject even at top level */
    {
        uint8_t wire[] = {0xd9, 0xd9, 0xf7, 0xa0};
        ec_value *d = NULL;
        ec_status st = ec_ecf_decode(wire, sizeof(wire), &d);
        if (st == EC_ERR_TAG_REJECTED) { g_pass++; }
        else { printf("FAIL selftest bare_tag: status %d\n", st); g_fail++; if (st == EC_OK) ec_value_free(d); }
    }

    /* N1: synthetic varint 128 -> 0x80 0x01 */
    {
        uint8_t b[10];
        size_t n = ec_varint_encode(128, b);
        if (n == 2 && b[0] == 0x80 && b[1] == 0x01) { g_pass++; }
        else { printf("FAIL selftest varint128\n"); g_fail++; }
    }

    /* base58 leading-zero preservation round-trip */
    {
        uint8_t raw[] = {0x00, 0x00, 0x01, 0x02, 0xff};
        char *s = NULL;
        ec_status st = ec_base58_encode(raw, sizeof(raw), &s);
        if (st == EC_OK) {
            uint8_t *back = NULL; size_t bl = 0;
            st = ec_base58_decode(s, &back, &bl);
            if (st == EC_OK && bl == sizeof(raw) && memcmp(back, raw, bl) == 0) { g_pass++; }
            else { printf("FAIL selftest base58_rt\n"); g_fail++; }
            free(back);
        } else { printf("FAIL selftest base58_enc %d\n", st); g_fail++; }
        free(s);
    }

    /* peer_id from a 32-byte Ed25519 pubkey -> §1.5 (0x01, 0x00, raw pubkey) */
    {
        uint8_t pk[32];
        for (int i = 0; i < 32; i++) pk[i] = (uint8_t)i;
        char *pid = NULL;
        ec_status st = ec_peer_id_from_pubkey(EC_KEY_TYPE_ED25519, pk, 32, &pid);
        if (st == EC_OK) {
            uint64_t kt, ht; uint8_t *dig = NULL; size_t dl = 0;
            st = ec_peer_id_parse(pid, &kt, &ht, &dig, &dl);
            if (st == EC_OK && kt == 0x01 && ht == 0x00 && dl == 32 &&
                memcmp(dig, pk, 32) == 0) { g_pass++; }
            else { printf("FAIL selftest peer_id_canonical kt=%llu ht=%llu dl=%zu\n",
                          (unsigned long long)kt, (unsigned long long)ht, dl); g_fail++; }
            free(dig);
        } else { printf("FAIL selftest peer_id_from_pubkey %d\n", st); g_fail++; }
        free(pid);
    }

    /* Ed25519 RFC-8032 TEST 1: all-zero seed -> known public key. */
    {
        uint8_t seed[32] = {0};
        uint8_t pk[32];
        ec_status st = ec_ed25519_pubkey(seed, 32, pk);
        const uint8_t want[32] = {
            0x3b,0x6a,0x27,0xbc,0xce,0xb6,0xa4,0x2d,0x62,0xa3,0xa8,0xd0,0x2a,0x6f,0x0d,0x73,
            0x65,0x32,0x15,0x77,0x1d,0xe2,0x43,0xa6,0x3a,0xc0,0x48,0xa1,0x8b,0x59,0xda,0x29
        };
        if (st == EC_OK && memcmp(pk, want, 32) == 0) { g_pass++; }
        else { printf("FAIL selftest ed25519_rfc8032_pk: status %d\n", st); g_fail++; }
    }

    /* Ed25519 sign + verify + tamper-reject */
    {
        uint8_t seed[32]; for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i + 1);
        uint8_t msg[] = {1,2,3,4,5};
        uint8_t pk[32], sig[64];
        ec_status s1 = ec_ed25519_pubkey(seed, 32, pk);
        ec_status s2 = ec_ed25519_sign(seed, 32, msg, sizeof(msg), sig);
        ec_status s3 = ec_ed25519_verify(pk, 32, sig, 64, msg, sizeof(msg));
        sig[0] ^= 0xff;
        ec_status s4 = ec_ed25519_verify(pk, 32, sig, 64, msg, sizeof(msg));
        if (s1 == EC_OK && s2 == EC_OK && s3 == EC_OK && s4 == EC_ERR_VERIFY_FAILED) { g_pass++; }
        else { printf("FAIL selftest sign_verify %d %d %d %d\n", s1,s2,s3,s4); g_fail++; }
    }
}

int main(int argc, char **argv)
{
    if (ec_crypto_init() != EC_OK) {
        printf("FATAL: libsodium init failed\n");
        return 1;
    }
    const char *fixture = (argc > 1)
        ? argv[1]
        : "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor";

    int rc = run_corpus(fixture);
    run_selftests();

    printf("== TOTAL: %d pass, %d fail ==\n", g_pass, g_fail);
    return (rc == 0 && g_fail == 0) ? 0 : 1;
}
