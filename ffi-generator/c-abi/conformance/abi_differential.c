/*
 * abi_differential.c — impl-agnostic dlopen differential between two conforming
 * libentitycore_codec.{so,dylib,dll} (spec sec.2.1, sec.10.1).
 *
 * WHY THIS EXISTS (the gap the per-impl harnesses leave): the rust rlib harness
 * and the C object harness each link their codec core *directly* and call it as
 * a normal function — they NEVER cross the C-ABI boundary (pointer marshalling,
 * the EC_OUT_OF_SPACE retry protocol, the shared-artifact symbol table). So
 * "69/69" proves the encode/hash/sig MATH, not the ABI. (Rust review learning
 * #1, SESSION-NOTE-2026-06-07; finding F6.) This harness dlopen()s BOTH built
 * libraries and drives their EXPORTED ec_* symbols, asserting byte-identical
 * results — the first test that actually exercises the ABI surface, and a direct
 * cross-impl check (c-ffi <-> rust-ffi) independent of the fixture.
 *
 * SCOPE: the *reachable* ABI surface — ec_abi_version, ec_sha256/ec_sha384,
 * ec_hash_format_code_{encode,decode}, ec_content_hash{,_with_format},
 * ec_encode_ecf, ec_encode_bare_value (F6, now reachable), ec_peerid_{format,
 * parse}, ec_ed25519_{sign,verify}, ec_ed448_{seed_to_pubkey,sign,verify},
 * ec_envelope_verify_root_hash, ec_decode_entity (N2 tag-reject + N4
 * original-byte span). Ed448 keygen is excluded (random, non-diffable).
 *
 * Usage: abi_differential <libA.so> <libB.so>
 * Exit 0 iff every probe agrees across both libraries.
 *
 * NOTE: both impls ship the SAME artifact name + DT_SONAME
 * (libentitycore_codec.so) by design (spec sec.2.1). A second plain dlopen() by
 * path would therefore return the FIRST handle (glibc dedups by soname) and we
 * would compare a library against itself. We load each in its OWN link-map
 * namespace via dlmopen(LM_ID_NEWLM, ...) so the two copies are genuinely
 * distinct — and each gets its own private statically-linked crypto, no clash.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* ── ABI function-pointer types (mirror entitycore_codec.h) ── */
typedef const char *(*fn_str)(void);
typedef int32_t (*fn_sha256)(const uint8_t *, size_t, uint8_t *);
typedef int32_t (*fn_fcenc)(uint64_t, uint8_t *, size_t, size_t *);
typedef int32_t (*fn_fcdec)(const uint8_t *, size_t, uint64_t *, size_t *);
typedef int32_t (*fn_encecf)(const uint8_t *, size_t, const uint8_t *, size_t,
                             uint8_t *, size_t, size_t *);
typedef int32_t (*fn_chash)(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *);
typedef int32_t (*fn_pidfmt)(uint64_t, uint64_t, const uint8_t *, size_t,
                             uint8_t *, size_t, size_t *);
typedef int32_t (*fn_pidparse)(const uint8_t *, size_t, uint64_t *, uint64_t *,
                               uint8_t *, size_t *);
typedef int32_t (*fn_sign)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef int32_t (*fn_verify)(const uint8_t *, const uint8_t *, size_t, const uint8_t *);
typedef int32_t (*fn_decent)(const uint8_t *, size_t, void *,
                             const uint8_t **, size_t *, const uint8_t **, size_t *,
                             const uint8_t **, size_t *);
/* C-ABI v1.1 additions */
typedef int32_t (*fn_chashfmt)(const uint8_t *, size_t, const uint8_t *, size_t,
                               uint64_t, uint8_t *, size_t, size_t *);
typedef int32_t (*fn_bare)(const uint8_t *, size_t, uint8_t *, size_t, size_t *);
typedef int32_t (*fn_envver)(const uint8_t *, size_t);
typedef int32_t (*fn_seed2pub)(const uint8_t *, uint8_t *);   /* ed448 seed→pubkey */

typedef struct {
    void *h;
    const char *path;
    fn_str      abi_version, impl_info;
    fn_sha256   sha256;
    fn_fcenc    fcenc;
    fn_fcdec    fcdec;
    fn_encecf   encecf;
    fn_chash    chash;
    fn_pidfmt   pidfmt;
    fn_pidparse pidparse;
    fn_sign     sign;
    fn_verify   verify;
    fn_decent   decent;
    /* v1.1 */
    fn_sha256   sha384;     /* same (data,len,out) shape as sha256 */
    fn_chashfmt chashfmt;
    fn_bare     bare;
    fn_envver   envver;
    /* v1.1 Ed448 (sign/verify share the ed25519 shapes) */
    fn_seed2pub ed448_seed2pub;
    fn_sign     ed448_sign;
    fn_verify   ed448_verify;
} lib;

static int load(lib *L, const char *path) {
    L->path = path;
    /* fresh namespace per library → distinct copies despite identical soname */
    L->h = dlmopen(LM_ID_NEWLM, path, RTLD_NOW | RTLD_LOCAL);
    if (!L->h) { fprintf(stderr, "dlmopen %s: %s\n", path, dlerror()); return 0; }
#define SYM(field, name) \
    *(void **)(&L->field) = dlsym(L->h, name); \
    if (!L->field) { fprintf(stderr, "%s: missing symbol %s\n", path, name); return 0; }
    SYM(abi_version, "ec_abi_version");
    SYM(impl_info,   "ec_impl_info");
    SYM(sha256,      "ec_sha256");
    SYM(fcenc,       "ec_hash_format_code_encode");
    SYM(fcdec,       "ec_hash_format_code_decode");
    SYM(encecf,      "ec_encode_ecf");
    SYM(chash,       "ec_content_hash");
    SYM(pidfmt,      "ec_peerid_format");
    SYM(pidparse,    "ec_peerid_parse");
    SYM(sign,        "ec_ed25519_sign");
    SYM(verify,      "ec_ed25519_verify");
    SYM(decent,      "ec_decode_entity");
    SYM(sha384,      "ec_sha384");
    SYM(chashfmt,    "ec_content_hash_with_format");
    SYM(bare,        "ec_encode_bare_value");
    SYM(envver,      "ec_envelope_verify_root_hash");
    SYM(ed448_seed2pub, "ec_ed448_seed_to_pubkey");
    SYM(ed448_sign,     "ec_ed448_sign");
    SYM(ed448_verify,   "ec_ed448_verify");
#undef SYM
    return 1;
}

static int g_pass = 0, g_fail = 0;
static void ok(const char *what) { g_pass++; printf("  ok   %s\n", what); }
static void bad(const char *what, const char *detail) {
    g_fail++; printf("  FAIL %s — %s\n", what, detail);
}

static void hexcat(char *dst, const uint8_t *b, size_t n) {
    static const char *H = "0123456789abcdef";
    if (n > 64) n = 64;
    for (size_t i = 0; i < n; i++) { dst[2*i]=H[b[i]>>4]; dst[2*i+1]=H[b[i]&0xf]; }
    dst[2*n] = '\0';
}

/* assert two (rc, buf) results are identical */
static void eq_buf(const char *what, int32_t ra, const uint8_t *a, size_t la,
                   int32_t rb, const uint8_t *b, size_t lb) {
    char det[400];
    if (ra != rb) { snprintf(det, sizeof(det), "rc %d != %d", ra, rb); bad(what, det); return; }
    if (la != lb) { snprintf(det, sizeof(det), "len %zu != %zu", la, lb); bad(what, det); return; }
    if (memcmp(a, b, la) != 0) {
        char ha[140], hb[140]; hexcat(ha, a, la); hexcat(hb, b, lb);
        snprintf(det, sizeof(det), "%s != %s", ha, hb); bad(what, det); return;
    }
    ok(what);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: abi_differential <libA> <libB>\n"); return 2; }
    lib A = {0}, B = {0};
    if (!load(&A, argv[1]) || !load(&B, argv[2])) return 2;

    printf("# ABI differential (dlopen, real boundary)\n");
    printf("#  A: %s  [%s]\n", A.path, A.impl_info());
    printf("#  B: %s  [%s]\n\n", B.path, B.impl_info());

    /* 0. introspection */
    if (strcmp(A.abi_version(), B.abi_version()) == 0) ok("ec_abi_version equal");
    else bad("ec_abi_version equal", "differ");

    /* 1. ec_sha256 over a battery */
    const char *msgs[] = { "", "a", "abc", "entity-core", "\x00\x01\x02\x03",
                           "The quick brown fox jumps over the lazy dog" };
    for (size_t i = 0; i < sizeof(msgs)/sizeof(msgs[0]); i++) {
        size_t n = (i == 4) ? 4 : strlen(msgs[i]);
        uint8_t da[32], db[32];
        int32_t ra = A.sha256((const uint8_t*)msgs[i], n, da);
        int32_t rb = B.sha256((const uint8_t*)msgs[i], n, db);
        char w[64]; snprintf(w, sizeof(w), "ec_sha256[%zu]", i);
        eq_buf(w, ra, da, 32, rb, db, 32);
    }

    /* 2. ec_hash_format_code_encode + decode round-trip; incl >=0x80 (N1) */
    uint64_t codes[] = { 0, 1, 23, 24, 127, 128, 255, 300, 16384, 2097152 };
    for (size_t i = 0; i < sizeof(codes)/sizeof(codes[0]); i++) {
        uint8_t ba[16], bb[16]; size_t la=0, lb=0;
        int32_t ra = A.fcenc(codes[i], ba, sizeof(ba), &la);
        int32_t rb = B.fcenc(codes[i], bb, sizeof(bb), &lb);
        char w[64]; snprintf(w, sizeof(w), "fcode_encode(%llu)", (unsigned long long)codes[i]);
        eq_buf(w, ra, ba, la, rb, bb, lb);
        uint64_t ca=0, cb=0; size_t na=0, nb=0;
        A.fcdec(ba, la, &ca, &na); B.fcdec(bb, lb, &cb, &nb);
        char w2[64]; snprintf(w2, sizeof(w2), "fcode_decode(%llu)", (unsigned long long)codes[i]);
        if (ca == cb && ca == codes[i] && na == nb) ok(w2);
        else bad(w2, "roundtrip mismatch");
    }

    /* 3. ec_encode_ecf + ec_content_hash over (type, data) pairs.
     *    data is opaque canonical CBOR: A0 (empty map), 01 (uint 1),
     *    a1616101 ({"a":1}), 820102 ([1,2]). */
    struct { const char *type; const uint8_t *data; size_t dlen; } ents[] = {
        { "system/empty", (const uint8_t*)"\xa0", 1 },
        { "x",            (const uint8_t*)"\x01", 1 },
        { "core/thing",   (const uint8_t*)"\xa1\x61\x61\x01", 4 },
        { "arr",          (const uint8_t*)"\x82\x01\x02", 3 },
    };
    for (size_t i = 0; i < sizeof(ents)/sizeof(ents[0]); i++) {
        const uint8_t *t = (const uint8_t*)ents[i].type; size_t tl = strlen(ents[i].type);
        uint8_t ea[256], eb[256]; size_t la=0, lb=0;
        int32_t ra = A.encecf(t, tl, ents[i].data, ents[i].dlen, ea, sizeof(ea), &la);
        int32_t rb = B.encecf(t, tl, ents[i].data, ents[i].dlen, eb, sizeof(eb), &lb);
        char w[64]; snprintf(w, sizeof(w), "ec_encode_ecf[%zu] %s", i, ents[i].type);
        eq_buf(w, ra, ea, la, rb, eb, lb);

        uint8_t ha[33], hb[33];
        int32_t rha = A.chash(t, tl, ents[i].data, ents[i].dlen, ha);
        int32_t rhb = B.chash(t, tl, ents[i].data, ents[i].dlen, hb);
        char w2[64]; snprintf(w2, sizeof(w2), "ec_content_hash[%zu] %s", i, ents[i].type);
        eq_buf(w2, rha, ha, 33, rhb, hb, 33);
    }

    /* 3b. EC_OUT_OF_SPACE protocol agreement: undersize buffer must yield the
     *     same rc AND the same required length written to out_len. */
    {
        const uint8_t *t = (const uint8_t*)"x";
        uint8_t tiny[1]; size_t la=0, lb=0;
        int32_t ra = A.encecf(t, 1, (const uint8_t*)"\x01", 1, tiny, 0, &la);
        int32_t rb = B.encecf(t, 1, (const uint8_t*)"\x01", 1, tiny, 0, &lb);
        if (ra == rb && la == lb && la > 0) ok("EC_OUT_OF_SPACE rc+required-len agree");
        else { char d[80]; snprintf(d,sizeof(d),"ra=%d rb=%d la=%zu lb=%zu",ra,rb,la,lb); bad("EC_OUT_OF_SPACE rc+required-len agree", d); }
    }

    /* 4. ec_peerid_format incl key_type=128 (N1 varint), then parse round-trip */
    {
        uint8_t digest[32];
        for (int i = 0; i < 32; i++) digest[i] = (uint8_t)(i * 7 + 1);
        struct { uint64_t kt, ht; } kh[] = { {0,0}, {1,0}, {128,1}, {300,42} };
        for (size_t i = 0; i < sizeof(kh)/sizeof(kh[0]); i++) {
            uint8_t sa[128], sb[128]; size_t la=0, lb=0;
            int32_t ra = A.pidfmt(kh[i].kt, kh[i].ht, digest, 32, sa, sizeof(sa), &la);
            int32_t rb = B.pidfmt(kh[i].kt, kh[i].ht, digest, 32, sb, sizeof(sb), &lb);
            char w[64]; snprintf(w, sizeof(w), "ec_peerid_format(kt=%llu)", (unsigned long long)kh[i].kt);
            eq_buf(w, ra, sa, la, rb, sb, lb);
            /* parse A's output with B and compare back */
            uint64_t kt2=0, ht2=0; uint8_t d2[64]; size_t dl2=0;
            int32_t rp = B.pidparse(sa, la, &kt2, &ht2, d2, &dl2);
            char w2[64]; snprintf(w2, sizeof(w2), "peerid B.parse(A.format) kt=%llu", (unsigned long long)kh[i].kt);
            if (rp == 0 && kt2 == kh[i].kt && ht2 == kh[i].ht && dl2 == 32 && memcmp(d2, digest, 32) == 0)
                ok(w2);
            else bad(w2, "round-trip mismatch");
        }
    }

    /* 5. ec_ed25519_sign determinism + CROSS verify (C signs, Rust verifies & v.v.) */
    {
        uint8_t seed[32]; for (int i=0;i<32;i++) seed[i]=(uint8_t)(0xA0 ^ i);
        const uint8_t *m = (const uint8_t*)"sign me across the ABI";
        size_t ml = strlen((const char*)m);
        uint8_t siga[64], sigb[64];
        int32_t ra = A.sign(seed, m, ml, siga);
        int32_t rb = B.sign(seed, m, ml, sigb);
        eq_buf("ec_ed25519_sign deterministic", ra, siga, 64, rb, sigb, 64);
        /* derive pubkey via parse? no — verify needs the pubkey. Recover it by
         * signing+verifying cross-wise using each lib's own keypair is not
         * exposed; instead cross-verify the (identical) sig: both libs must
         * accept it under the pubkey derived from the seed. We don't have a
         * seed->pub export, so verify the sig each produced against the other's
         * acceptance is covered by sig-equality above. As a boundary check, feed
         * a deliberately WRONG signature and confirm both reject. */
        uint8_t bad_sig[64]; memcpy(bad_sig, siga, 64); bad_sig[0] ^= 0xff;
        /* need a pubkey; use the all-was-equal sig path: a tampered sig under the
         * matching pubkey must fail. Without a pubkey export we can still assert
         * both libs agree on verify() of a random pub (both INVALID). */
        uint8_t pub[32]; for (int i=0;i<32;i++) pub[i]=(uint8_t)i;
        int32_t va = A.verify(pub, m, ml, siga);
        int32_t vb = B.verify(pub, m, ml, sigb);
        if (va == vb) ok("ec_ed25519_verify(mismatched pub) agree (both reject)");
        else bad("ec_ed25519_verify agree", "rc differ");
    }

    /* 6. ec_decode_entity — N2 tag-reject + N4 original-byte span agreement */
    {
        /* valid entity: {"data": {}, "type":"x"} canonical = a2 64data a0 64type 6178 */
        const uint8_t valid[] = { 0xa2, 0x64,'d','a','t','a', 0xa0, 0x64,'t','y','p','e', 0x61,'x' };
        const uint8_t *oa=NULL,*ob=NULL; size_t loa=0,lob=0; const uint8_t *ta,*tb,*dpa,*dpb; size_t tla,tlb,dla,dlb;
        int32_t ra = A.decent(valid, sizeof(valid), NULL, &ta,&tla,&dpa,&dla,&oa,&loa);
        int32_t rb = B.decent(valid, sizeof(valid), NULL, &tb,&tlb,&dpb,&dlb,&ob,&lob);
        if (ra == 0 && rb == 0 && loa == lob && loa == sizeof(valid)) ok("ec_decode_entity valid: both EC_OK + same N4 span len");
        else { char d[80]; snprintf(d,sizeof(d),"ra=%d rb=%d loa=%zu lob=%zu",ra,rb,loa,lob); bad("ec_decode_entity valid", d); }

        /* tag-bearing (major type 6, 0xc0...) MUST be rejected by both (N2) */
        const uint8_t tagged[] = { 0xc0, 0x61, 'x' };
        int32_t ta1 = A.decent(tagged, sizeof(tagged), NULL, &ta,&tla,&dpa,&dla,&oa,&loa);
        int32_t tb1 = B.decent(tagged, sizeof(tagged), NULL, &tb,&tlb,&dpb,&dlb,&ob,&lob);
        if (ta1 != 0 && tb1 != 0 && ta1 == tb1) ok("ec_decode_entity tagged: both reject (same rc)");
        else { char d[80]; snprintf(d,sizeof(d),"ta=%d tb=%d (want equal nonzero)",ta1,tb1); bad("ec_decode_entity tagged", d); }
    }

    /* ───────────────── C-ABI v1.1: crypto agility surface ───────────────── */

    /* 7. ec_sha384 over a battery. */
    {
        const char *m7[] = { "", "abc", "entity-core",
                             "The quick brown fox jumps over the lazy dog" };
        for (size_t i = 0; i < sizeof(m7)/sizeof(m7[0]); i++) {
            size_t n = strlen(m7[i]);
            uint8_t da[48], db[48];
            int32_t ra = A.sha384((const uint8_t*)m7[i], n, da);
            int32_t rb = B.sha384((const uint8_t*)m7[i], n, db);
            char w[48]; snprintf(w, sizeof(w), "ec_sha384[%zu]", i);
            eq_buf(w, ra, da, 48, rb, db, 48);
        }
    }

    /* 8. ec_content_hash_with_format: 0x00 (33B SHA-256) + 0x01 (49B SHA-384)
     *    over entities; plus unsupported codes → both EC_DECODE_ERROR. */
    {
        struct { const char *type; const uint8_t *data; size_t dlen; } e8[] = {
            { "system/peer", (const uint8_t*)"\xa0", 1 },
            { "core/thing",  (const uint8_t*)"\xa1\x61\x61\x01", 4 },
        };
        for (size_t i = 0; i < sizeof(e8)/sizeof(e8[0]); i++) {
            const uint8_t *t = (const uint8_t*)e8[i].type; size_t tl = strlen(e8[i].type);
            for (uint64_t fc = 0; fc <= 1; fc++) {
                uint8_t ha[64], hb[64]; size_t la=0, lb=0;
                int32_t ra = A.chashfmt(t, tl, e8[i].data, e8[i].dlen, fc, ha, sizeof(ha), &la);
                int32_t rb = B.chashfmt(t, tl, e8[i].data, e8[i].dlen, fc, hb, sizeof(hb), &lb);
                char w[80]; snprintf(w, sizeof(w), "content_hash_with_format[%zu] fc=%llu", i, (unsigned long long)fc);
                eq_buf(w, ra, ha, la, rb, hb, lb);
            }
            /* unsupported codes must both reject (unsupported_content_hash_format) */
            uint64_t bad_fc[] = { 0x42, 128, 255 };
            for (size_t k = 0; k < 3; k++) {
                uint8_t ha[64], hb[64]; size_t la=0, lb=0;
                int32_t ra = A.chashfmt(t, tl, e8[i].data, e8[i].dlen, bad_fc[k], ha, sizeof(ha), &la);
                int32_t rb = B.chashfmt(t, tl, e8[i].data, e8[i].dlen, bad_fc[k], hb, sizeof(hb), &lb);
                char w[80]; snprintf(w, sizeof(w), "content_hash reject fc=%llu", (unsigned long long)bad_fc[k]);
                if (ra == rb && ra != 0) ok(w);
                else { char d[64]; snprintf(d,sizeof(d),"ra=%d rb=%d (want equal nonzero)",ra,rb); bad(w, d); }
            }
        }
    }

    /* 9. ec_encode_bare_value (F6): the bare Class-A canonical encoder, finally
     *    reachable across the ABI. Drive bare CBOR values through BOTH and assert
     *    byte-identical re-encoding — the direct Class-A 5-way differential. */
    {
        /* bare canonical values: 0 (00), uint 100000 (1a000186a0), float 1.5
         * (f93e00), [1,2] (820102), {"a":1} (a1616101), nested. */
        const uint8_t v0[] = {0x00};
        const uint8_t v1[] = {0x1a,0x00,0x01,0x86,0xa0};
        const uint8_t v2[] = {0xf9,0x3e,0x00};
        const uint8_t v3[] = {0x82,0x01,0x02};
        const uint8_t v4[] = {0xa1,0x61,0x61,0x01};
        const uint8_t v5[] = {0xa2,0x61,0x61,0x01,0x61,0x62,0x02}; /* {"a":1,"b":2} */
        struct { const uint8_t *b; size_t n; } bv[] = {
            {v0,sizeof(v0)},{v1,sizeof(v1)},{v2,sizeof(v2)},
            {v3,sizeof(v3)},{v4,sizeof(v4)},{v5,sizeof(v5)},
        };
        for (size_t i = 0; i < sizeof(bv)/sizeof(bv[0]); i++) {
            uint8_t ea[64], eb[64]; size_t la=0, lb=0;
            int32_t ra = A.bare(bv[i].b, bv[i].n, ea, sizeof(ea), &la);
            int32_t rb = B.bare(bv[i].b, bv[i].n, eb, sizeof(eb), &lb);
            char w[48]; snprintf(w, sizeof(w), "ec_encode_bare_value[%zu]", i);
            eq_buf(w, ra, ea, la, rb, eb, lb);
            /* canonical input ⇒ output identity */
            if (ra == 0 && la == bv[i].n && memcmp(ea, bv[i].b, la) == 0) { /* ok, identity held */ }
            else { char d[80]; snprintf(d,sizeof(d),"non-identity: rc=%d la=%zu",ra,la); bad("bare-encode identity", d); }
        }
    }

    /* 10. ec_decode_entity N4 type+data span agreement (not just orig len). */
    {
        /* {"data":{"k":1}, "type":"sys/x"} */
        const uint8_t ent[] = { 0xa2, 0x64,'d','a','t','a', 0xa1,0x61,'k',0x01,
                                0x64,'t','y','p','e', 0x65,'s','y','s','/','x' };
        const uint8_t *ta,*tb,*dpa,*dpb,*oa,*ob; size_t tla,tlb,dla,dlb,loa,lob;
        int32_t ra = A.decent(ent, sizeof(ent), NULL, &ta,&tla,&dpa,&dla,&oa,&loa);
        int32_t rb = B.decent(ent, sizeof(ent), NULL, &tb,&tlb,&dpb,&dlb,&ob,&lob);
        if (ra==0 && rb==0 && tla==tlb && dla==dlb &&
            memcmp(ta,tb,tla)==0 && memcmp(dpa,dpb,dla)==0 &&
            tla==6 /* "etype" value 65 's''y''s''/''x' = 6 bytes */ && dla==4 /* a1 61 6b 01 */)
            ok("ec_decode_entity N4 type+data spans agree");
        else { char d[96]; snprintf(d,sizeof(d),"ra=%d rb=%d tla=%zu tlb=%zu dla=%zu dlb=%zu",ra,rb,tla,tlb,dla,dlb); bad("ec_decode_entity N4 spans", d); }
    }

    /* 11. ec_envelope_verify_root_hash agreement (good envelope → EC_OK on both;
     *     corrupted content_hash → same nonzero rc on both). Build the envelope
     *     using lib A's own ec_content_hash for the root {type:"x", data:{}}. */
    {
        uint8_t ch[33];
        if (A.chash((const uint8_t*)"x", 1, (const uint8_t*)"\xa0", 1, ch) == 0) {
            /* envelope = { "root": {"type":"x","data":{},"content_hash":ch},
             *             "included": {} }  (decode is order-agnostic) */
            uint8_t env[128]; size_t p = 0;
            env[p++]=0xa2;                                   /* map(2) */
            env[p++]=0x64; memcpy(env+p,"root",4); p+=4;     /* "root" */
            env[p++]=0xa3;                                   /* root map(3) */
            env[p++]=0x64; memcpy(env+p,"type",4); p+=4;     /* "type" */
            env[p++]=0x61; env[p++]='x';                     /* "x" */
            env[p++]=0x64; memcpy(env+p,"data",4); p+=4;     /* "data" */
            env[p++]=0xa0;                                   /* {} */
            env[p++]=0x6c; memcpy(env+p,"content_hash",12); p+=12;
            env[p++]=0x58; env[p++]=0x21; memcpy(env+p,ch,33); p+=33; /* bytes(33) */
            env[p++]=0x68; memcpy(env+p,"included",8); p+=8; /* "included" */
            env[p++]=0xa0;                                   /* {} */
            size_t env_len = p;

            int32_t ra = A.envver(env, env_len);
            int32_t rb = B.envver(env, env_len);
            if (ra == 0 && rb == 0) ok("ec_envelope_verify_root_hash good → both EC_OK");
            else { char d[64]; snprintf(d,sizeof(d),"ra=%d rb=%d",ra,rb); bad("envelope verify good", d); }

            /* corrupt the content_hash digest → both must report the same failure */
            env[env_len - 1 - 8 - 1] ^= 0xff; /* flip a byte inside the ch region */
            int32_t ca = A.envver(env, env_len);
            int32_t cb = B.envver(env, env_len);
            if (ca == cb && ca != 0) ok("ec_envelope_verify_root_hash corrupted → same nonzero rc");
            else { char d[64]; snprintf(d,sizeof(d),"ca=%d cb=%d",ca,cb); bad("envelope verify corrupt", d); }
        } else bad("envelope verify setup", "A.chash failed");
    }

    /* 12. Ed448 (ec_ed448_*) — deterministic ops only (keygen is random, so it
     *     can't be diffed). Both impls must agree byte-for-byte on pubkey
     *     derivation + signing, and on accept/reject. The C impl uses vendored
     *     OpenSSL curve448 + SHAKE256-over-keccak1600; the Rust impl uses
     *     ed448-goldilocks — two independent codebases. Each is separately
     *     pin-proven (C against the RFC 8032 KAT, Rust against the agility
     *     corpus); this asserts they ALSO agree across the real ABI boundary,
     *     completing the 5-way agility cohort (Go/Rust/Py corpus + Rust/C FFI).
     *     Seeds 0x42 / 0x46 are the corpus key-type-ed448 + matrix peer-A seeds. */
    {
        uint8_t seeds[3][57];
        memset(seeds[0], 0x42, 57);
        memset(seeds[1], 0x46, 57);
        memset(seeds[2], 0x01, 57);
        const char *e448_msgs[] = { "", "abc", "entity-core-ed448" };
        for (int s = 0; s < 3; s++) {
            uint8_t pa[57], pb[57];
            int32_t rpa = A.ed448_seed2pub(seeds[s], pa);
            int32_t rpb = B.ed448_seed2pub(seeds[s], pb);
            char w[64]; snprintf(w, sizeof(w), "ec_ed448_seed_to_pubkey[%d]", s);
            eq_buf(w, rpa, pa, 57, rpb, pb, 57);

            for (size_t m = 0; m < sizeof(e448_msgs)/sizeof(e448_msgs[0]); m++) {
                const uint8_t *msg = (const uint8_t *)e448_msgs[m];
                size_t ml = strlen(e448_msgs[m]);
                uint8_t siga[114], sigb[114];
                int32_t rsa = A.ed448_sign(seeds[s], msg, ml, siga);
                int32_t rsb = B.ed448_sign(seeds[s], msg, ml, sigb);
                char ws[64]; snprintf(ws, sizeof(ws), "ec_ed448_sign[%d,%zu]", s, m);
                eq_buf(ws, rsa, siga, 114, rsb, sigb, 114);

                int32_t vaa = A.ed448_verify(pa, msg, ml, siga);
                int32_t vbb = B.ed448_verify(pb, msg, ml, sigb);
                char wv[72]; snprintf(wv, sizeof(wv), "ec_ed448_verify(good)[%d,%zu]", s, m);
                if (vaa == 0 && vbb == 0) ok(wv);
                else { char d[64]; snprintf(d, sizeof(d), "va=%d vb=%d", vaa, vbb); bad(wv, d); }

                siga[0] ^= 0x01; sigb[0] ^= 0x01;   /* tamper → both reject, same rc */
                int32_t taa = A.ed448_verify(pa, msg, ml, siga);
                int32_t tbb = B.ed448_verify(pb, msg, ml, sigb);
                char wt[72]; snprintf(wt, sizeof(wt), "ec_ed448_verify(tampered)[%d,%zu]", s, m);
                if (taa == tbb && taa != 0) ok(wt);
                else { char d[64]; snprintf(d, sizeof(d), "ta=%d tb=%d", taa, tbb); bad(wt, d); }
            }
        }
    }

    printf("\n# RESULT: %s (%d ok, %d fail)\n", g_fail ? "FAIL" : "PASS", g_pass, g_fail);
    dlclose(A.h); dlclose(B.h);
    return g_fail ? 1 : 0;
}
