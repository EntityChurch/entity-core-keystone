/*
 * abi_leak_probe.c — does a CONSUMER of libentitycore_codec leak?
 *
 * The ASan run of the shipped test binaries cannot answer this: regression_test
 * and conformance_harness build ec_value trees directly and hold the corpus for
 * the life of the process, so their leak records are the HARNESS's, not the
 * library's. A peer never does that -- it only ever crosses the exported ec_*
 * surface. So this driver calls ONLY exported symbols, in the shapes a peer
 * calls them (per request), including the MALFORMED inputs that reach the
 * decoder's error paths -- which is where two of the three fixed leaks lived
 * and where anyone who can send bytes can reach them.
 *
 * Two modes, because they answer different questions and neither alone is
 * enough:
 *   --asan   one pass, exit; LeakSanitizer reports at exit (exact, needs an
 *            ASan build of the library, so C impl only).
 *   --rss N  N passes, report RSS growth (works on ANY impl through dlopen --
 *            this is how the Rust .so gets measured, since we cannot rebuild
 *            it under ASan without a nightly toolchain).
 *
 * Usage: abi_leak_probe <lib.so> [--rss N | --asan]
 *
 * Plain dlopen, not dlmopen: this process loads exactly ONE library, so the
 * shared-soname dedup that forces abi_differential.c to use dlmopen cannot bite
 * here -- and dlmopen would pull a second libasan into the new namespace, which
 * defeats the ASan mode. One impl per process; run it twice.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int32_t (*fn_encecf)(const uint8_t *, size_t, const uint8_t *, size_t,
                             uint8_t *, size_t, size_t *);
typedef int32_t (*fn_chash)(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *);
typedef int32_t (*fn_chashfmt)(const uint8_t *, size_t, const uint8_t *, size_t,
                               uint64_t, uint8_t *, size_t, size_t *);
typedef int32_t (*fn_bare)(const uint8_t *, size_t, uint8_t *, size_t, size_t *);
typedef int32_t (*fn_decent)(const uint8_t *, size_t, void *,
                             const uint8_t **, size_t *, const uint8_t **, size_t *,
                             const uint8_t **, size_t *);
typedef int32_t (*fn_origbytes)(const uint8_t *, size_t, const uint8_t **, size_t *);
typedef int32_t (*fn_envver)(const uint8_t *, size_t);
typedef int32_t (*fn_envfind)(const uint8_t *, size_t, const uint8_t *, size_t,
                              const uint8_t **, size_t *);
typedef int32_t (*fn_pidfmt)(uint64_t, uint64_t, const uint8_t *, size_t,
                             uint8_t *, size_t, size_t *);
typedef int32_t (*fn_pidparse)(const uint8_t *, size_t, uint64_t *, uint64_t *,
                               uint8_t *, size_t *);
typedef int32_t (*fn_sha)(const uint8_t *, size_t, uint8_t *);
typedef int32_t (*fn_sign)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef int32_t (*fn_verify)(const uint8_t *, const uint8_t *, size_t, const uint8_t *);
typedef int32_t (*fn_seed2pub)(const uint8_t *, uint8_t *);
typedef void   *(*fn_arena_new)(void);
typedef void    (*fn_arena_free)(void *);
typedef const char *(*fn_str)(void);

/* A symbol the spec declares but this impl may not export. Report and carry on
 * rather than exit: a probe that dies on the first gap tells you about one
 * symbol; a probe that records them tells you about all of them, and the gap
 * itself is a finding worth printing next to the leak numbers. */
static int n_missing = 0;
static const char *missing[32];

static void *need(void *h, const char *n) {
    void *p = dlsym(h, n);
    if (!p && n_missing < 32) missing[n_missing++] = n;
    return p;
}

static long rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256]; long kb = -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "VmRSS:", 6)) { kb = atol(line + 6); break; }
    fclose(f);
    return kb;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <lib.so> [--rss N|--asan]\n", argv[0]); return 2; }
    int passes = 1, rssmode = 0;
    if (argc > 2 && !strcmp(argv[2], "--rss")) { rssmode = 1; passes = argc > 3 ? atoi(argv[3]) : 20000; }

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "FATAL: dlopen %s: %s\n", argv[1], dlerror()); return 3; }

    fn_str       impl_info = (fn_str)need(h, "ec_impl_info");
    fn_encecf    encecf    = (fn_encecf)need(h, "ec_encode_ecf");
    fn_chash     chash     = (fn_chash)need(h, "ec_content_hash");
    fn_chashfmt  chashfmt  = (fn_chashfmt)need(h, "ec_content_hash_with_format");
    fn_bare      bare      = (fn_bare)need(h, "ec_encode_bare_value");
    fn_decent    decent    = (fn_decent)need(h, "ec_decode_entity");
    fn_origbytes origb     = (fn_origbytes)need(h, "ec_entity_original_bytes");
    fn_envver    envver    = (fn_envver)need(h, "ec_envelope_verify_root_hash");
    fn_envfind   envfind   = (fn_envfind)need(h, "ec_envelope_find_signature_for");
    fn_pidfmt    pidfmt    = (fn_pidfmt)need(h, "ec_peerid_format");
    fn_pidparse  pidparse  = (fn_pidparse)need(h, "ec_peerid_parse");
    fn_sha       sha256    = (fn_sha)need(h, "ec_sha256");
    fn_sha       sha384    = (fn_sha)need(h, "ec_sha384");
    fn_sign      sign      = (fn_sign)need(h, "ec_ed25519_sign");
    fn_verify    verify    = (fn_verify)need(h, "ec_ed25519_verify");
    fn_seed2pub  seed2pub  = (fn_seed2pub)need(h, "ec_ed25519_seed_to_pubkey");
    fn_arena_new anew      = (fn_arena_new)need(h, "ec_arena_new");
    fn_arena_free afree    = (fn_arena_free)need(h, "ec_arena_free");

    fprintf(stderr, "impl: %s\n", impl_info ? impl_info() : "(ec_impl_info absent)");
    if (n_missing) {
        fprintf(stderr, "ABI GAP: %d spec-declared symbol(s) not exported by this impl:\n", n_missing);
        for (int i = 0; i < n_missing; i++) fprintf(stderr, "  - %s\n", missing[i]);
    } else {
        fprintf(stderr, "ABI: all probed spec-declared symbols present\n");
    }

    /* A nested entity: exercises the array/map arms of the decoder, which are
     * the ones that allocate child arrays. */
    static const uint8_t type[] = "system/probe";
    static const uint8_t data[] = {
        0xa3, 0x61,'a', 0x01,
              0x61,'b', 0x83, 0x01, 0x02, 0x63,'x','y','z',
              0x61,'c', 0xa1, 0x61,'d', 0x82, 0xf4, 0xf5
    };
    static const uint8_t seed[32] = {1};

    /* MALFORMED inputs -- the error paths. (1) a major-type-6 tag nested inside
     * a map value, the shape the peers' salvage path meets; (2) an array header
     * declaring more items than follow, so the decoder fails PARTWAY through a
     * child array; (3) trailing bytes after a complete value. */
    static const uint8_t bad_tag[]   = { 0xa1, 0x61,'a', 0xc1, 0x01 };
    static const uint8_t bad_short[] = { 0x83, 0x01, 0x02 };
    static const uint8_t bad_trail[] = { 0x01, 0xff };

    uint8_t out[4096], hash[64], sig[64], pub[32];
    size_t olen;
    const uint8_t *p1, *p2, *p3; size_t l1, l2, l3;
    uint64_t kt, ht; uint8_t dig[64]; size_t diglen;

    long before = rss_kb(), mid = -1;

    for (int i = 0; i < passes; i++) {
        /* --- the per-request path: encode + hash --- */
        encecf(type, sizeof type - 1, data, sizeof data, out, sizeof out, &olen);
        chash(type, sizeof type - 1, data, sizeof data, hash);
        chashfmt(type, sizeof type - 1, data, sizeof data, 0x00, out, sizeof out, &olen);
        chashfmt(type, sizeof type - 1, data, sizeof data, 0x01, out, sizeof out, &olen);
        /* unsupported format code: an ERROR exit from a function that built a tree */
        chashfmt(type, sizeof type - 1, data, sizeof data, 0x7f, out, sizeof out, &olen);

        /* --- OUT_OF_SPACE: the retry protocol's first leg, an early error return --- */
        encecf(type, sizeof type - 1, data, sizeof data, out, 1, &olen);

        /* --- bare encode, valid and malformed --- */
        bare(data, sizeof data, out, sizeof out, &olen);
        bare(bad_tag, sizeof bad_tag, out, sizeof out, &olen);
        bare(bad_short, sizeof bad_short, out, sizeof out, &olen);
        bare(bad_trail, sizeof bad_trail, out, sizeof out, &olen);

        /* --- decode: valid entity, then the three malformed shapes --- */
        {
            uint8_t ent[4096]; size_t elen;
            if (encecf(type, sizeof type - 1, data, sizeof data, ent, sizeof ent, &elen) == 0) {
                void *ar = anew();
                decent(ent, elen, ar, &p1, &l1, &p2, &l2, &p3, &l3);
                afree(ar);
                if (origb) origb(ent, elen, &p1, &l1);
                /* envelope entry points over a non-envelope: error paths that
                 * decode first and must release before returning. */
                envver(ent, elen);
                envfind(ent, elen, hash, 32, &p1, &l1);
            }
            void *ar2 = anew();
            decent(bad_tag,   sizeof bad_tag,   ar2, &p1, &l1, &p2, &l2, &p3, &l3);
            decent(bad_short, sizeof bad_short, ar2, &p1, &l1, &p2, &l2, &p3, &l3);
            decent(bad_trail, sizeof bad_trail, ar2, &p1, &l1, &p2, &l2, &p3, &l3);
            afree(ar2);
            envver(bad_tag,   sizeof bad_tag);
            envver(bad_short, sizeof bad_short);
            envfind(bad_short, sizeof bad_short, hash, 32, &p1, &l1);
        }

        /* --- peer id, digests, signatures --- */
        pidfmt(0, 0, hash, 32, out, sizeof out, &olen);
        pidparse(out, olen, &kt, &ht, dig, &diglen);
        pidparse((const uint8_t *)"not-a-peer-id", 13, &kt, &ht, dig, &diglen);
        sha256(data, sizeof data, hash);
        sha384(data, sizeof data, hash);
        seed2pub(seed, pub);
        sign(seed, data, sizeof data, sig);
        verify(pub, data, sizeof data, sig);

        if (rssmode && i == passes / 10) mid = rss_kb();
    }

    long after = rss_kb();
    if (rssmode) {
        /* Report growth over the LAST 90% of passes: the first 10% includes
         * one-time warmup (allocator arenas, lazy crypto init) which is not a
         * leak and would otherwise be billed as one. */
        printf("passes=%d rss_start=%ldkB rss_at_10%%=%ldkB rss_end=%ldkB "
               "growth_over_last_90%%=%ldkB\n",
               passes, before, mid, after, mid >= 0 ? after - mid : -1);
        long grow = mid >= 0 ? after - mid : 0;
        long np = passes - passes / 10;
        printf("bytes_per_pass=%.2f\n", np > 0 ? (double)grow * 1024.0 / (double)np : 0.0);
    }
    /* deliberately not dlclose()d: unloading would let the impl's atexit paths
     * hide a leak from LSan. */
    return 0;
}
