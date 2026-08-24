/* ec_peerid_parse unit test (M3) — the conformance corpus has no peer-id PARSE vector
 * (peer_id.N are encode_equal only), so the accept-path of the base58/LEB128 decode is
 * untested by the oracle. This drives it three ways: (A) format->parse round-trip over a
 * spread of key/hash-type widths and digest lengths, (B) parse the known peer_id.N base58
 * strings and check the recovered key_type/hash_type/digest, (C) reject paths. Closes the
 * "accept-path the oracle can't cover" gap (AGENTS: conformance-green can be vacuous).
 * Links codec.o + the codec .so (codec.o's ec_content_hash pulls in ec_sha256). Run via
 * `make parse-test`. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

extern int32_t ec_peerid_format(uint64_t kt, uint64_t ht, const uint8_t *digest,
                                size_t dlen, uint8_t *out, size_t cap, size_t *outlen);
extern int32_t ec_peerid_parse(const uint8_t *b58, size_t b58len, uint64_t *kt,
                               uint64_t *ht, uint8_t *digest, size_t *dlen);

static int pass = 0, fail = 0;
#define CHECK(cond, name) do { if (cond) { pass++; printf("PASS %s\n", name); } \
    else { fail++; printf("FAIL %s\n", name); } } while (0)

static void roundtrip(const char *name, uint64_t kt, uint64_t ht,
                      const uint8_t *dg, size_t dlen) {
    uint8_t b58[128]; size_t b58len = 0;
    int32_t rc = ec_peerid_format(kt, ht, dg, dlen, b58, sizeof(b58), &b58len);
    if (rc != 0) { fail++; printf("FAIL %s (format rc=%d)\n", name, rc); return; }
    uint64_t okt = 0, oht = 0; uint8_t odg[128]; size_t odlen = 0;
    rc = ec_peerid_parse(b58, b58len, &okt, &oht, odg, &odlen);
    CHECK(rc == 0 && okt == kt && oht == ht && odlen == dlen &&
          memcmp(odg, dg, dlen) == 0, name);
}

int main(void) {
    uint8_t d_zero[32] = {0};
    uint8_t d_seq[32];  for (int i = 0; i < 32; i++) d_seq[i] = (uint8_t)i;

    printf("-- A: format -> parse round-trip --\n");
    roundtrip("rt.zero",      1,   1, d_zero, 32);
    roundtrip("rt.seq",       1,   1, d_seq,  32);
    roundtrip("rt.kt_multi",  128, 1, d_seq,  32);   /* multi-byte varint prefix */
    roundtrip("rt.kt_ht_big", 300, 257, d_seq, 32);  /* both varints multi-byte */
    roundtrip("rt.empty_dg",  1,   1, d_seq,  0);     /* zero-length digest */
    roundtrip("rt.short_dg",  1,   1, d_seq,  4);

    /* B: the peer_id.N canonical is the CBOR text-wrap 0x78 <len> <base58...>; the raw
     * base58 below is the payload after that 2-byte head (matches diff-harness g->bytes+2). */
    printf("-- B: parse the known peer_id.N base58 strings --\n");
    struct { const char *name, *b58; uint64_t kt, ht; const uint8_t *dg; } K[] = {
        { "peer_id.1", "2KM1QFZjCB38WVbCFMP6dBij93DvP4TV9JJ69aCjkFioFu", 1, 1, d_zero },
        { "peer_id.2", "2KM1R9GFHWbnni9kZqFEerNKgbvTofz7n5Hm8pE7fiUBd8", 1, 1, d_seq },
        { "peer_id.3", "DmnkRzikTVEYbJa65uAsaahF6RzEwvQJ8Wgt3FTMVZn8VYHt", 128, 1, d_seq },
    };
    for (int i = 0; i < 3; i++) {
        uint64_t okt = 0, oht = 0; uint8_t odg[128]; size_t odlen = 0;
        int32_t rc = ec_peerid_parse((const uint8_t *)K[i].b58, strlen(K[i].b58),
                                     &okt, &oht, odg, &odlen);
        CHECK(rc == 0 && okt == K[i].kt && oht == K[i].ht && odlen == 32 &&
              memcmp(odg, K[i].dg, 32) == 0, K[i].name);
    }

    printf("-- C: reject paths --\n");
    { uint64_t a,b; uint8_t d[128]; size_t dl;
      /* '0','O','I','l' are not in the base58 alphabet */
      CHECK(ec_peerid_parse((const uint8_t*)"2KM0OIl", 7, &a,&b,d,&dl) != 0, "reject.badchar");
      /* NULL pointer → EC_INVALID_ARGUMENT (-1) */
      CHECK(ec_peerid_parse(NULL, 5, &a,&b,d,&dl) == -1, "reject.null"); }

    printf("== ec_peerid_parse: %d PASS, %d FAIL ==\n", pass, fail);
    return fail ? 1 : 0;
}
