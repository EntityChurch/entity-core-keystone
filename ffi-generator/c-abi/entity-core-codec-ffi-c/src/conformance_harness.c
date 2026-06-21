/*
 * conformance_harness.c — first-pass conformance harness for
 * entity-core-codec-ffi-c. Twin of the Rust impl's src/bin/conformance_harness.rs.
 *
 * Loads the vendored, cross-blessed fixture
 * (protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor),
 * drives each vector through the matching codec surface, and diffs the output
 * against the fixture's baked `canonical` bytes (the 3-way Go/Rust/Py blessed
 * consensus). Agreement here == this C impl agrees byte-for-byte.
 *
 * SCOPE/CAVEAT (first pass, same as Rust): links the codec core directly, NOT
 * via dlopen. The impl-agnostic 5-way dlopen harness in
 * ffi-generator/c-abi/conformance/ is the next step (resolve F6 first).
 *
 * Usage: conformance_harness <path-to-conformance-vectors-v1.cbor>
 */
#include "codec_core.h"
#include "ecf.h"
#include "../include/entitycore_codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── fixture field helpers (over the decoded ec_value map) ── */

static const ec_value *field(const ec_value *map, const char *key) {
    if (!map || map->kind != EV_MAP) return NULL;
    size_t klen = strlen(key);
    for (size_t i = 0; i < map->u.map.len; i++) {
        const ec_value *k = map->u.map.pairs[i].key;
        if (k->kind == EV_TEXT && k->u.bytes.len == klen &&
            memcmp(k->u.bytes.ptr, key, klen) == 0)
            return map->u.map.pairs[i].val;
    }
    return NULL;
}

/* returns malloc'd null-terminated copy of a text field, or NULL */
static char *text_field(const ec_value *map, const char *key) {
    const ec_value *v = field(map, key);
    if (!v || v->kind != EV_TEXT) return NULL;
    char *s = (char *)malloc(v->u.bytes.len + 1);
    memcpy(s, v->u.bytes.ptr, v->u.bytes.len);
    s[v->u.bytes.len] = '\0';
    return s;
}

/* returns 1 + fills (ptr,len) for a bytes field, else 0 */
static int bytes_field(const ec_value *map, const char *key,
                       const uint8_t **ptr, size_t *len) {
    const ec_value *v = field(map, key);
    if (!v || v->kind != EV_BYTES) return 0;
    *ptr = v->u.bytes.ptr;
    *len = v->u.bytes.len;
    return 1;
}

/* returns 1 + fills *out for a non-negative int field, else 0 */
static int uint_field(const ec_value *map, const char *key, uint64_t *out) {
    const ec_value *v = field(map, key);
    if (!v || v->kind != EV_INT || v->u.i.negative) return 0;
    *out = v->u.i.arg;
    return 1;
}

static void hex(const uint8_t *b, size_t n, char *out /* >= 2n+1 */) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = H[b[i] >> 4];
        out[2 * i + 1] = H[b[i] & 0xf];
    }
    out[2 * n] = '\0';
}

/* run one vector. on success returns 1; on failure returns 0 and fills msg. */
static int run_vector(const char *kind, const char *category,
                      const ec_value *map, char *msg, size_t msgcap) {
    const uint8_t *canon;
    size_t canon_len;

    if (strcmp(kind, "decode_reject") == 0) {
        if (!bytes_field(map, "canonical", &canon, &canon_len)) {
            snprintf(msg, msgcap, "missing canonical bytes");
            return 0;
        }
        if (ecf_validate_no_tags(canon, canon_len)) {
            char h[512];
            hex(canon, canon_len < 200 ? canon_len : 200, h);
            snprintf(msg, msgcap, "decoder ACCEPTED bytes it must reject (%s)", h);
            return 0;
        }
        return 1;
    }

    /* encode_equal */
    if (!bytes_field(map, "canonical", &canon, &canon_len)) {
        snprintf(msg, msgcap, "missing canonical bytes");
        return 0;
    }
    const ec_value *input = field(map, "input");
    if (!input) { snprintf(msg, msgcap, "missing input"); return 0; }

    ecbuf got;
    ecbuf_init(&got);

    if (strcmp(category, "content_hash") == 0) {
        char *type_str = text_field(input, "type");
        const ec_value *data = field(input, "data");
        if (!type_str || !data) { snprintf(msg, msgcap, "content_hash: missing type/data"); ecbuf_free(&got); free(type_str); return 0; }
        ecbuf data_bytes; ecbuf_init(&data_bytes);
        ecf_encode(data, &data_bytes);
        uint64_t fc = 0; uint_field(input, "format_code", &fc);
        cc_content_hash((const uint8_t *)type_str, strlen(type_str),
                        data_bytes.ptr, data_bytes.len, fc, &got);
        ecbuf_free(&data_bytes);
        free(type_str);
    } else if (strcmp(category, "peer_id") == 0) {
        uint64_t kt = 0, ht = 0;
        const uint8_t *digest; size_t dlen;
        if (!uint_field(input, "key_type", &kt) || !uint_field(input, "hash_type", &ht) ||
            !bytes_field(input, "digest", &digest, &dlen)) {
            snprintf(msg, msgcap, "peer_id: missing key_type/hash_type/digest"); ecbuf_free(&got); return 0;
        }
        ecbuf id; ecbuf_init(&id);
        if (!cc_peerid_format(kt, ht, digest, dlen, &id)) {
            snprintf(msg, msgcap, "peer_id: base58 format failed"); ecbuf_free(&id); ecbuf_free(&got); return 0;
        }
        /* the canonical output is the CBOR text encoding of the peer-id string */
        ec_value *t = ev_text((const char *)id.ptr, id.len);
        ecf_encode(t, &got);
        ecbuf_free(&id);
    } else if (strcmp(category, "signature") == 0) {
        const uint8_t *seed; size_t seed_len;
        if (!bytes_field(input, "seed", &seed, &seed_len) || seed_len != 32) {
            snprintf(msg, msgcap, "signature: missing/!=32 seed"); ecbuf_free(&got); return 0;
        }
        const ec_value *entity = field(input, "entity");
        if (!entity) { snprintf(msg, msgcap, "signature: missing entity"); ecbuf_free(&got); return 0; }
        ecbuf encmsg; ecbuf_init(&encmsg);
        ecf_encode(entity, &encmsg);
        uint8_t sig[64];
        if (!cc_ed25519_sign(seed, encmsg.ptr, encmsg.len, sig)) {
            snprintf(msg, msgcap, "signature: sign failed"); ecbuf_free(&encmsg); ecbuf_free(&got); return 0;
        }
        ecbuf_append(&got, sig, 64);
        ecbuf_free(&encmsg);
    } else {
        /* Class A + envelope/nested: bare canonical encode. */
        ecf_encode(input, &got);
    }

    int ok = (got.len == canon_len) && (memcmp(got.ptr, canon, canon_len) == 0);
    if (!ok) {
        char hg[481], he[481]; /* cap diagnostic hex so two fit the msg buffer */
        hex(got.ptr, got.len < 240 ? got.len : 240, hg);
        hex(canon, canon_len < 240 ? canon_len : 240, he);
        snprintf(msg, msgcap, "got %s != want %s", hg, he);
    }
    ecbuf_free(&got);
    return ok;
}

/* ── category accounting ── */
#define MAX_CATS 32
struct cat { char name[32]; unsigned pass, total; };

static struct cat *find_cat(struct cat *cats, int *n, const char *name) {
    for (int i = 0; i < *n; i++)
        if (strcmp(cats[i].name, name) == 0) return &cats[i];
    struct cat *c = &cats[(*n)++];
    snprintf(c->name, sizeof(c->name), "%s", name);
    c->pass = c->total = 0;
    return c;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: conformance_harness <conformance-vectors-v1.cbor>\n");
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *bytes = (uint8_t *)malloc(sz);
    if (fread(bytes, 1, sz, f) != (size_t)sz) { fprintf(stderr, "read error\n"); return 2; }
    fclose(f);

    ec_value *corpus = ecf_decode(bytes, (size_t)sz);
    if (!corpus || corpus->kind != EV_ARRAY) {
        fprintf(stderr, "fixture top-level is not a CBOR array (or failed to parse)\n");
        return 2;
    }

    printf("# entity-core-codec-ffi-c — first-pass conformance run\n");
    printf("# impl: %s\n", ec_impl_info());
    printf("# corpus: %s (%zu vectors)\n\n", argv[1], corpus->u.arr.len);

    struct cat cats[MAX_CATS];
    int ncats = 0;
    char failures[128][1280];
    int nfail = 0;

    for (size_t i = 0; i < corpus->u.arr.len; i++) {
        const ec_value *vec = corpus->u.arr.items[i];
        if (vec->kind != EV_MAP) continue;
        char *id = text_field(vec, "id");
        char *kind = text_field(vec, "kind");
        if (!id || !kind) { free(id); free(kind); continue; }
        char category[32];
        const char *dot = strchr(id, '.');
        size_t clen = dot ? (size_t)(dot - id) : strlen(id);
        if (clen >= sizeof(category)) clen = sizeof(category) - 1;
        memcpy(category, id, clen);
        category[clen] = '\0';

        char msg[1024] = {0};
        int ok = run_vector(kind, category, vec, msg, sizeof(msg));
        struct cat *c = find_cat(cats, &ncats, category);
        c->total++;
        if (ok) c->pass++;
        else if (nfail < 128)
            snprintf(failures[nfail++], sizeof(failures[0]),
                     "  FAIL %-16s [%s] %s", id, kind, msg);
        free(id); free(kind);
    }

    printf("%-14s %5s %5s\n", "category", "pass", "total");
    printf("--------------------------\n");
    unsigned tp = 0, tt = 0;
    for (int i = 0; i < ncats; i++) {
        const char *mark = cats[i].pass == cats[i].total ? "ok" : "XX";
        printf("%-14s %5u %5u  %s\n", cats[i].name, cats[i].pass, cats[i].total, mark);
        tp += cats[i].pass; tt += cats[i].total;
    }
    printf("--------------------------\n");
    printf("%-14s %5u %5u\n", "TOTAL", tp, tt);

    if (nfail > 0) {
        printf("\n# %d failure(s):\n", nfail);
        for (int i = 0; i < nfail; i++) printf("%s\n", failures[i]);
        return 1;
    }
    printf("\n# RESULT: PASS (%u/%u)\n", tp, tt);
    return 0;
}
