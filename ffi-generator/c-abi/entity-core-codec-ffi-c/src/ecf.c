/*
 * ecf.c — hand-written canonical ECF encoder + decoder (C twin of the Rust
 * impl's value/encode/decode). See ecf.h for the contract; spec sec.3 for the
 * canonical obligations N1-N4. Float minimization is the highest-bug-density
 * part of the hand-roll (ffi-c.md) and is pinned by float.* corpus vectors plus
 * the local float-specials regression test.
 */
#include "ecf.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ── allocation: the harness + ABI calls are short-lived; we malloc value nodes
 * and never free the tree (process exits). Buffers (ecbuf) ARE freed by their
 * owners. This mirrors the first-pass Rust harness pragmatics; a v2 arena
 * (ec_arena_*) replaces this for the long-running peer decode path. ── */
static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) abort(); /* OOM: nothing useful to do in a codec primitive */
    return p;
}

/* ───────────────────────────── byte buffer ───────────────────────────── */

void ecbuf_init(ecbuf *b) { b->ptr = NULL; b->len = 0; b->cap = 0; }
void ecbuf_free(ecbuf *b) { free(b->ptr); b->ptr = NULL; b->len = b->cap = 0; }

static void ecbuf_reserve(ecbuf *b, size_t extra) {
    if (b->len + extra <= b->cap) return;
    size_t cap = b->cap ? b->cap : 32;
    while (cap < b->len + extra) cap *= 2;
    b->ptr = (uint8_t *)realloc(b->ptr, cap);
    if (!b->ptr) abort();
    b->cap = cap;
}

void ecbuf_push(ecbuf *b, uint8_t byte) {
    ecbuf_reserve(b, 1);
    b->ptr[b->len++] = byte;
}

void ecbuf_append(ecbuf *b, const uint8_t *src, size_t n) {
    if (n == 0) return;
    ecbuf_reserve(b, n);
    memcpy(b->ptr + b->len, src, n);
    b->len += n;
}

/* ───────────────────────────── LEB128 (N1) ───────────────────────────── */

void leb128_encode(uint64_t code, ecbuf *out) {
    for (;;) {
        uint8_t byte = (uint8_t)(code & 0x7f);
        code >>= 7;
        if (code != 0) byte |= 0x80;
        ecbuf_push(out, byte);
        if (code == 0) break;
    }
}

size_t leb128_decode(const uint8_t *in, size_t in_len, uint64_t *out_code) {
    uint64_t result = 0;
    unsigned shift = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (shift >= 64) return 0; /* overflow */
        uint8_t b = in[i];
        result |= (uint64_t)(b & 0x7f) << shift;
        if ((b & 0x80) == 0) { *out_code = result; return i + 1; }
        shift += 7;
    }
    return 0; /* ran off the end */
}

/* ──────────────────────────── value helpers ──────────────────────────── */

ec_value *ev_new(ev_kind kind) {
    ec_value *v = (ec_value *)xmalloc(sizeof(*v));
    memset(v, 0, sizeof(*v));
    v->kind = kind;
    return v;
}

ec_value *ev_int_u64(uint64_t n) {
    ec_value *v = ev_new(EV_INT);
    v->u.i.negative = 0;
    v->u.i.arg = n;
    return v;
}

static ec_value *ev_blob(ev_kind kind, const uint8_t *p, size_t len) {
    ec_value *v = ev_new(kind);
    v->u.bytes.ptr = (uint8_t *)xmalloc(len ? len : 1);
    if (len) memcpy(v->u.bytes.ptr, p, len);
    v->u.bytes.len = len;
    return v;
}

ec_value *ev_text(const char *s, size_t len) { return ev_blob(EV_TEXT, (const uint8_t *)s, len); }
ec_value *ev_bytes(const uint8_t *p, size_t len) { return ev_blob(EV_BYTES, p, len); }
ec_value *ev_preencoded(const uint8_t *p, size_t len) { return ev_blob(EV_PREENCODED, p, len); }

/* ────────────────────────────── encoder ──────────────────────────────── */

#define MT_UINT  (0u << 5)
#define MT_NINT  (1u << 5)
#define MT_BYTES (2u << 5)
#define MT_TEXT  (3u << 5)
#define MT_ARRAY (4u << 5)
#define MT_MAP   (5u << 5)

/* Major-type head with the shortest argument encoding (RFC 8949 sec.4.2.1). */
static void encode_head(uint8_t major, uint64_t n, ecbuf *out) {
    if (n < 24) {
        ecbuf_push(out, (uint8_t)(major | (uint8_t)n));
    } else if (n <= 0xff) {
        ecbuf_push(out, (uint8_t)(major | 24));
        ecbuf_push(out, (uint8_t)n);
    } else if (n <= 0xffff) {
        ecbuf_push(out, (uint8_t)(major | 25));
        uint8_t b[2] = { (uint8_t)(n >> 8), (uint8_t)n };
        ecbuf_append(out, b, 2);
    } else if (n <= 0xffffffffULL) {
        ecbuf_push(out, (uint8_t)(major | 26));
        uint8_t b[4] = { (uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n };
        ecbuf_append(out, b, 4);
    } else {
        ecbuf_push(out, (uint8_t)(major | 27));
        uint8_t b[8];
        for (int i = 0; i < 8; i++) b[i] = (uint8_t)(n >> (56 - 8 * i));
        ecbuf_append(out, b, 8);
    }
}

/* ── half-float helpers (no libc f16). Used only to *test* f16-representability
 * via exact round-trip; f16 ⊂ f32 ⊂ f64 exactly, so an exactly-representable
 * value round-trips and any other does not. ── */
static float f16_to_f32(uint16_t h) {
    uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    uint32_t exp  = (h >> 10) & 0x1fu;
    uint32_t mant = h & 0x3ffu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) {
            bits = sign;
        } else { /* subnormal → normalize */
            int e = 127 - 15 + 1;
            while ((mant & 0x400u) == 0) { mant <<= 1; e--; }
            mant &= 0x3ffu;
            bits = sign | ((uint32_t)e << 23) | (mant << 13);
        }
    } else if (exp == 0x1f) {
        bits = sign | 0x7f800000u | (mant << 13); /* inf / nan */
    } else {
        bits = sign | ((exp - 15 + 127) << 23) | (mant << 13);
    }
    float out;
    memcpy(&out, &bits, 4);
    return out;
}

static uint16_t f32_to_f16(float f) {
    uint32_t x;
    memcpy(&x, &f, 4);
    uint32_t sign = (x >> 16) & 0x8000u;
    int32_t  exp  = (int32_t)((x >> 23) & 0xffu) - 127 + 15;
    uint32_t mant = x & 0x7fffffu;

    if (((x >> 23) & 0xffu) == 0xff) /* inf/nan (specials handled before us) */
        return (uint16_t)(sign | 0x7c00u | (mant ? 0x200u : 0u));
    if (exp >= 0x1f) return (uint16_t)(sign | 0x7c00u); /* overflow → inf */
    if (exp <= 0) {                                     /* subnormal / zero */
        if (exp < -10) return (uint16_t)sign;
        mant |= 0x800000u;
        int shift = 14 - exp;
        uint32_t halfmant = mant >> shift;
        uint32_t rem = mant & (((uint32_t)1 << shift) - 1);
        uint32_t halfbit = (uint32_t)1 << (shift - 1);
        if (rem > halfbit || (rem == halfbit && (halfmant & 1))) halfmant++;
        return (uint16_t)(sign | halfmant);
    }
    /* normal */
    uint16_t halfmant = (uint16_t)(mant >> 13);
    uint32_t rem = mant & 0x1fffu;
    uint16_t base = (uint16_t)(sign | ((uint32_t)exp << 10) | halfmant);
    if (rem > 0x1000u || (rem == 0x1000u && (halfmant & 1))) base++;
    return base;
}

/* Shortest-float per spec sec.3.5: specials → f16; else f16/f32/f64 by exact
 * round-trip. Mirrors encode.rs::encode_float exactly. */
static void encode_float(double f, ecbuf *out) {
    if (isnan(f)) {
        uint8_t b[3] = { 0xf9, 0x7e, 0x00 }; /* canonical quiet NaN */
        ecbuf_append(out, b, 3);
        return;
    }
    if (isinf(f)) {
        uint8_t b[3] = { 0xf9, (uint8_t)(f > 0 ? 0x7c : 0xfc), 0x00 };
        ecbuf_append(out, b, 3);
        return;
    }
    if (f == 0.0) {
        uint8_t b[3] = { 0xf9, (uint8_t)(signbit(f) ? 0x80 : 0x00), 0x00 };
        ecbuf_append(out, b, 3);
        return;
    }
    /* f is finite, nonzero. f16 ⊂ f32 ⊂ f64, so test f32-exactness first. */
    float s = (float)f;
    if ((double)s == f) {
        uint16_t h = f32_to_f16(s);
        if ((double)f16_to_f32(h) == f) { /* exact f16 */
            uint8_t b[3] = { 0xf9, (uint8_t)(h >> 8), (uint8_t)h };
            ecbuf_append(out, b, 3);
            return;
        }
        uint32_t bits;
        memcpy(&bits, &s, 4);
        uint8_t b[5] = { 0xfa, (uint8_t)(bits >> 24), (uint8_t)(bits >> 16),
                         (uint8_t)(bits >> 8), (uint8_t)bits };
        ecbuf_append(out, b, 5);
        return;
    }
    uint64_t bits;
    memcpy(&bits, &f, 8);
    ecbuf_push(out, 0xfb);
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(bits >> (56 - 8 * i));
    ecbuf_append(out, b, 8);
}

/* qsort comparator for map pairs: bytewise-lexicographic on the encoded KEY,
 * shorter-is-less on a shared prefix (= Rust Vec<u8> Ord). Length-first falls
 * out for same-major-type keys because the length lives in the head. */
typedef struct { ecbuf key; ecbuf val; } encoded_pair;

static int cmp_encoded_pair(const void *pa, const void *pb) {
    const encoded_pair *a = (const encoded_pair *)pa;
    const encoded_pair *b = (const encoded_pair *)pb;
    size_t n = a->key.len < b->key.len ? a->key.len : b->key.len;
    int c = memcmp(a->key.ptr, b->key.ptr, n);
    if (c != 0) return c;
    if (a->key.len < b->key.len) return -1;
    if (a->key.len > b->key.len) return 1;
    return 0;
}

void ecf_encode(const ec_value *v, ecbuf *out) {
    switch (v->kind) {
    case EV_INT:
        encode_head(v->u.i.negative ? MT_NINT : MT_UINT, v->u.i.arg, out);
        break;
    case EV_FLOAT:
        encode_float(v->u.f, out);
        break;
    case EV_BYTES:
        encode_head(MT_BYTES, v->u.bytes.len, out);
        ecbuf_append(out, v->u.bytes.ptr, v->u.bytes.len);
        break;
    case EV_TEXT:
        encode_head(MT_TEXT, v->u.bytes.len, out);
        ecbuf_append(out, v->u.bytes.ptr, v->u.bytes.len);
        break;
    case EV_ARRAY:
        encode_head(MT_ARRAY, v->u.arr.len, out);
        for (size_t i = 0; i < v->u.arr.len; i++)
            ecf_encode(v->u.arr.items[i], out);
        break;
    case EV_MAP: {
        size_t n = v->u.map.len;
        encoded_pair *enc = (encoded_pair *)xmalloc(n * sizeof(*enc) + 1);
        for (size_t i = 0; i < n; i++) {
            ecbuf_init(&enc[i].key);
            ecbuf_init(&enc[i].val);
            ecf_encode(v->u.map.pairs[i].key, &enc[i].key);
            ecf_encode(v->u.map.pairs[i].val, &enc[i].val);
        }
        qsort(enc, n, sizeof(*enc), cmp_encoded_pair);
        encode_head(MT_MAP, n, out);
        for (size_t i = 0; i < n; i++) {
            ecbuf_append(out, enc[i].key.ptr, enc[i].key.len);
            ecbuf_append(out, enc[i].val.ptr, enc[i].val.len);
            ecbuf_free(&enc[i].key);
            ecbuf_free(&enc[i].val);
        }
        free(enc);
        break;
    }
    case EV_BOOL:
        ecbuf_push(out, (uint8_t)(v->u.b ? 0xf5 : 0xf4));
        break;
    case EV_NULL:
        ecbuf_push(out, 0xf6);
        break;
    case EV_PREENCODED:
        ecbuf_append(out, v->u.bytes.ptr, v->u.bytes.len);
        break;
    }
}

/* ────────────────────────────── decoder ──────────────────────────────── */
/* Minimal CBOR reader: reconstruct an ec_value and enforce N2 tag-rejection.
 * Rejects CBOR tags (major 6) anywhere and indefinite-length items. Twin of
 * decode.rs. On any error returns NULL. */

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} reader;

static int rd_byte(reader *r, uint8_t *out) {
    if (r->pos >= r->len) return 0;
    *out = r->buf[r->pos++];
    return 1;
}

static int rd_take(reader *r, size_t n, const uint8_t **out) {
    if (n > r->len - r->pos) return 0; /* (r->len - r->pos) is safe: pos <= len */
    *out = r->buf + r->pos;
    r->pos += n;
    return 1;
}

/* read the argument for additional-info `ai`; returns 1 on success */
static int rd_argument(reader *r, uint8_t ai, uint64_t *out) {
    if (ai < 24) { *out = ai; return 1; }
    const uint8_t *b;
    switch (ai) {
    case 24: { uint8_t x; if (!rd_byte(r, &x)) return 0; *out = x; return 1; }
    case 25:
        if (!rd_take(r, 2, &b)) return 0;
        *out = ((uint64_t)b[0] << 8) | b[1];
        return 1;
    case 26:
        if (!rd_take(r, 4, &b)) return 0;
        *out = ((uint64_t)b[0] << 24) | ((uint64_t)b[1] << 16) |
               ((uint64_t)b[2] << 8) | b[3];
        return 1;
    case 27:
        if (!rd_take(r, 8, &b)) return 0;
        *out = 0;
        for (int i = 0; i < 8; i++) *out = (*out << 8) | b[i];
        return 1;
    default: /* 28..=30 reserved, 31 indefinite — both forbidden in ECF */
        return 0;
    }
}

static int utf8_valid(const uint8_t *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        size_t extra;
        uint32_t cp, lo;
        if (c < 0x80) { i++; continue; }
        else if ((c & 0xe0) == 0xc0) { extra = 1; cp = c & 0x1f; lo = 0x80; }
        else if ((c & 0xf0) == 0xe0) { extra = 2; cp = c & 0x0f; lo = 0x800; }
        else if ((c & 0xf8) == 0xf0) { extra = 3; cp = c & 0x07; lo = 0x10000; }
        else return 0;
        if (i + 1 + extra > n) return 0; /* truncated multibyte sequence */
        for (size_t k = 1; k <= extra; k++) {
            uint8_t cc = s[i + k];
            if ((cc & 0xc0) != 0x80) return 0;
            cp = (cp << 6) | (cc & 0x3f);
        }
        if (cp < lo) return 0;                 /* overlong */
        if (cp > 0x10ffff) return 0;           /* out of range */
        if (cp >= 0xd800 && cp <= 0xdfff) return 0; /* surrogate */
        i += 1 + extra;
    }
    return 1;
}

static ec_value *rd_value(reader *r) {
    uint8_t head;
    if (!rd_byte(r, &head)) return NULL;
    uint8_t major = head >> 5;
    uint8_t ai = head & 0x1f;
    uint64_t arg;

    switch (major) {
    case 0:
        if (!rd_argument(r, ai, &arg)) return NULL;
        { ec_value *v = ev_new(EV_INT); v->u.i.negative = 0; v->u.i.arg = arg; return v; }
    case 1:
        if (!rd_argument(r, ai, &arg)) return NULL;
        { ec_value *v = ev_new(EV_INT); v->u.i.negative = 1; v->u.i.arg = arg; return v; }
    case 2: {
        const uint8_t *p;
        if (!rd_argument(r, ai, &arg) || !rd_take(r, (size_t)arg, &p)) return NULL;
        return ev_bytes(p, (size_t)arg);
    }
    case 3: {
        const uint8_t *p;
        if (!rd_argument(r, ai, &arg) || !rd_take(r, (size_t)arg, &p)) return NULL;
        if (!utf8_valid(p, (size_t)arg)) return NULL;
        return ev_text((const char *)p, (size_t)arg);
    }
    case 4: {
        if (!rd_argument(r, ai, &arg)) return NULL;
        size_t n = (size_t)arg;
        ec_value *v = ev_new(EV_ARRAY);
        v->u.arr.items = (ec_value **)xmalloc(n * sizeof(ec_value *) + 1);
        v->u.arr.len = n;
        for (size_t i = 0; i < n; i++) {
            ec_value *it = rd_value(r);
            if (!it) return NULL;
            v->u.arr.items[i] = it;
        }
        return v;
    }
    case 5: {
        if (!rd_argument(r, ai, &arg)) return NULL;
        size_t n = (size_t)arg;
        ec_value *v = ev_new(EV_MAP);
        v->u.map.pairs = (ec_pair *)xmalloc(n * sizeof(ec_pair) + 1);
        v->u.map.len = n;
        for (size_t i = 0; i < n; i++) {
            ec_value *k = rd_value(r);
            if (!k) return NULL;
            ec_value *val = rd_value(r);
            if (!val) return NULL;
            v->u.map.pairs[i].key = k;
            v->u.map.pairs[i].val = val;
        }
        return v;
    }
    case 6:
        return NULL; /* N2: CBOR tag forbidden in ECF */
    case 7:
        switch (ai) {
        case 20: { ec_value *v = ev_new(EV_BOOL); v->u.b = 0; return v; }
        case 21: { ec_value *v = ev_new(EV_BOOL); v->u.b = 1; return v; }
        case 22: return ev_new(EV_NULL);
        case 25: {
            const uint8_t *b;
            if (!rd_take(r, 2, &b)) return NULL;
            ec_value *v = ev_new(EV_FLOAT);
            v->u.f = (double)f16_to_f32((uint16_t)(((uint16_t)b[0] << 8) | b[1]));
            return v;
        }
        case 26: {
            const uint8_t *b;
            if (!rd_take(r, 4, &b)) return NULL;
            uint32_t bits = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                            ((uint32_t)b[2] << 8) | b[3];
            float fl; memcpy(&fl, &bits, 4);
            ec_value *v = ev_new(EV_FLOAT); v->u.f = (double)fl; return v;
        }
        case 27: {
            const uint8_t *b;
            if (!rd_take(r, 8, &b)) return NULL;
            uint64_t bits = 0;
            for (int i = 0; i < 8; i++) bits = (bits << 8) | b[i];
            double d; memcpy(&d, &bits, 8);
            ec_value *v = ev_new(EV_FLOAT); v->u.f = d; return v;
        }
        default: /* 23 (undefined), simple values: not used in ECF */
            return NULL;
        }
    default:
        return NULL; /* unreachable */
    }
}

ec_value *ecf_decode(const uint8_t *bytes, size_t len) {
    reader r = { bytes, len, 0 };
    ec_value *v = rd_value(&r);
    if (!v) return NULL;
    if (r.pos != len) return NULL; /* trailing bytes */
    return v;
}

int ecf_validate_no_tags(const uint8_t *bytes, size_t len) {
    return ecf_decode(bytes, len) != NULL;
}

/* ──────────────────────── span walkers (N4 + envelope) ────────────────────── */
/* Non-allocating structural skip: advances `pos` past one well-formed ECF item
 * without building a value tree (so no per-call leak in the long-running peer
 * decode path). Rejects tags (major 6) and indefinite/reserved (N2). */
static int rd_skip(reader *r) {
    uint8_t head;
    if (!rd_byte(r, &head)) return 0;
    uint8_t major = head >> 5, ai = head & 0x1f;
    uint64_t arg;
    const uint8_t *p;
    switch (major) {
    case 0: case 1:
        return rd_argument(r, ai, &arg);
    case 2: case 3:
        return rd_argument(r, ai, &arg) && rd_take(r, (size_t)arg, &p);
    case 4:
        if (!rd_argument(r, ai, &arg)) return 0;
        for (uint64_t i = 0; i < arg; i++) if (!rd_skip(r)) return 0;
        return 1;
    case 5:
        if (!rd_argument(r, ai, &arg)) return 0;
        for (uint64_t i = 0; i < arg; i++) { if (!rd_skip(r) || !rd_skip(r)) return 0; }
        return 1;
    case 6:
        return 0; /* N2: tag forbidden */
    case 7:
        switch (ai) {
        case 20: case 21: case 22: return 1;
        case 25: return rd_take(r, 2, &p);
        case 26: return rd_take(r, 4, &p);
        case 27: return rd_take(r, 8, &p);
        default: return 0;
        }
    default:
        return 0;
    }
}

/* Skip one value, recording its byte span. */
static int rd_skip_span(reader *r, ec_span *s) {
    s->off = r->pos;
    if (!rd_skip(r)) return 0;
    s->len = r->pos - s->off;
    return 1;
}

/* Read a text-string item, yielding its content ptr/len (no allocation). On a
 * non-text item, restores pos and returns 0. */
static int rd_text(reader *r, const uint8_t **ptr, size_t *len) {
    size_t save = r->pos;
    uint8_t head;
    if (!rd_byte(r, &head)) { r->pos = save; return 0; }
    if ((head >> 5) != 3) { r->pos = save; return 0; }
    uint64_t arg;
    const uint8_t *p;
    if (!rd_argument(r, head & 0x1f, &arg) || !rd_take(r, (size_t)arg, &p)) {
        r->pos = save;
        return 0;
    }
    *ptr = p;
    *len = (size_t)arg;
    return 1;
}

int ecf_entity_spans(const uint8_t *bytes, size_t len,
                     ec_span *type_span, ec_span *data_span) {
    reader r = { bytes, len, 0 };
    uint8_t head;
    if (!rd_byte(&r, &head) || (head >> 5) != 5) return 0;
    uint64_t n;
    if (!rd_argument(&r, head & 0x1f, &n)) return 0;
    int have_type = 0, have_data = 0;
    for (uint64_t i = 0; i < n; i++) {
        const uint8_t *k;
        size_t kl;
        if (rd_text(&r, &k, &kl)) {
            ec_span vs;
            if (!rd_skip_span(&r, &vs)) return 0;
            if (kl == 4 && memcmp(k, "type", 4) == 0) { *type_span = vs; have_type = 1; }
            else if (kl == 4 && memcmp(k, "data", 4) == 0) { *data_span = vs; have_data = 1; }
        } else {
            ec_span tmp;
            if (!rd_skip_span(&r, &tmp) || !rd_skip_span(&r, &tmp)) return 0;
        }
    }
    if (r.pos != len) return 0;
    return (have_type && have_data) ? 1 : 0;
}

int ecf_envelope_spans(const uint8_t *bytes, size_t len, ec_span *root,
                       ec_span *inc_keys, ec_span *inc_entities,
                       size_t *n_inc, size_t max_inc) {
    reader r = { bytes, len, 0 };
    uint8_t head;
    if (!rd_byte(&r, &head) || (head >> 5) != 5) return 0;
    uint64_t n;
    if (!rd_argument(&r, head & 0x1f, &n)) return 0;
    int have_root = 0;
    size_t ni = 0;
    for (uint64_t i = 0; i < n; i++) {
        const uint8_t *k;
        size_t kl;
        if (rd_text(&r, &k, &kl)) {
            if (kl == 4 && memcmp(k, "root", 4) == 0) {
                if (!rd_skip_span(&r, root)) return 0;
                have_root = 1;
            } else if (kl == 8 && memcmp(k, "included", 8) == 0) {
                uint8_t ih;
                if (!rd_byte(&r, &ih) || (ih >> 5) != 5) return 0;
                uint64_t m;
                if (!rd_argument(&r, ih & 0x1f, &m)) return 0;
                for (uint64_t j = 0; j < m; j++) {
                    ec_span ks, es;
                    if (!rd_skip_span(&r, &ks) || !rd_skip_span(&r, &es)) return 0;
                    if (ni < max_inc) { inc_keys[ni] = ks; inc_entities[ni] = es; }
                    ni++;
                }
            } else {
                ec_span tmp;
                if (!rd_skip_span(&r, &tmp)) return 0;
            }
        } else {
            ec_span tmp;
            if (!rd_skip_span(&r, &tmp) || !rd_skip_span(&r, &tmp)) return 0;
        }
    }
    if (r.pos != len || !have_root || ni > max_inc) return 0;
    *n_inc = ni;
    return 1;
}
