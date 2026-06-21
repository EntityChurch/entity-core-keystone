/*
 * ecf.c — Entity Canonical Form (ECF) codec: value model + canonical CBOR
 * encoder + structural decoder. Hand-rolled, one translation unit.
 *
 * Per ENTITY-CBOR-ENCODING.md v1.5 (spec-data v7.71/v7.75 byte-stable). No C CBOR
 * library gives ECF's guarantees, so the canonical layer is owned here:
 *   - minimal integer encoding (Rule 1) — full uint64 / -2^64 head-form range
 *     carried natively in uint64_t (ec_int: negative flag + magnitude/argument);
 *   - map keys sorted by ENCODED key bytes, length-FIRST then byte-lexicographic
 *     (ECF Rule 2 / CTAP2 — DIFFERS from RFC-8949 §4.2 pure-bytewise);
 *   - definite lengths only (Rule 3) — no 0x5f/0x7f/0x9f/0xbf;
 *   - shortest float preserving value incl. f16 (Rule 4) + Rule-4a specials
 *     (NaN f97e00 / +Inf f97c00 / -Inf f9fc00 / -0.0 f98000);
 *   - recursive major-type-6 (tag) rejection on decode (N2; §6.3);
 *   - empty map = the single byte 0xA0 (N3 — falls out of the generic encoder).
 *
 * Memory: encode returns a malloc'd buffer (caller frees with free()); decode
 * returns a malloc'd node tree (caller frees with ec_value_free()). The decoder
 * COPIES byte/text payloads into nodes, so the input buffer need not outlive the
 * tree. Error paths use goto-cleanup (free in reverse-alloc order).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "entity_core/protocol.h"

#include <stdlib.h>
#include <string.h>

/* ECF §10.2 nesting depth limit (also bounds decode recursion). */
#define EC_MAX_DEPTH 64

/* ───────────────────────── value model ─────────────────────────────────── */

static ec_value *val_new(ec_kind kind)
{
    ec_value *v = calloc(1, sizeof(*v));
    if (v) {
        v->kind = kind;
    }
    return v;
}

ec_value *ec_int_u(uint64_t n)
{
    ec_value *v = val_new(EC_INT);
    if (v) { v->as.i.negative = false; v->as.i.u = n; }
    return v;
}

ec_value *ec_int_neg(uint64_t arg)
{
    ec_value *v = val_new(EC_INT);
    if (v) { v->as.i.negative = true; v->as.i.u = arg; }
    return v;
}

ec_value *ec_float(double f)
{
    ec_value *v = val_new(EC_FLOAT);
    if (v) { v->as.f = f; }
    return v;
}

ec_value *ec_bool(bool b)
{
    ec_value *v = val_new(EC_BOOL);
    if (v) { v->as.b = b; }
    return v;
}

ec_value *ec_null(void)
{
    return val_new(EC_NULL);
}

ec_value *ec_special(ec_kind special_kind)
{
    switch (special_kind) {
        case EC_FLOAT_NAN:
        case EC_FLOAT_POS_INF:
        case EC_FLOAT_NEG_INF:
        case EC_FLOAT_NEG_ZERO:
            return val_new(special_kind);
        default:
            return NULL;
    }
}

static ec_value *bytes_or_text(ec_kind kind, const uint8_t *p, size_t len)
{
    ec_value *v = val_new(kind);
    if (!v) {
        return NULL;
    }
    /* Always allocate len+1 so text is NUL-terminated and a 0-length alloc is valid. */
    uint8_t *buf = malloc(len + 1);
    if (!buf) {
        free(v);
        return NULL;
    }
    if (len > 0) {
        memcpy(buf, p, len);
    }
    buf[len] = 0;
    v->as.bytes.p = buf;
    v->as.bytes.len = len;
    return v;
}

ec_value *ec_bytes(const uint8_t *p, size_t len)
{
    return bytes_or_text(EC_BYTES, p, len);
}

ec_value *ec_text_n(const char *s, size_t len)
{
    return bytes_or_text(EC_TEXT, (const uint8_t *)s, len);
}

ec_value *ec_text(const char *s)
{
    return ec_text_n(s, s ? strlen(s) : 0);
}

ec_value *ec_array(void)
{
    return val_new(EC_ARRAY);
}

ec_status ec_array_push(ec_value *arr, ec_value *item)
{
    if (!arr || arr->kind != EC_ARRAY || !item) {
        return EC_ERR_BAD_INPUT;
    }
    size_t n = arr->as.arr.len;
    ec_value **grown = realloc(arr->as.arr.items, (n + 1) * sizeof(*grown));
    if (!grown) {
        return EC_ERR_OOM;
    }
    arr->as.arr.items = grown;
    arr->as.arr.items[n] = item;
    arr->as.arr.len = n + 1;
    return EC_OK;
}

ec_value *ec_map(void)
{
    return val_new(EC_MAP);
}

ec_status ec_map_put(ec_value *map, ec_value *key, ec_value *val)
{
    if (!map || map->kind != EC_MAP || !key || !val) {
        return EC_ERR_BAD_INPUT;
    }
    size_t n = map->as.map.len;
    ec_entry *grown = realloc(map->as.map.entries, (n + 1) * sizeof(*grown));
    if (!grown) {
        return EC_ERR_OOM;
    }
    map->as.map.entries = grown;
    map->as.map.entries[n].key = key;
    map->as.map.entries[n].val = val;
    map->as.map.len = n + 1;
    return EC_OK;
}

ec_value *ec_map_get(const ec_value *map, const char *text_key)
{
    if (!map || map->kind != EC_MAP || !text_key) {
        return NULL;
    }
    size_t klen = strlen(text_key);
    for (size_t i = 0; i < map->as.map.len; i++) {
        ec_value *k = map->as.map.entries[i].key;
        if (k && k->kind == EC_TEXT && k->as.bytes.len == klen &&
            memcmp(k->as.bytes.p, text_key, klen) == 0) {
            return map->as.map.entries[i].val;
        }
    }
    return NULL;
}

ec_value *ec_value_clone(const ec_value *v)
{
    if (!v) {
        return NULL;
    }
    switch (v->kind) {
        case EC_INT: {
            ec_value *c = val_new(EC_INT);
            if (c) { c->as.i = v->as.i; }
            return c;
        }
        case EC_FLOAT: {
            ec_value *c = val_new(EC_FLOAT);
            if (c) { c->as.f = v->as.f; }
            return c;
        }
        case EC_BOOL: {
            ec_value *c = val_new(EC_BOOL);
            if (c) { c->as.b = v->as.b; }
            return c;
        }
        case EC_NULL:
        case EC_FLOAT_NAN:
        case EC_FLOAT_POS_INF:
        case EC_FLOAT_NEG_INF:
        case EC_FLOAT_NEG_ZERO:
            return val_new(v->kind);
        case EC_BYTES:
        case EC_TEXT:
            return bytes_or_text(v->kind, v->as.bytes.p, v->as.bytes.len);
        case EC_ARRAY: {
            ec_value *c = ec_array();
            if (!c) { return NULL; }
            for (size_t i = 0; i < v->as.arr.len; i++) {
                ec_value *item = ec_value_clone(v->as.arr.items[i]);
                if (!item || ec_array_push(c, item) != EC_OK) {
                    ec_value_free(item);
                    ec_value_free(c);
                    return NULL;
                }
            }
            return c;
        }
        case EC_MAP: {
            ec_value *c = ec_map();
            if (!c) { return NULL; }
            for (size_t i = 0; i < v->as.map.len; i++) {
                ec_value *k = ec_value_clone(v->as.map.entries[i].key);
                ec_value *val = ec_value_clone(v->as.map.entries[i].val);
                if (!k || !val || ec_map_put(c, k, val) != EC_OK) {
                    ec_value_free(k);
                    ec_value_free(val);
                    ec_value_free(c);
                    return NULL;
                }
            }
            return c;
        }
    }
    return NULL;
}

void ec_value_free(ec_value *v)
{
    if (!v) {
        return;
    }
    switch (v->kind) {
        case EC_BYTES:
        case EC_TEXT:
            free(v->as.bytes.p);
            break;
        case EC_ARRAY:
            for (size_t i = 0; i < v->as.arr.len; i++) {
                ec_value_free(v->as.arr.items[i]);
            }
            free(v->as.arr.items);
            break;
        case EC_MAP:
            for (size_t i = 0; i < v->as.map.len; i++) {
                ec_value_free(v->as.map.entries[i].key);
                ec_value_free(v->as.map.entries[i].val);
            }
            free(v->as.map.entries);
            break;
        default:
            break;
    }
    free(v);
}

/* ───────────────────────── growable byte buffer ────────────────────────── */

typedef struct buf {
    uint8_t *p;
    size_t len;
    size_t cap;
    bool oom;
} buf;

static void buf_init(buf *b)
{
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
    b->oom = false;
}

static void buf_free(buf *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

static bool buf_reserve(buf *b, size_t extra)
{
    if (b->oom) {
        return false;
    }
    if (b->len + extra <= b->cap) {
        return true;
    }
    size_t ncap = b->cap ? b->cap : 64;
    while (ncap < b->len + extra) {
        ncap *= 2;
    }
    uint8_t *np = realloc(b->p, ncap);
    if (!np) {
        b->oom = true;
        return false;
    }
    b->p = np;
    b->cap = ncap;
    return true;
}

static void buf_put(buf *b, uint8_t x)
{
    if (buf_reserve(b, 1)) {
        b->p[b->len++] = x;
    }
}

static void buf_append(buf *b, const uint8_t *src, size_t n)
{
    if (n == 0) {
        return;
    }
    if (buf_reserve(b, n)) {
        memcpy(b->p + b->len, src, n);
        b->len += n;
    }
}

/* ───────────────────────── encode ──────────────────────────────────────── */

/* Emit a CBOR head: major (0..7) with the shortest argument for `arg`. */
static void enc_head(buf *b, int major, uint64_t arg)
{
    int m = major << 5;
    if (arg < 24) {
        buf_put(b, (uint8_t)(m | (int)arg));
    } else if (arg < 0x100ULL) {
        buf_put(b, (uint8_t)(m | 24));
        buf_put(b, (uint8_t)(arg & 0xff));
    } else if (arg < 0x10000ULL) {
        buf_put(b, (uint8_t)(m | 25));
        buf_put(b, (uint8_t)((arg >> 8) & 0xff));
        buf_put(b, (uint8_t)(arg & 0xff));
    } else if (arg < 0x100000000ULL) {
        buf_put(b, (uint8_t)(m | 26));
        for (int i = 3; i >= 0; i--) {
            buf_put(b, (uint8_t)((arg >> (8 * i)) & 0xff));
        }
    } else {
        buf_put(b, (uint8_t)(m | 27));
        for (int i = 7; i >= 0; i--) {
            buf_put(b, (uint8_t)((arg >> (8 * i)) & 0xff));
        }
    }
}

/* ── float ladder: f16 ⊂ f32 ⊂ f64, shortest that round-trips exactly ───── */

static uint64_t dbits(double f)
{
    uint64_t u;
    memcpy(&u, &f, sizeof(u));
    return u;
}

static double f16_to_double(int h)
{
    int sign = (h >> 15) & 0x1;
    int exp = (h >> 10) & 0x1f;
    int mant = h & 0x3ff;
    double s = (sign == 1) ? -1.0 : 1.0;
    if (exp == 0) {
        if (mant == 0) {
            return s * 0.0;
        }
        /* subnormal: mant * 2^-24 */
        double v = (double)mant;
        for (int i = 0; i < 24; i++) v *= 0.5;
        return s * v;
    }
    if (exp == 0x1f) {
        return mant == 0 ? s * (1.0 / 0.0) : (0.0 / 0.0); /* unreachable for finite */
    }
    /* (1024 + mant) * 2^(exp-25) */
    double v = (double)(1024 + mant);
    int e = exp - 25;
    if (e >= 0) {
        for (int i = 0; i < e; i++) v *= 2.0;
    } else {
        for (int i = 0; i < -e; i++) v *= 0.5;
    }
    return s * v;
}

/* Try to convert a finite double to a 16-bit IEEE half. Returns true + *out on
 * exact representability; false otherwise. Pure-integer test (no f16 hardware). */
static bool double_to_f16(double f, int *out)
{
    uint64_t bits = dbits(f);
    int sign = (int)((bits >> 63) & 0x1);
    int exp = (int)((bits >> 52) & 0x7ff);
    uint64_t mant = bits & 0xfffffffffffffULL;
    if (exp == 0x7ff) {
        return false; /* inf/nan are specials, not here */
    }
    if (exp == 0 && mant == 0) {
        *out = (sign == 1) ? 0x8000 : 0x0000;
        return true;
    }
    int unbiased;
    uint64_t full_mant; /* 53-bit significand incl. implicit leading 1 */
    if (exp == 0) {
        /* subnormal double — normalize */
        int lead = __builtin_clzll(mant) - (63 - 52);
        unbiased = -1022 - lead;
        full_mant = (mant << (lead + 1)) & 0x1fffffffffffffULL;
        full_mant |= 0x10000000000000ULL;
    } else {
        unbiased = exp - 1023;
        full_mant = mant | 0x10000000000000ULL;
    }
    int he = unbiased + 15; /* half biased exponent */
    if (he > 30) {
        return false; /* too large for finite f16 */
    }
    if (he >= 1) {
        /* normalized f16: low 42 mantissa bits must be zero (10-bit fraction) */
        if ((mant & 0x3ffffffffffULL) != 0) {
            return false;
        }
        int hmant = (int)(mant >> 42);
        *out = (sign << 15) | (he << 10) | hmant;
        return true;
    }
    /* subnormal f16 (he <= 0): value = full_mant * 2^(unbiased-52); representable
     * iff full_mant divisible by 2^shift and quotient in [1,1023].
     * scaled_exp = (unbiased - 52) + 24 */
    int scaled_exp = (unbiased - 52) + 24;
    if (scaled_exp >= 0) {
        /* a left shift would exceed 1023 except for tiny mantissas; require fit */
        if (scaled_exp >= 11) {
            return false;
        }
        uint64_t scaled = full_mant << scaled_exp;
        if (scaled >= 1 && scaled <= 1023) {
            *out = (sign << 15) | (int)scaled;
            return true;
        }
        return false;
    }
    int shift = -scaled_exp;
    if (shift >= 64 || (full_mant & (((uint64_t)1 << shift) - 1)) != 0) {
        return false;
    }
    uint64_t q = full_mant >> shift;
    if (q >= 1 && q <= 1023) {
        *out = (sign << 15) | (int)q;
        return true;
    }
    return false;
}

static void enc_float(buf *b, double f)
{
    /* -0.0 is canonical f16 (Rule 4a). (+0.0 falls through to the f16 path.) */
    if (f == 0.0 && (dbits(f) != 0)) {
        buf_put(b, 0xf9); buf_put(b, 0x80); buf_put(b, 0x00);
        return;
    }
    int h;
    if (double_to_f16(f, &h) && f16_to_double(h) == f) {
        buf_put(b, 0xf9);
        buf_put(b, (uint8_t)((h >> 8) & 0xff));
        buf_put(b, (uint8_t)(h & 0xff));
        return;
    }
    float sf = (float)f;
    if ((double)sf == f) {
        uint32_t bits;
        memcpy(&bits, &sf, sizeof(bits));
        buf_put(b, 0xfa);
        for (int i = 3; i >= 0; i--) {
            buf_put(b, (uint8_t)((bits >> (8 * i)) & 0xff));
        }
        return;
    }
    uint64_t bits = dbits(f);
    buf_put(b, 0xfb);
    for (int i = 7; i >= 0; i--) {
        buf_put(b, (uint8_t)((bits >> (8 * i)) & 0xff));
    }
}

static ec_status enc_value(const ec_value *v, buf *b, int depth);

static void enc_int(const ec_int *i, buf *b)
{
    if (!i->negative) {
        enc_head(b, 0, i->u);
    } else {
        enc_head(b, 1, i->u); /* argument = -1 - value = i->u already */
    }
}

/* A pre-encoded map entry (key bytes + value bytes) for sorting. */
typedef struct enc_entry {
    uint8_t *key;
    size_t key_len;
    uint8_t *val;
    size_t val_len;
} enc_entry;

/* Length-FIRST then byte-lexicographic on encoded-key octets (ECF Rule 2). */
static int key_order(const void *pa, const void *pb)
{
    const enc_entry *a = pa;
    const enc_entry *b = pb;
    if (a->key_len != b->key_len) {
        return (a->key_len < b->key_len) ? -1 : 1;
    }
    if (a->key_len == 0) {
        return 0;
    }
    int c = memcmp(a->key, b->key, a->key_len);
    return (c < 0) ? -1 : (c > 0) ? 1 : 0;
}

static ec_status enc_map(const ec_value *m, buf *b, int depth)
{
    size_t n = m->as.map.len;
    enc_entry *entries = n ? calloc(n, sizeof(*entries)) : NULL;
    if (n && !entries) {
        return EC_ERR_OOM;
    }
    ec_status st = EC_OK;
    size_t built = 0;
    for (; built < n; built++) {
        buf kb, vb;
        buf_init(&kb);
        buf_init(&vb);
        st = enc_value(m->as.map.entries[built].key, &kb, depth + 1);
        if (st == EC_OK) {
            st = enc_value(m->as.map.entries[built].val, &vb, depth + 1);
        }
        if (st != EC_OK || kb.oom || vb.oom) {
            buf_free(&kb);
            buf_free(&vb);
            if (st == EC_OK) {
                st = EC_ERR_OOM;
            }
            goto cleanup;
        }
        entries[built].key = kb.p;
        entries[built].key_len = kb.len;
        entries[built].val = vb.p;
        entries[built].val_len = vb.len;
    }

    if (n > 1) {
        qsort(entries, n, sizeof(*entries), key_order);
    }

    enc_head(b, 5, n);
    for (size_t i = 0; i < n; i++) {
        buf_append(b, entries[i].key, entries[i].key_len);
        buf_append(b, entries[i].val, entries[i].val_len);
    }
    if (b->oom) {
        st = EC_ERR_OOM;
    }

cleanup:
    for (size_t i = 0; i < built; i++) {
        free(entries[i].key);
        free(entries[i].val);
    }
    free(entries);
    return st;
}

static ec_status enc_value(const ec_value *v, buf *b, int depth)
{
    if (depth > EC_MAX_DEPTH) {
        return EC_ERR_NON_CANONICAL_ECF;
    }
    if (!v) {
        return EC_ERR_BAD_INPUT;
    }
    switch (v->kind) {
        case EC_INT:
            enc_int(&v->as.i, b);
            break;
        case EC_FLOAT:
            enc_float(b, v->as.f);
            break;
        case EC_FLOAT_NAN:
            buf_put(b, 0xf9); buf_put(b, 0x7e); buf_put(b, 0x00);
            break;
        case EC_FLOAT_POS_INF:
            buf_put(b, 0xf9); buf_put(b, 0x7c); buf_put(b, 0x00);
            break;
        case EC_FLOAT_NEG_INF:
            buf_put(b, 0xf9); buf_put(b, 0xfc); buf_put(b, 0x00);
            break;
        case EC_FLOAT_NEG_ZERO:
            buf_put(b, 0xf9); buf_put(b, 0x80); buf_put(b, 0x00);
            break;
        case EC_BOOL:
            buf_put(b, v->as.b ? 0xf5 : 0xf4);
            break;
        case EC_NULL:
            buf_put(b, 0xf6);
            break;
        case EC_BYTES:
            enc_head(b, 2, v->as.bytes.len);
            buf_append(b, v->as.bytes.p, v->as.bytes.len);
            break;
        case EC_TEXT:
            enc_head(b, 3, v->as.bytes.len);
            buf_append(b, v->as.bytes.p, v->as.bytes.len);
            break;
        case EC_ARRAY:
            enc_head(b, 4, v->as.arr.len);
            for (size_t i = 0; i < v->as.arr.len; i++) {
                ec_status st = enc_value(v->as.arr.items[i], b, depth + 1);
                if (st != EC_OK) {
                    return st;
                }
            }
            break;
        case EC_MAP: {
            ec_status st = enc_map(v, b, depth);
            if (st != EC_OK) {
                return st;
            }
            break;
        }
        default:
            return EC_ERR_BAD_INPUT;
    }
    return b->oom ? EC_ERR_OOM : EC_OK;
}

ec_status ec_ecf_encode(const ec_value *v, uint8_t **out, size_t *out_len)
{
    if (!out || !out_len) {
        return EC_ERR_BAD_INPUT;
    }
    *out = NULL;
    *out_len = 0;
    buf b;
    buf_init(&b);
    ec_status st = enc_value(v, &b, 0);
    if (st != EC_OK || b.oom) {
        buf_free(&b);
        return st != EC_OK ? st : EC_ERR_OOM;
    }
    /* Hand back the buffer directly (caller frees with free()). Ensure non-NULL
     * even for a 0-byte encode (cannot happen for a valid value, but be safe). */
    if (b.p == NULL) {
        b.p = malloc(1);
        if (!b.p) {
            return EC_ERR_OOM;
        }
    }
    *out = b.p;
    *out_len = b.len;
    return EC_OK;
}

/* ───────────────────────── decode ──────────────────────────────────────── */

typedef struct cursor {
    const uint8_t *o;
    size_t len;
    size_t i;
} cursor;

static ec_status dec_value(cursor *c, int depth, ec_value **out);

/* Decode a CBOR head argument for the given additional-info `info`. Enforces
 * minimal (canonical) encoding: reject any longer-than-needed form. */
static ec_status dec_arg(cursor *c, int info, uint64_t *out)
{
    if (info < 24) {
        *out = (uint64_t)info;
        return EC_OK;
    }
    switch (info) {
        case 24: {
            if (c->i + 1 > c->len) return EC_ERR_TRUNCATED;
            uint64_t v = c->o[c->i];
            c->i += 1;
            if (v < 24) return EC_ERR_NON_CANONICAL_ECF; /* should be in the 1-byte head */
            *out = v;
            return EC_OK;
        }
        case 25: {
            if (c->i + 2 > c->len) return EC_ERR_TRUNCATED;
            uint64_t v = ((uint64_t)c->o[c->i] << 8) | c->o[c->i + 1];
            c->i += 2;
            if (v < 0x100ULL) return EC_ERR_NON_CANONICAL_ECF;
            *out = v;
            return EC_OK;
        }
        case 26: {
            if (c->i + 4 > c->len) return EC_ERR_TRUNCATED;
            uint64_t v = 0;
            for (int k = 0; k < 4; k++) v = (v << 8) | c->o[c->i + k];
            c->i += 4;
            if (v < 0x10000ULL) return EC_ERR_NON_CANONICAL_ECF;
            *out = v;
            return EC_OK;
        }
        case 27: {
            if (c->i + 8 > c->len) return EC_ERR_TRUNCATED;
            uint64_t v = 0;
            for (int k = 0; k < 8; k++) v = (v << 8) | c->o[c->i + k];
            c->i += 8;
            if (v < 0x100000000ULL) return EC_ERR_NON_CANONICAL_ECF;
            *out = v;
            return EC_OK;
        }
        default: /* 28,29,30 reserved; 31 indefinite — both non-canonical */
            return EC_ERR_NON_CANONICAL_ECF;
    }
}

static ec_status dec_len(cursor *c, int info, size_t *out)
{
    uint64_t v;
    ec_status st = dec_arg(c, info, &v);
    if (st != EC_OK) {
        return st;
    }
    if (v > (uint64_t)(SIZE_MAX)) {
        return EC_ERR_NON_CANONICAL_ECF;
    }
    *out = (size_t)v;
    return EC_OK;
}

/* major 7 simple/float decode. */
static ec_status dec_simple(cursor *c, int info, ec_value **out)
{
    switch (info) {
        case 20: *out = ec_bool(false); break;
        case 21: *out = ec_bool(true); break;
        case 22: *out = ec_null(); break;
        case 25: { /* f16 */
            if (c->i + 2 > c->len) return EC_ERR_TRUNCATED;
            int b0 = c->o[c->i], b1 = c->o[c->i + 1];
            c->i += 2;
            int h = (b0 << 8) | b1;
            int s = (h >> 15) & 1, e = (h >> 10) & 0x1f, m = h & 0x3ff;
            if (e == 0x1f) {
                *out = m == 0 ? ec_special(s ? EC_FLOAT_NEG_INF : EC_FLOAT_POS_INF)
                              : ec_special(EC_FLOAT_NAN);
            } else if (e == 0 && m == 0) {
                *out = s ? ec_special(EC_FLOAT_NEG_ZERO) : ec_float(0.0);
            } else {
                *out = ec_float(f16_to_double(h));
            }
            break;
        }
        case 26: { /* f32 */
            if (c->i + 4 > c->len) return EC_ERR_TRUNCATED;
            uint32_t bits = 0;
            for (int k = 0; k < 4; k++) bits = (bits << 8) | c->o[c->i + k];
            c->i += 4;
            int s = (int)((bits >> 31) & 1), e = (int)((bits >> 23) & 0xff);
            uint32_t mm = bits & 0x7fffff;
            if (e == 0xff) {
                *out = mm == 0 ? ec_special(s ? EC_FLOAT_NEG_INF : EC_FLOAT_POS_INF)
                               : ec_special(EC_FLOAT_NAN);
            } else if (e == 0 && mm == 0) {
                *out = s ? ec_special(EC_FLOAT_NEG_ZERO) : ec_float(0.0);
            } else {
                float fv;
                memcpy(&fv, &bits, sizeof(fv));
                *out = ec_float((double)fv);
            }
            break;
        }
        case 27: { /* f64 */
            if (c->i + 8 > c->len) return EC_ERR_TRUNCATED;
            uint64_t bits = 0;
            for (int k = 0; k < 8; k++) bits = (bits << 8) | c->o[c->i + k];
            c->i += 8;
            int s = (int)((bits >> 63) & 1), e = (int)((bits >> 52) & 0x7ff);
            uint64_t mm = bits & 0xfffffffffffffULL;
            if (e == 0x7ff) {
                *out = mm == 0 ? ec_special(s ? EC_FLOAT_NEG_INF : EC_FLOAT_POS_INF)
                               : ec_special(EC_FLOAT_NAN);
            } else if (e == 0 && mm == 0) {
                *out = s ? ec_special(EC_FLOAT_NEG_ZERO) : ec_float(0.0);
            } else {
                double dv;
                memcpy(&dv, &bits, sizeof(dv));
                *out = ec_float(dv);
            }
            break;
        }
        default:
            return EC_ERR_NON_CANONICAL_ECF; /* incl. f7 undefined, simple-value bytes */
    }
    return *out ? EC_OK : EC_ERR_OOM;
}

/* Compare two decoded map keys for equality (text/bytes only). */
static bool key_equal(const ec_value *a, const ec_value *b)
{
    if (a->kind != b->kind) {
        return false;
    }
    if (a->kind == EC_TEXT || a->kind == EC_BYTES) {
        return a->as.bytes.len == b->as.bytes.len &&
               (a->as.bytes.len == 0 ||
                memcmp(a->as.bytes.p, b->as.bytes.p, a->as.bytes.len) == 0);
    }
    if (a->kind == EC_INT) {
        return a->as.i.negative == b->as.i.negative && a->as.i.u == b->as.i.u;
    }
    return false;
}

static ec_status dec_value(cursor *c, int depth, ec_value **out)
{
    *out = NULL;
    if (depth > EC_MAX_DEPTH) {
        return EC_ERR_NON_CANONICAL_ECF;
    }
    if (c->i >= c->len) {
        return EC_ERR_TRUNCATED;
    }
    int ib = c->o[c->i];
    int major = ib >> 5;
    int info = ib & 0x1f;
    c->i++;

    switch (major) {
        case 0: {
            uint64_t arg;
            ec_status st = dec_arg(c, info, &arg);
            if (st != EC_OK) return st;
            *out = ec_int_u(arg);
            return *out ? EC_OK : EC_ERR_OOM;
        }
        case 1: {
            uint64_t arg;
            ec_status st = dec_arg(c, info, &arg);
            if (st != EC_OK) return st;
            *out = ec_int_neg(arg);
            return *out ? EC_OK : EC_ERR_OOM;
        }
        case 2: {
            size_t len;
            ec_status st = dec_len(c, info, &len);
            if (st != EC_OK) return st;
            if (c->i + len > c->len) return EC_ERR_TRUNCATED;
            *out = ec_bytes(c->o + c->i, len);
            c->i += len;
            return *out ? EC_OK : EC_ERR_OOM;
        }
        case 3: {
            size_t len;
            ec_status st = dec_len(c, info, &len);
            if (st != EC_OK) return st;
            if (c->i + len > c->len) return EC_ERR_TRUNCATED;
            *out = ec_text_n((const char *)(c->o + c->i), len);
            c->i += len;
            return *out ? EC_OK : EC_ERR_OOM;
        }
        case 4: {
            size_t len;
            ec_status st = dec_len(c, info, &len);
            if (st != EC_OK) return st;
            ec_value *arr = ec_array();
            if (!arr) return EC_ERR_OOM;
            for (size_t k = 0; k < len; k++) {
                ec_value *item = NULL;
                st = dec_value(c, depth + 1, &item);
                if (st != EC_OK) {
                    ec_value_free(arr);
                    return st;
                }
                st = ec_array_push(arr, item);
                if (st != EC_OK) {
                    ec_value_free(item);
                    ec_value_free(arr);
                    return st;
                }
            }
            *out = arr;
            return EC_OK;
        }
        case 5: {
            size_t len;
            ec_status st = dec_len(c, info, &len);
            if (st != EC_OK) return st;
            ec_value *map = ec_map();
            if (!map) return EC_ERR_OOM;
            for (size_t k = 0; k < len; k++) {
                ec_value *key = NULL, *val = NULL;
                st = dec_value(c, depth + 1, &key);
                if (st != EC_OK) { ec_value_free(map); return st; }
                /* keys must be text or bytes (canonical) */
                if (key->kind != EC_TEXT && key->kind != EC_BYTES) {
                    ec_value_free(key);
                    ec_value_free(map);
                    return EC_ERR_NON_CANONICAL_ECF;
                }
                /* duplicate-key check */
                for (size_t j = 0; j < map->as.map.len; j++) {
                    if (key_equal(map->as.map.entries[j].key, key)) {
                        ec_value_free(key);
                        ec_value_free(map);
                        return EC_ERR_DUPLICATE_KEY;
                    }
                }
                st = dec_value(c, depth + 1, &val);
                if (st != EC_OK) { ec_value_free(key); ec_value_free(map); return st; }
                st = ec_map_put(map, key, val);
                if (st != EC_OK) {
                    ec_value_free(key); ec_value_free(val); ec_value_free(map);
                    return st;
                }
            }
            *out = map;
            return EC_OK;
        }
        case 6:
            /* N2: major-type-6 tag rejected anywhere, any depth. */
            return EC_ERR_TAG_REJECTED;
        case 7:
            return dec_simple(c, info, out);
        default:
            return EC_ERR_NON_CANONICAL_ECF;
    }
}

ec_status ec_ecf_decode(const uint8_t *in, size_t in_len, ec_value **out)
{
    if (!out) {
        return EC_ERR_BAD_INPUT;
    }
    *out = NULL;
    if (!in && in_len > 0) {
        return EC_ERR_BAD_INPUT;
    }
    cursor c = { in, in_len, 0 };
    ec_value *v = NULL;
    ec_status st = dec_value(&c, 0, &v);
    if (st != EC_OK) {
        return st;
    }
    if (c.i < in_len) {
        ec_value_free(v);
        return EC_ERR_NON_CANONICAL_ECF; /* trailing bytes */
    }
    *out = v;
    return EC_OK;
}
