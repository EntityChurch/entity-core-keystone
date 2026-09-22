/*
 * IoEntityCodec.c — the EntityCodec Io addon: the codec/crypto seam of
 * entity-core-protocol-io.
 *
 * Two halves (profile [codec] strategy = ffi-addon-hybrid):
 *   1. Canonical CBOR (ECF) encoder/decoder, hand-rolled HERE against
 *      ENTITY-CBOR-ENCODING.md v1.5 (Rules 1-6 + tag-reject N2 + strict
 *      canonical decode), operating directly on Io values via the iovm C API.
 *   2. Crypto / content-hash / peer-id delegated to libentitycore_codec
 *      (the C-ABI, ffi-generator/c-abi/spec/entitycore_codec.h).
 *
 * Io value model (profile [codec], A-IO-001):
 *   map        <-> EcMap   (slots: keys List, vals List — insertion order;
 *                            canonical sort happens HERE at encode)
 *   array      <-> List
 *   text (mt3) <-> Sequence (validated UTF-8)
 *   bytes(mt2) <-> EcBytes  (slot: seq)
 *   int |x|<=2^53 <-> Number (integral; Number ALWAYS means integer)
 *   int beyond    <-> EcBig  (slots: neg true/false, mag 8-byte BE Sequence
 *                             holding the HEAD VALUE n — for mt1, int = -1-n)
 *   float      <-> EcFloat (slot: num) — shortest-form ladder incl f16
 *   true/false <-> true/false ; null <-> EcNull (nil accepted on encode)
 *
 * Error style (profile [error_model]): canonicality violations raise an Io
 * exception via IoState_error_ ("ec: <kind>: detail"), catchable by try().
 * The frozen iovm's IoState_error_ sets a flag and unwinds after the
 * CFunction returns, so the recursive codec threads an internal err field
 * and raises ONCE at the top level.
 *
 * Wrapper protos are Io-defined (io/A0_EntityCodec.io) and handed to C via
 * EntityCodec _setWrappers(EcMap, EcBytes, EcBig, EcFloat, EcNull).
 *
 * Apache-2.0 (keystone S9).
 */

#include "IoState.h"
#include "IoObject.h"
#include "IoSeq.h"
#include "IoNumber.h"
#include "IoList.h"
#include "IoMessage.h"

#include "entitycore_codec.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <sys/time.h>
#include <sys/random.h>

#define EC_MAX_DEPTH 64
#define EC_DOUBLE_INT_MAX 9007199254740992.0 /* 2^53 */

/* ── tiny grow buffer ── */
typedef struct {
    unsigned char *b;
    size_t len, cap;
} Buf;

static int buf_put(Buf *o, const unsigned char *p, size_t n) {
    if (o->len + n > o->cap) {
        size_t c = o->cap ? o->cap : 64;
        while (c < o->len + n) c *= 2;
        unsigned char *nb = realloc(o->b, c);
        if (!nb) return -1;
        o->b = nb; o->cap = c;
    }
    memcpy(o->b + o->len, p, n);
    o->len += n;
    return 0;
}

static int buf_byte(Buf *o, unsigned char c) { return buf_put(o, &c, 1); }

/* minimal-head (Rule 1): major type + shortest length/value form */
static int buf_head(Buf *o, int major, uint64_t v) {
    unsigned char h[9];
    int n;
    if (v < 24)              { h[0] = (unsigned char)((major << 5) | v); n = 1; }
    else if (v <= 0xFF)      { h[0] = (unsigned char)((major << 5) | 24); h[1] = (unsigned char)v; n = 2; }
    else if (v <= 0xFFFF)    { h[0] = (unsigned char)((major << 5) | 25); h[1] = v >> 8; h[2] = v; n = 3; }
    else if (v <= 0xFFFFFFFFULL) {
        h[0] = (unsigned char)((major << 5) | 26);
        h[1] = v >> 24; h[2] = v >> 16; h[3] = v >> 8; h[4] = v; n = 5;
    } else {
        h[0] = (unsigned char)((major << 5) | 27);
        h[1] = v >> 56; h[2] = v >> 48; h[3] = v >> 40; h[4] = v >> 32;
        h[5] = v >> 24; h[6] = v >> 16; h[7] = v >> 8; h[8] = v; n = 9;
    }
    return buf_put(o, h, n);
}

/* ── float16 helpers ── */
static int double_to_half_exact(double d, uint16_t *out) {
    /* d is not NaN here. Returns 1 iff d is exactly representable as f16. */
    float f = (float)d;
    if ((double)f != d) return 0;
    uint32_t bits;
    memcpy(&bits, &f, 4);
    uint32_t s = bits >> 31, E = (bits >> 23) & 0xFF, M = bits & 0x7FFFFF;
    if (E == 0 && M == 0) { *out = (uint16_t)(s << 15); return 1; }          /* ±0 */
    if (E == 0xFF && M == 0) { *out = (uint16_t)((s << 15) | 0x7C00); return 1; } /* ±inf */
    if (E == 0xFF) return 0;
    int e = (int)E - 127;
    if (e >= -14 && e <= 15) {
        if (M & 0x1FFF) return 0;                    /* low 13 bits must vanish */
        *out = (uint16_t)((s << 15) | ((uint32_t)(e + 15) << 10) | (M >> 13));
        return 1;
    }
    if (e >= -24 && e < -14) {                       /* subnormal half */
        uint32_t full = 0x800000 | M;
        int shift = (-14 - e) + 13;
        if (full & ((1u << shift) - 1)) return 0;
        *out = (uint16_t)((s << 15) | (full >> shift));
        return 1;
    }
    return 0;
}

static double half_to_double(uint16_t h) {
    uint32_t s = (h >> 15) & 1, E = (h >> 10) & 0x1F, M = h & 0x3FF;
    double d;
    if (E == 0)      d = ldexp((double)M, -24);
    else if (E == 31) d = M ? NAN : INFINITY;
    else             d = ldexp((double)(M | 0x400), (int)E - 25);
    return s ? -d : d;
}

/* ── UTF-8 validation ── */
static int utf8_valid(const unsigned char *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char c = p[i];
        if (c < 0x80) { i++; continue; }
        int len; uint32_t cp, min;
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; min = 0x80; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; min = 0x800; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; min = 0x10000; }
        else return 0;
        if (i + len > n) return 0;
        for (int k = 1; k < len; k++) {
            if ((p[i + k] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
        i += len;
    }
    return 1;
}

/* ── codec context ── */
typedef struct {
    IoState *state;
    IoObject *self;      /* the EntityCodec object (wrapper-proto slots live here) */
    const char *err;     /* first error kind, or NULL */
    char detail[128];
} Ctx;

static void ctx_err(Ctx *cx, const char *kind, const char *detail) {
    if (cx->err) return;
    cx->err = kind;
    snprintf(cx->detail, sizeof(cx->detail), "%s", detail ? detail : "");
}

static IoObject *slotOf(Ctx *cx, IoObject *obj, const char *name) {
    return IoObject_getSlot_(obj, IoState_symbolWithCString_(cx->state, (char *)name));
}

/* ecKind of an object, or NULL */
static const char *ecKindOf(Ctx *cx, IoObject *v) {
    IoObject *k = slotOf(cx, v, "ecKind");
    if (!k || !ISSEQ(k)) return NULL;
    return CSTRING(k);
}

/* ══════════════════════ ENCODE ══════════════════════ */

static int enc_value(Ctx *cx, Buf *o, IoObject *v, int depth);

static int enc_map(Ctx *cx, Buf *o, IoObject *v, int depth) {
    IoObject *keysO = slotOf(cx, v, "keys");
    IoObject *valsO = slotOf(cx, v, "vals");
    if (!keysO || !valsO || !ISLIST(keysO) || !ISLIST(valsO)) {
        ctx_err(cx, "encode_error", "EcMap missing keys/vals lists");
        return -1;
    }
    size_t n = IoList_rawSize(keysO);
    if (IoList_rawSize(valsO) != n) { ctx_err(cx, "encode_error", "EcMap keys/vals size mismatch"); return -1; }

    /* encode all keys into private bufs */
    Buf *kb = calloc(n ? n : 1, sizeof(Buf));
    size_t *order = malloc((n ? n : 1) * sizeof(size_t));
    int rc = -1;
    if (!kb || !order) { ctx_err(cx, "encode_error", "oom"); goto done; }
    for (size_t i = 0; i < n; i++) {
        order[i] = i;
        if (enc_value(cx, &kb[i], IoList_rawAt_(keysO, (int)i), depth + 1) != 0) goto done;
    }
    /* sort by (encoded length, lexicographic) — Rule 2; insertion sort (n small) */
    for (size_t i = 1; i < n; i++) {
        size_t cur = order[i];
        size_t j = i;
        while (j > 0) {
            Buf *a = &kb[order[j - 1]], *b = &kb[cur];
            int gt;
            if (a->len != b->len) gt = a->len > b->len;
            else {
                int c = memcmp(a->b, b->b, a->len);
                if (c == 0) { ctx_err(cx, "duplicate_key", "duplicate map key"); goto done; }
                gt = c > 0;
            }
            if (!gt) break;
            order[j] = order[j - 1];
            j--;
        }
        order[j] = cur;
    }
    /* adjacent-duplicate check across the whole ordering */
    for (size_t i = 1; i < n; i++) {
        Buf *a = &kb[order[i - 1]], *b = &kb[order[i]];
        if (a->len == b->len && memcmp(a->b, b->b, a->len) == 0) {
            ctx_err(cx, "duplicate_key", "duplicate map key");
            goto done;
        }
    }
    if (buf_head(o, 5, n) != 0) { ctx_err(cx, "encode_error", "oom"); goto done; }
    for (size_t i = 0; i < n; i++) {
        size_t idx = order[i];
        if (buf_put(o, kb[idx].b, kb[idx].len) != 0) { ctx_err(cx, "encode_error", "oom"); goto done; }
        if (enc_value(cx, o, IoList_rawAt_(valsO, (int)idx), depth + 1) != 0) goto done;
    }
    rc = 0;
done:
    for (size_t i = 0; i < n; i++) free(kb[i].b);
    free(kb);
    free(order);
    return rc;
}

static int enc_float(Ctx *cx, Buf *o, double d) {
    unsigned char t[9];
    if (isnan(d)) { t[0] = 0xF9; t[1] = 0x7E; t[2] = 0x00; return buf_put(o, t, 3); }
    uint16_t h;
    if (double_to_half_exact(d, &h)) {
        t[0] = 0xF9; t[1] = (unsigned char)(h >> 8); t[2] = (unsigned char)h;
        return buf_put(o, t, 3);
    }
    float f = (float)d;
    if ((double)f == d) {
        uint32_t bits; memcpy(&bits, &f, 4);
        t[0] = 0xFA; t[1] = bits >> 24; t[2] = bits >> 16; t[3] = bits >> 8; t[4] = bits;
        return buf_put(o, t, 5);
    }
    uint64_t bits; memcpy(&bits, &d, 8);
    t[0] = 0xFB;
    for (int i = 0; i < 8; i++) t[1 + i] = (unsigned char)(bits >> (56 - 8 * i));
    return buf_put(o, t, 9);
}

static int enc_value(Ctx *cx, Buf *o, IoObject *v, int depth) {
    if (cx->err) return -1;
    if (depth > EC_MAX_DEPTH) { ctx_err(cx, "encode_error", "nesting too deep"); return -1; }
    IoState *st = cx->state;

    if (v == NULL || v == st->ioNil) return buf_byte(o, 0xF6);
    if (v == st->ioTrue)  return buf_byte(o, 0xF5);
    if (v == st->ioFalse) return buf_byte(o, 0xF4);

    if (ISNUMBER(v)) {
        double d = IoNumber_asDouble(v);
        if (isnan(d) || isinf(d) || d != floor(d) || fabs(d) > EC_DOUBLE_INT_MAX) {
            ctx_err(cx, "encode_error", "Number must be an exact integer |x|<=2^53; wrap floats in EcFloat, big ints in EcBig");
            return -1;
        }
        if (d < 0) return buf_head(o, 1, (uint64_t)(-d - 1.0));
        return buf_head(o, 0, (uint64_t)d);
    }
    if (ISSEQ(v)) {
        const unsigned char *p = IoSeq_rawBytes(v);
        size_t n = IoSeq_rawSizeInBytes(v);
        if (!utf8_valid(p, n)) { ctx_err(cx, "encode_error", "text Sequence is not valid UTF-8 (bytes must ride EcBytes)"); return -1; }
        if (buf_head(o, 3, n) != 0) return -1;
        return buf_put(o, p, n);
    }
    if (ISLIST(v)) {
        size_t n = IoList_rawSize(v);
        if (buf_head(o, 4, n) != 0) return -1;
        for (size_t i = 0; i < n; i++)
            if (enc_value(cx, o, IoList_rawAt_(v, (int)i), depth + 1) != 0) return -1;
        return 0;
    }

    const char *kind = ecKindOf(cx, v);
    if (!kind) { ctx_err(cx, "encode_error", "unencodable Io value (no ecKind)"); return -1; }

    if (strcmp(kind, "bytes") == 0) {
        IoObject *s = slotOf(cx, v, "seq");
        if (!s || !ISSEQ(s)) { ctx_err(cx, "encode_error", "EcBytes missing seq"); return -1; }
        size_t n = IoSeq_rawSizeInBytes(s);
        if (buf_head(o, 2, n) != 0) return -1;
        return buf_put(o, IoSeq_rawBytes(s), n);
    }
    if (strcmp(kind, "null") == 0) return buf_byte(o, 0xF6);
    if (strcmp(kind, "float") == 0) {
        IoObject *nu = slotOf(cx, v, "num");
        if (!nu || !ISNUMBER(nu)) { ctx_err(cx, "encode_error", "EcFloat missing num"); return -1; }
        double d = IoNumber_asDouble(nu);
        /* Io's number cache folds -0.0 into +0.0 (long-cast cache hit), so the
         * sign of zero rides an explicit negZero slot on EcFloat instead. */
        if (d == 0.0 && !isnan(d)) {
            IoObject *nz = slotOf(cx, v, "negZero");
            if (nz == st->ioTrue) d = -0.0;
        }
        return enc_float(cx, o, d);
    }
    if (strcmp(kind, "big") == 0) {
        IoObject *mag = slotOf(cx, v, "mag");
        IoObject *neg = slotOf(cx, v, "neg");
        if (!mag || !ISSEQ(mag) || IoSeq_rawSizeInBytes(mag) != 8) {
            ctx_err(cx, "encode_error", "EcBig mag must be an 8-byte Sequence");
            return -1;
        }
        const unsigned char *p = IoSeq_rawBytes(mag);
        uint64_t n = 0;
        for (int i = 0; i < 8; i++) n = (n << 8) | p[i];
        return buf_head(o, (neg == cx->state->ioTrue) ? 1 : 0, n);
    }
    if (strcmp(kind, "map") == 0) return enc_map(cx, o, v, depth);

    ctx_err(cx, "encode_error", "unknown ecKind");
    return -1;
}

/* ══════════════════════ DECODE (strict canonical) ══════════════════════ */

typedef struct {
    const unsigned char *b;
    size_t len, pos;
    /* keep_tags makes dec_value yield the tag's INNER item instead of erroring. It
     * exists for ONE caller -- decodeSalvage -- and is never set on the strict path.
     * See IoEntityCodec_decodeSalvage for why this is not a weakening of §6.3. */
    int keep_tags;
} Cur;

static IoObject *makeWrapper(Ctx *cx, const char *protoSlot) {
    IoObject *proto = slotOf(cx, cx->self, protoSlot);
    if (!proto) { ctx_err(cx, "decode_error", "wrapper protos not installed (_setWrappers)"); return NULL; }
    IoObject *inst = IOCLONE(proto);
    return inst;
}

static void setSlot(Ctx *cx, IoObject *obj, const char *name, IoObject *v) {
    IoObject_setSlot_to_(obj, IoState_symbolWithCString_(cx->state, (char *)name), v);
}

/* read a data-item head with Rule-1/Rule-3 canonicality enforcement.
 * For mt7, ai 25/26/27 are float widths — returned raw (val = ai payload
 * unread; caller handles). */
static int dec_head(Ctx *cx, Cur *c, int *major, int *ai, uint64_t *val) {
    if (c->pos >= c->len) { ctx_err(cx, "truncated_input", "head"); return -1; }
    unsigned char ib = c->b[c->pos++];
    *major = ib >> 5;
    *ai = ib & 0x1F;
    if (*ai == 31) { ctx_err(cx, "non_canonical_ecf", "indefinite length"); return -1; }
    if (*ai >= 28) { ctx_err(cx, "non_canonical_ecf", "reserved additional info"); return -1; }
    if (*major == 7) { *val = *ai; return 0; }  /* floats/simple handled by caller */
    uint64_t v = *ai;
    int extra = 0;
    if (*ai == 24) extra = 1;
    else if (*ai == 25) extra = 2;
    else if (*ai == 26) extra = 4;
    else if (*ai == 27) extra = 8;
    if (extra) {
        if (c->pos + extra > c->len) { ctx_err(cx, "truncated_input", "head arg"); return -1; }
        v = 0;
        for (int i = 0; i < extra; i++) v = (v << 8) | c->b[c->pos++];
        /* Rule 1: minimal encoding */
        if ((extra == 1 && v < 24) ||
            (extra == 2 && v <= 0xFF) ||
            (extra == 4 && v <= 0xFFFF) ||
            (extra == 8 && v <= 0xFFFFFFFFULL)) {
            ctx_err(cx, "non_canonical_ecf", "non-minimal head");
            return -1;
        }
    }
    *val = v;
    return 0;
}

static IoObject *dec_value(Ctx *cx, Cur *c, int depth);

static IoObject *bigOrNumber(Ctx *cx, int neg, uint64_t n) {
    if ((double)n <= EC_DOUBLE_INT_MAX && n <= (uint64_t)1 << 53) {
        double d = (double)n;
        return IoState_numberWithDouble_(cx->state, neg ? (-d - 1.0) : d);
    }
    IoObject *big = makeWrapper(cx, "protoEcBig");
    if (!big) return NULL;
    unsigned char m[8];
    for (int i = 0; i < 8; i++) m[i] = (unsigned char)(n >> (56 - 8 * i));
    setSlot(cx, big, "mag", IoSeq_newWithData_length_(cx->state, m, 8));
    setSlot(cx, big, "neg", neg ? cx->state->ioTrue : cx->state->ioFalse);
    return big;
}

static IoObject *dec_map(Ctx *cx, Cur *c, uint64_t n, int depth) {
    IoObject *map = makeWrapper(cx, "protoEcMap");
    if (!map) return NULL;
    IoObject *keys = IoList_new(cx->state);
    IoObject *vals = IoList_new(cx->state);
    setSlot(cx, map, "keys", keys);
    setSlot(cx, map, "vals", vals);

    const unsigned char *prevK = NULL;
    size_t prevKLen = 0;
    for (uint64_t i = 0; i < n; i++) {
        size_t kStart = c->pos;
        IoObject *k = dec_value(cx, c, depth + 1);
        if (!k) return NULL;
        size_t kLen = c->pos - kStart;
        const unsigned char *kBytes = c->b + kStart;
        if (prevK) {
            /* Rule 2 canonical order, strictly ascending (implies Rule 5) */
            int ok;
            if (prevKLen != kLen) ok = prevKLen < kLen;
            else {
                int cmp = memcmp(prevK, kBytes, kLen);
                if (cmp == 0) { ctx_err(cx, "non_canonical_ecf", "duplicate map key"); return NULL; }
                ok = cmp < 0;
            }
            if (!ok) { ctx_err(cx, "non_canonical_ecf", "map keys not in canonical order"); return NULL; }
        }
        prevK = kBytes; prevKLen = kLen;
        IoObject *v = dec_value(cx, c, depth + 1);
        if (!v) return NULL;
        IoList_rawAppend_(keys, k);
        IoList_rawAppend_(vals, v);
    }
    return map;
}

static IoObject *dec_value(Ctx *cx, Cur *c, int depth) {
    if (cx->err) return NULL;
    if (depth > EC_MAX_DEPTH) { ctx_err(cx, "non_canonical_ecf", "nesting too deep"); return NULL; }
    IoState *st = cx->state;
    int major, ai;
    uint64_t val;
    if (dec_head(cx, c, &major, &ai, &val) != 0) return NULL;

    switch (major) {
    case 0: return bigOrNumber(cx, 0, val);
    case 1: return bigOrNumber(cx, 1, val);
    case 2: {
        if (c->pos + val > c->len) { ctx_err(cx, "truncated_input", "bytes"); return NULL; }
        IoObject *seq = IoSeq_newWithData_length_(st, c->b + c->pos, (size_t)val);
        c->pos += (size_t)val;
        IoObject *w = makeWrapper(cx, "protoEcBytes");
        if (!w) return NULL;
        setSlot(cx, w, "seq", seq);
        return w;
    }
    case 3: {
        if (c->pos + val > c->len) { ctx_err(cx, "truncated_input", "text"); return NULL; }
        if (!utf8_valid(c->b + c->pos, (size_t)val)) { ctx_err(cx, "non_canonical_ecf", "invalid UTF-8"); return NULL; }
        IoObject *seq = IoSeq_newWithData_length_(st, c->b + c->pos, (size_t)val);
        c->pos += (size_t)val;
        return seq;
    }
    case 4: {
        IoObject *list = IoList_new(st);
        for (uint64_t i = 0; i < val; i++) {
            IoObject *e = dec_value(cx, c, depth + 1);
            if (!e) return NULL;
            IoList_rawAppend_(list, e);
        }
        return list;
    }
    case 5: return dec_map(cx, c, val, depth);
    case 6:
        if (!c->keep_tags) { ctx_err(cx, "tag_rejected", "major-type-6 tag in data (N2)"); return NULL; }
        /* Salvage path only (decodeSalvage): the tag argument was already consumed into
         * `val` by the head read, so yield the item it wrapped. The frame is still
         * rejected -- the tag is never interpreted and never reaches an Entity. */
        (void)val;
        return dec_value(cx, c, depth + 1);
    case 7:
        switch (ai) {
        case 20: return st->ioFalse;
        case 21: return st->ioTrue;
        case 22: {
            IoObject *nu = slotOf(cx, cx->self, "protoEcNull");
            if (!nu) { ctx_err(cx, "decode_error", "wrappers not installed"); return NULL; }
            return nu;
        }
        case 23: ctx_err(cx, "non_canonical_ecf", "undefined (simple 23)"); return NULL;
        case 24: ctx_err(cx, "non_canonical_ecf", "extended simple value"); return NULL;
        case 25: { /* f16 — always shortest-possible; NaN must be 0x7e00 */
            if (c->pos + 2 > c->len) { ctx_err(cx, "truncated_input", "f16"); return NULL; }
            uint16_t h = ((uint16_t)c->b[c->pos] << 8) | c->b[c->pos + 1];
            c->pos += 2;
            double d = half_to_double(h);
            if (isnan(d) && h != 0x7E00) { ctx_err(cx, "non_canonical_ecf", "non-canonical NaN"); return NULL; }
            IoObject *w = makeWrapper(cx, "protoEcFloat");
            if (!w) return NULL;
            setSlot(cx, w, "num", IoState_numberWithDouble_(st, d));
            if (d == 0.0 && !isnan(d) && signbit(d))
                setSlot(cx, w, "negZero", st->ioTrue);
            return w;
        }
        case 26: {
            if (c->pos + 4 > c->len) { ctx_err(cx, "truncated_input", "f32"); return NULL; }
            uint32_t bits = 0;
            for (int i = 0; i < 4; i++) bits = (bits << 8) | c->b[c->pos++];
            float f; memcpy(&f, &bits, 4);
            double d = (double)f;
            uint16_t h;
            if (isnan(d)) { ctx_err(cx, "non_canonical_ecf", "NaN must be f16 7e00"); return NULL; }
            if (double_to_half_exact(d, &h)) { ctx_err(cx, "non_canonical_ecf", "f32 value representable as f16"); return NULL; }
            IoObject *w = makeWrapper(cx, "protoEcFloat");
            if (!w) return NULL;
            setSlot(cx, w, "num", IoState_numberWithDouble_(st, d));
            return w;
        }
        case 27: {
            if (c->pos + 8 > c->len) { ctx_err(cx, "truncated_input", "f64"); return NULL; }
            uint64_t bits = 0;
            for (int i = 0; i < 8; i++) bits = (bits << 8) | c->b[c->pos++];
            double d; memcpy(&d, &bits, 8);
            uint16_t h;
            if (isnan(d)) { ctx_err(cx, "non_canonical_ecf", "NaN must be f16 7e00"); return NULL; }
            if ((double)(float)d == d || double_to_half_exact(d, &h)) {
                ctx_err(cx, "non_canonical_ecf", "f64 value representable shorter");
                return NULL;
            }
            IoObject *w = makeWrapper(cx, "protoEcFloat");
            if (!w) return NULL;
            setSlot(cx, w, "num", IoState_numberWithDouble_(st, d));
            return w;
        }
        default: ctx_err(cx, "non_canonical_ecf", "unassigned simple value"); return NULL;
        }
    }
    ctx_err(cx, "decode_error", "unreachable");
    return NULL;
}

/* ══════════════════════ Io method glue ══════════════════════ */

#define RAISE_IF_ERR(cx)                                                     \
    if ((cx).err) {                                                          \
        IoState_error_(IOSTATE, m, "ec: %s: %s", (cx).err, (cx).detail);    \
        return IONIL(self);                                                  \
    }

static IoObject *IoEntityCodec_encode(IoObject *self, IoObject *locals, IoMessage *m) {
    Ctx cx = { IOSTATE, self, NULL, "" };
    IoObject *v = IoMessage_locals_valueArgAt_(m, locals, 0);
    Buf o = { NULL, 0, 0 };
    enc_value(&cx, &o, v, 0);
    if (cx.err) { free(o.b); }
    RAISE_IF_ERR(cx);
    IoObject *seq = IoSeq_newWithData_length_(IOSTATE, o.b ? o.b : (const unsigned char *)"", o.len);
    free(o.b);
    return seq;
}

static IoObject *IoEntityCodec_decode(IoObject *self, IoObject *locals, IoMessage *m) {
    Ctx cx = { IOSTATE, self, NULL, "" };
    IoSeq *s = IoMessage_locals_seqArgAt_(m, locals, 0);
    Cur c = { IoSeq_rawBytes(s), IoSeq_rawSizeInBytes(s), 0, 0 };
    /* Explicit retain-pool management (THE A-IO leak fix): the iovm allocators
     * (IoList_new, IoSeq_newWithData_length_, IOCLONE) auto-stackRetain each new
     * object onto the current coroutine's retain stack. A deeply-recursive
     * decode from C accumulates the whole object tree on that stack; Io only
     * drains it at a message-send boundary, which a single CFunction call does
     * NOT provide per-allocation — so across many decodes the retain stack (and
     * heap) grows without bound (~12 KB/frame). Push our own pool, then drain it
     * except the returned root. */
    /* Drain the coroutine retain stack of the whole decoded tree except the
     * returned root (the caller roots it). WITHOUT this, a decode's ~40 wrapper
     * objects stay stack-retained until the enclosing message-send boundary
     * drains — which for the poll loop's long-lived activation means unbounded
     * growth → GC-mark thrash → the ~6 req/s wall. Draining here keeps every
     * decode O(1)-retained and the peer fast (A-IO-021). */
    /* No manual retain-pool here: Io wraps each CFunction call (message send) in
     * a pool that drains-except-result on return, so the decoded tree is freed
     * once the caller's send returns. An explicit popRetainPoolExceptFor here
     * RE-retains the result onto the caller's pool a SECOND time — a genuine
     * per-decode leak (~2.6 KB/frame; A-IO-025). Callers that drive decode from a
     * long-lived loop must cross a method boundary per request (the transport's
     * _serviceFrame does), which is where Io's own pool drains. */
    IoObject *v = dec_value(&cx, &c, 0);
    if (!cx.err && c.pos != c.len) ctx_err(&cx, "non_canonical_ecf", "trailing bytes after value");
    RAISE_IF_ERR(cx);
    return v;
}

/* Non-raising decode (A-IO-025): returns the decoded value, or nil on any codec
 * error — WITHOUT IoState_error_. The peer's per-frame hot path decodes through
 * THIS, so a malformed frame is a nil check, not a `try` (Io's `try` clones a
 * Coroutine per call — the concurrency-throughput leak). The raising `decode`
 * stays for the S2 corpus's reject-path assertions. */
static IoObject *IoEntityCodec_tryDecode(IoObject *self, IoObject *locals, IoMessage *m) {
    Ctx cx = { IOSTATE, self, NULL, "" };
    IoSeq *s = IoMessage_locals_seqArgAt_(m, locals, 0);
    Cur c = { IoSeq_rawBytes(s), IoSeq_rawSizeInBytes(s), 0, 0 };
    IoObject *v = dec_value(&cx, &c, 0);
    if (!cx.err && c.pos != c.len) ctx_err(&cx, "non_canonical_ecf", "trailing bytes after value");
    if (cx.err) return IONIL(self);
    return v;
}

/* Decode for the sole purpose of REPORTING a rejection, not of accepting one. Identical
 * to tryDecode except that a major-type-6 tag yields the item it wrapped instead of
 * erroring.
 *
 * Why this exists (§6.3, a conformance requirement rather than a convenience): the tag
 * rule is "Implementations MUST reject any received protocol frame containing a CBOR tag
 * on a data field. Rejection returns 400 non_canonical_ecf." Rejecting by dropping the
 * frame on the floor satisfies the first sentence and violates the second -- the peer
 * owes the sender a status, and §4.9(c) deliver-or-signal says the same from the other
 * direction. But the status must ride a response correlated by request_id, and the strict
 * decoder cannot reach the request_id in a frame it refuses to parse. This recovers
 * exactly that much and nothing more.
 *
 * This is NOT a weakening of the tag reject. The frame stays rejected: the value this
 * returns is never converted to an Entity, never stored, never forwarded and never
 * interpreted, so §6.3's MUST NOT silently strip / MUST NOT preserve / MUST NOT attempt
 * to interpret all still hold. The strict decode/tryDecode paths that every real
 * ingestion route uses are byte-unchanged, which is what keeps the tag_reject
 * wire-conformance vectors meaningful. */
static IoObject *IoEntityCodec_decodeSalvage(IoObject *self, IoObject *locals, IoMessage *m) {
    Ctx cx = { IOSTATE, self, NULL, "" };
    IoSeq *s = IoMessage_locals_seqArgAt_(m, locals, 0);
    Cur c = { IoSeq_rawBytes(s), IoSeq_rawSizeInBytes(s), 0, 1 };
    IoObject *v = dec_value(&cx, &c, 0);
    if (!cx.err && c.pos != c.len) ctx_err(&cx, "non_canonical_ecf", "trailing bytes after value");
    if (cx.err) return IONIL(self);
    return v;
}

/* ── C-ABI passthroughs ── */

static IoSeq *seqArg(IoMessage *m, IoObject *locals, int n) {
    return IoMessage_locals_seqArgAt_(m, locals, n);
}

/* hand-assemble ECF({data: <dataBytes>, type: <type>}) — the hash input */
static int build_ecf_entity(Buf *o, const unsigned char *type, size_t typeLen,
                            const unsigned char *data, size_t dataLen) {
    if (buf_byte(o, 0xA2)) return -1;
    if (buf_head(o, 3, 4)) return -1;
    if (buf_put(o, (const unsigned char *)"data", 4)) return -1;
    if (buf_put(o, data, dataLen)) return -1;
    if (buf_head(o, 3, 4)) return -1;
    if (buf_put(o, (const unsigned char *)"type", 4)) return -1;
    if (buf_head(o, 3, typeLen)) return -1;
    if (buf_put(o, type, typeLen)) return -1;
    return 0;
}

static IoObject *IoEntityCodec_contentHash(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *type = seqArg(m, locals, 0);
    IoSeq *data = seqArg(m, locals, 1);
    unsigned char out[EC_CONTENT_HASH_LEN];
    int32_t rc = ec_content_hash(IoSeq_rawBytes(type), IoSeq_rawSizeInBytes(type),
                                 IoSeq_rawBytes(data), IoSeq_rawSizeInBytes(data), out);
    IOASSERT(rc == EC_OK, "ec_content_hash failed");
    return IoSeq_newWithData_length_(IOSTATE, out, EC_CONTENT_HASH_LEN);
}

static IoObject *IoEntityCodec_contentHashWithFormat(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *type = seqArg(m, locals, 0);
    IoSeq *data = seqArg(m, locals, 1);
    double codeD = IoMessage_locals_doubleArgAt_(m, locals, 2);
    uint64_t code = (uint64_t)codeD;
    unsigned char out[128];
    size_t outLen = 0;
    int32_t rc = ec_content_hash_with_format(IoSeq_rawBytes(type), IoSeq_rawSizeInBytes(type),
                                             IoSeq_rawBytes(data), IoSeq_rawSizeInBytes(data),
                                             code, out, sizeof(out), &outLen);
    if (rc != EC_OK) {
        /* construction-vs-verification asymmetry (ENTITY-CBOR-ENCODING §4.7):
         * the encoder serialises any caller-supplied code. Unregistered codes:
         * varint(code) ‖ SHA-256(ECF({type,data})). */
        Buf ecf = { NULL, 0, 0 };
        if (build_ecf_entity(&ecf, IoSeq_rawBytes(type), IoSeq_rawSizeInBytes(type),
                             IoSeq_rawBytes(data), IoSeq_rawSizeInBytes(data)) != 0) {
            free(ecf.b);
            IOASSERT(0, "oom");
        }
        unsigned char digest[EC_SHA256_LEN];
        int32_t r2 = ec_sha256(ecf.b, ecf.len, digest);
        free(ecf.b);
        IOASSERT(r2 == EC_OK, "ec_sha256 failed");
        outLen = 0;
        uint64_t v = code;
        do {
            unsigned char b = v & 0x7F;
            v >>= 7;
            if (v) b |= 0x80;
            out[outLen++] = b;
        } while (v);
        memcpy(out + outLen, digest, EC_SHA256_LEN);
        outLen += EC_SHA256_LEN;
    }
    return IoSeq_newWithData_length_(IOSTATE, out, outLen);
}

static IoObject *IoEntityCodec_sha256(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *s = seqArg(m, locals, 0);
    unsigned char out[EC_SHA256_LEN];
    int32_t rc = ec_sha256(IoSeq_rawBytes(s), IoSeq_rawSizeInBytes(s), out);
    IOASSERT(rc == EC_OK, "ec_sha256 failed");
    return IoSeq_newWithData_length_(IOSTATE, out, EC_SHA256_LEN);
}

static IoObject *IoEntityCodec_sha384(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *s = seqArg(m, locals, 0);
    unsigned char out[EC_SHA384_LEN];
    int32_t rc = ec_sha384(IoSeq_rawBytes(s), IoSeq_rawSizeInBytes(s), out);
    IOASSERT(rc == EC_OK, "ec_sha384 failed");
    return IoSeq_newWithData_length_(IOSTATE, out, EC_SHA384_LEN);
}

static IoObject *IoEntityCodec_ed25519SeedToPub(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *seed = seqArg(m, locals, 0);
    IOASSERT(IoSeq_rawSizeInBytes(seed) == EC_ED25519_PRIV_LEN, "seed must be 32 bytes");
    unsigned char pub[EC_ED25519_PUB_LEN];
    int32_t rc = ec_ed25519_seed_to_pubkey(IoSeq_rawBytes(seed), pub);
    IOASSERT(rc == EC_OK, "ec_ed25519_seed_to_pubkey failed");
    return IoSeq_newWithData_length_(IOSTATE, pub, EC_ED25519_PUB_LEN);
}

static IoObject *IoEntityCodec_ed25519Sign(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *seed = seqArg(m, locals, 0);
    IoSeq *msg = seqArg(m, locals, 1);
    IOASSERT(IoSeq_rawSizeInBytes(seed) == EC_ED25519_PRIV_LEN, "seed must be 32 bytes");
    unsigned char sig[EC_ED25519_SIG_LEN];
    int32_t rc = ec_ed25519_sign(IoSeq_rawBytes(seed), IoSeq_rawBytes(msg), IoSeq_rawSizeInBytes(msg), sig);
    IOASSERT(rc == EC_OK, "ec_ed25519_sign failed");
    return IoSeq_newWithData_length_(IOSTATE, sig, EC_ED25519_SIG_LEN);
}

static IoObject *IoEntityCodec_ed25519Verify(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *pub = seqArg(m, locals, 0);
    IoSeq *msg = seqArg(m, locals, 1);
    IoSeq *sig = seqArg(m, locals, 2);
    if (IoSeq_rawSizeInBytes(pub) != EC_ED25519_PUB_LEN ||
        IoSeq_rawSizeInBytes(sig) != EC_ED25519_SIG_LEN)
        return IOFALSE(self);
    int32_t rc = ec_ed25519_verify(IoSeq_rawBytes(pub), IoSeq_rawBytes(msg),
                                   IoSeq_rawSizeInBytes(msg), IoSeq_rawBytes(sig));
    return rc == EC_OK ? IOTRUE(self) : IOFALSE(self);
}

static IoObject *IoEntityCodec_peeridFormat(IoObject *self, IoObject *locals, IoMessage *m) {
    double kt = IoMessage_locals_doubleArgAt_(m, locals, 0);
    double ht = IoMessage_locals_doubleArgAt_(m, locals, 1);
    IoSeq *digest = seqArg(m, locals, 2);
    unsigned char out[256];
    size_t outLen = 0;
    int32_t rc = ec_peerid_format((uint64_t)kt, (uint64_t)ht,
                                  IoSeq_rawBytes(digest), IoSeq_rawSizeInBytes(digest),
                                  out, sizeof(out), &outLen);
    IOASSERT(rc == EC_OK, "ec_peerid_format failed");
    return IoSeq_newWithData_length_(IOSTATE, out, outLen);
}

static IoObject *IoEntityCodec_peeridParse(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *b58 = seqArg(m, locals, 0);
    uint64_t kt = 0, ht = 0;
    unsigned char digest[256];
    size_t digestLen = sizeof(digest);
    int32_t rc = ec_peerid_parse(IoSeq_rawBytes(b58), IoSeq_rawSizeInBytes(b58),
                                 &kt, &ht, digest, &digestLen);
    IOASSERT(rc == EC_OK, "ec_peerid_parse failed");
    IoState_pushRetainPool(IOSTATE);
    IoObject *list = IoList_new(IOSTATE);
    IoList_rawAppend_(list, IoState_numberWithDouble_(IOSTATE, (double)kt));
    IoList_rawAppend_(list, IoState_numberWithDouble_(IOSTATE, (double)ht));
    IoList_rawAppend_(list, IoSeq_newWithData_length_(IOSTATE, digest, digestLen));
    IoState_popRetainPoolExceptFor_(IOSTATE, list);
    return list;
}

static IoObject *IoEntityCodec_hexEncode(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *s = seqArg(m, locals, 0);
    size_t n = IoSeq_rawSizeInBytes(s);
    const unsigned char *p = IoSeq_rawBytes(s);
    char *out = malloc(n * 2 + 1);
    IOASSERT(out != NULL, "oom");
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hex[p[i] >> 4];
        out[2 * i + 1] = hex[p[i] & 0xF];
    }
    IoObject *r = IoSeq_newWithData_length_(IOSTATE, (unsigned char *)out, n * 2);
    free(out);
    return r;
}

static IoObject *IoEntityCodec_hexDecode(IoObject *self, IoObject *locals, IoMessage *m) {
    IoSeq *s = seqArg(m, locals, 0);
    size_t n = IoSeq_rawSizeInBytes(s);
    const unsigned char *p = IoSeq_rawBytes(s);
    IOASSERT(n % 2 == 0, "hexDecode: odd length");
    unsigned char *out = malloc(n / 2 + 1);
    IOASSERT(out != NULL, "oom");
    for (size_t i = 0; i < n / 2; i++) {
        int hi, lo;
        unsigned char a = p[2 * i], b = p[2 * i + 1];
        hi = (a >= '0' && a <= '9') ? a - '0' : (a >= 'a' && a <= 'f') ? a - 'a' + 10 : (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
        lo = (b >= '0' && b <= '9') ? b - '0' : (b >= 'a' && b <= 'f') ? b - 'a' + 10 : (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) { free(out); IOASSERT(0, "hexDecode: bad digit"); }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    IoObject *r = IoSeq_newWithData_length_(IOSTATE, out, n / 2);
    free(out);
    return r;
}

static IoObject *IoEntityCodec_base64Decode(IoObject *self, IoObject *locals, IoMessage *m) {
    /* standard base64 (the entity-core PEM keypair body); ignores whitespace */
    IoSeq *s = seqArg(m, locals, 0);
    size_t n = IoSeq_rawSizeInBytes(s);
    const unsigned char *p = IoSeq_rawBytes(s);
    unsigned char *out = malloc(n / 4 * 3 + 4);
    IOASSERT(out != NULL, "oom");
    size_t oi = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = p[i];
        int v;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '=') continue;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else { free(out); IOASSERT(0, "base64Decode: bad char"); }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[oi++] = (unsigned char)(acc >> bits);
        }
    }
    IoObject *r = IoSeq_newWithData_length_(IOSTATE, out, oi);
    free(out);
    return r;
}

static IoObject *IoEntityCodec_packU32be(IoObject *self, IoObject *locals, IoMessage *m) {
    double d = IoMessage_locals_doubleArgAt_(m, locals, 0);
    IOASSERT(d >= 0 && d <= 4294967295.0 && d == floor(d), "packU32be: out of range");
    uint32_t v = (uint32_t)d;
    unsigned char b[4] = { v >> 24, v >> 16, v >> 8, v };
    return IoSeq_newWithData_length_(IOSTATE, b, 4);
}

static IoObject *IoEntityCodec_randomBytes(IoObject *self, IoObject *locals, IoMessage *m) {
    double d = IoMessage_locals_doubleArgAt_(m, locals, 0);
    IOASSERT(d >= 1 && d <= 1024 && d == floor(d), "randomBytes: bad size");
    unsigned char buf[1024];
    size_t need = (size_t)d, got = 0;
    while (got < need) {
        ssize_t r = getrandom(buf + got, need - got, 0);
        IOASSERT(r > 0, "getrandom failed");
        got += (size_t)r;
    }
    return IoSeq_newWithData_length_(IOSTATE, buf, need);
}

static IoObject *IoEntityCodec_nowMs(IoObject *self, IoObject *locals, IoMessage *m) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double ms = (double)tv.tv_sec * 1000.0 + (double)(tv.tv_usec / 1000);
    return IoState_numberWithDouble_(IOSTATE, ms);
}

static IoObject *IoEntityCodec_implInfo(IoObject *self, IoObject *locals, IoMessage *m) {
    const char *s = ec_impl_info();
    return IoSeq_newWithCString_(IOSTATE, s ? s : "?");
}

static IoObject *IoEntityCodec_abiVersion(IoObject *self, IoObject *locals, IoMessage *m) {
    const char *s = ec_abi_version();
    return IoSeq_newWithCString_(IOSTATE, s ? s : "?");
}

/* the io layer hands the Io-defined wrapper protos to C */
static IoObject *IoEntityCodec_setWrappers(IoObject *self, IoObject *locals, IoMessage *m) {
    IoObject *map   = IoMessage_locals_valueArgAt_(m, locals, 0);
    IoObject *bytes = IoMessage_locals_valueArgAt_(m, locals, 1);
    IoObject *big   = IoMessage_locals_valueArgAt_(m, locals, 2);
    IoObject *flt   = IoMessage_locals_valueArgAt_(m, locals, 3);
    IoObject *nul   = IoMessage_locals_valueArgAt_(m, locals, 4);
    IoObject_setSlot_to_(self, IOSYMBOL("protoEcMap"), map);
    IoObject_setSlot_to_(self, IOSYMBOL("protoEcBytes"), bytes);
    IoObject_setSlot_to_(self, IOSYMBOL("protoEcBig"), big);
    IoObject_setSlot_to_(self, IOSYMBOL("protoEcFloat"), flt);
    IoObject_setSlot_to_(self, IOSYMBOL("protoEcNull"), nul);
    return self;
}

IoObject *IoEntityCodec_proto(void *state) {
    IoMethodTable methodTable[] = {
        {"encode", IoEntityCodec_encode},
        {"decode", IoEntityCodec_decode},
        {"tryDecode", IoEntityCodec_tryDecode},
        {"decodeSalvage", IoEntityCodec_decodeSalvage},
        {"contentHash", IoEntityCodec_contentHash},
        {"contentHashWithFormat", IoEntityCodec_contentHashWithFormat},
        {"sha256", IoEntityCodec_sha256},
        {"sha384", IoEntityCodec_sha384},
        {"ed25519SeedToPub", IoEntityCodec_ed25519SeedToPub},
        {"ed25519Sign", IoEntityCodec_ed25519Sign},
        {"ed25519Verify", IoEntityCodec_ed25519Verify},
        {"peeridFormat", IoEntityCodec_peeridFormat},
        {"peeridParse", IoEntityCodec_peeridParse},
        {"hexEncode", IoEntityCodec_hexEncode},
        {"hexDecode", IoEntityCodec_hexDecode},
        {"base64Decode", IoEntityCodec_base64Decode},
        {"packU32be", IoEntityCodec_packU32be},
        {"randomBytes", IoEntityCodec_randomBytes},
        {"nowMs", IoEntityCodec_nowMs},
        {"implInfo", IoEntityCodec_implInfo},
        {"abiVersion", IoEntityCodec_abiVersion},
        {"_setWrappers", IoEntityCodec_setWrappers},
        {NULL, NULL},
    };
    IoObject *self = IoObject_new(state);
    IoObject_addTaglessMethodTable_(self, methodTable);
    return self;
}
