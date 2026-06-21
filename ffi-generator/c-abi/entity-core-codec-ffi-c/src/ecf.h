/*
 * ecf.h — hand-written canonical ECF core for entity-core-codec-ffi-c.
 *
 * This is the C twin of the Rust impl's value/encode/decode modules
 * (entity-core-codec-ffi-rust/src/{value,encode,decode}.rs). No CBOR library is
 * trusted to produce canonical output (spec sec.3, N1-N4): every canonical
 * guarantee lives here.
 *
 *   - shortest-form integer arguments (RFC 8949 sec.4.2.1 Rule 1)
 *   - shortest-float minimization + the four special floats (spec sec.3.5)
 *   - map keys sorted bytewise-lexicographically on their *encoded* form
 *     (RFC 8949 sec.4.2.1; coincides with length-first for same-major-type keys)
 *   - reject CBOR tags (major type 6) anywhere on decode (N2)
 *
 * The value model mirrors the Rust `Value` enum exactly. Integers are stored as
 * (negative flag, u64 argument) -- the raw CBOR head argument -- which holds the
 * FULL mt-0 range [0, 2^64-1] and the full mt-1 range without any i64 overflow
 * (this is the F7 fix made structural: there is no signed integer to overflow).
 */
#ifndef ECF_H
#define ECF_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    EV_INT,        /* (negative, arg): value is negative ? -1 - arg : arg */
    EV_FLOAT,      /* IEEE-754 double; encoded to shortest round-tripping form */
    EV_BYTES,
    EV_TEXT,       /* UTF-8 bytes; not null-terminated */
    EV_ARRAY,
    EV_MAP,        /* pairs in arbitrary order; sorted canonically at encode time */
    EV_BOOL,
    EV_NULL,
    EV_PREENCODED  /* already-canonical CBOR spliced in verbatim (opaque `data`) */
} ev_kind;

typedef struct ec_value ec_value;

typedef struct {
    ec_value *key;
    ec_value *val;
} ec_pair;

struct ec_value {
    ev_kind kind;
    union {
        struct { int negative; uint64_t arg; } i; /* EV_INT */
        double f;                                  /* EV_FLOAT */
        int b;                                     /* EV_BOOL */
        struct { uint8_t *ptr; size_t len; } bytes; /* EV_BYTES/TEXT/PREENCODED */
        struct { ec_value **items; size_t len; } arr; /* EV_ARRAY */
        struct { ec_pair *pairs; size_t len; } map;   /* EV_MAP */
    } u;
};

/* ---- growable byte buffer ---- */
typedef struct {
    uint8_t *ptr;
    size_t   len;
    size_t   cap;
} ecbuf;

void ecbuf_init(ecbuf *b);
void ecbuf_free(ecbuf *b);
void ecbuf_push(ecbuf *b, uint8_t byte);
void ecbuf_append(ecbuf *b, const uint8_t *src, size_t n);

/* ---- LEB128 (N1) ---- */
void   leb128_encode(uint64_t code, ecbuf *out);
/* returns bytes consumed, or 0 on malformed/overflow input */
size_t leb128_decode(const uint8_t *in, size_t in_len, uint64_t *out_code);

/* ---- canonical encode ---- */
/* Append the canonical ECF encoding of `v` to `out`. */
void ecf_encode(const ec_value *v, ecbuf *out);

/* ---- decode (builds a value tree; rejects tags/indefinite per N2) ---- */
/* Returns a heap value tree on success, NULL on any decode error. Trailing
 * bytes after the single top-level item are an error. Allocations are owned by
 * the process (the harness is short-lived; see ecf.c note). */
ec_value *ecf_decode(const uint8_t *bytes, size_t len);

/* N2 gate: 1 iff `bytes` is a single well-formed tag-free ECF item, else 0. */
int ecf_validate_no_tags(const uint8_t *bytes, size_t len);

/* ---- byte-span walkers (N4 + envelope; twin of decode.rs span walkers) ---- */
/* A (offset, length) span of a sub-item within the decoded buffer — used to
 * hand the caller borrowed slices of the ORIGINAL wire bytes (N4, spec sec.4.1
 * option a), never a re-encode. */
typedef struct { size_t off; size_t len; } ec_span;

/* N4: structurally validate an entity map {type, data, ...} and return the byte
 * spans of its `type` and `data` VALUES within `bytes`. Rejects tags (N2).
 * Returns 1 on success, 0 on malformed / missing type|data / trailing bytes. */
int ecf_entity_spans(const uint8_t *bytes, size_t len,
                     ec_span *type_span, ec_span *data_span);

/* Walk an envelope map {root, included} and fill `root`'s span plus up to
 * `max_inc` (included key-span, included entity-span) pairs. `*n_inc` receives
 * the actual count of included entries (which may exceed max_inc → returns 0).
 * Rejects tags (N2). Returns 1 on success, 0 on malformed / over-capacity. */
int ecf_envelope_spans(const uint8_t *bytes, size_t len, ec_span *root,
                       ec_span *inc_keys, ec_span *inc_entities,
                       size_t *n_inc, size_t max_inc);

/* ---- value constructors (used by codec.c / the harness) ---- */
ec_value *ev_new(ev_kind kind);
ec_value *ev_int_u64(uint64_t v);
ec_value *ev_text(const char *s, size_t len);
ec_value *ev_bytes(const uint8_t *p, size_t len);
ec_value *ev_preencoded(const uint8_t *p, size_t len);

#endif /* ECF_H */
