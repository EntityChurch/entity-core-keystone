/*
 * regression_test.c — encoder regressions BEYOND the corpus. Twin of the Rust
 * impl's encode.rs #[test] block. These lock the exact gaps the cross-blessed
 * fixture does NOT cover (Rust review pass, F7):
 *   - CBOR mt-0 uints in [2^63, 2^64-1] — where a signed-i64 decode overflows.
 *     The C value model stores ints as (negative, u64 arg), so there is no
 *     signed integer to overflow; these pin that structurally.
 *   - negatives past the corpus's -256, incl. the i64::MIN boundary.
 *   - the four special floats + shortest-form f16/f32/f64 selection (sec.3.5).
 *
 * No oracle here — these are byte-literal assertions against hand-computed CBOR.
 */
#include "ecf.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static char *enc_hex(const ec_value *v) {
    static char out[256];
    ecbuf b;
    ecbuf_init(&b);
    ecf_encode(v, &b);
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < b.len; i++) {
        out[2 * i] = H[b.ptr[i] >> 4];
        out[2 * i + 1] = H[b.ptr[i] & 0xf];
    }
    out[2 * b.len] = '\0';
    ecbuf_free(&b);
    return out;
}

static void check(const char *name, const ec_value *v, const char *want) {
    const char *got = enc_hex(v);
    if (strcmp(got, want) != 0) {
        printf("  FAIL %-28s got %s != want %s\n", name, got, want);
        failures++;
    } else {
        printf("  ok   %-28s %s\n", name, got);
    }
}

static ec_value *int_pos(uint64_t arg) { return ev_int_u64(arg); }
static ec_value *int_neg(uint64_t arg) {
    ec_value *v = ev_new(EV_INT);
    v->u.i.negative = 1;
    v->u.i.arg = arg; /* value = -1 - arg */
    return v;
}
static ec_value *flt(double f) {
    ec_value *v = ev_new(EV_FLOAT);
    v->u.f = f;
    return v;
}

int main(void) {
    printf("# entity-core-codec-ffi-c — encoder regression tests (beyond corpus)\n\n");

    /* uint above i64::MAX — F7 gap (mt-0, arg = the value itself) */
    check("uint 2^63",        int_pos(9223372036854775808ULL),  "1b8000000000000000");
    check("uint u64::MAX",    int_pos(18446744073709551615ULL), "1bffffffffffffffff");

    /* negatives beyond corpus -256; value = -1 - arg, so arg = -1 - value */
    check("nint -257",        int_neg(256),                     "390100");      /* arg 256 */
    check("nint -65537",      int_neg(65536),                   "3a00010000");  /* arg 65536 */
    check("nint i64::MIN",    int_neg(9223372036854775807ULL),  "3b7fffffffffffffff");

    /* float specials + shortest-form selection (sec.3.5) */
    check("float NaN",        flt(NAN),                         "f97e00");
    check("float +inf",       flt(INFINITY),                    "f97c00");
    check("float -inf",       flt(-INFINITY),                   "f9fc00");
    check("float -0.0",       flt(-0.0),                        "f98000");
    check("float 1.5 (f16)",  flt(1.5),                         "f93e00");
    check("float 100000 (f32)", flt(100000.0),                  "fa47c35000");
    check("float 1.1 (f64)",  flt(1.1),                         "fb3ff199999999999a");

    if (failures) {
        printf("\n# %d regression failure(s)\n", failures);
        return 1;
    }
    printf("\n# RESULT: PASS (all regression assertions)\n");
    return 0;
}
