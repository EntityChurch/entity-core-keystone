/*
 * spike.c — the S2 codec spike (profile mandate): push the float + map_keys
 * v7.71 vectors through the hand-rolled encoder BEFORE the full build. Float
 * minimization (double->f16 re-decode-and-compare) is the highest bug-density
 * code in the peer; map-key ordering (length-then-lex / CTAP2) is the other
 * load-bearing canonical risk. If these two categories are byte-identical, the
 * native strategy is confirmed.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "entity_core/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static int fails = 0;
static int passes = 0;

static void hex(const uint8_t *p, size_t n, char *out)
{
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = H[p[i] >> 4];
        out[2 * i + 1] = H[p[i] & 0xf];
    }
    out[2 * n] = 0;
}

static void check(const char *id, ec_value *v, const char *want_hex)
{
    uint8_t *enc = NULL;
    size_t len = 0;
    ec_status st = ec_ecf_encode(v, &enc, &len);
    ec_value_free(v);
    if (st != EC_OK) {
        printf("FAIL %s: encode status %d\n", id, st);
        fails++;
        return;
    }
    char got[256];
    hex(enc, len, got);
    free(enc);
    if (strcmp(got, want_hex) == 0) {
        passes++;
    } else {
        printf("FAIL %s: want=%s got=%s\n", id, want_hex, got);
        fails++;
    }
}

int main(void)
{
    /* float ladder */
    check("float.1", ec_float(0.0), "f90000");
    check("float.2", ec_special(EC_FLOAT_NEG_ZERO), "f98000");
    check("float.3", ec_float(1.0), "f93c00");
    check("float.4", ec_float(1.5), "f93e00");
    check("float.5", ec_special(EC_FLOAT_POS_INF), "f97c00");
    check("float.6", ec_special(EC_FLOAT_NEG_INF), "f9fc00");
    check("float.7", ec_special(EC_FLOAT_NAN), "f97e00");
    check("float.8", ec_float(32768.0), "f97800");
    check("float.9", ec_float(65472.0), "f97bfe");
    check("float.10", ec_float(65504.0), "f97bff");
    check("float.11", ec_float(-65504.0), "f9fbff");
    check("float.12", ec_float(65503.0), "fa477fdf00");
    check("float.13", ec_float(100000.0), "fa47c35000");
    check("float.14", ec_float(1.1), "fb3ff199999999999a");

    /* map_keys (length-first then lex) */
    {
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("a"), ec_int_u(1));
        check("map_keys.1", m, "a1616101");
    }
    {
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("aa"), ec_int_u(2));
        ec_map_put(m, ec_text("z"), ec_int_u(1));
        check("map_keys.2", m, "a2617a0162616102");
    }
    {
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("b"), ec_int_u(2));
        ec_map_put(m, ec_text("a"), ec_int_u(1));
        check("map_keys.3", m, "a2616101616202");
    }
    {
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("aaaaaaaaaaaaaaaaaaaaaaaa"), ec_int_u(24)); /* 24 'a' */
        ec_map_put(m, ec_text("aaaaaaaaaaaaaaaaaaaaaaa"), ec_int_u(23));  /* 23 'a' */
        check("map_keys.4", m,
              "a27761616161616161616161616161616161616161616161611778186161616161616161616161616161616161616161616161611818");
    }
    {
        ec_value *m = ec_map();
        uint8_t key[] = {0x6b, 0x65, 0x79};
        ec_map_put(m, ec_bytes(key, 3), ec_int_u(2));
        ec_map_put(m, ec_text("text_key"), ec_int_u(1));
        check("map_keys.5", m, "a2436b65790268746578745f6b657901");
    }
    {
        ec_value *m = ec_map();
        ec_map_put(m, ec_text("aaa"), ec_int_u(2));
        ec_map_put(m, ec_text("aa"), ec_int_u(1));
        check("map_keys.6", m, "a2626161016361616102");
    }

    printf("== SPIKE: %d pass, %d fail ==\n", passes, fails);
    return fails == 0 ? 0 : 1;
}
